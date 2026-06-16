# SPDX-License-Identifier: BSD-3-Clause
"""OPTIONAL two-layer composition: SCITT/COSE substrate + Class-1 payload.

This module is imported only on the ``--transparent`` path and **requires the
optional ``scitt-cose`` package** (``pip install 'agent-action-capsule[transparent]'``).
Importing it without ``scitt-cose`` installed raises ``ImportError``, which the
CLI catches and turns into an actionable message — never a traceback.

Division of labour follows the spec: the **substrate** (COSE_Sign1 signature +
RFC 9162 receipt / inclusion proof) is verified *by reference* to SCITT/COSE —
we call ``scitt-cose`` and do NOT reimplement it (spec §3.2/§6). The **payload**
(the Agent Action Capsule) is this profile's Class-1 verification.

Attestation honesty (spec §3.2 MUST): ``anchored`` is reported ONLY when a
receipt actually verified. A signature with no verified receipt is
``self_attested``; an unverifiable signature is ``signature-invalid``.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

# Hard dependency on the optional extra — import error propagates to the CLI.
from scitt_cose import (  # type: ignore
    CoseError,
    extract_receipts,
    parse_signed_statement,
    verify_receipt,
)

from . import VerificationResult, verify


class SubstrateInputError(Exception):
    """The Signed Statement / key material could not be read or decoded."""


@dataclass
class TransparentReport:
    signature_verified: bool | None = None
    receipt_present: bool = False
    receipt_verified: bool | None = None
    attestation_tier: str = "signature-invalid"
    content_type: str | None = None
    substrate_errors: list[str] = field(default_factory=list)
    payload: VerificationResult | None = None
    ok: bool = False


def _read(path: str) -> bytes:
    return Path(path).read_bytes()


def verify_transparent(
    *,
    statement_path: str,
    issuer_key_path: str,
    log_key_path: str | None = None,
    leaf_entry_hex: str | None = None,
) -> TransparentReport:
    """Verify a SCITT Signed Statement: substrate layer (scitt-cose) then payload
    layer (Class-1). Returns a structured report; raises only ``SubstrateInputError``
    / ``OSError`` for unreadable inputs."""
    report = TransparentReport()

    msg = _read(statement_path)
    issuer_key = _read(issuer_key_path)

    # ---- substrate STEP 1: signature (scitt-cose) ---------------------------
    parsed = parse_signed_statement(msg, public_key_pem=issuer_key)  # never raises
    report.signature_verified = parsed.get("signature_verified")
    report.content_type = parsed.get("content_type")

    if report.signature_verified is not True:
        report.attestation_tier = "signature-invalid"
        report.substrate_errors.append("COSE_Sign1 signature did not verify under the issuer key")
        report.ok = False
        return report  # do not trust / verify an unauthenticated payload

    # ---- substrate STEP 1b: receipt / inclusion proof (optional) ------------
    receipt_requested = bool(log_key_path and leaf_entry_hex)
    try:
        receipts = extract_receipts(msg)
    except CoseError as exc:
        receipts = []
        report.substrate_errors.append(f"could not read receipts: {exc}")
    report.receipt_present = bool(receipts)

    if receipts and receipt_requested:
        log_key = _read(log_key_path)  # type: ignore[arg-type]
        verified = False
        for r in receipts:
            res = verify_receipt(r, leaf_entry_hex=leaf_entry_hex, log_public_key_pem=log_key)
            if res.ok:
                verified = True
                break
            report.substrate_errors.extend(res.errors)
        report.receipt_verified = verified
    elif receipts and not receipt_requested:
        report.receipt_verified = None
        report.substrate_errors.append(
            "receipt present but not verified — pass --log-key and --leaf-entry-hex to upgrade to 'anchored'"
        )
    elif not receipts and receipt_requested:
        # The caller asked to verify a receipt but the statement carries none —
        # explain why the combined verdict below will be ok=False (they expected
        # a Transparent Statement and got a bare Signed Statement).
        report.receipt_verified = False
        report.substrate_errors.append(
            "receipt verification requested (--log-key/--leaf-entry-hex) but the "
            "Signed Statement carries no receipt"
        )

    # ---- attestation tier (spec §3.2): anchored ONLY with a verified receipt
    if report.receipt_verified is True:
        report.attestation_tier = "anchored"
    else:
        report.attestation_tier = "self_attested"

    # ---- payload STEP 2: Class-1 over the AUTHENTICATED payload --------------
    payload_bytes = parsed.get("payload")
    if not isinstance(payload_bytes, (bytes, bytearray)):
        report.substrate_errors.append("authenticated statement carried no payload")
        report.ok = False
        return report
    try:
        capsule = json.loads(payload_bytes)
    except json.JSONDecodeError as exc:
        report.substrate_errors.append(f"authenticated payload is not valid JSON: {exc}")
        report.ok = False
        return report

    report.payload = verify(capsule)  # never raises

    # Combined verdict: substrate authenticated AND payload ok. If a receipt
    # check was explicitly requested, it must also have verified.
    report.ok = (
        report.signature_verified is True
        and report.payload.ok
        and (not receipt_requested or report.receipt_verified is True)
    )
    return report
