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
from ._ed25519_strict import strict_encoding
from .canonical import loads_bounded
from .media_types import CAPSULE_ID_MEDIA_TYPE

#: RFC 9943 Section 6 makes the CWT ``iss`` and ``sub`` claims MUST on a
#: Receipt, and the ``kid`` header MUST when neither ``x5t`` nor ``x5chain`` is
#: in the protected header. scitt-cose surfaces them and leaves the MUST to the
#: profile, so this profile requires them.
#:
#: The ``ts.agentactioncapsule.org`` witness issued receipts carrying none of
#: the three until capsule-anchor#103, and published interop runs cite such
#: receipts. A receipt whose ``iat`` is before this cutoff and which lacks a
#: header is therefore reported in ``receipt_findings`` instead of failing.
#: ``iat`` is in the protected header the log key signs, so only that key's
#: holder can place a receipt before the cutoff; a receipt without an integer
#: ``iat`` gets no exception. Any log key's holder can backdate ``iat``, but
#: the caller already trusts that key for inclusion, and a backdated receipt
#: still reports the finding.
#:
#: The cutoff (2026-11-26T00:00:00Z) must not be earlier than the fixed
#: witness's deploy, or receipts the unfixed witness issues in between fail;
#: if that deploy slips past it, move it later before the next release
#: (agent-action-capsule#683).
LEGACY_RECEIPT_IAT_CUTOFF = 1795651200

#: COSE header labels (RFC 9052 Section 3.1, RFC 9360 Section 2).
_HDR_KID = 4
_HDR_X5CHAIN = 33
_HDR_X5T = 34


class SubstrateInputError(Exception):
    """The Signed Statement / key material could not be read or decoded."""


@dataclass
class TransparentReport:
    signature_verified: bool | None = None
    receipt_present: bool = False
    receipt_verified: bool | None = None
    attestation_tier: str = "signature-invalid"
    content_type: str | None = None
    authenticated_capsule_id: str | None = None
    substrate_errors: list[str] = field(default_factory=list)
    receipt_findings: list[str] = field(default_factory=list)
    payload: VerificationResult | None = None
    ok: bool = False


def _read(path: str) -> bytes:
    return Path(path).read_bytes()


def _eddsa_not_strict(cose: bytes, key_pem: bytes) -> bool:
    """True when ``cose`` is a COSE_Sign1 signed EdDSA (-8) under the Ed25519
    ``key_pem`` and its signature fails strict Ed25519's conditions on A, R
    and S. ``scitt_cose`` verifies with ``cryptography``, which accepts a
    small-order key, and a small-order key verifies a forged signature over
    any message. Anything this cannot read is left to ``scitt_cose``."""
    import cbor2
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key

    try:
        key = load_pem_public_key(key_pem)
        outer = cbor2.loads(cose)
        value = outer.value if isinstance(outer, cbor2.CBORTag) else outer
        protected = cbor2.loads(value[0]) if value[0] else {}
        signature = value[3]
    except Exception:  # noqa: BLE001 -- scitt_cose has already judged what it could read
        return False
    # scitt_cose (checked at 0.5.0) verifies an Ed25519 key only under alg -8
    # (EdDSA) and raises for any other alg, so -8 is the only case to check.
    if not isinstance(key, Ed25519PublicKey) or not isinstance(protected, dict) or protected.get(1) != -8:
        return False
    raw = key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return not (isinstance(signature, bytes) and strict_encoding(raw, signature))


def _missing_receipt_headers(res) -> list[str]:
    """The RFC 9943 Section 6 Receipt headers a verified ``res`` lacks."""
    missing = []
    if not (isinstance(res.issuer, str) and res.issuer):
        missing.append("iss")
    if not (isinstance(res.subject, str) and res.subject):
        missing.append("sub")
    ext = res.protected_header_ext or {}
    kid = ext.get(_HDR_KID)
    if not (isinstance(kid, bytes) and kid) and _HDR_X5T not in ext and _HDR_X5CHAIN not in ext:
        missing.append("kid")
    return missing


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
    if report.signature_verified is True and _eddsa_not_strict(msg, issuer_key):
        report.signature_verified = False

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
            if res.ok and _eddsa_not_strict(r, log_key):
                report.substrate_errors.append("receipt EdDSA signature is not strict Ed25519")
                continue
            if res.ok:
                missing = _missing_receipt_headers(res)
                if missing:
                    text = "receipt lacks " + ", ".join(missing) + " (RFC 9943 Section 6)"
                    iat = res.iat
                    pre_fix = (
                        isinstance(iat, int) and not isinstance(iat, bool)
                        and iat < LEGACY_RECEIPT_IAT_CUTOFF
                    )
                    if not pre_fix:
                        report.substrate_errors.append(text)
                        continue
                    report.receipt_findings.append(
                        text + f"; accepted as issued before the cutoff (iat {iat})"
                    )
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
    if report.content_type == CAPSULE_ID_MEDIA_TYPE:
        if len(payload_bytes) != 32:
            report.substrate_errors.append("authenticated Capsule-ID payload is not 32 bytes")
            report.ok = False
            return report
        report.authenticated_capsule_id = bytes(payload_bytes).hex()
        report.ok = report.signature_verified is True and (
            not receipt_requested or report.receipt_verified is True
        )
        return report
    try:
        capsule = loads_bounded(payload_bytes)
    except ValueError as exc:  # JSONDecodeError, UnicodeDecodeError, NestingTooDeepError
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
