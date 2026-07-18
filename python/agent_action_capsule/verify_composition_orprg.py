# SPDX-License-Identifier: BSD-3-Clause
"""Owner-appraisal path for the ORPRG PermitReceipt + MachineMandate payment composition.

This module wires the ORPRG PermitReceipt owner-appraisal into the v3
verify_permitreceipt_mandate() gate model, and adds two payment-composition-specific
mandate gates that the base 4-gate verifier does not check.

Appraisal path (per Scott Lee's Jul 17 19:47 spec):
  verify signed carrier
  → carrier.authorization_ref MATCHES extracted authorization-ref view
  → ref_artifact_digest MATCHES SHA-256(CP-JSON-2(receipt_core))
  → receipt signature valid; receipt not revoked; receipt within validity window
  → policy epoch + permit provenance trusted
  → appraisal record names verifier_id + decision + evidence digests
  → result fed into permit_receipt_appraised gate — digest match alone never passes

Additional payment-composition mandate gates (from ORPRG expected-gates.json §2):
  machine_mandate_action_hash  — verifies mandate action hash is derivable from action object
                                 (structural consistency; PASS in both cases)
  machine_mandate_spend        — verifies permit scope.max_effect_budget <= mandate ceiling
                                 positive: 25000 EUR ≤ 50000 → PASS
                                 mandate-over-limit: 75000 EUR > 50000 → DENY

Gate failure semantics: a capsule whose gates fail MAY still be signed and
registered as audit evidence; gate failure = "no effect-commit marker" only.

Reference package: meridianverity/permit-receipt tag ietf126-payment-composition-v0.1
  (commit 5c2de6c3, ZIP SHA-256: d13c740c47710e4b28a1d2d511aa63574200256ce310f0e03ec618b383583c2f)
"""
from __future__ import annotations

import base64
import hashlib
import json
import unicodedata
from datetime import datetime
from typing import Any, Mapping

__all__ = [
    "ORPRG_VERIFIER_ID",
    "ORPRG_EVAL_TIME_ISO",
    "appraise_orprg_permit_receipt",
    "machine_mandate_action_hash_gate",
    "machine_mandate_spend_gate",
]

ORPRG_VERIFIER_ID = "orprg-aac-composition.v0.1"

# Frozen evaluation time for the ietf126-payment-composition-v0.1 package.
ORPRG_EVAL_TIME_ISO = "2026-07-18T09:00:00Z"


def _gate(name: str, passed: bool, reason: str) -> dict:
    return {"name": name, "passed": passed, "reason": reason}


# ---------------------------------------------------------------------------
# CP-JSON-2 canonicalization (matches ORPRG package; equivalent to RFC 8785
# JCS for all data in this package — verified against orprg_eval reference)
# ---------------------------------------------------------------------------

def _normalize(value: Any) -> Any:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, float):
        raise ValueError("floats not permitted in CP-JSON-2")
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list):
        return [_normalize(v) for v in value]
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for k, v in value.items():
            nk = unicodedata.normalize("NFC", k)
            out[nk] = _normalize(v)
        return {k: out[k] for k in sorted(out)}
    raise ValueError(f"unsupported type: {type(value)!r}")


def _cp_json2_bytes(obj: Mapping[str, Any]) -> bytes:
    """CP-JSON-2 canonical bytes (RFC 8785 key-sort; no NaN/Inf)."""
    return json.dumps(
        _normalize(obj),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _parse_iso(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _verify_ed25519(pub_b64: str, sig_b64: str, body: Mapping[str, Any]) -> bool:
    """Verify an Ed25519 signature over CP-JSON-2(body)."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        pub = base64.b64decode(pub_b64, validate=True)
        sig = base64.b64decode(sig_b64, validate=True)
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, _cp_json2_bytes(body))
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# ORPRG PermitReceipt owner-appraisal
# ---------------------------------------------------------------------------

def appraise_orprg_permit_receipt(
    carrier: dict,
    auth_ref_extracted: dict,
    permit_receipt: dict,
    *,
    policy: dict,
    trust_inputs: dict,
    revocation_state: dict,
    verifier_context: dict,
    permit_provenance: dict,
) -> tuple[bool, dict]:
    """Owner-appraisal of an ORPRG PermitReceipt.

    Implements the appraisal path in order:
    1. Verify carrier Ed25519 signature (issuer public key from policy).
    2. Confirm carrier.authorization_ref == extracted auth_ref view.
    3. Confirm ref_artifact_digest == SHA-256(CP-JSON-2(receipt_core)).
    4. Verify receipt core signature.
    5. Confirm action_commitment in auth_ref matches core.action_digest.
    6. Confirm scope in auth_ref matches scope in receipt_core.
    7. Check policy epoch consistency.
    8. Check policy_digest consistency.
    9. Check permit_provenance_digest is trusted.
    10. Check validity window (now within valid_from/valid_to).
    11. Verify revocation list signature; check freshness; confirm not revoked.
    12. Confirm auth_ref status=="valid" and signature_coverage==True.

    Parameters
    ----------
    carrier : dict
        Signed authorization-ref carrier (authorization-ref-carrier.json).
    auth_ref_extracted : dict
        Extracted authorization reference view (authorization-ref.json).
    permit_receipt : dict
        Full PermitReceipt JSON (permit-receipt.json).
    policy, trust_inputs, revocation_state, verifier_context, permit_provenance :
        Frozen shared context from the ORPRG package shared/ directory.

    Returns
    -------
    (appraisal_ok: bool, appraisal_record: dict)
        appraisal_ok: True iff ALL checks pass.
        appraisal_record: {verifier_id, decision, checks, evidence_digests, issuer_id}
    """
    checks: dict[str, bool] = {}

    issuer = trust_inputs.get("permit_receipt_issuer", {})
    issuer_id: str = issuer.get("issuer_id", "")
    issuer_pub_b64: str = policy.get("trusted_issuers", {}).get(issuer_id, "")

    rev_authority = trust_inputs.get("revocation_authority", {})
    rev_authority_id: str = rev_authority.get("issuer_id", "")
    rev_pub_b64: str = policy.get("revocation_authorities", {}).get(rev_authority_id, "")

    # 1. Carrier signature
    carrier_body: dict = carrier.get("carrier", {})
    carrier_auth: dict = carrier.get("authenticity", {})
    checks["carrier_signature"] = _verify_ed25519(
        issuer_pub_b64, carrier_auth.get("signature", ""), carrier_body
    )

    # 2. Carrier content matches extracted view
    checks["carrier_ref_matches_extracted"] = (
        carrier_body.get("authorization_ref") == auth_ref_extracted
    )

    # 3. Receipt core digest == ref_artifact_digest
    core: dict = permit_receipt.get("receipt_core", {})
    receipt_core_digest = _sha256hex(_cp_json2_bytes(core))
    expected_ref_digest = "sha256:" + receipt_core_digest
    checks["ref_artifact_digest_matches_core"] = (
        auth_ref_extracted.get("ref_artifact_digest") == expected_ref_digest
    )

    # 4. Receipt core signature
    receipt_auth: dict = permit_receipt.get("authenticity", {})
    checks["receipt_signature"] = _verify_ed25519(
        issuer_pub_b64, receipt_auth.get("signature", ""), core
    )

    # 5. Action commitment in auth_ref matches receipt_core.action_digest
    core_action_digest: str = core.get("action_digest", "")
    checks["ref_action_commitment"] = (
        auth_ref_extracted.get("action_commitment") == "sha256:" + core_action_digest
    )

    # 6. Scope in auth_ref matches scope in receipt_core
    checks["scope_match"] = (auth_ref_extracted.get("scope") == core.get("scope"))

    # 7. Policy epoch
    epoch_id = core.get("epoch_id")
    checks["policy_epoch"] = (
        epoch_id == policy.get("current_epoch_id")
        and auth_ref_extracted.get("policy_epoch") == policy.get("current_epoch_id")
    )

    # 8. Policy digest
    checks["policy_digest"] = (core.get("policy_digest") == policy.get("policy_digest"))

    # 9. Permit provenance trusted
    prov_digest = "sha256:" + _sha256hex(_cp_json2_bytes(permit_provenance))
    checks["permit_provenance_trusted"] = (
        prov_digest in policy.get("trusted_permit_provenance_digests", [])
    )
    checks["core_provenance_digest"] = (core.get("permit_provenance_digest") == prov_digest)

    # 10. Validity window
    now = _parse_iso(verifier_context.get("now", ORPRG_EVAL_TIME_ISO))
    try:
        checks["validity_window"] = (
            _parse_iso(core.get("valid_from", "")) <= now
            <= _parse_iso(core.get("valid_to", ""))
        )
    except Exception:
        checks["validity_window"] = False

    # 11. Revocation
    rev_list: dict = revocation_state.get("signed_revocation_list", {})
    rev_body: dict = rev_list.get("body", {})
    rev_sig: str = rev_list.get("authenticity", {}).get("signature", "")
    checks["revocation_signature"] = _verify_ed25519(rev_pub_b64, rev_sig, rev_body)
    try:
        rev_age_s = int(
            (now - _parse_iso(rev_body.get("issued_at", now.isoformat()))).total_seconds()
        )
    except Exception:
        rev_age_s = -1
    checks["revocation_fresh"] = 0 <= rev_age_s <= policy.get("revocation_max_age_seconds", 3600)
    checks["not_revoked"] = (
        receipt_core_digest not in rev_body.get("revoked_receipt_digests", [])
        and core.get("issuer_id", "") not in rev_body.get("revoked_issuers", [])
    )

    # 12. Auth ref status
    checks["ref_status_valid"] = (
        auth_ref_extracted.get("status") == "valid"
        and auth_ref_extracted.get("signature_coverage") is True
    )

    appraisal_ok = all(checks.values())
    return appraisal_ok, {
        "verifier_id": ORPRG_VERIFIER_ID,
        "decision": "ALLOW" if appraisal_ok else "DENY",
        "checks": checks,
        "evidence_digests": {
            "receipt_core_digest": receipt_core_digest,
            "ref_artifact_digest": expected_ref_digest,
            "action_commitment": auth_ref_extracted.get("action_commitment", ""),
        },
        "issuer_id": issuer_id,
    }


# ---------------------------------------------------------------------------
# Additional payment-composition mandate gates
# ---------------------------------------------------------------------------

def machine_mandate_action_hash_gate(
    machine_mandate_action: dict,
    expected_action_hash: str,
) -> dict:
    """Verify the MachineMandate action hash is derivable from its action object.

    ``expected_action_hash`` is the profile's ``machine_mandate.action_hash``
    (format: ``sha256:<64-hex>``).  This is a structural consistency gate; it
    passes for both the positive and mandate-over-limit cases.
    """
    computed = "sha256:" + _sha256hex(_cp_json2_bytes(machine_mandate_action))
    if computed == expected_action_hash:
        return _gate(
            "machine_mandate_action_hash", True,
            f"action hash matches {expected_action_hash[:22]}…",
        )
    return _gate(
        "machine_mandate_action_hash", False,
        f"action hash mismatch: expected {expected_action_hash!r}, computed {computed!r}",
    )


def machine_mandate_spend_gate(permit_receipt: dict, scope_max_spend_minor: int) -> dict:
    """Verify permitted effect budget does not exceed the mandate scope ceiling.

    ``scope_max_spend_minor``: mandate maximum in currency minor units
    (``mapping_profile.machine_mandate.scope_max_spend_minor``).

    Checks ``permit_receipt.receipt_core.scope.max_effect_budget <= scope_max_spend_minor``:
      positive:            25000 EUR ≤ 50000 → PASS
      mandate-over-limit:  75000 EUR > 50000 → DENY
    """
    core = permit_receipt.get("receipt_core") if isinstance(permit_receipt, dict) else None
    if not isinstance(core, dict):
        return _gate("machine_mandate_spend", False, "permit_receipt missing receipt_core")
    scope = core.get("scope", {})
    requested = scope.get("max_effect_budget")
    if not isinstance(requested, int) or isinstance(requested, bool):
        return _gate(
            "machine_mandate_spend", False,
            f"scope.max_effect_budget not an integer: {requested!r}",
        )
    if requested <= scope_max_spend_minor:
        return _gate(
            "machine_mandate_spend", True,
            f"max_effect_budget {requested} <= mandate ceiling {scope_max_spend_minor}",
        )
    return _gate(
        "machine_mandate_spend", False,
        f"max_effect_budget {requested} exceeds mandate ceiling {scope_max_spend_minor} — DENY",
    )
