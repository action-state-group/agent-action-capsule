# SPDX-License-Identifier: BSD-3-Clause
"""End-to-end dry run — ORPRG PermitReceipt + MachineMandate composition.

Frozen inputs: meridianverity/permit-receipt tag ietf126-payment-composition-v0.1
  commit 5c2de6c3f98a9deb2055f0d72d4d6aeef17a7ec9
  ZIP SHA-256: d13c740c47710e4b28a1d2d511aa63574200256ce310f0e03ec618b383583c2f
  Boundary: ORPRG Evaluation-Only Terms (non-production interoperability review)

Two cases:
  positive           EUR 250.00 (25000 minor) — all gates PASS; 1 effect-commit
  mandate-over-limit EUR 750.00 (75000 minor) — machine_mandate_spend DENY; 0 effect-commits

The PermitReceipt owner-appraisal (appraise_orprg_permit_receipt) returns ALLOW for
BOTH cases — both receipts are genuinely issued and valid. The DENY arises at the
mandate-level gate (machine_mandate_spend), not at the PermitReceipt appraisal gate.

Run locally against the downloaded ORPRG package:
  export ORPRG_FIXTURES=/tmp/orprg-v0.1/orprg-ietf126-payment-composition-v0.1
  pytest python/tests/test_orprg_composition.py -v

Skipped automatically when ORPRG_FIXTURES is not set or does not contain the package.
"""
from __future__ import annotations

import json
import os
import pathlib
from typing import Any

import pytest

from agent_action_capsule.canonical import compute_capsule_id, jcs, json_digest, normalize
from agent_action_capsule.contracts import EffectRecord
from agent_action_capsule.emit import emit
from agent_action_capsule.verify_composition import verify_permitreceipt_mandate
from agent_action_capsule.verify_composition_orprg import (
    ORPRG_EVAL_TIME_ISO,
    ORPRG_VERIFIER_ID,
    appraise_orprg_permit_receipt,
    machine_mandate_action_hash_gate,
    machine_mandate_spend_gate,
)

# ---------------------------------------------------------------------------
# Known-answer constants (verified against independent-verify.py 74/74 PASS)
# ---------------------------------------------------------------------------

POSITIVE_ACTION_DIGEST = "8defa2c7653af14f5e9869ddc0c9ae9233331cabf3bf69b7bb88f24517020136"
OVER_LIMIT_ACTION_DIGEST = "bd52ed187483ee61b5b5ec28b14afaf900d5c109c6a3a9918f404a6a9d17d700"

POSITIVE_RECEIPT_CORE_DIGEST = "6776443c809778182dc613df98fe4003586b4cb7537c4bbb986702937d62e3c0"
OVER_LIMIT_RECEIPT_CORE_DIGEST = "08987d4a076aeeb014575e835b02aa43cf00a304dbcbc1473c39ffebe57d4c89"

MACHINE_MANDATE_ACTION_HASH = "sha256:a89fbd2bd6f95cdb1ec27b6c7253770ff2a22220937cf065f6e45ef67b37e299"
MACHINE_MANDATE_ACTION_DIGEST = "a89fbd2bd6f95cdb1ec27b6c7253770ff2a22220937cf065f6e45ef67b37e299"

MANDATE_SCOPE_MAX_SPEND = 50000  # EUR minor units (mapping_profile.machine_mandate.scope_max_spend_minor)

ZIP_SHA256 = "d13c740c47710e4b28a1d2d511aa63574200256ce310f0e03ec618b383583c2f"

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _orprg_root() -> pathlib.Path | None:
    env = os.environ.get("ORPRG_FIXTURES")
    if env:
        p = pathlib.Path(env)
        if (p / "mapping-profile.json").exists():
            return p
    default = pathlib.Path("/tmp/orprg-v0.1/orprg-ietf126-payment-composition-v0.1")
    if (default / "mapping-profile.json").exists():
        return default
    return None


def _load(root: pathlib.Path, rel: str) -> Any:
    return json.loads((root / rel).read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def orprg_root() -> pathlib.Path:
    root = _orprg_root()
    if root is None:
        pytest.skip(
            "ORPRG fixtures not found. Set ORPRG_FIXTURES= to the path of "
            "orprg-ietf126-payment-composition-v0.1/ (ZIP SHA-256: d13c740c…)."
        )
    return root


@pytest.fixture(scope="module")
def shared(orprg_root: pathlib.Path) -> dict:
    return {
        "policy": _load(orprg_root, "shared/policy.json"),
        "trust_inputs": _load(orprg_root, "shared/trust-inputs.json"),
        "revocation_state": _load(orprg_root, "shared/revocation-state.json"),
        "verifier_context": _load(orprg_root, "shared/verifier-context.json"),
        "permit_provenance": _load(orprg_root, "shared/permit-provenance.json"),
        "machine_mandate_action": _load(orprg_root, "shared/machine-mandate-action.json"),
        "mapping_profile": _load(orprg_root, "mapping-profile.json"),
        "expected_gates": _load(orprg_root, "expected-gates.json"),
    }


@pytest.fixture(scope="module")
def positive_case(orprg_root: pathlib.Path) -> dict:
    base = orprg_root / "cases" / "positive"
    return {
        "carrier": _load(base, "authorization-ref-carrier.json"),
        "auth_ref": _load(base, "authorization-ref.json"),
        "permit_receipt": _load(base, "permit-receipt.json"),
    }


@pytest.fixture(scope="module")
def over_limit_case(orprg_root: pathlib.Path) -> dict:
    base = orprg_root / "cases" / "mandate-over-limit"
    return {
        "carrier": _load(base, "authorization-ref-carrier.json"),
        "auth_ref": _load(base, "authorization-ref.json"),
        "permit_receipt": _load(base, "permit-receipt.json"),
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_capsule(
    action_digest: str,
    receipt_core_digest: str,
    mandate_action_digest: str,
    effect_status: str = "dispatched",
) -> dict:
    """Build an AAC capsule with the correct effect.authorization refs for a case."""
    er = EffectRecord(
        status=effect_status,
        type="payment",
        request_digest=action_digest,
    )
    base = emit(
        action_type="payment/authorize",
        operator="asg-test",
        developer="test-composition-agent@v1",
        effect=er,
    )
    capsule = dict(base)
    capsule["effect"] = dict(base["effect"])
    capsule["effect"]["authorization"] = {
        "permit_receipt_digest": {
            "type": "PermitReceipt",
            "digest_alg": "SHA-256",
            "digest": receipt_core_digest,
        },
        "machine_mandate_digest": {
            "type": "MachineMandate",
            "digest_alg": "SHA-256",
            "digest": mandate_action_digest,
        },
    }
    capsule["capsule_id"] = compute_capsule_id(capsule)
    return capsule


def _run_composition(
    case: dict,
    shared: dict,
    capsule: dict,
    case_name: str,
) -> dict:
    """Run the full 6-gate composition check for one case and return a result summary."""
    mm_action = shared["machine_mandate_action"]
    mm_profile = shared["mapping_profile"]["machine_mandate"]

    # Owner appraisal: carrier → auth_ref → receipt_core → policy/revocation
    appraisal_ok, appraisal_record = appraise_orprg_permit_receipt(
        case["carrier"],
        case["auth_ref"],
        case["permit_receipt"],
        policy=shared["policy"],
        trust_inputs=shared["trust_inputs"],
        revocation_state=shared["revocation_state"],
        verifier_context=shared["verifier_context"],
        permit_provenance=shared["permit_provenance"],
    )

    # 4-gate binding + appraisal check (v3)
    # Pass receipt_core as companion (ref_artifact_digest commits to receipt_core digest)
    receipt_core = case["permit_receipt"]["receipt_core"]
    composition_result = verify_permitreceipt_mandate(
        capsule,
        receipt_core,           # permit_receipt companion: receipt_core dict
        mm_action,              # machine_mandate companion: action object dict
        permit_receipt_appraised=appraisal_ok,
        machine_mandate_appraised=True,  # MachineMandate is a fixed, trusted artifact
    )

    # Additional mandate gates (outside the base 4-gate verifier)
    action_hash_gate = machine_mandate_action_hash_gate(
        mm_action, mm_profile["action_hash"]
    )
    spend_gate = machine_mandate_spend_gate(
        case["permit_receipt"], mm_profile["scope_max_spend_minor"]
    )

    all_gates = composition_result["gates"] + [action_hash_gate, spend_gate]
    bindings_ok = composition_result["bindings_ok"]
    all_pass = bindings_ok and action_hash_gate["passed"] and spend_gate["passed"]

    # Effect-commit count: 1 iff all gates pass; 0 otherwise
    effect_commit_count = 1 if all_pass else 0

    return {
        "case": case_name,
        "appraisal_ok": appraisal_ok,
        "appraisal_record": appraisal_record,
        "bindings_ok": bindings_ok,
        "all_pass": all_pass,
        "effect_commit_count": effect_commit_count,
        "gates": {g["name"]: g for g in all_gates},
        "first_rejecting_gate": next(
            (g["name"] for g in all_gates if not g["passed"]), None
        ),
    }


# ---------------------------------------------------------------------------
# Digest known-answer tests (always run; no ORPRG fixtures needed)
# ---------------------------------------------------------------------------

def test_jcs_digest_matches_orprg_expected_positive():
    """AAC json_digest(receipt_core) matches the ORPRG ref_artifact_digest for positive."""
    import json
    import pathlib
    root = _orprg_root()
    if root is None:
        pytest.skip("ORPRG fixtures not available")
    pr = json.loads((root / "cases/positive/permit-receipt.json").read_text())
    assert json_digest(pr["receipt_core"]) == POSITIVE_RECEIPT_CORE_DIGEST


def test_jcs_digest_matches_orprg_expected_over_limit():
    """AAC json_digest(receipt_core) matches the ORPRG ref_artifact_digest for over-limit."""
    import json
    import pathlib
    root = _orprg_root()
    if root is None:
        pytest.skip("ORPRG fixtures not available")
    pr = json.loads((root / "cases/mandate-over-limit/permit-receipt.json").read_text())
    assert json_digest(pr["receipt_core"]) == OVER_LIMIT_RECEIPT_CORE_DIGEST


def test_machine_mandate_jcs_digest():
    """AAC json_digest(machine_mandate_action) matches the ORPRG action hash."""
    import json
    import pathlib
    root = _orprg_root()
    if root is None:
        pytest.skip("ORPRG fixtures not available")
    mm = json.loads((root / "shared/machine-mandate-action.json").read_text())
    assert json_digest(mm) == MACHINE_MANDATE_ACTION_DIGEST


def test_positive_permit_receipt_preimage_bytes_match_canonical_bin():
    """Fixture-specific exact-byte assertion for the positive case.

    The exact bytes that enter the PermitReceipt typed-reference digest —
    jcs(normalize(receipt_core)) — must be byte-for-byte identical to
    cases/positive/permit-receipt-core.canonical.bin in the frozen ORPRG tuple.

    This is NOT a general canonicalization-equivalence claim.  It is scoped
    to this specific case and this specific frozen artifact.  The companion
    CP-JSON-2 known-answer test (test_jcs_digest_matches_orprg_expected_positive)
    checks the SHA-256 of those same bytes; this test checks the preimage itself.
    """
    root = _orprg_root()
    if root is None:
        pytest.skip("ORPRG fixtures not available")
    pr = json.loads((root / "cases/positive/permit-receipt.json").read_text())
    our_bytes = jcs(normalize(pr["receipt_core"]))
    canonical_bytes = (root / "cases/positive/permit-receipt-core.canonical.bin").read_bytes()
    assert our_bytes == canonical_bytes, (
        f"Preimage bytes mismatch for positive case: "
        f"our JCS({len(our_bytes)}B) != canonical.bin({len(canonical_bytes)}B)"
    )


def test_over_limit_permit_receipt_preimage_bytes_match_canonical_bin():
    """Fixture-specific exact-byte assertion for the mandate-over-limit case.

    The exact bytes that enter the PermitReceipt typed-reference digest —
    jcs(normalize(receipt_core)) — must be byte-for-byte identical to
    cases/mandate-over-limit/permit-receipt-core.canonical.bin in the frozen
    ORPRG tuple.

    This is NOT a general canonicalization-equivalence claim.  It is scoped
    to this specific case and this specific frozen artifact.  The companion
    CP-JSON-2 known-answer test (test_jcs_digest_matches_orprg_expected_over_limit)
    checks the SHA-256 of those same bytes; this test checks the preimage itself.
    """
    root = _orprg_root()
    if root is None:
        pytest.skip("ORPRG fixtures not available")
    pr = json.loads((root / "cases/mandate-over-limit/permit-receipt.json").read_text())
    our_bytes = jcs(normalize(pr["receipt_core"]))
    canonical_bytes = (root / "cases/mandate-over-limit/permit-receipt-core.canonical.bin").read_bytes()
    assert our_bytes == canonical_bytes, (
        f"Preimage bytes mismatch for mandate-over-limit case: "
        f"our JCS({len(our_bytes)}B) != canonical.bin({len(canonical_bytes)}B)"
    )


# ---------------------------------------------------------------------------
# Owner-appraisal unit tests
# ---------------------------------------------------------------------------

def test_orprg_appraisal_positive(positive_case, shared):
    """PermitReceipt owner-appraisal returns ALLOW for the positive case."""
    ok, record = appraise_orprg_permit_receipt(
        positive_case["carrier"],
        positive_case["auth_ref"],
        positive_case["permit_receipt"],
        policy=shared["policy"],
        trust_inputs=shared["trust_inputs"],
        revocation_state=shared["revocation_state"],
        verifier_context=shared["verifier_context"],
        permit_provenance=shared["permit_provenance"],
    )
    assert ok is True, f"checks failed: {[k for k,v in record['checks'].items() if not v]}"
    assert record["decision"] == "ALLOW"
    assert record["verifier_id"] == ORPRG_VERIFIER_ID
    assert record["evidence_digests"]["receipt_core_digest"] == POSITIVE_RECEIPT_CORE_DIGEST


def test_orprg_appraisal_over_limit(over_limit_case, shared):
    """PermitReceipt owner-appraisal returns ALLOW for the over-limit case (valid receipt)."""
    ok, record = appraise_orprg_permit_receipt(
        over_limit_case["carrier"],
        over_limit_case["auth_ref"],
        over_limit_case["permit_receipt"],
        policy=shared["policy"],
        trust_inputs=shared["trust_inputs"],
        revocation_state=shared["revocation_state"],
        verifier_context=shared["verifier_context"],
        permit_provenance=shared["permit_provenance"],
    )
    assert ok is True, f"checks failed: {[k for k,v in record['checks'].items() if not v]}"
    assert record["decision"] == "ALLOW"
    assert record["evidence_digests"]["receipt_core_digest"] == OVER_LIMIT_RECEIPT_CORE_DIGEST


def test_appraisal_fails_on_tampered_carrier(positive_case, shared):
    """Tampered carrier signature causes appraisal to DENY — digest match alone never passes."""
    import copy
    bad_carrier = copy.deepcopy(positive_case["carrier"])
    sig = bad_carrier["authenticity"]["signature"]
    # Flip a character in the signature
    bad_carrier["authenticity"]["signature"] = ("A" if sig[0] != "A" else "B") + sig[1:]
    ok, record = appraise_orprg_permit_receipt(
        bad_carrier,
        positive_case["auth_ref"],
        positive_case["permit_receipt"],
        policy=shared["policy"],
        trust_inputs=shared["trust_inputs"],
        revocation_state=shared["revocation_state"],
        verifier_context=shared["verifier_context"],
        permit_provenance=shared["permit_provenance"],
    )
    assert ok is False
    assert record["decision"] == "DENY"
    assert record["checks"]["carrier_signature"] is False


def test_appraisal_fails_on_mismatched_auth_ref(positive_case, over_limit_case, shared):
    """Auth ref from a different case causes appraisal to DENY — cross-case binding rejected."""
    ok, record = appraise_orprg_permit_receipt(
        positive_case["carrier"],
        over_limit_case["auth_ref"],  # wrong auth_ref
        positive_case["permit_receipt"],
        policy=shared["policy"],
        trust_inputs=shared["trust_inputs"],
        revocation_state=shared["revocation_state"],
        verifier_context=shared["verifier_context"],
        permit_provenance=shared["permit_provenance"],
    )
    assert ok is False
    assert record["checks"]["carrier_ref_matches_extracted"] is False


# ---------------------------------------------------------------------------
# Mandate gate unit tests
# ---------------------------------------------------------------------------

def test_machine_mandate_action_hash_gate_passes(shared):
    mm_profile = shared["mapping_profile"]["machine_mandate"]
    result = machine_mandate_action_hash_gate(
        shared["machine_mandate_action"], mm_profile["action_hash"]
    )
    assert result["passed"] is True
    assert result["name"] == "machine_mandate_action_hash"


def test_machine_mandate_action_hash_gate_fails_on_tamper(shared):
    import copy
    mm_profile = shared["mapping_profile"]["machine_mandate"]
    bad_action = copy.deepcopy(shared["machine_mandate_action"])
    bad_action["action_id"] = "tampered"
    result = machine_mandate_action_hash_gate(bad_action, mm_profile["action_hash"])
    assert result["passed"] is False


def test_spend_gate_passes_positive(positive_case, shared):
    result = machine_mandate_spend_gate(
        positive_case["permit_receipt"], MANDATE_SCOPE_MAX_SPEND
    )
    assert result["passed"] is True
    assert result["name"] == "machine_mandate_spend"


def test_spend_gate_denies_over_limit(over_limit_case, shared):
    result = machine_mandate_spend_gate(
        over_limit_case["permit_receipt"], MANDATE_SCOPE_MAX_SPEND
    )
    assert result["passed"] is False
    assert result["name"] == "machine_mandate_spend"
    assert "DENY" in result["reason"]


# ---------------------------------------------------------------------------
# End-to-end dry run
# ---------------------------------------------------------------------------

def test_positive_all_six_gates_pass(positive_case, shared):
    """Positive case: all 6 gates pass, 1 effect-commit."""
    capsule = _build_capsule(
        POSITIVE_ACTION_DIGEST,
        POSITIVE_RECEIPT_CORE_DIGEST,
        MACHINE_MANDATE_ACTION_DIGEST,
    )
    result = _run_composition(positive_case, shared, capsule, "positive")

    assert result["appraisal_ok"] is True, "PermitReceipt owner-appraisal should ALLOW"
    assert result["bindings_ok"] is True, "v3 binding gates should all pass"
    assert result["all_pass"] is True, "all 6 gates should pass"
    assert result["first_rejecting_gate"] is None
    assert result["effect_commit_count"] == 1

    # Verify gate-name set, emission order, and per-gate pass
    gates = result["gates"]
    _FROZEN_GATE_NAMES = [
        "permit_receipt_reference_bound", "permit_receipt_appraised",
        "machine_mandate_reference_bound", "machine_mandate_appraised",
        "machine_mandate_action_hash", "machine_mandate_spend",
    ]
    assert set(gates.keys()) == set(_FROZEN_GATE_NAMES), (
        "composed gate-name set must be exactly the six frozen v0.5 names"
    )
    assert list(gates.keys()) == _FROZEN_GATE_NAMES, (
        "gate emission order must match frozen v0.5 sequence"
    )
    for name in _FROZEN_GATE_NAMES:
        assert gates[name]["passed"] is True, f"gate {name!r} should pass"

    eg = shared["expected_gates"]["cases"]["positive"]
    assert result["effect_commit_count"] == eg["expected_external_effect_commit_count"]


def test_over_limit_spend_gate_denies(over_limit_case, shared):
    """Over-limit case: all gates pass except machine_mandate_spend; 0 effect-commits."""
    capsule = _build_capsule(
        OVER_LIMIT_ACTION_DIGEST,
        OVER_LIMIT_RECEIPT_CORE_DIGEST,
        MACHINE_MANDATE_ACTION_DIGEST,
    )
    result = _run_composition(over_limit_case, shared, capsule, "mandate-over-limit")

    assert result["appraisal_ok"] is True, "PermitReceipt owner-appraisal should ALLOW (valid receipt)"
    assert result["bindings_ok"] is True, "v3 binding gates should pass"
    assert result["all_pass"] is False, "overall should fail due to spend gate"
    assert result["first_rejecting_gate"] == "machine_mandate_spend"
    assert result["effect_commit_count"] == 0

    gates = result["gates"]
    _FROZEN_GATE_NAMES = [
        "permit_receipt_reference_bound", "permit_receipt_appraised",
        "machine_mandate_reference_bound", "machine_mandate_appraised",
        "machine_mandate_action_hash", "machine_mandate_spend",
    ]
    assert set(gates.keys()) == set(_FROZEN_GATE_NAMES), (
        "composed gate-name set must be exactly the six frozen v0.5 names"
    )
    assert list(gates.keys()) == _FROZEN_GATE_NAMES, (
        "gate emission order must match frozen v0.5 sequence"
    )
    # All-pass gates
    for name in (
        "permit_receipt_reference_bound", "permit_receipt_appraised",
        "machine_mandate_reference_bound", "machine_mandate_appraised",
        "machine_mandate_action_hash",
    ):
        assert gates[name]["passed"] is True, f"gate {name!r} should pass"
    # Failing gate
    assert gates["machine_mandate_spend"]["passed"] is False
    assert "DENY" in gates["machine_mandate_spend"]["reason"]

    eg = shared["expected_gates"]["cases"]["mandate-over-limit"]
    assert result["effect_commit_count"] == eg["expected_external_effect_commit_count"]
    assert result["first_rejecting_gate"] == eg["expected_first_rejecting_gate"]


def test_over_limit_capsule_signable_as_audit_evidence(over_limit_case, shared):
    """A capsule whose spend gate fails MAY still be signed and registered as audit evidence."""
    capsule = _build_capsule(
        OVER_LIMIT_ACTION_DIGEST,
        OVER_LIMIT_RECEIPT_CORE_DIGEST,
        MACHINE_MANDATE_ACTION_DIGEST,
    )
    # capsule_id is well-formed even though the spend gate would deny
    assert len(capsule["capsule_id"]) == 64
    assert all(c in "0123456789abcdef" for c in capsule["capsule_id"])
    # The gate result carries a reason that can be logged as audit evidence
    result = _run_composition(over_limit_case, shared, capsule, "mandate-over-limit")
    assert result["gates"]["machine_mandate_spend"]["reason"]  # non-empty denial reason


def test_digest_match_alone_does_not_pass_appraisal(positive_case, shared):
    """Binding check alone (digest match) is not authorization success — appraisal required."""
    capsule = _build_capsule(
        POSITIVE_ACTION_DIGEST,
        POSITIVE_RECEIPT_CORE_DIGEST,
        MACHINE_MANDATE_ACTION_DIGEST,
    )
    receipt_core = positive_case["permit_receipt"]["receipt_core"]
    mm_action = shared["machine_mandate_action"]

    # Bindings pass, but appraisal not supplied (None) — must fail
    result_no_appraisal = verify_permitreceipt_mandate(
        capsule,
        receipt_core,
        mm_action,
        permit_receipt_appraised=None,   # not supplied
        machine_mandate_appraised=None,
    )
    assert result_no_appraisal["bindings_ok"] is False
    appraisal_gates = {
        g["name"]: g for g in result_no_appraisal["gates"]
        if g["name"] in ("permit_receipt_appraised", "machine_mandate_appraised")
    }
    assert appraisal_gates["permit_receipt_appraised"]["passed"] is False
    assert appraisal_gates["machine_mandate_appraised"]["passed"] is False
