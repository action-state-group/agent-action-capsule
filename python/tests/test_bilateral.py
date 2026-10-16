# SPDX-License-Identifier: BSD-3-Clause
"""Tests for agent_action_capsule.bilateral — pair-verify."""
from __future__ import annotations

from _capsules import sealed

from agent_action_capsule import Chain, ModelAttestation
from agent_action_capsule.bilateral import verify_pair


def _make_capsule(
    operator: str = "org-a",
    developer: str = "agent@v1",
    action_digest: str = "abc123",
    use_subject_digest: bool = False,
    prior_capsule_id: str | None = None,
    chain_relation: str | None = None,
) -> dict:
    digest_key = "subject_digest" if use_subject_digest else "action_digest"
    chain = None
    if prior_capsule_id is not None:
        chain = Chain(parent_capsule_id=prior_capsule_id, relation=chain_relation or "follows")
    return sealed(
        operator=operator,
        developer=developer,
        model_attestation=ModelAttestation(
            compute_attestation={digest_key: action_digest, "role": "requester"}
        ),
        chain=chain,
    )


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_verify_pair_ok():
    cap_a = _make_capsule("org-a", action_digest="deadbeef" * 8)
    cap_b = _make_capsule(
        "org-b",
        action_digest="deadbeef" * 8,
        prior_capsule_id=cap_a["capsule_id"],
        chain_relation="confirms",
    )
    pvr = verify_pair(cap_a, cap_b)
    assert pvr.ok
    assert pvr.shared_digest == "deadbeef" * 8
    assert pvr.capsule_id_a == cap_a["capsule_id"]
    assert pvr.capsule_id_b == cap_b["capsule_id"]


def test_verify_pair_subject_digest_key():
    """Accepts subject_digest (aauth-interop naming) as well as action_digest."""
    cap_a = _make_capsule("org-a", action_digest="digest1" * 8, use_subject_digest=True)
    cap_b = _make_capsule("org-b", action_digest="digest1" * 8, use_subject_digest=True)
    pvr = verify_pair(cap_a, cap_b)
    assert pvr.ok
    assert pvr.shared_digest is not None


# ---------------------------------------------------------------------------
# Digest mismatch
# ---------------------------------------------------------------------------


def test_verify_pair_digest_mismatch():
    cap_a = _make_capsule("org-a", action_digest="digest-a" * 8)
    cap_b = _make_capsule("org-b", action_digest="digest-b" * 8)
    pvr = verify_pair(cap_a, cap_b)
    assert not pvr.ok
    checks = [f.check for f in pvr.findings]
    assert "shared_digest" in checks


def test_verify_pair_no_digest_is_warning_not_error():
    """Missing digest on both sides is a warning, not an error."""
    cap_a = sealed(operator="org-a", developer="agent@v1")
    cap_b = sealed(operator="org-b", developer="agent@v1")
    pvr = verify_pair(cap_a, cap_b)
    assert pvr.ok  # warnings don't fail
    warnings = [f for f in pvr.findings if f.severity == "warning"]
    assert any("shared_digest" in f.check for f in warnings)


# ---------------------------------------------------------------------------
# Chain linkage
# ---------------------------------------------------------------------------


def test_verify_pair_wrong_chain_parent():
    cap_a = _make_capsule("org-a", action_digest="deadbeef" * 8)
    # Use a valid 64-hex string that is NOT cap_a's capsule_id
    fake_parent = "a" * 64
    cap_b = _make_capsule(
        "org-b",
        action_digest="deadbeef" * 8,
        prior_capsule_id=fake_parent,
        chain_relation="confirms",
    )
    pvr = verify_pair(cap_a, cap_b)
    assert not pvr.ok
    checks = [f.check for f in pvr.findings]
    assert "chain_linkage" in checks


def test_verify_pair_no_chain_is_ok():
    """No chain linkage is fine — chain is optional."""
    cap_a = _make_capsule("org-a", action_digest="deadbeef" * 8)
    cap_b = _make_capsule("org-b", action_digest="deadbeef" * 8)
    pvr = verify_pair(cap_a, cap_b)
    assert pvr.ok


# ---------------------------------------------------------------------------
# Distinct orgs
# ---------------------------------------------------------------------------


def test_verify_pair_same_operator_warns():
    """Same operator on both capsules is a warning (not an error)."""
    cap_a = _make_capsule("same-org", action_digest="deadbeef" * 8)
    cap_b = _make_capsule("same-org", action_digest="deadbeef" * 8)
    pvr = verify_pair(cap_a, cap_b)
    assert pvr.ok  # warning only
    warnings = [f for f in pvr.findings if f.severity == "warning"]
    assert any("distinct_orgs" in f.check for f in warnings)


# ---------------------------------------------------------------------------
# Individual verify failure
# ---------------------------------------------------------------------------


def test_verify_pair_tampered_capsule():
    """If one capsule fails Class-1 verify, the pair fails."""
    cap_a = _make_capsule("org-a", action_digest="deadbeef" * 8)
    cap_b = _make_capsule("org-b", action_digest="deadbeef" * 8)
    # Tamper with cap_a
    cap_a["operator"] = "tampered-org"
    pvr = verify_pair(cap_a, cap_b)
    assert not pvr.ok
