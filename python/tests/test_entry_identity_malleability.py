# SPDX-License-Identifier: BSD-3-Clause
"""compute_capsule_id (§5.1) must be immune to ECDSA signature malleability.

An ECDSA signature is not a function of the act it signs: for any valid
``(r, s)``, ``(r, n-s)`` also verifies (SEC1 v2.0 SS4.1.3). See
entry-identity-second-rule-sweep census: capsule_id is the JSON-DIGEST of the
capsule dict minus ``capsule_id``/``chain`` fields, and the capsule schema
never embeds a raw signature — the Capsule's content is signed *indirectly*
by anchoring its capsule_id as a COSE Signed Statement payload
(``agent_action_capsule.anchor.submit_anchor``), not by embedding a
signature inside the Capsule itself. That makes capsule_id architecturally
immune: it is computed before, and independently of, any signature.

This test makes the immunity concrete: two different signed-statement
encodings anchoring the SAME capsule_id (a real malleated ECDSA twin) leave
capsule_id completely unchanged, while a negative control shows capsule_id
DOES change for a genuinely different capsule.
"""
from __future__ import annotations

import hashlib

import cbor2
import pytest
from agent_action_capsule import compute_capsule_id

pytest.importorskip("scitt_cose", reason="scitt-cose not installed (agent-action-capsule[anchor] extra)")

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from scitt_cose.cose_sign1 import sign_sign1, verify_sign1  # noqa: E402

# NIST P-256 (secp256r1) group order (SEC2 SS2.4.2).
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

_CAPSULE = {
    "spec_version": "draft-mih-scitt-agent-action-capsule-02",
    "format_version": "2",
    "action_id": "act-1",
    "action_type": "fyi",
    "operator": "org-a",
    "developer": "agent-a@v1",
    "timestamp": "2026-08-18T00:00:00Z",
}


def _ec_key_pem() -> tuple[bytes, bytes]:
    key = ec.generate_private_key(ec.SECP256R1())
    priv_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem


def _malleate(statement: bytes) -> bytes:
    """Flip s -> n-s in an ES256 COSE_Sign1 message, keeping everything else."""
    tag = cbor2.loads(statement)
    protected_bstr, unprotected, payload, signature = tag.value
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    s_twin = _P256_N - s
    assert s != s_twin
    sig_twin = r.to_bytes(32, "big") + s_twin.to_bytes(32, "big")
    return cbor2.dumps(cbor2.CBORTag(tag.tag, [protected_bstr, unprotected, payload, sig_twin]))


def test_capsule_id_unaffected_by_malleated_anchoring_statement():
    """capsule_id never even looks at the signature that anchors it."""
    capsule_id = compute_capsule_id(_CAPSULE)

    priv_pem, pub_pem = _ec_key_pem()
    statement = sign_sign1(capsule_id.encode("ascii"), alg="ES256", private_key_pem=priv_pem)
    twin = _malleate(statement)
    assert statement != twin

    # Both are valid signed statements anchoring the SAME capsule_id.
    verify_sign1(statement, public_key_pem=pub_pem)
    verify_sign1(twin, public_key_pem=pub_pem)

    # Recomputing capsule_id from the untouched capsule dict is invariant —
    # it was never a function of either statement's signature bytes.
    assert compute_capsule_id(_CAPSULE) == capsule_id

    # Documented for contrast: the anchor's own entry_hash cross-check IS a
    # leaf-commitment digest and DOES change across the twin (expected — see
    # anchor.py:270 and the corrected hardening-review.md L2).
    assert hashlib.sha256(statement).hexdigest() != hashlib.sha256(twin).hexdigest()


def test_negative_control_different_capsule_is_a_different_id():
    """A genuinely different capsule MUST produce a different capsule_id —
    without this, the invariance assertion above would also pass for a
    constant function and prove nothing."""
    other = dict(_CAPSULE, action_id="act-2")
    assert compute_capsule_id(_CAPSULE) != compute_capsule_id(other)
