# SPDX-License-Identifier: BSD-3-Clause
"""Python-side checks for behaviour aligned with the Go, Rust and TS verifiers."""
from __future__ import annotations

import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_action_capsule.bundle import _safe_int
from agent_action_capsule.producer_envelope import CONTENT_TYPE, verify_producer_envelope

KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
PAYLOAD = bytes(range(32, 64))


def _envelope(protected: dict) -> bytes:
    protected_bytes = cbor2.dumps(protected, canonical=True)  # minimal float encoding
    sig = KEY.sign(cbor2.dumps(["Signature1", protected_bytes, b"", PAYLOAD]))
    return cbor2.dumps(cbor2.CBORTag(18, [protected_bytes, {}, PAYLOAD, sig]))


def test_envelope_label_and_alg_types_are_checked():
    kid = KEY.public_key().public_bytes_raw()
    assert verify_producer_envelope(PAYLOAD.hex(), _envelope({1: -8, 3: CONTENT_TYPE, 4: kid})).ok
    # True == 1 and -8.0 == -8 in Python; neither is the CBOR integer the profile requires.
    boolean = verify_producer_envelope(PAYLOAD.hex(), _envelope({True: -8, 3: CONTENT_TYPE, 4: kid}))
    assert [f.code for f in boolean.findings] == ["envelope_malformed"]
    floated = verify_producer_envelope(PAYLOAD.hex(), _envelope({1: -8.0, 3: CONTENT_TYPE, 4: kid}))
    assert [f.code for f in floated.findings] == ["envelope_algorithm_mismatch"]


def test_bundle_integers_are_bounded_like_the_other_verifiers():
    assert _safe_int(2**53 - 1) and _safe_int(-(2**53 - 1)) and _safe_int(0)
    assert not _safe_int(2**53)
    assert not _safe_int(True)
    assert not _safe_int(2.0)
