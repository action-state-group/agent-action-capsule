# SPDX-License-Identifier: BSD-3-Clause
"""``agent_action_capsule.witness`` edges the strict Bundle vectors do not reach."""
from __future__ import annotations

import pytest

pytest.importorskip("scitt_cose")

from agent_action_capsule.witness import (  # noqa: E402
    binding_of,
    endpoint_of,
    row_for,
    row_public_keys_pem,
    verify_receipt,
    verify_scrapi_receipt,
    verify_witness_receipts,
)

SIGNED = {"log_id": "l", "mmr_size": 1, "root": "00" * 32, "prev_size": 0, "prev_root": "",
          "key_id": "11" * 32, "timestamp": "2026-10-15T00:00:00Z"}


def test_bindings_and_endpoints_come_from_the_url_scheme():
    assert binding_of("https://w.example/") == "cll"
    assert binding_of("REKOR+https://r.example") == "rekor"
    assert binding_of("scrapi+https://s.example") == "scrapi"
    assert binding_of("not a url") == "cll"
    assert endpoint_of("scrapi+https://s.example/") == "https://s.example"


def test_row_lookup_ignores_rows_of_another_binding_and_malformed_rows():
    directory = {"witnesses": ["junk", {"endpoint": "https://s.example/", "binding": "scrapi", "key_ids": []}]}
    assert row_for(directory, "https://s.example") is None
    assert row_for(directory, "scrapi+https://s.example") is not None
    assert row_for(None, "https://s.example") is None
    assert row_for([{"endpoint": "https://s.example"}], "https://s.example/") is not None


def test_a_rekor_row_key_id_without_its_public_key_is_refused():
    with pytest.raises(ValueError):
        row_public_keys_pem({"name": "r", "binding": "rekor", "key_ids": ["22" * 32]})
    assert len(row_public_keys_pem({"key_ids": ["22" * 32]})) == 1


def test_rekor_and_scrapi_receipts_need_the_checkpoint_cose():
    record = {"ts_url": "rekor+https://r.example", "receipt_b64": "", "entry_hash": "", "leaf_index": 0, "tree_size": 1}
    assert verify_receipt(SIGNED, record, b"", None) == (
        False, "not checked: checkpoint COSE statement not available", None)


def test_scrapi_without_a_pinned_key_checks_nothing():
    assert verify_scrapi_receipt(b"", checkpoint_cose=b"x", service_public_key_pem=None)[0] is False


def test_unreadable_receipts_fail_and_never_raise():
    directory = {"witnesses": [{"endpoint": "https://r.example", "binding": "rekor", "key_ids": ["22" * 32],
                                "public_keys": ["not base64!"]}]}
    record = {"ts_url": "rekor+https://r.example", "receipt_b64": "%%%", "entry_hash": "", "leaf_index": 0,
              "tree_size": 1}
    status, findings, receipts = verify_witness_receipts([record], SIGNED, b"cose", directory)
    assert status == "withheld" and receipts[0].reason.startswith("not checked: unusable key")


def test_a_non_object_bundle_is_invalid_in_strict_mode():
    from agent_action_capsule.bundle import verify_bundle

    result = verify_bundle([1], strict=True)
    assert result.verdict == "INVALID" and result.kind_ok is False
    assert verify_bundle([1]).verdict is None


def test_row_key_lists_and_ids_are_typed():
    with pytest.raises(ValueError):
        row_public_keys_pem({"key_ids": {"22" * 32: 1}})
    with pytest.raises(ValueError):
        row_public_keys_pem({"key_ids": [" " + "22" * 32]})
    assert len(row_public_keys_pem({"key_ids": ["22" * 32], "public_keys": ["not base64!"]})) == 1


@pytest.mark.parametrize("protected", [{1: -8, 395: True}, {1: -8, 395: 1.0}, {1: -35, 395: 1}, {1: True, 395: 1}])
def test_receipt_vds_and_alg_are_integers(protected):
    import cbor2

    from agent_action_capsule.witness import _receipt_shape_error

    assert _receipt_shape_error(cbor2.dumps(cbor2.CBORTag(18, [cbor2.dumps(protected), {}, None, b""]))) is not None


def test_record_signature_hex_has_no_whitespace():
    from agent_action_capsule.producer_envelope import verify_record_signature

    verdict, _ = verify_record_signature({"capsule_id": "00" * 32, "signature": "d2 84", "key_id": "11" * 32})
    assert verdict == "invalid"


def test_a_rekor_payload_hash_must_say_sha256():
    import base64
    import json
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
    import generate_bundle_strict_vectors as g

    from agent_action_capsule.witness import verify_rekor_receipt

    cose = b"checkpoint statement"
    good = json.loads(base64.b64decode(g.rekor_receipt(cose)["receipt_b64"]))
    pem = g.spki_pem(g.REKOR_KEY)
    key_id = g.raw_public(g.LOG_KEY).hex()
    assert verify_rekor_receipt(good, checkpoint_cose=cose, checkpoint_key_id=key_id, rekor_public_key_pem=pem)[0]
    body = json.loads(base64.b64decode(good["body"]))
    body["spec"]["payloadHash"]["algorithm"] = "sha512"
    relabeled = {**good, "body": base64.b64encode(g._sorted_json(body)).decode()}
    ok, _ = verify_rekor_receipt(relabeled, checkpoint_cose=cose, checkpoint_key_id=key_id, rekor_public_key_pem=pem)
    assert not ok


def test_a_rekor_key_must_be_p256():
    import base64
    import json
    import sys
    from pathlib import Path

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
    import generate_bundle_strict_vectors as g

    from agent_action_capsule.witness import verify_rekor_receipt

    cose = b"checkpoint statement"
    entry = json.loads(base64.b64decode(g.rekor_receipt(cose)["receipt_b64"]))
    p384 = ec.derive_private_key(7, ec.SECP384R1())
    der = p384.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    entry["logID"] = __import__("hashlib").sha256(der).hexdigest()
    signed = {k: entry[k] for k in ("body", "integratedTime", "logID", "logIndex")}
    signature = p384.sign(g._sorted_json(signed), ec.ECDSA(hashes.SHA256()))
    entry["verification"] = {"signedEntryTimestamp": base64.b64encode(signature).decode()}
    pem = p384.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    ok, reason = verify_rekor_receipt(entry, checkpoint_cose=cose, checkpoint_key_id=g.raw_public(g.LOG_KEY).hex(),
                                      rekor_public_key_pem=pem)
    assert not ok and "P-256" in reason


def test_base64_with_non_zero_trailing_bits_is_refused():
    from agent_action_capsule.witness import _b64_canonical

    assert _b64_canonical("QQ==") == b"A"
    for text in ("QR==", "QQ", "Q Q==", "QQ==\n"):
        with pytest.raises(ValueError):
            _b64_canonical(text)


def test_deeply_nested_receipt_json_fails_and_never_raises():
    import base64

    record = {"ts_url": "rekor+https://r.example", "entry_hash": "", "leaf_index": 0, "tree_size": 1,
              "receipt_b64": base64.b64encode(b"[" * 100000 + b"]" * 100000).decode()}
    ok, reason, _ = verify_receipt(SIGNED, record, b"", b"cose")
    assert not ok and reason.startswith("unreadable receipt")


def test_a_public_key_that_is_not_spki_is_skipped():
    import base64

    row = {"key_ids": ["22" * 32], "public_keys": [base64.b64encode(b"not a key").decode()]}
    assert len(row_public_keys_pem(row)) == 1


def test_only_ed25519_and_ec_public_keys_count():
    import base64
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
    import generate_bundle_strict_vectors as g

    for spki in (g.RSA_SPKI, g.UNKNOWN_SPKI):
        import hashlib

        key_id = hashlib.sha256(spki).hexdigest()
        with pytest.raises(ValueError):  # a rekor row left without its key
            row_public_keys_pem({"binding": "rekor", "key_ids": [key_id], "public_keys": [base64.b64encode(spki).decode()]})
    p256 = g.spki_der(g.P256_WITNESS)
    row = {"binding": "rekor", "key_ids": [__import__("hashlib").sha256(p256).hexdigest()],
           "public_keys": [base64.b64encode(p256).decode()]}
    assert len(row_public_keys_pem(row)) == 1


def test_input_nested_beyond_the_interpreter_is_refused_not_raised():
    import copy
    import json
    from pathlib import Path

    from agent_action_capsule.bundle import verify_bundle
    from agent_action_capsule.producer_envelope import verify_record_signature

    vectors = json.loads((Path(__file__).resolve().parents[2] / "vectors" / "bundle" / "strict" / "vectors.json").read_text())
    bundle = copy.deepcopy(vectors["cases"][0]["bundle"])
    deep: list = []
    cursor = deep
    for _ in range(5000):
        cursor.append([])
        cursor = cursor[0]
    bundle["records"][0]["x_deep"] = deep
    assert verify_record_signature(bundle["records"][0])[0] == "invalid"
    assert verify_bundle(bundle).graph_closure.findings == ("bundle_malformed",)
    assert verify_bundle(bundle, strict=True).verdict == "INVALID"
