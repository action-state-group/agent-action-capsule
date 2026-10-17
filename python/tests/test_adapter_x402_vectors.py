# SPDX-License-Identifier: BSD-3-Clause
"""The x402 adapter v0 vectors are reproducible and agree with spec/adapters/x402-v0.md.

The generator writes the expected reports by hand. This test re-runs it and
requires byte-identical output, checks its Keccak-256 and secp256k1 against
published values, verifies the positive signature with ``cryptography``'s
ECDSA, and derives every report with an independent reading of the
declaration (sections 5 to 7), comparing it with the stated expectation.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, encode_dss_signature

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "vectors" / "adapters" / "x402"
GENERATOR = ROOT / "python" / "scripts" / "generate_adapter_x402_vectors.py"
HAND_WRITTEN = ("README.md",)

_spec = importlib.util.spec_from_file_location("generate_adapter_x402_vectors", GENERATOR)
gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen)

CASES = json.loads((VECTORS / "cases.json").read_text(encoding="utf-8"))


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _files(directory: Path) -> list[str]:
    return sorted(p.relative_to(directory).as_posix() for p in directory.rglob("*") if p.is_file())


# ---------------------------------------------------------------------------
# Reproducibility
# ---------------------------------------------------------------------------


def test_generator_reproduces_every_file_byte_for_byte(tmp_path):
    for name in HAND_WRITTEN:
        shutil.copyfile(VECTORS / name, tmp_path / name)
    subprocess.run([sys.executable, str(GENERATOR), "--out", str(tmp_path)], check=True)
    assert _files(tmp_path) == _files(VECTORS)
    for name in _files(VECTORS):
        assert (tmp_path / name).read_bytes() == (VECTORS / name).read_bytes(), name


def test_sha256sums_and_manifest_pin_every_file():
    listed = dict(reversed(line.split("  ", 1)) for line in
                  (VECTORS / "SHA256SUMS").read_text(encoding="utf-8").splitlines())
    assert set(listed) == set(_files(VECTORS)) - {"SHA256SUMS"}
    for name, digest in listed.items():
        assert _sha((VECTORS / name).read_bytes()) == digest, name
    manifest = json.loads((VECTORS / "manifest.json").read_text(encoding="utf-8"))
    assert {f["path"] for f in manifest["files"]} == set(_files(VECTORS)) - {"SHA256SUMS", "manifest.json",
                                                                              *HAND_WRITTEN}
    for entry in manifest["files"]:
        assert _sha((VECTORS / entry["path"]).read_bytes()) == entry["sha256"], entry["path"]


def test_top_level_registers_the_directory():
    top = dict(reversed(line.split("  ", 1)) for line in
               (ROOT / "vectors" / "SHA256SUMS").read_text(encoding="utf-8").splitlines())
    for name in _files(VECTORS):
        if name != "SHA256SUMS":
            assert top.get(f"adapters/x402/{name}") == _sha((VECTORS / name).read_bytes()), name
    corpora = json.loads((ROOT / "vectors" / "manifest.json").read_text(encoding="utf-8"))["corpora"]
    assert corpora["adapter_x402"] == "adapters/x402/manifest.json"


# ---------------------------------------------------------------------------
# The generator's primitives against published values
# ---------------------------------------------------------------------------


def test_keccak256_known_values():
    assert gen.keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    # The ERC-20 Transfer event topic.
    assert gen.TRANSFER_TOPIC == "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"


def test_development_key_is_the_documented_account():
    key = CASES["development_key"]
    point = gen._mul(int(key["private_key"], 16), gen.G)
    assert gen.address_of(point) == key["address"] == "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"


def test_x402_specification_example_recovers_to_its_payer():
    # x402 v2 specification 5.2.1 (x402-foundation/x402 at faa1c694c66a3732aaabbce93bdae140e521a67d): an
    # independent check of the EIP-712 encoding and the recovery, under the domain the policy names.
    authorization = {"from": "0x857b06519E91e3A54538791bDbb0E22373e36b66",
                     "to": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C", "value": "10000",
                     "validAfter": "1740672089", "validBefore": "1740672154",
                     "nonce": "0xf3746613c2d920b5fdabc0856f2aeb2d4f88ee6037b8cc5d04a71a4462f13480"}
    signature = bytes.fromhex("2d6a7588d6acca505cbf0d9a4a227e0c52c6c34008c8e8986a1283259764173608a2ce6496642e3"
                              "77d6da8dbbf5836e9bd15092f9ecab05ded3d6293af148b571c")
    assert gen.recover(gen.eip712_digest(gen.DOMAIN, authorization), signature) == authorization["from"]


def test_recovery_normalizes_v_zero_and_one():
    digest = gen.eip712_digest(gen.DOMAIN, gen.authorization())
    signature = gen.sign(gen.DEV_KEY, digest)
    lowered = signature[:64] + bytes([signature[64] - 27])
    assert gen.recover(digest, lowered) == gen.recover(digest, signature) == gen.PAYER


def _ecdsa_verifies(digest: bytes, signature: bytes) -> bool:
    public = ec.derive_private_key(gen.DEV_KEY, ec.SECP256K1()).public_key()
    der = encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:64], "big"))
    try:
        public.verify(der, digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    except InvalidSignature:
        return False
    return True


# ---------------------------------------------------------------------------
# An independent reading of x402-v0.md §5 to §7
# ---------------------------------------------------------------------------


def _parse(octets: bytes) -> dict | None:
    def no_duplicates(pairs):
        keys = [k for k, _ in pairs]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate member")
        return dict(pairs)

    try:
        return json.loads(octets.decode("utf-8"), object_pairs_hook=no_duplicates)
    except ValueError:
        return None


def _domain(policy: dict, accepted: dict) -> dict | None:
    for entry in policy["domains"]:
        if entry["network"] == accepted["network"] and entry["asset"].lower() == accepted["asset"].lower():
            return {k: entry[k] for k in ("name", "version", "chainId", "verifyingContract")}
    return None


def _same_address(a: str, b: str) -> bool:
    return bytes.fromhex(a[2:]) == bytes.fromhex(b[2:])


def _word_address(topic: str) -> str:
    return "0x" + topic[-40:]


def _evaluate(case: dict) -> dict[str, str]:
    inputs, policy = case["inputs"], case["policy"]
    octets = {w["type"]: (VECTORS / w["octets"]).read_bytes() for w in inputs["wrapped"]}
    lookup = json.loads((VECTORS / inputs["lookup"]).read_text(encoding="utf-8")) if inputs["online"] else None
    out: dict[str, str] = {}

    payload = _parse(octets[gen.PAYLOAD])
    out["payload_form"] = "PASS" if payload is not None else "FAIL"
    accepted, auth = payload["accepted"], payload["payload"]["authorization"]

    # §5.1: the domain comes from the policy, never from accepted.extra.
    domain = _domain(policy, accepted)
    signature = bytes.fromhex(payload["payload"]["signature"][2:])
    if domain is None or len(signature) != 65:
        out["payer_signature"] = "NOT_CHECKED"
    else:
        recovered = gen.recover(gen.eip712_digest(domain, auth), signature)
        if recovered is not None and _same_address(recovered, auth["from"]):
            out["payer_signature"] = "PASS"
        elif policy["signer"] == "eoa" or (lookup is not None and lookup.get("code_at_payer") == "0x"):
            out["payer_signature"] = "FAIL"
        else:
            out["payer_signature"] = "INCONCLUSIVE"

    payers = {p["address"].lower() for p in policy["payers"]}
    out["payer_trust"] = "PASS" if auth["from"].lower() in payers else "INCONCLUSIVE"
    out["asset_trust"] = "PASS" if domain is not None else "INCONCLUSIVE"

    terms = _same_address(auth["to"], accepted["payTo"]) and auth["value"] == accepted["amount"]
    out["authorization_terms"] = "PASS" if terms else "FAIL"

    # §6.1: strict window at the settling block's timestamp; offline NOT_CHECKED.
    settle = _parse(octets[gen.SETTLE])
    if not settle["transaction"]:
        out["authorization_window"] = "NOT_PRESENT"
    elif lookup is None:
        out["authorization_window"] = "NOT_CHECKED"
    else:
        t = int(lookup["block"]["timestamp"], 16)
        inside = int(auth["validAfter"]) < t < int(auth["validBefore"])
        out["authorization_window"] = "PASS" if inside else "FAIL"

    well_formed = (settle is not None and isinstance(settle.get("success"), bool)
                   and isinstance(settle.get("network"), str) and isinstance(settle.get("transaction"), str))
    out["settle_response_form"] = "PASS" if well_formed else "FAIL"
    joined = settle["network"] == accepted["network"] and ("payer" not in settle
                                                           or _same_address(settle["payer"], auth["from"]))
    out["settle_response_join"] = "PASS" if joined else "FAIL"
    out["settle_response_signature"] = "NOT_PRESENT"

    if not settle["transaction"]:
        out["settlement_onchain"] = "NOT_PRESENT"
    elif lookup is None:
        out["settlement_onchain"] = "NOT_CHECKED"
    else:
        receipt = lookup["transaction_receipt"]
        logs = [log for log in receipt["logs"] if _same_address(log["address"], accepted["asset"])]
        transfer = any(log["topics"][0] == gen.TRANSFER_TOPIC
                       and _same_address(_word_address(log["topics"][1]), auth["from"])
                       and _same_address(_word_address(log["topics"][2]), auth["to"])
                       and int(log["data"], 16) == int(auth["value"]) for log in logs)
        used = any(log["topics"][0] == gen.AUTHORIZATION_USED_TOPIC
                   and _same_address(_word_address(log["topics"][1]), auth["from"])
                   and log["topics"][2] == auth["nonce"] for log in logs)
        settled = receipt["transactionHash"] == settle["transaction"] and receipt["status"] == "0x1"
        out["settlement_onchain"] = "PASS" if settled and transfer and used else "FAIL"

    has_receipt = "offer-receipt" in settle.get("extensions", {})
    for check in ("receipt_signature", "receipt_signer_authorized", "delivery_binding"):
        assert not has_receipt, "receipt cases are not in this corpus"
        out[check] = "NOT_PRESENT"
    return out


@pytest.mark.parametrize("case", CASES["cases"], ids=lambda c: c["name"])
def test_wrapped_digests_and_informative_headers(case):
    for wrapped in case["inputs"]["wrapped"]:
        octets = (VECTORS / wrapped["octets"]).read_bytes()
        assert wrapped["digest_alg"] == "SHA-256"
        assert wrapped["digest"] == _sha(octets)
    # §4: the transport decoding step, checked once per file.
    headers = case["inputs"]["informative"]
    octets = {w["type"]: (VECTORS / w["octets"]).read_bytes() for w in case["inputs"]["wrapped"]}
    assert base64.b64decode((VECTORS / headers["PAYMENT-SIGNATURE"]).read_bytes(), validate=True) == \
        octets[gen.PAYLOAD]
    assert base64.b64decode((VECTORS / headers["PAYMENT-RESPONSE"]).read_bytes(), validate=True) == \
        octets[gen.SETTLE]


@pytest.mark.parametrize("case", CASES["cases"], ids=lambda c: c["name"])
def test_expected_reports_follow_the_declaration(case):
    stated = {r["detail"]["check"]: r["status"] for r in case["expect"]["reports"]}
    assert stated == _evaluate(case)
    for report in case["expect"]["reports"]:
        assert report["property"] == "native_check"
        assert report["detail"]["object"] == gen.OBJECT_OF[report["detail"]["check"]]


def test_positive_signature_verifies_under_independent_ecdsa():
    case = next(c for c in CASES["cases"] if c["name"] == "positive")
    payload = json.loads((VECTORS / case["inputs"]["wrapped"][0]["octets"]).read_bytes())
    digest = gen.eip712_digest(_domain(case["policy"], payload["accepted"]), payload["payload"]["authorization"])
    assert _ecdsa_verifies(digest, bytes.fromhex(payload["payload"]["signature"][2:]))


def test_native_check_fails_mutates_a_signed_member():
    # §6.1: value is inside the signed message, so the signature and the terms both FAIL.
    case = next(c for c in CASES["cases"] if c["name"] == "native-check-fails")
    stated = {r["detail"]["check"]: r["status"] for r in case["expect"]["reports"]}
    assert stated["payer_signature"] == stated["authorization_terms"] == "FAIL"
    assert case["policy"]["signer"] == "eoa"
    payload = json.loads((VECTORS / case["inputs"]["wrapped"][0]["octets"]).read_bytes())
    digest = gen.eip712_digest(_domain(case["policy"], payload["accepted"]), payload["payload"]["authorization"])
    assert not _ecdsa_verifies(digest, bytes.fromhex(payload["payload"]["signature"][2:]))
    rows = {(r["row"], r["sufficiency"], r["verdict"]) for r in case["expect"]["requirements"]}
    assert rows == {(5, "SATISFIED", "not_met"), (6, "INSUFFICIENT", "not_evaluable")}


def test_default_policy_reports_a_mismatch_as_inconclusive_unless_code_lookup_shows_none():
    # §6.1: under eoa-or-contract the same mutant is INCONCLUSIVE offline, and FAIL only when the
    # recorded code lookup shows no code at `from`.
    case = next(c for c in CASES["cases"] if c["name"] == "native-check-fails")
    relaxed = {**case, "policy": {**case["policy"], "signer": "eoa-or-contract"}}
    offline = {**relaxed, "inputs": {**relaxed["inputs"], "online": False}}
    assert _evaluate(offline)["payer_signature"] == "INCONCLUSIVE"
    assert json.loads((VECTORS / case["inputs"]["lookup"]).read_bytes())["code_at_payer"] == "0x"
    assert _evaluate(relaxed)["payer_signature"] == "FAIL"


def test_offline_window_and_settlement_are_not_checked():
    # §6.4: without the recorded lookup, the window and the settlement are NOT_CHECKED.
    case = next(c for c in CASES["cases"] if c["name"] == "positive")
    offline = {**case, "inputs": {**case["inputs"], "online": False}}
    result = _evaluate(offline)
    assert result["authorization_window"] == result["settlement_onchain"] == "NOT_CHECKED"
