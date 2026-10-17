# SPDX-License-Identifier: BSD-3-Clause
"""The UCP adapter vectors are reproducible and agree with spec/adapters/ucp-v0.md, section 3.

The generator writes the expectations by hand. This test re-runs it and requires
byte-identical output, checks its deterministic ES256 against RFC 6979 and its key
against RFC 7515 Appendix A.3, and then verifies each case's
``ap2.merchant_authorization`` independently: RFC 8785 from the ``rfc8785`` package,
ECDSA from ``cryptography``, nothing from the generator.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "vectors" / "adapters" / "ucp"
GENERATOR = ROOT / "python" / "scripts" / "generate_ucp_adapter_vectors.py"
HAND_WRITTEN = ("README.md",)
# payment_ap2_mandate.json#/$defs/merchant_authorization, UCP v2026-08-25.
MERCHANT_AUTHORIZATION_PATTERN = re.compile(r"^[A-Za-z0-9_-]+\.\.[A-Za-z0-9_-]+$")
AP2_ALGORITHMS = {"ES256", "ES384", "ES512"}


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _load(name: str) -> dict:
    return json.loads((VECTORS / name).read_text(encoding="utf-8"))


CASES = {case["name"]: case for case in _load("cases.json")["cases"]}


def _generator():
    sys.path.insert(0, str(GENERATOR.parent))
    try:
        import generate_ucp_adapter_vectors
    finally:
        sys.path.pop(0)
    return generate_ucp_adapter_vectors


def _public_key(jwk: dict) -> ec.EllipticCurvePublicKey:
    x = int.from_bytes(_b64u_decode(jwk["x"]), "big")
    y = int.from_bytes(_b64u_decode(jwk["y"]), "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def _es256_valid(jwk: dict, message: bytes, signature: bytes) -> bool:
    if len(signature) != 64:
        return False
    der = encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
    try:
        _public_key(jwk).verify(der, message, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True


def _native_checks(checkout: dict, key_set: dict) -> dict:
    """Section 3(c) of the declaration, steps 1 to 6, as name -> status."""
    statuses = {}
    value = checkout.get("ap2", {}).get("merchant_authorization")
    statuses["ucp.merchant_authorization.present"] = "PASS" if value is not None else "NOT_PRESENT"
    encoded_header, _, encoded_signature = value.partition("..")
    header = json.loads(_b64u_decode(encoded_header))
    form = MERCHANT_AUTHORIZATION_PATTERN.match(value) and {"alg", "kid"} <= header.keys()
    statuses["ucp.merchant_authorization.form"] = "PASS" if form else "FAIL"
    statuses["ucp.merchant_authorization.alg"] = "PASS" if header["alg"] == "ES256" else "FAIL"
    keys = [k for k in key_set["keys"] if k["kid"] == header["kid"] and k.get("use") != "enc"]
    statuses["ucp.merchant_authorization.key"] = "PASS" if len(keys) == 1 else "FAIL"
    payload = {name: member for name, member in checkout.items() if name != "ap2"}
    signing_input = f"{encoded_header}.{_b64u(rfc8785.dumps(payload))}".encode("ascii")
    valid = _es256_valid(keys[0], signing_input, _b64u_decode(encoded_signature))
    statuses["ucp.merchant_authorization.signature"] = "PASS" if valid else "FAIL"
    return statuses


# ---------------------------------------------------------------------------
# Reproducibility
# ---------------------------------------------------------------------------


def test_generator_reproduces_every_file_byte_for_byte(tmp_path):
    for name in HAND_WRITTEN:
        shutil.copyfile(VECTORS / name, tmp_path / name)
    subprocess.run([sys.executable, str(GENERATOR), "--out", str(tmp_path)], check=True, cwd=ROOT / "python")
    produced = sorted(p.name for p in tmp_path.iterdir())
    assert produced == sorted(p.name for p in VECTORS.iterdir())
    for name in produced:
        assert (tmp_path / name).read_bytes() == (VECTORS / name).read_bytes(), name


def test_corpus_is_listed_in_the_top_level_manifest():
    corpora = json.loads((ROOT / "vectors" / "manifest.json").read_text(encoding="utf-8"))["corpora"]
    assert corpora["adapter_ucp"] == "adapters/ucp/manifest.json"


def test_sha256sums_cover_every_file():
    listed = {}
    for line in (VECTORS / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        digest, name = line.split("  ")
        listed[name] = digest
    assert set(listed) == {p.name for p in VECTORS.iterdir()} - {"SHA256SUMS"}
    for name, digest in listed.items():
        assert hashlib.sha256((VECTORS / name).read_bytes()).hexdigest() == digest, name


# ---------------------------------------------------------------------------
# The generator's ES256 and key, against their RFCs
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("message", "k", "r", "s"),
    [
        (
            b"sample",
            0xA6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60,
            0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716,
            0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8,
        ),
        (
            b"test",
            0xD16B6AE827F17175E040871A1C7EC3500192C4C92677336EC2537ACAEE0008E0,
            0xF1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367,
            0x019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083,
        ),
    ],
)
def test_es256_matches_rfc6979_appendix_a25(message, k, r, s):
    gen = _generator()
    private = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
    assert gen.rfc6979_nonce(private, hashlib.sha256(message).digest()) == k
    assert gen.sign_es256(private, message) == (r, s)


def test_key_is_rfc7515_appendix_a3_and_verifies_its_published_jws():
    jwk = _load("key-set.json")["keys"][0]
    assert (jwk["kty"], jwk["crv"]) == ("EC", "P-256")
    assert jwk["x"] == "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"
    assert jwk["y"] == "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
    assert "d" not in jwk
    signing_input = (
        b"eyJhbGciOiJFUzI1NiJ9"
        b".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
    )
    signature = _b64u_decode("DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q")
    assert _es256_valid(jwk, signing_input, signature)


# ---------------------------------------------------------------------------
# The cases, against section 3 of the declaration
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", sorted(CASES))
def test_native_check_statuses_match_expected_reports(name):
    case = CASES[name]
    checkout = _load(case["checkout"])
    computed = _native_checks(checkout, _load(case["key_set"]))
    expected = {r["detail"]["check"]: r["status"] for r in case["expected"]["reports"]}
    assert {r["detail"]["object"] for r in case["expected"]["reports"]} == {"ucp.checkout"}
    assert {r["property"] for r in case["expected"]["reports"]} == {"native_check"}
    assert expected.pop("ucp.checkout.schema") == "PASS"
    assert computed == expected


def test_native_check_fails_differs_from_positive_only_at_the_mutation():
    positive = _load(CASES["positive"]["checkout"])
    tampered = _load(CASES["native-check-fails"]["checkout"])
    mutation = CASES["native-check-fails"]["mutation"]
    assert mutation["pointer"] == "/totals/2/amount"
    assert positive["totals"][2] == {"type": "total", "amount": mutation["from"]}
    restored = copy.deepcopy(tampered)
    restored["totals"][2]["amount"] = mutation["from"]
    assert restored == positive
    assert tampered["ap2"] == positive["ap2"]


@pytest.mark.parametrize("name", sorted(CASES))
def test_wrapped_entry_is_jcs_of_the_whole_checkout(name):
    case = CASES[name]
    octets = rfc8785.dumps(_load(case["checkout"]))
    entry = case["wrapped"]
    assert entry["type"] == "ucp.checkout"
    assert entry["digest_alg"] == "SHA-256"
    assert _b64u_decode(entry["content"]) == octets
    assert entry["digest"] == hashlib.sha256(octets).hexdigest()


def test_failing_case_maps_by_profile_rows_5_and_6():
    mapping = CASES["native-check-fails"]["expected"]["mapping"]
    assert mapping["requirement_is_the_check"] == {
        "row": 5, "status": "SATISFIED", "sufficiency": "SATISFIED", "verdict": "not_met",
    }
    assert mapping["requirement_rests_on_the_check"] == {
        "row": 6, "status": "INSUFFICIENT", "sufficiency": "INSUFFICIENT", "verdict": "not_evaluable",
    }


# ---------------------------------------------------------------------------
# UCP's own validator, when it is installed (see the vectors' README)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not (shutil.which("ucp-schema") and os.environ.get("UCP_SCHEMAS")),
    reason="needs ucp-schema on PATH and UCP_SCHEMAS set to UCP's source/schemas at the pinned commit",
)
@pytest.mark.parametrize("name", sorted(CASES))
def test_checkout_validates_with_ucp_schema(name):
    result = subprocess.run(
        [
            "ucp-schema", "validate", str(VECTORS / CASES[name]["checkout"]),
            "--schema-local-base", os.environ["UCP_SCHEMAS"],
            "--schema-remote-base", "https://ucp.dev/2026-08-25/schemas",
            "--response", "--op", "complete", "--json",
        ],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout)["valid"] is True
