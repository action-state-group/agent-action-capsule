# SPDX-License-Identifier: BSD-3-Clause
"""The person signature vectors (``vectors/person-signature-v0/``).

Every case is run from its inputs alone, by an evaluator written here from
``spec/person-signature-v0.md`` (PS) §3 to §6: the form of the object and of its ``webauthn`` key
and proof, the seven steps of PS §6.2 in order, and the record's ``person_signature`` status of
PS §6.3. The evaluator's result is compared with each case's ``expected`` block, which the
generator states by hand. Nothing here imports the generator.

The test also runs defective evaluators, each leaving out one check, and each must disagree with at
least one case. It regenerates the corpus twice and requires both runs to be byte-identical to the
committed files.
"""
from __future__ import annotations

import ast
import base64
import binascii
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_public_key

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "vectors" / "person-signature-v0"
GENERATOR = ROOT / "python" / "scripts" / "generate_person_signature_v0_vectors.py"
SPEC = ROOT / "spec" / "person-signature-v0.md"
HAND_WRITTEN = ("README.md",)
DATA = json.loads((VECTORS / "vectors.json").read_text(encoding="utf-8"))
CASES = DATA["cases"]

VERSION = "person-signature/0"
MEMBERS = {"person_signature_version", "record_digest", "key_type", "key", "proof"}
PROOF = {"authenticator_data", "client_data_json", "signature"}
HEX64 = re.compile(r"[0-9a-f]{64}")
B64U = re.compile(r"[A-Za-z0-9_-]*")
METHOD = {-7: "webauthn ES256 over person-signature/0", -8: "webauthn EdDSA over person-signature/0"}
CHECKS = ("form", "duplicates", "type", "challenge", "origin", "cross_origin", "rp_id", "up", "uv", "person_key",
          "excluded_key", "signature", "client_data_octets", "client_data_json", "authenticator_data")


class Malformed(Exception):
    pass


def b64u_decode(text: Any) -> bytes:
    """PS §1: base64url without padding; padding, other characters or non-zero trailing bits are
    rejected."""
    if not isinstance(text, str) or not B64U.fullmatch(text) or len(text) % 4 == 1:
        raise Malformed("binary")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as e:
        raise Malformed("binary") from e
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != text:
        raise Malformed("binary")
    return raw


def public_key(key: dict) -> tuple[int, bytes, Any]:
    """PS §4.2: ``(alg, public key value, key object)`` for -7 and -8. Raises Malformed when
    ``spki`` does not match ``alg``."""
    alg, der = key["alg"], b64u_decode(key["spki"])
    try:
        pub = load_der_public_key(der)
    except ValueError as e:
        raise Malformed("spki") from e
    if pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo) != der:
        raise Malformed("spki not in its canonical uncompressed form")
    if alg == -7:
        if not isinstance(pub, ec.EllipticCurvePublicKey) or not isinstance(pub.curve, ec.SECP256R1):
            raise Malformed("alg -7 needs a P-256 key")
        return alg, pub.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint), pub
    if alg == -8:
        if not isinstance(pub, Ed25519PublicKey):
            raise Malformed("alg -8 needs an Ed25519 key")
        return alg, pub.public_bytes(Encoding.Raw, PublicFormat.Raw), pub
    raise AssertionError("only -7 and -8 are defined")


def _cbor_item_end(data: bytes, i: int) -> int:
    """The offset just past one well-formed, definite-length CBOR data item starting at ``i``
    (RFC 8949 §3). Raises Malformed otherwise. Enough to check that extension output is exactly one
    map; the values are never interpreted."""
    if i >= len(data):
        raise Malformed("cbor")
    major, info = data[i] >> 5, data[i] & 0x1F
    i += 1
    if info < 24:
        arg = info
    elif info in (24, 25, 26, 27):
        n = 1 << (info - 24)
        if i + n > len(data):
            raise Malformed("cbor")
        arg = int.from_bytes(data[i:i + n], "big")
        i += n
    else:
        raise Malformed("cbor: indefinite length or reserved")
    if major == 7 and info == 24 and arg < 32:
        raise Malformed("cbor: simple value in two octets below 32")
    if major in (0, 1):
        return i
    if major in (2, 3):
        if i + arg > len(data):
            raise Malformed("cbor")
        return i + arg
    if major == 4:
        for _ in range(arg):
            i = _cbor_item_end(data, i)
        return i
    if major == 5:
        for _ in range(2 * arg):
            i = _cbor_item_end(data, i)
        return i
    if major == 6:
        return _cbor_item_end(data, i)
    return i  # major 7: simple values and floats, argument already consumed


def authenticator_data_form(adata: bytes) -> None:
    """PS §6.2 step 6: an assertion's authenticator data (WebAuthn §6.1)."""
    if len(adata) < 37:
        raise Malformed("short")
    fl = adata[32]
    if fl & 0x40:
        raise Malformed("AT set")
    if fl & 0x10 and not fl & 0x08:
        raise Malformed("BS without BE")
    if not fl & 0x80:
        if len(adata) != 37:
            raise Malformed("trailing octets")
        return
    if len(adata) == 37 or adata[37] >> 5 != 5 or _cbor_item_end(adata, 37) != len(adata):
        raise Malformed("extensions are not exactly one CBOR map")


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict:
    out = dict(pairs)
    if len(out) != len(pairs):
        raise Malformed("duplicate member")
    return out


def _no_constant(name: str) -> Any:
    raise Malformed(f"not JSON: {name}")


def strict_json(text: str, *, duplicates: bool = True) -> Any:
    """RFC 8259 JSON, refusing NaN and Infinity and, unless told otherwise, duplicate names."""
    try:
        return json.loads(text, parse_constant=_no_constant, object_pairs_hook=_no_duplicates if duplicates else None)
    except ValueError as e:
        raise Malformed("json") from e


class _Flagged(dict):
    """An object whose JSON text named a member twice; form() refuses it (PS §3.1)."""


def _flag_duplicates(pairs: list[tuple[str, Any]]) -> dict:
    out = dict(pairs)
    return _Flagged(out) if len(out) != len(pairs) else out


def candidates(case: dict, skip: frozenset[str]) -> list[Any]:
    if "person_signatures_json" in case:
        hook = None if "duplicates" in skip else _flag_duplicates
        return json.loads(case["person_signatures_json"], object_pairs_hook=hook)
    return case.get("person_signatures", [])


def same_key(a: Any, b: dict) -> bool:
    """PS §4.2. ``a`` is a key in the §4.2 form or a raw Ed25519 key identifier; ``b`` is a
    candidate's key under -7 or -8. The algorithm is compared first, so an input key under an
    undefined algorithm is never decoded."""
    if isinstance(a, str):
        return b["alg"] == -8 and public_key(b)[1].hex() == a
    if a.get("alg") != b["alg"]:
        return False
    return public_key(a)[1] == public_key(b)[1]


def form(ps: Any) -> None:
    """PS §3.1 and, for ``webauthn``, §4.2."""
    if not isinstance(ps, dict) or isinstance(ps, _Flagged) or set(ps) != MEMBERS:
        raise Malformed("members")
    if ps["person_signature_version"] != VERSION or not isinstance(ps["key_type"], str):
        raise Malformed("version or key_type")
    if not isinstance(ps["record_digest"], str) or not HEX64.fullmatch(ps["record_digest"]):
        raise Malformed("record_digest")
    if ps["key_type"] != "webauthn":
        return
    key, proof = ps["key"], ps["proof"]
    if not isinstance(key, dict) or isinstance(key, _Flagged) or set(key) != {"alg", "spki"}:
        raise Malformed("key members")
    if not isinstance(key["alg"], int) or isinstance(key["alg"], bool):
        raise Malformed("alg")
    b64u_decode(key["spki"])
    if key["alg"] in (-7, -8):
        public_key(key)
    if not isinstance(proof, dict) or isinstance(proof, _Flagged) or set(proof) != PROOF:
        raise Malformed("proof members")
    for name in PROOF:
        b64u_decode(proof[name])


def verify_signature(alg: int, pub: Any, sig: bytes, msg: bytes) -> bool:
    try:
        if alg == -7:
            r, s = decode_dss_signature(sig)
            if encode_dss_signature(r, s) != sig:
                return False
            pub.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
        else:
            pub.verify(sig, msg)
    except (InvalidSignature, ValueError):
        return False
    return True


def check_one(ps: dict, inp: dict, skip: frozenset[str] = frozenset()) -> dict:
    try:
        return _check_one(ps, inp, skip)
    except Malformed:
        # Malformed client data (step 5) or authenticator data (step 6), or, for a defective
        # evaluator that skips the form check, any value step 1 would have refused.
        return {"status": "FAIL", "reason": "malformed"}


def _check_one(ps: dict, inp: dict, skip: frozenset[str]) -> dict:
    """PS §6.2, the seven steps in order. Returns ``{status, reason}`` plus, for a signature that
    reached step 7, its flags and counter, and for a PASS its method."""
    def fail(reason: str, **more: Any) -> dict:
        return {"status": "FAIL", "reason": reason, **more}

    # 1. Form.
    if "form" not in skip:
        try:
            form(ps)
        except Malformed:
            return fail("malformed")
    # 2. Key type and algorithm.
    if ps.get("key_type") != "webauthn":
        return {"status": "NOT_CHECKED", "reason": "unsupported key type"}
    alg = ps["key"]["alg"]
    if alg not in (-7, -8):
        return {"status": "NOT_CHECKED", "reason": "unsupported algorithm"}
    pub = public_key(ps["key"])[2]
    # 3. Person key.
    if not inp["person_keys"]:
        return {"status": "NOT_CHECKED", "reason": "no person key"}
    if "person_key" not in skip and not any(same_key(k, ps["key"]) for k in inp["person_keys"]):
        return fail("not a person key")
    # 4. Not a record key.
    if "excluded_key" not in skip and any(same_key(k, ps["key"]) for k in inp["excluded_keys"]):
        return fail("record signer key")
    # 5. Client data: UTF-8 decoding removes a leading byte order mark.
    cdata = b64u_decode(ps["proof"]["client_data_json"])
    try:
        text = cdata.decode("utf-8-sig")
    except UnicodeDecodeError:
        return fail("malformed")
    if "client_data_json" in skip:
        cd = json.loads(text)
    else:
        cd = strict_json(text)
    if not isinstance(cd, dict):
        return fail("malformed")
    if "type" not in skip and cd.get("type") != "webauthn.get":
        return fail("wrong type")
    if "challenge" not in skip:
        try:
            ok = b64u_decode(cd.get("challenge")) == f"{VERSION}:{ps['record_digest']}".encode()
        except Malformed:
            ok = False
        if not ok:
            return fail("wrong challenge")
    if "origin" not in skip and cd.get("origin") not in inp["allowed_origins"]:
        return fail("origin not allowed")
    if "cross_origin" not in skip and (cd.get("crossOrigin", False) is not False or "topOrigin" in cd):
        if cd.get("topOrigin") not in inp["allowed_top_origins"]:
            return fail("cross-origin")
    # 6. Authenticator data.
    adata = b64u_decode(ps["proof"]["authenticator_data"])
    if len(adata) < 37:
        return fail("malformed")
    if "authenticator_data" not in skip:
        authenticator_data_form(adata)
    fl = adata[32]
    if "rp_id" not in skip and adata[:32] != hashlib.sha256(inp["relying_party_id"].encode()).digest():
        return fail("wrong relying party")
    if "up" not in skip and not fl & 0x01:
        return fail("user not present")
    if "uv" not in skip and inp["user_verification_required"] and not fl & 0x04:
        return fail("user not verified")
    seen = {"flags": {"up": bool(fl & 0x01), "uv": bool(fl & 0x04), "be": bool(fl & 0x08), "bs": bool(fl & 0x10)},
            "sign_count": int.from_bytes(adata[33:37], "big")}
    # 7. Signature.
    if "client_data_octets" in skip:
        cdata = json.dumps(cd, separators=(",", ":")).encode()
    if "signature" not in skip:
        sig = b64u_decode(ps["proof"]["signature"])
        if not verify_signature(alg, pub, sig, adata + hashlib.sha256(cdata).digest()):
            return fail("bad signature", **seen)
    return {"status": "PASS", "reason": None, **seen, "method": METHOD[alg]}


def evaluate(case: dict, skip: frozenset[str] = frozenset()) -> dict:
    """PS §5 selection and the PS §6.3 record status."""
    inp = case["inputs"]
    results = []
    for i, ps in enumerate(candidates(case, skip)):
        if isinstance(ps, dict) and ps.get("record_digest") == inp["target_record_digest"]:
            results.append({"index": i, **check_one(ps, inp, skip)})
    statuses = {r["status"] for r in results}
    status = next((s for s in ("PASS", "FAIL", "NOT_CHECKED") if s in statuses), "NOT_PRESENT")
    return {"signatures": results, "person_signature": status}


def expected(case: dict) -> dict:
    return {"signatures": case["expected"]["signatures"], "person_signature": case["expected"]["person_signature"]}


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_case(case):
    assert evaluate(case) == expected(case)


def test_corpus_shape():
    assert DATA["set"] == "aac-person-signature-v0"
    assert DATA["spec"] == "spec/person-signature-v0.md"
    assert DATA["count"] == len(CASES)
    for c in CASES:
        assert set(c) <= {"id", "title", "cites", "inputs", "person_signatures", "person_signatures_json", "expected"}
        assert c["cites"] and all(x.startswith("PS §") for x in c["cites"])


def test_every_status_and_reason_is_covered():
    statuses = {c["expected"]["person_signature"] for c in CASES}
    assert statuses == {"PASS", "FAIL", "NOT_CHECKED", "NOT_PRESENT"}
    reasons = {s["reason"] for c in CASES for s in c["expected"]["signatures"]}
    spec = SPEC.read_text(encoding="utf-8")
    for reason in reasons - {None}:
        assert f"`{reason}`" in spec, reason
    for reason in re.findall(r"reason\s+`([^`]+)`", spec):
        assert reason in reasons, f"no case for reason {reason!r}"


def test_policy_negatives_are_correctly_signed():
    """PS §9: a verifier that checks only the signature must fail every policy negative."""
    caught = [c["id"] for c in CASES
              if evaluate(c, frozenset(CHECKS) - {"signature", "client_data_octets"}) != expected(c)]
    # Authenticator data under 37 octets has no flags to read, so every evaluator refuses it.
    policy = [c["id"] for c in CASES if c["expected"]["person_signature"] == "FAIL"
              and c["expected"]["fails"] not in ("signature", "form")
              and c["id"] != "malformed-short-authenticator-data"]
    assert set(policy) <= set(caught)
    for c in CASES:
        if c["id"] in policy:
            ps = c["person_signatures"][c["expected"]["signatures"][0]["index"]]
            alg, _, pub = public_key(ps["key"])
            proof = {k: b64u_decode(v) for k, v in ps["proof"].items()}
            msg = proof["authenticator_data"] + hashlib.sha256(proof["client_data_json"]).digest()
            assert verify_signature(alg, pub, proof["signature"], msg), c["id"]


@pytest.mark.parametrize("check", CHECKS)
def test_every_defective_evaluator_is_caught(check):
    assert any(evaluate(c, frozenset({check})) != expected(c) for c in CASES), check


def test_verification_is_repeatable_and_order_free():
    """PS §6.2: checking changes no state."""
    for c in CASES:
        first = evaluate(c)
        assert evaluate(c) == first
        if "person_signatures_json" in c:
            continue
        sigs = c.get("person_signatures", [])
        rev = dict(c, person_signatures=list(reversed(sigs)))
        assert evaluate(rev)["person_signature"] == first["person_signature"]


def test_test_keys_derive_from_their_labels():
    order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    for name, k in DATA["test_keys"]["keys"].items():
        seed = hashlib.sha256(k["seed_label"].encode()).digest()
        if k["key"]["alg"] == -7:
            priv = ec.derive_private_key(int.from_bytes(seed, "big") % (order - 1) + 1, ec.SECP256R1())
        else:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            priv = Ed25519PrivateKey.from_private_bytes(seed)
        der = priv.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        assert b64u_decode(k["key"]["spki"]) == der, name


def test_spec_lists_the_corpus():
    spec = SPEC.read_text(encoding="utf-8")
    assert "vectors/person-signature-v0/" in spec
    assert "generate_person_signature_v0_vectors.py" in spec


# ---------------------------------------------------------------------------
# Reproducibility and registration
# ---------------------------------------------------------------------------


def _generate(out: Path) -> None:
    for name in HAND_WRITTEN:
        shutil.copyfile(VECTORS / name, out / name)
    subprocess.run([sys.executable, str(GENERATOR), "--out", str(out)], check=True)


def _files(d: Path) -> list[str]:
    return sorted(p.relative_to(d).as_posix() for p in d.rglob("*") if p.is_file() and "__pycache__" not in p.parts)


def test_generator_is_deterministic_and_reproduces_every_file(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    _generate(a)
    _generate(b)
    committed = _files(VECTORS)
    assert committed == _files(a) == _files(b)
    for name in committed:
        assert (a / name).read_bytes() == (b / name).read_bytes() == (VECTORS / name).read_bytes(), name


def test_sha256sums_and_registration():
    sha = lambda b: hashlib.sha256(b).hexdigest()  # noqa: E731
    listed = dict(reversed(line.split("  ", 1)) for line in (VECTORS / "SHA256SUMS").read_text().splitlines())
    assert set(listed) == set(_files(VECTORS)) - {"SHA256SUMS"}
    for name, digest in listed.items():
        assert sha((VECTORS / name).read_bytes()) == digest, name
    top = dict(reversed(line.split("  ", 1)) for line in (ROOT / "vectors" / "SHA256SUMS").read_text().splitlines())
    for name in set(_files(VECTORS)) - {"SHA256SUMS"}:
        assert top[f"person-signature-v0/{name}"] == sha((VECTORS / name).read_bytes()), name
    corpora = json.loads((ROOT / "vectors" / "manifest.json").read_text())["corpora"]
    assert corpora["person_signature_v0"] == "person-signature-v0/manifest.json"
    assert "generate_person_signature_v0_vectors.py" in (
        ROOT / "python" / "scripts" / "generate_all_vectors.py").read_text()


def test_does_not_import_the_generator():
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    modules = [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names]
    modules += [n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
    assert not [m for m in modules if m.startswith("generate_")]
