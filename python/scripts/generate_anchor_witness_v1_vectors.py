#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate the witness Receipt vectors of profile ``evidence-interop/1`` §6.2.2.

A ``cll-witness-receipt`` is an RFC 9942 COSE Receipt (RFC9162_SHA256) whose leaf entry is the
32 octets of an anchor digest. Each case gives the anchor digest, the Receipts beside it in the
order received, a witness policy and the ``anchor_witnessed`` report §6.2.2 gives: the overall
status, each Receipt's status, witness and registration time, and the anchor's witness and
witnessed time.

Every expected value is written here by hand from §6.2.2. The RFC 9162 tree, the CBOR encoder and
the P-256 signer are this script's own; it imports no repository implementation. Keys are test
keys derived from public labels. ES256 signatures use a nonce derived from a label, so the output
is deterministic: no clock and no randomness.

Output: ``vectors/anchor-witness-v1/`` (or ``--out DIR``). ``README.md`` is hand-written; when
present in the output directory it is included in ``SHA256SUMS`` but never rewritten.
Dependencies: ``cryptography`` (Ed25519 signing only).
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "vectors" / "anchor-witness-v1"
SPEC = "spec/interop-profile-v1.md"


def label_digest(text: str) -> bytes:
    return hashlib.sha256(text.encode()).digest()


# --- CBOR (RFC 8949), only what a Receipt needs -------------------------------------------------

class Tag:
    def __init__(self, number: int, value: Any):
        self.number, self.value = number, value


class Raw:
    """Octets placed as they are, for a malformed item."""

    def __init__(self, octets: bytes):
        self.octets = octets


def head(major: int, arg: int) -> bytes:
    if arg < 24:
        return bytes([major << 5 | arg])
    for info, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if arg < 1 << (8 * width):
            return bytes([major << 5 | info]) + arg.to_bytes(width, "big")
    raise ValueError("argument too large")


def cbor(value: Any) -> bytes:
    if isinstance(value, Raw):
        return value.octets
    if value is None:
        return b"\xf6"
    if isinstance(value, bool):
        return b"\xf5" if value else b"\xf4"
    if isinstance(value, int):
        return head(0, value) if value >= 0 else head(1, -1 - value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode()
        return head(3, len(raw)) + raw
    if isinstance(value, list):
        return head(4, len(value)) + b"".join(cbor(v) for v in value)
    if isinstance(value, dict):
        return head(5, len(value)) + b"".join(cbor(k) + cbor(v) for k, v in value.items())
    if isinstance(value, Tag):
        return head(6, value.number) + cbor(value.value)
    raise TypeError(type(value))


def sig_structure(protected: bytes, payload: bytes) -> bytes:
    return cbor(["Signature1", protected, b"", payload])


# --- RFC 9162 §2.1 Merkle tree ------------------------------------------------------------------

def leaf_hash(entry: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + entry).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def split(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def mth(entries: list[bytes]) -> bytes:
    if len(entries) == 1:
        return leaf_hash(entries[0])
    k = split(len(entries))
    return node_hash(mth(entries[:k]), mth(entries[k:]))


def path(m: int, entries: list[bytes]) -> list[bytes]:
    """PATH(m, D[n]) of RFC 9162 §2.1.3.1: the leaf's sibling first, the root's child last."""
    if len(entries) == 1:
        return []
    k = split(len(entries))
    if m < k:
        return path(m, entries[:k]) + [mth(entries[k:])]
    return path(m - k, entries[k:]) + [mth(entries[:k])]


# --- keys ------------------------------------------------------------------------------------

def ed_key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(label_digest("anchor-witness-v1 key " + label))


def ed_spki(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


# P-256 (SEC 2 secp256r1), affine arithmetic, for a deterministic ES256 test signer.
_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_A = _P - 3
_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
      0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)


def _add(p: Any, q: Any) -> Any:
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % _P == 0:
        return None
    if p == q:
        lam = (3 * p[0] * p[0] + _A) * pow(2 * p[1], -1, _P) % _P
    else:
        lam = (q[1] - p[1]) * pow(q[0] - p[0], -1, _P) % _P
    x = (lam * lam - p[0] - q[0]) % _P
    return x, (lam * (p[0] - x) - p[1]) % _P


def _mul(k: int, p: Any) -> Any:
    out = None
    while k:
        if k & 1:
            out = _add(out, p)
        p, k = _add(p, p), k >> 1
    return out


class P256Key:
    def __init__(self, label: str):
        self.label = label
        self.d = int.from_bytes(label_digest("anchor-witness-v1 p256 " + label), "big") % (_N - 1) + 1
        self.q = _mul(self.d, _G)

    def spki(self) -> bytes:
        point = b"\x04" + self.q[0].to_bytes(32, "big") + self.q[1].to_bytes(32, "big")
        return bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200") + point

    def sign(self, message: bytes) -> bytes:
        z = int.from_bytes(hashlib.sha256(message).digest(), "big")
        k = int.from_bytes(hashlib.sha256(b"nonce " + self.label.encode() + message).digest(), "big") % (_N - 1) + 1
        r = _mul(k, _G)[0] % _N
        s = pow(k, -1, _N) * (z + r * self.d) % _N
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")


# --- the log, the anchor and the Receipts ------------------------------------------------------

ANCHOR = label_digest("anchor-witness-v1 anchor")
OTHER_ANCHOR = label_digest("anchor-witness-v1 other anchor")
ENTRIES = [label_digest(f"anchor-witness-v1 entry {i}") for i in range(7)]
ANCHOR_INDEX = 4
ENTRIES[ANCHOR_INDEX] = ANCHOR
T1, T2 = 1793520240, 1793523840  # 2026-11-01T08:04:00Z and 09:04:00Z

KEY_A, KEY_A_OLD, KEY_C, KEY_OUTSIDE = ed_key("a"), ed_key("a-old"), ed_key("c"), ed_key("outside")
KEY_B = P256Key("b")

POLICY = {"witnesses": [
    {"name": "witness-a", "keys": [ed_spki(KEY_A_OLD).hex(), ed_spki(KEY_A).hex()]},
    {"name": "witness-b", "keys": [KEY_B.spki().hex()]},
    {"name": "witness-c", "keys": [ed_spki(KEY_C).hex()]},
]}
ED25519_ONLY = {"witnesses": [w for w in POLICY["witnesses"] if w["name"] != "witness-b"]}

# The y coordinate 1 is the identity: a small-order key under which [S]B = R verifies anything.
SMALL_ORDER_SPKI = bytes.fromhex("302a300506032b6570032100") + (1).to_bytes(32, "little")
_L = (1 << 252) + 27742317777372353535851937790883648493


def proof(index: int = ANCHOR_INDEX, entries: list[bytes] = ENTRIES) -> bytes:
    return cbor([len(entries), index, path(index, entries)])


def receipt(key: Any, *, iat: Any = None, entries: list[bytes] = ENTRIES, index: int = ANCHOR_INDEX,
            protected: dict | None = None, unprotected: dict | None = None, proofs: list | None = None,
            payload: Any = None, tag: int | None = 18, sign_root: bytes | None = None,
            signature: bytes | None = None, protected_raw: bytes | None = None, trailing: bytes = b"") -> bytes:
    alg = -7 if isinstance(key, P256Key) else -8
    if protected is None:
        protected = {1: alg, 395: 1}
        if iat is not None:
            protected[15] = {6: iat}
    protected_bytes = protected_raw if protected_raw is not None else cbor(protected)
    proofs = [proof(index, entries)] if proofs is None else proofs
    root = sign_root if sign_root is not None else mth(entries)
    if signature is None:
        message = sig_structure(protected_bytes, root)
        signature = key.sign(message)
    body = [protected_bytes, unprotected if unprotected is not None else {396: {-1: proofs}}, payload, signature]
    return cbor(Tag(tag, body) if tag is not None else body) + trailing


def passed(witness: str, time: int | None = None) -> dict:
    return {"status": "PASS", "witness": witness, "registration_time": time}


def status(value: str) -> dict:
    return {"status": value, "witness": None, "registration_time": None}


def case(name: str, description: str, receipts: list[bytes], results: list[dict], *,
         policy: dict | None = None, anchor: bytes = ANCHOR) -> dict:
    statuses = {r["status"] for r in results}
    overall = ("NOT_PRESENT" if not results else "PASS" if "PASS" in statuses
               else "FAIL" if "FAIL" in statuses else "NOT_CHECKED")
    passing = [r for r in results if r["status"] == "PASS"]
    timed = [r for r in passing if r["registration_time"] is not None]
    chosen = min(timed, key=lambda r: r["registration_time"]) if timed else (passing[0] if passing else None)
    return {
        "name": name,
        "description": description,
        "anchor": anchor.hex(),
        "receipts": [r.hex() for r in receipts],
        "policy": "default" if policy is None else policy,
        "expected": {
            "status": overall,
            "receipts": results,
            "witness": chosen["witness"] if chosen else None,
            "witnessed_time": chosen["registration_time"] if chosen else None,
        },
    }


def tampered(octets: bytes) -> bytes:
    return octets[:-1] + bytes([octets[-1] ^ 1])


def cases() -> list[dict]:
    r_a1 = receipt(KEY_A, iat=T1)
    r_a2 = receipt(KEY_A, iat=T2)
    r_c1 = receipt(KEY_C, iat=T1)
    r_a = receipt(KEY_A)
    r_c = receipt(KEY_C)
    r_b1 = receipt(KEY_B, iat=T1)
    wrong_index = 3  # a well-formed proof of another leaf: it rebuilds another root
    root = mth(ENTRIES)
    single = [ANCHOR]
    ed_a = KEY_A
    # A signature with S + L: the cofactorless equation still holds, the strict check refuses it.
    good = receipt(KEY_A, iat=T1)
    sig = ed_a.sign(sig_structure(cbor({1: -8, 395: 1, 15: {6: T1}}), root))
    big_s = sig[:32] + (int.from_bytes(sig[32:], "little") + _L).to_bytes(32, "little")
    # Under the identity key, R = [s]B and S = s verify over any message without the strict check.
    seed = label_digest("anchor-witness-v1 small order")
    h = bytearray(hashlib.sha512(seed).digest()[:32])
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64
    s_scalar = int.from_bytes(h, "little") % _L
    r_point = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    small_sig = r_point + s_scalar.to_bytes(32, "little")
    small_policy = {"witnesses": [{"name": "witness-small", "keys": [SMALL_ORDER_SPKI.hex()]}]}
    dup_protected = b"\xa3" + cbor(1) + cbor(-8) + cbor(395) + cbor(1) + cbor(1) + cbor(-8)
    seventeen = [proof()] * 17
    path_short = cbor([len(ENTRIES), ANCHOR_INDEX, path(ANCHOR_INDEX, ENTRIES)[:-1]])
    index_over = cbor([len(ENTRIES), len(ENTRIES), path(ANCHOR_INDEX, ENTRIES)])
    short_node = cbor([len(ENTRIES), ANCHOR_INDEX, path(ANCHOR_INDEX, ENTRIES)[:-1] + [b"\x00" * 31]])
    return [
        # PASS
        case("pass-eddsa-time", "one EdDSA Receipt with a protected iat (§6.2.2 steps 1 to 5)",
             [r_a1], [passed("witness-a", T1)]),
        case("pass-eddsa-no-time", "no CWT_Claims: PASS with no registration time (step 5)",
             [r_a], [passed("witness-a")]),
        case("pass-es256-time", "an ES256 Receipt under a P-256 key (step 3)", [r_b1], [passed("witness-b", T1)]),
        case("pass-single-leaf", "a tree of one leaf: an empty inclusion path (RFC 9162 §2.1.3)",
             [receipt(KEY_A, iat=T1, entries=single, index=0)], [passed("witness-a", T1)]),
        case("pass-rotated-key", "the first key of witness-a's row does not verify, the second does (step 3)",
             [r_a1], [passed("witness-a", T1)]),
        case("pass-second-proof", "the first inclusion proof rebuilds another root, the second this anchor's",
             [receipt(KEY_A, iat=T1, proofs=[proof(wrong_index), proof()])], [passed("witness-a", T1)]),
        case("earliest-time-and-its-witness", "two passing Receipts: the earlier time, with the witness that signed it",
             [r_a2, r_c1], [passed("witness-a", T2), passed("witness-c", T1)]),
        case("timed-before-untimed", "an untimed Receipt first: the anchor's time and witness come from the timed one",
             [r_a, r_c1], [passed("witness-a"), passed("witness-c", T1)]),
        case("equal-times-first-received", "two Receipts with one time: the first received names the witness",
             [r_c1, r_a1], [passed("witness-c", T1), passed("witness-a", T1)]),
        case("untimed-first-received", "no passing Receipt has a time: the first passing one names the witness",
             [r_c, r_a], [passed("witness-c"), passed("witness-a")]),
        case("pass-beside-fail", "a failing Receipt takes nothing from a passing one",
             [tampered(r_c1), r_a1], [status("FAIL"), passed("witness-a", T1)]),
        case("iat-negative", "iat below 0: PASS with no registration time",
             [receipt(KEY_A, iat=-1)], [passed("witness-a")]),
        case("iat-over-range", "iat above 2^53 - 1: PASS with no registration time",
             [receipt(KEY_A, iat=1 << 53)], [passed("witness-a")]),
        case("iat-text", "iat as a text string: PASS with no registration time",
             [receipt(KEY_A, iat="2026-11-01T08:04:00Z")], [passed("witness-a")]),
        case("iat-unprotected-only", "a time only in the unprotected header is never read",
             [receipt(KEY_A, unprotected={15: {6: T1}, 396: {-1: [proof()]}})], [passed("witness-a")]),
        # NOT_PRESENT and NOT_CHECKED
        case("no-receipt", "nothing beside the answer", [], []),
        case("policy-empty", "the policy lists no witness (step 2)", [r_a1], [status("NOT_CHECKED")],
             policy={"witnesses": []}),
        case("es256-no-p256-key", "an ES256 Receipt and a policy with Ed25519 keys only (step 2)",
             [r_b1], [status("NOT_CHECKED")], policy=ED25519_ONLY),
        case("not-checked-beside-fail", "one Receipt not checked and one failing: FAIL",
             [r_b1, tampered(r_a1)], [status("NOT_CHECKED"), status("FAIL")], policy=ED25519_ONLY),
        # FAIL: not by an accepted witness over this anchor (step 4)
        case("other-anchor", "a Receipt over another anchor", [r_a1], [status("FAIL")], anchor=OTHER_ANCHOR),
        case("unlisted-witness", "signed by a key the policy does not list", [receipt(KEY_OUTSIDE, iat=T1)],
             [status("FAIL")]),
        case("signature-tampered", "one signature bit flipped", [tampered(r_a1)], [status("FAIL")]),
        case("eddsa-s-not-reduced", "S + L: the cofactorless equation holds, S is not below L",
             [receipt(KEY_A, iat=T1, signature=big_s)], [status("FAIL")]),
        case("eddsa-small-order-key", "an identity key in the policy verifies any message without the strict check",
             [receipt(KEY_A, iat=T1, signature=small_sig)], [status("FAIL")], policy=small_policy),
        # FAIL: not of the form (step 1)
        case("attached-payload", "the root attached as the payload, signed: refused even though it verifies",
             [receipt(KEY_A, iat=T1, payload=root)], [status("FAIL")]),
        case("untagged", "a COSE_Sign1 without tag 18", [receipt(KEY_A, iat=T1, tag=None)], [status("FAIL")]),
        case("vds-2", "vds is not 1", [receipt(KEY_A, protected={1: -8, 395: 2})], [status("FAIL")]),
        case("alg-other", "alg PS256 (-37)", [receipt(KEY_A, protected={1: -37, 395: 1})], [status("FAIL")]),
        case("alg-absent", "no alg", [receipt(KEY_A, protected={395: 1})], [status("FAIL")]),
        case("crit-present", "crit lists vds: a Receipt carries no crit (step 1)",
             [receipt(KEY_A, protected={1: -8, 2: [395], 395: 1, 15: {6: T1}})], [status("FAIL")]),
        case("crit-alg", "crit lists alg, a registered label: still no crit (step 1)",
             [receipt(KEY_A, protected={1: -8, 2: [1], 395: 1})], [status("FAIL")]),
        case("crit-unknown", "crit lists kid (4)",
             [receipt(KEY_A, protected={1: -8, 2: [4], 4: b"k", 395: 1})], [status("FAIL")]),
        case("crit-empty", "crit is an empty array", [receipt(KEY_A, protected={1: -8, 2: [], 395: 1})],
             [status("FAIL")]),
        case("protected-duplicate-key", "alg twice in the protected header",
             [receipt(KEY_A, protected_raw=dup_protected)], [status("FAIL")]),
        case("no-vdp", "no vdp in the unprotected header", [receipt(KEY_A, iat=T1, unprotected={})], [status("FAIL")]),
        case("no-proofs", "vdp -1 is an empty array", [receipt(KEY_A, iat=T1, proofs=[])], [status("FAIL")]),
        case("seventeen-proofs", "more than 16 inclusion proofs", [receipt(KEY_A, iat=T1, proofs=seventeen)],
             [status("FAIL")]),
        case("proof-malformed-beside-good", "a valid proof does not hide a malformed one after it",
             [receipt(KEY_A, iat=T1, proofs=[proof(), b"\xff"])], [status("FAIL")]),
        case("path-short", "an inclusion path one node short", [receipt(KEY_A, iat=T1, proofs=[path_short])],
             [status("FAIL")]),
        case("index-not-below-size", "leaf_index equal to tree_size", [receipt(KEY_A, iat=T1, proofs=[index_over])],
             [status("FAIL")]),
        case("node-31-octets", "a path node of 31 octets", [receipt(KEY_A, iat=T1, proofs=[short_node])],
             [status("FAIL")]),
        case("trailing-octets", "an octet after the COSE_Sign1", [good + b"\x00"], [status("FAIL")]),
        case("not-cbor", "octets that are not CBOR", [b"\xff\xff"], [status("FAIL")]),
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    out: Path = args.out
    out.mkdir(parents=True, exist_ok=True)
    corpus = {
        "description": "Witness Receipts over a CLL anchor and the anchor_witnessed report (§6.2.2). Generated by "
                       "python/scripts/generate_anchor_witness_v1_vectors.py. Times are NumericDates; keys are hex "
                       "DER SubjectPublicKeyInfo test keys derived from public labels; the anchor digests are label "
                       "digests.",
        "spec": SPEC,
        "sections": ["§6.2.2"],
        "policies": {"default": POLICY},
        "cases": cases(),
    }
    vectors = json.dumps(corpus, indent=2, sort_keys=False) + "\n"
    (out / "vectors.json").write_text(vectors)
    manifest = {
        "spec": SPEC,
        "provenance": "spec-derived",
        "generator": "python/scripts/generate_anchor_witness_v1_vectors.py",
        "files": [{"path": "vectors.json", "sha256": hashlib.sha256(vectors.encode()).hexdigest(),
                   "count": len(corpus["cases"])}],
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    names = sorted(p.name for p in out.iterdir() if p.is_file() and p.name != "SHA256SUMS")
    sums = "".join(f"{hashlib.sha256((out / n).read_bytes()).hexdigest()}  {n}\n" for n in names)
    (out / "SHA256SUMS").write_text(sums)


if __name__ == "__main__":
    main()
