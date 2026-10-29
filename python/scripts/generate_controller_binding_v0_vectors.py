#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate the controller binding vectors (``spec/controller-binding-v0.md``, cited as CB).

Each case is a pair of agreeing halves (the producer record of IP §11.5), presented as
corroborating, with a binding record and, where the case needs them, revocation statements or a
credential. CB §10 lists the cases:

- bindings that apply, one per claim type, plus ones whose credential method the verifier does not
  implement, whose credential is forged, revoked only after the halves, or revoked by a key the
  binding does not bind: ``issuer_independence`` ``FAIL``, redundant;
- bindings that do not apply: expired, revoked, signed by one key, naming other keys, under an
  undefined method, or naming a delegator that is not bound: ``issuer_independence`` stays
  ``NOT_CHECKED``;
- a binding of a key to itself over two halves under that key: form ``FAIL``, and ``FAIL`` by the
  same-key rule;
- bindings of an Ed25519 key to a ``bip340`` (Nostr) key, signed by the Nostr event of CB §4.1: a
  valid one, one read as two Ed25519 keys, one whose event names another digest, one whose event
  is of another kind, and one revoked by the Nostr key. None binds the pair.

It states every expected status by hand from CB §6 and §7 and IP §6.7.4. Each case cites the
sections it comes from. Nothing here imports or runs a verifier. The credential and its method are
fixed for these vectors only and are not registered (CB §10).

Output: ``vectors/controller-binding-v0/`` (or ``--out DIR``). Deterministic: no clock, no
randomness. ``README.md`` is never rewritten; every file in the directory is listed in
``SHA256SUMS``. Dependencies: the standard library, ``cryptography`` (Ed25519 only) and the
generators beside this script, for their encodings, keys, halves and contract. BIP-340 signing is
written here from BIP-340 itself, with the all-zero ``aux_rand``, so it is deterministic too.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

import generate_coverage_declaration_v0_vectors as coverage_vectors
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from generate_coverage_declaration_v0_vectors import CONTRACT, CONTRACT_DIGEST, CONTRACT_REF, half
from generate_interop_profile_v0_vectors import EC_SCHEMA, PROFILE, jcs, sha, shx

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "vectors" / "controller-binding-v0"
SET = "aac-controller-binding-v0"
SPEC = "spec/controller-binding-v0.md"
STATUS = ("Conformance vectors for the informational Controller Binding v0 (spec/controller-binding-v0.md) "
          "and its use in issuer independence (evidence-interop/0, §6.7.4). Every key is a test key derived "
          "from a public seed; never use one for anything else.")
J = "application/json"

SEED_LABELS = {
    "producer-c": "controller-binding-v0 vectors: a third producer key",
    "credential-issuer": "controller-binding-v0 vectors: credential issuer key",
    "other-issuer": "controller-binding-v0 vectors: key that is not the credential issuer",
}
PRIV = {name: Ed25519PrivateKey.from_private_bytes(sha(label.encode())) for name, label in SEED_LABELS.items()}
PRIV |= {name: coverage_vectors.PRIV[name] for name in ("producer-a", "producer-b")}
PUB = {name: k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex() for name, k in PRIV.items()}

# ---------------------------------------------------------------------------
# BIP-340 (Schnorr over secp256k1), signing only, from the BIP's specification
# ---------------------------------------------------------------------------

_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
      0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _tagged(tag: str, msg: bytes) -> bytes:
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + msg).digest()


def _add(a: tuple[int, int] | None, b: tuple[int, int] | None) -> tuple[int, int] | None:
    if a is None or b is None:
        return a or b
    if a[0] == b[0] and a[1] != b[1]:
        return None
    lam = (3 * a[0] * a[0] * pow(2 * a[1], _P - 2, _P) if a == b
           else (b[1] - a[1]) * pow(b[0] - a[0], _P - 2, _P)) % _P
    x = (lam * lam - a[0] - b[0]) % _P
    return x, (lam * (a[0] - x) - a[1]) % _P


def _mul(pt: tuple[int, int] | None, n: int) -> tuple[int, int]:
    r = None
    for i in range(256):
        if (n >> i) & 1:
            r = _add(r, pt)
        pt = _add(pt, pt)
    assert r is not None
    return r


def bip340_public(secret: bytes) -> str:
    return _mul(_G, int.from_bytes(secret, "big"))[0].to_bytes(32, "big").hex()


def bip340_sign(secret: bytes, msg: bytes) -> str:
    """BIP-340's default signing, with ``aux_rand`` all zero."""
    d0 = int.from_bytes(secret, "big")
    assert 1 <= d0 < _N
    pt = _mul(_G, d0)
    d = d0 if pt[1] % 2 == 0 else _N - d0
    px = pt[0].to_bytes(32, "big")
    t = (d ^ int.from_bytes(_tagged("BIP0340/aux", bytes(32)), "big")).to_bytes(32, "big")
    k0 = int.from_bytes(_tagged("BIP0340/nonce", t + px + msg), "big") % _N
    r = _mul(_G, k0)
    k = k0 if r[1] % 2 == 0 else _N - k0
    rx = r[0].to_bytes(32, "big")
    e = int.from_bytes(_tagged("BIP0340/challenge", rx + px + msg), "big") % _N
    return (rx + ((k + e * d) % _N).to_bytes(32, "big")).hex()


# CB §3.3 and §4.1: a ``bip340`` key, the operator's Nostr identity in these vectors.
NOSTR_LABEL = "controller-binding-v0 vectors: an operator's Nostr key (bip340)"
NOSTR_SECRET = sha(NOSTR_LABEL.encode())
NOSTR = "operator-nostr"
PUB[NOSTR] = bip340_public(NOSTR_SECRET)
NOSTR_KIND = 3374
CREATED_AT = 1790812800  # ISSUED, as the signer's clock gives it; nothing checks it (CB §4.1)


def nostr_sig(version: str, signed_octets: bytes, *, kind: int = NOSTR_KIND, digest: str | None = None) -> dict:
    """CB §4.1: the signing event's BIP-340 signature, with its ``created_at``."""
    content = f"{version}:{digest or shx(signed_octets)}"
    event = json.dumps([0, PUB[NOSTR], CREATED_AT, kind, [], content], separators=(",", ":"), ensure_ascii=False)
    return {"created_at": CREATED_AT, "sig": bip340_sign(NOSTR_SECRET, sha(event.encode()))}

BINDING_PROPS = ["controller_binding_form", "controller_binding_signatures", "controller_binding_window",
                 "controller_binding_revocation", "controller_binding_credential"]

# CB §3.2.
METHODS = {"same_controller_asserted": "dual_signature/0", "delegated_by": "dual_signature/0",
           "same_organization_credentialed": "dual_signature_credential/0"}
CREDENTIAL_METHOD = ("Ed25519 over UTF-8 of JCS of the credential's other members "
                     "(controller-binding-v0 §10, vectors only)")
ORGANIZATION = shx(b"controller-binding-v0 vectors: an organization label")

# CB §7 item 2: what a binding whose form and signatures pass proves, and what it states.
PROVES = "control of both keys at the ceremony"
STATES = {"same_controller_asserted": "both key holders state that one controller holds both keys",
          "delegated_by": "both key holders state that the delegator delegated to the other key",
          "same_organization_credentialed": "both key holders state that both keys are held within one organization"}
CREDENTIALED = "a trusted issuer key states that both keys are held within one organization"

# IP §6.7.4.
SHOWN = {"FAIL": "redundant, not corroborating", "NOT_CHECKED": "not corroborating"}
BECOMES = {"FAIL": "INSUFFICIENT", "NOT_CHECKED": "UNKNOWN"}

CLAIM = "the deal's step was completed"
HALF_TIMES = ("2026-10-15T00:00:20Z", "2026-10-15T00:00:21Z")
ISSUED = "2026-10-01T00:00:00Z"
NOT_AFTER = "2027-10-01T00:00:00Z"
EVAL = "2026-10-19T01:00:00Z"


def signed(body: dict, signer: str) -> dict:
    if signer == NOSTR:
        return dict(body, sig=nostr_sig(body["revocation_version"], jcs(body).encode()))
    return dict(body, sig=PRIV[signer].sign(jcs(body).encode()).hex())


def octets(value: dict) -> dict:
    return {"media_type": J, "octets_text": jcs(value)}


def binding(claim: str, holders: tuple[str, str], *, signers: tuple[str, ...] | None = None,
            not_after: str = NOT_AFTER, method: str | None = None, nonce: str = "ceremony-1",
            typed: bool | None = None, **added: Any) -> dict:
    """A binding record over the two named keys (CB §3), signed by ``signers`` (default: both keys,
    in the order of ``keys``) over the record without ``sigs`` (CB §4), each key as its type signs
    (CB §4.1). ``key_types`` is present when a key is the ``bip340`` key, unless ``typed`` is
    False."""
    keys = sorted(PUB[h] for h in holders)
    by_key = {PUB[h]: h for h in holders}
    body = {"binding_version": "controller-binding/0", "claim": claim, "method": method or METHODS[claim],
            "keys": keys, "issued_at": ISSUED, "not_before": ISSUED, "not_after": not_after,
            "revocation": "revocation_statement/0", "nonce": nonce, **added}
    if typed if typed is not None else NOSTR in holders:
        body["key_types"] = ["bip340" if by_key[k] == NOSTR else "ed25519" for k in keys]
    names = signers if signers is not None else tuple(by_key[k] for k in keys)
    data = jcs(body).encode()
    return dict(body, sigs=[{"key_id": PUB[n], "sig": nostr_sig("controller-binding/0", data) if n == NOSTR
                             else PRIV[n].sign(data).hex()} for n in names])


def binding_digest(record: dict) -> str:
    """CB §4: SHA-256 of the signing input, the record without ``sigs``."""
    return shx(jcs({k: v for k, v in record.items() if k != "sigs"}).encode())


def revocation(record: dict, by: str, revoked_at: str) -> dict:
    """A revocation statement (CB §5), signed by ``by``."""
    return signed({"revocation_version": "controller-binding-revocation/0", "binding": binding_digest(record),
                   "key_id": PUB[by], "revoked_at": revoked_at}, by)


def credential(holders: tuple[str, str], signer: str) -> dict:
    """CB §10's credential: issued by the credential issuer key, signed by ``signer``."""
    return signed({"issued_at": ISSUED, "issuer": PUB["credential-issuer"], "keys": sorted(PUB[h] for h in holders),
                   "organization": ORGANIZATION}, signer)


def credentialed(holders: tuple[str, str], signer: str, method: str = CREDENTIAL_METHOD) -> tuple[dict, dict]:
    cred = octets(credential(holders, signer))
    record = binding("same_organization_credentialed", holders, credential={
        "issuer": PUB["credential-issuer"], "method": method, "digest": shx(cred["octets_text"].encode())})
    return record, cred


def pins() -> dict:
    trust = {"foreign_keys": sorted([PUB["producer-a"], PUB["producer-b"], PUB["producer-c"]]),
             "credential_issuers": [PUB["credential-issuer"]]}
    return {"trust_policy": trust,
            "verification_policy": {"online": False, "profiles_implemented": [PROFILE],
                                    "binding_methods_implemented": sorted(set(METHODS.values())),
                                    "credential_methods_implemented": [CREDENTIAL_METHOD]},
            "contract_ref": CONTRACT_REF, "contract_digest": CONTRACT_DIGEST, "evaluation_time": EVAL}


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------


def case(cid: str, title: str, cites: list[str], record: dict, props: dict, *, binds_pair: bool, applies: bool,
         independence: str, reason: str | None, second: str = "producer-b",
         revocations: list[dict] | None = None, cred: dict | None = None, fails: list[str]) -> dict:
    halves = [half(CLAIM, HALF_TIMES[0], "producer-a"), half(CLAIM, HALF_TIMES[1], second)]
    proves: list[str] = []
    if props.get("controller_binding_form") == "PASS" and props.get("controller_binding_signatures") == "PASS":
        proves = [PROVES, STATES[record["claim"]]]
        if props.get("controller_binding_credential") == "PASS":
            proves.append(CREDENTIALED)
    inputs: dict[str, Any] = {"halves": halves, "binding": octets(record)}
    if revocations is not None:
        inputs["revocations"] = [octets(r) for r in revocations]
    if cred is not None:
        inputs["credential"] = cred
    expected = {
        "halves": {"signatures": ["PASS", "PASS"], "agree": True},
        "binding": {"claim": record["claim"], "binding_digest": binding_digest(record), "properties": props,
                    "binds_pair": binds_pair, "applies": applies, "proves": proves},
        "issuer_independence": {"status": independence, "shown_as": SHOWN[independence], "reason": reason,
                                "satisfied_becomes": {"r-corroborated": BECOMES[independence]}},
        "fails": fails,
    }
    return {"id": cid, "title": title, "cites": cites,
            "source": "derived: two producer records (IP §11.5) and a binding record (CB §3)",
            "mode": "presented", "pins": pins(), "inputs": inputs, "expected": expected}


def by_binding(record: dict) -> str:
    return f"controller binding {record['claim']} {binding_digest(record)}"


def ok(**over: str) -> dict:
    props = {"controller_binding_form": "PASS", "controller_binding_signatures": "PASS",
             "controller_binding_window": "PASS", "controller_binding_revocation": "NOT_CHECKED"}
    return props | over


def cases() -> list[dict]:
    ab = ("producer-a", "producer-b")
    out = []

    r = binding("same_controller_asserted", ab)
    out.append(case("valid-same-controller", "Both keys bind themselves as one controller's",
                    ["CB §3", "CB §4", "CB §6", "CB §7", "IP §6.7.4"], r, ok(),
                    binds_pair=True, applies=True, independence="FAIL", reason=by_binding(r), fails=[]))

    r = binding("delegated_by", ab, delegator=PUB["producer-a"])
    out.append(case("valid-delegated-by", "The first key delegated to the second, and both signed",
                    ["CB §3.2", "CB §6", "CB §7", "IP §6.7.4"], r, ok(),
                    binds_pair=True, applies=True, independence="FAIL", reason=by_binding(r), fails=[]))

    r, cred = credentialed(ab, "credential-issuer")
    out.append(case("valid-same-organization-credentialed",
                    "Both keys bind themselves as one organization's, with a credential from a trusted issuer",
                    ["CB §3.2", "CB §6", "CB §7", "IP §6.7.4"], r, ok(controller_binding_credential="PASS"),
                    binds_pair=True, applies=True, independence="FAIL", reason=by_binding(r), cred=cred, fails=[]))

    r, cred = credentialed(ab, "credential-issuer", method="org.example.credential-method-not-implemented")
    out.append(case("credential-method-unimplemented",
                    "A same-organization binding whose credential method the verifier does not implement",
                    ["CB §6.1", "CB §6.2", "IP §6.7.4"], r, ok(controller_binding_credential="NOT_CHECKED"),
                    binds_pair=True, applies=True, independence="FAIL", reason=by_binding(r), cred=cred, fails=[]))

    r = binding("same_controller_asserted", ab)
    out.append(case("revoked-after-the-pair", "A binding revoked by one key after both halves were signed",
                    ["CB §5", "CB §6.1", "IP §6.7.4"], r, ok(),
                    binds_pair=True, applies=True, independence="FAIL", reason=by_binding(r),
                    revocations=[revocation(r, "producer-b", "2026-10-18T00:00:00Z")], fails=[]))

    r = binding("same_controller_asserted", ab, not_after="2026-10-10T00:00:00Z")
    out.append(case("expired", "A binding whose window ended before the halves were signed",
                    ["CB §6.1", "CB §6.2", "IP §6.7.4"], r, ok(controller_binding_window="FAIL"),
                    binds_pair=True, applies=False, independence="NOT_CHECKED", reason=None,
                    fails=["controller_binding_window"]))

    r = binding("same_controller_asserted", ab)
    out.append(case("revoked", "A binding revoked by one key before the halves were signed",
                    ["CB §5", "CB §6.1", "CB §6.2", "IP §6.7.4"], r, ok(controller_binding_revocation="FAIL"),
                    binds_pair=True, applies=False, independence="NOT_CHECKED", reason=None,
                    revocations=[revocation(r, "producer-b", "2026-10-12T00:00:00Z")],
                    fails=["controller_binding_revocation"]))

    r = binding("same_controller_asserted", ab, signers=(min(ab, key=PUB.__getitem__),))
    out.append(case("one-key-signed", "A binding record signed by one of its two keys only",
                    ["CB §4", "CB §6.1", "CB §6.2", "IP §6.7.4"], r,
                    {"controller_binding_form": "PASS", "controller_binding_signatures": "FAIL",
                     "controller_binding_window": "PASS", "controller_binding_revocation": "NOT_CHECKED"},
                    binds_pair=True, applies=False, independence="NOT_CHECKED", reason=None,
                    fails=["controller_binding_signatures"]))

    r = binding("same_controller_asserted", ("producer-a", "producer-a"), signers=("producer-a", "producer-a"))
    out.append(case("same-key-halves", "Two halves under one key, and a binding of that key to itself",
                    ["CB §3.1", "CB §6.1", "IP §6.7.4"], r, {"controller_binding_form": "FAIL"},
                    binds_pair=True, applies=False, independence="FAIL", reason="same key", second="producer-a",
                    fails=["controller_binding_form"]))

    r = binding("same_controller_asserted", ("producer-a", "producer-c"))
    out.append(case("other-keys", "A valid binding of the first half's key to a third key",
                    ["CB §6.2", "IP §6.7.4"], r, ok(),
                    binds_pair=False, applies=False, independence="NOT_CHECKED", reason=None, fails=[]))

    r, cred = credentialed(ab, "other-issuer")
    out.append(case("credential-forged", "A credential that names the issuer and is signed by another key",
                    ["CB §6.1", "CB §6.2", "IP §6.7.4"], r, ok(controller_binding_credential="FAIL"),
                    binds_pair=True, applies=True, independence="FAIL", reason=by_binding(r), cred=cred,
                    fails=["controller_binding_credential"]))

    r = binding("same_controller_asserted", ab, method="single_signature/0")
    out.append(case("unknown-method", "A binding under a method this revision does not define, over two valid signatures",
                    ["CB §3.2", "CB §6.1", "CB §6.2", "IP §6.7.4"], r,
                    ok(controller_binding_signatures="NOT_CHECKED"),
                    binds_pair=True, applies=False, independence="NOT_CHECKED", reason=None, fails=[]))

    r = binding("delegated_by", ab, delegator=PUB["producer-c"])
    out.append(case("delegator-not-bound", "A delegation whose delegator is neither bound key",
                    ["CB §3.2", "CB §6.1", "IP §6.7.4"], r, {"controller_binding_form": "FAIL"},
                    binds_pair=True, applies=False, independence="NOT_CHECKED", reason=None,
                    fails=["controller_binding_form"]))

    r = binding("same_controller_asserted", ab)
    out.append(case("revocation-by-other-key", "A revocation before the halves, signed by a key the binding does not bind",
                    ["CB §5", "CB §6.1", "IP §6.7.4"], r, ok(),
                    binds_pair=True, applies=True, independence="FAIL", reason=by_binding(r),
                    revocations=[revocation(r, "producer-c", "2026-10-12T00:00:00Z")], fails=[]))

    an = ("producer-a", NOSTR)
    r = binding("same_controller_asserted", an)
    out.append(case("valid-nostr-key", "A half's Ed25519 key bound to a bip340 (Nostr) key, signed by the Nostr event",
                    ["CB §3.3", "CB §4.1", "CB §6.1", "CB §6.2", "IP §6.7.4"], r, ok(),
                    binds_pair=False, applies=False, independence="NOT_CHECKED", reason=None, fails=[]))

    r = binding("same_controller_asserted", an, typed=False)
    out.append(case("nostr-key-read-as-ed25519", "The same keys and signatures with no key_types: both keys are ed25519",
                    ["CB §3.1", "CB §3.3", "CB §4.1", "CB §6.1"], r, ok(controller_binding_signatures="FAIL"),
                    binds_pair=False, applies=False, independence="NOT_CHECKED", reason=None,
                    fails=["controller_binding_signatures"]))

    r = binding("same_controller_asserted", an)
    other = binding("same_controller_asserted", an, nonce="ceremony-2")
    r["sigs"] = [dict(s, sig=nostr_sig("controller-binding/0", b"", digest=binding_digest(other)))
                 if s["key_id"] == PUB[NOSTR] else s for s in r["sigs"]]
    out.append(case("nostr-wrong-digest", "The Nostr event names the digest of another record",
                    ["CB §4.1", "CB §6.1"], r, ok(controller_binding_signatures="FAIL"),
                    binds_pair=False, applies=False, independence="NOT_CHECKED", reason=None,
                    fails=["controller_binding_signatures"]))

    r = binding("same_controller_asserted", an)
    signing_input = jcs({k: v for k, v in r.items() if k != "sigs"}).encode()
    r["sigs"] = [dict(s, sig=nostr_sig("controller-binding/0", signing_input, kind=1))
                 if s["key_id"] == PUB[NOSTR] else s for s in r["sigs"]]
    out.append(case("nostr-other-kind", "The Nostr event is a text note (kind 1) over the right content",
                    ["CB §4.1", "CB §6.1"], r, ok(controller_binding_signatures="FAIL"),
                    binds_pair=False, applies=False, independence="NOT_CHECKED", reason=None,
                    fails=["controller_binding_signatures"]))

    r = binding("same_controller_asserted", an)
    out.append(case("nostr-revoked", "A revocation by the bip340 key, signed by the Nostr event, before the halves",
                    ["CB §4.1", "CB §5", "CB §6.1"], r, ok(controller_binding_revocation="FAIL"),
                    binds_pair=False, applies=False, independence="NOT_CHECKED", reason=None,
                    revocations=[revocation(r, NOSTR, "2026-10-12T00:00:00Z")],
                    fails=["controller_binding_revocation"]))
    return out


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def _dump(value: Any) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def build() -> dict[str, bytes]:
    all_cases = cases()
    ids = [c["id"] for c in all_cases]
    assert len(ids) == len(set(ids)), "duplicate case id"
    labels = {**coverage_vectors.SEED_LABELS, **SEED_LABELS}
    corpus = {
        "set": SET,
        "status": STATUS,
        "profile": PROFILE,
        "spec": SPEC,
        "test_keys": {
            "note": ("TEST-ONLY. Each private key is the 32-byte Ed25519 seed SHA-256(seed_label), except "
                     "operator-nostr, whose BIP-340 secret key is SHA-256(seed_label)."),
            "keys": {**{name: {"seed_label": labels[name], "public": PUB[name]}
                        for name in ("producer-a", "producer-b", "producer-c", "credential-issuer", "other-issuer")},
                     NOSTR: {"seed_label": NOSTR_LABEL, "public": PUB[NOSTR], "key_type": "bip340"}},
        },
        "contract": {"document": CONTRACT, "document_jcs": jcs(CONTRACT), "contract_ref": CONTRACT_REF,
                     "contract_digest": CONTRACT_DIGEST, "schema": EC_SCHEMA},
        "credential_method": CREDENTIAL_METHOD,
        "binding_properties": BINDING_PROPS,
        "count": len(all_cases),
        "cases": all_cases,
    }
    files = {"vectors.json": _dump(corpus)}
    files["manifest.json"] = _dump({
        "set": SET,
        "status": STATUS,
        "spec": SPEC,
        "generator": "python/scripts/generate_controller_binding_v0_vectors.py",
        "files": [{"path": name, "sha256": shx(data), "count": json.loads(data).get("count")}
                  for name, data in sorted(files.items())],
    })
    return files


def write(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for name, data in build().items():
        (out / name).write_bytes(data)
    files = sorted((p.relative_to(out).as_posix(), p) for p in out.rglob("*") if p.is_file())
    lines = [f"{shx(p.read_bytes())}  {rel}" for rel, p in files if rel != "SHA256SUMS"]
    (out / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    write(args.out)


if __name__ == "__main__":
    main()
