# SPDX-License-Identifier: BSD-3-Clause
"""The controller binding vectors (``vectors/controller-binding-v0/``).

Every case is run from its inputs alone, by an evaluator written here from
``spec/controller-binding-v0.md`` (CB) §3 to §7 and IP §6.7.4:

- the halves' signatures and agreement;
- the binding properties of CB §6.1, with each key signing as its type says (CB §3.3, §4.1): an
  ``ed25519`` key with Ed25519, a ``bip340`` key with a Nostr event checked here under BIP-340;
- whether the binding binds the pair and applies to it (CB §6.2);
- what it proves (CB §7 item 2);
- the pair's ``issuer_independence`` (CB §7 item 4).

All of it is compared with the case's whole ``expected`` block, which the generator states by
hand. Nothing here imports the generator. The test regenerates the corpus twice and requires
both runs to be byte-identical to the committed files. It also runs defective evaluators, each of
which must disagree with at least one case.
"""
from __future__ import annotations

import ast
import copy
import hashlib
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("cryptography")

from cryptography.exceptions import InvalidSignature  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # noqa: E402

from agent_action_capsule.canonical import jcs  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "vectors" / "controller-binding-v0"
GENERATOR = ROOT / "python" / "scripts" / "generate_controller_binding_v0_vectors.py"
HAND_WRITTEN = ("README.md",)
DATA = json.loads((VECTORS / "vectors.json").read_text(encoding="utf-8"))
CASES = DATA["cases"]
SPEC_TEXT = (ROOT / DATA["spec"]).read_text(encoding="utf-8")
IP_TEXT = (ROOT / "spec" / "interop-profile-v0.md").read_text(encoding="utf-8")

# CB §3.1 and §3.2.
COMMON = {"binding_version", "claim", "method", "keys", "issued_at", "not_before", "not_after", "revocation",
          "nonce", "sigs"}
CLAIMS = {"same_controller_asserted": ("dual_signature/0", set()),
          "delegated_by": ("dual_signature/0", {"delegator"}),
          "same_organization_credentialed": ("dual_signature_credential/0", {"credential"})}
REVOCATION_MEMBERS = {"revocation_version", "binding", "key_id", "revoked_at", "sig"}
CREDENTIAL_MEMBERS = {"issued_at", "issuer", "keys", "organization", "sig"}
HEX64 = re.compile(r"[0-9a-f]{64}")
HEX128 = re.compile(r"[0-9a-f]{128}")
NONCE = re.compile(r"[0-9a-f]{32,}")
TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")

# CB §7 items 2 and 4; IP §6.7.4.
PROVES = "control of both keys at the ceremony"
STATES = {"same_controller_asserted": "both key holders state that one controller holds both keys",
          "delegated_by": "both key holders state that the delegator delegated to the other key",
          "same_organization_credentialed": "both key holders state that both keys are held within one organization"}
CREDENTIALED = "a trusted issuer key states that both keys are held within one organization"
SHOWN = {"FAIL": ("redundant, not corroborating", "INSUFFICIENT"),
         "NOT_CHECKED": ("not corroborating", "UNKNOWN"),
         "PASS": ("corroborating", None)}


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def is_hex64(v: Any) -> bool:
    return isinstance(v, str) and HEX64.fullmatch(v) is not None


def is_time(v: Any) -> bool:
    return isinstance(v, str) and TIME.fullmatch(v) is not None


def ed25519_ok(key_hex: Any, sig_hex: Any, data: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex)).verify(bytes.fromhex(sig_hex), data)
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


# BIP-340 verification, written here from BIP-340's specification.
_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
      0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _tagged(tag: str, msg: bytes) -> bytes:
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + msg).digest()


def _add(a: Any, b: Any) -> Any:
    if a is None or b is None:
        return a or b
    if a[0] == b[0] and a[1] != b[1]:
        return None
    lam = (3 * a[0] * a[0] * pow(2 * a[1], _P - 2, _P) if a == b
           else (b[1] - a[1]) * pow(b[0] - a[0], _P - 2, _P)) % _P
    x = (lam * lam - a[0] - b[0]) % _P
    return x, (lam * (a[0] - x) - a[1]) % _P


def _mul(pt: Any, n: int) -> Any:
    r = None
    for i in range(256):
        if (n >> i) & 1:
            r = _add(r, pt)
        pt = _add(pt, pt)
    return r


def bip340_ok(key: bytes, msg: bytes, sig: bytes) -> bool:
    """BIP-340 Verify(pk, m, sig)."""
    if len(key) != 32 or len(sig) != 64:
        return False
    x = int.from_bytes(key, "big")
    y_sq = (pow(x, 3, _P) + 7) % _P
    y = pow(y_sq, (_P + 1) // 4, _P)
    if x >= _P or pow(y, 2, _P) != y_sq:
        return False
    pt = (x, y if y % 2 == 0 else _P - y)
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if r >= _P or s >= _N:
        return False
    e = int.from_bytes(_tagged("BIP0340/challenge", sig[:32] + key + msg), "big") % _N
    rr = _add(_mul(_G, s), _mul(pt, _N - e))
    return rr is not None and rr[1] % 2 == 0 and rr[0] == r


# CB §4.1.
NOSTR_KIND = 3374
KEY_TYPES = {"ed25519", "bip340"}
MAX_CREATED_AT = 2**53 - 1


def nostr_ok(key_hex: str, sig: Any, version: str, signed_octets: bytes, rules: Rules) -> bool:
    """CB §4.1: ``sig`` is ``{created_at, sig}``, the BIP-340 signature over the id of the Nostr
    event (NIP-01) of kind 3374, no tags, and content ``<version>:<SHA-256 of signed_octets>``."""
    if not (isinstance(sig, dict) and set(sig) == {"created_at", "sig"} and isinstance(sig["sig"], str)
            and HEX128.fullmatch(sig["sig"])):
        return False
    if rules.created_at_form and not (type(sig["created_at"]) is int and 0 <= sig["created_at"] <= MAX_CREATED_AT):
        return False
    content = f"{version}:{sha(signed_octets)}"
    for kind in ([NOSTR_KIND] if rules.event_kind else [NOSTR_KIND, 1]):
        event = json.dumps([0, key_hex, sig["created_at"], kind, [], content], separators=(",", ":"),
                           ensure_ascii=False)
        if bip340_ok(bytes.fromhex(key_hex), hashlib.sha256(event.encode()).digest(), bytes.fromhex(sig["sig"])):
            return True
    return False


def key_types(r: dict, rules: Rules) -> list[str]:
    """CB §3.1 and §3.3: the binding's key types, in the order of ``keys``; ``ed25519`` for both
    when ``key_types`` is absent."""
    if rules.key_types_read and "key_types" in r:
        return list(r["key_types"])
    return ["ed25519", "ed25519"]


def sig_ok(key_hex: str, key_type: str, sig: Any, version: str, signed_octets: bytes, rules: Rules) -> bool:
    if key_type == "bip340":
        return nostr_ok(key_hex, sig, version, signed_octets, rules)
    if key_type == "ed25519":
        return isinstance(sig, str) and HEX128.fullmatch(sig) is not None and ed25519_ok(key_hex, sig, signed_octets)
    return False  # §3.3: a key type the verifier does not know never verifies


def without(d: dict, key: str) -> dict:
    return {k: v for k, v in d.items() if k != key}


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict:
    names = [k for k, _ in pairs]
    if len(names) != len(set(names)):
        raise ValueError(f"duplicate member name in {names}")  # IP §5.2: not well formed
    return dict(pairs)


def parse(octets_text: str) -> Any:
    return json.loads(octets_text, object_pairs_hook=_no_duplicates)


def digest_of(r: dict) -> str:
    """CB §4: the binding digest is SHA-256 of the signing input, the record without ``sigs``."""
    return sha(jcs(without(r, "sigs")))


# ---------------------------------------------------------------------------
# The evaluator, CB §3 to §7
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Rules:
    """Each field is one rule of CB; a defective evaluator replaces one."""

    distinct_keys: bool = True              # §3.1: a key bound to itself is malformed
    delegator_bound: bool = True            # §3.2: the delegator is one of the keys
    method_implemented: bool = True         # §3.2: an unimplemented method is NOT_CHECKED
    both_sign: bool = True                  # §4: both keys sign
    window: bool = True                     # §6.1
    revocation: bool = True                 # §5, §6.1
    revocation_by_bound_key: bool = True    # §5: only a bound key revokes
    revocation_from_revoked_at: bool = True  # §5: a later revocation leaves T untouched
    credential: bool = True                 # §6.1
    credential_decides: bool = False        # §6.2: the credential never decides application
    binds_pair: bool = True                 # §6.2
    not_checked_revocation_applies: bool = True  # §6.2: only a FAIL revocation blocks
    binding_gives: str = "FAIL"             # §7 item 4
    key_types_read: bool = True             # §3.3: key_types gives each key's type
    event_kind: bool = True                 # §4.1: the signing event is of kind 3374
    created_at_form: bool = True            # §4.1: created_at is an integer in 0..2^53-1
    bip340_nonce: bool = True               # §3.1, §9.3: a bip340 binding's nonce is 32+ hex


SPEC = Rules()


def form_ok(r: Any, rules: Rules) -> bool:
    if not isinstance(r, dict) or r.get("claim") not in CLAIMS:
        return False
    method, added = CLAIMS[r["claim"]]
    if set(r) - {"key_types"} != COMMON | added or r["binding_version"] != "controller-binding/0":
        return False
    if "key_types" in r and not (isinstance(r["key_types"], list) and len(r["key_types"]) == 2
                                 and all(isinstance(k, str) for k in r["key_types"])):
        return False
    if (rules.bip340_nonce and "bip340" in r.get("key_types", [])
            and not (isinstance(r["nonce"], str) and NONCE.fullmatch(r["nonce"]))):
        return False  # §3.1, §9.3
    other_claims = {m for c, (m, _) in CLAIMS.items() if c != r["claim"]} - {method}
    if not isinstance(r["method"], str) or r["method"] in other_claims:
        return False
    keys = r["keys"]
    if not (isinstance(keys, list) and len(keys) == 2 and all(is_hex64(k) for k in keys) and keys == sorted(keys)):
        return False
    if rules.distinct_keys and keys[0] == keys[1]:
        return False
    if not all(is_time(r[t]) for t in ("issued_at", "not_before", "not_after")):
        return False
    if not r["not_before"] <= r["issued_at"] < r["not_after"]:
        return False
    if r["revocation"] != "revocation_statement/0" or not isinstance(r["nonce"], str):
        return False
    if not isinstance(r["sigs"], list) or not all(isinstance(s, dict) and set(s) == {"key_id", "sig"}
                                                  for s in r["sigs"]):
        return False
    if "delegator" in added and rules.delegator_bound and r["delegator"] not in keys:
        return False
    if "credential" in added:
        c = r["credential"]
        if not (isinstance(c, dict) and set(c) == {"issuer", "method", "digest"} and is_hex64(c["issuer"])
                and isinstance(c["method"], str) and is_hex64(c["digest"])):
            return False
    return True


def signatures(r: dict, case: dict, rules: Rules) -> str:
    if rules.method_implemented and r["method"] not in case["pins"]["verification_policy"][
            "binding_methods_implemented"]:
        return "NOT_CHECKED"
    types = key_types(r, rules)
    if not set(types) <= KEY_TYPES:
        return "NOT_CHECKED"
    type_of = dict(zip(r["keys"], types))
    data = jcs(without(r, "sigs"))
    sigs = r["sigs"]
    if rules.both_sign:
        good = len(sigs) == 2 and [s["key_id"] for s in sigs] == r["keys"]
    else:
        good = 0 < len(sigs) <= 2 and all(s["key_id"] in r["keys"] for s in sigs)
    return "PASS" if good and all(sig_ok(s["key_id"], type_of[s["key_id"]], s["sig"], "controller-binding/0",
                                         data, rules) for s in sigs) else "FAIL"


def revocation_applies(statement: dict, r: dict, rules: Rules) -> bool:
    type_of = dict(zip(r["keys"], key_types(r, rules)))
    return (set(statement) == REVOCATION_MEMBERS
            and statement["revocation_version"] == "controller-binding-revocation/0"
            and statement["binding"] == digest_of(r)
            and (statement["key_id"] in r["keys"] or not rules.revocation_by_bound_key)
            and is_time(statement["revoked_at"])
            and sig_ok(statement["key_id"], type_of.get(statement["key_id"], "ed25519"), statement["sig"],
                       "controller-binding-revocation/0", jcs(without(statement, "sig")), rules))


def revocation_status(r: dict, case: dict, times: list[str], rules: Rules) -> str:
    if not rules.revocation:
        return "NOT_CHECKED"
    for o in case["inputs"].get("revocations", []):
        s = parse(o["octets_text"])
        if revocation_applies(s, r, rules) and (not rules.revocation_from_revoked_at
                                         or any(s["revoked_at"] <= t for t in times)):
            return "FAIL"
    return "NOT_CHECKED"


def credential_status(r: dict, case: dict, rules: Rules) -> str:
    c = r["credential"]
    pins = case["pins"]
    if "credential" not in case["inputs"]:
        return "NOT_PRESENT"
    if c["method"] not in pins["verification_policy"]["credential_methods_implemented"]:
        return "NOT_CHECKED"
    if not rules.credential:
        return "PASS"
    octets = case["inputs"]["credential"]["octets_text"].encode()
    o = parse(octets.decode())
    good = (sha(octets) == c["digest"] and set(o) == CREDENTIAL_MEMBERS and o["issuer"] == c["issuer"]
            and c["issuer"] in pins["trust_policy"]["credential_issuers"] and o["keys"] == r["keys"]
            and ed25519_ok(o["issuer"], o["sig"], jcs(without(o, "sig"))))
    return "PASS" if good else "FAIL"


def binding_properties(r: Any, case: dict, times: list[str], rules: Rules) -> dict:
    if not form_ok(r, rules):
        return {"controller_binding_form": "FAIL"}
    props = {"controller_binding_form": "PASS", "controller_binding_signatures": signatures(r, case, rules),
             "controller_binding_window": "PASS" if not rules.window
             or all(r["not_before"] <= t < r["not_after"] for t in times) else "FAIL",
             "controller_binding_revocation": revocation_status(r, case, times, rules)}
    if r["claim"] == "same_organization_credentialed":
        props["controller_binding_credential"] = credential_status(r, case, rules)
    return props


def evaluate(case: dict, rules: Rules = SPEC) -> dict:
    trusted = set(case["pins"]["trust_policy"]["foreign_keys"])
    halves = [parse(h["octets_text"]) for h in case["inputs"]["halves"]]
    sigs = ["PASS" if h["producer"] in trusted
            and ed25519_ok(h["producer"], h["sig"], jcs(without(h, "sig"))) else "FAIL" for h in halves]
    pair = sorted(h["producer"] for h in halves)
    times = [h["issued_at"] for h in halves]

    r = parse(case["inputs"]["binding"]["octets_text"])
    props = binding_properties(r, case, times, rules)
    binds = (not rules.binds_pair) or (isinstance(r.get("keys"), list) and sorted(r["keys"]) == pair)
    blocking = {"FAIL"} if rules.not_checked_revocation_applies else {"FAIL", "NOT_CHECKED"}
    applies = (binds and all(props.get(p) == "PASS" for p in ("controller_binding_form",
                                                               "controller_binding_signatures",
                                                               "controller_binding_window"))
               and props.get("controller_binding_revocation") not in blocking
               and not (rules.credential_decides and props.get("controller_binding_credential") == "FAIL"))
    proves = []
    if props.get("controller_binding_form") == "PASS" and props.get("controller_binding_signatures") == "PASS":
        proves = [PROVES, STATES[r["claim"]]] + ([CREDENTIALED] if props.get("controller_binding_credential")
                                                  == "PASS" else [])
    digest = digest_of(r)
    if pair[0] == pair[1]:
        status, reason = "FAIL", "same key"
    elif applies:
        status, reason = rules.binding_gives, f"controller binding {r['claim']} {digest}"
    else:
        status, reason = "NOT_CHECKED", None
    shown, becomes = SHOWN[status]
    return {"halves": {"signatures": sigs, "agree": halves[0]["claim"] == halves[1]["claim"]},
            "binding": {"claim": r.get("claim"), "binding_digest": digest, "properties": props,
                        "binds_pair": binds, "applies": applies, "proves": proves},
            "issuer_independence": {"status": status, "shown_as": shown, "reason": reason,
                                    "satisfied_becomes": {"r-corroborated": becomes}}}


def comparable(expected: dict) -> dict:
    e = copy.deepcopy(expected)
    e.pop("fails")
    return e


# ---------------------------------------------------------------------------
# The vectors
# ---------------------------------------------------------------------------


def test_corpus_shape_and_pins():
    assert DATA["count"] == len(CASES) == 25
    assert sha(DATA["contract"]["document_jcs"].encode()) == DATA["contract"]["contract_digest"]
    for case in CASES:
        assert case["pins"]["contract_digest"] == DATA["contract"]["contract_digest"]
        assert case["pins"]["verification_policy"]["online"] is False
        assert case["source"].startswith("derived: ")
        for o in [*case["inputs"]["halves"], case["inputs"]["binding"], *case["inputs"].get("revocations", [])]:
            assert o["octets_text"].encode() == jcs(parse(o["octets_text"])), case["id"]


def test_test_keys_derive_from_their_labels():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    for k in DATA["test_keys"]["keys"].values():
        secret = hashlib.sha256(k["seed_label"].encode()).digest()
        if k.get("key_type") == "bip340":
            assert _mul(_G, int.from_bytes(secret, "big"))[0].to_bytes(32, "big").hex() == k["public"]
            continue
        priv = Ed25519PrivateKey.from_private_bytes(secret)
        assert priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex() == k["public"]


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_case(case):
    assert evaluate(case) == comparable(case["expected"])


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_named_property_fails(case):
    props = evaluate(case)["binding"]["properties"]
    assert {p for p, s in props.items() if s == "FAIL"} == set(case["expected"]["fails"])


def test_required_cases_are_present():
    """The five the brief names, plus one valid binding per claim type."""
    ids = {c["id"] for c in CASES}
    assert {"valid-same-controller", "expired", "revoked", "one-key-signed", "same-key-halves"} <= ids
    claims = {c["expected"]["binding"]["claim"] for c in CASES if c["expected"]["binding"]["applies"]}
    assert claims == set(CLAIMS)


def test_a_binding_never_gives_pass():
    for case in CASES:
        assert case["expected"]["issuer_independence"]["status"] in {"FAIL", "NOT_CHECKED"}
        if case["expected"]["binding"]["applies"]:
            assert case["expected"]["issuer_independence"]["shown_as"] == "redundant, not corroborating"


def test_both_keys_sign_the_same_bytes():
    """CB §4: wherever signatures are expected to pass, both entries name the keys in order and
    verify over the one signing input."""
    for case in CASES:
        r = json.loads(case["inputs"]["binding"]["octets_text"])
        if case["expected"]["binding"]["properties"].get("controller_binding_signatures") != "PASS":
            continue
        data = jcs(without(r, "sigs"))
        type_of = dict(zip(r["keys"], key_types(r, SPEC)))
        assert [s["key_id"] for s in r["sigs"]] == r["keys"]
        assert all(sig_ok(s["key_id"], type_of[s["key_id"]], s["sig"], "controller-binding/0", data, SPEC)
                   for s in r["sigs"])


def test_one_key_signed_carries_a_valid_signature_by_one_bound_key():
    """The negative fails for the missing second signature, not for a broken first one."""
    case = next(c for c in CASES if c["id"] == "one-key-signed")
    r = json.loads(case["inputs"]["binding"]["octets_text"])
    assert len(r["sigs"]) == 1 and r["sigs"][0]["key_id"] in r["keys"]
    assert ed25519_ok(r["sigs"][0]["key_id"], r["sigs"][0]["sig"], jcs(without(r, "sigs")))


def test_spec_lists_every_case():
    section = SPEC_TEXT.split("## 10. Vectors", 1)[1].split("\n## ", 1)[0]
    assert set(re.findall(r"^\| `([a-z0-9-]+)` \|", section, re.M)) == {c["id"] for c in CASES}


def test_ip_points_to_this_document():
    section = IP_TEXT.split("#### 6.7.4", 1)[1].split("#### 6.7.5", 1)[0]
    assert "[CB §6.2]" in section and "never into `PASS`" in section


# ---------------------------------------------------------------------------
# Negative checks: each defective evaluator must disagree with some case
# ---------------------------------------------------------------------------

DEFECTS = {
    "a key may be bound to itself": replace(SPEC, distinct_keys=False),
    "any delegator": replace(SPEC, delegator_bound=False),
    "an undefined method is verified as dual_signature": replace(SPEC, method_implemented=False),
    "one signature is enough": replace(SPEC, both_sign=False),
    "window not checked": replace(SPEC, window=False),
    "revocation not checked": replace(SPEC, revocation=False),
    "any key may revoke": replace(SPEC, revocation_by_bound_key=False),
    "revocation reaches back": replace(SPEC, revocation_from_revoked_at=False),
    "credential not checked": replace(SPEC, credential=False),
    "a failed credential discards the signatures": replace(SPEC, credential_decides=True),
    "binding applies to any pair": replace(SPEC, binds_pair=False),
    "NOT_CHECKED revocation blocks a binding": replace(SPEC, not_checked_revocation_applies=False),
    "a binding gives PASS": replace(SPEC, binding_gives="PASS"),
    "a binding is ignored": replace(SPEC, binding_gives="NOT_CHECKED"),
    "key_types ignored: every key is ed25519": replace(SPEC, key_types_read=False),
    "a Nostr event of any kind signs": replace(SPEC, event_kind=False),
    "any nonce with a bip340 key": replace(SPEC, bip340_nonce=False),
    "any created_at": replace(SPEC, created_at_form=False),
}


@pytest.mark.parametrize("name", list(DEFECTS))
def test_every_defective_evaluator_is_caught(name):
    rules = DEFECTS[name]
    assert any(evaluate(c, rules) != comparable(c["expected"]) for c in CASES), name


def test_ignoring_the_binding_is_the_unbound_keys_rule():
    """A verifier that ignores bindings gives NOT_CHECKED for every pair of distinct keys: the
    coverage-declaration corpus's unbound-keys case. The binding is what makes it FAIL."""
    rules = DEFECTS["a binding is ignored"]
    for case in CASES:
        got = evaluate(case, rules)["issuer_independence"]["status"]
        want = case["expected"]["issuer_independence"]["status"]
        if case["expected"]["binding"]["applies"]:
            assert (got, want) == ("NOT_CHECKED", "FAIL"), case["id"]


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
    listed = dict(reversed(line.split("  ", 1)) for line in (VECTORS / "SHA256SUMS").read_text().splitlines())
    assert set(listed) == set(_files(VECTORS)) - {"SHA256SUMS"}
    for name, digest in listed.items():
        assert sha((VECTORS / name).read_bytes()) == digest, name
    top = dict(reversed(line.split("  ", 1)) for line in (ROOT / "vectors" / "SHA256SUMS").read_text().splitlines())
    for name in set(_files(VECTORS)) - {"SHA256SUMS"}:
        assert top[f"controller-binding-v0/{name}"] == sha((VECTORS / name).read_bytes()), name
    corpora = json.loads((ROOT / "vectors" / "manifest.json").read_text())["corpora"]
    assert corpora["controller_binding_v0"] == "controller-binding-v0/manifest.json"
    assert "generate_controller_binding_v0_vectors.py" in (
        ROOT / "python" / "scripts" / "generate_all_vectors.py").read_text()


def test_does_not_import_the_generator():
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    modules = [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names]
    modules += [n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
    assert not [m for m in modules if m.startswith("generate_")]


def test_evaluator_names_every_binding_property():
    assert set(DATA["binding_properties"]) == {p for c in CASES for p in c["expected"]["binding"]["properties"]}



def test_revocation_names_the_signing_input_not_the_signed_record():
    """CB §4: the digest leaves out ``sigs``, so a second signature by either key cannot dodge a
    revocation that names the binding."""
    case = next(c for c in CASES if c["id"] == "revoked")
    r = parse(case["inputs"]["binding"]["octets_text"])
    named = parse(case["inputs"]["revocations"][0]["octets_text"])["binding"]
    assert named == digest_of(r) != sha(jcs(r))
    resigned = dict(r, sigs=[dict(s, sig="00" * 64) for s in r["sigs"]])
    assert digest_of(resigned) == named


def test_parse_rejects_duplicate_member_names():
    with pytest.raises(ValueError):
        parse('{"a":1,"a":2}')


# BIP-340's own test vectors (bitcoin/bips, bip-0340/test-vectors.csv), rows 0, 1, 5, 6 and 9: the
# BIP-340 check above against the BIP's answers, two valid and three invalid.
BIP340_ROWS = [
    ("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
     True),
    ("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
     "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
     "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
     True),
    ("EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34",
     "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
     "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
     False),
    ("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
     "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
     "FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A14602975563CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2",
     False),
    ("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
     "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
     "0000000000000000000000000000000000000000000000000000000000000000123DDA8328AF9C23A94C1FEECFD123BA4FB73476F0D594DCB65C6425BD186051",
     False),
]


@pytest.mark.parametrize("row", range(len(BIP340_ROWS)))
def test_the_bip340_check_agrees_with_the_bips_vectors(row):
    key, msg, sig, valid = BIP340_ROWS[row]
    assert bip340_ok(bytes.fromhex(key), bytes.fromhex(msg), bytes.fromhex(sig)) is valid
