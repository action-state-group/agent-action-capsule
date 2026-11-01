# SPDX-License-Identifier: BSD-3-Clause
"""The experimental evidence commitment carrier vectors are reproducible and agree with
spec/bindings/evidence-commitment-carriers-v0.md.

The generator states the expected values. This test re-runs it and requires byte-identical output.
With its own code it applies the binding's verify steps V0 to V5 to every carrier entry: the
carrier forms, the NIP-01 id and BIP-340 signature of each announce event (the mailbox test's
checks), the naddr (bech32), the commitment's Ed25519 signature over JCS, its staples, the newest
issued_at, and the cards V6 hands to the admission pack. A V5 answer goes to the reference
verifier of the interop profile, offline.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import re
import socket
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_public_key

from agent_action_capsule.interop_profile import (
    Exchange,
    InteropVerifier,
    Message,
    TrustPolicy,
    VerificationPolicy,
)

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "vectors" / "adapters" / "evidence-commitment-carriers"
GENERATOR = ROOT / "python" / "scripts" / "generate_evidence_commitment_carriers_vectors.py"
BINDING_TEXT = (ROOT / "spec" / "bindings" / "evidence-commitment-carriers-v0.md").read_text(encoding="utf-8")
DATA = json.loads((VECTORS / "vectors.json").read_text(encoding="utf-8"))
CASES = DATA["cases"]
KIND = DATA["carriage"]["announce_kind"]
EXT_URI = DATA["carriage"]["a2a_extension_uri"]
ER_EXT_URI = "https://datatracker.ietf.org/doc/draft-mih-agent-evidence-request/"
READ_AT = DATA["verifier"]["read_at"]
assert DATA["verifier"]["clock_skew"] == "PT5M"
SKEW = timedelta(minutes=5)
PROFILES = {"evidence-commitment/0", "evidence-commitment/1"}


def _module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# NIP-01, BIP-340 and bech32 from the mailbox test, which checks them against published values.
nostr = _module("_nostr_mailbox_checks", Path(__file__).with_name("test_nostr_mailbox_vectors.py"))


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def jcs(value: Any) -> bytes:
    """RFC 8785 for the value space of these vectors: ASCII keys, strings, booleans, null, integers."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def b64u(text: str) -> bytes:
    out = nostr.b64url(text)
    assert out is not None, "base64url"
    return out


_HEX64 = re.compile(r"[0-9a-f]{64}")
_SHA_TAG = re.compile(r"sha256:[0-9a-f]{64}")

# Every check a mutant test may switch off.
ALL_CHECKS = frozenset({"discovery_object", "nostr_event", "key_id_spki", "commitment_signature",
                        "staple_digest", "future", "newest", "conflict", "key_binding",
                        "handoff_gate"})

# ---------------------------------------------------------------------------
# V0 and V1: carrier forms, and where the octets are
# ---------------------------------------------------------------------------


def naddr(uri: str) -> dict:
    hrp, data = nostr.bech32_decode(uri[len("nostr:"):])
    assert hrp == "naddr"
    out: dict[str, Any] = {"relays": []}
    i = 0
    while i < len(data):
        t, n = data[i], data[i + 1]
        v = data[i + 2:i + 2 + n]
        if t == 0:
            out["d"] = v.decode("ascii")
        elif t == 1:
            out["relays"].append(v.decode("ascii"))
        elif t == 2:
            out["author"] = v.hex()
        elif t == 3:
            out["kind"] = int.from_bytes(v, "big")
        i += 2 + n
    return out


def nostr_form(ev: dict, checks: frozenset) -> bool:
    """§5.3 and V0: kind, one d, one t, one x, at most one r, base64url content, a valid id and signature."""
    tags = {}
    for t in ev["tags"]:
        tags.setdefault(t[0], []).append(t[1])
    if ev["kind"] != KIND or any(len(tags.get(n, [])) != 1 for n in ("d", "t", "x")) or len(tags.get("r", [])) > 1:
        return False
    if tags["t"] != ["evidence-commitment"] or not _HEX64.fullmatch(tags["x"][0]):
        return False
    if nostr.b64url(ev["content"]) is None:
        return False
    return "nostr_event" not in checks or nostr.check_event(ev) is None


def fetch(uri: str, case: dict, checks: frozenset) -> tuple[bytes | None, dict | None]:
    """The octets at a URI: served over https:, or the announce event an naddr names."""
    if uri.startswith("nostr:"):
        a = naddr(uri)
        assert a["kind"] == KIND and a["relays"], "an naddr names the kind and at least one relay"
        for ev in case["relay_events"]:
            if ev["kind"] == a["kind"] and ev["pubkey"] == a["author"] and ["d", a["d"]] in ev["tags"]:
                assert nostr_form(ev, checks)
                return b64u(ev["content"]), ev
        return None, None
    assert uri.startswith("https:")
    return b64u(case["served"][uri]), None


def read_carrier(entry: dict, case: dict, checks: frozenset) -> dict:
    """V0, then V1. Returns the carrier result and, when it is read, the octets and any event."""
    kind = entry["carrier"]
    if kind == "directory":
        (att,) = entry["record"]["trustManifest"]["attestations"]
        if (set(att) != {"type", "uri", "mediaType", "digest", "description"} or att["type"] not in PROFILES
                or att["mediaType"] != "application/json" or not _SHA_TAG.fullmatch(att["digest"])):
            return {"carrier": kind, "check": "directory_entry"}
        data, ev = fetch(att["uri"], case, checks)
        claimed = att["digest"][len("sha256:"):]
    elif kind == "a2a":
        exts = entry["card"]["capabilities"]["extensions"]
        er = [e for e in exts if e["uri"] == ER_EXT_URI]
        if "discovery_object" in checks and any({"commitment_uri", "commitment_digest"} & set(e["params"]) for e in er):
            return {"carrier": kind, "check": "discovery_object"}
        ce = [e for e in exts if e["uri"] == EXT_URI]
        if (len(ce) != 1 or ce[0]["required"] is not False
                or set(ce[0]["params"]) != {"commitment_uri", "commitment_digest"}
                or not _SHA_TAG.fullmatch(ce[0]["params"]["commitment_digest"])):
            return {"carrier": kind, "check": "a2a_entry"}
        data, ev = fetch(ce[0]["params"]["commitment_uri"], case, checks)
        claimed = ce[0]["params"]["commitment_digest"][len("sha256:"):]
    else:
        ev = entry["event"]
        if not nostr_form(ev, checks):
            return {"carrier": kind, "check": "nostr_event"}
        r = [t[1] for t in ev["tags"] if t[0] == "r"]
        data = b64u(ev["content"]) if ev["content"] else fetch(r[0], case, checks)[0]
        claimed = next(t[1] for t in ev["tags"] if t[0] == "x")
    return {"carrier": kind, "check": None, "octets": data, "event": ev if kind == "nostr" else None,
            "digest_mismatch": claimed != sha(data)}


# ---------------------------------------------------------------------------
# V2 and V3: the commitment itself
# ---------------------------------------------------------------------------


def verify_commitment(data: bytes, checks: frozenset) -> tuple[str, dict | None]:
    try:
        c = json.loads(data)
    except ValueError:
        return "commitment_form", None
    if not isinstance(c, dict) or c.get("profile") not in PROFILES or not isinstance(c.get("sig"), dict):
        return "commitment_form", None
    key = load_der_public_key(base64.b64decode(c["spki"]))
    if not isinstance(key, Ed25519PublicKey):
        return "commitment_form", None
    if "key_id_spki" in checks and key.public_bytes(Encoding.Raw, PublicFormat.Raw).hex() != c["key_id"]:
        return "key_id_spki", None
    sig = c["sig"]
    if sig.get("alg") != "Ed25519" or sig.get("canon") != "jcs":
        return "commitment_form", None
    body = {k: v for k, v in c.items() if k != "sig"}
    if "commitment_signature" in checks:
        try:
            key.verify(b64u(sig["value"]), jcs(body))
        except InvalidSignature:
            return "commitment_signature", None
    cards = c["history_cards"] if c["profile"] == "evidence-commitment/1" else [c["history_card"]]
    if "staple_digest" in checks:
        for s in [c["checkpoint"], *cards]:
            if sha(base64.b64decode(s["bytes"])) != s["sha256"]:
                return "staple_digest", None
    return "verified", c


def _time(t: str) -> datetime:
    return datetime.strptime(t, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def standings(commitments: list[tuple[bytes, dict]], checks: frozenset) -> dict[str, str]:
    """V4: a commitment past the verifier's time and skew is future_dated; of the rest, per
    (key_id, node_id), the latest issued_at is current, and a tie between different octets conflicts."""
    out = {}
    if "future" in checks:
        limit = _time(READ_AT) + SKEW
        out = {d: "future_dated" for d, c in commitments if _time(c["issued_at"]) > limit}
        commitments = [(d, c) for d, c in commitments if d not in out]
    for digest, c in commitments:
        peers = [(d, p) for d, p in commitments if (p["key_id"], p["node_id"]) == (c["key_id"], c["node_id"])]
        latest = max(p["issued_at"] for _, p in peers)
        if "newest" in checks and c["issued_at"] != latest:
            out[digest] = "superseded"
        elif "conflict" in checks and len({d for d, p in peers if p["issued_at"] == c["issued_at"]}) > 1:
            out[digest] = "conflicting"
        else:
            out[digest] = "current"
    return out


# ---------------------------------------------------------------------------
# V5: key binding through an answer the reference verifier accepts
# ---------------------------------------------------------------------------


def answer_key(answer: dict) -> str:
    pins = DATA["interop_pins"]
    verifier = InteropVerifier(TrustPolicy.from_dict(pins["trust_policy"]),
                               VerificationPolicy.from_dict(pins["verification_policy"]),
                               pins["evaluation_time"], contract=DATA["contract"]["document"])
    req, reply, mt = b64u(answer["request"]), b64u(answer["reply"]), answer["media_type"]
    (r,) = verifier.verify([Exchange(Message(req, mt), [Message(reply, mt)])],
                           requirements=["r-record"]).exchanges[0].replies
    assert r.message_type == "envelope"
    assert all(r.status(p) == "PASS" for p in ("envelope_signature", "responder_trust", "request_binding"))
    return json.loads(reply)["responder"]


# ---------------------------------------------------------------------------
# V6: the cards handed to the admission pack
# ---------------------------------------------------------------------------


def handed(c: dict) -> list[dict]:
    """V6: the cards of a commitment that V5 bound, handed on with its key_id."""
    out = []
    for s in c["history_cards"]:
        card = json.loads(base64.b64decode(s["bytes"]))
        assert card["evidence_stream"] == s["stream"] and card["derivation"] == "history_card/1"
        out.append({"key_id": c["key_id"], "stream": s["stream"], "checkpoint_key": s.get("checkpoint_key"),
                    "sha256": s["sha256"]})
    return out


# ---------------------------------------------------------------------------
# A case end to end
# ---------------------------------------------------------------------------


def run_case(case: dict, checks: frozenset = ALL_CHECKS) -> dict:
    carriers, octets = [], []
    for entry in case["carriers"]:
        r = read_carrier(entry, case, checks)
        carriers.append(r)
        if r["check"] is None and r["octets"] not in octets:
            octets.append(r["octets"])
    results, good = {}, []
    for data in octets:
        result, c = verify_commitment(data, checks)
        results[sha(data)] = result
        if c is not None:
            good.append((sha(data), c))
    stand = standings(good, checks)
    by_digest = dict(good)

    out: dict[str, Any] = {"carriers": [], "commitments": []}
    for r in carriers:
        row: dict[str, Any] = {"carrier": r["carrier"], "check": r["check"]}
        if r["check"] is None:
            digest = sha(r["octets"])
            row.update(octets_sha256=digest, digest_mismatch=r["digest_mismatch"])
            c = by_digest.get(digest)
            if r["event"] is not None and c is not None:
                nk = c.get("ask", {}).get("nostr", {})
                ev = r["event"]
                announced = ev["pubkey"] == nk.get("mailbox_key") and ["d", c["node_id"]] in ev["tags"]
                row["attribution"] = "announced" if announced else "relayed"
        out["carriers"].append(row)
    for data in octets:
        row = {"sha256": sha(data), "result": results[sha(data)]}
        if row["result"] == "verified":
            row["standing"] = stand[sha(data)]
        out["commitments"].append(row)
    current = [c for d, c in good if stand[d] == "current"]
    if "answer" in case:
        assert len(current) == 1
        bound = "key_binding" not in checks or answer_key(case["answer"]) == current[0]["key_id"]
        out["key_binding"] = "bound" if bound else "key_mismatch"
    if "answer" in case and (out["key_binding"] == "bound" or "handoff_gate" not in checks):
        out["cards"] = handed(current[0])
    return out


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def _generator():
    return _module("generate_evidence_commitment_carriers_vectors", GENERATOR)


def test_regeneration_is_byte_identical(tmp_path):
    # The hand-written README is part of SHA256SUMS, so it is copied in before regenerating.
    (tmp_path / "README.md").write_bytes((VECTORS / "README.md").read_bytes())
    _generator().write(tmp_path)
    on_disk = sorted(p.name for p in VECTORS.iterdir() if p.is_file())
    assert sorted(p.name for p in tmp_path.iterdir()) == on_disk
    for name in on_disk:
        assert (tmp_path / name).read_bytes() == (VECTORS / name).read_bytes(), name


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_case_matches_expectation(case):
    assert run_case(case) == case["expected"]


def test_corpus_covers_the_acceptance():
    """AAC#541's acceptance: one commitment carried three ways that all verify to the same octets; a
    forged carrier entry, a key mismatch and an older commitment beside a newer one. The unwitnessed
    label is the admission pack's term (binding §7, C-6), not this corpus's."""
    got = {c["id"]: run_case(c) for c in CASES}
    three = got["three-carriers-one-commitment"]
    assert [r["carrier"] for r in three["carriers"]] == ["directory", "a2a", "nostr"]
    assert len({r["octets_sha256"] for r in three["carriers"]}) == 1
    assert three["commitments"] == [{"sha256": three["carriers"][0]["octets_sha256"], "result": "verified",
                                     "standing": "current"}]
    assert three["key_binding"] == "bound" and [c["stream"] for c in three["cards"]] == ["book-a"]
    assert got["forged-carrier-entry"]["commitments"][0]["result"] == "commitment_signature"
    assert got["answer-key-mismatch"]["key_binding"] == "key_mismatch"
    assert [c["standing"] for c in got["older-beside-newer"]["commitments"]] == ["superseded", "current"]
    assert DATA["count"] == len(CASES)


def test_binding_lists_every_case():
    section = BINDING_TEXT.split("## 10. Vectors", 1)[1].split("## 11.", 1)[0]
    listed = re.findall(r"^\| `([a-z0-9-]+)` \|", section, flags=re.M)
    assert sorted(listed) == sorted(c["id"] for c in CASES)


def test_offline_opens_no_socket(monkeypatch, tmp_path):
    def refuse(*a, **k):
        raise AssertionError("the vectors must verify offline")
    for name in ("socket", "create_connection", "getaddrinfo"):
        monkeypatch.setattr(socket, name, refuse)
    _generator().write(tmp_path)
    for case in CASES:
        assert run_case(case) == case["expected"]


def test_kind_and_uri_match_the_binding():
    assert f"`{KIND}`" in BINDING_TEXT and 30000 <= KIND < 40000
    assert f"exactly `{EXT_URI}`" in BINDING_TEXT


def test_commitments_carry_no_count():
    """The count rule the commitment profile applies: no number, and no string of digits only,
    outside the staples' bytes, which are signed artifacts carried whole."""
    def scan(v, path=""):
        if isinstance(v, bool) or v is None:
            return
        assert not isinstance(v, (int, float)), path
        if isinstance(v, str):
            assert not v.isdigit(), path
        elif isinstance(v, list):
            for i, x in enumerate(v):
                scan(x, f"{path}[{i}]")
        elif isinstance(v, dict):
            for k, x in v.items():
                if k != "bytes":
                    scan(x, f"{path}.{k}")
    for case in CASES:
        for uri, text in case["served"].items():
            scan(json.loads(b64u(text)), uri)


# ---------------------------------------------------------------------------
# Mutants: each negative case must fail when the rule it tests is removed
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("check, case_id", [
    ("discovery_object", "a2a-commitment-in-discovery-object"),
    ("nostr_event", "nostr-event-bad-signature"),
    ("key_id_spki", "forged-key-id"),
    ("commitment_signature", "forged-carrier-entry"),
    ("staple_digest", "staple-digest-mismatch"),
    ("newest", "older-beside-newer"),
    ("conflict", "same-issued-at-conflict"),
    ("key_binding", "answer-key-mismatch"),
    ("handoff_gate", "answer-key-mismatch"),
    ("future", "future-dated-issued-at"),
])
def test_mutant_check_removed(check, case_id):
    (case,) = [c for c in CASES if c["id"] == case_id]
    try:
        disagrees = run_case(case, ALL_CHECKS - {check}) != case["expected"]
    except AssertionError:
        disagrees = True
    assert disagrees, f"removing {check} leaves {case_id} unchanged"
