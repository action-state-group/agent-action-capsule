# SPDX-License-Identifier: BSD-3-Clause
"""The experimental Nostr mailbox vectors are reproducible and agree with spec/bindings/nostr-mailbox-v0.md.

The generator states the expected values. This test re-runs it and requires byte-identical output.
With its own code it checks every event (the NIP-01 id, the BIP-340 signature and the reply checks
of the binding's §4.2), the route (NIP-19 nprofile) and the absence window. It checks its NIP-01
id and BIP-340 against the events published in NIP-59 and BIP-340's test vectors, and its bech32
against NIP-19's example. The replies it accepts go to the reference verifier of the interop
profile, offline, and the results must equal the stated expectation.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import re
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from agent_action_capsule.interop_profile import (
    Exchange,
    InteropVerifier,
    Message,
    TrustPolicy,
    VerificationPolicy,
)

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "vectors" / "adapters" / "nostr-mailbox"
GENERATOR = ROOT / "python" / "scripts" / "generate_nostr_mailbox_vectors.py"
BINDING_TEXT = (ROOT / "spec" / "bindings" / "nostr-mailbox-v0.md").read_text(encoding="utf-8")
PROFILE_TEXT = (ROOT / "spec" / "interop-profile-v1.md").read_text(encoding="utf-8")
DATA = json.loads((VECTORS / "vectors.json").read_text(encoding="utf-8"))
CASES = DATA["cases"]
CONTRACT = DATA["contract"]["document"]
REQUEST_KIND = DATA["carriage"]["request_kind"]
REPLY_KIND = DATA["carriage"]["reply_kind"]


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# ---------------------------------------------------------------------------
# BIP-340 verification, written apart from the generator's signer
# ---------------------------------------------------------------------------

_P = 2**256 - 2**32 - 977
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def _jacobian_double(p):
    x, y, z = p
    if y == 0:
        return (0, 0, 0)
    s = 4 * x * y * y % _P
    m = 3 * x * x % _P
    nx = (m * m - 2 * s) % _P
    return nx, (m * (s - nx) - 8 * y**4) % _P, 2 * y * z % _P


def _jacobian_add(p, q):
    if p[2] == 0:
        return q
    if q[2] == 0:
        return p
    u1, u2 = p[0] * q[2] ** 2 % _P, q[0] * p[2] ** 2 % _P
    s1, s2 = p[1] * q[2] ** 3 % _P, q[1] * p[2] ** 3 % _P
    if u1 == u2:
        return _jacobian_double(p) if s1 == s2 else (0, 0, 0)
    h, r = u2 - u1, s2 - s1
    nx = (r * r - h**3 - 2 * u1 * h * h) % _P
    return nx, (r * (u1 * h * h - nx) - s1 * h**3) % _P, h * p[2] * q[2] % _P


def _jacobian_mul(k, p):
    acc = (0, 0, 0)
    for bit in bin(k)[2:]:
        acc = _jacobian_double(acc)
        if bit == "1":
            acc = _jacobian_add(acc, p)
    return acc


def _affine(p):
    if p[2] == 0:
        return None
    zi = pow(p[2], -1, _P)
    return p[0] * zi * zi % _P, p[1] * zi**3 % _P


def _tagged(tag: str, data: bytes) -> bytes:
    h = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(h + h + data).digest()


def schnorr_verify(pub: bytes, msg: bytes, sig: bytes) -> bool:
    """BIP-340 Verify."""
    if len(pub) != 32 or len(sig) != 64:
        return False
    x = int.from_bytes(pub, "big")
    if x >= _P:
        return False
    y_sq = (pow(x, 3, _P) + 7) % _P
    y = pow(y_sq, (_P + 1) // 4, _P)
    if y * y % _P != y_sq:
        return False
    if y & 1:
        y = _P - y
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if r >= _P or s >= _N:
        return False
    e = int.from_bytes(_tagged("BIP0340/challenge", sig[:32] + pub + msg), "big") % _N
    point = _affine(_jacobian_add(_jacobian_mul(s, (_GX, _GY, 1)), _jacobian_mul(_N - e, (x, y, 1))))
    return point is not None and point[1] % 2 == 0 and point[0] == r


# ---------------------------------------------------------------------------
# bech32 decoding and the NIP-19 nprofile
# ---------------------------------------------------------------------------

_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def bech32_decode(text: str) -> tuple[str, bytes]:
    hrp, _, rest = text.rpartition("1")
    values = [_CHARSET.index(c) for c in rest]
    chk = 1
    for v in [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp] + values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i, g in enumerate((0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)):
            if (top >> i) & 1:
                chk ^= g
    assert chk == 1, "bech32 checksum"
    acc, bits, out = 0, 0, bytearray()
    for v in values[:-6]:
        acc, bits = (acc << 5) | v, bits + 5
        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    return hrp, bytes(out)


def nprofile(uri: str) -> tuple[str, list[str]]:
    assert uri.startswith("nostr:")
    hrp, data = bech32_decode(uri[len("nostr:"):])
    assert hrp == "nprofile"
    key, relays, i = None, [], 0
    while i < len(data):
        t, n = data[i], data[i + 1]
        v = data[i + 2:i + 2 + n]
        if t == 0:
            key = v.hex()
        elif t == 1:
            relays.append(v.decode("ascii"))
        i += 2 + n
    return key, relays


# ---------------------------------------------------------------------------
# NIP-01 events and the binding's reply checks (§4.2)
# ---------------------------------------------------------------------------

_B64URL = re.compile(r"[A-Za-z0-9_-]*")


def nip01_id(ev: dict) -> str:
    body = [0, ev["pubkey"], ev["created_at"], ev["kind"], ev["tags"], ev["content"]]
    return sha(json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


def b64url(text: str) -> bytes | None:
    if not _B64URL.fullmatch(text) or len(text) % 4 == 1:
        return None
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def tag_values(ev: dict, name: str) -> list[str]:
    return [t[1] for t in ev["tags"] if len(t) >= 2 and t[0] == name]


def check_event(ev: dict) -> str | None:
    if nip01_id(ev) != ev["id"]:
        return "id"
    if not schnorr_verify(bytes.fromhex(ev["pubkey"]), bytes.fromhex(ev["id"]), bytes.fromhex(ev["sig"])):
        return "signature"
    return None


def proves(content: bytes, request: bytes, media_type: str, pins: dict) -> bool:
    """§4.2, reply by content: verified on its own, the content is the responder's signed answer to
    this request. Its signature verifies, under a key the trust policy accepts, and it binds this
    request's digest."""
    verifier = InteropVerifier(TrustPolicy.from_dict(pins["trust_policy"]),
                               VerificationPolicy.from_dict(pins["verification_policy"]),
                               pins["evaluation_time"], contract=CONTRACT)
    (r,) = verifier.verify([Exchange(Message(request, media_type), [Message(content, media_type)])],
                           requirements=["r-record"]).exchanges[0].replies
    signature = {"envelope": "envelope_signature", "refusal": "refusal_signature"}.get(r.message_type)
    return signature is not None and all(r.status(p) == "PASS"
                                         for p in (signature, "responder_trust", "request_binding"))


def classify(ev: dict, request_event: dict, mailbox_key: str, media_type: str,
             content_proves, within_limit=lambda ev: True) -> tuple[str, bytes | None]:
    """§4.2: the format checks, then the attribution checks, in order. A format failure means the
    event is not a reply. An attribution failure leaves a reply only when its content proves itself,
    and only within the requester's limit on replies by content."""
    if ev["kind"] != REPLY_KIND:
        return "not_a_reply:kind", None
    if tag_values(ev, "e") != [request_event["id"]]:
        return "not_a_reply:reply_to", None
    if tag_values(ev, "m") != [media_type]:
        return "not_a_reply:media_type", None
    data = b64url(ev["content"])
    if data is None:
        return "not_a_reply:content", None
    failed = check_event(ev) or ("author" if ev["pubkey"] != mailbox_key else None)
    if failed is None:
        return "reply", data
    if not within_limit(ev):
        return "not_a_reply:limit", None
    if content_proves(data):
        return f"reply_by_content:{failed}", data
    return f"not_a_reply:{failed}", None


def limiter(limit: int | None):
    """§4.2: at most `limit` events not attributed to the mailbox are verified by content for one
    request. An event is counted by its recomputed NIP-01 hash, never its claimed id, so a
    redelivery counts once. No limit when the case sets none."""
    counted: set = set()

    def within(ev: dict) -> bool:
        key = nip01_id(ev)
        if key not in counted:
            if limit is not None and len(counted) >= limit:
                return False
            counted.add(key)
        return True
    return within


def seen_before(event_id: str, seen: set) -> bool:
    """§4.2: events with one id are one event, however many times a relay delivers it."""
    return event_id in seen


def keep_late(absence: bytes, late: list[bytes]) -> tuple[bytes, list[bytes]]:
    """§5.3: the absence record stays as written, and each late reply is kept beside it."""
    return absence, late


def unix(t: str) -> int:
    return int(datetime.strptime(t, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())


def octets(o: dict) -> bytes:
    return o["octets_text"].encode("utf-8") if "octets_text" in o else bytes.fromhex(o["octets_hex"])


def decode_request(data: bytes, media_type: str) -> dict:
    if media_type == "application/json":
        return json.loads(data)
    from agent_action_capsule.interop_profile import _cbor
    return _cbor.decode(data).value


# ---------------------------------------------------------------------------
# Running a case
# ---------------------------------------------------------------------------


def render_requirements(reqs: dict) -> dict:
    return {q: {"row": r.row, "status": r.status, "sufficiency": r.sufficiency, "verdict": r.verdict}
            | ({"note": r.note} if r.note is not None else {}) for q, r in reqs.items()}


def render_replies(ex) -> list[dict]:
    return [{"message_type": r.message_type,
             "properties": {p.property: p.status for p in r.properties},
             "requirements": render_requirements(r.requirements),
             "claim": {"evidence": r.evidence, "proofs": r.proofs}}
            for r in ex.replies]


def responder_action(ev: dict, mailbox_key: str) -> str:
    """§4.1: the responder answers only a request event whose id and signature check."""
    failed = check_event(ev)
    if failed is not None:
        return "ignored:" + failed
    assert ev["kind"] == REQUEST_KIND and tag_values(ev, "p") == [mailbox_key]
    return "answer"


def render_absence(ex, absence_record: Message, box: dict, deadline: str | None) -> dict:
    record = json.loads(absence_record.octets)
    # §5.3: the window opens when the request event is published.
    assert unix(record["window"]["opened"]) == box["request_event"]["created_at"]
    # §5.3: the window closes at the request's deadline, and the route is the mailbox addressed.
    key, relays = nprofile(record["route"])
    assert key == box["mailbox_key"] and relays == [box["relay"]]
    closed = record["window"]["closed"]
    if deadline is not None:
        closes_at = "deadline" if closed == deadline else "mismatch"
    else:
        closes_at = "local_timeout" if closed == box.get("local_timeout") else "mismatch"
    return {"form": ex.absence.form, "window_closes_at": closes_at,
            "requirements": render_requirements(ex.absence.requirements),
            "presentation_kind_recommended": ex.absence.presentation_kind_recommended,
            "claim": {"evidence": ex.absence.evidence, "proofs": []}}


def run_case(case: dict) -> dict:
    inp, pins = case["inputs"], case["pins"]
    request = octets(inp["request"])
    media_type = inp["request"]["media_type"]
    box = inp["mailbox"]
    req_ev = box["request_event"]

    # The request event (§4.1).
    assert check_event(req_ev) is None
    assert req_ev["kind"] == REQUEST_KIND
    assert b64url(req_ev["content"]) == request
    assert tag_values(req_ev, "p") == [box["mailbox_key"]]
    assert tag_values(req_ev, "m") == [media_type]
    deadline = decode_request(request, media_type).get("deadline")
    # §4.1: the expiration tag, when present, is the deadline; a request without one carries none.
    assert tag_values(req_ev, "expiration") in ([], [str(unix(deadline))] if deadline else [])

    def content_proves(data: bytes) -> bool:
        return proves(data, request, media_type, pins)

    classification, replies, seen = [], [], set()
    within_limit = limiter(box.get("reply_by_content_limit"))
    for ev in box["events"]:
        outcome, data = classify(ev, req_ev, box["mailbox_key"], media_type, content_proves, within_limit)
        if data is not None and seen_before(ev["id"], seen):
            outcome = "duplicate"
        elif data is not None:
            seen.add(ev["id"])
            replies.append(data)
        classification.append(outcome)

    absence_record = Message(octets(inp["absence_record"]), "application/json") if "absence_record" in inp else None
    verifier = InteropVerifier(TrustPolicy.from_dict(pins["trust_policy"]),
                               VerificationPolicy.from_dict(pins["verification_policy"]),
                               pins["evaluation_time"], contract=CONTRACT)
    def verify(replies: list[bytes], absence: Message | None):
        return verifier.verify([Exchange(Message(request, media_type), [Message(r, media_type) for r in replies],
                                         absence)], requirements=["r-record"])

    result = verify(replies, absence_record)
    ex = result.exchanges[0]
    out: dict[str, Any] = {"request_digest": ex.request_digest, "request_event_id": req_ev["id"],
                           "classification": classification, "replies": render_replies(ex)}
    if ex.replies:
        out["set_properties"] = {"caller_invariance": result.caller_invariance.status}
    if ex.absence is not None:
        out["absence"] = render_absence(ex, absence_record, box, deadline)

    if "responder_events" in box:
        out["responder"] = [responder_action(ev, box["mailbox_key"]) for ev in box["responder_events"]]

    if "late_events" in box:
        # §5.3: events reaching the requester after the absence record, by its own clock.
        written = absence_record.octets
        record = json.loads(written)
        late_classification, late = [], []
        for item in box["late_events"]:
            assert unix(item["received_at"]) > unix(record["window"]["closed"])
            assert unix(item["received_at"]) >= unix(record["recorded_at"])
            outcome, data = classify(item["event"], req_ev, box["mailbox_key"], media_type, content_proves,
                                     within_limit)
            if data is not None and seen_before(item["event"]["id"], seen):
                outcome = "duplicate"
            elif data is not None:
                seen.add(item["event"]["id"])
                late.append(data)
            late_classification.append(outcome)
        kept, held = keep_late(written, late)
        # The kept record, verified again, gives what it gave before the late replies arrived.
        again = verify([], Message(kept, "application/json")).exchanges[0]
        unchanged = kept == written and render_absence(again, Message(kept, "application/json"), box,
                                                       deadline) == out["absence"]
        late_ex = verify(held, None).exchanges[0]
        # What each late reply cites: the request digest it signs, and the request event its e tag names.
        digests = {decode_request(r, media_type)["request_digest"] for r in held} | {record["request_digest"]}
        event_ids = {e for item in box["late_events"] for e in tag_values(item["event"], "e")}
        out["late"] = {"classification": late_classification, "replies": render_replies(late_ex),
                       "absence_record_unchanged": unchanged,
                       "cites": {"request_digest": digests.pop() if len(digests) == 1 else sorted(digests),
                                 "request_event_id": event_ids.pop() if len(event_ids) == 1 else sorted(event_ids)}}
    return out


def _comparable(expected: dict) -> dict:
    out = json.loads(json.dumps(expected))
    for r in out.get("replies", []) + out.get("late", {}).get("replies", []):
        r.pop("presentation_kinds_allowed", None)
    return out


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def _generator():
    spec = importlib.util.spec_from_file_location("generate_nostr_mailbox_vectors", GENERATOR)
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    return gen


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
    assert run_case(case) == _comparable(case["expected"])


def test_corpus_covers_the_acceptance():
    """The item's acceptance: one request/answer pair that verifies, a wrong key, a replay, and
    deadline -> absence; each showing what it is named for."""
    got = {c["id"]: run_case(c) for c in CASES}
    ok = got["mailbox-exchange"]
    assert ok["classification"] == ["reply"]
    assert ok["replies"][0]["requirements"]["r-record"]["row"] == "envelope-7"
    assert all(s == "PASS" for p, s in ok["replies"][0]["properties"].items() if p != "responder_key_current")
    assert got["mailbox-envelope-untrusted-key"]["replies"][0]["properties"]["responder_trust"] == "FAIL"
    assert got["mailbox-envelope-replayed"]["replies"][0]["properties"]["request_binding"] == "FAIL"
    assert got["mailbox-no-reply"]["absence"]["window_closes_at"] == "deadline"
    assert got["mailbox-no-deadline-no-reply"]["absence"]["window_closes_at"] == "local_timeout"
    late = got["mailbox-late-reply-after-absence"]
    assert late["absence"] == got["mailbox-no-reply"]["absence"]
    assert late["late"]["absence_record_unchanged"] is True
    assert late["late"]["replies"] == ok["replies"]
    assert late["late"]["cites"] == {"request_digest": ok["request_digest"],
                                     "request_event_id": ok["request_event_id"]}
    assert DATA["count"] == len(CASES)


def test_offline_opens_no_socket(monkeypatch, tmp_path):
    def refuse(*a, **k):
        raise AssertionError("the vectors must verify offline")
    for name in ("socket", "create_connection", "getaddrinfo"):
        monkeypatch.setattr(socket, name, refuse)
    _generator().write(tmp_path)
    for case in CASES:
        assert run_case(case) == _comparable(case["expected"])


def test_binding_defines_no_token():
    assert f"`{REQUEST_KIND}`" in BINDING_TEXT and f"`{REPLY_KIND}`" in BINDING_TEXT
    assert "defines no binding" in BINDING_TEXT and "EXPERIMENTAL" in BINDING_TEXT
    # No binding token for this carriage exists in the profile's list of binding tokens (§11.4.2).
    (row,) = [line for line in PROFILE_TEXT.splitlines() if line.startswith("| `bindings` |")]
    assert re.findall(r"`([^`]+)`", row.split("|")[3]) == ["evidence-request/1", "http", "a2a", "mcp"]


# NIP-59's worked example, nostr-protocol/nips commit 0b54c4d1c70b046fbb2e3c599c09b641e00f5dcd
# (59.md): a rumor (id, no signature) and a seal (id and signature). Its content has "/" and "+",
# which NIP-01 includes verbatim.
NIP59_RUMOR = {"created_at": 1691518405, "content": "Are you going to the party tonight?", "tags": [], "kind": 1,
               "pubkey": "611df01bfcf85c26ae65453b772d8f1dfd25c264621c0277e1fc1518686faef9",
               "id": "9dd003c6d3b73b74a85a9ab099469ce251653a7af76f523671ab828acd2a0ef9"}
NIP59_SEAL = {
    "content": "AqBCdwoS7/tPK+QGkPCadJTn8FxGkd24iApo3BR9/M0uw6n4RFAFSPAKKMgkzVMoRyR3ZS/aqATDFvoZJOkE9cPG/TAzmyZvr/"
               "WUIS8kLmuI1dCA+itFF6+ULZqbkWS0YcVU0j6UDvMBvVlGTzHz+UHzWYJLUq2LnlynJtFap5k8560+tBGtxi9Gx2NIycKgbO"
               "Uv0gEqhfVzAwvg1IhTltfSwOeZXvDvd40rozONRxwq8hjKy+4DbfrO0iRtlT7G/eVEO9aJJnqagomFSkqCscttf/o6VeT2+A"
               "9JhcSxLmjcKFG3FEK3Try/WkarJa1jM3lMRQqVOZrzHAaLFW/5sXano6DqqC5ERD6CcVVsrny0tYN4iHHB8BHJ9zvjff0NjLGG"
               "/v5Wsy31+BwZA8cUlfAZ0f5EYRo9/vKSd8TV0wRb9DQ=",
    "kind": 13, "created_at": 1703015180,
    "pubkey": "611df01bfcf85c26ae65453b772d8f1dfd25c264621c0277e1fc1518686faef9", "tags": [],
    "id": "28a87d7c074d94a58e9e89bb3e9e4e813e2189f285d797b1c56069d36f59eaa7",
    "sig": "02fc3facf6621196c32912b1ef53bac8f8bfe9db51c0e7102c073103586b0d29"
           "c3f39bdaa1e62856c20e90b6c7cc5dc34ca8bb6a528872cf6e65e6284519ad73"}


def test_nip01_id_and_signature_against_published_events():
    assert nip01_id(NIP59_RUMOR) == NIP59_RUMOR["id"]
    assert nip01_id(NIP59_SEAL) == NIP59_SEAL["id"]
    assert check_event(NIP59_SEAL) is None
    gen = _generator()
    for ev in (NIP59_RUMOR, NIP59_SEAL):
        assert gen.event_id(ev["pubkey"], ev["created_at"], ev["kind"], ev["tags"], ev["content"]) == ev["id"]


# Published values: BIP-340 test-vectors.csv, bitcoin/bips commit
# 5aadddb511a5dcfe4599531bd8ae5e5b96d0f793, file SHA-256
# 34c9d1d9c3a88d524bc80778540dc43f8306ec249a7485293063c376db851c2d; rows 0, 1, 5, 6, 12, 13 and 14.
BIP340_ROWS = [
    ("0000000000000000000000000000000000000000000000000000000000000003",
     "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
     "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0", True),
    ("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
     "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
     "0000000000000000000000000000000000000000000000000000000000000001",
     "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
     "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE3341"
     "8906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A", True),
    (None, "EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34", None,
     "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
     "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769"
     "69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B", False),
    (None, "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", None,
     "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
     "FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A14602975563"
     "CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2", False),
    (None, "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", None,
     "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
     "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"
     "69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B", False),
    (None, "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", None,
     "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
     "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769"
     "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", False),
    (None, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30", None,
     "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
     "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769"
     "69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B", False),
]


@pytest.mark.parametrize("row", BIP340_ROWS)
def test_bip340_published_vectors(row):
    secret, pub, aux, msg, sig, ok = row
    assert schnorr_verify(bytes.fromhex(pub), bytes.fromhex(msg), bytes.fromhex(sig)) is ok
    if secret is not None:
        gen = _generator()
        assert gen.xonly(int(secret, 16)).hex() == pub.lower()
        assert gen.schnorr_sign(int(secret, 16), bytes.fromhex(msg), bytes.fromhex(aux)).hex() == sig.lower()


# NIP-19 example, nostr-protocol/nips commit 0b54c4d1c70b046fbb2e3c599c09b641e00f5dcd (19.md).
NIP19_EXAMPLE = ("nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gpp4mhxue69uhhytnc9e3k7mgpz4mhxue69uhkg6nzv9ejuumpv34kytnrdaksjlyr9p")


def test_nprofile_published_example():
    key, relays = nprofile("nostr:" + NIP19_EXAMPLE)
    assert key == "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d"
    assert relays == ["wss://r.x.com", "wss://djbas.sadkb.com"]
    gen = _generator()
    tlv = bytes([0, 32]) + bytes.fromhex(key)
    for r in relays:
        tlv += bytes([1, len(r)]) + r.encode()
    assert gen.bech32("nprofile", tlv) == NIP19_EXAMPLE


# ---------------------------------------------------------------------------
# Mutants: each negative check must fail when the rule it tests is removed (R4)
# ---------------------------------------------------------------------------


def _disagreeing(monkeypatch, name: str, replacement) -> set[str]:
    monkeypatch.setattr(__import__(__name__), name, replacement)
    bad = set()
    for case in CASES:
        try:
            if run_case(case) != _comparable(case["expected"]):
                bad.add(case["id"])
        except AssertionError:
            bad.add(case["id"])
    return bad


def test_mutant_author_not_checked(monkeypatch):
    real = classify

    def no_author(ev, request_event, mailbox_key, media_type, content_proves, within_limit=lambda ev: True):
        return real(ev, request_event, ev["pubkey"], media_type, content_proves, within_limit)
    assert {"mailbox-relayed-by-other-key", "mailbox-other-key-replays-old-envelope"} <= \
        _disagreeing(monkeypatch, "classify", no_author)


def test_mutant_reply_to_not_checked(monkeypatch):
    real = classify

    def any_request(ev, request_event, mailbox_key, media_type, content_proves, within_limit=lambda ev: True):
        forged = dict(request_event, id=(tag_values(ev, "e") or [""])[0])
        return real(ev, forged, mailbox_key, media_type, content_proves, within_limit)
    assert "mailbox-reply-to-other-request" in _disagreeing(monkeypatch, "classify", any_request)


def test_mutant_event_id_not_checked(monkeypatch):
    assert {"mailbox-event-tampered", "mailbox-request-tampered"} <= \
        _disagreeing(monkeypatch, "nip01_id", lambda ev: ev["id"])


def test_mutant_signature_not_checked(monkeypatch):
    assert {"mailbox-event-bad-signature", "mailbox-request-tampered"} <= \
        _disagreeing(monkeypatch, "schnorr_verify", lambda *a: True)


def test_mutant_duplicates_counted_twice(monkeypatch):
    assert "mailbox-request-redelivered" in _disagreeing(monkeypatch, "seen_before", lambda *a: False)


def test_mutant_content_proof_ignores_request_binding(monkeypatch):
    def weak(content, request, media_type, pins):
        verifier = InteropVerifier(TrustPolicy.from_dict(pins["trust_policy"]),
                                   VerificationPolicy.from_dict(pins["verification_policy"]),
                                   pins["evaluation_time"], contract=CONTRACT)
        (r,) = verifier.verify([Exchange(Message(request, media_type), [Message(content, media_type)])],
                               requirements=["r-record"]).exchanges[0].replies
        return r.status("envelope_signature") == "PASS" and r.status("responder_trust") == "PASS"
    assert "mailbox-other-key-replays-old-envelope" in _disagreeing(monkeypatch, "proves", weak)


def test_mutant_content_never_proves(monkeypatch):
    assert {"mailbox-relayed-by-other-key", "mailbox-event-bad-signature"} <= \
        _disagreeing(monkeypatch, "proves", lambda *a: False)


def test_mutant_late_reply_rewrites_absence(monkeypatch):
    def rewrite(absence, late):
        record = json.loads(absence)
        record["window"]["closed"] = record["recorded_at"] = "2026-10-12T00:01:40Z"
        return json.dumps(record, separators=(",", ":"), sort_keys=True).encode(), late
    assert "mailbox-late-reply-after-absence" in _disagreeing(monkeypatch, "keep_late", rewrite)


def test_mutant_late_reply_dropped(monkeypatch):
    assert "mailbox-late-reply-after-absence" in _disagreeing(monkeypatch, "keep_late", lambda absence, late: (absence, []))


LIMIT_CASE = "mailbox-reply-by-content-limit"


def test_mutant_no_limit_on_replies_by_content(monkeypatch):
    assert LIMIT_CASE in _disagreeing(monkeypatch, "limiter", lambda limit: lambda ev: True)


def test_mutant_limit_keyed_on_claimed_id(monkeypatch):
    def by_claimed_id(limit):
        counted: set = set()

        def within(ev):
            if ev["id"] not in counted:
                if len(counted) >= limit:
                    return False
                counted.add(ev["id"])
            return True
        return within
    assert LIMIT_CASE in _disagreeing(monkeypatch, "limiter", lambda limit: by_claimed_id(limit) if limit else (lambda ev: True))


def test_mutant_limit_counts_redeliveries(monkeypatch):
    def every_call(limit):
        calls = []

        def within(ev):
            calls.append(ev)
            return len(calls) <= limit
        return within
    assert LIMIT_CASE in _disagreeing(monkeypatch, "limiter", lambda limit: every_call(limit) if limit else (lambda ev: True))


def test_mutant_limit_counts_mailbox_events(monkeypatch):
    real = classify

    def eager(ev, request_event, mailbox_key, media_type, content_proves, within_limit=lambda ev: True):
        if ev["kind"] == REPLY_KIND and not within_limit(ev):
            return "not_a_reply:limit", None
        return real(ev, request_event, mailbox_key, media_type, content_proves, within_limit)
    assert LIMIT_CASE in _disagreeing(monkeypatch, "classify", eager)
