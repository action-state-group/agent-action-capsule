#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate the vectors of the experimental Nostr mailbox carriage (spec/bindings/nostr-mailbox-v0.md).

The binding carries the exchange of the Minimum Evidence Interoperability Profile
(``spec/interop-profile-v0.md``) through a Nostr relay. Every expected classification and status
below is chosen by hand from the binding's text and cites the section it comes from; digests, event
ids and signatures are computed, and property maps and rows are spelled with the interop
generator's helpers. Nothing here runs a verifier or contacts a relay: the script builds NIP-01 events around request and reply octets and signs them
with BIP-340 Schnorr over secp256k1. ``python/tests/test_nostr_mailbox_vectors.py`` checks every
event with its own code and passes the replies it accepts to the reference verifier.

The evidence side reuses the interop profile corpus: its responder key, its Checkpointed Local Log,
its canonical Artifact and its envelope and refusal builders
(``python/scripts/generate_interop_profile_v0_vectors.py``). So an envelope carried here verifies
exactly as it does there.

Output: ``vectors/adapters/nostr-mailbox/`` (or ``--out DIR``). Deterministic: no clock and no
randomness. Every Nostr key is SHA-256 of a public label, reduced into the secp256k1 scalar range,
and is for testing only. BIP-340 signing uses 32 zero bytes as ``aux_rand``, which BIP-340 permits.
``README.md`` is hand-written; when present in the output directory it is included in
``SHA256SUMS`` but never rewritten. Dependencies: the standard library and ``cryptography``
(Ed25519 only, through the interop generator).
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "vectors" / "adapters" / "nostr-mailbox"
SET = "aac-nostr-mailbox-v0"
BINDING = "spec/bindings/nostr-mailbox-v0.md"
STATUS = ("EXPERIMENTAL. Vectors for a carriage binding that is not part of evidence-interop/0 and "
          "names no binding token. Every key is a test key derived from a public label; never use one "
          "for anything else.")

_spec = importlib.util.spec_from_file_location(
    "generate_interop_profile_v0_vectors", Path(__file__).with_name("generate_interop_profile_v0_vectors.py"))
ip = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ip)

# The two event kinds of §4. Placeholders in NIP-01's regular range, outside the 5000-7000 range
# NIP-90 reserves and absent from the NIPs kind list at the pinned commit; not registered (§10, N-1).
REQUEST_KIND = 4700
REPLY_KIND = 4701
RELAY = "wss://relay.example"

# ---------------------------------------------------------------------------
# secp256k1 and BIP-340 Schnorr signatures
# ---------------------------------------------------------------------------

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _add(p1: tuple[int, int] | None, p2: tuple[int, int] | None) -> tuple[int, int] | None:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    if p1[0] == p2[0] and p1[1] != p2[1]:
        return None
    if p1 == p2:
        lam = 3 * p1[0] * p1[0] * pow(2 * p1[1], P - 2, P) % P
    else:
        lam = (p2[1] - p1[1]) * pow(p2[0] - p1[0], P - 2, P) % P
    x3 = (lam * lam - p1[0] - p2[0]) % P
    return x3, (lam * (p1[0] - x3) - p1[1]) % P


def _mul(k: int, point: tuple[int, int] | None) -> tuple[int, int] | None:
    out = None
    while k:
        if k & 1:
            out = _add(out, point)
        point = _add(point, point)
        k >>= 1
    return out


def tagged_hash(tag: str, data: bytes) -> bytes:
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + data).digest()


def _int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _b32(n: int) -> bytes:
    return n.to_bytes(32, "big")


def xonly(secret: int) -> bytes:
    """The BIP-340 public key: the x coordinate of secret*G."""
    return _b32(_mul(secret, G)[0])


def schnorr_sign(secret: int, msg: bytes, aux: bytes = bytes(32)) -> bytes:
    """BIP-340 Sign, for a 32-byte message."""
    point = _mul(secret, G)
    d = secret if point[1] % 2 == 0 else N - secret
    t = _b32(d ^ _int(tagged_hash("BIP0340/aux", aux)))
    k0 = _int(tagged_hash("BIP0340/nonce", t + _b32(point[0]) + msg)) % N
    assert k0 != 0
    r = _mul(k0, G)
    k = k0 if r[1] % 2 == 0 else N - k0
    e = _int(tagged_hash("BIP0340/challenge", _b32(r[0]) + _b32(point[0]) + msg)) % N
    return _b32(r[0]) + _b32((k + e * d) % N)


# ---------------------------------------------------------------------------
# bech32 (BIP-173) and the NIP-19 nprofile the route records (§5.3)
# ---------------------------------------------------------------------------

_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _polymod(values: list[int]) -> int:
    gen = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (top >> i) & 1 else 0
    return chk


def bech32(hrp: str, data: bytes) -> str:
    acc, bits, five = 0, 0, []
    for byte in data:
        acc, bits = (acc << 8) | byte, bits + 8
        while bits >= 5:
            bits -= 5
            five.append((acc >> bits) & 31)
    if bits:
        five.append((acc << (5 - bits)) & 31)
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    mod = _polymod(expanded + five + [0] * 6) ^ 1
    return hrp + "1" + "".join(_CHARSET[d] for d in five + [(mod >> 5 * (5 - i)) & 31 for i in range(6)])


def nprofile_uri(pubkey: bytes, relay: str) -> str:
    """NIP-21 ``nostr:`` URI of a NIP-19 nprofile: TLV 0 the key, TLV 1 one relay."""
    tlv = bytes([0, 32]) + pubkey + bytes([1, len(relay)]) + relay.encode("ascii")
    return "nostr:" + bech32("nprofile", tlv)


# ---------------------------------------------------------------------------
# Nostr test keys and NIP-01 events
# ---------------------------------------------------------------------------

NOSTR_LABELS = {
    "mailbox": "nostr-mailbox-v0 vectors: mailbox key",
    # A fresh carriage key per request (binding §8).
    **{f"requester-{n}": f"nostr-mailbox-v0 vectors: requester carriage key {n}" for n in (1, 2, 3, 4)},
    "other": "nostr-mailbox-v0 vectors: a key the request did not address",
}
NOSTR_SECRET = {name: _int(hashlib.sha256(label.encode()).digest()) % (N - 1) + 1
                for name, label in NOSTR_LABELS.items()}
NOSTR_PUB = {name: xonly(s).hex() for name, s in NOSTR_SECRET.items()}
ROUTE = nprofile_uri(bytes.fromhex(NOSTR_PUB["mailbox"]), RELAY)


def _check_ascii(value: Any) -> None:
    """The NIP-01 escaping rules agree with ``json.dumps`` on printable ASCII; these vectors use
    nothing else."""
    if isinstance(value, str):
        assert value.isascii() and value.isprintable(), value
    elif isinstance(value, list):
        for v in value:
            _check_ascii(v)


def event_id(pubkey: str, created_at: int, kind: int, tags: list, content: str) -> str:
    """NIP-01: SHA-256 over the UTF-8 JSON of [0, pubkey, created_at, kind, tags, content]."""
    _check_ascii(tags)
    _check_ascii(content)
    data = json.dumps([0, pubkey, created_at, kind, tags, content], separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def event(signer: str, created_at: int, kind: int, tags: list, content: str) -> dict:
    eid = event_id(NOSTR_PUB[signer], created_at, kind, tags, content)
    sig = schnorr_sign(NOSTR_SECRET[signer], bytes.fromhex(eid)).hex()
    return {"id": eid, "pubkey": NOSTR_PUB[signer], "created_at": created_at, "kind": kind, "tags": tags,
            "content": content, "sig": sig}


def unix(t: str) -> int:
    return int(datetime.strptime(t, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())


def request_event(signer: str, octets: bytes, media_type: str, sent: str, deadline: str | None) -> dict:
    """§4.1: addressed to the mailbox key; expiring at the request's deadline when it has one."""
    tags = [["p", NOSTR_PUB["mailbox"], RELAY], ["m", media_type]]
    if deadline is not None:
        tags.append(["expiration", str(unix(deadline))])
    return event(signer, unix(sent), REQUEST_KIND, tags, ip.b64u(octets))


def reply_event(req_event: dict, octets: bytes, media_type: str, sent: str, *, signer: str = "mailbox") -> dict:
    """§4.2: a reply to one request event, to its author."""
    tags = [["e", req_event["id"], RELAY], ["p", req_event["pubkey"]], ["m", media_type]]
    return event(signer, unix(sent), REPLY_KIND, tags, ip.b64u(octets))


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------

C, J = "application/cbor", "application/json"
SENT, DEADLINE = "2026-10-12T00:00:10Z", "2026-10-12T00:01:10Z"
# The requester's local timeout, for a request that carries no deadline (§5.3).
LOCAL_TIMEOUT = "2026-10-12T00:05:10Z"


def mailbox_request(nonce: str, deadline: str | None = DEADLINE) -> dict:
    r = ip.request(nonce, ip.ART, ip.ANCHOR1)
    if deadline is not None:
        r["deadline"] = deadline
    return r


def absence(request_octets: bytes, closed: str) -> bytes:
    """§5.3: the window closes at the deadline, or the local timeout; the route is the mailbox."""
    return ip.jcs({"outcome": "recorded_absence", "recorded_at": closed, "request_digest": ip.shx(request_octets),
                   "route": ROUTE, "window": {"closed": closed, "opened": SENT}}).encode()


def pins() -> dict:
    return ip.pins(ip.EVAL)


def build_cases() -> list[dict]:
    ok_claim = {"evidence": [ip.ref(ip.ART)], "proofs": ip.proofs_of(ip.MATERIAL1)}
    ok_reply = {"message_type": "envelope", "properties": ip.env_props(),
                "requirements": {"r-record": ip.mapped("envelope-7")}, "claim": ok_claim}

    r1 = ip.cbor(mailbox_request(f"{SENT}/n1"))
    q1 = request_event("requester-1", r1, C, SENT, DEADLINE)
    e1 = ip.envelope(r1, ip.ART, ip.ANCHOR1, ip.ARTIFACT, ip.MATERIAL1, "2026-10-12T00:00:12Z", C)
    a1 = reply_event(q1, e1, C, "2026-10-12T00:00:12Z")

    r2 = ip.cbor(mailbox_request(f"{SENT}/n2"))
    q2 = request_event("requester-2", r2, C, SENT, DEADLINE)

    rj = ip.encode(J, mailbox_request(f"{SENT}/n3"))
    qj = request_event("requester-3", rj, J, SENT, DEADLINE)
    refused = ip.refusal(rj, "deadline_unmet", "2026-10-12T00:00:13Z")

    r4 = ip.cbor(mailbox_request(f"{SENT}/n4", deadline=None))
    q4 = request_event("requester-4", r4, C, SENT, None)

    def case(case_id: str, description: str, cites: list, req: bytes, media_type: str, req_event: dict,
             events: list[dict], classification: list[str], replies: list[dict], *,
             closed: str | None = None, set_props: dict | None = None) -> dict:
        inputs: dict[str, Any] = {
            "request": ip.octets(media_type, req),
            "mailbox": {"relay": RELAY, "mailbox_key": NOSTR_PUB["mailbox"], "route": ROUTE,
                        "request_event": req_event, "events": events},
        }
        expected: dict[str, Any] = {"request_digest": ip.shx(req), "request_event_id": req_event["id"],
                                    "classification": classification, "replies": replies}
        if replies:
            expected["set_properties"] = set_props or {"caller_invariance": "NOT_CHECKED"}
        if closed is not None:
            record = absence(req, closed)
            inputs["absence_record"] = ip.octets(J, record)
            expected["absence"] = {"form": "conforming",
                                   "window_closes_at": "deadline" if closed == DEADLINE else "local_timeout",
                                   "requirements": {"r-record": ip.mapped("absence")},
                                   "presentation_kind_recommended": "story",
                                   "claim": {"evidence": [ip.ref(ip.shx(record))], "proofs": []}}
        return {"id": case_id, "description": description, "cites": cites, "pins": pins(),
                "inputs": inputs, "expected": expected}

    untrusted = ip.envelope(r1, ip.ART, ip.ANCHOR1, ip.ARTIFACT, ip.MATERIAL1, "2026-10-12T00:00:12Z", C,
                            key="impostor")
    # A second reply to request event 1, as a responder that read the request event twice might send.
    e1b = ip.envelope(r1, ip.ART, ip.ANCHOR1, ip.ARTIFACT, ip.MATERIAL1, "2026-10-12T00:00:15Z", C)
    a1b = reply_event(q1, e1b, C, "2026-10-12T00:00:15Z")
    absent = ["§4.2", "§5.3", "§6"]

    return [
        case("mailbox-exchange",
             "Request 1 as deterministic CBOR in a request event addressed to the mailbox key; one reply "
             "event by that key carrying the envelope. A reply, and every required envelope property PASS: "
             "row 7 of the profile's §8.1.",
             ["§4.1", "§4.2", "§5.1", "§5.2", "interop §8.1 row 7"], r1, C, q1, [a1], ["reply"], [ok_reply]),
        case("mailbox-refusal-deadline-unmet",
             "Request 3 as JCS; the responder answers with a signed deadline_unmet refusal before the "
             "deadline, as ER §3.4 says it SHOULD. A reply; a conforming refusal.",
             ["§4.2", "§5.2", "ER §3.4", "interop §6.3", "interop §8.1"], rj, J, qj,
             [reply_event(qj, refused, J, "2026-10-12T00:00:13Z")], ["reply"],
             [{"message_type": "refusal", "properties": ip.ref_props(),
               "requirements": {"r-record": ip.mapped("refusal-deadline_or_malformed")},
               "claim": {"evidence": [ip.ref(ip.shx(refused))], "proofs": []}}]),
        case("mailbox-request-redelivered",
             "What the requester receives when the responder answered request event 1 twice (for example "
             "because a relay delivered it twice): two reply events with distinct envelopes, and the first "
             "delivered again. Two replies, one per event id; caller_invariance PASS over them.",
             ["§4.2", "§6", "interop §11.4.1 rule 8"], r1, C, q1, [a1, a1b, a1],
             ["reply", "reply", "duplicate"], [ok_reply, ok_reply],
             set_props={"caller_invariance": "PASS"}),
        case("mailbox-envelope-untrusted-key",
             "The mailbox key answers with an envelope signed by, and naming, a key the trust policy does not "
             "accept. The event is a reply (the reply position, §4.2). responder_trust FAIL: row 2.",
             ["§3", "§4.2", "§6", "interop §7.2 responder_trust", "interop §8.1 row 2"], r1, C, q1,
             [reply_event(q1, untrusted, C, "2026-10-12T00:00:12Z")], ["reply"],
             [dict(ok_reply, properties=ip.env_props(responder_trust="FAIL"),
                   requirements={"r-record": ip.mapped("envelope-2")})]),
        case("mailbox-envelope-replayed",
             "The mailbox key answers request 2 with the genuine envelope it signed for request 1. A reply; "
             "request_binding FAIL: row 2.",
             ["§4.2", "§6", "interop §7.2 request_binding", "interop §8.1 row 2"], r2, C, q2,
             [reply_event(q2, e1, C, "2026-10-12T00:00:14Z")], ["reply"],
             [dict(ok_reply, properties=ip.env_props(request_binding="FAIL"),
                   requirements={"r-record": ip.mapped("envelope-2")})]),
        case("mailbox-relayed-by-other-key",
             "A reply event naming request event 1, signed by a Nostr key the request did not address, "
             "carrying the responder's genuine envelope for request 1. Check 7 (author) fails, but the "
             "content is signed by a trusted responder key and binds this request: a reply by content "
             "(ER §3.6), verified as in mailbox-exchange.",
             ["§4.2 check 7", "§4.2 reply by content", "ER §3.6", "ER §4.5"], r1, C, q1,
             [reply_event(q1, e1, C, "2026-10-12T00:00:12Z", signer="other")], ["reply_by_content:author"],
             [ok_reply]),
        case("mailbox-other-key-replays-old-envelope",
             "A reply event naming request event 2, signed by a key the request did not address, carrying "
             "the responder's genuine envelope for request 1. Check 7 fails and the content does not bind "
             "this request: not a reply; a recorded absence at the deadline. A relay cannot turn the "
             "request into a response received and failed.",
             ["§4.2 check 7", "§4.2 reply by content", "§6"] + absent[1:], r2, C, q2,
             [reply_event(q2, e1, C, "2026-10-12T00:00:14Z", signer="other")], ["not_a_reply:author"], [],
             closed=DEADLINE),
        case("mailbox-event-bad-signature",
             "Reply event 1 with its id intact and its signature replaced by another event's. Check 6 "
             "(signature) fails; the content is still the responder's envelope for this request: a reply by "
             "content.",
             ["§4.2 check 6", "§4.2 reply by content", "ER §3.6"], r1, C, q1, [dict(a1, sig=a1b["sig"])],
             ["reply_by_content:signature"], [ok_reply]),
        case("mailbox-event-tampered",
             "Reply event 1 with its content replaced, after signing, by an envelope under a key the trust "
             "policy does not accept. Check 5 (id) fails and the content proves nothing: not a reply; a "
             "recorded absence at the deadline.",
             ["§4.2 check 5", "§4.2 reply by content"] + absent[1:], r1, C, q1,
             [dict(a1, content=ip.b64u(untrusted))], ["not_a_reply:id"], [], closed=DEADLINE),
        case("mailbox-reply-to-other-request",
             "The relay delivers reply event 1, unchanged, on request 2's subscription. Its e tag names "
             "request event 1: check 2 (reply_to) fails, so it is not a reply to this request; a recorded "
             "absence at the deadline.",
             ["§4.2 check 2"] + absent[1:], r2, C, q2, [a1], ["not_a_reply:reply_to"], [], closed=DEADLINE),
        case("mailbox-no-reply",
             "No event arrives before the deadline. The requester records an absence whose window closes "
             "at the request's deadline and whose route is the mailbox it addressed.",
             ["§5.3", "interop §6.4", "interop §8.1"], r1, C, q1, [], [], [], closed=DEADLINE),
        case("mailbox-no-deadline-no-reply",
             "Request 4 has no deadline, so its request event has no expiration tag. No event arrives; the "
             "window closes at the requester's local timeout.",
             ["§4.1", "§5.3", "ER §4.4", "interop §6.4"], r4, C, q4, [], [], [], closed=LOCAL_TIMEOUT),
    ]


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def _dump(value: Any) -> bytes:
    return (json.dumps(value, indent=1, ensure_ascii=False) + "\n").encode("utf-8")


def build() -> dict[str, bytes]:
    cases = build_cases()
    ids = [c["id"] for c in cases]
    assert len(ids) == len(set(ids)), "duplicate case id"
    corpus = {
        "set": SET,
        "status": STATUS,
        "provenance": "spec-derived, constructed; no relay was contacted",
        "binding": BINDING,
        "carriage": {"request_kind": REQUEST_KIND, "reply_kind": REPLY_KIND, "relay": RELAY},
        "nostr_test_keys": {
            "note": "TEST-ONLY. Each secret key is SHA-256(label) as a big-endian integer, reduced mod (n-1), "
                    "plus 1; aux_rand is 32 zero bytes.",
            "keys": {name: {"label": NOSTR_LABELS[name], "public": NOSTR_PUB[name]} for name in NOSTR_LABELS},
        },
        "evidence_test_keys": {
            "note": "The Ed25519 keys of vectors/interop-profile-v0/ (its test_keys), used unchanged.",
            "responder": ip.PUB["responder"], "impostor": ip.PUB["impostor"], "log": ip.PUB["log"],
        },
        "contract": {"document": ip.CONTRACT, "contract_ref": ip.CONTRACT_REF, "contract_digest": ip.CONTRACT_DIGEST},
        "count": len(cases),
        "cases": cases,
    }
    files = {"vectors.json": _dump(corpus)}
    files["manifest.json"] = _dump({
        "set": SET, "status": STATUS, "document": BINDING,
        "generator": "python/scripts/generate_nostr_mailbox_vectors.py",
        "files": [{"path": n, "sha256": ip.shx(d)} for n, d in sorted(files.items())],
    })
    return files


def write(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for name, data in build().items():
        (out / name).write_bytes(data)
    lines = [f"{ip.shx(p.read_bytes())}  {p.name}"
             for p in sorted(out.iterdir()) if p.is_file() and p.name != "SHA256SUMS"]
    (out / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    write(parser.parse_args().out)


if __name__ == "__main__":
    main()
