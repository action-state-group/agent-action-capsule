#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate the vectors of the experimental evidence commitment carriers (spec/bindings/evidence-commitment-carriers-v0.md).

One signed evidence commitment is carried three ways: an attestation entry in a directory record's
trust manifest, an extension entry in an A2A Agent Card, and an addressable Nostr event. Every
expected result below is chosen by hand from the binding's text and cites the step it comes from;
digests, event ids and signatures are computed. Nothing here runs a verifier or contacts a relay,
directory or host. ``python/tests/test_evidence_commitment_carriers_vectors.py`` checks every
carrier entry, commitment, card and answer with its own code.

The Nostr side reuses the mailbox generator's BIP-340, NIP-01 and bech32 code
(``python/scripts/generate_nostr_mailbox_vectors.py``); the evidence side reuses the interop profile
corpus for its responder and impostor keys, its manifest and its envelope builder
(``python/scripts/generate_interop_profile_v0_vectors.py``), so a V5 answer verifies exactly as it
does there.

Output: ``vectors/adapters/evidence-commitment-carriers/`` (or ``--out DIR``). Deterministic: no
clock and no randomness. Every key is derived from a public label and is for testing only.
``README.md`` is hand-written; when present in the output directory it is included in
``SHA256SUMS`` but never rewritten. Dependencies: the standard library and ``cryptography``
(Ed25519 only).
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "vectors" / "adapters" / "evidence-commitment-carriers"
SET = "aac-evidence-commitment-carriers-v0"
BINDING = "spec/bindings/evidence-commitment-carriers-v0.md"
STATUS = ("EXPERIMENTAL. Vectors for a carrier binding that is not part of evidence-interop/0 and "
          "names no binding token. Every key is a test key derived from a public label; never use one "
          "for anything else.")


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(f"{name}.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ip = _load("generate_interop_profile_v0_vectors")
nm = _load("generate_nostr_mailbox_vectors")

# §5.3: a placeholder in NIP-01's addressable range, absent from the kind list at the pinned commit (C-1).
ANNOUNCE_KIND = 34700
RELAY = "wss://relay.example"
# §5.2: the commitment extension entry's URI, compared as a string.
COMMITMENT_EXT_URI = ("https://github.com/action-state-group/agent-action-capsule/blob/main/"
                      "spec/bindings/evidence-commitment-carriers-v0.md")
HOST = "https://node.example"

# ---------------------------------------------------------------------------
# Test keys
# ---------------------------------------------------------------------------

# Ed25519: the responder and impostor are the interop corpus's keys; the rest are this corpus's.
ED_LABELS = {name: f"evidence-commitment-carriers-v0 vectors: {name} key"
             for name in ("stream-log", "witness-configured")}
ED_PRIV = {"responder": ip.PRIV["responder"], "impostor": ip.PRIV["impostor"],
           **{n: Ed25519PrivateKey.from_private_bytes(ip.sha(label.encode())) for n, label in ED_LABELS.items()}}
ED_PUB = {n: k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex() for n, k in ED_PRIV.items()}


def spki(name: str) -> bytes:
    return ED_PRIV[name].public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


NOSTR_LABELS = {name: f"evidence-commitment-carriers-v0 vectors: nostr {name} key" for name in ("mailbox", "other")}
NOSTR_SECRET = {n: nm._int(hashlib.sha256(label.encode()).digest()) % (nm.N - 1) + 1
                for n, label in NOSTR_LABELS.items()}
NOSTR_PUB = {n: nm.xonly(s).hex() for n, s in NOSTR_SECRET.items()}

NODE_ID = ip.shx(b"evidence-commitment-carriers-v0 vectors: node id")
assert not NODE_ID.isdigit()

# ---------------------------------------------------------------------------
# History cards, in the test-only format of inference-service-history-profile-v0 §9 (binding §7)
# ---------------------------------------------------------------------------


def signed(body: dict, signer: str) -> dict:
    return dict(body, sig=ED_PRIV[signer].sign(ip.jcs(body).encode()).hex())


def card(stream: str, checkpoints: list[tuple[str, int, str | None]]) -> dict:
    """``history_card/1``: per checkpoint (timestamp, log size, witness signing a receipt or None)."""
    history = []
    for t, size, witness in checkpoints:
        root = ip.shx(f"evidence-commitment-carriers-v0 vectors: {stream} root at size {size}".encode())
        cp = signed({"key_id": ED_PUB["stream-log"], "log_size": size, "root": root, "timestamp": t}, "stream-log")
        receipts = [signed({"checkpoint": ip.json_digest(cp), "witness": ED_PUB[witness]}, witness)] if witness else []
        history.append({"checkpoint": cp, "receipts": receipts})
    return {"anchor": ip.json_digest(history[-1]["checkpoint"]), "derivation": "history_card/1",
            "evidence_stream": stream, "history": history, "subject": {"full_history": None}}


WITNESSED = [("2026-10-01T12:00:00Z", 10, "witness-configured"), ("2026-10-02T12:00:00Z", 14, "witness-configured")]
LATER = WITNESSED + [("2026-10-03T12:00:00Z", 19, "witness-configured")]


def staple(stream: str, cps: list) -> dict:
    data = ip.jcs(card(stream, cps)).encode()
    return {"bytes": base64.b64encode(data).decode(), "checkpoint_key": ip.b64u(spki("stream-log")),
            "community": "example-community", "derivation": "history_card/1", "sha256": ip.shx(data),
            "stream": stream}


# ---------------------------------------------------------------------------
# The commitment (binding §3)
# ---------------------------------------------------------------------------


def commitment(issued_at: str, streams: list[tuple[str, list]], *, key: str = "responder",
               key_id: str | None = None, nostr: bool = True, bad_staple: bool = False) -> dict:
    """An ``evidence-commitment/1``. Members beyond those §3 reads are fixed placeholders.

    ``key_id`` differs from ``key``'s own only to forge one (V2, ``key_id_spki``); ``bad_staple``
    signs a card digest that is not its bytes' (V3)."""
    cards = [staple(s, cps) for s, cps in sorted(streams)]
    if bad_staple:
        cards[0]["sha256"] = ip.shx(b"evidence-commitment-carriers-v0 vectors: not the card")
    first = card(*sorted(streams)[0])["history"][-1]["checkpoint"]
    cp_bytes = ip.jcs(first).encode()
    ask: dict[str, Any] = {"bindings": ["http"], "endpoint": f"{HOST}/evidence"}
    if nostr:
        ask["nostr"] = {"mailbox_key": NOSTR_PUB["mailbox"], "relays": [RELAY]}
    body = {
        "answers": {"derivations": ["checkpoints", "history_card/1"], "subjects": ["record"]},
        "answers_within": "PT24H",
        "ask": ask,
        "checkpoint": {"bytes": base64.b64encode(cp_bytes).decode(), "sha256": ip.shx(cp_bytes)},
        "history_cards": cards,
        "human_gated": False,
        "issued_at": issued_at,
        "key_id": key_id or ED_PUB[key],
        "lcap": {"policy_digest": ip.shx(b"evidence-commitment-carriers-v0 vectors: policy placeholder"),
                 "policy_uri": "policy.json", "predicate_classes": ["performed:counterparty_half"]},
        "node_id": NODE_ID,
        "profile": "evidence-commitment/1",
        "spki": base64.b64encode(spki(key)).decode(),
    }
    sig = ED_PRIV[key].sign(ip.jcs(body).encode())
    return dict(body, sig={"alg": "Ed25519", "canon": "jcs", "value": ip.b64u(sig)})


def octets_of(c: dict) -> bytes:
    """The octets as served: JCS, so a reader's re-serialization would also match (§4 still forbids it)."""
    return ip.jcs(c).encode()


T1, T2 = "2026-10-02T12:05:00Z", "2026-10-03T12:05:00Z"
C_CURRENT = commitment(T2, [("book-a", LATER)])
C_OLDER = commitment(T1, [("book-a", WITNESSED)])
CUR, OLD = octets_of(C_CURRENT), octets_of(C_OLDER)

# ---------------------------------------------------------------------------
# Carriers (binding §5)
# ---------------------------------------------------------------------------


def sha_tag(data: bytes) -> str:
    return "sha256:" + ip.shx(data)


def directory(uri: str, digest: str) -> dict:
    """§5.1: one attestation entry in the record's trust manifest; the rest of the record is omitted."""
    entry = {"description": "Answers evidence requests about its own records; verify the commitment, not this entry",
             "digest": digest, "mediaType": "application/json", "type": "evidence-commitment/1", "uri": uri}
    return {"carrier": "directory",
            "record": {"tags": ["evidence-request"],
                       "trustManifest": {"attestations": [entry], "identity": HOST}}}


def a2a(uri: str, digest: str, *, pointer_in_discovery_object: bool = False) -> dict:
    """§5.2: the evidence-request entry of IP §11.4.4 and, apart from it, the commitment entry."""
    params = {"commitment_digest": digest, "commitment_uri": uri}
    er_params = dict(ip.manifest(), **params) if pointer_in_discovery_object else ip.manifest()
    er = {"description": "Answers evidence requests under evidence-interop/0", "params": er_params,
          "required": False, "uri": ip.EXT_URI}
    ce = {"description": "Points to this agent's signed evidence commitment; verify the commitment, not this entry",
          "params": params, "required": False, "uri": COMMITMENT_EXT_URI}
    extensions = [er] if pointer_in_discovery_object else [er, ce]
    return {"carrier": "a2a", "card": {"capabilities": {"extensions": extensions}}}


def nostr_event(signer: str, data: bytes, created_at: str, *, inline: bool = True, r: str | None = None,
                content: bytes | None = None) -> dict:
    """§5.3: the announce event. ``content`` differs from ``data`` only to forge one."""
    tags = [["d", NODE_ID], ["t", "evidence-commitment"], ["x", ip.shx(data)]]
    if r is not None:
        tags.append(["r", r])
    body = ip.b64u(content if content is not None else data) if inline else ""
    eid = nm.event_id(NOSTR_PUB[signer], nm.unix(created_at), ANNOUNCE_KIND, tags, body)
    sig = nm.schnorr_sign(NOSTR_SECRET[signer], bytes.fromhex(eid)).hex()
    return {"id": eid, "pubkey": NOSTR_PUB[signer], "created_at": nm.unix(created_at), "kind": ANNOUNCE_KIND,
            "tags": tags, "content": body, "sig": sig}


def naddr_uri(author: str, relay: str) -> str:
    """§5.3: NIP-19 naddr (TLV 0 the d value, 1 a relay, 2 the author, 3 the kind) as a nostr: URI."""
    d = NODE_ID.encode("ascii")
    tlv = (bytes([0, len(d)]) + d + bytes([1, len(relay)]) + relay.encode("ascii")
           + bytes([2, 32]) + bytes.fromhex(author) + bytes([3, 4]) + ANNOUNCE_KIND.to_bytes(4, "big"))
    return "nostr:" + nm.bech32("naddr", tlv)


def served(**uris: bytes) -> dict:
    return {u: ip.b64u(b) for u, b in uris.items()}


URI_CUR, URI_OLD = f"{HOST}/commitment.json", f"{HOST}/commitment-2026-10-02.json"
SENT = "2026-10-03T12:06:00Z"

# ---------------------------------------------------------------------------
# V5 answers: envelopes of the interop corpus
# ---------------------------------------------------------------------------


def answer(key: str = "responder") -> dict:
    req = ip.jcs(ip.request("commitment-carriers-v5", ip.ART, ip.ANCHOR1)).encode()
    env = ip.envelope(req, ip.ART, ip.ANCHOR1, ip.ARTIFACT, ip.MATERIAL1, "2026-10-12T00:00:20Z",
                      "application/json", key=key)
    return {"media_type": "application/json", "request": ip.b64u(req), "reply": ip.b64u(env)}


# ---------------------------------------------------------------------------
# Expected results, by hand
# ---------------------------------------------------------------------------


def carrier_result(carrier: str, data: bytes | None, *, check: str | None = None, digest_mismatch: bool = False,
                   attribution: str | None = None) -> dict:
    out: dict[str, Any] = {"carrier": carrier, "check": check}
    if check is None:  # attribution is reported only beside a commitment that verifies (§5.3)
        out["octets_sha256"] = ip.shx(data)
        out["digest_mismatch"] = digest_mismatch
        if attribution is not None:
            out["attribution"] = attribution
    return out


def verified(data: bytes, standing: str) -> dict:
    return {"sha256": ip.shx(data), "result": "verified", "standing": standing}


def refused(data: bytes, reason: str) -> dict:
    return {"sha256": ip.shx(data), "result": reason}


def handed(c: dict) -> list[dict]:
    """V6: the cards handed to the admission pack, each with its stream, log key and digest."""
    return [{"stream": s["stream"], "checkpoint_key": s.get("checkpoint_key"), "sha256": s["sha256"]}
            for s in c["history_cards"]]


def build_cases() -> list[dict]:
    cases: list[dict] = []

    def case(cid: str, shows: str, sections: list[str], carriers: list[dict], expected: dict, *,
             uris: dict | None = None, relay_events: list | None = None, answer_: dict | None = None) -> None:
        c: dict[str, Any] = {"id": cid, "shows": shows, "sections": sections, "carriers": carriers,
                             "served": uris or {}, "relay_events": relay_events or []}
        if answer_ is not None:
            c["answer"] = answer_
        c["expected"] = expected
        cases.append(c)

    ev_cur = nostr_event("mailbox", CUR, SENT)
    cards_cur = handed(C_CURRENT)

    case("three-carriers-one-commitment",
         "one commitment through a directory entry, an A2A entry and a Nostr event: one digest, verified once",
         ["§5", "§6", "§7"],
         [directory(URI_CUR, sha_tag(CUR)), a2a(URI_CUR, sha_tag(CUR)), {"carrier": "nostr", "event": ev_cur}],
         {"carriers": [carrier_result("directory", CUR), carrier_result("a2a", CUR),
                       carrier_result("nostr", CUR, attribution="announced")],
          "commitments": [verified(CUR, "current")],
          "key_binding": "bound", "cards": cards_cur},
         uris=served(**{URI_CUR: CUR}), answer_=answer())

    naddr = naddr_uri(NOSTR_PUB["mailbox"], RELAY)
    case("directory-entry-naddr",
         "a directory entry whose uri is the announce event's naddr: resolved to the event, same octets",
         ["§5.1", "§5.3"],
         [directory(naddr, sha_tag(CUR))],
         {"carriers": [carrier_result("directory", CUR)], "commitments": [verified(CUR, "current")],
          "cards": cards_cur},
         relay_events=[ev_cur])

    r_uri = f"{HOST}/commitment-over-cap.json"
    case("nostr-over-size-r-tag",
         "an announce event with empty content, its x digest and an r URI: the octets are fetched from r",
         ["§5.3"],
         [{"carrier": "nostr", "event": nostr_event("mailbox", CUR, SENT, inline=False, r=r_uri)}],
         {"carriers": [carrier_result("nostr", CUR, attribution="announced")],
          "commitments": [verified(CUR, "current")], "cards": cards_cur},
         uris=served(**{r_uri: CUR}))

    case("nostr-relayed-by-other-key",
         "the genuine commitment in an announce event by a key other than its mailbox key: verified, relayed",
         ["§5.3"],
         [{"carrier": "nostr", "event": nostr_event("other", CUR, SENT)}],
         {"carriers": [carrier_result("nostr", CUR, attribution="relayed")],
          "commitments": [verified(CUR, "current")], "cards": cards_cur})

    # A member changed after signing: the event's own x and signature are made to match the forgery.
    forged = copy.deepcopy(C_CURRENT)
    forged["answers_within"] = "PT1H"
    forged_octets = octets_of(forged)
    case("forged-carrier-entry",
         "an announce event, well formed and signed, whose commitment has a member changed: refused",
         ["§6 V2", "§8"],
         [{"carrier": "nostr", "event": nostr_event("other", forged_octets, SENT)}],
         {"carriers": [carrier_result("nostr", forged_octets)],
          "commitments": [refused(forged_octets, "commitment_signature")]})

    forged_kid = octets_of(commitment(T2, [("book-a", LATER)], key="impostor", key_id=ED_PUB["responder"]))
    case("forged-key-id",
         "a commitment signed under one key whose key_id names the responder: refused",
         ["§6 V2"],
         [directory(URI_CUR, sha_tag(forged_kid))],
         {"carriers": [carrier_result("directory", forged_kid)],
          "commitments": [refused(forged_kid, "key_id_spki")]},
         uris=served(**{URI_CUR: forged_kid}))

    case("stale-digest",
         "a directory entry whose digest names an older version: digest_mismatch, and the served octets verify",
         ["§4", "§6 V1"],
         [directory(URI_CUR, sha_tag(OLD))],
         {"carriers": [carrier_result("directory", CUR, digest_mismatch=True)],
          "commitments": [verified(CUR, "current")], "cards": cards_cur},
         uris=served(**{URI_CUR: CUR}))

    bad_staple = octets_of(commitment(T2, [("book-a", LATER)], bad_staple=True))
    case("staple-digest-mismatch",
         "a commitment, signed as it is, whose card digest is not the SHA-256 of its card bytes: refused",
         ["§6 V3"],
         [directory(URI_CUR, sha_tag(bad_staple))],
         {"carriers": [carrier_result("directory", bad_staple)],
          "commitments": [refused(bad_staple, "staple_digest")]},
         uris=served(**{URI_CUR: bad_staple}))

    other_key = octets_of(commitment(T2, [("book-a", LATER)], key="impostor"))
    case("answer-key-mismatch",
         "a valid commitment under another key, beside an answer signed by the responder: key_mismatch",
         ["§6 V5"],
         [directory(URI_CUR, sha_tag(other_key))],
         {"carriers": [carrier_result("directory", other_key)], "commitments": [verified(other_key, "current")],
          "key_binding": "key_mismatch", "cards": handed(json.loads(other_key))},
         uris=served(**{URI_CUR: other_key}), answer_=answer())

    case("older-beside-newer",
         "two valid commitments under one key from two carriers: the later issued_at is current",
         ["§6 V4"],
         [directory(URI_OLD, sha_tag(OLD)), {"carrier": "nostr", "event": ev_cur}],
         {"carriers": [carrier_result("directory", OLD), carrier_result("nostr", CUR, attribution="announced")],
          "commitments": [verified(OLD, "superseded"), verified(CUR, "current")], "cards": cards_cur},
         uris=served(**{URI_OLD: OLD}))

    twin = octets_of(commitment(T2, [("book-a", LATER)], nostr=False))
    case("same-issued-at-conflict",
         "two valid commitments under one key with one issued_at and different octets: conflicting, none current",
         ["§6 V4"],
         [directory(URI_CUR, sha_tag(twin)), {"carrier": "nostr", "event": ev_cur}],
         {"carriers": [carrier_result("directory", twin), carrier_result("nostr", CUR, attribution="announced")],
          "commitments": [verified(twin, "conflicting"), verified(CUR, "conflicting")]},
         uris=served(**{URI_CUR: twin}))

    future = octets_of(commitment("2099-01-01T00:00:00Z", [("book-a", LATER)]))
    case("future-dated-issued-at",
         "a valid commitment dated past the verifier's time and skew, beside the current one: future_dated",
         ["§6 V4"],
         [directory(URI_CUR, sha_tag(future)), {"carrier": "nostr", "event": ev_cur}],
         {"carriers": [carrier_result("directory", future), carrier_result("nostr", CUR, attribution="announced")],
          "commitments": [verified(future, "future_dated"), verified(CUR, "current")], "cards": cards_cur},
         uris=served(**{URI_CUR: future}))

    case("a2a-commitment-in-discovery-object",
         "the commitment pointer in the evidence-request entry's params: discovery_object, not read",
         ["§5.2", "§6 V0"],
         [a2a(URI_CUR, sha_tag(CUR), pointer_in_discovery_object=True)],
         {"carriers": [carrier_result("a2a", None, check="discovery_object")], "commitments": []},
         uris=served(**{URI_CUR: CUR}))

    bad = dict(ev_cur, sig=nostr_event("mailbox", OLD, SENT)["sig"])
    case("nostr-event-bad-signature",
         "an announce event whose signature does not verify: nostr_event, not read",
         ["§6 V0"],
         [{"carrier": "nostr", "event": bad}],
         {"carriers": [carrier_result("nostr", None, check="nostr_event")], "commitments": []})

    return cases


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
        "provenance": "spec-derived, constructed; no relay, directory or host was contacted",
        "binding": BINDING,
        "carriage": {"announce_kind": ANNOUNCE_KIND, "relay": RELAY, "a2a_extension_uri": COMMITMENT_EXT_URI},
        "node_id": NODE_ID,
        "verifier": {"note": "The verifier's own configuration (binding §6 V4): when it reads the carriers "
                             "(its time), and its clock skew.",
                     "read_at": SENT, "clock_skew": "PT5M"},
        "test_keys": {
            "note": "TEST-ONLY. Ed25519 secret keys are SHA-256(label); responder and impostor are the "
                    "interop-profile-v0 corpus's keys. Nostr secret keys are SHA-256(label) as a big-endian "
                    "integer, reduced mod (n-1), plus 1; aux_rand is 32 zero bytes.",
            "ed25519": {n: ED_PUB[n] for n in sorted(ED_PUB)},
            "nostr": {n: {"label": NOSTR_LABELS[n], "public": NOSTR_PUB[n]} for n in NOSTR_LABELS},
        },
        "contract": {"document": ip.CONTRACT, "contract_ref": ip.CONTRACT_REF, "contract_digest": ip.CONTRACT_DIGEST},
        "interop_pins": ip.pins(ip.EVAL),
        "count": len(cases),
        "cases": cases,
    }
    files = {"vectors.json": _dump(corpus)}
    files["manifest.json"] = _dump({
        "set": SET, "status": STATUS, "document": BINDING,
        "generator": "python/scripts/generate_evidence_commitment_carriers_vectors.py",
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
