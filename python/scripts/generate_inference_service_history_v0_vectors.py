#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate the conformance vectors of the Inference-Service History Profile v0.

The profile is ``spec/inference-service-history-profile-v0.md``; its §9.4 lists these cases. They
are built here from one node's stream, minted by this script:

- the Standard level: a served-only History, the same History at a later anchor, and the negatives
  of §5, §6 and §7 (a count that mixes units, a count labelled stronger than its evidence, an
  overlapping, a duplicated, an open and a short period, a first, a middle and a last period left
  out, a cell below the floor, a missing complementary suppression, a closed period changed or
  dropped between two anchors);
- the Detailed level: one History whose exchanges are peer-confirmed, one-sided, signed twice by
  the node key, under two client nonces and uncited, each labelled as its evidence allows, and the
  negatives that label one stronger (§7);
- refusals: an interval that is not a run of whole closed periods, asked by two requesters, and a
  Detailed History asked by another requester, each ``policy_declined``; and, under
  ``evidence-interop/1`` only, a History the node declines for its own load, ``capacity_exceeded``.

It states every expected status by hand from the profile text. Each case cites the sections it
comes from. Nothing here imports or runs a verifier.

The definitions, the history card, the period counts and the halves are fixed for these vectors
only and are not registered (§9.4). The checkpoint roots are label digests: no consistency proof is
carried, so the card's consistency is not checked here.

The History is served under either interop profile identifier, negotiated per request (IP §3.3).
The ``evidence-interop/0`` set is frozen; ``--profile 1`` writes the ``evidence-interop/1`` set, the
same cases with every request and envelope naming /1, plus the ``capacity_exceeded`` refusal.
Definitions, Histories and their digests are the same in both.

Output: ``vectors/inference-service-history-v0/``, or ``vectors/inference-service-history-v0-interop-v1/``
under ``--profile 1`` (or ``--out DIR``). Deterministic: no clock, no
randomness. ``README.md`` is never rewritten; every file in the directory is listed in
``SHA256SUMS``. Dependencies: the standard library, ``cryptography`` (Ed25519 only) and the
interop profile generator beside this script, for its encodings and statuses.
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any

import history_frame
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from generate_interop_profile_v0_vectors import (
    EC_SCHEMA,
    KINDS,
    REFUSAL_PROPS,
    b64u,
    env_props,
    jcs,
    json_digest,
    mapped,
    ref,
    ref_props,
    sha,
    shx,
)

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "vectors" / "inference-service-history-v0"
SET = "aac-inference-service-history-v0"
SPEC = "spec/inference-service-history-profile-v0.md"
# The interop profile identifier the requests and envelopes name; use_profile(1) switches the set.
PROFILE = "evidence-interop/0"
STATUS = ("Conformance vectors for the informational Inference-Service History Profile v0, over "
          "evidence-interop/0. Every key is a test key derived from a public seed; never use one for "
          "anything else.")


def use_profile(version: int) -> None:
    """Write the set for ``evidence-interop/<version>``; 0 is the frozen set."""
    global PROFILE, DEFAULT_OUT, SET, STATUS
    PROFILE = f"evidence-interop/{version}"
    if version:
        DEFAULT_OUT = ROOT / "vectors" / f"inference-service-history-v0-interop-v{version}"
        SET = f"aac-inference-service-history-v0-interop-v{version}"
    STATUS = ("Conformance vectors for the informational Inference-Service History Profile v0, over "
              f"{PROFILE}. Every key is a test key derived from a public seed; never use one for "
              "anything else.")
HISTORY_PROFILE = "inference-service-history/0"
STANDARD = "service_history_example/0"
DETAILED = "service_history_detail_example/0"
J = "application/json"
STREAM = "node-stream-1"
RECIPIENT = "principal:recipient-example"

SEED_LABELS = {
    "node": "inference-service-history-profile-v0 conformance vectors: node key",
    "node-log": "inference-service-history-profile-v0 conformance vectors: node log key",
    "peer": "inference-service-history-profile-v0 conformance vectors: peer node key",
    "untrusted-peer": "inference-service-history-profile-v0 conformance vectors: peer key the relying party does not trust",
    "witness": "inference-service-history-profile-v0 conformance vectors: witness key",
    "other-witness": "inference-service-history-profile-v0 conformance vectors: witness key the relying party has not configured",
}
PRIV = {name: Ed25519PrivateKey.from_private_bytes(sha(label.encode())) for name, label in SEED_LABELS.items()}
PUB = {name: k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex() for name, k in PRIV.items()}

# §5.1, §7.1.
UNITS = ["exchanges_served", "exchanges_requested", "exchanges_unattributed", "checkpoints", "witness_receipts",
         "referee_verdicts", "records"]
LABELS = ["self_reported", "peer_confirmed", "corroborated"]

STANDARD_PROPS = ["definition_form", "definition_binding", "artifact_form", "history_card_content", "units",
                  "labels", "period_alignment", "period_anchor", "period_floor"]
DETAILED_PROPS = ["definition_form", "definition_binding", "artifact_form", "history_card_content", "units",
                  "labels"]

# §6.1: the period policy every Standard definition here carries.
POLICY = {"epoch": "2026-10-01T00:00:00Z", "floor": 5, "length_s": 86400, "min_length_s": 86400,
          "suppression": "complementary"}
POLICY_DIGEST = json_digest(POLICY)

# The relying party's requirement a Service History answer is the only evidence for (§8.1).
CONTRACT = {
    "id": "S",
    "version": "1",
    "requirements": [
        {"id": "r-service", "profile": "outcome",
         "statement": "The node's served exchanges are shown under a verified envelope.",
         "evidence_requirements": {"accepted_epistemic_types": ["producer_claim"]}},
    ],
}
CONTRACT_REF = f"{CONTRACT['id']}@{CONTRACT['version']}"
CONTRACT_DIGEST = json_digest(CONTRACT)
REQUIREMENT = "r-service"
EVAL = "2026-10-05T06:00:00Z"


def signed(body: dict, key: str) -> dict:
    return dict(body, sig=PRIV[key].sign(jcs(body).encode()).hex())


def carried(value: dict) -> dict:
    return {"media_type": J, "octets_text": jcs(value)}


# ---------------------------------------------------------------------------
# The node's stream: checkpoints and the history card (§4.2; vector-only shape, §9.4)
# ---------------------------------------------------------------------------

# (time, log size, witness signing a receipt or None) per checkpoint. Checkpoints 3 and 5 are at
# period boundaries, so a Standard History answers there (§6.1 item 2); checkpoint 4 is inside the
# open 4 October.
CHECKPOINTS = [
    ("2026-10-01T12:00:00Z", 10, None),
    ("2026-10-02T12:00:00Z", 25, "witness"),
    ("2026-10-03T12:00:00Z", 38, "witness"),
    ("2026-10-04T00:00:00Z", 52, "other-witness"),
    ("2026-10-04T12:00:00Z", 60, None),
    ("2026-10-05T00:00:00Z", 67, None),
]


def checkpoint(i: int) -> dict:
    t, size, _ = CHECKPOINTS[i]
    root = shx(f"inference-service-history-profile-v0 conformance vectors: root at size {size}".encode())
    return signed({"key_id": PUB["node-log"], "log_size": size, "root": root, "timestamp": t}, "node-log")


def card(last: int) -> dict:
    """``history_card/1`` in this corpus's shape: every checkpoint from the first to ``last``."""
    history = []
    for i in range(last + 1):
        cp = checkpoint(i)
        witness = CHECKPOINTS[i][2]
        receipts = [signed({"checkpoint": json_digest(cp), "witness": PUB[witness]}, witness)] if witness else []
        history.append({"checkpoint": cp, "receipts": receipts})
    return {"anchor": json_digest(history[-1]["checkpoint"]), "derivation": "history_card/1",
            "evidence_stream": STREAM, "history": history, "subject": {"full_history": None}}


ANCHOR_N = card(3)["anchor"]
ANCHOR_OPEN = card(4)["anchor"]
ANCHOR_N1 = card(5)["anchor"]

# ---------------------------------------------------------------------------
# Definitions (§4.1, §4.4)
# ---------------------------------------------------------------------------

CARD_MEMBER = {
    "name": "history_card", "required": True, "derivation": "history_card/1",
    "reads": ["checkpoint: key_id, log_size, root, timestamp, sig", "receipt: checkpoint, witness, sig"],
    "units": [{"where": "history (one entry per checkpoint)", "unit": "checkpoints"},
              {"where": "history[].receipts", "unit": "witness_receipts"}],
}


def standard_definition(units: list[str] | None = None) -> dict:
    members = [CARD_MEMBER, {
        "name": "period_counts", "required": True,
        "reads": ["record: role", "record: committed_at", "record: model claim"],
        "units": [{"where": "periods[].cells[]", "unit": u} for u in (units or ["exchanges_served"])],
        "claims": {"asserted_by": "provider", "label": "provider states", "where": ["periods[].cells[].dimension"]},
    }]
    reads: list[str] = []
    for m in members:
        reads += [r for r in m["reads"] if r not in reads]
    return {"coverage_declaration": {"kind": "stream_interval", "rule": "all_records"},
            "embeds": ["history_card/1"], "excludes": ["requester identity", "per-recipient release state"],
            "kind": "projection", "level": "standard", "members": members, "name": STANDARD,
            "period_policy": POLICY, "profile": HISTORY_PROFILE, "reads": reads,
            "spec": "vectors/inference-service-history-v0/README.md", "subjects": ["full_history"]}


def detailed_definition() -> dict:
    members = [CARD_MEMBER, {
        "name": "exchanges", "required": True,
        "reads": ["record: the node's half, as signed", "record: the peer's half, as signed, where held"],
        "units": [{"where": "exchanges[] whose half is served", "unit": "exchanges_served"},
                  {"where": "exchanges[] whose half is requested", "unit": "exchanges_requested"}],
    }]
    reads: list[str] = []
    for m in members:
        reads += [r for r in m["reads"] if r not in reads]
    return {"coverage_declaration": {"kind": "holder_selected"}, "embeds": ["history_card/1"],
            "excludes": ["requesters other than the recipient"], "kind": "projection", "level": "detailed",
            "members": members, "name": DETAILED, "profile": HISTORY_PROFILE, "reads": reads,
            "recipient": RECIPIENT, "spec": "vectors/inference-service-history-v0/README.md",
            "subjects": ["full_history"]}


# ---------------------------------------------------------------------------
# Period counts (§6; vector-only shape, §9.4)
# ---------------------------------------------------------------------------

DAY = ["2026-10-01T00:00:00Z", "2026-10-02T00:00:00Z", "2026-10-03T00:00:00Z", "2026-10-04T00:00:00Z",
       "2026-10-05T00:00:00Z"]

# The node's served exchanges per closed period and per model it states, as its log holds them.
# Its requested exchanges (4, 2 and 1) are in the log and in no cell: the counts are served-only.
SERVED = [{"model-a": 12, "model-b": 7}, {"model-a": 9, "model-b": 3}, {"model-a": 6, "model-b": 5}]
# 4 October, closed at the next boundary.
SERVED_4 = {"model-a": 8, "model-b": 6}


def cell(value: int | None, dimension: dict | None, *, unit: str = "exchanges_served", label: str = "self_reported",
         suppressed: str | None = None) -> dict:
    c: dict[str, Any] = {"dimension": dimension, "label": label, "unit": unit, "value": value}
    if suppressed is not None:
        c["suppressed"] = suppressed
        c["value"] = None
    return c


def period_cells(counts: dict) -> list[dict]:
    """§6.2: the floor per cell, then the complementary rule: a published total and one suppressed
    cell would give it away, so the next smallest cell is suppressed with it."""
    floor = POLICY["floor"]
    out = []
    below = {m for m, v in counts.items() if v < floor}
    complementary = set()
    if len(below) == 1:
        complementary = {min((m for m in counts if m not in below), key=lambda m: (counts[m], m))}
    for m in sorted(counts):
        if m in below:
            out.append(cell(None, {"model": m}, suppressed="below_floor"))
        elif m in complementary:
            out.append(cell(None, {"model": m}, suppressed="complementary"))
        else:
            out.append(cell(counts[m], {"model": m}))
    out.append(cell(sum(counts.values()), None))
    return out


def period_counts(served: list[dict] = SERVED) -> dict:
    return {"periods": [{"cells": period_cells(c), "from": DAY[i], "to": DAY[i + 1]} for i, c in enumerate(served)],
            "policy": POLICY_DIGEST}


# ---------------------------------------------------------------------------
# Halves (§7.2; vector-only shape, §9.4)
# ---------------------------------------------------------------------------


def peer_half(nonce: str, at: str, key: str = "peer", role: str = "requested") -> dict:
    return carried(signed({"client_nonce": nonce, "committed_at": at, "producer": PUB[key], "role": role}, key))


def node_half(nonce: str, at: str, cites: dict | None) -> dict:
    body: dict[str, Any] = {"client_nonce": nonce, "committed_at": at, "producer": PUB["node"], "role": "served"}
    if cites is not None:
        body["references"] = [{"citation_purpose": "counterparty_half", "digest": shx(cites["octets_text"].encode())}]
    return carried(signed(body, "node"))


def entry(nonce: str, half: dict, peer: dict | None, label: str) -> dict:
    e: dict[str, Any] = {"client_nonce": nonce, "half": half, "label": label, "unit": "exchanges_served"}
    if peer is not None:
        e["peer_half"] = peer
    return e


# ---------------------------------------------------------------------------
# Answers (§8)
# ---------------------------------------------------------------------------


def request(definition_digest: str, nonce: str, *, anchor: str = ANCHOR_N, subject: dict | None = None) -> dict:
    return carried({"coverage": {"expected_pin": anchor}, "derivation": definition_digest, "nonce": nonce,
                    "profile": PROFILE, "subject": subject or {"full_history": None}})


def envelope(req: dict, artifact: dict, issued_at: str) -> dict:
    data = jcs(artifact).encode()
    r = json.loads(req["octets_text"])
    body = {"anchor": {"digest": r["coverage"]["expected_pin"]}, "artifact_digest": shx(data),
            "derivation": r["derivation"], "issued_at": issued_at, "profile": PROFILE,
            "request_digest": shx(req["octets_text"].encode()), "responder": PUB["node"], "subject": r["subject"]}
    sig = PRIV["node"].sign(jcs(body).encode()).hex()
    return carried(dict(body, sig=sig, artifact=b64u(data)))


def refusal(req: dict, reason: str, issued_at: str) -> dict:
    body = {"issued_at": issued_at, "reason": reason, "request_digest": shx(req["octets_text"].encode())}
    return carried(dict(body, key_id=PUB["node"], sig=PRIV["node"].sign(jcs(body).encode()).hex()))


def artifact(definition: dict, anchor: str, last: int, members: dict) -> dict:
    """§8.2: the fixed members, the members ``declared`` names, and the card with its digest."""
    c = card(last)
    a: dict[str, Any] = {"anchor": anchor, "declared": sorted(["history_card", *members]),
                         "derivation": json_digest(definition), "evidence_stream": STREAM,
                         "history_card": c, "history_card_digest": json_digest(c),
                         "subject": {"full_history": None}}
    if definition["level"] == "standard":
        a["coverage_declaration"] = {
            "interval": {"from": None, "to": anchor}, "kind": "stream_interval", "rule": "all_records",
            "live_set": [{"checkpoint": anchor, "count": CHECKPOINTS[last][1], "start": 0, "stream": STREAM}]}
    a.update(members)
    return a


# ---------------------------------------------------------------------------
# Expected values
# ---------------------------------------------------------------------------

ACCEPTED_PROPS = env_props(verification_binding="NOT_PRESENT", anchor_inclusion="NOT_CHECKED")


def answered(env: dict) -> dict:
    """The envelope's IP result (§8.1): accepted, and the only evidence for the requirement: row 4."""
    e = json.loads(env["octets_text"])
    return {"message_type": "envelope", "subject": e["subject"], "properties": ACCEPTED_PROPS, "accepted": True,
            "requirements": {REQUIREMENT: mapped("envelope-4")},
            "claim": {"evidence": [ref(e["artifact_digest"])], "proofs": []}}


def props(names: list[str], **over: str) -> dict:
    out = dict.fromkeys(names, "PASS")
    out.update(over)
    return out


def standard_coverage(**over: str) -> dict:
    p = {"coverage_declaration_form": "PASS", "coverage_declaration_anchor": "PASS",
         "coverage_declaration_population": "NOT_CHECKED", "coverage_declaration_commitment": "NOT_CHECKED"}
    p.update(over)
    return {"declared_kind": "stream_interval", "properties": p,
            "relative_to": "the node's stream at the anchor, under all_records; completeness not established: "
                           "counts not checked against records"}


DETAILED_COVERAGE = {"declared_kind": "holder_selected", "properties": {"coverage_declaration_form": "PASS"},
                     "relative_to": "not asserted"}


def witness(last: int) -> dict:
    """§5.2, as the relying party's pins configure only the witness key: receipts it verified, and
    receipts it did not count with the reason."""
    counted = sum(1 for i in range(last + 1) if CHECKPOINTS[i][2] == "witness")
    not_counted = [{"checkpoint": i, "reason": "witness key not configured"}
                   for i in range(last + 1) if CHECKPOINTS[i][2] == "other-witness"]
    return {"checkpoints": last + 1, "witness_receipts_counted": counted, "witness_receipts_not_counted": not_counted}


# (derived label, shown as, issuer_independence) per §7.2 outcome.
PEER_CONFIRMED = ("peer_confirmed", "peer-confirmed; not corroborating (independence not established)", "NOT_CHECKED")
ONE_SIDED = ("self_reported", "one-sided", None)
REDUNDANT = ("self_reported", "redundant, not corroborating", "FAIL")
NOT_JOINABLE = ("self_reported", "not joinable", None)
PEER_UNTRUSTED = ("self_reported", "peer half not verified under a trusted key", None)


def shown(entries: list[dict], outcomes: list[tuple[str, str, str | None]]) -> list[dict]:
    out = []
    for e, (label, as_, independence) in zip(entries, outcomes):
        s: dict[str, Any] = {"client_nonce": e["client_nonce"], "claimed": e["label"], "derived": label, "shown_as": as_}
        if independence is not None:
            s["issuer_independence"] = independence
        out.append(s)
    return out


def pins(peer_keys: tuple[str, ...] = ("peer",)) -> dict:
    trust = {"responder_keys": [PUB["node"]], "log_keys": [], "foreign_keys": [], "parties": {},
             "successions": [], "require_action_time_from_other_party": False}
    return {"trust_policy": trust,
            "verification_policy": {"online": False, "profiles_implemented": [PROFILE], "kinds_implemented": KINDS},
            "service_history": {"log_keys": [PUB["node-log"]], "witness_keys": [PUB["witness"]],
                                "peer_keys": [PUB[k] for k in peer_keys]},
            "contract_ref": CONTRACT_REF, "contract_digest": CONTRACT_DIGEST, "evaluation_time": EVAL}


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------


def history(definition: dict, nonce: str, art: dict, issued_at: str, *, anchor: str = ANCHOR_N) -> dict:
    req = request(json_digest(definition), nonce, anchor=anchor)
    return {"definition": definition, "request": req, "reply": envelope(req, art, issued_at)}


def standard(*, counts: dict | None = None, definition: dict | None = None, last: int = 3,
             anchor: str = ANCHOR_N, nonce: str = "requester-1/standard", at: str = "2026-10-04T00:00:05Z") -> dict:
    d = definition or standard_definition()
    return history(d, nonce, artifact(d, anchor, last, {"period_counts": counts or period_counts()}), at,
                   anchor=anchor)


def cases() -> list[dict]:
    out: list[dict] = []

    def history_case(cid: str, title: str, cites: list[str], source: str, h: dict, hprops: dict, coverage: dict,
                     fails: list[str], *, last: int = 3, exchanges: list[dict] | None = None,
                     peer_keys: tuple[str, ...] = ("peer",)) -> dict:
        accepted = all(v == "PASS" for v in hprops.values()) and "FAIL" not in coverage["properties"].values()
        assert accepted is (not fails), cid
        shows: dict[str, Any] = {"witness": witness(last)}
        if exchanges is not None:
            shows["exchanges"] = exchanges
        return {"id": cid, "title": title, "cites": cites, "source": source, "kind": "history",
                "pins": pins(peer_keys), "inputs": h,
                "expected": {"exchange": answered(h["reply"]), "history_properties": hprops, "coverage": coverage,
                             "shows": shows, "accepted": accepted, "fails": fails}}

    # --- Standard level -------------------------------------------------------------------------
    out.append(history_case(
        "standard-served-only", "A Standard History: served exchanges per closed period, requested ones in no cell",
        ["§4", "§5", "§6", "§8.3", "§9.1"], "constructed", standard(),
        props(STANDARD_PROPS), standard_coverage(), []))

    mixed = period_counts()
    mixed["periods"][0]["cells"].append(cell(23, None, unit="exchanges"))  # 19 served + 4 requested
    out.append(history_case(
        "mutant-count-mixes-units", "A cell counting served and requested exchanges together",
        ["§5.1", "§9.1"], "constructed: the served-only History with one cell in the unit 'exchanges' (19 + 4)",
        standard(counts=mixed), props(STANDARD_PROPS, units="FAIL"), standard_coverage(), ["units"]))

    loud = period_counts()
    loud["periods"][0]["cells"][-1]["label"] = "peer_confirmed"
    out.append(history_case(
        "mutant-standard-count-labelled-peer-confirmed", "A Standard count labelled peer_confirmed",
        ["§7.1", "§7.3", "§9.1"], "constructed: the served-only History with the first period's total labelled "
        "peer_confirmed", standard(counts=loud), props(STANDARD_PROPS, labels="FAIL"), standard_coverage(), ["labels"]))

    overlap = period_counts()
    overlap["periods"].insert(1, {"cells": period_cells({"model-a": 10, "model-b": 6}),
                                  "from": "2026-10-01T12:00:00Z", "to": "2026-10-02T12:00:00Z"})
    out.append(history_case(
        "mutant-overlapping-period", "A period that overlaps two published periods",
        ["§6.1", "§6.3", "§9.1"], "constructed: the served-only History with a period from 12:00 to 12:00 inserted",
        standard(counts=overlap), props(STANDARD_PROPS, period_alignment="FAIL"), standard_coverage(),
        ["period_alignment"]))

    duplicate = period_counts()
    duplicate["periods"].insert(1, copy.deepcopy(duplicate["periods"][0]))
    out.append(history_case(
        "mutant-duplicate-period", "One aligned period listed twice",
        ["§6.1", "§6.3", "§9.1"], "constructed: the served-only History with 1 October listed twice",
        standard(counts=duplicate), props(STANDARD_PROPS, period_alignment="FAIL"), standard_coverage(),
        ["period_alignment"]))

    open_ = period_counts([*SERVED, SERVED_4])
    out.append(history_case(
        "mutant-open-period", "The period the anchor falls in, counted before it is closed",
        ["§6.1", "§6.3", "§9.1"], "constructed: the served-only History with 4 October counted at an anchor of "
        "4 October 00:00", standard(counts=open_), props(STANDARD_PROPS, period_alignment="FAIL"),
        standard_coverage(), ["period_alignment"]))

    out.append(history_case(
        "mutant-answered-at-open-anchor", "A Standard History answered at an anchor inside an open period",
        ["§6.1", "§6.3", "§9.1", "§12"], "constructed: the served-only History answered at the checkpoint of "
        "4 October 12:00, inside the open 4 October",
        standard(last=4, anchor=ANCHOR_OPEN, nonce="requester-1/standard-open", at="2026-10-04T12:00:05Z"),
        props(STANDARD_PROPS, period_anchor="FAIL"), standard_coverage(), ["period_anchor"], last=4))

    short = period_counts()
    short["periods"][2]["to"] = "2026-10-03T12:00:00Z"
    out.append(history_case(
        "mutant-short-period", "A period shorter than the policy's length",
        ["§6.1", "§6.3", "§9.1"], "constructed: the served-only History with 3 October ending at 12:00",
        standard(counts=short), props(STANDARD_PROPS, period_alignment="FAIL"), standard_coverage(),
        ["period_alignment"]))

    no_first = period_counts()
    del no_first["periods"][0]
    out.append(history_case(
        "mutant-omitted-first-period", "The stream's first closed period left out",
        ["§6.1", "§6.3", "§9.1"], "constructed: the served-only History without 1 October, the period of the "
        "stream's first record (the card's first checkpoint is 1 October 12:00, log size 10)",
        standard(counts=no_first), props(STANDARD_PROPS, period_alignment="FAIL"), standard_coverage(),
        ["period_alignment"]))

    gap = period_counts()
    del gap["periods"][1]
    out.append(history_case(
        "mutant-omitted-period", "A closed period left out between two listed ones",
        ["§6.1", "§6.3", "§9.1"], "constructed: the served-only History without 2 October",
        standard(counts=gap), props(STANDARD_PROPS, period_alignment="FAIL"), standard_coverage(),
        ["period_alignment"]))

    no_last = period_counts()
    del no_last["periods"][-1]
    out.append(history_case(
        "mutant-omitted-last-period", "The last closed period left out",
        ["§6.1", "§6.3", "§9.1"], "constructed: the served-only History without 3 October, the period that ends "
        "at the anchor", standard(counts=no_last), props(STANDARD_PROPS, period_alignment="FAIL"),
        standard_coverage(), ["period_alignment"]))

    floor = period_counts()
    floor["periods"][1]["cells"] = [cell(9, {"model": "model-a"}), cell(3, {"model": "model-b"}), cell(12, None)]
    out.append(history_case(
        "mutant-cell-below-floor", "A cell of 3 published under a floor of 5",
        ["§6.2", "§6.3", "§9.1"], "constructed: the served-only History with 2 October's cells unsuppressed",
        standard(counts=floor), props(STANDARD_PROPS, period_floor="FAIL"), standard_coverage(), ["period_floor"]))

    complement = period_counts()
    complement["periods"][1]["cells"] = [cell(9, {"model": "model-a"}), cell(None, {"model": "model-b"},
                                         suppressed="below_floor"), cell(12, None)]
    out.append(history_case(
        "mutant-complementary-not-suppressed", "One cell suppressed, and the total and the other cell published",
        ["§6.2", "§6.3", "§9.1"], "constructed: the served-only History with 2 October's model-a cell published "
        "beside its total", standard(counts=complement), props(STANDARD_PROPS, period_floor="FAIL"),
        standard_coverage(), ["period_floor"]))

    # --- Two anchors: each closed period's bytes are fixed once produced (§6.1) -------------------
    first = standard()
    later = standard(counts=period_counts([*SERVED, SERVED_4]), last=5, anchor=ANCHOR_N1,
                     nonce="requester-1/standard-later", at="2026-10-05T00:00:05Z")
    changed = copy.deepcopy([*SERVED, SERVED_4])
    changed[2]["model-a"] += 1
    moved = standard(counts=period_counts(changed), last=5, anchor=ANCHOR_N1, nonce="requester-1/standard-later",
                     at="2026-10-05T00:00:05Z")
    dropping = period_counts([*SERVED, SERVED_4])
    del dropping["periods"][1]
    dropped = standard(counts=dropping, last=5, anchor=ANCHOR_N1, nonce="requester-1/standard-later",
                       at="2026-10-05T00:00:05Z")

    def pair_case(cid: str, title: str, source: str, histories: list[dict], status: str, fails: list[str]) -> dict:
        return {"id": cid, "title": title, "cites": ["§6.1", "§6.3", "§9.2"], "source": source, "kind": "pair",
                "pins": pins(), "inputs": {"histories": histories},
                "expected": {"exchanges": [answered(h["reply"]) for h in histories],
                             "period_fixed": status, "accepted": not fails, "fails": fails}}

    out.append(pair_case(
        "periods-fixed-across-anchors", "The same History at two period boundaries: identical earlier periods",
        "constructed: the served-only History, and the same definition answered at the next boundary, with "
        "4 October added",
        [first, later], "PASS", []))
    out.append(pair_case(
        "mutant-period-changed-across-anchors", "A closed period's count changed at the later anchor",
        "constructed: the later History with 3 October's model-a count raised by one", [first, moved], "FAIL",
        ["period_fixed"]))
    out.append(pair_case(
        "mutant-period-dropped-across-anchors", "A closed period answered at the first anchor, dropped at the later one",
        "constructed: the later History without 2 October, which the first History carries", [first, dropped],
        "FAIL", ["period_fixed"]))

    # --- Refusals (§6.1 item 5, §8.4) -----------------------------------------------------------
    d = standard_definition()
    for i, (cid, nonce) in enumerate((("refused-range-interval", "requester-1/range"),
                                      ("refused-range-interval-other-requester", "requester-2/range"))):
        req = request(json_digest(d), nonce, subject={"range": [10, 37]})
        rep = refusal(req, "policy_declined", f"2026-10-04T00:00:1{i}Z")
        out.append({"id": cid, "title": "A Standard History asked over records 10 to 37, which is no run of whole periods",
                    "cites": ["§6.1", "§8.4", "IP §6.3"], "source": "constructed", "kind": "refusal",
                    "pins": pins(), "inputs": {"definition": d, "request": req, "reply": rep},
                    "expected": {"message_type": "refusal", "reason": "policy_declined", "properties": ref_props(),
                                 "requirements": {REQUIREMENT: mapped("refusal-withheld")},
                                 "claim": {"evidence": [ref(shx(rep["octets_text"].encode()))], "proofs": []}}})

    req = request(json_digest(d), "requester-1/open-anchor", anchor=ANCHOR_OPEN)
    rep = refusal(req, "policy_declined", "2026-10-04T12:00:15Z")
    out.append({"id": "refused-open-period-anchor", "title": "A Standard History asked at an anchor inside an open period",
                "cites": ["§6.1", "§8.4", "IP §6.3"], "source": "constructed", "kind": "refusal",
                "pins": pins(), "inputs": {"definition": d, "request": req, "reply": rep},
                "expected": {"message_type": "refusal", "reason": "policy_declined", "properties": ref_props(),
                             "requirements": {REQUIREMENT: mapped("refusal-withheld")},
                             "claim": {"evidence": [ref(shx(rep["octets_text"].encode()))], "proofs": []}}})

    dd = detailed_definition()
    req = request(json_digest(dd), "requester-3/detailed")
    rep = refusal(req, "policy_declined", "2026-10-04T00:00:20Z")
    out.append({"id": "refused-detailed-other-requester", "title": "A Detailed History asked by a requester it does not name",
                "cites": ["§4.4", "§8.4", "IP §6.5 item 4"], "source": "constructed", "kind": "refusal",
                "pins": pins(), "inputs": {"definition": dd, "request": req, "reply": rep},
                "expected": {"message_type": "refusal", "reason": "policy_declined", "properties": ref_props(),
                             "requirements": {REQUIREMENT: mapped("refusal-withheld")},
                             "claim": {"evidence": [ref(shx(rep["octets_text"].encode()))], "proofs": []}}})

    if PROFILE != "evidence-interop/0":  # capacity_exceeded is unregistered under /0 (IP v1 §9.1)
        req = request(json_digest(d), "requester-4/under-load")
        rep = refusal(req, "capacity_exceeded", "2026-10-04T00:00:25Z")
        out.append({"id": "refused-capacity-exceeded", "title": "A Standard History the node declines for its own load",
                    "cites": ["§6.1", "§8.4", "IP §6.3", "IP §8.1"], "source": "constructed", "kind": "refusal",
                    "pins": pins(), "inputs": {"definition": d, "request": req, "reply": rep},
                    "expected": {"message_type": "refusal", "reason": "capacity_exceeded", "properties": ref_props(),
                                 "requirements": {REQUIREMENT: mapped("refusal-capacity_exceeded")},
                                 "claim": {"evidence": [ref(shx(rep["octets_text"].encode()))], "proofs": []}}})

    # --- Detailed level (§7) --------------------------------------------------------------------
    def detailed(labels: list[str], *, untrusted: bool = False) -> tuple[dict, list[dict]]:
        p1 = peer_half("x-1", "2026-10-02T09:00:00Z", "untrusted-peer" if untrusted else "peer")
        p3 = peer_half("x-3", "2026-10-03T09:00:00Z", "node")
        p4 = peer_half("x-4-peer", "2026-10-03T10:00:00Z")
        p5 = peer_half("x-5", "2026-10-03T11:00:00Z")
        entries = [
            entry("x-1", node_half("x-1", "2026-10-02T09:00:01Z", p1), p1, labels[0]),
            entry("x-2", node_half("x-2", "2026-10-02T10:00:01Z", None), None, labels[1]),
            entry("x-3", node_half("x-3", "2026-10-03T09:00:01Z", p3), p3, labels[2]),
            entry("x-4", node_half("x-4", "2026-10-03T10:00:01Z", p4), p4, labels[3]),
            entry("x-5", node_half("x-5", "2026-10-03T11:00:01Z", None), p5, labels[4]),
        ]
        h = history(dd, "recipient/detailed", artifact(dd, ANCHOR_N, 3, {"exchanges": entries}),
                    "2026-10-04T00:00:30Z")
        return h, entries

    honest = ["peer_confirmed", "self_reported", "self_reported", "self_reported", "self_reported"]
    outcomes = [PEER_CONFIRMED, ONE_SIDED, REDUNDANT, NOT_JOINABLE, NOT_JOINABLE]
    h, entries = detailed(honest)
    out.append(history_case(
        "detailed-peer-confirmed", "A Detailed History: one peer-confirmed exchange, and four the node alone shows",
        ["§7.1", "§7.2", "§9.3"], "constructed", h, props(DETAILED_PROPS), DETAILED_COVERAGE, [],
        exchanges=shown(entries, outcomes)))

    for cid, title, i, label, source in (
        ("mutant-labelled-corroborated", "A peer-confirmed exchange labelled corroborated", 0, "corroborated",
         "x-1 labelled corroborated: two keys, no evidence about their controllers"),
        ("mutant-same-key-halves-labelled-peer-confirmed", "Both halves signed by the node key, labelled peer_confirmed",
         2, "peer_confirmed", "x-3, whose peer half the node key signed, labelled peer_confirmed"),
        ("mutant-unjoined-halves-labelled-peer-confirmed", "Halves with different client nonces, labelled peer_confirmed",
         3, "peer_confirmed", "x-4, whose peer half carries another client nonce, labelled peer_confirmed"),
        ("mutant-uncited-halves-labelled-peer-confirmed", "Halves with one client nonce, the node's citing no half, "
         "labelled peer_confirmed", 4, "peer_confirmed",
         "x-5, whose half cites no counterparty half, labelled peer_confirmed"),
        ("mutant-one-sided-labelled-peer-confirmed", "An exchange with no peer half, labelled peer_confirmed",
         1, "peer_confirmed", "x-2, which carries no peer half, labelled peer_confirmed"),
    ):
        labels = list(honest)
        labels[i] = label
        h, entries = detailed(labels)
        out.append(history_case(cid, title, ["§7.2", "§7.3", "§9.3", "IP §6.7.4"], f"constructed: the Detailed History with {source}",
                                h, props(DETAILED_PROPS, labels="FAIL"), DETAILED_COVERAGE, ["labels"],
                                exchanges=shown(entries, outcomes)))

    h, entries = detailed(honest, untrusted=True)
    out.append(history_case(
        "mutant-untrusted-peer-labelled-peer-confirmed", "A peer half under a key the relying party does not trust, "
        "labelled peer_confirmed", ["§7.2", "§7.3", "§9.3"],
        "constructed: the Detailed History with x-1's peer half signed by a key outside the pins' peer keys", h,
        props(DETAILED_PROPS, labels="FAIL"), DETAILED_COVERAGE, ["labels"],
        exchanges=shown(entries, [PEER_UNTRUSTED, *outcomes[1:]])))
    return out


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def _dump(value: Any) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def check_frame(all_cases: list[dict]) -> None:
    """HF §6.3: the instance's counting table and wording pack (``spec/history-frame/``) match the
    definitions and what these vectors emit, and every case's acceptance is HF §4.5's rule."""
    table, pack = history_frame.load(HISTORY_PROFILE)
    assert table["units"] == UNITS and table["labels"] == LABELS, "counting table: units, labels"
    assert table["properties"] == {"standard": STANDARD_PROPS, "detailed": DETAILED_PROPS}, "counting table: properties"
    members = table["definition_members"]
    for d, absent in ((standard_definition(), "recipient"), (detailed_definition(), "period_policy")):
        assert sorted(d) == sorted(m for m in members if m != absent), f"counting table: {d['level']} members"
        assert all(d[k] == v for k, v in table["definition_fixed"].items()), "counting table: definition values"
        assert d["level"] in table["levels"]
        for m in d["members"]:
            assert set(m) <= set(table["member_entry"]), "counting table: member entry"
            assert {u["unit"] for u in m["units"]} <= set(UNITS), "counting table: member units"
            assert set(m.get("claims", {})) <= set(table["member_claims"]), "counting table: member claims"
    assert sorted(POLICY) == sorted(table["period_policy"]) and POLICY["suppression"] in table["suppression"]
    s = pack["strings"]
    for _, shown_as, _ in (PEER_CONFIRMED, ONE_SIDED, REDUNDANT, NOT_JOINABLE, PEER_UNTRUSTED):
        assert shown_as in s.values(), f"wording pack: {shown_as!r}"
    for c in all_cases:
        e = c["expected"]
        for x in e.get("shows", {}).get("exchanges", []):
            assert x["shown_as"] in s.values() and x["derived"] in LABELS, c["id"]
        if "history_properties" in e:
            ok = (e["exchange"]["accepted"]
                  and history_frame.accepted(e["history_properties"], table["may_be_not_checked"])
                  and "FAIL" not in e["coverage"]["properties"].values())
            assert e["accepted"] is ok, c["id"]
        if e.get("message_type") == "refusal" and c["id"] == "refused-detailed-other-requester":
            assert e["reason"] == "policy_declined", "HF §4.9: the instance's non-recipient refusal"


def build() -> dict[str, bytes]:
    all_cases = cases()
    ids = [c["id"] for c in all_cases]
    assert len(ids) == len(set(ids)), "duplicate case id"
    check_frame(all_cases)
    corpus = {
        "set": SET,
        "status": STATUS,
        "profile": PROFILE,
        "history_profile": HISTORY_PROFILE,
        "spec": SPEC,
        "example_definitions": [STANDARD, DETAILED],
        "test_keys": {
            "note": "TEST-ONLY. Each private key is the 32-byte Ed25519 seed SHA-256(seed_label).",
            "keys": {name: {"seed_label": SEED_LABELS[name], "public": PUB[name]} for name in SEED_LABELS},
        },
        "contract": {"document": CONTRACT, "document_jcs": jcs(CONTRACT), "contract_ref": CONTRACT_REF,
                     "contract_digest": CONTRACT_DIGEST, "schema": EC_SCHEMA},
        "period_policy": {"document": POLICY, "digest": POLICY_DIGEST},
        "units": UNITS,
        "labels": LABELS,
        "standard_properties": STANDARD_PROPS,
        "detailed_properties": DETAILED_PROPS,
        "refusal_properties": REFUSAL_PROPS,
        "count": len(all_cases),
        "cases": all_cases,
    }
    files = {"vectors.json": _dump(corpus)}
    files["manifest.json"] = _dump({
        "set": SET,
        "status": STATUS,
        "spec": SPEC,
        "generator": "python/scripts/generate_inference_service_history_v0_vectors.py",
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
    parser.add_argument("--profile", type=int, choices=(0, 1), default=0,
                        help="the interop profile identifier: 0 (the frozen set) or 1")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    use_profile(args.profile)
    write(args.out or DEFAULT_OUT)


if __name__ == "__main__":
    main()
