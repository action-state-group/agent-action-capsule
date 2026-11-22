#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate the Evidence Bundle ``composed/v1`` History member vectors.

The History member and the ``same_key`` join basis are defined by
``draft-mih-zhang-agent-disclosure-bundle-03``: "History Members" (the
``history`` body, its digest, its five checks and its join view), "Joins"
(``same_key``, ``controller_binding`` with a History member, History times,
Histories under two keys) and "Observers and Redundancy".

Every expected result below is written by hand from the draft text. The
script builds the literal objects with the composed generator's records, keys
and block helpers: each party's History answer is an evidence-interop
envelope whose artifact is an illustrative History card (its counts are not
this document's subject and nothing here reads them), signed by the party's
key, and its anchor is a CLL COSE checkpoint of the party's own log, signed by
the same key. Nothing here imports or runs an implementation of the join.

The reference composition: responder-a and responder-b each answered with an
Evidence Bundle of their half of one exchange, joined on the exchange
identifier (``pre_agreed_identifier``), and each party's History answer
(``history-a``, ``history-b``) joins its own party's half on ``same_key``.

Cases:

* ``history-two-parties``: the reference composition; every join derives
  ``agree``. The two same_key agreements are redundant (``same_key``) though
  every observer is in its own custody domain; the halves corroborate.
* ``history-anchored-before-exchange``: history-b's anchor is before
  responder-b's root record. The tie is the key alone: still ``agree``, and the
  History times report ``before``.
* ``history-key-mismatch-declared-agree``: history-a joined to responder-b's
  half on ``same_key`` and declared ``agree``: the keys differ, the verifier
  derives ``unjoined`` and reports both keys. A failed check.
* ``history-key-mismatch-unjoined``: the same join declared ``unjoined``.
* ``history-record-names-key-not-signed``: responder-b's root record states
  responder-a's key in ``key_id`` but was signed by responder-b's key. Its
  producer signature does not verify under the key it names, so it gives no
  key: ``not_derivable``.
* ``history-record-unsigned``: responder-a's root record carries no
  signature: ``not_derivable``.
* ``history-member-missing``: history-a declared missing: closure
  ``withheld``, its join ``not_derivable``; the composed digest equals
  ``history-two-parties``.
* ``history-anchor-checkpoint-mismatch``: history-a carries another
  checkpoint than the one its envelope names: a failed member, no join view.
* ``history-envelope-signature-invalid``: history-a's envelope signed by
  another key than its responder: a failed member.
* ``history-artifact-anchor-mismatch``: history-a's card states another
  anchor than its envelope: a failed member.
* ``history-profile-not-implemented``: history-a's envelope names a profile
  this revision does not read: signature-unverified, ``withheld``, its join
  ``not_derivable``.
* ``history-artifact-digest-mismatch``, ``history-request-digest-mismatch``,
  ``history-anchor-checkpoint-invalid`` (its signature does not verify),
  ``history-anchor-checkpoint-unprotected-header`` (not the one form),
  ``history-artifact-not-jcs``: each a failed member with no join view.
* ``history-profile-not-a-string``: signature-unverified, ``withheld``.
* ``history-envelope-digest-mismatch``: every check passes but the envelope is
  not the declared member digest: closure fails, no join view.
* ``history-empty-history-half-other-key``: same_key against an empty-history
  Bundle under another key: ``unjoined`` with both keys.
* ``history-member-listed-missing-carries-body``: closure fails; joins derive.
* ``history-refused-half``: responder-a refused; history-a's same_key join
  with that refusal is ``one_sided``.
* ``history-empty-history-half``: responder-a answered with an empty-history
  Bundle whose checkpoint responder-a's key signed: same_key ``one_sided``.
* ``history-pre-agreed-identifier-not-derivable``: a pre_agreed_identifier
  join naming a History member: ``not_derivable``.
* ``history-histories-controller-binding``: history-a and history-b joined by
  ``controller_binding`` over the two keys, in effect at both anchor times:
  ``agree``, redundant (``controller_binding``).
* ``history-compare-mismatch``: a ``controller_binding`` join of history-a
  and responder-b carrying ``compare``: linked, and the compare pointer does
  not resolve in the History: ``mismatch``.

Malformed blocks (the verifier reports no composition result):
``history-malformed-subject``, ``history-malformed-with-response``,
``history-malformed-with-bundle``, ``history-malformed-noncanonical-base64url``,
``history-malformed-same-key-pointer``.

Output: ``vectors/bundle/composed-history/`` (or ``--out DIR``). ``README.md``
is hand-written; when present in the output directory it is included in
``SHA256SUMS`` but never rewritten. The run is deterministic.
"""
from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import generate_bundle_composed_cb_vectors as cbv  # noqa: E402
import generate_bundle_composed_vectors as composed  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "vectors" / "bundle" / "composed-history"
DRAFT = "draft-mih-zhang-agent-disclosure-bundle-03 (History Members; Joins)"

S_HISTORY = "composed/v1: History Members"
S_JOINS = "composed/v1: Joins"
S_OBSERVERS = "composed/v1: Observers and Redundancy"
S_BLOCK = "composed/v1: Block"
S_CLOSURE = "composed/v1: Composition Closure"
S_BINDING = "composed/v1: Controller Binding Records"

A, B = composed.RESPONDER_A, composed.RESPONDER_B
OTHER = composed.RUNTIME
PROFILE = "evidence-interop/0"
DERIVATION = "standard_history/4"
# The halves' root records are at t(10) (responder-a) and t(11) (responder-b).
AFTER = composed.t(20)
BEFORE = composed.t(5)

HALVES = ("responder-a", "responder-b")


def history_checkpoint(key: composed.Key, name: str, timestamp: str, leaves: int = 3) -> bytes:
    """A CLL COSE checkpoint of ``name``'s own log, signed by ``key``."""
    store = composed.MemoryNodeStore()
    for i in range(leaves):
        composed.add_leaf(store, composed.leaf_hash(composed.hashlib.sha256(f"{name} entry {i}".encode()).digest()))
    size = store.size()
    peak_hashes = [store.node(p) for p in composed.peaks(size)]
    signer = composed._StatementSigner(key)
    cp = composed.CheckpointRecord(v=1, kind="mmr_checkpoint", signature="", log_id=f"log:composed-history/{name}",
                                   mmr_size=size, root=composed.root_from_peaks(peak_hashes).hex(), prev_size=0,
                                   prev_root="", key_id=signer.key_id, timestamp=timestamp)
    return composed.checkpoint_to_cose(cp, signer, peak_hashes)


def history_request(member_id: str) -> dict:
    return {"subject": {"full_history": None}, "derivation": DERIVATION, "profile": PROFILE,
            "nonce": f"n-{member_id}"}


def history_member(member_id: str, observer: str, key: composed.Key, timestamp: str, *, signer: composed.Key | None = None,
                   profile: Any = PROFILE, card_anchor: str | None = None, checkpoint: bytes | None = None,
                   subject: dict | None = None, anchor_octets=None, artifact_text=None,
                   artifact_digest: str | None = None, envelope_request_digest: str | None = None,
                   member_digest: str | None = None) -> dict:
    """A History member: ``key``'s envelope over an illustrative card, as of
    its own log's checkpoint at ``timestamp``. ``anchor_octets`` turns the
    checkpoint's octets into the anchor's (the anchor digest follows them);
    ``checkpoint`` carries other octets than the anchor names; the remaining
    keywords set one envelope or member value to a wrong one."""
    anchor_cp = history_checkpoint(key, member_id, timestamp)
    if anchor_octets is not None:
        anchor_cp = anchor_octets(anchor_cp)
    anchor = composed.sha256_hex(anchor_cp)
    card = {"anchor": card_anchor or anchor, "derivation": DERIVATION, "since": "2026-09",
            "in_window": {"counted": 1, "not_counted": 0, "of": 1}}
    artifact = composed.jcs(card) if artifact_text is None else artifact_text(card)
    request_digest = composed.sha256_hex(composed.jcs(history_request(member_id)))
    signed = {"profile": profile, "request_digest": envelope_request_digest or request_digest,
              "subject": subject if subject is not None else {"full_history": None}, "derivation": DERIVATION,
              "anchor": {"digest": anchor}, "artifact_digest": artifact_digest or composed.sha256_hex(artifact),
              "responder": key.public_hex, "issued_at": composed.t(40)}
    envelope = dict(signed, sig=(signer or key).private.sign(composed.jcs(signed)).hex(),
                    artifact=composed._b64u(artifact))
    return {"id": member_id, "observer": observer, "request_digest": request_digest, "outcome": "artifact",
            "digest": member_digest or composed.sha256_hex(composed.jcs(envelope)),
            "history": {"envelope": envelope, "anchor_checkpoint": composed._b64u(checkpoint or anchor_cp)}}


def history_observer(member_id: str) -> dict:
    return {"id": f"obs-{member_id}", "role": "responder", "custody_domain": f"custody-{member_id}.example"}


def same_key(a: str, b: str, state: str) -> dict:
    return {"members": sorted([a, b]), "basis": "same_key", "state": state}


def exchange_join(state: str = "agree") -> dict:
    return composed.join("responder-a", "responder-b", state)


def parties(*, b_time: str = AFTER, a_kwargs: dict | None = None) -> tuple[list[dict], list[dict]]:
    """The two halves and both Histories, each anchored at ``AFTER`` unless
    told otherwise."""
    members, observers = composed.two_responders()
    members += [history_member("history-a", "obs-history-a", A, AFTER, **(a_kwargs or {})),
                history_member("history-b", "obs-history-b", B, b_time)]
    observers += [history_observer("history-a"), history_observer("history-b")]
    return members, observers


def reference_joins() -> list[dict]:
    return [exchange_join(), same_key("history-a", "responder-a", "agree"),
            same_key("history-b", "responder-b", "agree")]


# --- expected results ------------------------------------------------------

HALF = {"outcome": "artifact", "body": "carried", "digest": "reproduced", "claims": composed.MEMBER_CLAIMS_DEPTH0}
CORROBORATING = {"result": "corroborating", "qualifier": "custody_declared"}
REDUNDANT_SAME_KEY = {"result": "redundant", "reason": "same_key", "report": "redundant, not corroborating"}
NOT_APPLICABLE = {"result": "not_applicable"}


def history_expect(key: composed.Key | None, time: str | None, **checks: str) -> dict:
    """A carried History member's expected report. ``key`` and ``time`` are
    its join view, ``None`` when it has none."""
    state = {"envelope_signature": "verified", "artifact_digest": "matches", "request_digest": "matches",
             "artifact_anchor": "matches", "anchor_checkpoint": "verified"}
    state.update(checks)
    return {"outcome": "artifact", "body": "carried", "digest": "reproduced", "claims": None,
            "history_member": {"derivation": DERIVATION, **state, "key": key.public_hex if key else None,
                               "time": time}}


def times(history: str, history_time: str, record: str, record_time: str, relation: str) -> dict:
    return {"history": history, "history_time": history_time, "record": record, "record_time": record_time,
            "relation": relation}


def join_expect(members: list[str], declared: str, derived: str | None, *, keys: list | None = None,
                history_times: dict | None = None) -> dict:
    result = "not_derivable" if derived is None else "derived_matches" if derived == declared else "join_state_mismatch"
    out = {"members": members, "declared": declared, "derived": derived, "result": result}
    if keys:
        out["keys"] = keys
    if history_times:
        out["history_times"] = history_times
    return out


def corroboration(members: list[str], value: dict) -> dict:
    return {"members": members, **value}


#: Where each member's key comes from in the reference composition (-03
#: "Joins"): the Histories' join views and the halves' signed root records.
SOURCES = {"history-a": "history", "history-b": "history", "responder-a": "record_signature",
           "responder-b": "record_signature"}


def with_key_sources(joins: list[dict], joins_expect: list[dict], sources: dict) -> list[dict]:
    """Add ``key_sources`` to every expected controller_binding and same_key
    join, in its member order, from ``sources`` (member id to source)."""
    keyed = {tuple(j["members"]) for j in joins if j["basis"] in ("same_key", "controller_binding")}
    for e in joins_expect:
        if tuple(e["members"]) in keyed:
            e["key_sources"] = [{"member": m, "source": sources[m]} for m in e["members"]]
    return joins_expect


def make_case(case_id: str, description: str, members: list[dict], observers: list[dict], joins: list[dict], *,
              status: str, members_expect: dict, joins_expect: list[dict], corroboration_expect: list[dict],
              section: list[str], missing: list[str] | None = None, bindings: list[dict] | None = None,
              sources: dict | None = None) -> dict:
    joins_expect = with_key_sources(joins, copy.deepcopy(joins_expect), {**SOURCES, **(sources or {})})
    for m in members:
        if m["id"] in (missing or []):
            # A declared-missing member carries no body (Composition Closure).
            m.pop("history", None)
    comp = composed.block(members, observers, joins, missing=missing)
    digest, preimage = composed.composed_digest(comp)
    closure = {"status": "pass", "missing": []}
    if missing:
        closure = {"status": "withheld", "finding": "declared_incomplete", "missing": sorted(missing)}
    return {
        "id": case_id,
        "section": section,
        "description": description,
        "container": composed.container(comp),
        "controller_bindings": bindings or [],
        "binding_revocations": [],
        "expect": {
            "composed_digest": digest,
            "canonical_preimage": preimage,
            "status": status,
            "members": members_expect,
            "composition_closure": closure,
            "joins": joins_expect,
            "corroboration": corroboration_expect,
        },
    }


def malformed_case(case_id: str, description: str, members: list[dict], observers: list[dict],
                   joins: list[dict]) -> dict:
    comp = composed.block(members, observers, [])
    comp["joins"] = joins
    digest_source = dict(comp, joins=[])
    comp["composed_digest"] = composed.composed_digest(digest_source)[0]
    return {
        "id": case_id,
        "section": [S_BLOCK, S_HISTORY],
        "description": description,
        "container": composed.container(comp),
        "controller_bindings": [],
        "binding_revocations": [],
        "expect": {"status": "fail", "malformed": True},
    }


def reference_members_expect(b_time: str = AFTER) -> dict:
    return {"responder-a": HALF, "responder-b": HALF, "history-a": history_expect(A, AFTER),
            "history-b": history_expect(B, b_time)}


def reference_joins_expect(b_time: str = AFTER, b_relation: str = "after") -> list[dict]:
    return [
        join_expect(["history-a", "responder-a"], "agree", "agree",
                    history_times=times("history-a", AFTER, "responder-a", composed.t(10), "after")),
        join_expect(["history-b", "responder-b"], "agree", "agree",
                    history_times=times("history-b", b_time, "responder-b", composed.t(11), b_relation)),
        join_expect(list(HALVES), "agree", "agree"),
    ]


REFERENCE_CORROBORATION = [
    corroboration(["history-a", "responder-a"], REDUNDANT_SAME_KEY),
    corroboration(["history-b", "responder-b"], REDUNDANT_SAME_KEY),
    corroboration(list(HALVES), CORROBORATING),
]
SECTIONS = [S_HISTORY, S_JOINS, S_OBSERVERS]


def _ordered(joins_expect: list[dict], joins: list[dict]) -> list[dict]:
    """Expected joins in the block's carried order."""
    by = {tuple(e["members"]): e for e in joins_expect}
    return [by[tuple(j["members"])] for j in joins]


def _ordered_corroboration(values: list[dict], joins: list[dict]) -> list[dict]:
    by = {tuple(e["members"]): e for e in values}
    return [by[tuple(j["members"])] for j in joins]


def case_two_parties() -> dict:
    members, observers = parties()
    joins = reference_joins()
    return make_case(
        "history-two-parties",
        "Two parties' halves of one exchange joined on the exchange identifier, and each party's History answer "
        "joined to its own party's half on same_key. Each History's envelope verifies under its responder, its "
        "artifact and request digests match, its card states the anchor its envelope names, and its anchor "
        "checkpoint is that checkpoint and verifies. Each History's key is the key under which its party's root "
        "record's producer signature verifies: agree. Every observer is in its own custody domain, yet each "
        "same_key agreement is redundant: one key answered and signed for both members. The halves corroborate "
        "on declared custody. Each History's time is after its party's root record, reported as a fact.",
        members, observers, joins, status="pass", members_expect=reference_members_expect(),
        joins_expect=_ordered(reference_joins_expect(), joins),
        corroboration_expect=_ordered_corroboration(REFERENCE_CORROBORATION, joins), section=SECTIONS)


def case_anchored_before() -> dict:
    members, observers = parties(b_time=BEFORE)
    joins = reference_joins()
    return make_case(
        "history-anchored-before-exchange",
        "The reference composition with history-b anchored before responder-b's root record: the History "
        "responder-b could show when it agreed. The tie is the key alone, so the join still derives agree; the "
        "verifier reports history-b's time as before the record's, as a fact with no join state.",
        members, observers, joins, status="pass", members_expect=reference_members_expect(BEFORE),
        joins_expect=_ordered(reference_joins_expect(BEFORE, "before"), joins),
        corroboration_expect=_ordered_corroboration(REFERENCE_CORROBORATION, joins), section=SECTIONS)


def _mismatch_case(case_id: str, declared: str, status: str, description: str) -> dict:
    members, observers = parties()
    joins = [exchange_join(), same_key("history-a", "responder-b", declared),
             same_key("history-b", "responder-b", "agree")]
    joins_expect = [
        join_expect(list(HALVES), "agree", "agree"),
        join_expect(["history-a", "responder-b"], declared, "unjoined",
                    keys=[{"member": "history-a", "key": A.public_hex}, {"member": "responder-b", "key": B.public_hex}],
                    history_times=times("history-a", AFTER, "responder-b", composed.t(11), "after")),
        join_expect(["history-b", "responder-b"], "agree", "agree",
                    history_times=times("history-b", AFTER, "responder-b", composed.t(11), "after")),
    ]
    corro = [corroboration(list(HALVES), CORROBORATING),
             corroboration(["history-a", "responder-b"], NOT_APPLICABLE),
             corroboration(["history-b", "responder-b"], REDUNDANT_SAME_KEY)]
    return make_case(case_id, description, members, observers, joins, status=status,
                     members_expect=reference_members_expect(), joins_expect=_ordered(joins_expect, joins),
                     corroboration_expect=_ordered_corroboration(corro, joins), section=SECTIONS)


def _unsigned_half_case(case_id: str, description: str, record_edit) -> dict:
    members, observers = parties()
    target = 1 if case_id == "history-record-names-key-not-signed" else 0
    half = members[target]
    record = half["bundle"]["records"][0]
    record_edit(record)
    half["digest"] = composed.bundle_digest(half["bundle"])
    history_id = "history-a"
    half_id = HALVES[target]
    joins = [exchange_join(), same_key(history_id, half_id, "agree")]
    joins_expect = [join_expect(list(HALVES), "agree", "agree"),
                    join_expect(sorted([history_id, half_id]), "agree", None,
                                history_times=times(history_id, AFTER, half_id, composed.t(10 + target), "after"))]
    # Both halves' root records now state responder-a's key_id: the halves'
    # agreement is redundant on that stated key, as before this revision.
    halves = (CORROBORATING if target == 0 else
              {"result": "redundant", "reason": "same_key_id", "report": "redundant, not corroborating"})
    corro = [corroboration(list(HALVES), halves), corroboration(sorted([history_id, half_id]), NOT_APPLICABLE)]
    expect = reference_members_expect()
    return make_case(case_id, description, members, observers, joins, status="withheld", members_expect=expect,
                     joins_expect=_ordered(joins_expect, joins),
                     corroboration_expect=_ordered_corroboration(corro, joins), section=SECTIONS,
                     sources={half_id: "none"})


def case_missing() -> dict:
    members, observers = parties()
    joins = reference_joins()
    expect = reference_members_expect()
    expect["history-a"] = {"outcome": "artifact", "body": "declared_missing", "digest": "not_shown", "claims": None}
    joins_expect = reference_joins_expect()
    joins_expect[0] = join_expect(["history-a", "responder-a"], "agree", None)
    corro = copy.deepcopy(REFERENCE_CORROBORATION)
    corro[0] = corroboration(["history-a", "responder-a"], NOT_APPLICABLE)
    case = make_case(
        "history-member-missing",
        "The reference composition with history-a declared missing: its body is withheld, its id, observer, "
        "request digest, outcome and digest stay in the composed digest, which equals history-two-parties. "
        "Composition closure is withheld, and the join naming history-a is not_derivable.",
        members, observers, joins, status="withheld", members_expect=expect,
        joins_expect=_ordered(joins_expect, joins), corroboration_expect=_ordered_corroboration(corro, joins),
        section=SECTIONS + [S_CLOSURE], missing=["history-a"], sources={"history-a": "none"})
    case["expect"]["composed_digest_equals_case"] = "history-two-parties"
    return case


def _failed_history_case(case_id: str, description: str, a_kwargs: dict, checks: dict, status: str = "fail",
                         digest: str = "reproduced") -> dict:
    members, observers = parties(a_kwargs=a_kwargs)
    joins = reference_joins()
    expect = reference_members_expect()
    expect["history-a"] = history_expect(None, None, **checks)
    expect["history-a"]["digest"] = digest
    joins_expect = reference_joins_expect()
    joins_expect[0] = join_expect(["history-a", "responder-a"], "agree", None)
    corro = copy.deepcopy(REFERENCE_CORROBORATION)
    corro[0] = corroboration(["history-a", "responder-a"], NOT_APPLICABLE)
    return make_case(case_id, description, members, observers, joins, status=status, members_expect=expect,
                     joins_expect=_ordered(joins_expect, joins),
                     corroboration_expect=_ordered_corroboration(corro, joins), section=SECTIONS,
                     sources={"history-a": "none"})


def bad_signature(cose: bytes) -> bytes:
    """The checkpoint with the last octet of its signature changed."""
    return cose[:-1] + bytes([cose[-1] ^ 1])


def unprotected_header(cose: bytes) -> bytes:
    """The checkpoint with one unprotected header entry: the signature does
    not cover the unprotected header, so it still verifies."""
    tagged = composed_cbor2().loads(cose)
    protected, _, payload, signature = tagged.value
    return composed_cbor2().dumps(composed_cbor2().CBORTag(18, [protected, {"x-note": "added"}, payload, signature]))


def composed_cbor2():
    import cbor2

    return cbor2


def case_envelope_digest_mismatch() -> dict:
    members, observers = parties(a_kwargs={"member_digest": "3" * 64})
    joins = reference_joins()
    expect = reference_members_expect()
    expect["history-a"] = history_expect(None, None)
    expect["history-a"]["digest"] = "mismatch"
    joins_expect = reference_joins_expect()
    joins_expect[0] = join_expect(["history-a", "responder-a"], "agree", None)
    corro = copy.deepcopy(REFERENCE_CORROBORATION)
    corro[0] = corroboration(["history-a", "responder-a"], NOT_APPLICABLE)
    case = make_case(
        "history-envelope-digest-mismatch",
        "history-a's envelope passes all five checks, but its digest is not the member digest the block declares. "
        "It is not the History the composed digest names: composition closure fails and it has no join view.",
        members, observers, joins, status="fail", members_expect=expect,
        joins_expect=_ordered(joins_expect, joins), corroboration_expect=_ordered_corroboration(corro, joins),
        section=SECTIONS + [S_CLOSURE], sources={"history-a": "none"})
    case["expect"]["composition_closure"] = {"status": "fail", "missing": []}
    return case


def case_empty_half_other_key() -> dict:
    members, observers = parties()
    bundle = cbv.empty_history_bundle(A)
    members[0] = dict(members[0], digest=composed.bundle_digest(bundle), bundle=bundle)
    joins = [same_key("history-b", "responder-a", "unjoined")]
    empty = {"outcome": "artifact", "body": "carried", "digest": "reproduced", "claims": composed.MEMBER_CLAIMS_DEPTH0,
             "history": {"state": "none", "since": cbv.EMPTY_CHECKPOINT_TIME}}
    expect = {"responder-a": empty, "responder-b": HALF, "history-a": history_expect(A, AFTER),
              "history-b": history_expect(B, AFTER)}
    return make_case(
        "history-empty-history-half-other-key",
        "history-b joined on same_key to responder-a's empty-history Bundle, whose checkpoint responder-a's key "
        "signed. The keys differ: unjoined, as declared, and the verifier reports both keys.",
        members, observers, joins, status="pass", members_expect=expect,
        joins_expect=[join_expect(["history-b", "responder-a"], "unjoined", "unjoined",
                                  keys=[{"member": "history-b", "key": B.public_hex},
                                        {"member": "responder-a", "key": A.public_hex}])],
        corroboration_expect=[corroboration(["history-b", "responder-a"], NOT_APPLICABLE)], section=SECTIONS,
        sources={"responder-a": "log_checkpoint"})


def case_missing_carries_body() -> dict:
    members, observers = parties()
    joins = reference_joins()
    comp = composed.block(members, observers, joins)
    comp["missing"] = ["history-a"]
    digest, preimage = composed.composed_digest(comp)
    expect = reference_members_expect()
    return {
        "id": "history-member-listed-missing-carries-body",
        "section": SECTIONS + [S_CLOSURE],
        "description": "history-a is listed in missing but still carries its body: composition closure fails. A "
                       "join naming it still derives from the carried body.",
        "container": composed.container(comp),
        "controller_bindings": [],
        "binding_revocations": [],
        "expect": {
            "composed_digest": digest,
            "canonical_preimage": preimage,
            "status": "fail",
            "members": expect,
            "composition_closure": {"status": "fail", "missing": ["history-a"]},
            "joins": with_key_sources(joins, _ordered(reference_joins_expect(), joins), SOURCES),
            "corroboration": _ordered_corroboration(REFERENCE_CORROBORATION, joins),
        },
    }


def case_refused_half() -> dict:
    members, observers = parties()
    request_digest = members[0]["request_digest"]
    refusal = {"request_digest": request_digest, "reason": "policy_declined", "issued_at": composed.t(9)}
    members[0] = {"id": "responder-a", "observer": "obs-a", "request_digest": request_digest, "outcome": "refusal",
                  "digest": composed.sha256_hex(composed.jcs(refusal)), "refusal": refusal}
    joins = [same_key("history-a", "responder-a", "one_sided")]
    expect = {"responder-a": {"outcome": "refusal", "body": "carried", "digest": "reproduced", "claims": None},
              "responder-b": HALF, "history-a": history_expect(A, AFTER), "history-b": history_expect(B, AFTER)}
    return make_case(
        "history-refused-half",
        "responder-a refused its half (a signed refusal, signature-unverified with no deployment profile). "
        "history-a's same_key join with that refusal: one member is an artifact with records, the other is not "
        "an artifact, so the join is one_sided, as declared. The refusal's signature is unverified, so the block "
        "is withheld.",
        members, observers, joins, status="withheld", members_expect=expect,
        joins_expect=[join_expect(["history-a", "responder-a"], "one_sided", "one_sided")],
        corroboration_expect=[corroboration(["history-a", "responder-a"], NOT_APPLICABLE)], section=SECTIONS,
        sources={"responder-a": "none"})


def case_empty_half() -> dict:
    members, observers = parties()
    bundle = cbv.empty_history_bundle(A)
    members[0] = dict(members[0], digest=composed.bundle_digest(bundle), bundle=bundle)
    joins = [same_key("history-a", "responder-a", "one_sided")]
    empty = {"outcome": "artifact", "body": "carried", "digest": "reproduced", "claims": composed.MEMBER_CLAIMS_DEPTH0,
             "history": {"state": "none", "since": cbv.EMPTY_CHECKPOINT_TIME}}
    expect = {"responder-a": empty, "responder-b": HALF, "history-a": history_expect(A, AFTER),
              "history-b": history_expect(B, AFTER)}
    return make_case(
        "history-empty-history-half",
        "responder-a answered with an empty-history Bundle whose stream's first checkpoint responder-a's key "
        "signed. Under same_key its key is that checkpoint's signer, the same key as history-a's responder: "
        "linked, and only one member has records, so one_sided, as declared. No root record, so no History times.",
        members, observers, joins, status="pass", members_expect=expect,
        joins_expect=[join_expect(["history-a", "responder-a"], "one_sided", "one_sided")],
        corroboration_expect=[corroboration(["history-a", "responder-a"], NOT_APPLICABLE)], section=SECTIONS,
        sources={"responder-a": "log_checkpoint"})


def case_pre_agreed_not_derivable() -> dict:
    members, observers = parties()
    bad = composed.join("history-a", "responder-a", "agree")
    joins = [exchange_join(), bad]
    joins_expect = [join_expect(list(HALVES), "agree", "agree"),
                    join_expect(["history-a", "responder-a"], "agree", None,
                                history_times=times("history-a", AFTER, "responder-a", composed.t(10), "after"))]
    corro = [corroboration(list(HALVES), CORROBORATING), corroboration(["history-a", "responder-a"], NOT_APPLICABLE)]
    return make_case(
        "history-pre-agreed-identifier-not-derivable",
        "A pre_agreed_identifier join between history-a and responder-a. A History has no root record, and this "
        "revision defines no derivation for a History member on that basis: not_derivable, not malformed.",
        members, observers, joins, status="withheld", members_expect=reference_members_expect(),
        joins_expect=_ordered(joins_expect, joins), corroboration_expect=_ordered_corroboration(corro, joins),
        section=SECTIONS)


def _cb_join(a: str, b: str, record: dict, state: str, *, pointer: bool, compare: bool = False) -> dict:
    out = {"members": sorted([a, b]), "basis": "controller_binding", "identifier_digest": cbv.binding_digest(record),
           "state": state}
    if pointer:
        out["pointer"] = cbv.KEY_POINTER
    if compare:
        out["compare"] = [composed.COMPARE_POINTER]
    return out


def case_histories_controller_binding() -> dict:
    members, observers = parties()
    record = cbv.binding((A, B))
    joins = [_cb_join("history-a", "history-b", record, "agree", pointer=False)]
    return make_case(
        "history-histories-controller-binding",
        "history-a and history-b joined by controller_binding: one binding record over the two responder keys, "
        "both keys signed it, in effect at both anchor times. Each History's key and T are its join view; T only "
        "tests the binding's window. No pointer is needed between two Histories. Linked: agree, redundant "
        "(controller_binding).",
        members, observers, joins, status="pass", members_expect=reference_members_expect(),
        joins_expect=[join_expect(["history-a", "history-b"], "agree", "agree")],
        corroboration_expect=[corroboration(["history-a", "history-b"],
                                            {"result": "redundant", "reason": "controller_binding",
                                             "report": "redundant, not corroborating"})],
        section=SECTIONS + [S_BINDING], bindings=[record])


def case_compare_mismatch() -> dict:
    members, observers = parties()
    record = cbv.binding((A, B))
    joins = [_cb_join("history-a", "responder-b", record, "mismatch", pointer=True, compare=True)]
    return make_case(
        "history-compare-mismatch",
        "A controller_binding join of history-a and responder-b carrying compare. The binding applies to "
        "history-a's responder key at its anchor time and the key responder-b's root record names at its "
        "timestamp: linked. The compare pointer resolves in responder-b's root record and never in a History, "
        "so the join derives mismatch, as declared.",
        members, observers, joins, status="pass", members_expect=reference_members_expect(),
        joins_expect=[join_expect(["history-a", "responder-b"], "mismatch", "mismatch",
                                  history_times=times("history-a", AFTER, "responder-b", composed.t(11), "after"))],
        corroboration_expect=[corroboration(["history-a", "responder-b"], NOT_APPLICABLE)],
        section=SECTIONS + [S_BINDING], bindings=[record])


def malformed_cases() -> list[dict]:
    out = []
    members, observers = parties(a_kwargs={"subject": {"record": "0" * 64}})
    out.append(malformed_case("history-malformed-subject",
                              "history-a's envelope names a record subject, not full_history: the history body is "
                              "malformed, and so is the block.", members, observers, reference_joins()))
    members, observers = parties()
    env = members[2]["history"]["envelope"]
    members[2]["response"] = {k: v for k, v in env.items() if k != "artifact"}
    out.append(malformed_case("history-malformed-with-response",
                              "history-a carries a response beside its history body. The envelope is the History's "
                              "response and is digest-covered; a response member beside it is not: malformed.",
                              members, observers, reference_joins()))
    members, observers = parties()
    members[2]["bundle"] = members[0]["bundle"]
    out.append(malformed_case("history-malformed-with-bundle",
                              "history-a carries both a history and a bundle body: an artifact member carries at "
                              "most one. Malformed.", members, observers, reference_joins()))
    members, observers = parties()
    body = members[2]["history"]
    field = next(k for k, v in (("anchor_checkpoint", body["anchor_checkpoint"]),
                                ("artifact", body["envelope"]["artifact"])) if len(v) % 4 in (2, 3))
    holder = body if field == "anchor_checkpoint" else body["envelope"]
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    text = holder[field]
    # Set the lowest pad bit of the last character: the same octets, a second text.
    holder[field] = text[:-1] + alphabet[alphabet.index(text[-1]) | 1]
    out.append(malformed_case("history-malformed-noncanonical-base64url",
                              f"history-a's {field} is unpadded base64url whose pad bits are not zero: it decodes "
                              "to the same octets as the canonical text, so it is not the one form -03 allows. "
                              "Malformed.", members, observers, reference_joins()))
    members, observers = parties()
    joins = reference_joins()
    joins[1] = dict(joins[1], pointer=cbv.KEY_POINTER)
    out.append(malformed_case("history-malformed-same-key-pointer",
                              "A same_key join carrying pointer. same_key reads each member's own key and carries "
                              "none of pointer, identifier_digest and compare: malformed.", members, observers, joins))
    return out


def cases() -> list[dict]:
    other_cp = history_checkpoint(A, "history-a-other", AFTER, leaves=4)

    def names_a(record: dict) -> None:
        record["key_id"] = A.public_hex

    def unsigned(record: dict) -> None:
        record.pop("signature")

    return [
        case_two_parties(),
        case_anchored_before(),
        _mismatch_case("history-key-mismatch-declared-agree", "agree", "fail",
                       "history-a joined to responder-b's half on same_key and declared agree. history-a's key is "
                       "responder-a's; responder-b's root record verifies under responder-b's key. The keys differ: "
                       "the verifier derives unjoined and reports both keys. The declaration does not match the "
                       "derivation: a failed check."),
        _mismatch_case("history-key-mismatch-unjoined", "unjoined", "pass",
                       "The same join declared unjoined: the verifier derives unjoined and reports both keys."),
        _unsigned_half_case("history-record-names-key-not-signed",
                            "responder-b's root record states responder-a's key in key_id, but its producer signature "
                            "was made by responder-b's key. A same_key join reads a key only from a signature that "
                            "verifies under it, never from what the record states, so responder-b has no key: the "
                            "join with history-a is not_derivable, never agree.", names_a),
        _unsigned_half_case("history-record-unsigned",
                            "responder-a's root record carries no producer signature: it gives no key, and the "
                            "same_key join with history-a is not_derivable.", unsigned),
        case_missing(),
        _failed_history_case("history-anchor-checkpoint-mismatch",
                             "history-a carries a checkpoint other than the one its envelope's anchor.digest names. "
                             "The member fails; it has no join view, so its join is not_derivable.",
                             {"checkpoint": other_cp}, {"anchor_checkpoint": "mismatch"}),
        _failed_history_case("history-envelope-signature-invalid",
                             "history-a's envelope signature was made by another key than its responder: the "
                             "member fails, and its join is not_derivable.", {"signer": OTHER},
                             {"envelope_signature": "invalid"}),
        _failed_history_case("history-artifact-anchor-mismatch",
                             "history-a's card states another anchor than its envelope's anchor.digest: the member "
                             "fails, and its join is not_derivable.", {"card_anchor": "0" * 64},
                             {"artifact_anchor": "mismatch"}),
        _failed_history_case("history-profile-not-implemented",
                             "history-a's envelope names a profile whose member names and signature this revision "
                             "does not read: signature-unverified, neither failed nor absent. It has no join view, so "
                             "its join is not_derivable and the block is withheld.",
                             {"profile": "x-example-profile/0"}, {"envelope_signature": "signature_unverified"},
                             status="withheld"),
        _failed_history_case("history-artifact-digest-mismatch",
                             "history-a's envelope signs an artifact_digest that is not the SHA-256 of its artifact "
                             "octets: the member fails, and its join is not_derivable.",
                             {"artifact_digest": "1" * 64}, {"artifact_digest": "mismatch"}),
        _failed_history_case("history-request-digest-mismatch",
                             "history-a's envelope answers another request than the member's request_digest names: "
                             "the member fails, and its join is not_derivable.",
                             {"envelope_request_digest": "2" * 64}, {"request_digest": "mismatch"}),
        _failed_history_case("history-anchor-checkpoint-invalid",
                             "history-a's anchor checkpoint is the one its envelope names, but its signature does not "
                             "verify: the member fails, and its join is not_derivable.",
                             {"anchor_octets": bad_signature}, {"anchor_checkpoint": "invalid"}),
        _failed_history_case("history-anchor-checkpoint-unprotected-header",
                             "history-a's anchor checkpoint carries an entry in its unprotected header. Its signature "
                             "still verifies, but it is not the one form the interop profile fixes for a checkpoint "
                             "(tagged COSE_Sign1, an empty unprotected header): the member fails, and its join is "
                             "not_derivable.", {"anchor_octets": unprotected_header},
                             {"anchor_checkpoint": "invalid"}),
        _failed_history_case("history-artifact-not-jcs",
                             "history-a's artifact is the card with whitespace, not its JCS serialization: it does "
                             "not state its anchor in the one form a History artifact takes, so check 4 fails.",
                             {"artifact_text": lambda card: json.dumps(card, indent=1).encode()},
                             {"artifact_anchor": "mismatch"}),
        _failed_history_case("history-profile-not-a-string",
                             "history-a's envelope profile is an array, not a profile identifier: the verifier reads "
                             "no profile it implements, so the signature is unverified and the block is withheld.",
                             {"profile": []}, {"envelope_signature": "signature_unverified"}, status="withheld"),
        case_envelope_digest_mismatch(),
        case_empty_half_other_key(),
        case_missing_carries_body(),
        case_refused_half(),
        case_empty_half(),
        case_pre_agreed_not_derivable(),
        case_histories_controller_binding(),
        case_compare_mismatch(),
        *malformed_cases(),
    ]


def build() -> dict[str, bytes]:
    case_list = cases()
    files = {
        "vectors.json": composed._dump({
            "draft": DRAFT,
            "provenance": "spec-derived",
            "status": "draft -03 text; held for ratification with -03",
            "kind": composed.KIND,
            "inputs": "controller_bindings and binding_revocations are delivered beside the containing Bundle. Each "
                      "History card is illustrative: no verifier of these vectors reads its counts.",
            "keys": {k.name: {"seed_hex": k.seed.hex(), "public_key_hex": k.public_hex} for k in (A, B, OTHER)},
            "count": len(case_list),
            "cases": case_list,
        }),
    }
    files["manifest.json"] = composed._dump({
        "draft": DRAFT,
        "provenance": "spec-derived",
        "generator": "python/scripts/generate_bundle_composed_history_vectors.py",
        "files": [{"path": name, "sha256": composed.sha256_hex(data), "count": json.loads(data).get("count")}
                  for name, data in sorted(files.items())],
    })
    return files


def write(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for name, data in build().items():
        (out / name).write_bytes(data)
    lines = [f"{composed.sha256_hex(p.read_bytes())}  {p.name}"
             for p in sorted(out.iterdir()) if p.is_file() and p.name != "SHA256SUMS"]
    (out / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    write(parser.parse_args().out)


if __name__ == "__main__":
    main()
