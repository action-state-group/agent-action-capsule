#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate the ``composed/v1`` History member vectors.

The text is "History Members" in ``draft-mih-zhang-agent-disclosure-bundle-03``
(the ``composed/v1`` extension). A History answer is an ``artifact`` member
with ``form`` ``history``; a ``same_key`` join ties it to the member that
carries its party's half of a deal.

Every expected result below is written by hand from the draft text. The
script builds the literal objects (each party's half of one deal, each
party's History answer as an evidence-interop envelope over a
``standard_history/1`` card, each History's anchor checkpoint), computes the
digests the text defines, signs with fixed test-only seeds, and records the
literal JCS preimage of every composed digest. Nothing here imports or runs an
implementation of the extension.

The building blocks (keys, Capsules, member Bundles, the pre-agreed-identifier
join on the deal identifier, the container) are those of
``generate_bundle_composed_vectors.py``, imported from it.

Output: ``vectors/bundle/composed-history/`` (or ``--out DIR``). The run is a
pure function of this file and that one. ``README.md`` is hand-written; when
present in the output directory it is included in ``SHA256SUMS`` but never
rewritten.

Dependencies: as ``generate_bundle_composed_vectors.py`` (``cryptography``,
the CLL reference and ``scitt-cose`` for the anchor checkpoints).
"""
from __future__ import annotations

import argparse
import copy
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

from cll.checkpoint import (
    CheckpointRecord,
    MemoryNodeStore,
    add_leaf,
    checkpoint_to_cose,
    leaf_hash,
    peaks,
    root_from_peaks,
)


def _sibling(name: str) -> Any:
    """Load a generator beside this file as a module (scripts/ is not a package)."""
    spec = importlib.util.spec_from_file_location(name, Path(__file__).resolve().parent / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


base = _sibling("generate_bundle_composed_vectors")

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "vectors" / "bundle" / "composed-history"
DRAFT = "draft-mih-zhang-agent-disclosure-bundle-03 (composed/v1: History Members)"
PROFILE = "evidence-interop/0"
DERIVATION = "standard_history/1"

S_HISTORY = "composed/v1: History Members"
S_SHAPE = "composed/v1: Block"
S_DIGEST = "composed/v1: Composed Digest"
S_CLOSURE = "composed/v1: Composition Closure"
S_OBSERVERS = "composed/v1: Observers and Redundancy"
S_VERIFY = "composed/v1: Verifying composed/v1"

OTHER = base.Key("history other responder")
KEYS = [base.RESPONDER_A, base.RESPONDER_B, OTHER, base.COMPOSER]

# The options every case is run with: the evidence-interop envelope signature
# (Ed25519 by `responder` over the JCS of the signed members present).
WITH_PROFILE = {"history_signature": PROFILE}
_SIGNED = ("profile", "request_digest", "subject", "derivation", "anchor", "artifact_digest", "verification",
           "responder", "issued_at")


# ---------------------------------------------------------------------------
# A party's anchor checkpoint and its History answer
# ---------------------------------------------------------------------------


def anchor_checkpoint(records: list[dict], key: base.Key, log_id: str, timestamp: str) -> bytes:
    """The COSE checkpoint of a log holding ``records`` (seq 1..n), signed by
    ``key`` at ``timestamp``: a History's coverage anchor."""
    store = MemoryNodeStore()
    for record in records:
        add_leaf(store, leaf_hash(bytes.fromhex(record["capsule_id"])))
    size = store.size()
    peak_hashes = [store.node(p) for p in peaks(size)]
    signer = base._StatementSigner(key)
    cp = CheckpointRecord(v=1, kind="mmr_checkpoint", signature="", log_id=log_id, mmr_size=size,
                          root=root_from_peaks(peak_hashes).hex(), prev_size=0, prev_root="",
                          key_id=signer.key_id, timestamp=timestamp)
    return checkpoint_to_cose(cp, signer, peak_hashes)


def card(anchor_digest: str) -> dict:
    """A ``standard_history/1`` card counting one held deal (its own profile's
    rules are not checked by the composed verifier)."""
    return {
        "anchor": anchor_digest,
        "bands": [{"currency": "USD", "decade": 1, "did_not_hold": 0, "held": 1, "of": 1, "undecided": 0}],
        "class_missing": {"count": 1, "of": 1},
        "controller_class": "node_declared",
        "derivation": DERIVATION,
        "disputes": {
            "raised": {"by_forum": {"auto": 0, "external": 0, "network": 0, "of": 0, "rail": 0},
                       "by_outcome": {"against": 0, "for": 0, "no_finding": 0, "of": 0, "open": 0, "split": 0,
                                      "withdrawn": 0}, "of": 0},
            "received": {"by_forum": {"auto": 0, "external": 0, "network": 0, "of": 0, "rail": 0},
                         "by_outcome": {"against": 0, "for": 0, "no_finding": 0, "of": 0, "open": 0, "split": 0,
                                        "withdrawn": 0}, "of": 0},
        },
        "happened": {"no_record": 0, "of": 1, "receipt_only": 0, "stamped_by_both": 1},
        "holder_kind": "node",
        "in_window": {"counted": 1, "not_counted": 0, "of": 1},
        "outcomes": {"did_not_hold": 0, "held": 1, "of": 1, "undecided": 0},
        "policy": base.label_hex("history policy"),
        "roles": {"bought": 0, "of": 1, "provided": 1},
        "since": "2026-10",
        "window": {"all": True},
    }


def history_request(anchor_digest: str) -> dict:
    return {"profile": PROFILE, "subject": {"full_history": None}, "coverage": {"expected_pin": anchor_digest},
            "derivation": DERIVATION}


def envelope(request_digest: str, anchor_digest: str, signer: base.Key, *, issued_at: str) -> dict:
    """The responder's signed evidence-interop envelope over the card, as received."""
    artifact = base.jcs(card(anchor_digest))
    env = {
        "profile": PROFILE,
        "request_digest": request_digest,
        "subject": {"full_history": None},
        "derivation": DERIVATION,
        "anchor": {"digest": anchor_digest},
        "artifact_digest": base.sha256_hex(artifact),
        "responder": signer.public_hex,
        "issued_at": issued_at,
    }
    env["sig"] = signer.private.sign(base.jcs({k: env[k] for k in _SIGNED if k in env})).hex()
    env["artifact"] = base._b64u(artifact)
    return env


def history_member(member_id: str, observer: str, signer: base.Key, anchor_records: list[dict], *,
                   anchor_time: str, carry_anchor: bool = True, corrupt_anchor: bool = False) -> dict:
    """With ``corrupt_anchor``, the checkpoint's last signature octet is
    flipped before the envelope signs its digest: it matches the signed
    anchor digest and does not verify."""
    log_id = f"log:composed-history-vectors/{member_id}"
    cose = anchor_checkpoint(anchor_records, signer, log_id, anchor_time)
    if corrupt_anchor:
        cose = cose[:-1] + bytes([cose[-1] ^ 1])
    anchor_digest = base.sha256_hex(cose)
    request_digest = base.sha256_hex(base.jcs(history_request(anchor_digest)))
    env = envelope(request_digest, anchor_digest, signer, issued_at=base.t(40))
    out = {"id": member_id, "observer": observer, "form": "history", "request_digest": request_digest,
           "outcome": "artifact", "digest": base.sha256_hex(base.jcs(env)), "history": env}
    if carry_anchor:
        out["anchor_checkpoint"] = base._b64u(cose)
    return out


def same_key(half: str, history: str, state: str) -> dict:
    return {"members": sorted([half, history]), "basis": "same_key", "state": state}


# ---------------------------------------------------------------------------
# The staple: two parties' halves of one deal and each party's History
# ---------------------------------------------------------------------------

OBSERVERS = [
    {"id": "obs-a", "role": "responder", "custody_domain": "custody-a.example"},
    {"id": "obs-b", "role": "responder", "custody_domain": "custody-b.example"},
]


def halves() -> tuple[dict, dict]:
    """Each party's half of the deal, both carrying the deal identifier at the
    composed vectors' exchange pointer: party A at minute 10, party B at 11."""
    rec_a = base.observation("responder-a", "responder-a.example", base.RESPONDER_A, 10,
                             transcript="shared transcript")
    rec_b = base.observation("responder-b", "responder-b.example", base.RESPONDER_B, 11,
                             transcript="shared transcript")
    return rec_a, rec_b


def staple(*, a_signer: base.Key = base.RESPONDER_A, a_anchor_time: str | None = None,
           a_anchor_records: list[dict] | None = None, a_carry_anchor: bool = True,
           a_corrupt_anchor: bool = False, deal_id_b: str | None = None) -> tuple[list[dict], dict, dict]:
    """Members half-a, half-b, history-a, history-b. History A's anchor is A's
    log after its half (minute 20) unless told otherwise; History B's is B's."""
    rec_a, rec_b = halves()
    if deal_id_b is not None:
        body = {k: v for k, v in rec_b.items() if k not in ("capsule_id", "key_id", "signature")}
        body["model_attestation"]["compute_attestation"][base.EXCHANGE_MEMBER]["exchange_id"] = deal_id_b
        rec_b = base.seal(body, base.RESPONDER_B)
    half_a = base.artifact_member("half-a", "obs-a", rec_a)
    half_b = base.artifact_member("half-b", "obs-b", rec_b)
    history_a = history_member("history-a", "obs-a", a_signer,
                               a_anchor_records if a_anchor_records is not None else [rec_a],
                               anchor_time=a_anchor_time or base.t(20), carry_anchor=a_carry_anchor,
                               corrupt_anchor=a_corrupt_anchor)
    history_b = history_member("history-b", "obs-b", base.RESPONDER_B, [rec_b], anchor_time=base.t(21))
    return [half_a, half_b, history_a, history_b], rec_a, rec_b


def staple_joins(deal_state: str = "agree", a_state: str = "agree", b_state: str = "agree") -> list[dict]:
    return [base.join("half-a", "half-b", deal_state), same_key("half-a", "history-a", a_state),
            same_key("half-b", "history-b", b_state)]


def block(members: list[dict], joins: list[dict], missing: list[str] | None = None,
          keep_bodies: bool = False) -> dict:
    out: dict[str, Any] = {"members": members, "observers": copy.deepcopy(OBSERVERS), "joins": joins}
    if missing:
        out["missing"] = sorted(missing)
        for m in out["members"]:
            if m["id"] in missing and not keep_bodies:
                for body in ("bundle", "history"):
                    m.pop(body, None)
    out["composed_digest"] = digest(out)[0]
    return out


_MEMBER_FIELDS = ("id", "observer", "request_digest", "outcome", "digest", "form")


def digest(block_: dict) -> tuple[str, str]:
    """Composed Digest: as -02, with each member's ``form`` when it has one."""
    value = base.digest_input(block_)
    value["members"] = sorted(({k: m[k] for k in _MEMBER_FIELDS if k in m} for m in block_["members"]),
                              key=lambda m: m["id"])
    preimage = base.jcs(value)
    return base.sha256_hex(preimage), preimage.decode("utf-8")


# ---------------------------------------------------------------------------
# Expected results (written by hand from the draft text)
# ---------------------------------------------------------------------------

HALF = {"outcome": "artifact", "body": "carried", "digest": "reproduced", "claims": base.MEMBER_CLAIMS_DEPTH0}


def history_expect(anchor: str = "verified", anchor_time: str = "", signature: str = "verified",
                   digest_state: str = "reproduced", findings: list[str] | None = None) -> dict:
    return {"outcome": "artifact", "form": "history", "body": "carried", "digest": digest_state,
            "history_signature": signature, "anchor_checkpoint": anchor, "anchor_time": anchor_time,
            "findings": findings or []}


def join_expect(members: list[str], declared: str, derived: str, findings: list[str] | None = None) -> dict:
    result = "not_derivable" if derived == "" else ("derived_matches" if derived == declared else
                                                     "join_state_mismatch")
    return {"members": members, "declared": declared, "derived": derived, "result": result,
            "findings": findings or []}


DEAL_LINK = {"histories": ["history-a", "history-b"], "halves": ["half-a", "half-b"], "pointer": base.ID_POINTER}
SAME_KEY_REDUNDANT = {"result": "redundant", "reasons": ["same_observer", "same_custody_domain", "same_key"]}
CORROBORATING = {"result": "corroborating", "qualifier": "custody_declared"}
NOT_APPLICABLE = {"result": "not_applicable"}


def corroboration(deal: dict, a: dict, b: dict) -> list[dict]:
    return [{"members": ["half-a", "half-b"], **deal}, {"members": ["half-a", "history-a"], **a},
            {"members": ["half-b", "history-b"], **b}]


def case(case_id: str, sections: list[str], description: str, comp: dict, expect: dict,
         options: dict | None = None) -> dict:
    d, preimage = digest(comp)
    full = {"composed_digest": d, "canonical_preimage": preimage, **expect}
    return {"id": case_id, "section": sections, "description": description,
            "options": WITH_PROFILE if options is None else options,
            "container": base.container(comp), "expect": full}


def staple_expect(status: str = "pass", findings: list[str] | None = None, *, history_a: dict | None = None,
                  joins: list[dict] | None = None, corr: list[dict] | None = None,
                  related: list[list[str]] | None = None) -> dict:
    return {
        "status": status,
        "findings": findings or [],
        "members": {"half-a": HALF, "half-b": HALF,
                    "history-a": history_a or history_expect(anchor_time=base.t(20)),
                    "history-b": history_expect(anchor_time=base.t(21))},
        "composition_closure": {"status": "pass", "missing": []},
        "joins": joins or [join_expect(["half-a", "half-b"], "agree", "agree"),
                           join_expect(["half-a", "history-a"], "agree", "agree"),
                           join_expect(["half-b", "history-b"], "agree", "agree")],
        "corroboration": corr or corroboration(CORROBORATING, SAME_KEY_REDUNDANT, SAME_KEY_REDUNDANT),
        "related_histories": [DEAL_LINK] if related is None else related,
    }


def case_staple() -> dict:
    members, _, _ = staple()
    return case("history-staple", [S_HISTORY, S_SHAPE, S_DIGEST, S_OBSERVERS, S_VERIFY],
                "Two parties' halves of one deal joined pre_agreed_identifier on the deal id (agree), and each "
                "party's standard_history/1 answer tied to its own half by same_key: the half's key_id is the "
                "History's responder, and the History's anchor (minute 20, 21) is after the half (minute 10, "
                "11). Both same_key agreements are redundant (one key made both); the deal agreement "
                "corroborates on declared custody; the two Histories are related through the three derived "
                "agreements.",
                block(members, staple_joins()), staple_expect())


def case_key_differs() -> dict:
    members, _, _ = staple(a_signer=OTHER)
    joins = [join_expect(["half-a", "half-b"], "agree", "agree"),
             join_expect(["half-a", "history-a"], "agree", "unjoined", ["history_key_differs"]),
             join_expect(["half-b", "history-b"], "agree", "agree")]
    return case("history-key-differs", [S_HISTORY],
                "History A is answered, and validly signed, by a key other than the one that signed half A. "
                "same_key derives unjoined (history_key_differs); the declared agree fails "
                "(join_state_mismatch), and the two Histories are not related.",
                block(members, staple_joins()),
                staple_expect("fail", ["join_state_mismatch:half-a,history-a"], joins=joins,
                              corr=corroboration(CORROBORATING, NOT_APPLICABLE, SAME_KEY_REDUNDANT), related=[]))


def _prior_record() -> dict:
    return base.observation("responder-a-prior", "responder-a.example", base.RESPONDER_A, 2,
                            transcript="prior transcript")


def case_anchored_before_deal() -> dict:
    members, _, _ = staple(a_anchor_time=base.t(5), a_anchor_records=[_prior_record()])
    joins = [join_expect(["half-a", "half-b"], "agree", "agree"),
             join_expect(["half-a", "history-a"], "agree", "unjoined", ["history_anchor_predates_deal"]),
             join_expect(["half-b", "history-b"], "agree", "agree")]
    return case("history-anchored-before-deal", [S_HISTORY],
                "History A's anchor is A's log at minute 5, before half A (minute 10). A History as of an anchor "
                "before the deal is not about it: same_key derives unjoined (history_anchor_predates_deal) and "
                "the declared agree fails.",
                block(members, staple_joins()),
                staple_expect("fail", ["join_state_mismatch:half-a,history-a"],
                              history_a=history_expect(anchor_time=base.t(5)), joins=joins,
                              corr=corroboration(CORROBORATING, NOT_APPLICABLE, SAME_KEY_REDUNDANT), related=[]))


def case_anchor_at_deal_time() -> dict:
    members, _, _ = staple(a_anchor_time=base.t(10))
    return case("history-anchored-at-deal-time", [S_HISTORY],
                "History A's anchor time equals half A's timestamp (minute 10). Only an anchor earlier than the "
                "deal is unjoined: same_key derives agree.",
                block(members, staple_joins()),
                staple_expect(history_a=history_expect(anchor_time=base.t(10))))


def case_anchor_not_carried() -> dict:
    members, _, _ = staple(a_carry_anchor=False)
    joins = [join_expect(["half-a", "half-b"], "agree", "agree"),
             join_expect(["half-a", "history-a"], "agree", "", ["history_anchor_time_unknown"]),
             join_expect(["half-b", "history-b"], "agree", "agree")]
    return case("history-anchor-not-carried", [S_HISTORY],
                "History A carries no anchor_checkpoint, so there is no anchor time: same_key is not derivable "
                "(history_anchor_time_unknown). Nothing failed, so the block is withheld.",
                block(members, staple_joins()),
                staple_expect("withheld", ["join_not_derivable:half-a,history-a"],
                              history_a=history_expect(anchor="absent"), joins=joins,
                              corr=corroboration(CORROBORATING, NOT_APPLICABLE, SAME_KEY_REDUNDANT), related=[]))


def case_anchor_checkpoint_other() -> dict:
    members, _, _ = staple()
    by_id = {m["id"]: m for m in members}
    by_id["history-a"]["anchor_checkpoint"] = by_id["history-b"]["anchor_checkpoint"]
    joins = [join_expect(["half-a", "half-b"], "agree", "agree"),
             join_expect(["half-a", "history-a"], "agree", "", ["history_anchor_time_unknown"]),
             join_expect(["half-b", "history-b"], "agree", "agree")]
    return case("history-anchor-checkpoint-other", [S_HISTORY],
                "History A carries History B's anchor checkpoint, whose SHA-256 is not A's signed anchor digest: "
                "history_anchor_checkpoint_mismatch fails the block, and with no anchor time same_key is not "
                "derivable.",
                block(members, staple_joins()),
                staple_expect("fail", ["history_anchor_checkpoint_mismatch:history-a",
                                       "join_not_derivable:half-a,history-a"],
                              history_a=history_expect(anchor="mismatch",
                                                       findings=["history_anchor_checkpoint_mismatch"]),
                              joins=joins, corr=corroboration(CORROBORATING, NOT_APPLICABLE, SAME_KEY_REDUNDANT),
                              related=[]))


def case_signature_invalid() -> dict:
    members, _, _ = staple()
    history_a = next(m for m in members if m["id"] == "history-a")
    history_a["history"]["issued_at"] = base.t(41)
    history_a["digest"] = base.sha256_hex(base.jcs(history_a["history"]))
    joins = [join_expect(["half-a", "half-b"], "agree", "agree"),
             join_expect(["half-a", "history-a"], "agree", ""),
             join_expect(["half-b", "history-b"], "agree", "agree")]
    return case("history-signature-invalid", [S_HISTORY],
                "History A's issued_at was changed after the responder signed (its member digest recomputed): "
                "the signature does not verify (history_signature_invalid, a failure), and same_key does not "
                "derive from an unverified responder.",
                block(members, staple_joins()),
                staple_expect("fail", ["history_signature_invalid:history-a", "join_not_derivable:half-a,history-a"],
                              history_a=history_expect(anchor_time=base.t(20), signature="invalid",
                                                       findings=["history_signature_invalid"]),
                              joins=joins, corr=corroboration(CORROBORATING, NOT_APPLICABLE, SAME_KEY_REDUNDANT),
                              related=[]))


def case_signature_unverified() -> dict:
    members, _, _ = staple()
    joins = [join_expect(["half-a", "half-b"], "agree", "agree"),
             join_expect(["half-a", "history-a"], "agree", ""),
             join_expect(["half-b", "history-b"], "agree", "")]
    expect = staple_expect("withheld", ["history_signature_unverified:history-a",
                                        "history_signature_unverified:history-b",
                                        "join_not_derivable:half-a,history-a", "join_not_derivable:half-b,history-b"],
                           history_a=history_expect(anchor_time=base.t(20), signature="signature_unverified"),
                           joins=joins, corr=corroboration(CORROBORATING, NOT_APPLICABLE, NOT_APPLICABLE), related=[])
    expect["members"]["history-b"] = history_expect(anchor_time=base.t(21), signature="signature_unverified")
    return case("history-signature-unverified", [S_HISTORY],
                "The staple, verified with no deployment signature profile: each History is "
                "signature_unverified (withheld, never failed) and neither same_key join derives.",
                block(members, staple_joins()), expect, options={})


def case_request_digest_other() -> dict:
    members, _, _ = staple()
    history_a = next(m for m in members if m["id"] == "history-a")
    history_a["request_digest"] = next(m for m in members if m["id"] == "history-b")["request_digest"]
    joins = [join_expect(["half-a", "half-b"], "agree", "agree"),
             join_expect(["half-a", "history-a"], "agree", ""),
             join_expect(["half-b", "history-b"], "agree", "agree")]
    return case("history-request-digest-other", [S_HISTORY],
                "History A's member names History B's request: the answer's request_digest differs from the "
                "member's (member_request_digest_mismatch), which fails the block, and same_key does not read an "
                "answer to another request.",
                block(members, staple_joins()),
                staple_expect("fail", ["member_request_digest_mismatch:history-a", "join_not_derivable:half-a,history-a"],
                              history_a=history_expect(anchor_time=base.t(20), findings=["request_digest_mismatch"]),
                              joins=joins, corr=corroboration(CORROBORATING, NOT_APPLICABLE, SAME_KEY_REDUNDANT),
                              related=[]))


def case_member_missing() -> dict:
    members, _, _ = staple()
    joins = [join_expect(["half-a", "half-b"], "agree", "agree"),
             join_expect(["half-a", "history-a"], "agree", ""),
             join_expect(["half-b", "history-b"], "agree", "agree")]
    expect = staple_expect("withheld", ["declared_incomplete", "join_not_derivable:half-a,history-a"], joins=joins,
                           corr=corroboration(CORROBORATING, NOT_APPLICABLE, SAME_KEY_REDUNDANT), related=[])
    expect["members"]["history-a"] = {"outcome": "artifact", "form": "history", "body": "declared_missing",
                                      "digest": "not_shown"}
    expect["composition_closure"] = {"status": "withheld", "missing": ["history-a"]}
    expect["composed_digest_equals_case"] = "history-staple"
    return case("history-member-missing", [S_HISTORY, S_CLOSURE, S_DIGEST],
                "The staple with History A declared missing and its answer not carried: the composed digest is "
                "the staple's; closure is withheld; same_key with a declared-missing member is not derivable.",
                block(members, staple_joins(), missing=["history-a"]), expect)


def case_deal_unjoined() -> dict:
    members, _, _ = staple(deal_id_b="example-run-0002")
    joins = [join_expect(["half-a", "half-b"], "unjoined", "unjoined"),
             join_expect(["half-a", "history-a"], "agree", "agree"),
             join_expect(["half-b", "history-b"], "agree", "agree")]
    return case("history-deal-unjoined", [S_HISTORY],
                "Half B carries another deal id, so the halves do not join (declared and derived unjoined). Each "
                "History still agrees with its own half, but the two Histories are not related: they are only "
                "carried in one block.",
                block(members, staple_joins(deal_state="unjoined")),
                staple_expect(joins=joins, corr=corroboration(NOT_APPLICABLE, SAME_KEY_REDUNDANT, SAME_KEY_REDUNDANT),
                              related=[]))


def case_beside_refusal() -> dict:
    members, _, _ = staple()
    by_id = {m["id"]: m for m in members}
    refusal = {"request_digest": by_id["half-b"]["request_digest"], "reason": "policy_declined",
               "issued_at": base.t(12)}
    half_b = {k: v for k, v in by_id["half-b"].items() if k != "bundle"}
    half_b.update({"outcome": "refusal", "digest": base.sha256_hex(base.jcs(refusal)), "refusal": refusal})
    members = [half_b if m["id"] == "half-b" else m for m in members]
    joins = [join_expect(["half-a", "half-b"], "one_sided", "one_sided"),
             join_expect(["half-a", "history-a"], "agree", "agree"),
             join_expect(["half-b", "history-b"], "unjoined", "unjoined")]
    expect = staple_expect("withheld", ["refusal_signature_unverified:half-b"], joins=joins,
                           corr=corroboration(NOT_APPLICABLE, SAME_KEY_REDUNDANT, NOT_APPLICABLE), related=[])
    expect["members"]["half-b"] = {"outcome": "refusal", "body": "carried", "digest": "reproduced"}
    return case("history-beside-refusal", [S_HISTORY],
                "Party B refused to give its half and answered its History. same_key against a refusal member "
                "derives unjoined; the deal join is one_sided.",
                block(members, staple_joins(deal_state="one_sided", b_state="unjoined")), expect)


def _malformed(case_id: str, description: str, comp: dict, reason: str) -> dict:
    """A malformed block: the composed digest is not computed (the block fails
    before it), and no composition result is reported."""
    return {"id": case_id, "section": [S_SHAPE], "description": description, "options": WITH_PROFILE,
            "container": base.container(comp),
            "expect": {"status": "fail", "malformed": True, "findings": [f"composed_block_malformed:{reason}"]}}


def _malformed_block(members: list[dict], joins: list[dict]) -> dict:
    out = {"members": members, "observers": copy.deepcopy(OBSERVERS), "joins": joins}
    out["composed_digest"] = base.label_hex("malformed blocks carry an arbitrary composed digest")
    return out


def case_malformed_deal_join_on_history() -> dict:
    members, _, _ = staple()
    joins = staple_joins() + [dict(base.join("half-b", "history-a", "agree"))]
    return _malformed("malformed-history-in-deal-join",
                      "A pre_agreed_identifier join names History A: a join naming a History member must be "
                      "same_key.", _malformed_block(members, joins), "join:3:join_names_history_member")


def case_malformed_two_histories() -> dict:
    members, _, _ = staple()
    joins = staple_joins() + [same_key("history-a", "history-b", "agree")]
    return _malformed("malformed-same-key-two-histories",
                      "A same_key join between the two History members: two Histories are never joined to each "
                      "other.", _malformed_block(members, joins), "join:3:same_key_members")


def case_malformed_same_key_compare() -> dict:
    members, _, _ = staple()
    joins = staple_joins()
    joins[1] = {**joins[1], "compare": [base.COMPARE_POINTER]}
    return _malformed("malformed-same-key-with-compare",
                      "A same_key join carrying compare: a History has no root record to compare.",
                      _malformed_block(members, joins), "join:1:same_key_shape")


def case_malformed_history_with_bundle() -> dict:
    members, _, _ = staple()
    by_id = {m["id"]: m for m in members}
    by_id["history-a"]["bundle"] = copy.deepcopy(by_id["half-a"]["bundle"])
    return _malformed("malformed-history-with-bundle",
                      "History A also carries a bundle: a History member's body is history, never bundle.",
                      _malformed_block(members, staple_joins()), "member:2:body_outcome_conflict")


def _replace(members: list[dict], member: dict) -> list[dict]:
    return [member if m["id"] == member["id"] else m for m in members]


def _unsigned(record: dict) -> dict:
    return {k: v for k, v in record.items() if k not in ("key_id", "signature")}


A_NOT_DERIVABLE = [join_expect(["half-a", "half-b"], "agree", "agree"),
                   join_expect(["half-a", "history-a"], "agree", "", ["half_signature_unverified"]),
                   join_expect(["half-b", "history-b"], "agree", "agree")]


def case_half_unsigned() -> dict:
    members, rec_a, _ = staple()
    members = _replace(members, base.artifact_member("half-a", "obs-a", _unsigned(rec_a)))
    return case("history-half-unsigned", [S_HISTORY],
                "Half A's root record carries party A's key_id but no signature (the composing party wrote the "
                "key). Nothing shows that A's key signed the half: same_key is not derivable "
                "(half_signature_unverified), and the Histories are not related.",
                block(members, staple_joins()),
                staple_expect("withheld", ["join_not_derivable:half-a,history-a"], joins=A_NOT_DERIVABLE,
                              corr=corroboration(CORROBORATING, NOT_APPLICABLE, SAME_KEY_REDUNDANT), related=[]))


def case_half_key_copied() -> dict:
    members, rec_a, _ = staple()
    forged = base.seal(_unsigned({k: v for k, v in rec_a.items() if k != "capsule_id"}), OTHER)
    forged["key_id"] = base.RESPONDER_A.public_hex
    members = _replace(members, base.artifact_member("half-a", "obs-a", forged))
    return case("history-half-key-copied", [S_HISTORY],
                "Half A is signed by another key, with party A's key copied into its key_id. The Producer "
                "Envelope does not verify under that key_id: same_key is not derivable "
                "(half_signature_unverified), never agree.",
                block(members, staple_joins()),
                staple_expect("withheld", ["join_not_derivable:half-a,history-a"], joins=A_NOT_DERIVABLE,
                              corr=corroboration(CORROBORATING, NOT_APPLICABLE, SAME_KEY_REDUNDANT), related=[]))


def case_missing_with_body() -> dict:
    members, _, _ = staple()
    joins = [join_expect(["half-a", "half-b"], "agree", "agree"),
             join_expect(["half-a", "history-a"], "agree", ""),
             join_expect(["half-b", "history-b"], "agree", "agree")]
    expect = staple_expect("fail", ["composition_closure_fail", "join_not_derivable:half-a,history-a"],
                           joins=joins, corr=corroboration(CORROBORATING, NOT_APPLICABLE, SAME_KEY_REDUNDANT),
                           related=[])
    expect["composition_closure"] = {"status": "fail", "missing": ["history-a"]}
    return case("history-listed-missing-carries-body", [S_HISTORY, S_CLOSURE],
                "History A is listed in missing but its answer is still carried: closure fails "
                "(missing_member_carries_body), and a member listed in missing is not derivable on same_key.",
                block(members, staple_joins(), missing=["history-a"], keep_bodies=True), expect)


def case_history_body_changed() -> dict:
    members, _, _ = staple()
    history_a = next(m for m in members if m["id"] == "history-a")
    comp = block(members, staple_joins())
    history_a["history"]["x-note"] = "added after the member digest was computed"
    joins = [join_expect(["half-a", "half-b"], "agree", "agree"),
             join_expect(["half-a", "history-a"], "agree", ""),
             join_expect(["half-b", "history-b"], "agree", "agree")]
    return case("history-body-changed", [S_HISTORY, S_CLOSURE],
                "History A's answer gained an unsigned member after its digest was declared: the digest does not "
                "reproduce (closure fails), and a body that did not verify as carried is not read by "
                "same_key, though its signature still verifies.",
                comp,
                staple_expect("fail", ["composition_closure_fail", "join_not_derivable:half-a,history-a"],
                              history_a=history_expect(anchor_time=base.t(20), digest_state="mismatch",
                                                       findings=["member_digest_mismatch"]),
                              joins=joins, corr=corroboration(CORROBORATING, NOT_APPLICABLE, SAME_KEY_REDUNDANT),
                              related=[]) | {"composition_closure": {"status": "fail", "missing": []}})


def _spec_version_join(basis: str, state: str) -> dict:
    out = {"members": ["half-a", "half-b"], "basis": basis, "pointer": "/spec_version", "state": state}
    if basis == "pre_agreed_identifier":
        out["identifier_digest"] = base.sha256_hex(base.AAC_SPEC_VERSION.encode("utf-8"))
    return out


def case_halves_linked_other_basis() -> dict:
    members, _, _ = staple(deal_id_b="example-run-0002")
    joins = staple_joins(deal_state="unjoined") + [_spec_version_join("shared_artifact_digest", "agree")]
    expect = staple_expect(joins=[join_expect(["half-a", "half-b"], "unjoined", "unjoined"),
                                  join_expect(["half-a", "history-a"], "agree", "agree"),
                                  join_expect(["half-b", "history-b"], "agree", "agree"),
                                  join_expect(["half-a", "half-b"], "agree", "agree")],
                           corr=corroboration(NOT_APPLICABLE, SAME_KEY_REDUNDANT, SAME_KEY_REDUNDANT)
                           + [{"members": ["half-a", "half-b"], **CORROBORATING}], related=[])
    return case("history-halves-linked-other-basis", [S_HISTORY],
                "Two different deals; the halves also agree on shared_artifact_digest at /spec_version. Only a "
                "pre_agreed_identifier agreement between the halves relates two Histories: none here.",
                block(members, joins), expect)


def case_trivial_identifier() -> dict:
    members, _, _ = staple(deal_id_b="example-run-0002")
    joins = staple_joins(deal_state="unjoined") + [_spec_version_join("pre_agreed_identifier", "agree")]
    expect = staple_expect(joins=[join_expect(["half-a", "half-b"], "unjoined", "unjoined"),
                                  join_expect(["half-a", "history-a"], "agree", "agree"),
                                  join_expect(["half-b", "history-b"], "agree", "agree"),
                                  join_expect(["half-a", "half-b"], "agree", "agree")],
                           corr=corroboration(NOT_APPLICABLE, SAME_KEY_REDUNDANT, SAME_KEY_REDUNDANT)
                           + [{"members": ["half-a", "half-b"], **CORROBORATING}],
                           related=[{"histories": ["history-a", "history-b"], "halves": ["half-a", "half-b"],
                                     "pointer": "/spec_version"}])
    return case("history-related-through-a-shared-field", [S_HISTORY],
                "Two different deals, linked by a pre_agreed_identifier join on /spec_version, which every record "
                "of that version shares. The Histories are reported related, with the pointer /spec_version: the "
                "relation is only as strong as the identifier the pointer selects, and the deal-id join is "
                "unjoined.",
                block(members, joins), expect)


def case_anchor_time_malformed() -> dict:
    members, _, _ = staple(a_anchor_time="2026-10-02 12:20:00")
    joins = [join_expect(["half-a", "half-b"], "agree", "agree"),
             join_expect(["half-a", "history-a"], "agree", "", ["history_anchor_time_unknown"]),
             join_expect(["half-b", "history-b"], "agree", "agree")]
    return case("history-anchor-time-malformed", [S_HISTORY],
                "History A's anchor checkpoint is signed with a timestamp that is not an RFC 3339 instant: "
                "history_anchor_checkpoint_invalid fails the block, and there is no anchor time.",
                block(members, staple_joins()),
                staple_expect("fail", ["history_anchor_checkpoint_invalid:history-a",
                                       "join_not_derivable:half-a,history-a"],
                              history_a=history_expect(anchor="invalid",
                                                       findings=["history_anchor_checkpoint_invalid"]),
                              joins=joins, corr=corroboration(CORROBORATING, NOT_APPLICABLE, SAME_KEY_REDUNDANT),
                              related=[]))


def case_anchor_time_offset() -> dict:
    members, _, _ = staple(a_anchor_time="2026-10-02T12:20:00+00:00")
    joins = [join_expect(["half-a", "half-b"], "agree", "agree"),
             join_expect(["half-a", "history-a"], "agree", "", ["history_anchor_time_unknown"]),
             join_expect(["half-b", "history-b"], "agree", "agree")]
    return case("history-anchor-time-offset", [S_HISTORY],
                "History A's anchor checkpoint is signed with an RFC 3339 time carrying a numeric offset, not a "
                "UTC instant with Z: history_anchor_checkpoint_invalid, as for any other time form.",
                block(members, staple_joins()),
                staple_expect("fail", ["history_anchor_checkpoint_invalid:history-a",
                                       "join_not_derivable:half-a,history-a"],
                              history_a=history_expect(anchor="invalid",
                                                       findings=["history_anchor_checkpoint_invalid"]),
                              joins=joins, corr=corroboration(CORROBORATING, NOT_APPLICABLE, SAME_KEY_REDUNDANT),
                              related=[]))


def case_anchor_checkpoint_invalid() -> dict:
    members, _, _ = staple(a_corrupt_anchor=True)
    joins = [join_expect(["half-a", "half-b"], "agree", "agree"),
             join_expect(["half-a", "history-a"], "agree", "", ["history_anchor_time_unknown"]),
             join_expect(["half-b", "history-b"], "agree", "agree")]
    return case("history-anchor-signature-invalid", [S_HISTORY],
                "History A's anchor checkpoint matches the signed anchor digest but its signature does not "
                "verify: history_anchor_checkpoint_invalid fails the block.",
                block(members, staple_joins()),
                staple_expect("fail", ["history_anchor_checkpoint_invalid:history-a",
                                       "join_not_derivable:half-a,history-a"],
                              history_a=history_expect(anchor="invalid",
                                                       findings=["history_anchor_checkpoint_invalid"]),
                              joins=joins, corr=corroboration(CORROBORATING, NOT_APPLICABLE, SAME_KEY_REDUNDANT),
                              related=[]))


def case_half_empty_history() -> dict:
    members, _, _ = staple()
    empty = {"bundle_version": "2", "bundle_kind": "evidence-bundle/v2", "records": [],
             "completeness": {"records_mode": "complete", "payloads_mode": "none"}}
    half_b = next(m for m in members if m["id"] == "half-b")
    half_b = {**half_b, "bundle": empty, "digest": base.bundle_digest(empty)}
    members = _replace(members, half_b)
    expect = staple_expect(joins=[join_expect(["half-a", "half-b"], "one_sided", "one_sided"),
                                  join_expect(["half-a", "history-a"], "agree", "agree"),
                                  join_expect(["half-b", "history-b"], "unjoined", "unjoined")],
                           corr=corroboration(NOT_APPLICABLE, SAME_KEY_REDUNDANT, NOT_APPLICABLE), related=[])
    expect["members"]["half-b"] = {"outcome": "artifact", "body": "carried", "digest": "reproduced"}
    return case("history-half-empty-history", [S_HISTORY],
                "Party B's half is an empty-history Bundle: same_key against a member with no records derives "
                "unjoined; the deal join is one_sided.",
                block(members, staple_joins(deal_state="one_sided", b_state="unjoined")), expect)


def case_half_relabelled() -> dict:
    members, rec_a, _ = staple()
    relabelled = {**rec_a, "capsule_id": "0" * 64}
    half_a = base.artifact_member("half-a", "obs-a", relabelled)
    half_a["bundle"]["root"] = relabelled["capsule_id"]
    half_a["digest"] = base.bundle_digest(half_a["bundle"])
    members = _replace(members, half_a)
    expect = staple_expect("withheld", ["join_not_derivable:half-a,history-a"], joins=A_NOT_DERIVABLE,
                           corr=corroboration(CORROBORATING, NOT_APPLICABLE, SAME_KEY_REDUNDANT), related=[])
    expect["members"]["half-a"] = {"outcome": "artifact", "body": "carried", "digest": "reproduced"}
    expect["joins"][0] = join_expect(["half-a", "half-b"], "agree", "agree")
    return case("history-half-capsule-id-relabelled", [S_HISTORY],
                "Half A's content is party A's signed record, but its carried capsule_id (and the Bundle's root) "
                "is another value. The signature verifies over the recomputed Capsule ID, which is not the record "
                "the Bundle names: same_key is not derivable (half_signature_unverified).",
                block(members, staple_joins()), expect)


def case_half_response_mismatch() -> dict:
    members, _, _ = staple()
    half_a = next(m for m in members if m["id"] == "half-a")
    other = next(m for m in members if m["id"] == "half-b")
    half_a = {**half_a, "response": {"request_digest": other["request_digest"], "artifact_digest": half_a["digest"]}}
    members = _replace(members, half_a)
    joins = [join_expect(["half-a", "half-b"], "agree", "agree"),
             join_expect(["half-a", "history-a"], "agree", ""),
             join_expect(["half-b", "history-b"], "agree", "agree")]
    return case("history-half-response-other-request", [S_HISTORY],
                "Half A carries a response naming party B's request: the block fails "
                "(member_response_request_digest_mismatch), and same_key does not read a half that failed as "
                "carried.",
                block(members, staple_joins()),
                staple_expect("fail", ["member_response_request_digest_mismatch:half-a",
                                       "response_signature_unverified:half-a", "join_not_derivable:half-a,history-a"],
                              joins=joins, corr=corroboration(CORROBORATING, NOT_APPLICABLE, SAME_KEY_REDUNDANT),
                              related=[]))


def case_malformed_same_key_pointer() -> dict:
    members, _, _ = staple()
    joins = staple_joins()
    joins[1] = {**joins[1], "pointer": "/key_id"}
    return _malformed("malformed-same-key-with-pointer",
                      "A same_key join carrying pointer: the key is the one that signed the half, never a value a "
                      "pointer selects.", _malformed_block(members, joins), "join:1:same_key_shape")


def case_malformed_form_on_refusal() -> dict:
    members, _, _ = staple()
    refusal = {"request_digest": members[1]["request_digest"], "reason": "policy_declined", "issued_at": base.t(12)}
    half_b = {k: v for k, v in members[1].items() if k != "bundle"}
    half_b.update({"outcome": "refusal", "form": "history", "digest": base.sha256_hex(base.jcs(refusal)),
                   "refusal": refusal})
    return _malformed("malformed-form-on-refusal",
                      "A refusal member carrying form history: a History member's outcome is artifact.",
                      _malformed_block(_replace(members, half_b), staple_joins()), "member:1:form")


def cases() -> list[dict]:
    return [case_staple(), case_key_differs(), case_anchored_before_deal(), case_anchor_at_deal_time(),
            case_anchor_not_carried(), case_anchor_checkpoint_other(), case_signature_invalid(),
            case_signature_unverified(), case_request_digest_other(), case_member_missing(), case_deal_unjoined(),
            case_beside_refusal(), case_malformed_deal_join_on_history(), case_malformed_two_histories(),
            case_malformed_same_key_compare(), case_malformed_history_with_bundle(), case_half_unsigned(),
            case_half_key_copied(), case_missing_with_body(), case_history_body_changed(),
            case_halves_linked_other_basis(), case_trivial_identifier(), case_anchor_time_malformed(), case_anchor_time_offset(),
            case_anchor_checkpoint_invalid(), case_half_empty_history(), case_half_relabelled(), case_half_response_mismatch(), case_malformed_same_key_pointer(),
            case_malformed_form_on_refusal()]


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------


def build() -> dict[str, bytes]:
    case_list = cases()
    files = {
        "vectors.json": base._dump({
            "draft": DRAFT,
            "provenance": "spec-derived",
            "status": "held for ratification with -03",
            "kind": base.KIND,
            "digest_rule": "composed_digest as in vectors/bundle/composed, with each member's form in the digest "
                           "input when the member carries it; see canonical_preimage in each case.",
            "history_signature": {
                PROFILE: "Ed25519 by `responder` over the UTF-8 JCS of the envelope members profile, "
                         "request_digest, subject, derivation, anchor, artifact_digest, verification, responder "
                         "and issued_at that are present (spec/interop-profile-v0.md section 6.2). A case whose "
                         "options name no history_signature is verified with no deployment signature profile.",
            },
            "keys": {k.name: {"seed_hex": k.seed.hex(), "public_key_hex": k.public_hex} for k in KEYS},
            "count": len(case_list),
            "cases": case_list,
        }),
    }
    files["manifest.json"] = base._dump({
        "draft": DRAFT,
        "provenance": "spec-derived",
        "generator": "python/scripts/generate_bundle_composed_history_vectors.py",
        "files": [{"path": name, "sha256": base.sha256_hex(data), "count": json.loads(data).get("count")}
                  for name, data in sorted(files.items())],
    })
    return files


def write(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for name, data in build().items():
        (out / name).write_bytes(data)
    lines = [f"{base.sha256_hex(p.read_bytes())}  {p.name}"
             for p in sorted(out.iterdir()) if p.is_file() and p.name != "SHA256SUMS"]
    (out / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    write(parser.parse_args().out)


if __name__ == "__main__":
    main()
