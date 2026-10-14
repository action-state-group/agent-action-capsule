# SPDX-License-Identifier: BSD-3-Clause
"""Generate the frozen conformance vectors in ../../vectors/capsule/ and
../../provenance-mode-vectors/.

Vectors are DERIVED from the spec-faithful reference verifier and then FROZEN
(the same discipline as golden digests): each case's expected.json is produced
by running verify()/verify_store() over a hand-built input, and committed. A
third party regenerates the capsule_id and checks ok + the §6 check numbers +
derived modes against the spec text, without running this package.

vectors/capsule/ is the Class-1 corpus and is cross-language-shared (the go/
reference implementation's vector_runner reads vectors/capsule/vectors.json
directly), so every case there is a bare Capsule or {"ledger": [...]}.
The capsule cases here are the -04 compatibility set: they were released as
format 2 and moved to format 4 with spec_version -04 in #99, and they stay
-04 because a verifier MUST accept -04 and spec_version is in the capsule_id
preimage. New cases default to -05 (generate_v05_vectors.py). Four legacy-format
negatives are frozen fixtures: the reference refuses to seal format 1, 2 or 3,
so this script lists them in the manifest without rewriting them.

Run:  cd python && python -m scripts.generate_vectors
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from agent_action_capsule import compute_capsule_id, json_digest, verify, verify_store

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vector_layout import dumps, ledger_preimages, preimage, sort_members  # noqa: E402

OUT = Path(__file__).resolve().parents[2] / "vectors/capsule"
PM_OUT = Path(__file__).resolve().parents[2] / "provenance-mode-vectors"
CURRENT_SPEC = "draft-mih-scitt-agent-action-capsule-05"
# The capsule corpus's released -04 compatibility set.
COMPAT_SPEC = "draft-mih-scitt-agent-action-capsule-04"
SPEC_DERIVED = "spec-derived"
# The provenance-mode corpus shipped in v0.5.0 / go/v0.5.x sealed as -04; those
# files are frozen. Each case also gets a "-v05" twin sealed as -05.
RELEASED_PM_SPEC = "draft-mih-scitt-agent-action-capsule-04"
HEX_R = "1" * 64  # a stand-in response/request digest (64-hex); content is opaque here
HEX_R2 = "2" * 64
MISSING_PARENT = "9" * 64


def ident(action_id: str, action_type: str = "decide", spec_version: str = COMPAT_SPEC) -> dict:
    """Identity fields of the cases first released as format 2."""
    return {
        "spec_version": spec_version,
        "format_version": "4",
        "canonicalization_id": "jcs",
        "action_id": action_id,
        "action_type": action_type,
        "operator": "ACME-CO",
        "developer": "agent@v1",
        "timestamp": "2026-06-13T00:00:00Z",
    }


def ident_v4(action_id: str, action_type: str = "decide", spec_version: str = CURRENT_SPEC) -> dict:
    """Identity fields for the current declared-JCS serialization suite."""
    return {
        "spec_version": spec_version,
        "format_version": "4",
        "canonicalization_id": "jcs",
        "action_id": action_id,
        "action_type": action_type,
        "operator": "ACME-CO",
        "developer": "agent@v1",
        "timestamp": "2026-08-24T00:00:00Z",
    }


def assurance(effect_mode: str, ledger_mode: str = "standalone", cross_party_rung: str | None = None) -> dict:
    a = {"attestation_mode": "self_attested", "effect_mode": effect_mode, "ledger_mode": ledger_mode}
    if cross_party_rung is not None:
        a["cross_party_rung"] = cross_party_rung
    return a


def provenance_mode_backfilled(source_ref=True, source_asserted_at="2026-01-01T00:00:00Z",
                                import_batch="import-2026-09", imported_at="2026-09-22T00:00:00Z",
                                time_rung=None) -> dict:
    pm: dict = {"mode": "backfilled"}
    if source_ref:
        pm["source_ref"] = {"type": "x-external-ledger-entry", "digest_alg": "SHA-256", "digest": "3" * 64}
    if source_asserted_at is not None:
        pm["source_asserted_at"] = source_asserted_at
    if import_batch is not None:
        pm["import_batch"] = import_batch
    if imported_at is not None:
        pm["imported_at"] = imported_at
    if time_rung is not None:
        pm["time_rung"] = time_rung
    return pm


def cross_party_block(has_counterparty: bool, substantive: bool = False) -> dict:
    cp = {"initiator_ref": HEX_R}
    if has_counterparty:
        cp["counterparty_ref"] = HEX_R2
        cp["correlator"] = "exchange-corr-1"
        cp["substantive"] = substantive
    return cp


def released_layout(cap: dict) -> dict:
    """Member order of the cases first released as format 2.

    #99 moved them to format 4 in place: the format-2 members stay sorted and
    canonicalization_id follows them.
    """
    members = {key: val for key, val in cap.items() if key != "canonicalization_id"}
    members.setdefault("capsule_id", None)
    out = sort_members(members)
    out["canonicalization_id"] = cap["canonicalization_id"]
    return out


def seal(cap: dict) -> dict:
    """Seal a case first released as format 2, in its released layout."""
    cap = released_layout(cap)
    cap["capsule_id"] = compute_capsule_id(cap)
    return cap


def seal_v4(cap: dict) -> dict:
    """Seal a Capsule with its members sorted."""
    cap = sort_members({**cap, "capsule_id": None})
    cap["capsule_id"] = compute_capsule_id(cap)
    return cap


# --- case builders ----------------------------------------------------------
def c_executed() -> dict:
    return seal({
        **ident("po-001"),
        "effect": {"status": "confirmed", "type": "write_order", "response_digest": HEX_R, "effect_attestation": "gate_executed", "irreversibility_class": "two_way"},
        "assurance": assurance("confirmed"),
        "disposition": {"decision": "accept", "approver": "human", "human_disposed": True},
    })


def c_verdict(action_id, verdict_class, decision, approver, human_disposed, effect=None, effect_mode="not_applicable") -> dict:
    cap = {**ident(action_id), "assurance": assurance(effect_mode),
           "disposition": {"decision": decision, "approver": approver, "human_disposed": human_disposed, "verdict_class": verdict_class}}
    if effect is not None:
        cap["effect"] = effect
    return seal(cap)


def c_matrix(action_id, effect, effect_mode, verdict_class=None) -> dict:
    disp = {"decision": "accept", "approver": "human", "human_disposed": True}
    if verdict_class:
        disp["verdict_class"] = verdict_class
    return seal({**ident(action_id), "effect": effect, "assurance": assurance(effect_mode), "disposition": disp})


def build_cases() -> list[dict]:
    """The capsule corpus's base cases in manifest order.

    ``provenance`` is recorded when the released case carries it; a case
    without it was released before provenance was recorded and keeps that
    writer's ASCII escaping. ``preimages`` adds the Capsule ID preimages to
    expected.json. A case with ``frozen`` set is a legacy-format fixture:
    only its manifest entry is written, read from its released expected.json.
    """
    cases: list[dict] = []

    def add(name, kind, description, inp, provenance=SPEC_DERIVED, preimages=True):
        cases.append({"name": name, "kind": kind, "description": description, "input": inp,
                      "provenance": provenance, "preimages": preimages})

    def frozen(name):
        cases.append({"name": name, "frozen": True})

    # ---- IDENTITY PROFILE: format 4 ----
    current = seal_v4({
        **ident_v4("v4-chain", spec_version=COMPAT_SPEC),
        "assurance": assurance("not_applicable", ledger_mode="chained"),
        "disposition": {
            "decision": "accept",
            "approver": "policy",
            "human_disposed": False,
            "verdict_class": "executed",
        },
        "chain": {
            "parent_capsule_id": "a" * 64,
            "relation": "confirms",
        },
        "constraints": [],
    })
    add(
        "pos-v4-jcs-chain-committed",
        "positive",
        "Format 4 plain JCS commits the chain block and a present empty array to capsule_id.",
        current,
        provenance=None,
        preimages=False,
    )

    frozen("neg-v3-format-version-unsupported")

    chain_tampered = json.loads(json.dumps(current))
    chain_tampered["chain"]["relation"] = "supersedes"
    add(
        "neg-v4-chain-tampered",
        "negative",
        "Changing a format-4 chain member after sealing causes capsule_id mismatch.",
        chain_tampered,
        provenance=None,
        preimages=False,
    )

    missing_declaration = dict(current)
    missing_declaration.pop("canonicalization_id")
    add(
        "neg-v4-canonicalization-missing",
        "negative",
        "Format 4 without canonicalization_id is a profile mismatch.",
        missing_declaration,
        preimages=False,
    )

    for name, declaration, description in (
        (
            "neg-v4-canonicalization-jcs-n",
            "jcs-n",
            "Format 4 explicitly declaring withdrawn jcs-n is rejected.",
        ),
        (
            "neg-v4-canonicalization-non-string",
            7,
            "Format 4 declaring a non-string canonicalization identifier is rejected.",
        ),
    ):
        malformed = dict(current)
        malformed["canonicalization_id"] = declaration
        add(name, "negative", description, malformed, preimages=False)

    frozen("neg-v2-canonicalization-absent")
    frozen("neg-v2-canonicalization-null")

    # ---- POSITIVE: identity + verdict_class categories ----
    add("pos-executed-confirmed", "positive",
        "Clean executed capsule: confirmed effect (gate_executed), full identity, no verdict_class reason.",
        c_executed())
    add("pos-blocked", "positive",
        "blocked: a blocking constraint stopped it pre-dispatch; no effect, effect_mode not_applicable.",
        c_verdict("po-blocked", "blocked", "reject", "policy", False))
    add("pos-denied", "positive",
        "denied: operator/policy refused pre-dispatch; not_applicable.",
        c_verdict("po-denied", "denied", "reject", "human", True))
    add("pos-hitl-dispatched", "positive",
        "hitl_dispatched: routed to a human, awaiting resolution; not_applicable, human_disposed false.",
        c_verdict("po-hitl", "hitl_dispatched", "needs_input", "human", False))
    add("pos-deferred", "positive",
        "deferred: a human postponed the decision; human_disposed true, not_applicable.",
        c_verdict("po-deferred", "deferred", "deferred", "human", True))
    add("pos-errored", "positive",
        "errored: action ran and threw, state unknown; effect dispatched -> dispatched_unconfirmed, attestation present.",
        c_verdict("po-errored", "errored", "accept", "human", True,
                  effect={"status": "dispatched", "type": "write_order", "request_digest": HEX_R, "effect_attestation": "runtime_claimed"},
                  effect_mode="dispatched_unconfirmed"))
    add("pos-timeout-pre-dispatch", "positive",
        "timeout before dispatch: no effect -> not_applicable (one timeout value covers both, per §5.4.2).",
        c_verdict("po-timeout-pre", "timeout", "needs_input", "policy", False))
    add("pos-timeout-post-dispatch", "positive",
        "timeout after dispatch: effect dispatched -> dispatched_unconfirmed, attestation present.",
        c_verdict("po-timeout-post", "timeout", "accept", "human", True,
                  effect={"status": "dispatched", "type": "send_payment", "request_digest": HEX_R, "effect_attestation": "runtime_claimed"},
                  effect_mode="dispatched_unconfirmed"))

    # ---- POSITIVE: full effect_attestation matrix ----
    add("pos-confirmed-runtime-claimed", "positive",
        "confirmed -> effect_attestation REQUIRED (runtime_claimed variant).",
        c_matrix("po-conf-rc", {"status": "confirmed", "type": "write_order", "response_digest": HEX_R, "effect_attestation": "runtime_claimed"}, "confirmed"))
    add("pos-dispatched-unconfirmed-required", "positive",
        "dispatched_unconfirmed -> effect_attestation REQUIRED (present).",
        c_matrix("po-disp", {"status": "dispatched", "type": "write_order", "request_digest": HEX_R, "effect_attestation": "gate_executed"}, "dispatched_unconfirmed", verdict_class="executed"))
    add("pos-not-applicable-absent", "positive",
        "not_applicable -> effect_attestation MUST be absent (no effect record).",
        c_verdict("po-na", "blocked", "reject", "policy", False))
    add("pos-planned-carve", "positive",
        "planned carve: effect.status planned -> not_applicable, effect_attestation absent; no digests.",
        c_matrix("po-planned", {"status": "planned", "type": "write_order"}, "not_applicable", verdict_class="needs_decision"))
    add("pos-failed-required", "positive",
        "failed -> dispatched_unconfirmed, effect_attestation REQUIRED (present). (§6 NOTE, conformant side.)",
        c_matrix("po-failed", {"status": "failed", "type": "write_order", "effect_attestation": "runtime_claimed"}, "dispatched_unconfirmed", verdict_class="errored"))
    add("pos-reverted-required", "positive",
        "reverted -> dispatched_unconfirmed, effect_attestation REQUIRED; underlying effect via external_ref.",
        c_matrix("po-reverted", {"status": "reverted", "type": "send_payment", "external_ref": "payment:42", "effect_attestation": "runtime_claimed"}, "dispatched_unconfirmed", verdict_class="errored"))

    # ---- POSITIVE: unknown registry values (informational, never rejected) ----
    add("pos-unknown-effect-attestation", "positive",
        "unknown effect_attestation value: informational + graded no stronger than runtime_claimed; ok stays true.",
        c_matrix("po-unk-ea", {"status": "confirmed", "type": "write_order", "response_digest": HEX_R, "effect_attestation": "tee_anchored"}, "confirmed"))
    add("pos-unknown-verdict-class", "positive",
        "unknown verdict_class value: informational finding, ok stays true.",
        c_verdict("po-unk-vc", "custom_review", "needs_input", "policy", False))
    add("pos-unknown-effect-type", "positive",
        "unknown effect.type value: informational finding, ok stays true.",
        c_matrix("po-unk-type", {"status": "confirmed", "type": "teleport_goods", "response_digest": HEX_R, "effect_attestation": "gate_executed"}, "confirmed"))

    # ---- POSITIVE: chain / store ----
    parent = c_verdict("po-parent-hitl", "hitl_dispatched", "needs_input", "human", False)
    resolution = seal({
        **ident("po-resolution"),
        "effect": {"status": "confirmed", "type": "write_order", "response_digest": HEX_R, "effect_attestation": "gate_executed"},
        "assurance": assurance("confirmed", ledger_mode="chained"),
        "disposition": {"decision": "accept", "approver": "human", "human_disposed": True, "verdict_class": "executed"},
        "chain": {"parent_capsule_id": parent["capsule_id"], "relation": "supersedes"},
    })
    add("pos-supersedes-chain", "store",
        "supersedes chain: a hitl_dispatched parent + a superseding resolution capsule; parent's open item is resolved.",
        {"ledger": [parent, resolution]})

    parent2 = c_verdict("po-parent2", "hitl_dispatched", "needs_input", "human", False)
    res_a = seal({**ident("po-res-a"), "assurance": assurance("not_applicable", ledger_mode="chained"),
                  "disposition": {"decision": "reject", "approver": "human", "human_disposed": True, "verdict_class": "resolved"},
                  "chain": {"parent_capsule_id": parent2["capsule_id"], "relation": "supersedes"}})
    res_b = seal({**ident("po-res-b"), "assurance": assurance("not_applicable", ledger_mode="chained"),
                  "disposition": {"decision": "reject", "approver": "human", "human_disposed": True, "verdict_class": "resolved"},
                  "chain": {"parent_capsule_id": parent2["capsule_id"], "relation": "supersedes"}})
    add("pos-concurrent-supersedes", "store",
        "two supersedes over one parent: earliest in ledger order is authoritative; the later one surfaces an info finding; both remain ok.",
        {"ledger": [parent2, res_a, res_b]})

    # ---- POSITIVE/OVERCLAIM: cross-party assurance rung (§5.3 Cross-party assurance) ----
    cp_disp = {"decision": "accept", "approver": "human", "human_disposed": True, "verdict_class": "executed"}
    add("pos-cross-party-full-bilateral", "positive",
        "full_bilateral: initiator_ref + counterparty_ref + correlator all present, substantive result -> verifies clean.",
        seal({**ident("cp-full"), "assurance": assurance("not_applicable", cross_party_rung="full_bilateral"),
              "disposition": cp_disp, "cross_party": cross_party_block(has_counterparty=True, substantive=True)}))
    add("pos-cross-party-acknowledged-receipt", "positive",
        "acknowledged_receipt: initiator_ref + counterparty_ref + correlator present, bare receipt (no substantive result) -> verifies clean.",
        seal({**ident("cp-ack"), "assurance": assurance("not_applicable", cross_party_rung="acknowledged_receipt"),
              "disposition": cp_disp, "cross_party": cross_party_block(has_counterparty=True, substantive=False)}))
    add("pos-cross-party-unilateral-fallback", "positive",
        "unilateral_fallback: only initiator_ref present, no counterparty evidence -> verifies clean.",
        seal({**ident("cp-uni"), "assurance": assurance("not_applicable", cross_party_rung="unilateral_fallback"),
              "disposition": cp_disp, "cross_party": cross_party_block(has_counterparty=False)}))
    add("neg-cross-party-overclaim", "overclaim",
        "the named overclaim case: full_bilateral claimed with only the initiator's signed half present "
        "(no counterparty_ref) -> assurance_overclaim (check 7, info severity, non-gating), "
        "derived.cross_party_rung downgraded to unilateral_fallback.",
        seal({**ident("cp-overclaim"), "assurance": assurance("not_applicable", cross_party_rung="full_bilateral"),
              "disposition": cp_disp, "cross_party": cross_party_block(has_counterparty=False)}))
    add("pos-disposition-approver-counterparty", "positive",
        "disposition.approver='counterparty': a valid third member of the closed approver enum; "
        "human_disposed stays false, confirming the honesty invariant (human_disposed=true REQUIRES "
        "approver='human') still holds against the new value.",
        seal({**ident("cp-approver"), "assurance": assurance("not_applicable"),
              "disposition": {"decision": "accept", "approver": "counterparty", "human_disposed": False, "verdict_class": "executed"}}))

    # ---- NEGATIVE: MUST-reject (ok=false) ----
    add("neg-confirmed-without-response", "negative",
        "confirmed effect with NO response_digest -> confirmed-effect binding failure (check 3).",
        seal({**ident("neg-conf"), "effect": {"status": "confirmed", "type": "write_order", "effect_attestation": "gate_executed"},
              "assurance": assurance("dispatched_unconfirmed"),
              "disposition": {"decision": "accept", "approver": "human", "human_disposed": True}}))

    float_cap = {**ident("neg-float"), "effect": {"status": "confirmed", "type": "write_order", "response_digest": HEX_R, "effect_attestation": "gate_executed", "amount": 12.5},
                 "assurance": assurance("confirmed"), "disposition": {"decision": "accept", "approver": "human", "human_disposed": True},
                 "capsule_id": "0" * 64}  # cannot recompute over a float; carried id is a placeholder
    float_cap = released_layout(float_cap)
    add("neg-float-in-digest-field", "negative",
        "a JSON floating-point value in a digest-bearing field -> structural failure (check 1, §5.1).",
        float_cap)

    # Historical format-2 guard: an integer beyond the IEEE-754-double safe range
    # (2^53-1) is a cross-implementation digest-reproducibility hazard. The
    # current draft codifies the bound; this vector preserves coverage for the
    # older wire profile that first exposed it.
    unsafe_int_cap = {**ident("neg-unsafeint"),
                      "effect": {"status": "confirmed", "type": "write_order", "response_digest": HEX_R,
                                 "effect_attestation": "gate_executed", "amount": 2**53},
                      "assurance": assurance("confirmed"),
                      "disposition": {"decision": "accept", "approver": "human", "human_disposed": True},
                      "capsule_id": "0" * 64}  # cannot recompute over an unsafe int; carried id is a placeholder
    unsafe_int_cap = released_layout(unsafe_int_cap)
    add("neg-unsafe-integer-in-digest-field", "negative",
        "an integer beyond 2^53-1 in a digest-bearing field -> structural failure (check 1); "
        "the current draft requires large integers to be decimal strings.",
        unsafe_int_cap)

    add("neg-attestation-present-when-not-applicable", "negative",
        "planned (not_applicable) with effect_attestation present -> matrix failure (check 5).",
        c_matrix("neg-planned-att", {"status": "planned", "type": "write_order", "effect_attestation": "gate_executed"}, "not_applicable", verdict_class="needs_decision"))
    add("neg-attestation-missing-when-required", "negative",
        "failed (dispatched_unconfirmed) with effect_attestation absent -> matrix failure (check 5, the §6 NOTE).",
        c_matrix("neg-failed-noatt", {"status": "failed", "type": "write_order"}, "dispatched_unconfirmed", verdict_class="errored"))
    add("neg-never-dispatch-conflict", "negative",
        "never-dispatch verdict_class (blocked) with a dispatched effect (dispatched_unconfirmed) -> orthogonality failure (check 4).",
        c_verdict("neg-ortho", "blocked", "reject", "policy", False,
                  effect={"status": "dispatched", "type": "write_order", "request_digest": HEX_R, "effect_attestation": "runtime_claimed"},
                  effect_mode="dispatched_unconfirmed"))

    tampered = c_executed()
    # The released case kept the capsule_id it carried as format 2 (-00).
    tampered["capsule_id"] = json_digest({
        **{key: val for key, val in tampered.items() if key not in ("capsule_id", "canonicalization_id")},
        "format_version": "2",
        "spec_version": "draft-mih-scitt-agent-action-capsule-00",
    })
    tampered["operator"] = "TAMPERED-CO"  # mutate a field WITHOUT resealing capsule_id
    add("neg-capsule-id-mismatch", "negative",
        "a field mutated after sealing: capsule_id no longer recomputes over the canonical form (check 2).",
        tampered)

    orphan = seal({**ident("neg-orphan"),
                   "effect": {"status": "confirmed", "type": "write_order", "response_digest": HEX_R, "effect_attestation": "gate_executed"},
                   "assurance": assurance("confirmed", ledger_mode="chained"),
                   "disposition": {"decision": "accept", "approver": "human", "human_disposed": True, "verdict_class": "executed"},
                   "chain": {"parent_capsule_id": MISSING_PARENT, "relation": "supersedes"}})
    add("neg-chain-missing-parent", "store",
        "a chain referencing a parent_capsule_id not present in the store -> chain failure (check 6).",
        {"ledger": [orphan]})

    add("neg-approver-invalid", "negative",
        "disposition.approver outside the closed {human, policy} enum (neutral invalid token) -> structural failure (check 1, §5.4).",
        seal({**ident("neg-approver"), "assurance": assurance("not_applicable"),
              "disposition": {"decision": "reject", "approver": "vendor_bot", "human_disposed": False, "verdict_class": "denied"}}))

    # ---- HONESTY (per §6 / A1): non-gating defensive warning, ok still reflects gating checks ----
    add("honesty-dishonest-human-disposed", "honesty",
        "human_disposed=true with a non-human (policy) approver in parsed bytes: §6 makes this a structurally-guaranteed invariant, so the verifier reports a NON-GATING defensive warning; ok still reflects the gating checks (here, true).",
        seal({**ident("honesty-1"),
              "effect": {"status": "confirmed", "type": "write_order", "response_digest": HEX_R, "effect_attestation": "gate_executed"},
              "assurance": assurance("confirmed"),
              "disposition": {"decision": "accept", "approver": "policy", "human_disposed": True, "verdict_class": "executed"}}))

    # ---- Hardening pass (W9) ----
    frozen("neg-format-version-unknown")
    add("neg-never-dispatch-with-dispatched-effect", "negative",
        "blocked verdict_class (NEVER_DISPATCH §5.4.2) combined with effect.status='dispatched' → verdict/effect orthogonality failure (check 4).",
        seal({**ident("neg-nd-001"), "assurance": assurance("dispatched_unconfirmed"),
              "disposition": {"decision": "reject", "approver": "policy", "human_disposed": False, "verdict_class": "blocked"},
              "effect": {"status": "dispatched", "type": "write_order", "request_digest": "a" * 64, "effect_attestation": "runtime_claimed"}}))
    add("neg-never-dispatch-confirmed-no-response", "negative",
        "denied (NEVER_DISPATCH) with effect.status='confirmed' and no response_digest → both check 3 (confirmed-effect binding) and check 4 (verdict/effect conflict).",
        seal({**ident("neg-nd-002"), "assurance": assurance("dispatched_unconfirmed"),
              "disposition": {"decision": "reject", "approver": "policy", "human_disposed": False, "verdict_class": "denied"},
              "effect": {"status": "confirmed", "type": "write_order", "effect_attestation": "gate_executed"}}))

    return cases


# ---- Provenance mode vectors (§5.3(bis), draft -05) ------------------------
# Written to a SEPARATE directory (PM_OUT), not vectors/capsule/: vectors/capsule/ is
# the historical checks-1-8 corpus (go/cmd/vector_runner reads vectors/capsule/
# vectors.json and expects every listed case to verify identically under the Go
# reference implementation). provenance_mode (check 9) IS ported to Go
# (go/verify's TestProvenanceModeVectors asserts this same expected.json), so
# this corpus is cross-language too; it stays in its own directory rather than
# merging into vectors/capsule/ to avoid disturbing that corpus's own manifest
# and generation. The domain/provenance (-02) addendum remains a separate,
# still Python-only surface Go does not implement.
def build_provenance_mode_cases(spec_version: str = RELEASED_PM_SPEC) -> list[dict]:
    cases: list[dict] = []

    def ident(action_id: str, action_type: str = "decide") -> dict:
        return ident_v4(action_id, action_type, spec_version)

    def add(name, kind, description, inp):
        cases.append({"name": name, "kind": kind, "description": description, "input": inp})

    add("pos-provenance-mode-backfilled", "positive",
        "a well-formed backfilled record: provenance_mode.mode='backfilled' with all four "
        "REQUIRED companion fields present and well-formed, time_rung absent (implies "
        "self_attested) -> verifies clean; derived.provenance_mode='backfilled' and "
        "derived.provenance_time_rung='self_attested' are always reported (check 9).",
        seal_v4({**ident("prov-backfilled"), "assurance": assurance("not_applicable"),
              "disposition": {"decision": "accept", "approver": "policy", "human_disposed": False, "verdict_class": "executed"},
              "provenance_mode": provenance_mode_backfilled()}))

    add("neg-provenance-mode-time-rung-overclaim", "negative",
        "provenance_mode.time_rung='witnessed' claimed with no references[] entry citing "
        "citation_purpose='corroborates_source_time' -> provenance_time_rung_overclaim "
        "(check 9, gating — unlike the informational overclaim treatment check 7 gives "
        "attestation_mode/ledger_mode/cross_party_rung, this profile treats an unsupported "
        "provenance_mode time claim as a falsifiable dishonesty claim); "
        "derived.provenance_time_rung stays 'self_attested', the rederived value, never the claim.",
        seal_v4({**ident("prov-witnessed-overclaim"), "assurance": assurance("not_applicable"),
              "disposition": {"decision": "accept", "approver": "policy", "human_disposed": False, "verdict_class": "executed"},
              "provenance_mode": provenance_mode_backfilled(time_rung="witnessed")}))

    add("neg-provenance-mode-backfilled-missing-fields", "negative",
        "provenance_mode.mode='backfilled' with none of the four REQUIRED companion fields "
        "(source_ref, source_asserted_at, import_batch, imported_at) present -> four "
        "provenance_mode_missing_required_field failures (check 9).",
        seal_v4({**ident("prov-missing-fields"), "assurance": assurance("not_applicable"),
              "disposition": {"decision": "accept", "approver": "policy", "human_disposed": False, "verdict_class": "executed"},
              "provenance_mode": {"mode": "backfilled"}}))

    add("neg-provenance-mode-time-laundering", "negative",
        "provenance_mode.imported_at equals source_asserted_at on a backfilled record -- the "
        "shape a laundering producer would construct to make an import look contemporaneous "
        "-> provenance_time_laundering_shape (check 9, gating); equality is never treated as "
        "corroboration, regardless of any other assurance value the record carries.",
        seal_v4({**ident("prov-laundering"), "assurance": assurance("not_applicable"),
              "disposition": {"decision": "accept", "approver": "policy", "human_disposed": False, "verdict_class": "executed"},
              "provenance_mode": provenance_mode_backfilled(
                  source_asserted_at="2026-09-22T00:00:00Z", imported_at="2026-09-22T00:00:00Z")}))

    prov_contemporaneous = seal_v4({**ident("prov-contemporaneous-parent"),
                                  "assurance": assurance("not_applicable"),
                                  "disposition": {"decision": "accept", "approver": "policy", "human_disposed": False, "verdict_class": "executed"}})
    prov_duplicate = seal_v4({**ident("prov-backfilled-duplicate"),
                            "assurance": assurance("not_applicable", ledger_mode="chained"),
                            "disposition": {"decision": "accept", "approver": "policy", "human_disposed": False, "verdict_class": "executed"},
                            "provenance_mode": provenance_mode_backfilled(),
                            "chain": {"parent_capsule_id": prov_contemporaneous["capsule_id"], "relation": "duplicates"}})
    add("pos-chain-duplicates-collapsed-once", "store",
        "a backfilled import of the same logical event a contemporaneous capsule already "
        "recorded, chained to it via chain.relation='duplicates': both capsules verify ok; "
        "the store-level pass reports duplicate_collapsed (info, check 9) on the backfilled "
        "member -- verifiers and downstream evidence evaluators count the pair once, the "
        "contemporaneous record governing, never twice.",
        {"ledger": [prov_contemporaneous, prov_duplicate]})

    # ---- ADDED (bounce): 6 branches the check-9 Go port carried by reading only ----
    # Each case below is generated from the Python reference and asserted by BOTH
    # languages via the (check, severity, code) + derived + ok parity mechanism.

    # (1) invalid mode: an unknown mode string is neither backfilled nor
    # contemporaneous, so provenance_mode_invalid fires and derived.provenance_mode
    # is NEVER set (the else-branch that records it is skipped) — the backfilled and
    # contemporaneous sub-checks are both skipped, so this is the ONLY check-9
    # finding and derived carries no provenance_mode / provenance_time_rung key.
    add("neg-provenance-mode-invalid-mode", "negative",
        "provenance_mode.mode='fabricated' is outside the closed {backfilled, contemporaneous} "
        "enum -> provenance_mode_invalid (check 9, gating); derived.provenance_mode is left "
        "UNSET (only a recognized mode is ever recorded) and no backfilled/contemporaneous "
        "sub-checks run.",
        seal_v4({**ident("prov-invalid-mode"), "assurance": assurance("not_applicable"),
              "disposition": {"decision": "accept", "approver": "policy", "human_disposed": False, "verdict_class": "executed"},
              "provenance_mode": {"mode": "fabricated"}}))

    # (2) invalid time_rung: an unknown time_rung on an otherwise well-formed
    # backfilled record -> provenance_mode_invalid, and the reference verifier
    # RESETS time_rung to None (excluded from the derived cap) so it is NOT then
    # treated as a witnessed overclaim; derived.provenance_time_rung stays
    # 'self_attested' (no corroborating reference present).
    add("neg-provenance-mode-invalid-time-rung", "negative",
        "provenance_mode.time_rung='notarized' is outside the closed {self_attested, witnessed} "
        "enum on an otherwise well-formed backfilled record -> a single provenance_mode_invalid "
        "(check 9, gating); the unrecognized value is reset (time_rung=None) so it is NOT also "
        "treated as a witnessed overclaim, and derived.provenance_time_rung stays 'self_attested'.",
        seal_v4({**ident("prov-invalid-time-rung"), "assurance": assurance("not_applicable"),
              "disposition": {"decision": "accept", "approver": "policy", "human_disposed": False, "verdict_class": "executed"},
              "provenance_mode": provenance_mode_backfilled(time_rung="notarized")}))

    # (3a) source_ref malformed — non-object when present: source_ref is a string,
    # so the object-shape check fires (the elif '"source_ref" in pm' branch).
    add("neg-provenance-mode-source-ref-not-object", "negative",
        "provenance_mode.source_ref present but a non-object (string) on a backfilled record "
        "-> provenance_mode_source_ref_malformed (check 9, gating; the source_ref-MUST-be-object "
        "branch). All other backfilled companion fields are present and well-formed.",
        seal_v4({**ident("prov-source-ref-not-object"), "assurance": assurance("not_applicable"),
              "disposition": {"decision": "accept", "approver": "policy", "human_disposed": False, "verdict_class": "executed"},
              "provenance_mode": {**provenance_mode_backfilled(source_ref=False),
                                  "source_ref": "x-external-ledger-entry"}}))

    # (3b) source_ref malformed — present object missing a REQUIRED subfield: the
    # object-shape check passes, but the per-subfield loop reports the missing
    # 'digest' as provenance_mode_source_ref_malformed.
    add("neg-provenance-mode-source-ref-missing-subfield", "negative",
        "provenance_mode.source_ref is a well-formed object but MISSING the REQUIRED 'digest' "
        "subfield on a backfilled record -> provenance_mode_source_ref_malformed (check 9, "
        "gating; the per-subfield branch). type and digest_alg are present.",
        seal_v4({**ident("prov-source-ref-missing-subfield"), "assurance": assurance("not_applicable"),
              "disposition": {"decision": "accept", "approver": "policy", "human_disposed": False, "verdict_class": "executed"},
              "provenance_mode": {**provenance_mode_backfilled(source_ref=False),
                                  "source_ref": {"type": "x-external-ledger-entry", "digest_alg": "SHA-256"}}}))

    # (4) contemporaneous with orphaned fields: mode='contemporaneous' MUST carry
    # none of the backfilled-only companion fields; a present-and-non-null source_ref
    # is orphaned -> provenance_mode_invalid. derived.provenance_mode='contemporaneous'
    # (a recognized mode) is still recorded; derived.provenance_time_rung is NOT set
    # (that cap is only rederived on the backfilled branch).
    add("neg-provenance-mode-contemporaneous-orphaned-fields", "negative",
        "provenance_mode.mode='contemporaneous' carrying a backfilled-only companion field "
        "(source_ref present and non-null) -> provenance_mode_invalid (check 9, gating; the "
        "orphaned-fields branch, presence-and-non-null). derived.provenance_mode='contemporaneous' "
        "is still recorded; no provenance_time_rung cap is derived for a contemporaneous record.",
        seal_v4({**ident("prov-contemporaneous-orphaned"), "assurance": assurance("not_applicable"),
              "disposition": {"decision": "accept", "approver": "policy", "human_disposed": False, "verdict_class": "executed"},
              "provenance_mode": {"mode": "contemporaneous",
                                  "source_ref": {"type": "x-external-ledger-entry", "digest_alg": "SHA-256", "digest": "3" * 64}}}))

    # (5) witnessed WITH corroboration: the ONLY path that rederives
    # derived.provenance_time_rung='witnessed'. A backfilled record claims
    # time_rung='witnessed' AND carries a well-formed references[] entry citing
    # citation_purpose='corroborates_source_time' (non-empty type/digest_alg/digest)
    # -> verifies clean (no overclaim), derived.provenance_time_rung='witnessed'.
    add("pos-provenance-mode-witnessed-corroborated", "positive",
        "a backfilled record claiming provenance_mode.time_rung='witnessed' WITH a well-formed "
        "references[] entry citing citation_purpose='corroborates_source_time' (all of "
        "type/digest_alg/digest non-empty) -> verifies clean; this is the ONLY case where "
        "derived.provenance_time_rung='witnessed' (the cap rederived from cited evidence, "
        "not from the claim).",
        seal_v4({**ident("prov-witnessed-corroborated"), "assurance": assurance("not_applicable"),
              "disposition": {"decision": "accept", "approver": "policy", "human_disposed": False, "verdict_class": "executed"},
              "provenance_mode": provenance_mode_backfilled(time_rung="witnessed"),
              "references": [{"type": "x-witnessed-timestamp", "digest_alg": "SHA-256", "digest": "4" * 64,
                              "citation_purpose": "corroborates_source_time"}]}))

    # (6) duplicate_parent_not_contemporaneous: the store-level 'duplicates' pass.
    # When a 'duplicates'-linked child's parent is ITSELF backfilled (not the
    # contemporaneous record 'duplicates' is defined to cite), the pass reports
    # duplicate_collapsed AND duplicate_parent_not_contemporaneous (both info, check 9)
    # on the child; both members remain ok.
    dup_backfilled_parent = seal_v4({**ident("prov-backfilled-parent"),
                                   "assurance": assurance("not_applicable"),
                                   "disposition": {"decision": "accept", "approver": "policy", "human_disposed": False, "verdict_class": "executed"},
                                   "provenance_mode": provenance_mode_backfilled()})
    dup_backfilled_child = seal_v4({**ident("prov-backfilled-child"),
                                  "assurance": assurance("not_applicable", ledger_mode="chained"),
                                  "disposition": {"decision": "accept", "approver": "policy", "human_disposed": False, "verdict_class": "executed"},
                                  "provenance_mode": provenance_mode_backfilled(),
                                  "chain": {"parent_capsule_id": dup_backfilled_parent["capsule_id"], "relation": "duplicates"}})
    add("pos-chain-duplicates-parent-backfilled", "store",
        "a 'duplicates'-linked pair whose parent is ITSELF provenance_mode.mode='backfilled' "
        "(not the contemporaneous record 'duplicates' is defined to cite): the store-level pass "
        "reports BOTH duplicate_collapsed AND duplicate_parent_not_contemporaneous (both info, "
        "check 9) on the child; both members remain ok.",
        {"ledger": [dup_backfilled_parent, dup_backfilled_child]})

    return cases


def result_to_expected(res) -> dict:
    return {
        "ok": res.ok,
        "derived": res.assurance,
        "capsule_id_recomputed": res.capsule_id,
        "findings": [{"check": f.check, "severity": f.severity, "code": f.code, "detail": f.detail} for f in res.findings],
    }


def capsule_expected(case: dict) -> dict:
    """expected.json: the sorted result, then provenance, then any preimages."""
    inp = case["input"]
    if isinstance(inp, dict) and "ledger" in inp:
        base = {"description": case["description"], "kind": case["kind"],
                "results": [result_to_expected(r) for r in verify_store(inp["ledger"])]}
        preimages = ledger_preimages(inp["ledger"])
    else:
        result = result_to_expected(verify(inp))
        base = {"description": case["description"], "kind": case["kind"], **result}
        preimages = {"capsule_id": preimage(inp)} if result["capsule_id_recomputed"] else None
    expected = sort_members(base)
    if case["provenance"]:
        expected["provenance"] = case["provenance"]
    if case["preimages"] and preimages:
        expected["canonical_preimages"] = preimages
    return expected


def write_capsule_corpus() -> None:
    """Write the base cases and a manifest of them; later generators append theirs."""
    OUT.mkdir(exist_ok=True)
    manifest = []
    for case in build_cases():
        name = case["name"]
        if case.get("frozen"):
            released = json.loads((OUT / name / "expected.json").read_text(encoding="utf-8"))
            manifest.append({"name": name, "kind": released["kind"], "description": released["description"],
                             "provenance": released["provenance"]})
            continue
        case_dir = OUT / name
        case_dir.mkdir(exist_ok=True)
        ascii_only = not case["provenance"]
        for file_name, value in (("input.json", case["input"]), ("expected.json", capsule_expected(case))):
            (case_dir / file_name).write_text(
                json.dumps(value, indent=2, ensure_ascii=ascii_only) + "\n", encoding="utf-8"
            )
        entry = {"name": name, "kind": case["kind"], "description": case["description"]}
        if case["provenance"]:
            entry["provenance"] = case["provenance"]
        manifest.append(entry)

    # "spec" is the newest revision every listed case verifies under;
    # generate_v05_vectors.py raises it when it adds the -05 cases.
    (OUT / "vectors.json").write_text(
        dumps({"format_versions": ["4"], "spec": COMPAT_SPEC, "count": len(manifest), "cases": manifest}),
        encoding="utf-8",
    )
    print(f"wrote {len(manifest)} vectors to {OUT}")


def write_provenance_mode_corpus() -> None:
    PM_OUT.mkdir(exist_ok=True)
    pm_manifest = []
    twins = [
        {**case, "name": f"{case['name']}-v05",
         "description": f"-05 twin of {case['name']} (only spec_version differs): {case['description']}"}
        for case in build_provenance_mode_cases(CURRENT_SPEC)
    ]
    for case in [*build_provenance_mode_cases(), *twins]:
        name, kind, desc, inp = case["name"], case["kind"], case["description"], case["input"]
        case_dir = PM_OUT / name
        case_dir.mkdir(exist_ok=True)

        if isinstance(inp, dict) and "ledger" in inp:
            results = verify_store(inp["ledger"])
            expected = {"description": desc, "kind": kind,
                        "results": [result_to_expected(r) for r in results]}
        else:
            res = verify(inp)
            expected = {"description": desc, "kind": kind, **result_to_expected(res)}

        (case_dir / "input.json").write_text(json.dumps(inp, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (case_dir / "expected.json").write_text(json.dumps(expected, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        pm_manifest.append({"name": name, "kind": kind, "description": desc})

    (PM_OUT / "vectors.json").write_text(
        json.dumps({"spec": "draft-mih-scitt-agent-action-capsule-05",
                    "count": len(pm_manifest), "cases": pm_manifest}, indent=2) + "\n",
        encoding="utf-8",
    )
    pm_checksum_lines = []
    for path in sorted(PM_OUT.glob("*/*.json")):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        pm_checksum_lines.append(f"{digest}  {path.relative_to(PM_OUT)}")
    (PM_OUT / "SHA256SUMS").write_text("\n".join(pm_checksum_lines) + "\n", encoding="ascii")
    print(f"wrote {len(pm_manifest)} vectors to {PM_OUT}")


CORPORA = {
    "capsule": write_capsule_corpus,
    "provenance-mode": write_provenance_mode_corpus,
}


def main(argv: list[str] | None = None) -> None:
    """Write the named corpora (default: all), e.g.
    ``python scripts/generate_vectors.py provenance-mode``.
    """
    names = list(argv if argv is not None else sys.argv[1:]) or list(CORPORA)
    unknown = [name for name in names if name not in CORPORA]
    if unknown:
        raise SystemExit(f"unknown corpus {unknown!r}; choose from {sorted(CORPORA)}")
    for name in names:
        CORPORA[name]()


if __name__ == "__main__":
    main()
