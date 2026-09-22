# SPDX-License-Identifier: BSD-3-Clause
"""Generate the frozen conformance vectors in ../../vectors/capsule/ and
../../vectors/disclosure-envelope/.

Vectors are DERIVED from the spec-faithful reference verifier and then FROZEN
(the same discipline as golden digests): each case's expected.json is produced
by running verify()/verify_store() over a hand-built input, and committed. A
third party regenerates the capsule_id and checks ok + the §6 check numbers +
derived modes against the spec text, without running this package.

vectors/capsule/ is the Class-1 corpus and is cross-language-shared (the go/
reference implementation's vector_runner reads vectors/capsule/vectors.json
directly), so every case there is a bare Capsule or {"ledger": [...]}.
vectors/disclosure-envelope/ is a separate corpus, in the same frozen-vector
style, for the Disclosure Envelope companion profile's {"envelope": {...}}
input shape — kept out of vectors/capsule/ so it never needs Go-side support to
keep that corpus's cross-language conformance run passing.

Run:  cd python && python -m scripts.generate_vectors
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from agent_action_capsule import (
    compute_capsule_id,
    json_digest,
    verify,
    verify_disclosure_envelope,
    verify_store,
)

OUT = Path(__file__).resolve().parents[2] / "vectors/capsule"
DE_OUT = Path(__file__).resolve().parents[2] / "vectors/disclosure-envelope"
PM_OUT = Path(__file__).resolve().parents[2] / "provenance-mode-vectors"
VINTAGE_SPEC = "draft-mih-scitt-agent-action-capsule-00"
CURRENT_SPEC = "draft-mih-scitt-agent-action-capsule-04"
HEX_R = "1" * 64  # a stand-in response/request digest (64-hex); content is opaque here
HEX_R2 = "2" * 64
MISSING_PARENT = "9" * 64


def ident(action_id: str, action_type: str = "decide") -> dict:
    return {
        "spec_version": VINTAGE_SPEC,
        "format_version": "2",
        "action_id": action_id,
        "action_type": action_type,
        "operator": "ACME-CO",
        "developer": "agent@v1",
        "timestamp": "2026-06-13T00:00:00Z",
    }


def ident_v4(action_id: str, action_type: str = "decide") -> dict:
    """Identity fields for the current declared-JCS serialization suite."""
    return {
        "spec_version": CURRENT_SPEC,
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


def seal(cap: dict) -> dict:
    cap = dict(cap)
    cap.pop("capsule_id", None)
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
    cases: list[dict] = []

    def add(name, kind, description, inp):
        cases.append({"name": name, "kind": kind, "description": description, "input": inp})

    # ---- IDENTITY PROFILE: current format 4 and vintage format 2 ----
    current = seal({
        **ident_v4("v4-chain"),
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
    )

    format3_unsupported = seal({**current, "format_version": "3"})
    add(
        "neg-v3-format-version-unsupported",
        "negative",
        "Format 3 was never published and must fail closed rather than aliasing format 4.",
        format3_unsupported,
    )

    chain_tampered = json.loads(json.dumps(current))
    chain_tampered["chain"]["relation"] = "supersedes"
    add(
        "neg-v4-chain-tampered",
        "negative",
        "Changing a format-4 chain member after sealing causes capsule_id mismatch.",
        chain_tampered,
    )

    missing_declaration = dict(current)
    missing_declaration.pop("canonicalization_id")
    add(
        "neg-v4-canonicalization-missing",
        "negative",
        "Format 4 without canonicalization_id is a profile mismatch.",
        missing_declaration,
    )

    for name, declaration, description in (
        (
            "neg-v4-canonicalization-jcs-n",
            "jcs-n",
            "Format 4 explicitly declaring withdrawn jcs-n is rejected.",
        ),
        (
            "neg-v4-canonicalization-unknown",
            "future-algorithm",
            "Format 4 declaring an unknown canonicalization algorithm is rejected.",
        ),
        (
            "neg-v4-canonicalization-non-string",
            7,
            "Format 4 declaring a non-string canonicalization identifier is rejected.",
        ),
    ):
        malformed = dict(current)
        malformed["canonicalization_id"] = declaration
        add(name, "negative", description, malformed)

    vintage_with_declaration = c_executed()
    vintage_with_declaration["canonicalization_id"] = "jcs"
    add(
        "neg-v2-canonicalization-declared",
        "negative",
        "Format 2 is the absent-field vintage profile and rejects any canonicalization_id declaration.",
        vintage_with_declaration,
    )

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
    tampered = dict(tampered)
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

    return cases


# ---- Disclosure Envelope vectors (draft-mih-scitt-agent-action-capsule-disclosure-envelope-00) ---
# Written to a SEPARATE directory (DE_OUT), not vectors/capsule/: the envelope input shape
# ({"envelope": {...}}) is not a bare Capsule or {"ledger": [...]}, and vectors/capsule/ is
# cross-language-shared (go/cmd/vector_runner reads vectors/capsule/vectors.json and expects
# every listed case to be Class-1-shape). Mixing shapes there would break that Go conformance
# run rather than extend it.
def build_disclosure_envelope_cases() -> list[dict]:
    cases: list[dict] = []

    def add(name, kind, description, inp):
        cases.append({"name": name, "kind": kind, "description": description, "input": inp})

    disclosed_input = {"amount": "500.00", "sku": "PO-9981"}
    envelope_capsule = seal({**c_executed(),
                              "model_attestation": {"compute_attestation": {"agent_input_digest": json_digest(disclosed_input)}}})
    add("pos-disclosure-envelope-match", "positive",
        "Disclosure Envelope whose agent_input disclosure recomputes to the digest committed in "
        "model_attestation.compute_attestation.agent_input_digest: DE-3 reports disclosure_match, and "
        "the wrapped capsule's own capsule_id / Class 1 result is unaffected and still ok.",
        {"envelope": {"capsule": envelope_capsule, "disclosures": {"agent_input": disclosed_input}}})
    add("neg-disclosure-envelope-mismatch", "negative",
        "Disclosure Envelope whose agent_input disclosure does NOT recompute to the committed digest "
        "(same capsule as pos-disclosure-envelope-match, tampered disclosure value): DE-3 reports "
        "disclosure_mismatch and the envelope's ok is false, while the wrapped capsule's own capsule_id "
        "recomputation and Class 1 result are unchanged and still ok — a bad disclosure never gates the "
        "capsule's own verification.",
        {"envelope": {"capsule": envelope_capsule, "disclosures": {"agent_input": {"amount": "999.00", "sku": "PO-9981"}}}})

    return cases


# ---- Provenance mode vectors (§5.3(bis), draft -05) ------------------------
# Written to a SEPARATE directory (PM_OUT), not vectors/capsule/: vectors/capsule/ is
# cross-language-shared (go/cmd/vector_runner reads vectors/capsule/vectors.json
# and expects every listed case to verify identically under the Go reference
# implementation). The Go implementation has never carried the -02 domain/
# provenance addendum either (Class 1 check 9's domain/provenance handling is
# Python-only), so provenance_mode joins that same Python-only surface rather
# than breaking Go conformance on a feature it doesn't implement.
def build_provenance_mode_cases() -> list[dict]:
    cases: list[dict] = []

    def add(name, kind, description, inp):
        cases.append({"name": name, "kind": kind, "description": description, "input": inp})

    add("pos-provenance-mode-backfilled", "positive",
        "a well-formed backfilled record: provenance_mode.mode='backfilled' with all four "
        "REQUIRED companion fields present and well-formed, time_rung absent (implies "
        "self_attested) -> verifies clean; derived.provenance_mode='backfilled' and "
        "derived.provenance_time_rung='self_attested' are always reported (check 9).",
        seal({**ident_v4("prov-backfilled"), "assurance": assurance("not_applicable"),
              "disposition": {"decision": "accept", "approver": "policy", "human_disposed": False, "verdict_class": "executed"},
              "provenance_mode": provenance_mode_backfilled()}))

    add("neg-provenance-mode-time-rung-overclaim", "negative",
        "provenance_mode.time_rung='witnessed' claimed with no references[] entry citing "
        "citation_purpose='corroborates_source_time' -> provenance_time_rung_overclaim "
        "(check 9, gating — unlike the informational overclaim treatment check 7 gives "
        "attestation_mode/ledger_mode/cross_party_rung, this profile treats an unsupported "
        "provenance_mode time claim as a falsifiable dishonesty claim); "
        "derived.provenance_time_rung stays 'self_attested', the rederived value, never the claim.",
        seal({**ident_v4("prov-witnessed-overclaim"), "assurance": assurance("not_applicable"),
              "disposition": {"decision": "accept", "approver": "policy", "human_disposed": False, "verdict_class": "executed"},
              "provenance_mode": provenance_mode_backfilled(time_rung="witnessed")}))

    add("neg-provenance-mode-backfilled-missing-fields", "negative",
        "provenance_mode.mode='backfilled' with none of the four REQUIRED companion fields "
        "(source_ref, source_asserted_at, import_batch, imported_at) present -> four "
        "provenance_mode_missing_required_field failures (check 9).",
        seal({**ident_v4("prov-missing-fields"), "assurance": assurance("not_applicable"),
              "disposition": {"decision": "accept", "approver": "policy", "human_disposed": False, "verdict_class": "executed"},
              "provenance_mode": {"mode": "backfilled"}}))

    add("neg-provenance-mode-time-laundering", "negative",
        "provenance_mode.imported_at equals source_asserted_at on a backfilled record -- the "
        "shape a laundering producer would construct to make an import look contemporaneous "
        "-> provenance_time_laundering_shape (check 9, gating); equality is never treated as "
        "corroboration, regardless of any other assurance value the record carries.",
        seal({**ident_v4("prov-laundering"), "assurance": assurance("not_applicable"),
              "disposition": {"decision": "accept", "approver": "policy", "human_disposed": False, "verdict_class": "executed"},
              "provenance_mode": provenance_mode_backfilled(
                  source_asserted_at="2026-09-22T00:00:00Z", imported_at="2026-09-22T00:00:00Z")}))

    prov_contemporaneous = seal({**ident_v4("prov-contemporaneous-parent"),
                                  "assurance": assurance("not_applicable"),
                                  "disposition": {"decision": "accept", "approver": "policy", "human_disposed": False, "verdict_class": "executed"}})
    prov_duplicate = seal({**ident_v4("prov-backfilled-duplicate"),
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

    return cases


def result_to_expected(res) -> dict:
    return {
        "ok": res.ok,
        "derived": res.assurance,
        "capsule_id_recomputed": res.capsule_id,
        "findings": [{"check": f.check, "severity": f.severity, "code": f.code, "detail": f.detail} for f in res.findings],
    }


def envelope_result_to_expected(res) -> dict:
    """`ok` here is the overall envelope result (capsule ok AND every disclosure
    matches); the wrapped capsule's own Class 1 result — unaffected by a bad
    disclosure — is nested under `capsule` so the two `ok` values can never
    collide or be conflated by a consumer reading only the top level."""
    return {
        "ok": res.ok,
        "capsule": result_to_expected(res.capsule_result),
        "disclosures_checked": res.disclosures_checked,
        "disclosures_matched": res.disclosures_matched,
        "disclosure_findings": [{"member": f.member, "code": f.code} for f in res.disclosure_findings],
    }


# Hand-authored hardening-pass vectors (the W9 pass) whose input.json/expected.json
# predate this script's case builders and are NOT reproduced by build_cases(). They
# are frozen files this script must not touch; only their manifest entries are
# re-declared here so a full regeneration doesn't drop them from vectors.json.
HAND_AUTHORED_CASES = [
    {"name": "neg-format-version-unknown", "kind": "negative",
     "description": "format_version '1' (old/unknown) must be explicitly rejected — no silent v1/v2 mis-parse (§5.1, W9)."},
    {"name": "neg-never-dispatch-with-dispatched-effect", "kind": "negative",
     "description": "blocked verdict_class (NEVER_DISPATCH §5.4.2) combined with effect.status='dispatched' → verdict/effect orthogonality failure (check 4)."},
    {"name": "neg-never-dispatch-confirmed-no-response", "kind": "negative",
     "description": "denied (NEVER_DISPATCH) with effect.status='confirmed' and no response_digest → both check 3 (confirmed-effect binding) and check 4 (verdict/effect conflict)."},
    # canonical-* (RFC 8785 JCS hardening pass): input.json/expected.json test
    # compute_capsule_id() directly (kind="canonical"), predate this script's
    # case builders, and are NOT reproduced by build_cases(). Frozen files this
    # script must not touch; only their manifest entries are re-declared here
    # so a full regeneration doesn't drop them from vectors.json (this bucket
    # was previously undeclared here and WAS silently dropped by a from-scratch
    # regeneration — fixed alongside the provenance_mode vector addition).
    {"name": "canonical-null-member-removed", "kind": "canonical",
     "description": "normalize() removes a null-valued member (S:2 absent-field normalization)"},
    {"name": "canonical-empty-object-removed", "kind": "canonical",
     "description": "normalize() removes an empty-object member (S:2 absent-field normalization)"},
    {"name": "canonical-empty-array-removed", "kind": "canonical",
     "description": "normalize() removes an empty-array member (S:2 absent-field normalization)"},
    {"name": "canonical-object-emptied-by-normalization", "kind": "canonical",
     "description": "normalize() bottom-up: object becomes empty after null member removed; parent removes it"},
    {"name": "canonical-nested-two-deep-emptied", "kind": "canonical",
     "description": "normalize() bottom-up two levels: d->c->b all emptied and removed"},
    {"name": "canonical-array-of-objects-normalized", "kind": "canonical",
     "description": "normalize() recurses into array elements; null member in nested object removed"},
    {"name": "canonical-array-preserved-not-sorted", "kind": "canonical",
     "description": "Array elements preserved in insertion order, not sorted (RFC 8785 S:3.2.2)"},
    {"name": "canonical-nested-member-named-capsule-id", "kind": "canonical",
     "description": "Top-level capsule_id/chain exclusion does not apply to nested members with those names"},
    {"name": "canonical-nested-member-named-chain", "kind": "canonical",
     "description": "Top-level capsule_id/chain exclusion does not apply to nested members with those names"},
    {"name": "canonical-key-sort-utf16-vs-codepoint", "kind": "canonical",
     "description": "UTF-16 key ordering: U+1F600 emoji (first surrogate 0xD83D) sorts after U+FF3A (single unit)"},
    {"name": "canonical-key-nfc-vs-nfd", "kind": "canonical",
     "description": "JCS does not normalize Unicode; NFD key A+U+030A (first unit 0x0041) sorts before B (0x0042)"},
    {"name": "canonical-string-escapes", "kind": "canonical",
     "description": 'JCS mandatory escapes: \\" \\\\ \\b \\t \\n \\f \\r in a single string value (RFC 8785 S:3.2.2.2)'},
    {"name": "canonical-control-char-below-0x20", "kind": "canonical",
     "description": "Control char U+0001 not in named-shortcut set: serialized as \\u0001 (RFC 8785 S:3.2.2.2)"},
    {"name": "canonical-non-bmp-value", "kind": "canonical",
     "description": "Non-BMP char U+1F600 in a string value passes through as UTF-8 (no \\uXXXX escaping needed)"},
    {"name": "canonical-solidus-not-escaped", "kind": "canonical",
     "description": "Solidus / is NOT escaped in JCS (RFC 8785 S:3.2.2.2 forbids the \\/ escape)"},
    {"name": "canonical-integer-zero", "kind": "canonical",
     "description": "Integer 0 serialized as '0' (int branch in _jcs_value, S:5.1)"},
    {"name": "canonical-integer-negative", "kind": "canonical",
     "description": "Negative integer -1 serialized as '-1'"},
    {"name": "canonical-integer-at-safe-max", "kind": "canonical",
     "description": "Integer at exactly Number.MAX_SAFE_INTEGER = 9007199254740991 accepted (S:5.1 boundary)"},
    {"name": "canonical-integer-above-safe-max", "kind": "canonical",
     "description": "Integer one above Number.MAX_SAFE_INTEGER raises UnsafeIntegerError (S:5.1 guard)"},
    {"name": "canonical-integer-at-safe-min", "kind": "canonical",
     "description": "Integer at exactly -Number.MAX_SAFE_INTEGER = -9007199254740991 accepted (S:5.1 boundary)"},
    {"name": "canonical-float-in-value", "kind": "canonical",
     "description": "Float value raises FloatInDigestError (S:5.1 forbids floats in digest-bearing fields)"},
    {"name": "canonical-float-integral-valued", "kind": "canonical",
     "description": "Integral-valued float 2.0 raises FloatInDigestError: the guard is a type check, not a value check"},
    {"name": "canonical-bool-and-deep-nesting", "kind": "canonical",
     "description": "Boolean true and deep object nesting: exercises bool branch and recursive dict serialization"},
    {"name": "canonical-all-members-removed", "kind": "canonical",
     "description": "After normalization all members removed; capsule_id = SHA-256(JCS({})) = SHA-256('{}')"},
]


def main() -> None:
    OUT.mkdir(exist_ok=True)
    manifest = []
    for case in build_cases():
        name, kind, desc, inp = case["name"], case["kind"], case["description"], case["input"]
        case_dir = OUT / name
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
        manifest.append({"name": name, "kind": kind, "description": desc})

    manifest.extend(HAND_AUTHORED_CASES)

    (OUT / "vectors.json").write_text(
        json.dumps(
            {
                "format_versions": ["2", "4"],
                "spec": CURRENT_SPEC,
                "count": len(manifest),
                "cases": manifest,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    checksum_lines = []
    for path in sorted(OUT.glob("*/*.json")):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        checksum_lines.append(f"{digest}  {path.relative_to(OUT)}")
    (OUT / "SHA256SUMS").write_text(
        "\n".join(checksum_lines) + "\n",
        encoding="ascii",
    )
    print(f"wrote {len(manifest)} vectors to {OUT}")

    de_manifest = []
    for case in build_disclosure_envelope_cases():
        name, kind, desc, inp = case["name"], case["kind"], case["description"], case["input"]
        case_dir = DE_OUT / name
        case_dir.mkdir(parents=True, exist_ok=True)

        res = verify_disclosure_envelope(inp["envelope"])
        expected = {"description": desc, "kind": kind, **envelope_result_to_expected(res)}

        (case_dir / "input.json").write_text(json.dumps(inp, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (case_dir / "expected.json").write_text(json.dumps(expected, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        de_manifest.append({"name": name, "kind": kind, "description": desc})

    (DE_OUT / "vectors.json").write_text(
        json.dumps({"format_version": "1", "spec": "draft-mih-scitt-agent-action-capsule-disclosure-envelope-00",
                    "count": len(de_manifest), "cases": de_manifest}, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {len(de_manifest)} vectors to {DE_OUT}")

    PM_OUT.mkdir(exist_ok=True)
    pm_manifest = []
    for case in build_provenance_mode_cases():
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


if __name__ == "__main__":
    main()
