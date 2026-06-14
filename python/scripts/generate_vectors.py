# SPDX-License-Identifier: BSD-3-Clause
"""Generate the frozen conformance vectors in ../../test-vectors/.

Vectors are DERIVED from the spec-faithful reference verifier and then FROZEN
(the same discipline as golden digests): each case's expected.json is produced
by running verify()/verify_store() over a hand-built input, and committed. A
third party regenerates the capsule_id and checks ok + the §6 check numbers +
derived modes against the spec text, without running this package.

Run:  cd python && python -m scripts.generate_vectors
"""
from __future__ import annotations

import json
from pathlib import Path

from agent_action_capsule import compute_capsule_id, verify, verify_store

OUT = Path(__file__).resolve().parents[2] / "test-vectors"
SPEC = "draft-mih-scitt-agent-action-capsule-00"
HEX_R = "1" * 64  # a stand-in response/request digest (64-hex); content is opaque here
HEX_R2 = "2" * 64
MISSING_PARENT = "9" * 64


def ident(action_id: str, action_type: str = "decide") -> dict:
    return {
        "spec_version": SPEC,
        "format_version": "2",
        "action_id": action_id,
        "action_type": action_type,
        "operator": "ACME-CO",
        "developer": "agent@v1",
        "timestamp": "2026-06-13T00:00:00Z",
    }


def assurance(effect_mode: str, ledger_mode: str = "standalone") -> dict:
    return {"attestation_mode": "self_attested", "effect_mode": effect_mode, "ledger_mode": ledger_mode}


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

    # Impl guard AHEAD of the -00 text: an integer beyond the IEEE-754-double safe
    # range (2^53-1) is a cross-impl digest-reproducibility hazard. The -00 forbids
    # floats and mandates decimal STRINGS for monetary/quantity values but does not
    # yet state this integer bound — see the -01 FLAG in test-vectors/README.md.
    unsafe_int_cap = {**ident("neg-unsafeint"),
                      "effect": {"status": "confirmed", "type": "write_order", "response_digest": HEX_R,
                                 "effect_attestation": "gate_executed", "amount": 2**53},
                      "assurance": assurance("confirmed"),
                      "disposition": {"decision": "accept", "approver": "human", "human_disposed": True},
                      "capsule_id": "0" * 64}  # cannot recompute over an unsafe int; carried id is a placeholder
    add("neg-unsafe-integer-in-digest-field", "negative",
        "an integer beyond 2^53-1 in a digest-bearing field -> structural failure (check 1). "
        "IMPL GUARD ahead of -00; flagged for an -01 clarification (large integers MUST be decimal strings).",
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


def result_to_expected(res) -> dict:
    return {
        "ok": res.ok,
        "derived": res.assurance,
        "capsule_id_recomputed": res.capsule_id,
        "findings": [{"check": f.check, "severity": f.severity, "code": f.code, "detail": f.detail} for f in res.findings],
    }


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

    (OUT / "vectors.json").write_text(
        json.dumps({"format_version": "2", "spec": SPEC, "count": len(manifest), "cases": manifest}, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {len(manifest)} vectors to {OUT}")


if __name__ == "__main__":
    main()
