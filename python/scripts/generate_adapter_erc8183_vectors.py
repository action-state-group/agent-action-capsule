#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate the ERC-8183 adapter profile vectors (spec/adapters/erc-8183-v0.md).

Each case is one ERC-8183 job: its recorded lookups (``getJob`` and the job's events, in the
shapes a chain node returns), the evaluator's sealed ``evaluation-report/v1`` capsule with its
Producer Envelope and payload, the provider's deliverable capsule, the contract version document
when the verifier holds it, and the expected status of each of the profile's seven checks (§7,
§8). Every expected status is chosen by hand from the profile's text and cites the step it comes
from; digests, Capsule IDs and signatures are computed. Nothing here runs a verifier or reads a
chain. ``python/tests/test_adapter_erc8183_vectors.py`` recomputes every check with its own code.

Output: ``vectors/adapters/erc-8183/`` (or ``--out DIR``). Deterministic: no clock and no
randomness. Every key is derived from a public label and is for testing only. ``README.md`` is
hand-written; when present in the output directory it is included in ``SHA256SUMS`` but never
rewritten. Dependencies: ``agent_action_capsule``, ``cryptography`` and ``scitt-cose`` (the dev
extra).
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scitt_cose.cose_sign1 import sign_sign1

from agent_action_capsule.canonical import compute_capsule_id, json_digest
from agent_action_capsule.media_types import CAPSULE_ID_MEDIA_TYPE

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "vectors" / "adapters" / "erc-8183"
SET = "aac-adapter-erc-8183-v0"
PROFILE = "spec/adapters/erc-8183-v0.md"
STATUS = ("Vectors for an informational adapter profile. No chain was read: every lookup is a "
          "constructed recording. Every key is a test key derived from a public label; never use one "
          "for anything else.")
CHECKS = ("is_evaluation", "reason_binding", "capsule_verifies", "contract_binding", "contract_digest",
          "deliverable_cited", "verdict_call")
PASS, FAIL, NOT_PRESENT, NOT_CHECKED = "PASS", "FAIL", "NOT_PRESENT", "NOT_CHECKED"

# Example accounts on Base Sepolia. Nothing reads them.
CHAIN = "eip155:84532"
CONTRACT = f"{CHAIN}:0x00000000000000000000000000000000008183a0"
CLIENT = "0x00000000000000000000000000000000c11e0001"
PROVIDER = "0x00000000000000000000000000000000c11e0002"
EVALUATOR = "0x00000000000000000000000000000000c11e0003"
ZERO32 = "0x" + "00" * 32

CONTRACT_DOC = {
    "id": "ec:example-review:2026-11",
    "version": "1",
    "requirements": [
        {"id": "r-work", "profile": "outcome",
         "statement": "The submitted work does what the job description asks.",
         "evidence_requirements": {"accepted_epistemic_types": ["semantic_judgment"]}},
    ],
}
OTHER_CONTRACT_DOC = {**CONTRACT_DOC, "id": "ec:example-other:2026-11", "version": "2"}


def contract_ref(doc: dict) -> str:
    return f"{doc['id']}@{doc['version']}"


CONTRACT_REF = contract_ref(CONTRACT_DOC)
CONTRACT_DIGEST = json_digest(CONTRACT_DOC)

# ---------------------------------------------------------------------------
# Test keys and sealing
# ---------------------------------------------------------------------------

KEY_LABELS = {name: f"erc-8183-v0 vectors: {name} key" for name in ("evaluator", "provider")}
PRIV = {n: Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode()).digest())
        for n, label in KEY_LABELS.items()}


def _pub(name: str) -> bytes:
    return PRIV[name].public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _pem(name: str) -> bytes:
    return PRIV[name].private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption())


def seal(action_id: str, developer: str, timestamp: str, payload: dict) -> dict:
    """A format-4 Capsule committing ``payload`` as its agent_input, as `capsulectl publish` seals one."""
    body = {
        "spec_version": "draft-mih-scitt-agent-action-capsule-05",
        "format_version": "4",
        "canonicalization_id": "jcs",
        "action_id": action_id,
        "action_type": "fyi",
        "operator": "example-operator",
        "developer": developer,
        "timestamp": timestamp,
        "assurance": {"effect_mode": "not_applicable", "attestation_mode": "self_attested",
                      "ledger_mode": "standalone"},
        "model_attestation": {"compute_attestation": {"agent_input_digest": json_digest(payload)}},
    }
    return {**body, "capsule_id": compute_capsule_id(body)}


def envelope(capsule_id: str, signer: str) -> bytes:
    """The Producer Envelope: COSE_Sign1, EdDSA, over the raw 32-byte Capsule ID (draft-06)."""
    return sign_sign1(bytes.fromhex(capsule_id), alg="EdDSA", private_key_pem=_pem(signer),
                      protected={3: CAPSULE_ID_MEDIA_TYPE, 4: _pub(signer)}, unprotected={})


def broken(encoded: bytes) -> bytes:
    """The same envelope with the signature's last octet changed."""
    return encoded[:-1] + bytes([encoded[-1] ^ 0x01])


def citation(type_: str, digest: str, purpose: str) -> dict:
    return {"type": type_, "digest_alg": "SHA-256", "digest": digest, "citation_purpose": purpose}


RUBRIC_DIGEST = json_digest({"placeholder": "erc-8183-v0 vectors: rubric"})
JUDGE_PIN = {
    "model_id": "example-judge-v1",
    "prompt_digest": {"digest_alg": "SHA-256", "digest": json_digest({"placeholder": "erc-8183-v0 vectors: prompt"})},
    "axes_digest": {"digest_alg": "SHA-256", "digest": json_digest({"placeholder": "erc-8183-v0 vectors: axes"})},
    "sampling": {"seed": 1, "temperature_micros": 0},
}


def report(job_id: int, verdicts: list[str], cited: str, ref: str = CONTRACT_REF) -> dict:
    """A JF evaluation-report/v1 with one case per verdict, each citing ``cited`` (§6.3)."""
    return {
        "record_version": "evaluation-report/v1",
        "record_id": f"er-erc8183-job-{job_id}",
        "epistemic_type": "semantic_judgment",
        "generated_at": "2026-11-03T12:00:00Z",
        "contract_ref": ref,
        "judge_pin": copy.deepcopy(JUDGE_PIN),
        "cases": [{"case_id": f"job-{job_id}-case-{i + 1}", "verdict": v,
                   "acts": [citation("agent-action-capsule", cited, "grounds")],
                   "method": citation("rubric", RUBRIC_DIGEST, "method")}
                  for i, v in enumerate(verdicts)],
    }


def deliverable_capsule(job_id: int) -> dict:
    payload = {"work": f"erc-8183-v0 vectors: the provider's work product for job {job_id}"}
    return {"capsule": seal(f"urn:example:deliverable:{job_id}", "example-provider@v1",
                            "2026-11-03T11:00:00Z", payload),
            "payload": payload}


def report_capsule(rec: dict) -> dict:
    cap = seal(f"urn:example:evaluation-report:{rec['record_id']}", "example-evaluator@v1",
               "2026-11-03T12:00:00Z", rec)
    return {"capsule": cap, "envelope_hex": envelope(cap["capsule_id"], "evaluator").hex(), "payload": rec}


def description(ref: str = CONTRACT_REF, digest: str = CONTRACT_DIGEST) -> str:
    """§6.1: the first line, then free text a verifier ignores."""
    return f"{ref} sha256:{digest}\nReview the attached change and report whether it does what the ticket asks."


def job(job_id: int, ending: str, deliverable: str | None, reason: str | None = None, desc: str | None = None,
        rejector: str = EVALUATOR) -> dict:
    """The recorded lookups for one job. ``ending`` is complete, reject or expire."""
    status = {"complete": "Completed", "reject": "Rejected", "expire": "Expired"}[ending]
    events: list[dict] = []
    if deliverable is not None:
        events.append({"event": "JobSubmitted",
                       "args": {"jobId": job_id, "provider": PROVIDER, "deliverable": "0x" + deliverable}})
    if ending == "complete":
        events.append({"event": "JobCompleted", "args": {"jobId": job_id, "evaluator": EVALUATOR, "reason": reason}})
    elif ending == "reject":
        events.append({"event": "JobRejected", "args": {"jobId": job_id, "rejector": rejector, "reason": reason}})
    else:
        events.append({"event": "JobExpired", "args": {"jobId": job_id}})
    return {
        "contract": CONTRACT,
        "job_id": job_id,
        "getJob": {"id": job_id, "client": CLIENT, "provider": PROVIDER, "evaluator": EVALUATOR,
                   "description": description() if desc is None else desc, "budget": "1000000",
                   "expiredAt": 1793750400, "status": status, "hook": "0x" + "00" * 20},
        "events": events,
    }


def expect(**overrides: str) -> dict:
    out = {c: PASS for c in CHECKS}
    out.update(overrides)
    return out


AFTER_EVAL_FAIL = {c: NOT_CHECKED for c in CHECKS[1:]}  # §7: check 1 FAIL
AFTER_CAPSULE_FAIL = {c: NOT_CHECKED for c in CHECKS[3:]}  # §7: check 3 not PASS

# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------


def cases() -> list[dict]:
    out: list[dict] = []

    def add(case_id: str, why: str, job_: dict, rep: dict | None, deliv: dict, expected: dict,
            predicates: list[str], *, holds_contract: bool = True) -> None:
        assert set(expected) == set(CHECKS)
        out.append({"id": case_id, "description": why, "job": job_, "report": rep, "deliverable": deliv,
                    "contract_document": CONTRACT_DOC if holds_contract else None,
                    "expected": expected, "predicates": predicates})

    def std(n: int, verdicts: list[str], ending: str | None, **kw: Any):
        d = deliverable_capsule(n)
        did = d["capsule"]["capsule_id"]
        rec = report(n, verdicts, kw.pop("cited", did), kw.pop("ref", CONTRACT_REF))
        rep = report_capsule(rec)
        reason = kw.pop("reason", "0x" + rep["capsule"]["capsule_id"])
        j = job(n, ending, kw.pop("deliverable", did), reason if ending != "expire" else None, **kw)
        return j, rep, d

    j, r, d = std(1, ["met"], "complete")
    add("met-complete", "met judged and complete called with reason = the report's Capsule ID (§6.3, §6.4); "
        "the verifier holds the contract document", j, r, d, expect(), ["E1", "E2"])
    j, r, d = std(2, ["met"], "complete")
    add("met-complete-no-contract-document", "as met-complete, without the contract document: contract_digest "
        "NOT_CHECKED (§7 step 5), which never downgrades E1 (§9.1)", j, r, d,
        expect(contract_digest=NOT_CHECKED), ["E1"], holds_contract=False)
    j, r, d = std(3, ["not_met"], "reject")
    add("not-met-reject", "not_met judged and reject called by the evaluator (§6.4)", j, r, d, expect(), ["E1", "E2"])
    j, r, d = std(4, ["not_evaluable"], "expire")
    add("not-evaluable-refund", "not_evaluable judged; no call; claimRefund after expiredAt (§6.4). No call and "
        "no reason (§7 steps 1, 2); the report is bound off chain only (E3)", j, r, d,
        expect(is_evaluation=NOT_PRESENT, reason_binding=NOT_PRESENT), ["E3"])

    # MUST reject.
    other = report_capsule(report(99, ["met"], "00" * 32))["capsule"]["capsule_id"]
    j, r, d = std(5, ["met"], "complete", reason="0x" + other)
    add("reason-digest-mismatch", "reason names another capsule than the report held (§7 step 2)", j, r, d,
        expect(reason_binding=FAIL), [])
    j, r, d = std(6, ["met"], "complete",
                  desc=description(contract_ref(OTHER_CONTRACT_DOC), json_digest(OTHER_CONTRACT_DOC)))
    add("contract-ref-mismatch", "the job's description names another contract than the report's contract_ref "
        "(§7 step 4); contract_digest is then NOT_CHECKED (§7 step 5)", j, r, d,
        expect(contract_binding=FAIL, contract_digest=NOT_CHECKED), [])
    j, r, d = std(7, ["met"], "complete", cited=json_digest({"placeholder": "some other work"}))
    add("deliverable-not-cited", "the report's case cites a capsule other than the job's deliverable (§7 step 6)",
        j, r, d, expect(deliverable_cited=FAIL), [])
    for n, (cid, verdict, ending) in enumerate([
            ("not-evaluable-with-complete", "not_evaluable", "complete"),
            ("not-evaluable-with-reject", "not_evaluable", "reject"),
            ("met-with-reject", "met", "reject"),
            ("not-met-with-complete", "not_met", "complete"),
            ("out-of-scope-with-complete", "out_of_scope", "complete")], start=8):
        j, r, d = std(n, [verdict], ending)
        add(cid, f"a {verdict} report under a {ending} call (§6.4, §7 step 7)", j, r, d,
            expect(verdict_call=FAIL), [])
    j, r, d = std(13, ["met", "not_met"], "complete")
    add("two-cases", "a report with two cases, both citing the deliverable (§6.3: exactly one; §7 step 7)",
        j, r, d, expect(verdict_call=FAIL), [])
    j, r, d = std(14, ["met"], "complete", reason=ZERO32)
    add("reason-zero", "complete called with reason bytes32(0): it names no report (§7 step 2)", j, r, d,
        expect(reason_binding=NOT_PRESENT), [])
    j, r, d = std(15, ["met"], "complete", desc=description(CONTRACT_REF, json_digest({"placeholder": "x"})))
    add("contract-digest-mismatch", "the description names the report's contract_ref with another digest, and the "
        "verifier holds the document (§7 step 5)", j, r, d, expect(contract_digest=FAIL), [])
    j, r, d = std(16, ["not_met"], "reject", deliverable=None)
    add("rejected-while-funded", "the evaluator rejected before any submit: no deliverable to cite (§7 step 6)",
        j, r, d, expect(deliverable_cited=NOT_PRESENT), [])
    j, r, d = std(17, ["not_met"], "reject", deliverable=None, rejector=CLIENT)
    add("client-reject-open", "the client rejected while Open: not an evaluation, no report is read (§7 step 1)",
        j, r, d, expect(is_evaluation=FAIL, **AFTER_EVAL_FAIL), [])
    j, r, d = std(18, ["met"], "complete")
    r = {**r, "envelope_hex": broken(bytes.fromhex(r["envelope_hex"])).hex()}
    add("bad-report-signature", "the report's Producer Envelope signature changed after signing (§7 step 3)",
        j, r, d, expect(capsule_verifies=FAIL, **AFTER_CAPSULE_FAIL), [])
    j, r, d = std(19, ["not_met"], "complete")
    tampered = copy.deepcopy(r["payload"])
    tampered["cases"][0]["verdict"] = "met"
    r = {**r, "payload": tampered}
    add("payload-digest-mismatch", "the held payload's verdict changed from not_met to met after sealing: its "
        "JSON-DIGEST no longer equals agent_input_digest (§7 step 3)", j, r, d,
        expect(capsule_verifies=FAIL, **AFTER_CAPSULE_FAIL), [])
    return out


def _dump(v: Any) -> bytes:
    return (json.dumps(v, indent=2, ensure_ascii=False) + "\n").encode()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    out = ap.parse_args().out
    out.mkdir(parents=True, exist_ok=True)
    vectors = {
        "set": SET,
        "profile": PROFILE,
        "status": STATUS,
        "checks": list(CHECKS),
        "test_keys": {n: {"label": label, "public_key_hex": _pub(n).hex()} for n, label in KEY_LABELS.items()},
        "contract_ref": CONTRACT_REF,
        "contract_digest": CONTRACT_DIGEST,
        "cases": cases(),
    }
    files = {"vectors.json": _dump(vectors)}
    files["manifest.json"] = _dump({"set": SET, "profile": PROFILE, "status": STATUS,
                                    "files": {n: hashlib.sha256(b).hexdigest() for n, b in files.items()}})
    for name, data in files.items():
        (out / name).write_bytes(data)
    sums = sorted(list(files) + (["README.md"] if (out / "README.md").exists() else []))
    (out / "SHA256SUMS").write_text("".join(f"{hashlib.sha256((out / n).read_bytes()).hexdigest()}  {n}\n"
                                            for n in sums))


if __name__ == "__main__":
    main()
