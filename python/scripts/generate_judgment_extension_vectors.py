#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate the judgment extension vectors (PROVISIONAL, digest rules unratified).

The judgment extension adds one namespaced member to a Capsule that records a
judgment, at ``/model_attestation/compute_attestation/x-judgment-v1``:
``rubric_digest``, ``rubric_version``, ``judge_parameters_digest``. Base fields
keep their meaning: ``developer`` is the judge, ``agent_output_digest`` binds
the judge's answer ``{verdict, rationale}``, and ``references[]`` carries
exactly one ``judged_from`` entry naming the evidence by digest. Schema:
``schemas/judgment/judgment-extension-v1.json``.

The digest rules below are PROPOSED and UNRATIFIED:

* ``rubric_digest`` = JSON-DIGEST of the published rubric document;
* ``judge_parameters_digest`` = JSON-DIGEST of
  ``{instruction_template_digest, prompt_digest, axes_digest, sampling_params,
  min_confidence_micros, judge_batch}`` for a model judge, or of
  ``{protocol, packet_digest}`` for a human expert;
* ``agent_output_digest`` = JSON-DIGEST of ``{verdict, rationale}``.

JSON-DIGEST is lowercase-hex SHA-256 of ``UTF8(JCS(value))`` (RFC 8785), the
base profile's rule. Inner file digests (``prompt_digest``, ``axes_digest``,
``policy_digest``) are SHA-256 of the raw file bytes, which every case
carries as text so they recompute too.

Every case carries its preimages and the literal JCS string of each one, so a
reader recomputes every digest without running this script. Nothing here
imports an implementation of the extension; ``capsule_id`` is computed from
the base profile's rule (SHA-256 of JCS of the Capsule minus ``capsule_id``).

Cases:

* ``pos-ai-judge``: a model judge's judgment of one evidence Capsule. It cites
  the evidence with ``judged_from`` and the expert judgment over the same
  evidence with ``calibrated_against`` (the pre-registered calibration
  pattern: the expert judgment was sealed first).
* ``pos-human-expert``: a human expert's judgment of the same evidence under
  the same rubric; ``judge_parameters_digest`` covers the rating protocol and
  the packet shown to the rater.
* ``neg-judge-parameters-digest-mismatch``: schema-valid and Class 1 valid,
  but ``judge_parameters_digest`` does not recompute from the published
  judge parameters (it was computed over a different temperature).
* ``neg-missing-rubric-version``: the extension member lacks the required
  ``rubric_version``; the schema rejects it.

Output: ``vectors/judgment/`` (or ``--out DIR``). Deterministic: no clock, no
randomness, no keys. ``README.md`` is hand-written; when present in the
output directory it is included in ``SHA256SUMS`` but never rewritten.
Dependencies: the standard library only.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "vectors" / "judgment"
SCHEMA = "schemas/judgment/judgment-extension-v1.json"
MEMBER = "x-judgment-v1"
MEMBER_POINTER = f"/model_attestation/compute_attestation/{MEMBER}"
AAC_SPEC_VERSION = "draft-mih-scitt-agent-action-capsule-05"
OPERATOR = "EXAMPLE-ORG"
TIMESTAMP_EVIDENCE = "2026-10-01T09:00:00Z"
TIMESTAMP_EXPERT = "2026-10-01T10:00:00Z"
TIMESTAMP_JUDGE = "2026-10-01T11:00:00Z"
STATUS = ("PROVISIONAL: the judgment extension is held for ratification and not registered; "
          "the rubric_digest and judge_parameters_digest rules are proposed and unratified.")

# ---------------------------------------------------------------------------
# Encodings
# ---------------------------------------------------------------------------


def _check_json_value(value: Any) -> None:
    if isinstance(value, float):
        raise TypeError("floats are forbidden in digest-bearing values")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or not key.isascii():
                raise TypeError("map keys in these vectors are ASCII text")
            _check_json_value(item)
    elif isinstance(value, list):
        for item in value:
            _check_json_value(item)


def jcs(value: Any) -> str:
    """RFC 8785 for the value space these vectors use (no floats, ASCII keys).

    With ASCII keys, UTF-16 code-unit order equals code-point order, so
    ``sort_keys`` is the RFC 8785 member order.
    """
    _check_json_value(value)
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_digest(value: Any) -> str:
    return sha256_hex(jcs(value).encode("utf-8"))


def seal(capsule: dict) -> dict:
    """Set capsule_id per the base profile: SHA-256 of JCS of the Capsule minus capsule_id."""
    body = {k: v for k, v in capsule.items() if k != "capsule_id"}
    return {**body, "capsule_id": json_digest(body)}


# ---------------------------------------------------------------------------
# Published inputs (raw file text, as a judge would read it)
# ---------------------------------------------------------------------------

POLICY_TEXT = (
    "# EXAMPLE-ORG refund policy\n"
    "\n"
    "1. A refund over 500.00 requires a supervisor approval reference.\n"
    "2. The agent states the refund amount to the customer before issuing it.\n"
)
PROMPT_TEXT = (
    "You are grading one recorded agent action against one rubric criterion.\n"
    "Answer met, not_met or not_evaluable, and give a one-sentence rationale.\n"
)
AXES_TEXT = '{"axes":[{"id":"A1","name":"policy adherence"}]}\n'

INSTRUCTION_TEMPLATE = {
    "template": "Criterion: {claim}\nEvidence: {evidence}\nAnswer with one option.",
    "na_instructions": "Choose not_evaluable when the evidence does not bear on the criterion.",
    "options": ["met", "not_met"],
    "na_option": "not_evaluable",
}

RAW_FILES = {"policy.md": POLICY_TEXT, "judge-prompt.md": PROMPT_TEXT, "axes.json": AXES_TEXT}


def raw_digest(name: str) -> str:
    return sha256_hex(RAW_FILES[name].encode("utf-8"))


RUBRIC = {
    "rubric_id": "org.example.refund-policy-adherence",
    "criteria": [
        {"id": "C1", "claim": "A refund over 500.00 carries a supervisor approval reference."},
        {"id": "C2", "claim": "The agent stated the refund amount before issuing it."},
    ],
    "verdicts": ["met", "not_met", "not_evaluable"],
    "policy_digest": raw_digest("policy.md"),
}
RUBRIC_VERSION = "1.2"

JUDGE_PARAMETERS = {
    "instruction_template_digest": json_digest(INSTRUCTION_TEMPLATE),
    "prompt_digest": raw_digest("judge-prompt.md"),
    "axes_digest": raw_digest("axes.json"),
    "sampling_params": {"temperature": "0", "max_output_tokens": 512, "seed": 7},
    "min_confidence_micros": 700000,
    "judge_batch": 1,
}
JUDGE_DEVELOPER = "example-judge-model@2026-09-15"

# ---------------------------------------------------------------------------
# The evidence: one agent action Capsule (what both judgments are made from)
# ---------------------------------------------------------------------------

EVIDENCE_INPUT = {"request": "refund order EX-1001", "amount": "620.00", "currency": "USD"}
EVIDENCE_OUTPUT = {"refund_issued": True, "amount": "620.00", "approval_ref": "SUP-EX-77",
                   "said_to_customer": "I am refunding 620.00 USD now."}

EVIDENCE = seal({
    "spec_version": AAC_SPEC_VERSION,
    "format_version": "4",
    "canonicalization_id": "jcs",
    "action_id": "example-support-refund-0001",
    "action_type": "fyi",
    "operator": OPERATOR,
    "developer": "example-support-agent@1.0",
    "timestamp": TIMESTAMP_EVIDENCE,
    "assurance": {"attestation_mode": "self_attested", "effect_mode": "not_applicable",
                  "ledger_mode": "standalone"},
    "model_attestation": {"compute_attestation": {
        "agent_input_digest": json_digest(EVIDENCE_INPUT),
        "agent_output_digest": json_digest(EVIDENCE_OUTPUT),
    }},
})


def judged_from() -> dict:
    return {"type": "agent-action-capsule", "digest_alg": "SHA-256",
            "digest": EVIDENCE["capsule_id"], "citation_purpose": "judged_from"}


# ---------------------------------------------------------------------------
# Judgment Capsules
# ---------------------------------------------------------------------------


def judgment_capsule(*, action_id: str, developer: str, timestamp: str, answer: dict,
                     member: dict, references: list[dict]) -> dict:
    return seal({
        "spec_version": AAC_SPEC_VERSION,
        "format_version": "4",
        "canonicalization_id": "jcs",
        "action_id": action_id,
        "action_type": "fyi",
        "operator": OPERATOR,
        "developer": developer,
        "timestamp": timestamp,
        "assurance": {"attestation_mode": "self_attested", "effect_mode": "not_applicable",
                      "ledger_mode": "standalone"},
        "model_attestation": {"compute_attestation": {
            "agent_output_digest": json_digest(answer),
            MEMBER: member,
        }},
        "references": references,
    })


def member_for(rubric: dict, rubric_version: str, judge_parameters: dict) -> dict:
    return {
        "rubric_digest": json_digest(rubric),
        "rubric_version": rubric_version,
        "judge_parameters_digest": json_digest(judge_parameters),
    }


EXPERT_PACKET = {
    "evidence": EVIDENCE["capsule_id"],
    "rubric_digest": json_digest(RUBRIC),
    "criterion": "C1",
    "shown": ["agent_input", "agent_output"],
    "model_verdict_shown": False,
}
EXPERT_PARAMETERS = {"protocol": "org.example.blind-review/1", "packet_digest": json_digest(EXPERT_PACKET)}
EXPERT_DEVELOPER = "human-expert/org.example.blind-review"
EXPERT_ANSWER = {"verdict": "met", "rationale": "The refund carries approval reference SUP-EX-77."}
JUDGE_ANSWER = {"verdict": "met", "rationale": "Approval reference present for a refund over 500.00."}

EXPERT = judgment_capsule(
    action_id="example-judgment-expert-C1-0001",
    developer=EXPERT_DEVELOPER,
    timestamp=TIMESTAMP_EXPERT,
    answer=EXPERT_ANSWER,
    member=member_for(RUBRIC, RUBRIC_VERSION, EXPERT_PARAMETERS),
    references=[judged_from()],
)


def calibrated_against_expert() -> dict:
    return {"type": "agent-action-capsule", "digest_alg": "SHA-256",
            "digest": EXPERT["capsule_id"], "citation_purpose": "calibrated_against"}


AI_JUDGE = judgment_capsule(
    action_id="example-judgment-model-C1-0001",
    developer=JUDGE_DEVELOPER,
    timestamp=TIMESTAMP_JUDGE,
    answer=JUDGE_ANSWER,
    member=member_for(RUBRIC, RUBRIC_VERSION, JUDGE_PARAMETERS),
    references=[judged_from(), calibrated_against_expert()],
)

# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------


def _preimages(rubric: dict, judge_parameters: dict, answer: dict, extra: dict | None = None) -> dict:
    values = {"rubric": rubric, "judge_parameters": judge_parameters, "agent_output": answer}
    if extra:
        values.update(extra)
    return {
        "values": values,
        "canonical": {name: jcs(value) for name, value in values.items()},
    }


def _digests(capsule: dict) -> dict:
    ca = capsule["model_attestation"]["compute_attestation"]
    member = ca.get(MEMBER, {})
    return {
        "rubric_digest": member.get("rubric_digest"),
        "judge_parameters_digest": member.get("judge_parameters_digest"),
        "agent_output_digest": ca["agent_output_digest"],
        "judged_from": [r["digest"] for r in capsule["references"] if r.get("citation_purpose") == "judged_from"],
    }


def case_ai_judge() -> dict:
    return {
        "id": "pos-ai-judge",
        "kind": "positive",
        "description": "A model judge's judgment of one evidence Capsule, citing it with judged_from and "
                       "citing the expert judgment over the same evidence with calibrated_against.",
        "capsule": AI_JUDGE,
        "preimages": _preimages(RUBRIC, JUDGE_PARAMETERS, JUDGE_ANSWER,
                                {"instruction_template": INSTRUCTION_TEMPLATE}),
        "expect": {
            "schema_valid": True,
            "capsule_id": AI_JUDGE["capsule_id"],
            "digests": _digests(AI_JUDGE),
            "inner_digests": {
                "judge_parameters.instruction_template_digest": "json-digest of preimages.values.instruction_template",
                "judge_parameters.prompt_digest": "sha256 of raw_files['judge-prompt.md']",
                "judge_parameters.axes_digest": "sha256 of raw_files['axes.json']",
                "rubric.policy_digest": "sha256 of raw_files['policy.md']",
            },
            "judged_from_target": "evidence.capsule_id",
            "calibrated_against_target": "pos-human-expert capsule_id",
            "result": "pass",
            "findings": [],
        },
    }


def case_human_expert() -> dict:
    return {
        "id": "pos-human-expert",
        "kind": "positive",
        "description": "A human expert's judgment of the same evidence under the same rubric; "
                       "judge_parameters covers the rating protocol and the packet shown to the rater.",
        "capsule": EXPERT,
        "preimages": _preimages(RUBRIC, EXPERT_PARAMETERS, EXPERT_ANSWER, {"packet": EXPERT_PACKET}),
        "expect": {
            "schema_valid": True,
            "capsule_id": EXPERT["capsule_id"],
            "digests": _digests(EXPERT),
            "inner_digests": {
                "judge_parameters.packet_digest": "json-digest of preimages.values.packet",
                "rubric.policy_digest": "sha256 of raw_files['policy.md']",
            },
            "judged_from_target": "evidence.capsule_id",
            "same_as_pos_ai_judge": ["rubric_digest", "judged_from"],
            "result": "pass",
            "findings": [],
        },
    }


def case_params_mismatch() -> dict:
    sealed_over = copy.deepcopy(JUDGE_PARAMETERS)
    sealed_over["sampling_params"]["temperature"] = "1"
    capsule = judgment_capsule(
        action_id="example-judgment-model-C1-0002",
        developer=JUDGE_DEVELOPER,
        timestamp=TIMESTAMP_JUDGE,
        answer=JUDGE_ANSWER,
        member=member_for(RUBRIC, RUBRIC_VERSION, sealed_over),
        references=[judged_from()],
    )
    return {
        "id": "neg-judge-parameters-digest-mismatch",
        "kind": "negative",
        "description": "Schema-valid and Class 1 valid, but judge_parameters_digest does not recompute from "
                       "the published judge parameters: it was computed over temperature \"1\", the "
                       "published parameters say \"0\".",
        "capsule": capsule,
        "preimages": _preimages(RUBRIC, JUDGE_PARAMETERS, JUDGE_ANSWER,
                                {"instruction_template": INSTRUCTION_TEMPLATE}),
        "expect": {
            "schema_valid": True,
            "capsule_id": capsule["capsule_id"],
            "digests": _digests(capsule),
            "recomputed_judge_parameters_digest": json_digest(JUDGE_PARAMETERS),
            "result": "fail",
            "findings": [{"code": "judge_parameters_digest_mismatch",
                          "pointer": f"{MEMBER_POINTER}/judge_parameters_digest"}],
        },
    }


def case_missing_rubric_version() -> dict:
    member = member_for(RUBRIC, RUBRIC_VERSION, JUDGE_PARAMETERS)
    del member["rubric_version"]
    capsule = judgment_capsule(
        action_id="example-judgment-model-C1-0003",
        developer=JUDGE_DEVELOPER,
        timestamp=TIMESTAMP_JUDGE,
        answer=JUDGE_ANSWER,
        member=member,
        references=[judged_from()],
    )
    return {
        "id": "neg-missing-rubric-version",
        "kind": "negative",
        "description": "The extension member lacks the required rubric_version. The digests recompute; "
                       "the schema rejects the member.",
        "capsule": capsule,
        "preimages": _preimages(RUBRIC, JUDGE_PARAMETERS, JUDGE_ANSWER,
                                {"instruction_template": INSTRUCTION_TEMPLATE}),
        "expect": {
            "schema_valid": False,
            "capsule_id": capsule["capsule_id"],
            "digests": _digests(capsule),
            "result": "fail",
            "findings": [{"code": "schema_required_member_missing",
                          "pointer": f"{MEMBER_POINTER}/rubric_version"}],
        },
    }


def cases() -> list[dict]:
    return [case_ai_judge(), case_human_expert(), case_params_mismatch(), case_missing_rubric_version()]


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------


def _dump(value: Any) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def build() -> dict[str, bytes]:
    case_list = cases()
    files = {
        "vectors.json": _dump({
            "set": "aac-judgment-extension-v1",
            "status": STATUS,
            "provenance": "spec-derived",
            "schema": SCHEMA,
            "member": MEMBER,
            "member_pointer": MEMBER_POINTER,
            "digest_rules": {
                "json_digest": "lowercase hex SHA-256 of UTF8(JCS(value)) (RFC 8785), no member filtering",
                "rubric_digest": "json_digest(rubric)  [PROPOSED, UNRATIFIED]",
                "judge_parameters_digest": "json_digest(judge_parameters): {instruction_template_digest, "
                                           "prompt_digest, axes_digest, sampling_params, "
                                           "min_confidence_micros?, judge_batch?} for a model judge; "
                                           "{protocol, packet_digest} for a human expert  "
                                           "[PROPOSED, UNRATIFIED]",
                "agent_output_digest": "json_digest({verdict, rationale})",
                "raw_file_digests": "prompt_digest, axes_digest, policy_digest: SHA-256 of the raw file bytes",
                "capsule_id": "json_digest(capsule minus capsule_id)",
            },
            "raw_files": RAW_FILES,
            "evidence": EVIDENCE,
            "count": len(case_list),
            "cases": case_list,
        }),
    }
    files["manifest.json"] = _dump({
        "set": "aac-judgment-extension-v1",
        "status": STATUS,
        "provenance": "spec-derived",
        "generator": "python/scripts/generate_judgment_extension_vectors.py",
        "schema": SCHEMA,
        "pending_registrations": {
            "citation_purpose": ["judged_from", "calibrated_against"],
            "capsule_extension_member": [MEMBER],
        },
        "files": [{"path": name, "sha256": sha256_hex(data), "count": json.loads(data).get("count")}
                  for name, data in sorted(files.items())],
    })
    return files


def write(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for name, data in build().items():
        (out / name).write_bytes(data)
    lines = [f"{sha256_hex(p.read_bytes())}  {p.name}"
             for p in sorted(out.iterdir()) if p.is_file() and p.name != "SHA256SUMS"]
    (out / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    write(parser.parse_args().out)


if __name__ == "__main__":
    main()
