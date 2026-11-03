# SPDX-License-Identifier: BSD-3-Clause
"""Check the ERC-8183 adapter profile vectors (spec/adapters/erc-8183-v0.md) with this file's own code.

The checker below implements the profile's §7 from its text, independently of the generator: it
recomputes every Capsule ID and payload digest, verifies every Producer Envelope, compares the
description line octet by octet, and derives each case's predicates (§9) from its statuses.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path

import pytest

from agent_action_capsule.canonical import compute_capsule_id, jcs, json_digest

envelope_mod = pytest.importorskip("agent_action_capsule.producer_envelope")

ROOT = Path(__file__).resolve().parents[2]
VEC = ROOT / "vectors" / "adapters" / "erc-8183"
DATA = json.loads((VEC / "vectors.json").read_text())
CHECKS = ("is_evaluation", "reason_binding", "capsule_verifies", "contract_binding", "contract_digest",
          "deliverable_cited", "verdict_call")
VERDICTS = {"met", "not_met", "not_evaluable", "out_of_scope"}
HEX64 = re.compile(rb"[0-9a-f]{64}")


def _addr(a: str) -> bytes:
    return bytes.fromhex(a[2:])


def _citation(c: object, purpose: str) -> bool:
    return (isinstance(c, dict) and c.get("digest_alg") == "SHA-256" and isinstance(c.get("digest"), str)
            and re.fullmatch(r"[0-9a-f]{64}", c["digest"]) is not None and c.get("citation_purpose") == purpose
            and isinstance(c.get("type"), str))


def _is_report(rec: object) -> bool:
    """The members of JF §2 this profile relies on."""
    if not isinstance(rec, dict) or rec.get("record_version") != "evaluation-report/v1":
        return False
    if rec.get("epistemic_type") != "semantic_judgment" or not isinstance(rec.get("contract_ref"), str):
        return False
    if re.fullmatch(r"[^@\s]+@[^@\s]+", rec["contract_ref"]) is None:  # JF schema's contract_ref pattern
        return False
    pin = rec.get("judge_pin")
    if not isinstance(pin, dict) or not isinstance(pin.get("model_id"), str) or "prompt_digest" not in pin:
        return False
    cases = rec.get("cases")
    if not isinstance(cases, list) or not cases:
        return False
    for case in cases:
        if not isinstance(case, dict) or case.get("verdict") not in VERDICTS or not isinstance(case.get("case_id"), str):
            return False
        acts = case.get("acts")
        if not isinstance(acts, list) or not acts or not all(_citation(a, "grounds") for a in acts):
            return False
        if not _citation(case.get("method"), "method"):
            return False
    return True


def check(case: dict, *, online: bool = True) -> dict:
    """Profile §7, steps 1 to 7, in order. ``online=False`` is a verifier with no chain source."""
    job, held = case["job"], case["report"]
    get_job = job["getJob"]
    events = {e["event"]: e["args"] for e in job["events"]}
    out: dict[str, str] = {}

    # 1. is_evaluation
    call = None
    if "JobCompleted" in events:
        call = ("complete", events["JobCompleted"])
        out["is_evaluation"] = "PASS" if _addr(call[1]["evaluator"]) == _addr(get_job["evaluator"]) else "FAIL"
    elif "JobRejected" in events:
        call = ("reject", events["JobRejected"])
        past_open = "JobFunded" in events or "JobSubmitted" in events  # else it was the client's Open rejection
        evaluator = _addr(call[1]["rejector"]) == _addr(get_job["evaluator"])
        out["is_evaluation"] = "PASS" if evaluator and past_open else "FAIL"
    else:
        out["is_evaluation"] = "NOT_PRESENT"
    if not online:
        out["is_evaluation"] = "NOT_CHECKED"
    if out["is_evaluation"] == "FAIL":
        return {**out, **{c: "NOT_CHECKED" for c in CHECKS[1:]}}
    settled = out["is_evaluation"] in ("PASS", "NOT_PRESENT")

    capsule = held["capsule"] if held else None
    supported = bool(capsule) and capsule.get("format_version") == "4" and capsule.get("canonicalization_id") == "jcs"
    recomputed = compute_capsule_id(dict(capsule)) if supported else None

    # 2. reason_binding
    if not settled:
        out["reason_binding"] = "NOT_CHECKED"
    elif call is None or held is None or call[1]["reason"] == "0x" + "00" * 32:
        out["reason_binding"] = "NOT_PRESENT"
    elif not supported:
        out["reason_binding"] = "NOT_CHECKED"
    else:
        out["reason_binding"] = "PASS" if call[1]["reason"][2:] == recomputed else "FAIL"

    # 3. capsule_verifies
    if held is None or not held.get("envelope_hex") or held.get("payload") is None:
        out["capsule_verifies"] = "NOT_PRESENT"
    elif not supported:
        out["capsule_verifies"] = "NOT_CHECKED"
    else:
        env = envelope_mod.verify_producer_envelope(recomputed, bytes.fromhex(held["envelope_hex"]))
        committed = ((capsule.get("model_attestation") or {}).get("compute_attestation") or {}).get("agent_input_digest")
        ok = (capsule.get("capsule_id") == recomputed and env.ok and json_digest(held["payload"]) == committed
              and _is_report(held["payload"]))
        out["capsule_verifies"] = "PASS" if ok else "FAIL"
    if out["capsule_verifies"] != "PASS" or not settled:
        return {**out, **{c: "NOT_CHECKED" for c in CHECKS[3:]}}
    rec = held["payload"]

    # 4. contract_binding: octets before the first LF, compared, never split.
    line = get_job["description"].encode().split(b"\n", 1)[0]
    prefix = rec["contract_ref"].encode() + b" sha256:"
    bound = line.startswith(prefix) and len(line) == len(prefix) + 64 and HEX64.fullmatch(line[len(prefix):])
    out["contract_binding"] = "PASS" if bound else "FAIL"

    # 5. contract_digest
    doc = case["contract_document"]
    if not bound or doc is None or f"{doc['id']}@{doc['version']}" != rec["contract_ref"]:
        out["contract_digest"] = "NOT_CHECKED"
    else:
        out["contract_digest"] = "PASS" if hashlib.sha256(jcs(doc)).hexdigest().encode() == line[len(prefix):] else "FAIL"

    # 6. deliverable_cited
    if "JobSubmitted" not in events:
        out["deliverable_cited"] = "NOT_PRESENT"
    else:
        d = events["JobSubmitted"]["deliverable"][2:]
        out["deliverable_cited"] = "PASS" if any(a["digest"] == d for c in rec["cases"] for a in c["acts"]) else "FAIL"

    # 7. verdict_call
    want = {"met": "complete", "not_met": "reject", "not_evaluable": "expire", "out_of_scope": "expire"}
    ended = call[0] if call else ("expire" if "JobExpired" in events else None)
    if ended is None:
        out["verdict_call"] = "NOT_CHECKED"  # not ended yet: the evaluator may still call
    else:
        out["verdict_call"] = "PASS" if len(rec["cases"]) == 1 and want[rec["cases"][0]["verdict"]] == ended else "FAIL"
    return out


def predicates(st: dict) -> list[str]:
    """Profile §9."""
    e1 = all(st[c] == "PASS" for c in ("is_evaluation", "reason_binding", "capsule_verifies", "contract_binding",
                                       "deliverable_cited", "verdict_call")) and st["contract_digest"] != "FAIL"
    e3 = (all(st[c] == "PASS" for c in ("capsule_verifies", "contract_binding", "deliverable_cited", "verdict_call"))
          and st["is_evaluation"] == st["reason_binding"] == "NOT_PRESENT" and st["contract_digest"] != "FAIL")
    return (["E1"] if e1 else []) + (["E2"] if e1 and st["contract_digest"] == "PASS" else []) + (["E3"] if e3 else [])


@pytest.mark.parametrize("case", DATA["cases"], ids=lambda c: c["id"])
def test_case(case):
    st = check(case)
    assert st == case["expected"]
    assert predicates(st) == case["predicates"]


def test_case_set():
    ids = [c["id"] for c in DATA["cases"]]
    assert len(ids) == len(set(ids))
    for required in ("met-complete", "not-met-reject", "not-evaluable-refund", "reason-digest-mismatch",
                     "contract-ref-mismatch", "deliverable-not-cited", "not-evaluable-with-complete"):
        assert required in ids
    passing = [c for c in DATA["cases"] if c["predicates"]]
    assert {c["id"] for c in passing} == {"met-complete", "met-complete-no-contract-document", "not-met-reject",
                                          "not-evaluable-refund", "out-of-scope-refund"}
    assert "not-evaluable-still-open" in ids and "client-is-evaluator-reject-open" in ids


def test_unsupported_capsule_format_is_not_checked():
    """§3, §8: a report capsule that is not format 4 / jcs is NOT_CHECKED, never FAIL."""
    case = copy.deepcopy(DATA["cases"][0])
    case["report"]["capsule"]["canonicalization_id"] = "cbor-det"
    st = check(case)
    assert st["capsule_verifies"] == st["reason_binding"] == "NOT_CHECKED"
    assert predicates(st) == []


def test_deliverable_is_capsule_id_not_file_hash():
    """§6.2: the deliverable is the Capsule ID, which leaves out the envelope; hashing the file differs."""
    case = DATA["cases"][0]
    cap = case["deliverable"]["capsule"]
    submitted = next(e for e in case["job"]["events"] if e["event"] == "JobSubmitted")["args"]["deliverable"][2:]
    assert submitted == compute_capsule_id(dict(cap)) == cap["capsule_id"]
    assert submitted != hashlib.sha256(json.dumps(cap).encode()).hexdigest()


@pytest.mark.parametrize("mutate", [
    lambda s: s.replace(" sha256:", "  sha256:", 1),
    lambda s: s.replace("\n", " \n", 1),
    lambda s: s.replace("\n", "\r\n", 1),
    lambda s: s.split(" sha256:")[0] + " sha256:" + s.split(" sha256:")[1][:64].upper() + s.split(" sha256:")[1][64:],
    lambda s: s.split(" sha256:")[0] + " sha256:" + s.split(" sha256:")[1][:63] + s.split(" sha256:")[1][64:],
    lambda s: s.replace("ec:example-review:2026-11@1", "ec:example-review:2026-11@10", 1),
], ids=["double-space", "trailing-space", "crlf", "uppercase-hex", "short-hex", "other-version"])
def test_description_line_is_compared_not_parsed(mutate):
    case = copy.deepcopy(DATA["cases"][0])
    case["job"]["getJob"]["description"] = mutate(case["job"]["getJob"]["description"])
    assert check(case)["contract_binding"] == "FAIL"


def test_free_text_after_first_line_is_ignored():
    case = copy.deepcopy(DATA["cases"][0])
    first = case["job"]["getJob"]["description"].split("\n", 1)[0]
    for desc in (first, first + "\nanything at all\nsha256:" + "0" * 64):
        case["job"]["getJob"]["description"] = desc
        assert check(case)["contract_binding"] == "PASS"


def test_reports_validate_against_jf_schema():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((ROOT / "schemas" / "judge" / "evaluation-report-v1.json").read_text())
    for case in DATA["cases"]:
        if case["id"] in ("payload-digest-mismatch", "report-without-envelope"):
            continue  # the tampered payload is still schema-valid, but is not the sealed one
        if case["id"] == "payload-not-a-report":
            with pytest.raises(jsonschema.ValidationError):
                jsonschema.validate(case["report"]["payload"], schema)
            continue
        jsonschema.validate(case["report"]["payload"], schema)


def test_manifest_and_sums():
    manifest = json.loads((VEC / "manifest.json").read_text())
    for name, digest in manifest["files"].items():
        assert hashlib.sha256((VEC / name).read_bytes()).hexdigest() == digest
    for line in (VEC / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split("  ")
        assert hashlib.sha256((VEC / name).read_bytes()).hexdigest() == digest



@pytest.mark.parametrize("case", DATA["cases"], ids=lambda c: c["id"])
def test_offline_checks_only_the_report(case):
    """§7: with check 1 NOT_CHECKED (no chain source), 2 and 4 to 7 are NOT_CHECKED; check 3 still runs."""
    st = check(case, online=False)
    if case["expected"]["is_evaluation"] == "FAIL":
        return  # the online result gates on the event itself; offline that event is unread
    assert st["is_evaluation"] == "NOT_CHECKED"
    assert all(st[c] == "NOT_CHECKED" for c in ("reason_binding", "contract_binding", "contract_digest",
                                                 "deliverable_cited", "verdict_call"))
    assert st["capsule_verifies"] == case["expected"]["capsule_verifies"]
    assert predicates(st) == []
