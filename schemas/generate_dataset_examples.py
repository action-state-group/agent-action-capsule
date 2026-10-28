#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""
generate_dataset_examples.py

Writes vectors/evidence-dataset/: dataset plans (spec/evidence-plan-ir-v0.md
section 5.1), the record headers they run over, and the datasets
(section 6.2) they select, with cases.json naming what each case must do.
A pure function of the literal objects below: rerunning it reproduces the
committed bytes. check_evidence_dataset_examples.py and go/evidenceplan read
the output.

Every case is three files, <name>.plan.json, <name>.records.json and
<name>.dataset.json. A positive's dataset is the one evidence_dataset.py
builds. A negative is its base positive with one change, and cases.json names
the reason both gates must refuse it with.
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from evidence_dataset import build_dataset, row  # noqa: E402

from agent_action_capsule.canonical import json_digest  # noqa: E402

OUT_DIR = Path(__file__).resolve().parent.parent / "vectors" / "evidence-dataset"

CONTRACT = "ec:example-org-daily-check:2026-09-01@1"
BOOK = "example-org"
EVENT = "example-event"
RUN = "example-run"


def _record(seq: int, record_type: str, at: str, subject: str = "example-org:subject-1", book: str = BOOK) -> dict:
    return {
        "v": 1,
        "book_id": book,
        "seq": seq,
        "record_type": record_type,
        "epistemic_type": "producer_claim",
        "committed_at": at if at.endswith("Z") else "2026-09-06T00:00:00Z",
        "event_time_claim": at,
        "links": [],
        "subject_ref": subject,
        "statement": {"note": f"EXAMPLE-ORG {record_type} placeholder, seq {seq}", "sample": seq % 2 == 1},
    }


# One book over five days. The plan below keeps seq 2, 3, 5 and 6:
#   seq 1  run    09-01             before the window
#   seq 2  run    09-02T00:00:00Z   the window's first instant: a run day
#   seq 3  event  09-02T10:00:00Z
#   seq 4  event  09-02T23:59:59Z   excluded by subject
#   seq 5  run    09-03             a run day with no event: a 0, not "not run"
#   seq 6  event  09-05T01:30+05:00 = 09-04T20:30Z: in the window, on a day with no run
#   seq 7  event  09-04T23:59:59-00:30 = 09-05T00:29:59Z: after the window
#   seq 8  note   09-03             a record type the population does not list
#   seq 9  event  09-03             committed after through_seq: the book grew
# and one record of another book, which the population never reads.
RECORDS = [
    _record(1, RUN, "2026-09-01T06:00:00Z"),
    _record(2, RUN, "2026-09-02T00:00:00Z"),
    _record(3, EVENT, "2026-09-02T10:00:00Z"),
    _record(4, EVENT, "2026-09-02T23:59:59Z", subject="example-org:excluded"),
    _record(5, RUN, "2026-09-03T06:00:00Z"),
    _record(6, EVENT, "2026-09-05T01:30:00+05:00"),
    _record(7, EVENT, "2026-09-04T23:59:59-00:30"),
    _record(8, "example-note", "2026-09-03T08:00:00Z"),
    _record(9, EVENT, "2026-09-03T09:00:00Z"),
    _record(3, EVENT, "2026-09-03T09:00:00Z", book="example-org-peer"),
]


def _node(node_id: str, operator: str, params: dict, reads: str | None) -> dict:
    return {
        "id": node_id,
        "family": "traditional",
        "operator": operator,
        "inputs": [] if reads is None else [{"by": "node", "node_id": reads}],
        "classification": "CLOUD_SAFE",
        "tier": "recomputed",
        "contract_ref": CONTRACT,
        "params": params,
    }


POPULATION = _node(
    "population",
    "traditional.population",
    {"book_id": BOOK, "through_seq": 8, "record_types": [EVENT, RUN]},
    None,
)
WINDOW = _node(
    "window",
    "traditional.window",
    {"field": "event_time_claim", "from": "2026-09-02", "to": "2026-09-04"},
    "population",
)
FILTER = _node(
    "exclusions",
    "traditional.filter",
    {"where": [{"field": "subject_ref", "not_one_of": ["example-org:excluded"]}]},
    "window",
)


def _plan(*nodes: dict) -> dict:
    return {
        "header": {
            "contract_ref": CONTRACT,
            "ir_version": "evidence-plan-ir-v0",
            "planner_id": "local:example-org-planner",
            "created_at": "2026-09-06T00:00:00Z",
            "replay_seed": "example-org-seed-1",
        },
        "nodes": [copy.deepcopy(n) for n in nodes],
    }


PLAN = _plan(POPULATION, WINDOW, FILTER)
DATASET = build_dataset(PLAN, RECORDS)


def _case(plan: dict, records: list, dataset: dict | None = None) -> dict:
    """A case; a missing dataset is the one the plan builds, its plan_ref
    always the plan's own digest."""
    if dataset is None:
        dataset = {
            "dataset_version": "evidence-dataset-v0",
            "plan_ref": {"digest_alg": "SHA-256", "digest": json_digest(plan)},
            "rows": copy.deepcopy(DATASET["rows"]),
        }
    return {"plan": plan, "records": records, "dataset": dataset}


def cases() -> list[tuple[str, str | None, str, dict]]:
    """(name, base, expect, case): expect is "valid" or the refusal reason."""
    out = []

    def positive(name: str, plan: dict) -> None:
        out.append((name, None, "valid", {"plan": plan, "records": RECORDS, "dataset": build_dataset(plan, RECORDS)}))

    def negative(name: str, reason: str, case: dict, base: str = "pos-window-and-exclusion") -> None:
        out.append((name, base, reason, case))

    positive("pos-window-and-exclusion", PLAN)
    positive("pos-population-only", _plan(POPULATION))
    empty_window = copy.deepcopy(WINDOW)
    empty_window["params"].update({"from": "2026-10-01", "to": "2026-10-31"})
    positive("pos-empty-window", _plan(POPULATION, empty_window, FILTER))
    # equal, one_of and a boolean in one filter, then a second filter: seq 3
    # and 5 (odd seq is sample), of the four rows the window keeps.
    predicates = _node(
        "selection",
        "traditional.filter",
        {
            "where": [
                {"field": "epistemic_type", "equal": "producer_claim"},
                {"field": "record_type", "one_of": [EVENT, RUN]},
                {"field": "statement.sample", "equal": True},
            ]
        },
        "exclusions",
    )
    positive("pos-every-predicate", _plan(POPULATION, WINDOW, FILTER, predicates))
    # A record committed after through_seq with no canonical form (a float)
    # changes nothing: the book grew, and the plan still selects seq 2, 3, 5, 6.
    grown_book = copy.deepcopy(RECORDS)
    tail = _record(10, EVENT, "2026-09-03T10:00:00Z")
    tail["statement"]["ratio"] = 0.5
    grown_book.append(tail)
    out.append(("pos-book-grew-past-through-seq", None, "valid",
                {"plan": PLAN, "records": grown_book, "dataset": build_dataset(PLAN, grown_book)}))

    # rows-mismatch: the rows are not what the plan selects.
    dropped = copy.deepcopy(DATASET)
    del dropped["rows"][1]
    negative("neg-row-dropped", "rows-mismatch", _case(PLAN, RECORDS, dropped))
    duplicated = copy.deepcopy(DATASET)
    duplicated["rows"].insert(1, copy.deepcopy(duplicated["rows"][1]))
    negative("neg-row-duplicated", "rows-mismatch", _case(PLAN, RECORDS, duplicated))
    reordered = copy.deepcopy(DATASET)
    reordered["rows"][0], reordered["rows"][1] = reordered["rows"][1], reordered["rows"][0]
    negative("neg-rows-out-of-order", "rows-mismatch", _case(PLAN, RECORDS, reordered))
    grown = copy.deepcopy(DATASET)
    grown["rows"].append(row(RECORDS[8]))
    negative("neg-row-past-through-seq", "rows-mismatch", _case(PLAN, RECORDS, grown))
    edited = copy.deepcopy(RECORDS)
    edited[2]["statement"]["note"] += " (edited after the dataset was built)"
    negative("neg-record-edited", "rows-mismatch", _case(PLAN, edited, copy.deepcopy(DATASET)))

    # plan-ref-mismatch and dataset-invalid.
    other_plan = copy.deepcopy(DATASET)
    other_plan["plan_ref"]["digest"] = json_digest(_plan(POPULATION))
    negative("neg-plan-ref-mismatch", "plan-ref-mismatch", _case(PLAN, RECORDS, other_plan))
    extra = copy.deepcopy(DATASET)
    extra["window"] = WINDOW["params"]
    negative("neg-dataset-extra-member", "dataset-invalid", _case(PLAN, RECORDS, extra))
    valued = copy.deepcopy(DATASET)
    valued["rows"][0]["event_time_claim"] = RECORDS[1]["event_time_claim"]
    negative("neg-row-carries-a-value", "dataset-invalid", _case(PLAN, RECORDS, valued))

    # field-missing and field-type: a record that reaches a node.
    missing = copy.deepcopy(RECORDS)
    del missing[2]["event_time_claim"]
    negative("neg-window-field-missing", "field-missing", _case(PLAN, missing))
    dated = copy.deepcopy(RECORDS)
    dated[2]["event_time_claim"] = "2026-09-02"
    negative("neg-window-field-not-a-timestamp", "field-type", _case(PLAN, dated))
    no_offset = copy.deepcopy(RECORDS)
    no_offset[2]["event_time_claim"] = "2026-09-02T10:00:00"
    negative("neg-window-field-without-offset", "field-type", _case(PLAN, no_offset))
    object_filter = copy.deepcopy(FILTER)
    object_filter["params"]["where"] = [{"field": "statement", "not_one_of": ["example-org:excluded"]}]
    negative("neg-filter-field-not-a-scalar", "field-type", _case(_plan(POPULATION, WINDOW, object_filter), RECORDS))

    later_missing = copy.deepcopy(FILTER)
    later_missing["params"]["where"] = [
        {"field": "subject_ref", "equal": "example-org:nobody"},
        {"field": "statement.missing", "equal": True},
    ]
    negative(
        "neg-later-predicate-field-missing",
        "field-missing",
        _case(_plan(POPULATION, WINDOW, later_missing), RECORDS),
    )

    # plan-shape: not a dataset plan.
    first = copy.deepcopy(FILTER)
    first["inputs"] = [{"by": "node", "node_id": "population"}]
    negative(
        "neg-filter-before-population",
        "plan-shape",
        _case(_plan(first, POPULATION, _node("window", "traditional.window", WINDOW["params"], "population")), RECORDS),
    )
    skipping = copy.deepcopy(FILTER)
    skipping["inputs"] = [{"by": "node", "node_id": "population"}]
    negative("neg-filter-skips-the-window", "plan-shape", _case(_plan(POPULATION, WINDOW, skipping), RECORDS))
    decision = {
        "id": "verdict",
        "family": "decision",
        "operator": "decision.resolve_verdict",
        "inputs": [{"by": "node", "node_id": "exclusions"}],
        "classification": "CLOUD_SAFE",
        "tier": "recomputed",
        "contract_ref": CONTRACT,
        "requirement_ref": "req-daily-check",
    }
    negative("neg-mixed-operator", "plan-shape", _case(_plan(POPULATION, WINDOW, FILTER, decision), RECORDS))
    other_contract = copy.deepcopy(WINDOW)
    other_contract["contract_ref"] = "ec:example-org-other:2026-09-01@1"
    negative("neg-node-contract-differs", "plan-shape", _case(_plan(POPULATION, other_contract, FILTER), RECORDS))

    # plan-invalid: the schema, or a window day.
    unparamed = copy.deepcopy(POPULATION)
    del unparamed["params"]
    negative("neg-population-without-params", "plan-invalid", _case(_plan(unparamed, WINDOW, FILTER), RECORDS))
    numeric = copy.deepcopy(FILTER)
    numeric["params"]["where"] = [{"field": "seq", "equal": 3}]
    negative("neg-predicate-number", "plan-invalid", _case(_plan(POPULATION, WINDOW, numeric), RECORDS))
    newline = copy.deepcopy(WINDOW)
    newline["params"]["field"] = "event_time_claim\n"
    negative("neg-field-path-trailing-newline", "plan-invalid", _case(_plan(POPULATION, newline, FILTER), RECORDS))
    impossible = copy.deepcopy(WINDOW)
    impossible["params"]["to"] = "2026-09-31"
    negative("neg-window-day-impossible", "plan-invalid", _case(_plan(POPULATION, impossible, FILTER), RECORDS))
    reversed_window = copy.deepcopy(WINDOW)
    reversed_window["params"].update({"from": "2026-09-04", "to": "2026-09-02"})
    negative("neg-window-reversed", "plan-invalid", _case(_plan(POPULATION, reversed_window, FILTER), RECORDS))

    whitespace = _plan(POPULATION, WINDOW, FILTER)
    for holder in [whitespace["header"], *whitespace["nodes"]]:
        holder["contract_ref"] = CONTRACT + "\ufeff"  # ECMA-262 whitespace: refused by \S
    negative("neg-contract-ref-ecma-whitespace", "plan-invalid", _case(whitespace, RECORDS))

    # records-invalid.
    twice = copy.deepcopy(RECORDS)
    twice.append(_record(3, EVENT, "2026-09-03T11:00:00Z"))
    negative("neg-record-seq-twice", "records-invalid", _case(PLAN, twice))
    return out


def _write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    manifest = []
    for name, base, expect, case in cases():
        for part in ("plan", "records", "dataset"):
            _write(OUT_DIR / f"{name}.{part}.json", case[part])
        entry = {"name": name, "expect": expect}
        if base is not None:
            entry["base"] = base
        manifest.append(entry)
    _write(OUT_DIR / "cases.json", manifest)
    print(f"wrote {len(manifest)} case(s) to {OUT_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
