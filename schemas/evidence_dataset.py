# SPDX-License-Identifier: BSD-3-Clause
"""
evidence_dataset.py

The Python reference for a dataset plan and its dataset
(spec/evidence-plan-ir-v0.md sections 5.1 and 6.2): run a dataset plan over a
book's committed record headers, and check a dataset document against that
run. go/evidenceplan is the Go gate; both read vectors/evidence-dataset/ and
must refuse each negative with the same reason.

A refusal is a DatasetError whose `reason` is one of REASONS:

  plan-invalid       the plan fails $defs/EvidencePlan, or a window day does
                     not exist or ends before it starts
  plan-shape         the plan is not a dataset plan: section 5.1's chain, ids
                     or contract_ref rule is broken
  dataset-invalid    the dataset fails $defs/Dataset
  plan-ref-mismatch  dataset.plan_ref is not the digest of the plan
  records-invalid    a record header lacks the book_id, seq or record_type the
                     population reads, or two share a seq
  field-missing      a record that reaches a window or filter node lacks the
                     field it names
  field-type         that field holds a value the node cannot read
  rows-mismatch      the dataset's rows are not the rows the plan selects
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from check_evidence_result_examples import (  # noqa: E402
    _calendar_date,
    _utc_date,
    _validator_for,
)

from agent_action_capsule.canonical import json_digest  # noqa: E402

SCHEMA_PATH = Path(__file__).resolve().parent / "evidence-plan-ir-v0.json"

REASONS = (
    "plan-invalid",
    "plan-shape",
    "dataset-invalid",
    "plan-ref-mismatch",
    "records-invalid",
    "field-missing",
    "field-type",
    "rows-mismatch",
)

POPULATION = "traditional.population"
WINDOW = "traditional.window"
FILTER = "traditional.filter"

class DatasetError(Exception):
    def __init__(self, reason: str, message: str):
        assert reason in REASONS, reason
        super().__init__(f"{reason}: {message}")
        self.reason = reason


_validators: dict = {}


def _validator(defn: str):
    if defn not in _validators:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        schema["$ref"] = f"#/$defs/{defn}"
        _validators[defn] = _validator_for(schema)
    return _validators[defn]


def _digest(value: object, reason: str, what: str) -> str:
    # A digest-bearing document holds no float and no integer outside
    # +-(2**53 - 1) (the canonical form both gates share).
    try:
        return json_digest(value)
    except ValueError as exc:
        raise DatasetError(reason, f"{what} has no canonical form: {exc}") from None


def _schema_error(defn: str, instance: object) -> str | None:
    errors = sorted(_validator(defn).iter_errors(instance), key=lambda e: list(e.absolute_path))
    if not errors:
        return None
    error = errors[0]
    return "/" + "/".join(str(p) for p in error.absolute_path) + ": " + error.message


def dataset_nodes(plan: dict) -> list[dict]:
    """The plan's nodes, once the plan is shown to be a dataset plan."""
    error = _schema_error("EvidencePlan", plan)
    if error is not None:
        raise DatasetError("plan-invalid", error)
    _digest(plan, "plan-invalid", "the plan")
    nodes = plan["nodes"]
    header_contract = plan["header"]["contract_ref"]
    seen = set()
    for index, node in enumerate(nodes):
        where = f"nodes[{index}] ({node['id']})"
        if node["id"] in seen:
            raise DatasetError("plan-shape", f"{where}: node ids are unique within a plan")
        seen.add(node["id"])
        if node["contract_ref"] != header_contract:
            raise DatasetError("plan-shape", f"{where}: contract_ref differs from the header's")
        operator = node["operator"]
        if operator not in (POPULATION, WINDOW, FILTER):
            raise DatasetError("plan-shape", f"{where}: {operator} is not a dataset operator")
        if (index == 0) != (operator == POPULATION):
            raise DatasetError("plan-shape", f"{where}: a dataset plan has one population node, first")
        if index > 0 and node["inputs"][0]["node_id"] != nodes[index - 1]["id"]:
            raise DatasetError("plan-shape", f"{where}: reads {node['inputs'][0]['node_id']!r}, not the node before it")
        if operator == WINDOW:
            start = _calendar_date(node["params"]["from"])
            end = _calendar_date(node["params"]["to"])
            if start is None or end is None:
                raise DatasetError("plan-invalid", f"{where}: a window day does not exist")
            if end < start:
                raise DatasetError("plan-invalid", f"{where}: the window ends before it starts")
    return nodes


def _field(record: dict, path: str) -> tuple[bool, object]:
    value: object = record
    for name in path.split("."):
        if not isinstance(value, dict) or name not in value:
            return False, None
        value = value[name]
    return True, value


def _read(record: dict, path: str, where: str) -> object:
    found, value = _field(record, path)
    if not found:
        raise DatasetError("field-missing", f"{where}: record seq {record['seq']} has no {path}")
    return value


def _in_window(record: dict, params: dict, where: str) -> bool:
    value = _read(record, params["field"], where)
    day = _utc_date(value) if isinstance(value, str) else None
    if day is None:
        raise DatasetError(
            "field-type",
            f"{where}: record seq {record['seq']} {params['field']} is not an RFC 3339 date-time with an offset",
        )
    return _calendar_date(params["from"]) <= day <= _calendar_date(params["to"])


def _same(a: object, b: object) -> bool:
    # Strings and booleans only (the schema's Scalar), compared with their
    # type, so True never equals a string.
    return type(a) is type(b) and a == b


def _passes(record: dict, params: dict, where: str) -> bool:
    # Every predicate's field is read before any is applied, so a record
    # missing a later predicate's field is refused whatever the earlier ones
    # decide, and the order of `where` never changes the outcome.
    values = []
    for predicate in params["where"]:
        value = _read(record, predicate["field"], where)
        if type(value) not in (str, bool):
            raise DatasetError(
                "field-type", f"{where}: record seq {record['seq']} {predicate['field']} is not a string or boolean"
            )
        values.append(value)
    for predicate, value in zip(params["where"], values):
        if "equal" in predicate:
            ok = _same(value, predicate["equal"])
        elif "one_of" in predicate:
            ok = any(_same(value, s) for s in predicate["one_of"])
        else:
            ok = not any(_same(value, s) for s in predicate["not_one_of"])
        if not ok:
            return False
    return True


def _population(records: object, params: dict) -> list[dict]:
    if not isinstance(records, list) or not all(isinstance(r, dict) for r in records):
        raise DatasetError("records-invalid", "records are not a JSON array of objects")
    book = params["book_id"]
    by_seq: dict[int, dict] = {}
    for index, record in enumerate(records):
        if not isinstance(record.get("book_id"), str):
            raise DatasetError("records-invalid", f"records[{index}] has no string book_id")
        if record["book_id"] != book:
            continue
        seq = record.get("seq")
        if type(seq) is not int or seq < 0 or not isinstance(record.get("record_type"), str):
            raise DatasetError("records-invalid", f"records[{index}] has no non-negative integer seq and string record_type")
        if seq in by_seq:
            raise DatasetError("records-invalid", f"records[{index}]: seq {seq} appears twice in book {book!r}")
        by_seq[seq] = record
    selected = [
        by_seq[seq]
        for seq in sorted(by_seq)
        if seq <= params["through_seq"] and by_seq[seq]["record_type"] in params["record_types"]
    ]
    # Only a selected record is digested, so a record committed after
    # through_seq never changes the run.
    for record in selected:
        _digest(record, "records-invalid", f"record seq {record['seq']}")
    return selected


def row(record: dict) -> dict:
    """A dataset row: the record by the digest of its header (section 6.2)."""
    return {
        "seq": record["seq"],
        "record_type": record["record_type"],
        "digest_alg": "SHA-256",
        "digest": json_digest(record),
    }


def run_plan(plan: dict, records: object) -> list[dict]:
    """The rows a dataset plan selects from a book's record headers."""
    nodes = dataset_nodes(plan)
    selected = _population(records, nodes[0]["params"])
    for index, node in enumerate(nodes[1:], start=1):
        where = f"nodes[{index}] ({node['id']})"
        keep = _in_window if node["operator"] == WINDOW else _passes
        selected = [r for r in selected if keep(r, node["params"], where)]
    return [row(r) for r in selected]


def build_dataset(plan: dict, records: object) -> dict:
    rows = run_plan(plan, records)  # validates the plan before it is digested
    return {
        "dataset_version": "evidence-dataset-v0",
        "plan_ref": {"digest_alg": "SHA-256", "digest": json_digest(plan)},
        "rows": rows,
    }


def check_dataset(plan: dict, dataset: object, records: object) -> None:
    """Refuse (raise DatasetError) unless dataset is what plan selects from records."""
    dataset_nodes(plan)
    error = _schema_error("Dataset", dataset)
    if error is not None:
        raise DatasetError("dataset-invalid", error)
    _digest(dataset, "dataset-invalid", "the dataset")
    if dataset["plan_ref"]["digest"] != json_digest(plan):
        raise DatasetError("plan-ref-mismatch", "dataset.plan_ref is not the digest of the plan")
    want = run_plan(plan, records)
    if dataset["rows"] != want:
        raise DatasetError(
            "rows-mismatch",
            f"the dataset has {len(dataset['rows'])} row(s); the plan selects {len(want)}"
            + ("" if len(want) != len(dataset["rows"]) else ", in another order or with other digests"),
        )


__all__ = ["DatasetError", "REASONS", "build_dataset", "check_dataset", "row", "run_plan"]
