#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate the conformance vectors of the verdict counts member of the Inference-Service History
Profile v0 (``spec/inference-service-history-profile-v0.md`` §4.3, §5.3, §6; open point SH-14).

They are built on the Standard History of ``generate_inference_service_history_v0_vectors.py``: the
same node stream, definition frame, period policy and card, with a third member, ``verdict_counts``,
that counts the referee verdicts the node holds about itself, per closed period, per model hash and
per result. Every expected status is stated by hand from the profile text and each case cites the
sections it comes from. Nothing here imports or runs a verifier.

The member's shape is fixed for these vectors only and is not registered (SH-12):
``{"check": "referee_verdict", "signed_by": "checker", "policy": <digest>, "periods": [...]}``; a
period lists, for each of the four results in the order of §5.3, one cell per model hash and then
the result's total, in the unit ``referee_verdicts``, labelled ``self_reported``. Each result is a
table of its own with the floor and complementary suppression of §6.2; no total across results is
listed. Whether the node or the other party asked the referee is not in the artifact (§5.3).

Output: ``vectors/inference-service-history-verdicts-v0/`` (or ``--out DIR``). Deterministic.
``README.md`` is never rewritten; every file in the directory is listed in ``SHA256SUMS``.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import generate_inference_service_history_v0_vectors as g

ROOT = g.ROOT
DEFAULT_OUT = ROOT / "vectors" / "inference-service-history-verdicts-v0"
SET = "aac-inference-service-history-verdicts-v0"
SPEC = g.SPEC
NAME = "service_history_verdicts_example/0"
RESULTS = ["corroborated", "contradicted", "inconclusive", "not_comparable"]  # §5.3
UNIT = "referee_verdicts"
FLOOR = g.POLICY["floor"]
STATUS = ("Conformance vectors for the verdict counts member of the informational Inference-Service History "
          "Profile v0. Every key is a test key derived from a public seed; never use one for anything else.")

# What the node holds, per closed period (1 to 3 October): result -> model hash -> verdicts.
H1, H2 = g.shx(b"verdict vectors: model identity hash 1"), g.shx(b"verdict vectors: model identity hash 2")
HELD = [
    # Period 1: contradicted has 3 (under the floor, so its total is withheld); not_comparable has 5, the floor.
    {"corroborated": {H1: 9, H2: 6}, "contradicted": {H1: 3}, "inconclusive": {}, "not_comparable": {H2: 5}},
    # Period 2: contradicted has H1 7 and H2 2: H2 is under the floor beside a published total of 9, so
    # H1 is withheld with it (§6.2 item 3, complementary).
    {"corroborated": {H1: 5}, "contradicted": {H1: 7, H2: 2}, "inconclusive": {H2: 11}, "not_comparable": {}},
    # Period 3.
    {"corroborated": {H1: 20, H2: 8}, "contradicted": {}, "inconclusive": {H1: 5, H2: 6}, "not_comparable": {H1: 1}},
]


def vcell(result: str, model_hash: str | None, value: int | None, *, suppressed: str | None = None,
          unit: str = UNIT, label: str = "self_reported") -> dict:
    dimension = {"result": result} if model_hash is None else {"model_hash": model_hash, "result": result}
    c: dict[str, Any] = {"dimension": dimension, "label": label, "unit": unit, "value": value}
    if suppressed is not None:
        c["value"] = None
        c["suppressed"] = suppressed
    return c


def result_cells(result: str, per_model: dict[str, int]) -> list[dict]:
    """§6.2 by hand, one result's table: a cell under the floor is withheld; where a published total
    stands beside exactly one withheld model, the smallest other published model goes with it."""
    total = sum(per_model.values())
    below = [m for m, n in per_model.items() if n < FLOOR]
    comp: set[str] = set()
    if total >= FLOOR and len(below) == 1:
        others = [m for m in per_model if m not in below]
        if others:
            comp = {min(others, key=lambda m: (per_model[m], m))}
    cells = []
    for m in sorted(per_model):
        if m in below:
            cells.append(vcell(result, m, None, suppressed="below_floor"))
        elif m in comp:
            cells.append(vcell(result, m, None, suppressed="complementary"))
        else:
            cells.append(vcell(result, m, per_model[m]))
    cells.append(vcell(result, None, None, suppressed="below_floor") if total < FLOOR
                 else vcell(result, None, total))
    return cells


def verdict_counts(held: list[dict] = HELD) -> dict:
    periods = []
    for i, by_result in enumerate(held):
        cells = [c for r in RESULTS for c in result_cells(r, by_result[r])]
        periods.append({"cells": cells, "from": g.DAY[i], "to": g.DAY[i + 1]})
    return {"check": "referee_verdict", "periods": periods, "policy": g.POLICY_DIGEST, "signed_by": "checker"}


def definition() -> dict:
    d = g.standard_definition()
    d["name"] = NAME
    d["members"] = d["members"] + [{
        "name": "verdict_counts", "required": True,
        "reads": ["record: referee verdict held by this node", "record: model identity hash",
                  "record: committed_at"],
        "units": [{"where": "periods[].cells[]", "unit": UNIT}],
        "claims": {"asserted_by": "provider", "label": "provider states",
                   "where": ["periods[].cells[].dimension.model_hash"]},
    }]
    reads: list[str] = []
    for m in d["members"]:
        reads += [r for r in m["reads"] if r not in reads]
    d["reads"] = reads
    d["spec"] = "vectors/inference-service-history-verdicts-v0/README.md"
    return d


def history(counts: dict | None = None, verdicts: dict | None = None, d: dict | None = None,
            declare: bool = True) -> dict:
    d = d or definition()
    members = {"period_counts": counts or g.period_counts()}
    if declare:
        members["verdict_counts"] = verdicts or verdict_counts()
    art = g.artifact(d, g.ANCHOR_N, 3, members)
    if not declare:
        art["verdict_counts"] = verdicts or verdict_counts()
    return g.history(d, "requester-1/verdicts", art, "2026-10-04T00:00:05Z")


def cases() -> list[dict]:
    out: list[dict] = []

    def case(cid: str, title: str, cites: list[str], source: str, h: dict, fail: str | None) -> None:
        hprops = g.props(g.STANDARD_PROPS, **({fail: "FAIL"} if fail else {}))
        if fail == "artifact_form":
            # §8.3: when artifact_form is FAIL no property after it is reported.
            keep = g.STANDARD_PROPS[:g.STANDARD_PROPS.index("artifact_form") + 1]
            hprops = {k: hprops[k] for k in keep}
        cov = g.standard_coverage()
        out.append({"id": cid, "title": title, "cites": cites, "source": source, "kind": "history",
                    "pins": g.pins(), "inputs": h,
                    "expected": {"exchange": g.answered(h["reply"]), "history_properties": hprops, "coverage": cov,
                                 "shows": {"witness": g.witness(3)}, "accepted": fail is None,
                                 "fails": [fail] if fail else []}})

    case("verdict-counts-held",
         "A Standard History whose verdict counts show all four results, a cell under the floor and a complementary one",
         ["§4.3", "§5.3", "§6.1", "§6.2", "§6.3"], "constructed", history(), None)

    def tampered(edit) -> dict:
        v = verdict_counts()
        edit(v)
        return history(verdicts=v)

    def first(v: dict, **where) -> dict:
        return next(c for p in v["periods"] for c in p["cells"]
                    if all(c["dimension"].get(k) == x for k, x in where.items()) and c["value"] is not None)

    case("mutant-verdict-cell-below-floor", "A verdict cell published with a value under the floor",
         ["§6.2", "§6.3"], "constructed: the contradicted total of period 2 published as 4",
         tampered(lambda v: first(v, result="contradicted", model_hash=None).update(value=4)), "period_floor")

    def drop_complementary(v: dict) -> None:
        c = next(c for c in v["periods"][1]["cells"]
                 if c["dimension"] == {"model_hash": H1, "result": "contradicted"})
        c.update(value=7, suppressed=None)
        del c["suppressed"]
    case("mutant-verdict-complementary-not-suppressed",
         "A withheld model beside a published total, with no other cell withheld with it",
         ["§6.2"], "constructed: period 2's H1 contradicted cell published as 7", tampered(drop_complementary),
         "period_floor")

    def drop_table(v: dict) -> None:
        v["periods"][1]["cells"] = [c for c in v["periods"][1]["cells"]
                                    if c["dimension"]["result"] != "inconclusive"]
    case("mutant-verdict-result-table-dropped", "A period that lists no inconclusive cells at all",
         ["§5.3", "§13 SH-12"], "constructed: period 2 without its inconclusive table", tampered(drop_table),
         "artifact_form")

    def withheld_with_a_value(v: dict) -> None:
        c = next(c for c in v["periods"][0]["cells"] if c.get("suppressed") == "below_floor")
        c["value"] = 3
    case("mutant-verdict-withheld-cell-carries-a-value", "A withheld cell that still states its value",
         ["§6.2", "§6.3"], "constructed: period 1's under-floor contradicted cell with the value 3",
         tampered(withheld_with_a_value), "period_floor")

    def unknown_reason(v: dict) -> None:
        c = next(c for c in v["periods"][0]["cells"] if c.get("suppressed") == "below_floor")
        c["suppressed"] = "because"
    case("mutant-verdict-withheld-for-an-unknown-reason", "A withheld cell whose reason is not one of the profile's",
         ["§6.2", "§6.3"], "constructed: period 1's under-floor contradicted cell withheld as 'because'",
         tampered(unknown_reason), "period_floor")

    def another_unit(v: dict) -> None:
        v["periods"][0]["cells"][0]["unit"] = "exchanges_served"
    case("mutant-verdict-cell-in-another-unit", "A verdict cell counted in exchanges_served",
         ["§5.1"], "constructed: the first cell's unit changed", tampered(another_unit), "units")

    def stronger(v: dict) -> None:
        v["periods"][0]["cells"][0]["label"] = "peer_confirmed"
    case("mutant-verdict-cell-labelled-peer-confirmed", "A verdict count labelled peer_confirmed",
         ["§5.3", "§7.1"], "constructed: the first cell's label changed", tampered(stronger), "labels")

    def by_node(v: dict) -> None:
        v["signed_by"] = "node"
    case("mutant-verdict-counts-signed-by-the-node", "A verdict count that names the node itself as the signer",
         ["§5.3", "§13 SH-12"], "constructed: signed_by node", tampered(by_node), "artifact_form")

    def other_check(v: dict) -> None:
        v["check"] = "audit_result"
    case("mutant-verdict-counts-of-another-check", "A verdict count that names another kind of check",
         ["§5.3", "§13 SH-12"], "constructed: check audit_result", tampered(other_check), "artifact_form")

    def blended(v: dict) -> None:
        v["periods"][0]["cells"].append(vcell("all", None, 34))
    case("mutant-verdict-results-added-together", "A cell adding the results into one figure",
         ["§5.1", "§5.3", "§13 SH-12"], "constructed: a cell with the dimension {result: all} and the value 34",
         tampered(blended), "artifact_form")

    def swapped(v: dict) -> None:
        cells = v["periods"][0]["cells"]
        cells[0], cells[1] = cells[1], cells[0]
    case("mutant-verdict-models-out-of-order", "A result's model cells not in model hash order",
         ["§5.3", "§13 SH-12"], "constructed: the first two cells of period 1 swapped", tampered(swapped),
         "artifact_form")

    def other_policy(v: dict) -> None:
        v["policy"] = "0" * 64
    case("mutant-verdict-counts-name-another-policy", "Verdict counts naming another period policy",
         ["§6.1", "§6.3"], "constructed: policy digest changed", tampered(other_policy), "period_alignment")

    def dropped_period(v: dict) -> None:
        v["periods"].pop(1)
    case("mutant-verdict-counts-omit-a-period", "Verdict counts that leave a closed period out",
         ["§6.1", "§6.3"], "constructed: period 2 removed", tampered(dropped_period), "period_alignment")

    case("mutant-verdict-counts-undeclared", "A verdict_counts member the artifact does not declare",
         ["§8.2", "§13 SH-12"], "constructed: declared lists only history_card and period_counts",
         history(declare=False), "artifact_form")
    return out


def build() -> dict[str, bytes]:
    all_cases = cases()
    ids = [c["id"] for c in all_cases]
    assert len(ids) == len(set(ids))
    corpus = {
        "set": SET, "status": STATUS, "profile": g.PROFILE, "history_profile": g.HISTORY_PROFILE, "spec": SPEC,
        "example_definitions": [NAME],
        "test_keys": {"note": "TEST-ONLY. Each private key is the 32-byte Ed25519 seed SHA-256(seed_label).",
                      "keys": {n: {"seed_label": g.SEED_LABELS[n], "public": g.PUB[n]} for n in g.SEED_LABELS}},
        "period_policy": {"document": g.POLICY, "digest": g.POLICY_DIGEST},
        "results": RESULTS, "unit": UNIT, "standard_properties": g.STANDARD_PROPS,
        "count": len(all_cases), "cases": all_cases,
    }
    files = {"vectors.json": g._dump(corpus)}
    files["manifest.json"] = g._dump({
        "set": SET, "status": STATUS, "spec": SPEC,
        "generator": "python/scripts/generate_inference_service_history_verdicts_v0_vectors.py",
        "files": [{"path": n, "sha256": g.shx(d), "count": json.loads(d).get("count")}
                  for n, d in sorted(files.items())],
    })
    return files


def write(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for name, data in build().items():
        (out / name).write_bytes(data)
    files = sorted((p.relative_to(out).as_posix(), p) for p in out.rglob("*") if p.is_file())
    lines = [f"{g.shx(p.read_bytes())}  {rel}" for rel, p in files if rel != "SHA256SUMS"]
    (out / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    write(args.out or DEFAULT_OUT)


if __name__ == "__main__":
    main()
