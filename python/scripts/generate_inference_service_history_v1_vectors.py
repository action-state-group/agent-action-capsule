#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate the conformance vectors of ``inference-service-history/1``
(``spec/inference-service-history-profile-v0.md`` §6.2 item 5, SH-8).

``/1`` is ``/0`` with one more complementary rule: where a table's total is published and two or
more of its dimension cells are withheld, every one ``below_floor``, and the rest of the total (the
total less its published cells) is the number of those cells or that number times ``floor`` - 1,
the total fixes each of them, so it is withheld ``complementary``, even when it is under the floor
too. A dimension cell is listed only for a value the period counted.

These cases are built on ``generate_inference_service_history_v0_vectors.py``'s Standard History
under ``evidence-interop/1``: the same node stream, card, period policy (floor 5) and envelopes,
with definitions naming ``inference-service-history/1`` and 2 October's cells replaced by the
table each case is about. The counts carry no records (§4.2), so a table need not match the card's
log sizes. Two cases add the verdict counts member of
``generate_inference_service_history_verdicts_v0_vectors.py``, whose result tables follow the same
rule under ``/1``. Every expected status is stated by hand from the profile text; nothing here runs a
verifier.

Output: ``vectors/inference-service-history-v1/`` (or ``--out DIR``). Deterministic. ``README.md`` is
never rewritten; every file in the directory is listed in ``SHA256SUMS``.
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any

import generate_inference_service_history_v0_vectors as g
import generate_inference_service_history_verdicts_v0_vectors as gv
import history_frame

g.use_profile(1)

ROOT = g.ROOT
DEFAULT_OUT = ROOT / "vectors" / "inference-service-history-v1"
SET = "aac-inference-service-history-v1"
SPEC = g.SPEC
HISTORY_PROFILE = "inference-service-history/1"
STANDARD = "service_history_example/1"
VERDICTS = "service_history_verdicts_example/1"
FLOOR = g.POLICY["floor"]
STATUS = ("Conformance vectors for inference-service-history/1 of the informational Inference-Service "
          "History Profile, over evidence-interop/1. Every key is a test key derived from a public seed; "
          "never use one for anything else.")


def withheld(per_model: dict[str, int]) -> tuple[set[str], set[str], str | None]:
    """§6.2 by hand under ``/1``, for one table: the cells withheld ``below_floor``, those withheld
    ``complementary``, and the total's reason (``None`` when it is published)."""
    total = sum(per_model.values())
    below = {m for m, n in per_model.items() if n < FLOOR}
    total_why = "below_floor" if total < FLOOR else None
    comp: set[str] = set()
    others = [m for m in per_model if m not in below]
    if total_why is None and len(below) == 1 and others:
        comp = {min(others, key=lambda m: (per_model[m], m))}
    rest = total - sum(n for m, n in per_model.items() if m not in below)
    if not comp and len(below) >= 2 and rest in (len(below), len(below) * (FLOOR - 1)):
        total_why = "complementary"
    return below, comp, total_why


def period_cells(per_model: dict[str, int]) -> list[dict]:
    assert all(n >= 1 for n in per_model.values()), "a cell is listed only when counted"
    below, comp, total_why = withheld(per_model)
    out = []
    for m in sorted(per_model):
        why = "below_floor" if m in below else "complementary" if m in comp else None
        out.append(g.cell(None if why else per_model[m], {"model": m}, suppressed=why))
    out.append(g.cell(None if total_why else sum(per_model.values()), None, suppressed=total_why))
    return out


def period_counts(day2: dict[str, int] | None = None) -> dict:
    served = copy.deepcopy(g.SERVED)
    if day2 is not None:
        served[1] = day2
    return {"periods": [{"cells": period_cells(c), "from": g.DAY[i], "to": g.DAY[i + 1]}
                        for i, c in enumerate(served)], "policy": g.POLICY_DIGEST}


def standard_definition() -> dict:
    d = g.standard_definition()
    d.update(profile=HISTORY_PROFILE, name=STANDARD, spec="vectors/inference-service-history-v1/README.md")
    return d


def verdict_cells(result: str, per_model: dict[str, int]) -> list[dict]:
    below, comp, total_why = withheld(per_model)
    out = []
    for m in sorted(per_model):
        why = "below_floor" if m in below else "complementary" if m in comp else None
        out.append(gv.vcell(result, m, None if why else per_model[m], suppressed=why))
    out.append(gv.vcell(result, None, None if total_why else sum(per_model.values()), suppressed=total_why))
    return out


def verdict_counts(held: list[dict]) -> dict:
    periods = []
    for i, by_result in enumerate(held):
        cells = [c for r in gv.RESULTS for c in verdict_cells(r, by_result[r])]
        periods.append({"cells": cells, "from": g.DAY[i], "to": g.DAY[i + 1]})
    return {"check": "referee_verdict", "periods": periods, "policy": g.POLICY_DIGEST, "signed_by": "checker"}


def verdicts_definition() -> dict:
    d = gv.definition()
    d.update(profile=HISTORY_PROFILE, name=VERDICTS, spec="vectors/inference-service-history-v1/README.md")
    return d


# What the node holds about itself for the verdict cases: 2 October's contradicted verdicts are 4
# about each model hash, a total of 8 that fixes both.
HELD = copy.deepcopy(gv.HELD)
HELD[1]["contradicted"] = {gv.H1: 4, gv.H2: 4}


def history(d: dict, members: dict, nonce: str) -> dict:
    return g.history(d, nonce, g.artifact(d, g.ANCHOR_N, 3, members), "2026-10-04T00:00:05Z")


def cases() -> list[dict]:
    out: list[dict] = []

    def case(cid: str, title: str, source: str, h: dict, fail: str | None,
             cites: tuple[str, ...] = ("§6.2", "§6.3", "§9")) -> None:
        hprops = g.props(g.STANDARD_PROPS, **({fail: "FAIL"} if fail else {}))
        out.append({"id": cid, "title": title, "cites": list(cites), "source": source, "kind": "history",
                    "pins": g.pins(), "inputs": h,
                    "expected": {"exchange": g.answered(h["reply"]), "history_properties": hprops,
                                 "coverage": g.standard_coverage(), "shows": {"witness": g.witness(3)},
                                 "accepted": fail is None, "fails": [fail] if fail else []}})

    d = standard_definition()

    def std(counts: dict, nonce: str = "requester-1/v1") -> dict:
        return history(d, {"period_counts": counts}, nonce)

    case("v1-standard-served", "The served-only History under /1: one withheld model and its partner, as under /0",
         "constructed: the base set's served counts; 2 October's model-b (3) is under the floor beside a "
         "published total, so model-a goes with it", std(period_counts()), None)
    case("v1-total-withheld-two-under-floor", "Two models of 4 under a floor of 5: the total of 8 is withheld",
         "constructed: 2 October served 4 by model-a and 4 by model-b", std(period_counts({"model-a": 4, "model-b": 4})),
         None)
    case("v1-total-withheld-five-ones", "Five models of 1 each: the total of 5 is withheld",
         "constructed: 2 October served 1 by each of five models",
         std(period_counts({f"model-{x}": 1 for x in "abcde"})), None)
    case("v1-total-under-floor-withheld-complementary",
         "Two models of 1: the total of 2, under the floor, is withheld complementary, so the reason does not "
         "tell it from a total of 8", "constructed: 2 October served 1 by model-a and 1 by model-b",
         std(period_counts({"model-a": 1, "model-b": 1})), None)
    case("v1-total-pins-nothing-published", "Models of 3 and 4: the total of 7 fixes neither and is published",
         "constructed: 2 October served 3 by model-a and 4 by model-b",
         std(period_counts({"model-a": 3, "model-b": 4})), None)

    def published(day2: dict[str, int]) -> dict:
        counts = period_counts(day2)
        total = counts["periods"][1]["cells"][-1]
        assert total.get("suppressed") == "complementary"
        del total["suppressed"]
        total["value"] = sum(day2.values())
        return counts

    case("mutant-v1-total-pins-two-under-floor", "Two models of 4 withheld beside a published total of 8",
         "constructed: v1-total-withheld-two-under-floor with the total published",
         std(published({"model-a": 4, "model-b": 4})), "period_floor")
    case("mutant-v1-total-pins-five-ones", "Five models of 1 withheld beside a published total of 5",
         "constructed: v1-total-withheld-five-ones with the total published",
         std(published({f"model-{x}": 1 for x in "abcde"})), "period_floor")
    case("mutant-v1-total-pins-beside-published",
         "A published model of 10 and two of 4 withheld beside a published total of 18: the rest of 8 fixes both",
         "constructed: 2 October served 10 by model-a, 4 by model-b and 4 by model-c, the total published",
         std(published({"model-a": 10, "model-b": 4, "model-c": 4})), "period_floor")

    short = period_counts({"model-a": 10, "model-b": 1, "model-c": 1, "model-d": 1})
    total = short["periods"][1]["cells"][-1]
    assert total.get("suppressed") == "complementary"
    del total["suppressed"]
    total["value"] = 12
    case("mutant-v1-total-short-of-withheld",
         "A published model of 10 and three withheld beside a published total of 12: three listed cells hold at "
         "least 1 each, so the total is at least 13",
         "constructed: 2 October's three withheld models beside a total 2 more than the published cells",
         std(short), "period_floor")

    beyond = published({"model-a": 10, "model-b": 4, "model-c": 4})
    beyond["periods"][1]["cells"][-1]["value"] = 19
    case("mutant-v1-total-over-withheld",
         "A published model of 10 and two withheld under the floor beside a published total of 19: two cells "
         "under a floor of 5 hold at most 8",
         "constructed: mutant-v1-total-pins-beside-published with the total raised to 19",
         std(beyond), "period_floor")

    over = period_counts()
    total = over["periods"][1]["cells"][-1]
    total.update(value=None, suppressed="complementary")
    case("mutant-v1-total-withheld-beside-one-model",
         "One model withheld under the floor, its partner and the total withheld complementary",
         "constructed: v1-standard-served with 2 October's total withheld complementary; /1 withholds a total "
         "only beside two or more models under the floor", std(over), "period_floor")

    vd = verdicts_definition()
    case("v1-verdict-total-withheld",
         "A verdict result's table under /1: 4 contradicted about each of two model hashes, total withheld",
         "constructed: the verdict set's verdicts with 2 October's contradicted ones 4 and 4",
         history(vd, {"period_counts": period_counts(), "verdict_counts": verdict_counts(HELD)}, "requester-1/v1-verdicts"),
         None, ("§5.3", "§6.2", "§6.3", "§9"))
    leak = verdict_counts(HELD)
    vt = next(c for c in leak["periods"][1]["cells"] if c["dimension"] == {"result": "contradicted"})
    assert vt.get("suppressed") == "complementary"
    del vt["suppressed"]
    vt["value"] = 8
    case("mutant-v1-verdict-total-pins", "The same verdict table with the contradicted total of 8 published",
         "constructed: v1-verdict-total-withheld with 2 October's contradicted total published",
         history(vd, {"period_counts": period_counts(), "verdict_counts": leak}, "requester-1/v1-verdicts"),
         "period_floor", ("§5.3", "§6.2", "§6.3", "§9"))
    return out


def check_frame(all_cases: list[dict]) -> None:
    """HF §6.3: ``inference-service-history/1``'s counting table and wording pack are ``/0``'s with
    the instance and the fixed ``profile`` changed, and every case's definition names ``/1``."""
    t1, p1 = history_frame.load(HISTORY_PROFILE)
    t0, p0 = history_frame.load("inference-service-history/0")
    want = copy.deepcopy(t0)
    want["instance"] = HISTORY_PROFILE
    want["definition_fixed"]["profile"] = HISTORY_PROFILE
    assert t1 == want, "counting table differs from /0's but for the instance"
    assert p1 == dict(p0, instance=HISTORY_PROFILE), "wording pack differs from /0's but for the instance"
    for c in all_cases:
        assert c["inputs"]["definition"]["profile"] == HISTORY_PROFILE, c["id"]
        assert c["expected"]["accepted"] is history_frame.accepted(c["expected"]["history_properties"],
                                                                   t1["may_be_not_checked"]), c["id"]


def build() -> dict[str, bytes]:
    all_cases = cases()
    ids = [c["id"] for c in all_cases]
    assert len(ids) == len(set(ids)), "duplicate case id"
    check_frame(all_cases)
    corpus: dict[str, Any] = {
        "set": SET, "status": STATUS, "profile": g.PROFILE, "history_profile": HISTORY_PROFILE, "spec": SPEC,
        "example_definitions": [STANDARD, VERDICTS],
        "test_keys": {"note": "TEST-ONLY. Each private key is the 32-byte Ed25519 seed SHA-256(seed_label).",
                      "keys": {n: {"seed_label": g.SEED_LABELS[n], "public": g.PUB[n]} for n in g.SEED_LABELS}},
        "contract": {"document": g.CONTRACT, "document_jcs": g.jcs(g.CONTRACT), "contract_ref": g.CONTRACT_REF,
                     "contract_digest": g.CONTRACT_DIGEST, "schema": g.EC_SCHEMA},
        "period_policy": {"document": g.POLICY, "digest": g.POLICY_DIGEST},
        "standard_properties": g.STANDARD_PROPS,
        "count": len(all_cases), "cases": all_cases,
    }
    files = {"vectors.json": g._dump(corpus)}
    files["manifest.json"] = g._dump({
        "set": SET, "status": STATUS, "spec": SPEC,
        "generator": "python/scripts/generate_inference_service_history_v1_vectors.py",
        "files": [{"path": n, "sha256": g.shx(b), "count": json.loads(b).get("count")}
                  for n, b in sorted(files.items())],
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
