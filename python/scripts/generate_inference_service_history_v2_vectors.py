#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate the conformance vectors of ``inference-service-history/2``
(``spec/inference-service-history-profile-v0.md`` §6.2 item 6, SH-8).

``/2`` is ``/1`` with one more complementary rule. Take a table with exactly two dimension cells
withheld: one ``below_floor`` (``x``) and item 3's ``complementary`` partner (``p``). The reader
knows ``1 <= x <= floor - 1``, ``floor <= p`` and ``x + p = r``, the total less its published
cells. Where a dimension cell is still published, the reader also knows ``p <= m``, the smallest
of them. So ``max(1, r - m) <= x <= min(floor - 1, r - floor)``. Where that range holds one
value, the total is withheld ``complementary`` too.

Two sets are written:

- ``vectors/inference-service-history-v2/``: the ``/1`` cases under ``/2``, and the cases of item
  6. They are built on ``generate_inference_service_history_v1_vectors.py``: the same node
  stream, card, period policy (floor 5) and envelopes under ``evidence-interop/1``, with
  2 October's cells replaced by the table each case is about.
- ``vectors/inference-service-history-v2-base/`` (``--base``): every case of
  ``vectors/inference-service-history-v0-interop-v1/`` rerun with definitions naming ``/2``. Its
  tables hold no shape that items 5 or 6 change, so every case expects what it expects under
  ``/0``.

Every expected status is stated by hand from the profile text; nothing here runs a verifier.
Deterministic. ``README.md`` is never rewritten, and every file in a set is listed in its
``SHA256SUMS``.
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any

import generate_inference_service_history_v0_vectors as g
import generate_inference_service_history_v1_vectors as v1
import generate_inference_service_history_verdicts_v0_vectors as gv
import history_frame

ROOT = g.ROOT
DEFAULT_OUT = ROOT / "vectors" / "inference-service-history-v2"
BASE_OUT = ROOT / "vectors" / "inference-service-history-v2-base"
SET = "aac-inference-service-history-v2"
BASE_SET = "aac-inference-service-history-v2-base"
SPEC = g.SPEC
HISTORY_PROFILE = "inference-service-history/2"
STANDARD = "service_history_example/2"
DETAILED = "service_history_detail_example/2"
VERDICTS = "service_history_verdicts_example/2"
README = "vectors/inference-service-history-v2/README.md"
FLOOR = g.POLICY["floor"]
STATUS = ("Conformance vectors for inference-service-history/2 of the informational Inference-Service "
          "History Profile, over evidence-interop/1. Every key is a test key derived from a public seed; "
          "never use one for anything else.")
BASE_STATUS = ("Conformance vectors for inference-service-history/2 of the informational Inference-Service "
               "History Profile: the evidence-interop/1 base cases under /2 definitions. Every key is a test "
               "key derived from a public seed; never use one for anything else.")


def pair_values(rest: int, smallest: int | None) -> int:
    """§6.2 item 6: how many values the bounds leave for the one cell withheld ``below_floor``."""
    lo = 1 if smallest is None else max(1, rest - smallest)
    hi = min(FLOOR - 1, rest - FLOOR)
    return max(0, hi - lo + 1)


def withheld(per_model: dict[str, int]) -> tuple[set[str], set[str], str | None]:
    """§6.2 by hand under ``/2``, for one table: ``/1``'s rule, then item 6."""
    below, comp, total_why = v1.withheld(per_model)
    if total_why is None and len(below) == 1 and len(comp) == 1:
        published = [n for m, n in per_model.items() if m not in below | comp]
        rest = sum(per_model.values()) - sum(published)
        if pair_values(rest, min(published, default=None)) == 1:
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
    d.update(profile=HISTORY_PROFILE, name=STANDARD, spec=README)
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
    d.update(profile=HISTORY_PROFILE, name=VERDICTS, spec=README)
    return d


# The verdict cases: 2 October's contradicted verdicts are 4 about each model hash (item 5), or
# 1 and 5, where no hash is left published and the rest of 6 fixes the pair (item 6).
HELD_PINNED = copy.deepcopy(gv.HELD)
HELD_PINNED[1]["contradicted"] = {gv.H1: 4, gv.H2: 4}
HELD_ONE = copy.deepcopy(gv.HELD)
HELD_ONE[1]["contradicted"] = {gv.H1: 1, gv.H2: 5}


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

    def std(counts: dict, nonce: str = "requester-1/v2") -> dict:
        return history(d, {"period_counts": counts}, nonce)

    def day2(counts: dict) -> list[dict]:
        return counts["periods"][1]["cells"]

    def total_why(counts: dict) -> str | None:
        return day2(counts)[-1].get("suppressed")

    def published(models: dict[str, int], value: int | None = None) -> dict:
        """The table with its withheld total published, as ``value`` or the true total."""
        counts = period_counts(models)
        total = day2(counts)[-1]
        assert total.get("suppressed") == "complementary"
        del total["suppressed"]
        total["value"] = sum(models.values()) if value is None else value
        return counts

    def accepted(cid: str, title: str, source: str, models: dict[str, int] | None, want: str | None) -> None:
        counts = period_counts(models)
        assert total_why(counts) == want, (cid, total_why(counts))
        case(cid, title, source, std(counts), None)

    # /1's cases, under /2.
    accepted("v2-standard-served", "The served-only History under /2: one withheld model and its partner, "
             "the total of 12 published",
             "constructed: the base set's served counts; 2 October's model-b (3) and its partner model-a (9) "
             "hold 12 between them, which leaves model-b 1 to 4", None, None)
    accepted("v2-total-withheld-two-under-floor", "Two models of 4 under a floor of 5: the total of 8 is withheld",
             "constructed: 2 October served 4 by model-a and 4 by model-b", {"model-a": 4, "model-b": 4},
             "complementary")
    accepted("v2-total-withheld-five-ones", "Five models of 1 each: the total of 5 is withheld",
             "constructed: 2 October served 1 by each of five models", {f"model-{x}": 1 for x in "abcde"},
             "complementary")
    accepted("v2-total-under-floor-withheld-complementary",
             "Two models of 1: the total of 2, under the floor, is withheld complementary",
             "constructed: 2 October served 1 by model-a and 1 by model-b", {"model-a": 1, "model-b": 1},
             "complementary")
    accepted("v2-total-pins-nothing-published", "Models of 3 and 4: the total of 7 fixes neither and is published",
             "constructed: 2 October served 3 by model-a and 4 by model-b", {"model-a": 3, "model-b": 4}, None)

    # Item 6.
    accepted("v2-one-value-least", "Models 1, 5 and 9: the rest of 6 can only be 1 and 5, so the total is withheld",
             "constructed: 2 October served 1 by model-a, 5 by model-b and 9 by model-c",
             {"model-a": 1, "model-b": 5, "model-c": 9}, "complementary")
    accepted("v2-one-value-most", "Models 4, 6 and 6: the rest of 10 can only be 4 and 6, so the total is withheld",
             "constructed: 2 October served 4 by model-a and 6 by model-b and model-c",
             {"model-a": 4, "model-b": 6, "model-c": 6}, "complementary")
    accepted("v2-one-value-partner-at-floor",
             "Models 3, 5 and 5: the partner lies between 5 and 5, so the rest of 8 is 3 and 5 and the total is "
             "withheld", "constructed: 2 October served 3 by model-a and 5 by model-b and model-c",
             {"model-a": 3, "model-b": 5, "model-c": 5}, "complementary")
    accepted("v2-two-values-published", "Models 3, 6 and 6: the rest of 9 leaves 3 or 4, so the total of 15 is "
             "published", "constructed: 2 October served 3 by model-a and 6 by model-b and model-c",
             {"model-a": 3, "model-b": 6, "model-c": 6}, None)
    accepted("v2-one-value-nothing-published",
             "Models 1 and 5, nothing else published: the rest of 6 can only be 1 and 5, so the total is withheld",
             "constructed: 2 October served 1 by model-a and 5 by model-b", {"model-a": 1, "model-b": 5},
             "complementary")
    accepted("v2-two-values-nothing-published",
             "Models 3 and 7, nothing else published: the rest of 10 leaves 1 to 4, so the total is published",
             "constructed: 2 October served 3 by model-a and 7 by model-b", {"model-a": 3, "model-b": 7}, None)

    shape_only = period_counts()
    total = day2(shape_only)[-1]
    total.update(value=None, suppressed="complementary")
    case("v2-total-withheld-beside-one-model",
         "One model withheld under the floor, its partner, and the total withheld complementary: accepted, "
         "since a verifier sees the shape only (SH-14)",
         "constructed: v2-standard-served with 2 October's total withheld complementary; item 6 would have "
         "published it, which no verifier can see", std(shape_only), None)

    # MUST-reject.
    case("mutant-v2-total-pins-two-under-floor", "Two models of 4 withheld beside a published total of 8",
         "constructed: v2-total-withheld-two-under-floor with the total published",
         std(published({"model-a": 4, "model-b": 4})), "period_floor")
    case("mutant-v2-total-pins-five-ones", "Five models of 1 withheld beside a published total of 5",
         "constructed: v2-total-withheld-five-ones with the total published",
         std(published({f"model-{x}": 1 for x in "abcde"})), "period_floor")
    case("mutant-v2-total-pins-beside-published",
         "A published model of 10 and two of 4 withheld beside a published total of 18: the rest of 8 fixes both",
         "constructed: 2 October served 10 by model-a, 4 by model-b and 4 by model-c, the total published",
         std(published({"model-a": 10, "model-b": 4, "model-c": 4})), "period_floor")
    case("mutant-v2-total-short-of-withheld",
         "A published model of 10 and three withheld beside a published total of 12: three listed cells hold at "
         "least 1 each", "constructed: 2 October's three withheld models beside a total 2 more than the "
         "published cells", std(published({"model-a": 10, "model-b": 1, "model-c": 1, "model-d": 1}, 12)),
         "period_floor")
    case("mutant-v2-total-over-withheld",
         "A published model of 10 and two withheld under the floor beside a published total of 19: two cells "
         "under a floor of 5 hold at most 8", "constructed: mutant-v2-total-pins-beside-published with the total "
         "raised to 19", std(published({"model-a": 10, "model-b": 4, "model-c": 4}, 19)), "period_floor")
    for cid, models, title in (
            ("mutant-v2-one-value-least", {"model-a": 1, "model-b": 5, "model-c": 9},
             "v2-one-value-least with its total of 15 published"),
            ("mutant-v2-one-value-most", {"model-a": 4, "model-b": 6, "model-c": 6},
             "v2-one-value-most with its total of 16 published"),
            ("mutant-v2-one-value-partner-at-floor", {"model-a": 3, "model-b": 5, "model-c": 5},
             "v2-one-value-partner-at-floor with its total of 13 published"),
            ("mutant-v2-one-value-nothing-published", {"model-a": 1, "model-b": 5},
             "v2-one-value-nothing-published with its total of 6 published")):
        case(cid, f"The case {title}", f"constructed: {title}", std(published(models)), "period_floor")
    case("mutant-v2-no-value-low",
         "Models 1, 5 and 9 with a published total of 14: a rest of 5 is less than a cell under the floor and "
         "its partner at the floor hold", "constructed: v2-one-value-least with its total published as 14",
         std(published({"model-a": 1, "model-b": 5, "model-c": 9}, 14)), "period_floor")
    case("mutant-v2-no-value-high",
         "Models 1, 5 and 9 with a published total of 23: a rest of 14 is more than a cell under the floor and "
         "a partner of at most 9 hold", "constructed: v2-one-value-least with its total published as 23",
         std(published({"model-a": 1, "model-b": 5, "model-c": 9}, 23)), "period_floor")
    alone = period_counts()
    cells = day2(alone)
    partner = next(c for c in cells if c.get("suppressed") == "complementary")
    del partner["suppressed"]
    partner["value"] = 9
    cells[-1].update(value=None, suppressed="complementary")
    case("mutant-v2-total-withheld-without-partner",
         "One model withheld under the floor, no partner, and the total withheld complementary",
         "constructed: v2-total-withheld-beside-one-model with the partner published; /2 withholds a total "
         "beside one model under the floor only with its partner", std(alone), "period_floor")

    vd = verdicts_definition()
    vcites = ("§5.3", "§6.2", "§6.3", "§9")
    for cid, held, title, which in (
            ("v2-verdict-total-withheld", HELD_PINNED,
             "A verdict result's table under /2: 4 contradicted about each of two model hashes, total withheld",
             "4 and 4"),
            ("v2-verdict-one-value", HELD_ONE,
             "A verdict result's table under /2: 1 and 5 contradicted, the rest of 6 fixes both, total withheld",
             "1 and 5")):
        vc = verdict_counts(held)
        vt = next(c for c in vc["periods"][1]["cells"] if c["dimension"] == {"result": "contradicted"})
        assert vt.get("suppressed") == "complementary", cid
        case(cid, title, f"constructed: the verdict set's verdicts with 2 October's contradicted ones {which}",
             history(vd, {"period_counts": period_counts(), "verdict_counts": vc}, "requester-1/v2-verdicts"),
             None, vcites)
        leak = copy.deepcopy(vc)
        vt = next(c for c in leak["periods"][1]["cells"] if c["dimension"] == {"result": "contradicted"})
        del vt["suppressed"]
        vt["value"] = sum(held[1]["contradicted"].values())
        case(f"mutant-{cid}", f"The case {cid} with the contradicted total of {vt['value']} published",
             f"constructed: {cid} with 2 October's contradicted total published",
             history(vd, {"period_counts": period_counts(), "verdict_counts": leak}, "requester-1/v2-verdicts"),
             "period_floor", vcites)
    return out


def check_frame(all_cases: list[dict]) -> None:
    """HF §6.3: ``/2``'s counting table and wording pack are ``/0``'s with the instance and the fixed
    ``profile`` changed, and every case's definition names ``/2``."""
    t2, p2 = history_frame.load(HISTORY_PROFILE)
    t0, p0 = history_frame.load("inference-service-history/0")
    want = copy.deepcopy(t0)
    want["instance"] = HISTORY_PROFILE
    want["definition_fixed"]["profile"] = HISTORY_PROFILE
    assert t2 == want, "counting table differs from /0's but for the instance"
    assert p2 == dict(p0, instance=HISTORY_PROFILE), "wording pack differs from /0's but for the instance"
    for c in all_cases:
        assert c["inputs"]["definition"]["profile"] == HISTORY_PROFILE, c["id"]
        assert c["expected"]["accepted"] is history_frame.accepted(c["expected"]["history_properties"],
                                                                   t2["may_be_not_checked"]), c["id"]


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
        "generator": "python/scripts/generate_inference_service_history_v2_vectors.py",
        "files": [{"path": n, "sha256": g.shx(b), "count": json.loads(b).get("count")}
                  for n, b in sorted(files.items())],
    })
    return files


def use_base() -> None:
    """Point the base generator's definitions at ``/2``. Its interop profile is already
    ``evidence-interop/1``, set when the ``/1`` generator was imported."""
    standard, detailed = g.standard_definition, g.detailed_definition

    def std(*args: Any, **kwargs: Any) -> dict:
        d = standard(*args, **kwargs)
        d["spec"] = README
        return d

    def det(*args: Any, **kwargs: Any) -> dict:
        d = detailed(*args, **kwargs)
        d["spec"] = README
        return d

    g.HISTORY_PROFILE, g.STANDARD, g.DETAILED = HISTORY_PROFILE, STANDARD, DETAILED
    g.standard_definition, g.detailed_definition = std, det
    g.SET, g.STATUS = BASE_SET, BASE_STATUS


def build_base() -> dict[str, bytes]:
    use_base()
    files = g.build()
    manifest = json.loads(files["manifest.json"])
    manifest["generator"] = "python/scripts/generate_inference_service_history_v2_vectors.py --base"
    files["manifest.json"] = g._dump(manifest)
    return files


def write(out: Path, files: dict[str, bytes]) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        (out / name).write_bytes(data)
    listed = sorted((p.relative_to(out).as_posix(), p) for p in out.rglob("*") if p.is_file())
    lines = [f"{g.shx(p.read_bytes())}  {rel}" for rel, p in listed if rel != "SHA256SUMS"]
    (out / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--base", action="store_true", help="write the base cases rerun under /2")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    if args.base:
        write(args.out or BASE_OUT, build_base())
    else:
        write(args.out or DEFAULT_OUT, build())


if __name__ == "__main__":
    main()
