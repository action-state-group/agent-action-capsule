# SPDX-License-Identifier: BSD-3-Clause
"""The verdict counts vectors (``vectors/inference-service-history-verdicts-v0/``), checked from
their inputs alone.

The evaluator here reads each case's History artifact and applies the profile's rules to its
``verdict_counts`` member (§4.3, §5.3, §6.2, §6.3) with its own code, not the generator's. It must
agree with every case's ``expected`` block, and the generator must regenerate the directory
byte for byte. The IP envelope checks and the other History properties are those of
``test_inference_service_history_v0_vectors.py`` for the same frame; this module checks only
what the member adds.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "python" / "scripts"))
import generate_inference_service_history_verdicts_v0_vectors as gen  # noqa: E402

DIR = ROOT / "vectors" / "inference-service-history-verdicts-v0"
RESULTS = ["corroborated", "contradicted", "inconclusive", "not_comparable"]
# The order a verifier reports the first failing property in.
ORDER = ["artifact_form", "units", "labels", "period_alignment", "period_floor"]


def corpus() -> dict:
    return json.loads((DIR / "vectors.json").read_text())


def artifact_of(case: dict) -> dict:
    envelope = json.loads(case["inputs"]["reply"]["octets_text"])
    raw = envelope["artifact"]
    return json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))


def fails(case: dict) -> set[str]:
    """The History properties the case's verdict counts break, by the profile's rules."""
    art = artifact_of(case)
    floor = corpus()["period_policy"]["document"]["floor"]
    out: set[str] = set()
    v = art.get("verdict_counts")
    if "verdict_counts" not in art.get("declared", []) or v is None:
        return {"artifact_form"}
    if v.get("check") != "referee_verdict" or v.get("signed_by") != "checker":
        out.add("artifact_form")
    if v.get("policy") != corpus()["period_policy"]["digest"]:
        out.add("period_alignment")
    counted = art["period_counts"]["periods"]
    if [(p["from"], p["to"]) for p in v["periods"]] != [(p["from"], p["to"]) for p in counted]:
        out.add("period_alignment")
    for period in v["periods"]:
        cells = period["cells"]
        # Results appear in the order of §5.3, each as models in hash order, then the total.
        position = [RESULTS.index(c["dimension"]["result"]) if c["dimension"].get("result") in RESULTS else -1
                    for c in cells]
        if -1 in position or position != sorted(position):
            out.add("artifact_form")
            continue
        for index, _result in enumerate(RESULTS):
            group = [c for c, p in zip(cells, position) if p == index]
            models = [c for c in group if "model_hash" in c["dimension"]]
            totals = [c for c in group if "model_hash" not in c["dimension"]]
            if [c["dimension"]["model_hash"] for c in models] != sorted(c["dimension"]["model_hash"]
                                                                       for c in models):
                out.add("artifact_form")
            if len(totals) != 1 or group[-1] is not totals[0]:
                out.add("artifact_form")
                continue
            for c in group:
                if c["unit"] != "referee_verdicts":
                    out.add("units")
                if c["label"] != "self_reported":
                    out.add("labels")
                if c.get("suppressed") is None:
                    if c["value"] is None or c["value"] < floor:
                        out.add("period_floor")
                elif c["value"] is not None or c["suppressed"] not in ("below_floor", "complementary"):
                    # §6.2: a withheld cell states no value and one of the two reasons.
                    out.add("period_floor")
            total = totals[0]
            withheld = [c for c in models if c.get("suppressed") is not None]
            published = sum(c["value"] for c in models if c.get("suppressed") is None)
            if total.get("suppressed") is None:
                # §6.2 item 3: one withheld model beside a published total gives it away.
                if len(withheld) == 1:
                    out.add("period_floor")
                if published > total["value"] or (not withheld and published != total["value"]):
                    out.add("period_floor")
    return out


def test_every_case_agrees_with_the_independent_evaluation():
    data = corpus()
    assert data["count"] == len(data["cases"]) == 15
    for case in data["cases"]:
        expected = set(case["expected"]["fails"])
        got = fails(case)
        assert got == expected, (case["id"], got, expected)
        assert case["expected"]["accepted"] is (not expected), case["id"]
        reported = case["expected"]["history_properties"]
        assert {p for p, s in reported.items() if s == "FAIL"} == expected, case["id"]
        # §8.3: the properties up to the first failing one in the profile's order are reported when
        # artifact_form fails (none after it); otherwise every property is.
        if "artifact_form" in expected:
            assert list(reported) == gen.g.STANDARD_PROPS[:3], case["id"]
        else:
            assert list(reported) == gen.g.STANDARD_PROPS, case["id"]
        assert expected <= set(ORDER)


def test_the_positive_case_withholds_what_the_floor_withholds():
    case = corpus()["cases"][0]
    art = artifact_of(case)
    p1 = art["verdict_counts"]["periods"][0]["cells"]
    contradicted = [c for c in p1 if c["dimension"]["result"] == "contradicted"]
    assert [c.get("suppressed") for c in contradicted] == ["below_floor", "below_floor"]
    p2 = art["verdict_counts"]["periods"][1]["cells"]
    reasons = sorted(c["suppressed"] for c in p2
                     if c["dimension"]["result"] == "contradicted" and "suppressed" in c)
    assert reasons == ["below_floor", "complementary"]


def test_the_directory_is_regenerated_byte_for_byte():
    with tempfile.TemporaryDirectory() as tmp:
        # The README is written by hand and listed in SHA256SUMS with the generated files.
        (Path(tmp) / "README.md").write_bytes((DIR / "README.md").read_bytes())
        gen.write(Path(tmp))
        for name in ("vectors.json", "manifest.json", "SHA256SUMS"):
            assert (Path(tmp) / name).read_bytes() == (DIR / name).read_bytes(), name


def test_sha256sums_list_every_file():
    sums = dict(line.split("  ")[::-1] for line in (DIR / "SHA256SUMS").read_text().splitlines())
    for path in DIR.iterdir():
        if path.name == "SHA256SUMS":
            continue
        assert sums[path.name] == hashlib.sha256(path.read_bytes()).hexdigest()
