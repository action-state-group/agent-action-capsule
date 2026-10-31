#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate the History frame vectors (``spec/history-frame-v0.md``, cited as HF).

Each case is one instance's counting table and wording pack, with the digests HF §6 lists for that
instance, and the three document properties of HF §6.2 stated by hand: ``table_binding``,
``pack_binding`` and ``pack_form``. The positives are the four instances' documents as
``spec/history-frame/`` holds them. The negatives change one document each: a pack whose label is
made stronger (its digest no longer matches), a translated pack offered in place of the pinned one,
a table with a member added, a pack that carries a string its table checks, and a pack naming
another instance.

Output: ``vectors/history-frame-v0/`` (or ``--out DIR``). Deterministic: no clock, no randomness.
``README.md`` is never rewritten; every file in the directory is listed in ``SHA256SUMS``.
Standard library only, plus ``history_frame`` beside this script.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import history_frame

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "vectors" / "history-frame-v0"
SET = "aac-history-frame-v0"
SPEC = "spec/history-frame-v0.md"
GENERATOR = "python/scripts/generate_history_frame_v0_vectors.py"
STATUS = ("Conformance vectors for the informational History frame v0 (spec/history-frame-v0.md): the "
          "counting table and wording pack each instance pins, and their digests.")
PROPERTIES = ("table_binding", "pack_binding", "pack_form")

SH, PH, PO, ISH = ("standard_history/1", "personal_history_basic/1", "personal_history_outcome/1",
                   "inference-service-history/0")


def props(**overrides: str) -> dict:
    p = dict.fromkeys(PROPERTIES, "PASS")
    p.update(overrides)
    return p


def case(cid: str, description: str, sections: list[str], instance: str, table: dict, pack: dict,
         expected: dict) -> dict:
    # The statuses are stated by hand; the generator re-derives them from HF §6.2 and refuses a case
    # whose hand-stated status the rule does not give.
    listed = history_frame.DIGESTS[instance]
    derived = {
        "table_binding": "PASS" if history_frame.json_digest(table) == listed["table"] else "FAIL",
        "pack_binding": "PASS" if history_frame.json_digest(pack) == listed["pack"] else "FAIL",
        "pack_form": "PASS" if history_frame.pack_form(table, pack, instance) else "FAIL",
    }
    assert derived == expected, (cid, derived)
    fails = [k for k in PROPERTIES if expected[k] == "FAIL"]
    return {"id": cid, "description": description, "sections": sections,
            "inputs": {"instance": instance, "listed": listed, "table": table, "pack": pack},
            "expected": {"properties": expected, "accepted": not fails, "fails": fails}}


def mutate(doc: dict, fn) -> dict:
    d = copy.deepcopy(doc)
    fn(d)
    return d


def cases() -> list[dict]:
    docs = {i: history_frame.load(i) for i in history_frame.FILES}
    out = [case(f"{tag}-as-pinned", f"The counting table and wording pack of {i}, as spec/history-frame/ holds them",
                ["§5", "§6"], i, *docs[i], props())
           for tag, i in (("standard-history", SH), ("personal-history-basic", PH),
                          ("personal-history-outcome", PO), ("inference-service-history", ISH))]
    ish_table, ish_pack = docs[ISH]
    ph_table, ph_pack = docs[PH]
    sh_table, sh_pack = docs[SH]
    out += [
        case("pack-digest-mismatch", "The inference-service pack with \"one-sided\" made \"peer-confirmed\": a "
             "label stronger than its evidence, so a pack whose digest is not the listed one",
             ["§5.3", "§6.2"], ISH, ish_table,
             mutate(ish_pack, lambda p: p["strings"].update({"exchange.one_sided": "peer-confirmed"})),
             props(pack_binding="FAIL")),
        case("pack-translated-in-place", "A translation of the Basic level pack offered as its pack: a "
             "translation binds nothing (§5.3), so its digest is not the listed one",
             ["§5.3", "§6.2"], PH, ph_table,
             mutate(ph_pack, lambda p: p.update(language="fr", strings={
                 "coverage.completeness": "exhaustivité non affirmée",
                 "deal_state.completed_only": "avec des étapes achevées enregistrées seulement",
                 "deal_state.failed_step": "avec une étape échouée enregistrée",
                 "deal_state.no_step": "sans étape enregistrée",
                 "not_established": "non établi"})),
             props(pack_binding="FAIL")),
        case("table-digest-mismatch", "The standard_history/1 table with a share member added to a tally",
             ["§5.2", "§6.2"], SH, mutate(sh_table, lambda t: t["tallies"]["outcomes"].append("held_share")),
             sh_pack, props(table_binding="FAIL")),
        case("pack-carries-checked-string", "The inference-service pack showing a one-sided exchange as "
             "peer_confirmed, a label its table lists and its labels property checks",
             ["§5.3", "§6.2"], ISH, ish_table,
             mutate(ish_pack, lambda p: p["strings"].update({"exchange.one_sided": "peer_confirmed"})),
             props(pack_binding="FAIL", pack_form="FAIL")),
        case("pack-for-another-instance", "The standard_history/1 pack naming the Basic level as its instance",
             ["§5.3", "§6.2"], SH, sh_table, mutate(sh_pack, lambda p: p.update(instance=PH)),
             props(pack_binding="FAIL", pack_form="FAIL")),
    ]
    return out


def _dump(value: Any) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def build() -> dict[str, bytes]:
    all_cases = cases()
    ids = [c["id"] for c in all_cases]
    assert len(ids) == len(set(ids)), "duplicate case id"
    instances = [{"instance": i, "table": f"spec/history-frame/{t}", "pack": f"spec/history-frame/{p}",
                  "table_digest": history_frame.DIGESTS[i]["table"], "pack_digest": history_frame.DIGESTS[i]["pack"]}
                 for i, (t, p) in history_frame.FILES.items()]
    corpus = {"set": SET, "status": STATUS, "spec": SPEC, "frame": history_frame.FRAME, "instances": instances,
              "properties": list(PROPERTIES), "count": len(all_cases), "cases": all_cases}
    files = {"vectors.json": _dump(corpus)}
    files["manifest.json"] = _dump({
        "set": SET, "status": STATUS, "spec": SPEC, "generator": GENERATOR,
        "files": [{"path": name, "sha256": hashlib.sha256(data).hexdigest(), "count": json.loads(data).get("count")}
                  for name, data in sorted(files.items())],
    })
    return files


def write(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for name, data in build().items():
        (out / name).write_bytes(data)
    files = sorted((p.relative_to(out).as_posix(), p) for p in out.rglob("*") if p.is_file())
    lines = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {rel}" for rel, p in files if rel != "SHA256SUMS"]
    (out / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    write(args.out)


if __name__ == "__main__":
    main()
