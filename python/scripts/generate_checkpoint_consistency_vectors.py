#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate the retained-head vectors (``vectors/checkpoint-consistency/``).

A reader who kept a log head (MMR size and root) from an earlier look can ask
whether a later head extends it (checkpoint consistency). The kept head is
the reader's own state, so it is a verifier input and no Bundle member. Each
case gives the retained head, the current head and an optional consistency
proof in the wire shape of ``parent-log-witness/v1``'s
``earlier.consistency_proof``, and the expected result.

Every expected result below is written by hand, per case; nothing here runs a
verifier. The logs and proofs are the ``cll`` reference's (MMR, no signatures:
the current head is taken from a checkpoint the caller has authenticated). The
output is a pure function of this file. ``README.md`` is hand-written and never
rewritten here.

Dependencies: ``checkpointed-local-log`` >=0.6,<0.7 (import package ``cll``).
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from cll.checkpoint import MemoryNodeStore, add_leaf, core, leaf_hash, peaks, root_from_peaks

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "vectors" / "checkpoint-consistency"


def log(label: str, leaves: int) -> MemoryNodeStore:
    store = MemoryNodeStore()
    for i in range(leaves):
        add_leaf(store, leaf_hash(hashlib.sha256(b"%s %d" % (label.encode(), i)).digest()))
    return store


def head(store: MemoryNodeStore) -> dict:
    size = store.size()
    return {"size": size, "root": root_from_peaks([store.node(p) for p in peaks(size)]).hex()}


def wire(p: Any) -> dict:
    return {
        "v": p.v, "kind": p.kind, "old_size": p.size_a, "new_size": p.size_b, "old_peaks": list(p.old_peaks),
        "witness": [list(w) for w in p.witness], "new_peaks": list(p.new_peaks),
    }


def proof(label: str, old_leaves: int, new_leaves: int) -> dict:
    old = log(label, old_leaves)
    return wire(core.consistency_proof(log(label, new_leaves), old.size(), log(label, new_leaves).size()))


def case(case_id: str, description: str, retained: Any, current: Any, proof_: Any, status: str, finding: Any) -> dict:
    out: dict = {"id": case_id, "description": description}
    if retained is not ...:
        out["retained"] = retained
    out["current"] = current
    if proof_ is not ...:
        out["proof"] = proof_
    out["expect"] = {"status": status, "finding": finding}
    return out


def flip(hex_hash: str) -> str:
    return hex_hash[:-1] + ("0" if hex_hash[-1] != "0" else "1")


def build_cases() -> list[dict]:
    cases = []
    # (old leaves, new leaves, what it exercises)
    growth = [
        (3, 4, "pos-grow-3-to-4", "Three leaves to four: peaks 3 and 1 merge into one."),
        (4, 8, "pos-grow-4-to-8", "Four to eight: one peak grows, a merge."),
        (7, 8, "pos-grow-7-to-8", "Seven to eight: three old peaks collapse into one."),
        (1, 7, "pos-grow-1-to-7", "One leaf to seven."),
        (10, 39, "pos-grow-10-to-39", "Ten to thirty-nine: several peaks on each side."),
    ]
    for old_n, new_n, case_id, description in growth:
        cases.append(case(case_id, description, head(log("a", old_n)), head(log("a", new_n)),
                          proof("a", old_n, new_n), "pass", None))
    same = head(log("a", 5))
    cases.append(case("pos-same-head", "The retained head is the current head; no proof needed.", same, same, ..., "pass", None))
    cases.append(case("pos-same-head-with-proof-ignored", "Same head; a stray proof is not consulted.", same, same,
                      {"kind": "junk"}, "pass", None))

    # not_present: nothing to check
    cur = head(log("a", 8))
    ret = head(log("a", 4))
    good = proof("a", 4, 8)
    cases.append(case("np-retained-absent", "No retained head supplied.", None, cur, good, "not_present", "retained_head_absent"))
    cases.append(case("np-retained-omitted", "The retained member is omitted.", ..., cur, good, "not_present",
                      "retained_head_absent"))
    cases.append(case("np-retained-ahead", "The retained head is later than the current (older) Bundle checkpoint; "
                      "a valid proof the other way round is no help.", cur, ret, good, "not_present",
                      "retained_head_ahead_of_current"))
    cases.append(case("np-retained-ahead-no-proof", "Same, with no proof.", cur, ret, ..., "not_present",
                      "retained_head_ahead_of_current"))
    cases.append(case("np-other-log", "Both heads name a log and the names differ.",
                      {**ret, "log_id": "log:one"}, {**cur, "log_id": "log:two"}, good, "not_present",
                      "retained_head_other_log"))
    cases.append(case("pos-same-log-id", "Both heads name the same log.",
                      {**ret, "log_id": "log:one"}, {**cur, "log_id": "log:one"}, good, "pass", None))
    cases.append(case("pos-log-id-on-one-head", "Only one head names a log; the caller matched the logs.",
                      {**ret, "log_id": "log:one"}, cur, good, "pass", None))
    cases.append(case("np-proof-absent", "A retained head that differs from the current one, and no proof.", ret, cur, ...,
                      "not_present", "consistency_proof_absent"))
    cases.append(case("np-proof-null", "The proof is null.", ret, cur, None, "not_present", "consistency_proof_absent"))

    # fail
    def edited(path: tuple, value: Any) -> dict:
        p = copy.deepcopy(good)
        target = p
        for step in path[:-1]:
            target = target[step]
        if value is ...:
            del target[path[-1]]
        else:
            target[path[-1]] = value
        return p

    neg = [
        ("neg-other-log", "The retained head is of another log with the same sizes.", head(log("b", 4)), cur, good,
         "retained_head_not_a_prefix"),
        ("neg-retained-root-wrong", "One digit of the retained root changed.",
         {**ret, "root": flip(ret["root"])}, cur, good, "retained_head_not_a_prefix"),
        ("neg-current-root-wrong", "One digit of the current root changed.",
         ret, {**cur, "root": flip(cur["root"])}, good, "retained_head_not_a_prefix"),
        ("neg-witness-tampered", "One hash of the proof's witness path changed.", ret, cur,
         edited(("witness", 0, 0), flip(good["witness"][0][0])), "retained_head_not_a_prefix"),
        ("neg-new-peak-tampered", "The proof's first new peak changed.", ret, cur,
         edited(("new_peaks", 0), flip(good["new_peaks"][0])), "retained_head_not_a_prefix"),
        ("neg-old-peak-tampered", "The proof's first old peak changed.", ret, cur,
         edited(("old_peaks", 0), flip(good["old_peaks"][0])), "retained_head_not_a_prefix"),
        ("neg-proof-other-sizes", "The proof is for other sizes than the two heads.", ret, head(log("a", 9)), good,
         "consistency_proof_sizes_differ"),
        ("neg-proof-old-size-edited", "The proof states old_size 1.", ret, cur, edited(("old_size",), 1),
         "consistency_proof_sizes_differ"),
        ("neg-same-size-root-differs", "Same size, another root.", head(log("a", 5)), head(log("b", 5)), ...,
         "retained_head_root_differs"),
        ("neg-log-id-number", "log_id is a number.", {**ret, "log_id": 1}, cur, good, "retained_head_malformed"),
        ("neg-retained-size-not-an-mmr", "The retained size is no MMR size (5).", {**ret, "size": 5}, cur, good,
         "retained_head_malformed"),
        ("neg-same-size-not-an-mmr", "Both heads have size 5, which no MMR has, and equal roots.",
         {"size": 5, "root": "00" * 32}, {"size": 5, "root": "00" * 32}, ..., "retained_head_malformed"),
        ("neg-current-size-not-an-mmr", "The current size is no MMR size (6).", ret, {**cur, "size": 6}, good,
         "current_head_malformed"),
        ("neg-proof-kind-missing", "The proof has no kind.", ret, cur, edited(("kind",), ...), "consistency_proof_malformed"),
        ("neg-proof-not-object", "The proof is a string.", ret, cur, "proof", "consistency_proof_malformed"),
        ("neg-proof-peak-uppercase", "A peak hash is spelled in uppercase.", ret, cur,
         edited(("new_peaks", 0), good["new_peaks"][0].upper()), "consistency_proof_malformed"),
        ("neg-proof-size-boolean", "old_size is true.", ret, cur, edited(("old_size",), True), "consistency_proof_malformed"),
        ("neg-retained-size-string", "The retained size is a string.", {**ret, "size": str(ret["size"])}, cur, good,
         "retained_head_malformed"),
        ("neg-retained-size-zero", "The retained size is zero.", {**ret, "size": 0}, cur, good, "retained_head_malformed"),
        ("neg-retained-root-uppercase", "The retained root is uppercase.", {**ret, "root": ret["root"].upper()}, cur, good,
         "retained_head_malformed"),
        ("neg-retained-not-object", "The retained head is a string.", "head", cur, good, "retained_head_malformed"),
        ("neg-current-root-short", "The current root is short.", ret, {**cur, "root": cur["root"][:-2]}, good,
         "current_head_malformed"),
        ("neg-current-missing", "No current head.", ret, None, good, "current_head_malformed"),
    ]
    for case_id, description, retained, current, proof_, finding in neg:
        cases.append(case(case_id, description, retained, current, proof_, "fail", finding))
    return cases


def dump(value: Any) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    out = parser.parse_args().out
    out.mkdir(parents=True, exist_ok=True)
    cases = build_cases()
    vectors = {
        "format_version": "1",
        "description": "verifyRetainedHead: does the current log head extend a head the reader kept. See README.md.",
        "cases": cases,
    }
    files = {"vectors.json": dump(vectors)}
    files["manifest.json"] = dump({
        "format_version": "1",
        "files": {name: {"sha256": hashlib.sha256(data).hexdigest()} for name, data in files.items()},
        "case_count": len(cases),
    })
    for name, data in files.items():
        (out / name).write_bytes(data)
    names = sorted(p.name for p in out.iterdir() if p.is_file() and p.name != "SHA256SUMS")
    (out / "SHA256SUMS").write_text(
        "".join(f"{hashlib.sha256((out / n).read_bytes()).hexdigest()}  {n}\n" for n in names))


if __name__ == "__main__":
    main()
