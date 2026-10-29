#!/usr/bin/env python3
"""Check that VECTORS.md indexes every in-repo vector set with the right case count.

VECTORS.md is informative. This script keeps it honest: it fails when a vector
directory has no row, when a row names a path that does not exist, or when a
row's case count differs from the count recomputed from the files.

    python3 scripts/check_vector_index.py            # check
    python3 scripts/check_vector_index.py --print    # print the recomputed counts
"""
import glob
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INDEX = os.path.join(ROOT, "VECTORS.md")

# Directories under vectors/ that only group sets: each child needs its own row.
# `bundle` also holds sets of its own, so its direct files are rows too.
CONTAINERS = ("adapters", "bundle", "evidence-layer")


def jload(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return json.load(f)


def cases(rel, key="cases"):
    return len(jload(rel)[key])


def listing(rel):
    return len(jload(rel))


def glob_count(pattern, *, dirs=False, exclude=None):
    paths = glob.glob(os.path.join(ROOT, pattern))
    paths = [p for p in paths if os.path.isdir(p) == dirs]
    if exclude:
        paths = [p for p in paths if not re.search(exclude, os.path.basename(p))]
    return len(paths)


def request_count():
    files = jload("vectors/evidence-request/manifest.json")["files"]
    return sum(f["count"] for f in files if f.get("count") is not None)


def profile_count():
    return len(jload("vectors/profiles/manifest.json")["cases"])


# Row path -> how its case count is recomputed. A "case" is one entry of the
# set's own case list, or one case file or directory where the set has no list.
COUNTERS = {
    "vectors/capsule/": lambda: cases("vectors/capsule/vectors.json"),
    "provenance-mode-vectors/": lambda: cases("provenance-mode-vectors/vectors.json"),
    "vectors/producer-envelope/": lambda: cases("vectors/producer-envelope/vectors.json"),
    "vectors/disclosure-envelope/": lambda: cases("vectors/disclosure-envelope/vectors.json"),
    "vectors/cross-language/": lambda: glob_count("vectors/cross-language/*.json"),
    "vectors/bundle/vectors.json": lambda: cases("vectors/bundle/vectors.json"),
    "vectors/bundle/composed/": lambda: cases("vectors/bundle/composed/vectors.json"),
    "vectors/bundle/producer-key/": lambda: cases("vectors/bundle/producer-key/vectors.json"),
    "vectors/bundle/report-single-record.json": lambda: cases("vectors/bundle/report-single-record.json"),
    "vectors/bundle/strict/": lambda: cases("vectors/bundle/strict/vectors.json"),
    "vectors/bundle/fragment/": lambda: cases("vectors/bundle/fragment/vectors.json"),
    "vectors/interop/": lambda: glob_count("vectors/interop/*/[pn]*-*", dirs=True),
    "vectors/evidence-request/": request_count,
    "vectors/settlement/": lambda: cases("vectors/settlement/cases.json"),
    "vectors/evidence-layer/padding/": lambda: cases("vectors/evidence-layer/padding/cases.json"),
    "vectors/cll-material/": lambda: cases("vectors/cll-material/cases.json"),
    "vectors/minimum-necessary/": lambda: cases("vectors/minimum-necessary/manifest.json"),
    "vectors/judgment/": lambda: cases("vectors/judgment/vectors.json"),
    "vectors/judge/": lambda: glob_count("vectors/judge/*/[pn]*-*.json"),
    "vectors/evidence-result/": lambda: glob_count("vectors/evidence-result/[pn]*-*.json", exclude=r"\.records\.json$"),
    "vectors/evidence-dataset/": lambda: listing("vectors/evidence-dataset/cases.json"),
    "vectors/interop-profile-v0/": lambda: cases("vectors/interop-profile-v0/vectors.json"),
    "vectors/interop-profile-v0-requirement-facts/": lambda: cases("vectors/interop-profile-v0-requirement-facts/vectors.json"),
    "vectors/personal-history-basic-v0/": lambda: cases("vectors/personal-history-basic-v0/vectors.json"),
    "vectors/personal-history-outcome-v0/": lambda: cases("vectors/personal-history-outcome-v0/vectors.json"),
    "vectors/coverage-declaration-v0/": lambda: cases("vectors/coverage-declaration-v0/vectors.json"),
    "vectors/controller-binding-v0/": lambda: cases("vectors/controller-binding-v0/vectors.json"),
    "vectors/deal-reconcile-v0/": lambda: cases("vectors/deal-reconcile-v0/vectors.json"),
    "vectors/standard-history-v0/": lambda: cases("vectors/standard-history-v0/vectors.json"),
    "vectors/profiles/": profile_count,
    "vectors/registry-conformance/": lambda: cases("vectors/registry-conformance/vectors.json"),
    "vectors/adapters/x402/": lambda: cases("vectors/adapters/x402/cases.json"),
    "vectors/adapters/ucp/": lambda: cases("vectors/adapters/ucp/cases.json"),
    "vectors/viewer-core-text/": lambda: jload("vectors/viewer-core-text/core-text.json")["count"],
}


def index_rows():
    """Return {path: stated count} for the first section's tables (in-repo sets)."""
    rows = {}
    text = open(INDEX, encoding="utf-8").read()
    # Sibling-repo sets are informative copies of other repositories' files and
    # are not checked here.
    text = text.split("<!-- sibling-sets -->")[0]
    for line in text.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if not line.startswith("|") or len(cells) < 2:
            continue
        m = re.fullmatch(r"`([^`]+)`", cells[0])
        last = cells[-1].replace(",", "")
        if m and last.isdigit():
            rows[m.group(1)] = int(last)
    return rows


def required_paths():
    """Every vector set that must have a row."""
    need = ["provenance-mode-vectors/"]
    vroot = os.path.join(ROOT, "vectors")
    for name in sorted(os.listdir(vroot)):
        full = os.path.join(vroot, name)
        if not os.path.isdir(full):
            continue
        if name in CONTAINERS:
            for child in sorted(os.listdir(full)):
                if os.path.isdir(os.path.join(full, child)):
                    need.append(f"vectors/{name}/{child}/")
        else:
            need.append(f"vectors/{name}/")
    # `bundle` also carries top-level case files of its own.
    need += ["vectors/bundle/vectors.json", "vectors/bundle/report-single-record.json"]
    return need


def main():
    counts = {p: fn() for p, fn in COUNTERS.items()}
    if "--print" in sys.argv:
        for p, n in counts.items():
            print(f"{p}\t{n}")
        return 0
    errors = []
    rows = index_rows()
    for p in required_paths():
        if p not in rows:
            errors.append(f"VECTORS.md has no row for {p}")
        if p not in COUNTERS:
            errors.append(f"check_vector_index.py has no counter for {p}")
    for p, stated in rows.items():
        if not os.path.exists(os.path.join(ROOT, p)):
            errors.append(f"VECTORS.md row {p} does not exist")
        elif p in counts and counts[p] != stated:
            errors.append(f"VECTORS.md says {stated} cases for {p}, files have {counts[p]}")
        elif p not in counts:
            errors.append(f"check_vector_index.py has no counter for the row {p}")
    for e in errors:
        print(f"error: {e}")
    if errors:
        return 1
    print(f"VECTORS.md lists {len(rows)} vector sets with matching counts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
