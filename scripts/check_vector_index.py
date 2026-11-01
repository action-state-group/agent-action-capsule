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
    # Each file's own case list; a file without one (the single imported
    # refusal) is one case when the manifest says so.
    total = 0
    for f in jload("vectors/evidence-request/manifest.json")["files"]:
        doc = jload("vectors/evidence-request/" + f["path"])
        if isinstance(doc, dict) and isinstance(doc.get("cases"), list):
            total += len(doc["cases"])
        elif f.get("count"):
            total += 1
    return total


def cross_language_count():
    # The Ed25519 and COSE cases of the strict-Ed25519 file, plus one case per
    # other input file.
    ed = jload("vectors/cross-language/cll-ed25519-vectors.json")
    others = glob_count("vectors/cross-language/*.json") - 1
    return len(ed["ed25519_cases"]) + len(ed["cose_cases"]) + others


def strict_count():
    # The checkpoint, bundle and witness cases plus the producer signature cases.
    doc = jload("vectors/bundle/strict/vectors.json")
    return len(doc["cases"]) + len(doc["record_signatures"])


def viewer_count():
    core = jload("vectors/viewer-core-text/core-text.json")
    return len(core["banner"]) + len(core["check_lists"]["lines"])


def profile_count():
    return len(jload("vectors/profiles/manifest.json")["cases"])


# Row path -> how its case count is recomputed. A "case" is one entry of the
# set's own case list, or one case file or directory where the set has no list.
COUNTERS = {
    "vectors/capsule/": lambda: cases("vectors/capsule/vectors.json"),
    "provenance-mode-vectors/": lambda: cases("provenance-mode-vectors/vectors.json"),
    "vectors/producer-envelope/": lambda: cases("vectors/producer-envelope/vectors.json"),
    "vectors/disclosure-envelope/": lambda: cases("vectors/disclosure-envelope/vectors.json"),
    "vectors/cross-language/": cross_language_count,
    "vectors/bundle/vectors.json": lambda: cases("vectors/bundle/vectors.json"),
    "vectors/bundle/composed/": lambda: cases("vectors/bundle/composed/vectors.json"),
    "vectors/bundle/composed-controller-binding/": lambda: cases("vectors/bundle/composed-controller-binding/vectors.json"),
    "vectors/bundle/non-record-leaves/": lambda: cases("vectors/bundle/non-record-leaves/vectors.json"),
    "vectors/bundle/certificate-mode/": lambda: cases("vectors/bundle/certificate-mode/vectors.json"),
    "vectors/bundle/category-coverage/": lambda: cases("vectors/bundle/category-coverage/vectors.json"),
    "vectors/bundle/producer-key/": lambda: cases("vectors/bundle/producer-key/vectors.json"),
    "vectors/bundle/report-single-record.json": lambda: cases("vectors/bundle/report-single-record.json"),
    "vectors/bundle/strict/": strict_count,
    "vectors/bundle/fragment/": lambda: cases("vectors/bundle/fragment/vectors.json"),
    "vectors/interop/": lambda: glob_count("vectors/interop/*/[pn]*-*", dirs=True),
    "vectors/evidence-request/": request_count,
    "vectors/settlement/": lambda: cases("vectors/settlement/cases.json"),
    "vectors/evidence-layer/padding/": lambda: cases("vectors/evidence-layer/padding/cases.json"),
    "vectors/cll-material/": lambda: cases("vectors/cll-material/cases.json"),
    "vectors/anchor-witness-v1/": lambda: cases("vectors/anchor-witness-v1/vectors.json"),
    "vectors/json-nesting/": lambda: cases("vectors/json-nesting/cases.json"),
    "vectors/cbor-nesting/": lambda: cases("vectors/cbor-nesting/cases.json"),
    "vectors/minimum-necessary/": lambda: cases("vectors/minimum-necessary/manifest.json"),
    "vectors/judgment/": lambda: cases("vectors/judgment/vectors.json"),
    "vectors/judge/": lambda: glob_count("vectors/judge/*/[pn]*-*.json"),
    "vectors/evidence-result/": lambda: glob_count("vectors/evidence-result/[pn]*-*.json", exclude=r"\.records\.json$"),
    "vectors/evidence-dataset/": lambda: listing("vectors/evidence-dataset/cases.json"),
    "vectors/interop-profile-v0/": lambda: cases("vectors/interop-profile-v0/vectors.json"),
    "vectors/interop-profile-v0-requirement-facts/": lambda: cases("vectors/interop-profile-v0-requirement-facts/vectors.json"),
    "vectors/interop-profile-v1/": lambda: cases("vectors/interop-profile-v1/vectors.json"),
    "vectors/interop-profile-v1-requirement-facts/": lambda: cases("vectors/interop-profile-v1-requirement-facts/vectors.json"),
    "vectors/personal-history-basic-v0/": lambda: cases("vectors/personal-history-basic-v0/vectors.json"),
    "vectors/personal-history-outcome-v0/": lambda: cases("vectors/personal-history-outcome-v0/vectors.json"),
    "vectors/coverage-declaration-v0/": lambda: cases("vectors/coverage-declaration-v0/vectors.json"),
    "vectors/controller-binding-v0/": lambda: cases("vectors/controller-binding-v0/vectors.json"),
    "vectors/deal-reconcile-v0/": lambda: cases("vectors/deal-reconcile-v0/vectors.json"),
    "vectors/standard-history-v0/": lambda: cases("vectors/standard-history-v0/vectors.json"),
    "vectors/inference-service-history-v0/": lambda: cases("vectors/inference-service-history-v0/vectors.json"),
    "vectors/inference-service-history-v0-interop-v1/": lambda: cases("vectors/inference-service-history-v0-interop-v1/vectors.json"),
    "vectors/history-frame-v0/": lambda: cases("vectors/history-frame-v0/vectors.json"),
    "vectors/profiles/": profile_count,
    "vectors/registry-conformance/": lambda: cases("vectors/registry-conformance/vectors.json"),
    "vectors/adapters/x402/": lambda: cases("vectors/adapters/x402/cases.json"),
    "vectors/adapters/ucp/": lambda: cases("vectors/adapters/ucp/cases.json"),
    "vectors/adapters/nostr-mailbox/": lambda: cases("vectors/adapters/nostr-mailbox/vectors.json"),
    "vectors/viewer-core-text/": viewer_count,
}


def index_rows(errors):
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
        if not m or last == "none":
            continue
        if not last.isdigit():
            errors.append(f"VECTORS.md row {m.group(1)} has no integer case count: {cells[-1]!r}")
        elif m.group(1) in rows:
            errors.append(f"VECTORS.md lists {m.group(1)} twice")
        else:
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
    for path in sorted(glob.glob(os.path.join(vroot, "bundle", "*.json"))):
        need.append("vectors/bundle/" + os.path.basename(path))
    return need


def main():
    counts = {p: fn() for p, fn in COUNTERS.items()}
    if "--print" in sys.argv:
        for p, n in counts.items():
            print(f"{p}\t{n}")
        return 0
    errors = []
    rows = index_rows(errors)
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
