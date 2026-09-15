#!/usr/bin/env python3
"""Regenerate every Python-produced corpus and deterministic checksums."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "vectors"


def checksums(directory: Path) -> None:
    lines = []
    for path in sorted(p for p in directory.rglob("*") if p.is_file()):
        if path.name == "SHA256SUMS" or "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {path.relative_to(directory).as_posix()}")
    (directory / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def complete_capsule_manifest() -> None:
    """Add generator-independent canonical cases without dropping any corpus case."""
    path = VECTORS / "capsule" / "vectors.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    listed = {case["name"] for case in manifest["cases"]}
    for directory in sorted(p for p in path.parent.iterdir() if p.is_dir()):
        if directory.name in listed:
            continue
        expected = json.loads((directory / "expected.json").read_text(encoding="utf-8"))
        manifest["cases"].append(
            {
                "name": directory.name,
                "kind": expected["kind"],
                "description": expected["description"],
            }
        )
    manifest["count"] = len(manifest["cases"])
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    python = sys.executable
    for script in (
        "generate_vectors.py",
        "generate_canonical_differential.py",
        "generate_reference_vectors.py",
        "generate_disclosure_vectors.py",
        "generate_producer_envelope_vectors.py",
    ):
        subprocess.run([python, str(Path(__file__).with_name(script))], check=True, cwd=ROOT / "python")
    complete_capsule_manifest()
    for corpus in (
        VECTORS / "capsule",
        VECTORS / "producer-envelope",
        VECTORS / "disclosure-envelope",
        VECTORS / "interop" / "composition",
        VECTORS / "interop" / "ran_under",
    ):
        checksums(corpus)
    checksums(VECTORS)


if __name__ == "__main__":
    main()
