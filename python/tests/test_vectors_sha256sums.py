# SPDX-License-Identifier: BSD-3-Clause
"""The top-level vectors/SHA256SUMS lists every released vector file."""
from __future__ import annotations

import hashlib
from pathlib import Path

VECTORS = Path(__file__).resolve().parents[2] / "vectors"


def test_top_level_sha256sums_cover_every_file():
    lines = (VECTORS / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
    listed = dict(reversed(line.split("  ", 1)) for line in lines)
    # Excluded as generate_all_vectors.py excludes them: checksum files at
    # every depth (each corpus's own SHA256SUMS covers its files, and none can
    # list itself), and the bytecode Python writes when a test imports
    # vectors/interop/ran_under/verify_ran_under.py.
    on_disk = {
        p.relative_to(VECTORS).as_posix()
        for p in VECTORS.rglob("*")
        if p.is_file() and p.name != "SHA256SUMS" and "__pycache__" not in p.parts and p.suffix != ".pyc"
    }
    assert set(listed) == on_disk
    assert len(listed) == len(lines), "a path is listed twice"
    for name, digest in listed.items():
        assert hashlib.sha256((VECTORS / name).read_bytes()).hexdigest() == digest, name


def test_full_regeneration_runs_every_generator():
    # A generator left out of generate_all_vectors.py is never checked by the
    # Vector regeneration workflow, so its corpus can go stale unnoticed.
    import importlib.util

    scripts = Path(__file__).resolve().parents[1] / "scripts"
    spec = importlib.util.spec_from_file_location("generate_all_vectors", scripts / "generate_all_vectors.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    on_disk = {p.name for p in scripts.glob("generate_*.py")} - {"generate_all_vectors.py"}
    assert set(module.GENERATORS) == on_disk
