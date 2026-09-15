# SPDX-License-Identifier: BSD-3-Clause
"""The packaged registry is a verbatim mirror of the spec.

`agent_action_capsule/data/REGISTRY.md` is the wheel-path registry of record that
`registries.py` loads at runtime; it must equal `spec/REGISTRY.md` exactly, the
same contract the Go conformance enforces for `go/registries/data/REGISTRY.md`
(`go/registries/registries_test.go`). Without this check the Python copy silently
drifts from the spec (as it had: missing sections and a stale section reference).
"""
from __future__ import annotations

from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_SPEC = _ROOT / "spec" / "REGISTRY.md"
_MIRROR = _ROOT / "python" / "agent_action_capsule" / "data" / "REGISTRY.md"


@pytest.mark.skipif(not _SPEC.exists(), reason="spec/REGISTRY.md not present (installed wheel, not the source tree)")
def test_packaged_registry_mirrors_spec_verbatim():
    assert _MIRROR.read_text(encoding="utf-8") == _SPEC.read_text(encoding="utf-8"), (
        "python/agent_action_capsule/data/REGISTRY.md has drifted from spec/REGISTRY.md; "
        "regenerate the packaged mirror from the spec."
    )
