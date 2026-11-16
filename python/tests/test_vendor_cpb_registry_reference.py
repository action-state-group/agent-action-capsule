# SPDX-License-Identifier: BSD-3-Clause
"""The vendor script reads a whole hard-wrapped ``**Reference:**`` field."""
import importlib.util
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "vendor_cpb_registry.py"
_spec = importlib.util.spec_from_file_location("vendor_cpb_registry", _SCRIPT)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)


def _ref(body: str) -> str:
    md = "## Proposed: `demo`\n\n**Owner:** x\n" + body + "**Proposed by:** y\n"
    return _mod._projection_from_markdown(md)["demo"]["reference"]


def test_single_line_reference():
    assert _ref("**Reference:** `a/b` @ `c0ffee`\n") == "`a/b` @ `c0ffee`"


def test_wrapped_reference_is_joined():
    got = _ref("**Reference:** `a/b` @ `c0ffee` —\n`f.py`, `g.py`\n(note)\n")
    assert got == "`a/b` @ `c0ffee` — `f.py`, `g.py` (note)"


def test_reference_stops_at_next_label():
    got = _ref("**Reference:** `a/b` @ `c0ffee`\n**Reference files:** `f.py`\n")
    assert got == "`a/b` @ `c0ffee`"


def test_reference_stops_at_blank_line():
    assert _ref("**Reference:** `a/b`\n\nprose\n") == "`a/b`"
