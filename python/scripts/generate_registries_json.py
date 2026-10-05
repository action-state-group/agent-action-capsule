# SPDX-License-Identifier: BSD-3-Clause
"""Generate ``agent_action_capsule/data/registries.json`` from ``spec/REGISTRY.md``.

The JSON is the machine-readable form of every registry of record: for each,
its REGISTRY.md section, title, defining Internet-Draft and seeded values in
document order. It ships in the Python wheel and, copied by ``go generate
./registries``, in the Go module, so consumers in any language can read the
value sets instead of vendoring copies. REGISTRY.md stays the source of truth.

Usage:
    python scripts/generate_registries_json.py           # write
    python scripts/generate_registries_json.py --check   # exit 1 if stale
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

PY_ROOT = Path(__file__).resolve().parent.parent  # .../agent-action-capsule/python
sys.path.insert(0, str(PY_ROOT))

from agent_action_capsule.registries import registries_document  # noqa: E402

SPEC = PY_ROOT.parent / "spec" / "REGISTRY.md"
OUT = PY_ROOT / "agent_action_capsule" / "data" / "registries.json"


def render(spec: Path = SPEC) -> str:
    doc = registries_document(spec.read_text(encoding="utf-8"))
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def main(argv: list[str]) -> int:
    text = render()
    if "--check" in argv:
        if not OUT.is_file() or OUT.read_text(encoding="utf-8") != text:
            print(f"{OUT} is stale; run python scripts/generate_registries_json.py", file=sys.stderr)
            return 1
        return 0
    OUT.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
