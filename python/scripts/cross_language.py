#!/usr/bin/env python3
"""Minimal stdin/stdout adapter for the CI language interlock."""
import json
import sys

from agent_action_capsule import compute_capsule_id, verify


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in {"seal", "verify"}:
        print("usage: cross_language.py seal|verify", file=sys.stderr)
        return 2
    value = json.load(sys.stdin)
    if sys.argv[1] == "seal":
        sealed = dict(value)
        sealed["capsule_id"] = compute_capsule_id(sealed)
        json.dump(sealed, sys.stdout, sort_keys=True, separators=(",", ":"))
        sys.stdout.write("\n")
        return 0
    result = verify(value)
    if not result.ok:
        print(", ".join(finding.code for finding in result.findings), file=sys.stderr)
        return 1
    print(result.capsule_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
