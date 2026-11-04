#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""A pinned model judge. It speaks the --judge-cmd contract of evidencebook-skills scripts/run_daily.py:
one JSON request on stdin, one JSON answer on stdout, and {"describe": true} reports the digest of what
it sends besides the request's own values.

It calls `claude -p` with no tools and no user settings, in an empty directory, and it refuses an answer
that any other model produced, so a pin cannot misstate which model judged.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROMPT = (HERE / "judge-prompt.md").read_text()
INVOCATION = ["claude", "-p", "--tools", "", "--no-session-persistence", "--setting-sources", "project",
              "--output-format", "json"]
VERDICTS = {"met", "not_met", "not_evaluable"}


def main() -> None:
    request = json.load(sys.stdin)
    if request.get("describe") is True:
        template = json.dumps({"prompt": PROMPT, "invocation": INVOCATION}, sort_keys=True)
        json.dump({"instruction_template_digest": hashlib.sha256(template.encode()).hexdigest()}, sys.stdout)
        return
    model = request["judge_model_id"]
    message = json.dumps({"requirement": request["clause"]["statement"], "work": request["case"]["work"],
                          "reference": request["reference"]})
    with tempfile.TemporaryDirectory() as cwd:
        run = subprocess.run([*INVOCATION, "--model", model, "--system-prompt", PROMPT], input=message, cwd=cwd,
                             capture_output=True, text=True, timeout=600)
    if run.returncode != 0:
        sys.exit(f"claude exited {run.returncode}: {run.stderr[-500:]}")
    output = json.loads(run.stdout)
    used = set(output.get("modelUsage", {}))
    if used != {model}:
        sys.exit(f"pinned model {model!r}, but the answer came from {sorted(used)}")
    found = re.search(r"\{.*\}", output["result"], re.S)
    answer = json.loads(found.group(0)) if found else {}
    if answer.get("verdict") not in VERDICTS or not isinstance(answer.get("rationale"), str):
        sys.exit(f"no valid verdict in the answer: {output['result'][:500]!r}")
    json.dump({"verdict": answer["verdict"], "rationale": answer["rationale"]}, sys.stdout)


if __name__ == "__main__":
    main()
