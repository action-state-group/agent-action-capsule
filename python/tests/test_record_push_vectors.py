# SPDX-License-Identifier: BSD-3-Clause
"""The record push carriage vectors are reproducible and agree with spec/bindings/record-push-v0.md.

The generator states the expected values. This test re-runs it and requires byte-identical output,
then checks every case against a small reader written here from §2-§4 of the binding: what a
receiver does with a tool call or Message, how a sender classifies a reply, and which tool
definition and extension entry conform. It reads no record and no stamp proof: the vectors pin the
carriage only. No other implementation serves record_push yet, so this reader is the only checker.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DIR = ROOT / "vectors" / "record-push-v0"
DATA = json.loads((DIR / "carriage.json").read_text(encoding="utf-8"))
CASES = DATA["cases"]
URI = DATA["extension_uri"]
BINDING = (ROOT / "spec" / "bindings" / "record-push-v0.md").read_text(encoding="utf-8")

# §3.1: the outputSchema is the second JSON block of that section; the vectors must carry it exactly.
OUTPUT_SCHEMA = json.loads(re.search(r"The `outputSchema` is:\n\n```json\n(.*?)\n```", BINDING, re.S).group(1))

B64U = re.compile(r"^[A-Za-z0-9_-]+$")
RECORD_KEYS = {"digest": str, "stored": bool, "duplicate": bool, "deleted": bool, "counted": bool,
               "ask_for_book": bool, "refused": str}
RECORD_REFUSED = {"", "invalid", "refused", "over_limit", "busy"}
PROOF_KEYS = {"accepted": bool, "duplicate": bool, "refused": str}
PROOF_REFUSED = {"", "invalid", "refused"}


def decode(text):
    """§3.2: strict base64url, no padding, at least one octet; None when it does not decode."""
    if not isinstance(text, str) or not B64U.fullmatch(text) or len(text) % 4 == 1:
        return None
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def read_push(obj):
    """§2.1, §3.2: the decoded parts of a push object, or None when it carries no push."""
    if not isinstance(obj, dict) or not obj or not set(obj) <= {"record", "stamp_proof"}:
        return None
    parts = {name: decode(value) for name, value in obj.items()}
    return None if any(v is None for v in parts.values()) else parts


def receive(case):
    """What a receiver does with the case's input: the push's decoded parts, or an error."""
    if case["carriage"] == "mcp":
        if case["input"].get("name") != "record_push":
            return "error"
        parts = read_push(case["input"].get("arguments"))
    else:
        message = case["input"]
        content = message.get("parts")
        if (message.get("role") != "ROLE_USER" or URI not in message.get("extensions", [])
                or "taskId" in message or not isinstance(content, list) or len(content) != 1):
            return "error"
        part = content[0]
        if (part.get("mediaType") != "application/json" or "data" not in part
                or {"raw", "text", "url"} & set(part)):
            return "error"
        parts = read_push(part["data"])
    return "error" if parts is None else parts


def well_formed_answer(answer, pushed):
    """§2.2: one member per part pushed, each of exactly the listed members and types."""
    if not isinstance(answer, dict) or set(answer) != set(pushed):
        return False
    for name, keys, refused in (("record", RECORD_KEYS, RECORD_REFUSED),
                                ("stamp_proof", PROOF_KEYS, PROOF_REFUSED)):
        if name in answer:
            body = answer[name]
            if not isinstance(body, dict) or set(body) != set(keys):
                return False
            if any(type(body[k]) is not t for k, t in keys.items()) or body["refused"] not in refused:
                return False
    return True


def sender_classify(case):
    """§2.3 rule 5, §3.3, §4.3: an answer in the answer position, else a transport condition."""
    response = case["received"]["response"]
    pushed = case["pushed"]
    if "result" not in response:
        return "transport_condition", None
    result = response["result"]
    if case["carriage"] == "mcp":
        if result.get("resultType") != "complete":
            return "transport_condition", None
        answer = result.get("structuredContent")
    else:
        task = result.get("task")
        if task is None:
            return "transport_condition", None
        answer = None
        for artifact in task.get("artifacts", []):
            if URI in artifact.get("extensions", []):
                content = artifact.get("parts", [])
                if (len(content) == 1 and content[0].get("mediaType") == "application/json"
                        and "data" in content[0] and not {"raw", "text", "url"} & set(content[0])):
                    answer = content[0]["data"]
                break
    if answer is None or not well_formed_answer(answer, pushed):
        return "transport_condition", None
    return "answer", answer


def conforms(case):
    """§3.1, §4.1: the tool definition or extension entry is the fixed one."""
    value = case["input"]
    if case["carriage"] == "a2a":
        return value.get("uri") == URI and value.get("required") is False and "params" not in value
    props = value.get("inputSchema", {}).get("properties", {})
    schema = value.get("inputSchema", {})
    out = value.get("outputSchema")
    return (value.get("name") == "record_push"
            and set(props) == {"record", "stamp_proof"}
            and all(p == {"type": "string", "pattern": "^[A-Za-z0-9_-]+$"} for p in props.values())
            and schema.get("additionalProperties") is False and schema.get("minProperties") == 1
            and out == OUTPUT_SCHEMA)


def test_generator_reproduces_every_file_byte_for_byte(tmp_path):
    (tmp_path / "README.md").write_bytes((DIR / "README.md").read_bytes())
    script = ROOT / "python" / "scripts" / "generate_record_push_vectors.py"
    subprocess.run([sys.executable, str(script), "--out", str(tmp_path)], check=True)
    for path in DIR.iterdir():
        assert (tmp_path / path.name).read_bytes() == path.read_bytes(), path.name


def test_the_readme_lists_every_case():
    readme = (DIR / "README.md").read_text(encoding="utf-8")
    for case in CASES:
        assert f"`{case['id']}`" in readme, case["id"]


def test_manifest_matches_the_file():
    manifest = json.loads((DIR / "manifest.json").read_text(encoding="utf-8"))
    entry = manifest["files"][0]
    raw = (DIR / entry["path"]).read_bytes()
    assert entry["sha256"] == hashlib.sha256(raw).hexdigest()
    assert entry["count"] == len(CASES)


def test_the_extension_uri_is_the_binding_s():
    assert URI in BINDING


def test_every_kind_and_both_carriages_are_covered():
    assert {c["kind"] for c in CASES} == {"push", "classify", "declaration"}
    for kind in ("push", "classify", "declaration"):
        for carriage in ("mcp", "a2a"):
            assert any(c["kind"] == kind and c["carriage"] == carriage and c["id"].startswith("neg-")
                       for c in CASES), (kind, carriage)
            assert any(c["kind"] == kind and c["carriage"] == carriage and c["id"].startswith("pos-")
                       for c in CASES), (kind, carriage)


def test_the_binding_s_named_edge_cases_are_present():
    ids = {c["id"] for c in CASES}
    # RP-1: a member failing strict decoding, a raw or text part, an Artifact on a task that is
    # not completed, and a completed task with no Artifact.
    assert {"neg-mcp-padded", "neg-a2a-raw-part", "neg-a2a-text-part",
            "pos-classify-a2a-artifact-on-failed-task", "neg-classify-a2a-completed-no-artifact"} <= ids


@pytest.mark.parametrize("case", [c for c in CASES if c["kind"] == "push"], ids=lambda c: c["id"])
def test_push_cases(case):
    got = receive(case)
    expect = case["expect"]
    if expect["result"] == "error":
        assert got == "error"
        assert expect["answer"] is False
        return
    assert got != "error"
    assert (got["record"].hex() if "record" in got else None) == expect["record_hex"]
    assert (got["stamp_proof"].hex() if "stamp_proof" in got else None) == expect["stamp_proof_hex"]


@pytest.mark.parametrize("case", [c for c in CASES if c["kind"] == "classify"], ids=lambda c: c["id"])
def test_classify_cases(case):
    classification, answer = sender_classify(case)
    assert classification == case["expect"]["classification"]
    if classification == "answer":
        assert answer == case["expect"]["answer"]


@pytest.mark.parametrize("case", [c for c in CASES if c["kind"] == "declaration"], ids=lambda c: c["id"])
def test_declaration_cases(case):
    assert conforms(case) is case["expect"]["conforms"]
