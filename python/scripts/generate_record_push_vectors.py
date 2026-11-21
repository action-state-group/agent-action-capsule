#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate the record push carriage vectors in ../../vectors/record-push-v0/ (RP-1).

Every expected result is written by hand below from spec/bindings/record-push-v0.md §2-§4 and
cites its section. The generator runs no receiver or sender: it base64url-encodes fixed octets,
writes the cases and hashes the files. The vectors cover the carriage only: the shape of the
tool call or message, strict base64url members, an error against an answer, and the task states
RP-1 names. They never read a record or a stamp proof, name no profile, and say nothing about
who may push (SF-6) or how strictly a proof's JSON is read (SF-4). The answer objects are those
of EBL's receive vectors (§7); the cases here use the §3.4 example only to give the answer
position a well-formed value.

Output: ``carriage.json``, ``manifest.json`` and ``SHA256SUMS`` (``--out DIR`` to redirect).
``README.md`` is hand-written. Deterministic: no clock, randomness or keys.

Run: cd python && python scripts/generate_record_push_vectors.py
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vector_layout import dumps  # noqa: E402

OUT = Path(__file__).resolve().parents[2] / "vectors" / "record-push-v0"
URI = "https://datatracker.ietf.org/doc/draft-mih-agent-record-push/"

# Opaque octets. Neither is a record or a proof of any profile: the carriage never reads them.
RECORD = bytes(range(0, 24))
PROOF = b'{"opaque":"stamp proof octets"}'


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


RECORD_B64 = b64u(RECORD)
PROOF_B64 = b64u(PROOF)
# Octets whose base64url text holds both '-' and '_' (and whose base64 holds '+' and '/').
ALPHABET_OCTETS = bytes([0xFB, 0xFF, 0xBF])

# The §3.4 answer, for both parts pushed. Its values are EBL's (§7), not a rule of this set.
ANSWER = {
    "record": {"ask_for_book": False, "counted": True, "deleted": False,
               "digest": "71db53839ee90023a82b5d166eceb29c262872e43df0bfe46a21cb8311c67ccb",
               "duplicate": True, "refused": "", "stored": False},
    "stamp_proof": {"accepted": True, "duplicate": False, "refused": ""},
}
RECORD_ONLY = {"record": ANSWER["record"]}
PROOF_ONLY = {"stamp_proof": ANSWER["stamp_proof"]}


# §3.1: the fixed outputSchema, copied from the binding (the test checks the copy against the text).
OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "record": {
            "type": "object",
            "properties": {
                "digest": {"type": "string"}, "stored": {"type": "boolean"},
                "duplicate": {"type": "boolean"}, "deleted": {"type": "boolean"},
                "counted": {"type": "boolean"}, "ask_for_book": {"type": "boolean"},
                "refused": {"enum": ["", "invalid", "refused", "over_limit", "busy"]},
            },
            "required": ["digest", "stored", "duplicate", "deleted", "counted", "ask_for_book", "refused"],
            "additionalProperties": False,
        },
        "stamp_proof": {
            "type": "object",
            "properties": {
                "accepted": {"type": "boolean"}, "duplicate": {"type": "boolean"},
                "refused": {"enum": ["", "invalid", "refused"]},
            },
            "required": ["accepted", "duplicate", "refused"],
            "additionalProperties": False,
        },
    },
    "minProperties": 1,
    "additionalProperties": False,
}


def with_(base: dict, **changes) -> dict:
    out = copy.deepcopy(base)
    out.update(changes)
    return out


def without(base: dict, *names: str) -> dict:
    return {k: v for k, v in base.items() if k not in names}


def push_ok(carriage: str, case_id: str, section: list[str], description: str, arguments: dict,
            record: bytes | None, proof: bytes | None) -> dict:
    return {
        "id": case_id, "kind": "push", "carriage": carriage, "section": section,
        "description": description, "input": wrap(carriage, arguments),
        "expect": {"result": "push",
                   "record_hex": None if record is None else record.hex(),
                   "stamp_proof_hex": None if proof is None else proof.hex()},
    }


def push_err(carriage: str, case_id: str, section: list[str], description: str, message: dict) -> dict:
    return {
        "id": case_id, "kind": "push", "carriage": carriage, "section": section,
        "description": description, "input": message,
        "expect": {"result": "error", "answer": False},
    }


def a2a_message(data=None, **changes) -> dict:
    """A conforming A2A Message (§4.2) around ``data`` (the push object)."""
    message = {
        "messageId": "m-7", "role": "ROLE_USER", "extensions": [URI],
        "parts": [{"mediaType": "application/json",
                   "data": {"record": RECORD_B64, "stamp_proof": PROOF_B64} if data is None else data}],
    }
    message.update(changes)
    return message


def wrap(carriage: str, arguments: dict) -> dict:
    if carriage == "mcp":
        return {"name": "record_push", "arguments": arguments}
    return a2a_message(arguments)


def push_cases() -> list[dict]:
    mcp_args = {"record": RECORD_B64, "stamp_proof": PROOF_B64}
    cases = [
        push_ok("mcp", "pos-mcp-both-parts", ["§3.2", "§2.1"],
                "A tools/call of record_push with both members: each decodes to the octets pushed.",
                mcp_args, RECORD, PROOF),
        push_ok("mcp", "pos-mcp-record-only", ["§3.2", "§2.1"],
                "One member is enough: a push with only a record.", {"record": RECORD_B64}, RECORD, None),
        push_ok("mcp", "pos-mcp-proof-only", ["§3.2", "§2.1"],
                "One member is enough: a push with only a stamp proof.",
                {"stamp_proof": PROOF_B64}, None, PROOF),
        push_ok("mcp", "pos-mcp-url-safe-alphabet", ["§3.2", "§2.1"],
                "Octets whose text uses '-' and '_': base64url, not base64.",
                {"record": b64u(ALPHABET_OCTETS)}, ALPHABET_OCTETS, None),
        push_ok("a2a", "pos-a2a-both-parts", ["§4.2", "§2.1"],
                "A SendMessage Message with one data part holding the push object: the same octets as the MCP case.",
                mcp_args, RECORD, PROOF),
        push_ok("a2a", "pos-a2a-record-only", ["§4.2", "§2.1"],
                "One member is enough over A2A too.", {"record": RECORD_B64}, RECORD, None),
        push_ok("a2a", "pos-a2a-proof-only", ["§4.2", "§2.1"],
                "One member is enough over A2A too.", {"stamp_proof": PROOF_B64}, None, PROOF),
    ]
    bad_args = [
        ("empty-arguments", "No member: a push with neither part carries no push (§2.3 rule 3).", {}),
        ("extra-member", "A member that is neither record nor stamp_proof.",
         {"record": RECORD_B64, "sender": "abc"}),
        ("padded", "base64url without padding: a padded member does not strictly decode.",
         {"record": RECORD_B64 + "=="}),
        ("standard-alphabet", "base64 (with '+' and '/') is not base64url.",
         {"record": base64.b64encode(ALPHABET_OCTETS).decode("ascii")}),
        ("empty-member", "A member that decodes to no octet.", {"record": ""}),
        ("impossible-length", "Five characters never decode: not strict base64url.", {"record": "AAAAA"}),
        ("trailing-newline", "A member with a newline after the last character.", {"record": RECORD_B64 + "\n"}),
        ("whitespace", "A member with a space in it.", {"record": RECORD_B64[:8] + " " + RECORD_B64[8:]}),
        ("not-a-string", "A member that is not a string.", {"record": list(RECORD)}),
        ("null-member", "A null member is not an absent member.", {"record": RECORD_B64, "stamp_proof": None}),
        ("one-bad-member", "One member decodes and the other does not: the whole call carries no push, "
                           "and no part is answered.", {"record": RECORD_B64, "stamp_proof": PROOF_B64 + "!"}),
    ]
    for name, description, arguments in bad_args:
        cases.append(push_err("mcp", f"neg-mcp-{name}", ["§3.2", "§2.3"], description + " Error, never an answer.",
                              wrap("mcp", arguments)))
        cases.append(push_err("a2a", f"neg-a2a-{name}", ["§4.2", "§3.2", "§2.3"],
                              description + " Error, never an answer.", wrap("a2a", arguments)))
    push_object = {"record": RECORD_B64}
    shapes = [
        ("raw-part", "The push object in a raw part, as the evidence request carriage does: not this carriage.",
         a2a_message(parts=[{"mediaType": "application/json", "raw": b64u(json.dumps(push_object).encode())}])),
        ("text-part", "The push object as JSON text in a text part.",
         a2a_message(parts=[{"mediaType": "application/json", "text": json.dumps(push_object)}])),
        ("metadata-only", "The push object in the Message's metadata, with a data part that is not a push object.",
         a2a_message(data={}, metadata={"record": RECORD_B64})),
        ("two-parts", "Two parts: the Message holds exactly one.",
         a2a_message(parts=[{"mediaType": "application/json", "data": push_object},
                            {"mediaType": "application/json", "data": push_object}])),
        ("no-parts", "No part.", a2a_message(parts=[])),
        ("other-media-type", "A data part whose mediaType is not application/json. An A2A error such as "
                             "ContentTypeNotSupportedError is also a transport condition.",
         a2a_message(parts=[{"mediaType": "application/cbor", "data": push_object}])),
        ("task-id-present", "A taskId: each push starts its own task.", a2a_message(taskId="t-1")),
        ("role-agent", "A Message whose role is not ROLE_USER.", a2a_message(role="ROLE_AGENT")),
        ("extension-not-listed", "The extension URI missing from the Message's extensions.",
         a2a_message(extensions=[])),
    ]
    for name, description, message in shapes:
        cases.append(push_err("a2a", f"neg-a2a-{name}", ["§4.2", "§2.3"], description + " Error, never an answer.",
                              message))
    return cases


def mcp_result(structured, **changes) -> dict:
    result = {"resultType": "complete", "isError": False, "content": []}
    if structured is not None:
        result["structuredContent"] = structured
    result.update(changes)
    return result


def a2a_task(state="TASK_STATE_COMPLETED", artifacts=None) -> dict:
    task = {"id": "task-1", "contextId": "ctx-1", "status": {"state": state}}
    if artifacts is not None:
        task["artifacts"] = artifacts
    return task


def a2a_artifact(data, uri=URI, media="application/json", parts=None) -> dict:
    artifact = {"artifactId": "a-1", "extensions": [uri] if uri else [],
                "parts": parts if parts is not None else [{"mediaType": media, "data": data}]}
    return artifact


def classify(carriage: str, case_id: str, section: list[str], description: str, pushed: list[str],
             received: dict, classification: str) -> dict:
    expect = {"classification": classification}
    if classification == "answer":
        expect["answer"] = received["__answer__"]
    received = {k: v for k, v in received.items() if k != "__answer__"}
    return {"id": case_id.replace("-", "-classify-", 1), "kind": "classify", "carriage": carriage, "section": section,
            "description": description, "pushed": pushed, "received": received, "expect": expect}


def classify_cases() -> list[dict]:
    both = ["record", "stamp_proof"]
    out: list[dict] = []

    def mcp(case_id, description, pushed, response, classification, answer=None):
        received = {"response": response}
        if classification == "answer":
            received["__answer__"] = answer
        out.append(classify("mcp", case_id, ["§3.3", "§2.3"], description, pushed, received, classification))

    def a2a(case_id, description, pushed, response, classification, answer=None):
        received = {"response": response}
        if classification == "answer":
            received["__answer__"] = answer
        out.append(classify("a2a", case_id, ["§4.3", "§2.3"], description, pushed, received, classification))

    def rpc(result=None, error=None):
        body = {"jsonrpc": "2.0", "id": 7}
        body["result" if error is None else "error"] = result if error is None else error
        return body

    refused = {"record": {"ask_for_book": False, "counted": False, "deleted": False, "digest": "",
                          "duplicate": False, "refused": "invalid", "stored": False},
               "stamp_proof": {"accepted": False, "duplicate": False, "refused": "invalid"}}
    busy = {"record": with_(refused["record"], refused="busy", digest=ANSWER["record"]["digest"])}
    mcp("pos-mcp-answer-both", "A complete, non-error result whose structuredContent is the answer object.",
        both, rpc(mcp_result(ANSWER)), "answer", ANSWER)
    mcp("pos-mcp-answer-record-only", "One member per part pushed: a record-only push is answered with a record member.",
        ["record"], rpc(mcp_result(RECORD_ONLY)), "answer", RECORD_ONLY)
    mcp("pos-mcp-answer-proof-only", "One member per part pushed: a proof-only push is answered with a proof member.",
        ["stamp_proof"], rpc(mcp_result(PROOF_ONLY)), "answer", PROOF_ONLY)
    mcp("pos-mcp-refused-is-an-answer", "A refused part is an answer, not an error (§3.3).",
        both, rpc(mcp_result(refused)), "answer", refused)
    mcp("pos-mcp-busy-is-an-answer", "refused \"busy\" is an answer; the sender may push again (§2.3 rule 5).",
        ["record"], rpc(mcp_result(busy)), "answer", busy)
    mcp("pos-mcp-is-error-true-still-an-answer",
        "An answer object in the answer position is the answer, whatever isError says (§2.3 rule 5).",
        both, rpc(mcp_result(ANSWER, isError=True)), "answer", ANSWER)
    mcp("pos-mcp-text-block-ignored", "A text block beside structuredContent: the sender reads only structuredContent.",
        both, rpc(mcp_result(ANSWER, content=[{"type": "text", "text": "not read"}])), "answer", ANSWER)
    mcp("neg-mcp-jsonrpc-error", "A JSON-RPC error is a transport condition, never a refusal (§2.3 rule 3).",
        both, rpc(error={"code": -32602, "message": "invalid params"}), "transport_condition")
    mcp("neg-mcp-internal-error", "-32603 on a receiver fault: no answer, so nothing is concluded (§2.3 rule 4).",
        both, rpc(error={"code": -32603, "message": "internal"}), "transport_condition")
    mcp("neg-mcp-message-too-large", "-32600 on a message over the bound: a transport condition (§2.3 rule 6).",
        both, rpc(error={"code": -32600, "message": "too large"}), "transport_condition")
    mcp("neg-mcp-input-required", "An input_required result is a transport condition (§3.3).",
        both, rpc({"resultType": "input_required", "isError": False, "content": []}), "transport_condition")
    mcp("neg-mcp-task-handle", "A task handle instead of a complete result (§3.3); its form is MCP's, not pinned here.",
        both, rpc({"resultType": "task", "task": {"taskId": "t-1", "status": "working"}}), "transport_condition")
    mcp("neg-mcp-no-structured-content", "No structuredContent: no answer in the answer position.",
        both, rpc(mcp_result(None, content=[{"type": "text", "text": json.dumps(ANSWER)}])), "transport_condition")
    mcp("neg-mcp-missing-part-member", "A part was pushed and its member is missing from the answer.",
        both, rpc(mcp_result(RECORD_ONLY)), "transport_condition")
    mcp("neg-mcp-extra-part-member", "An answer member for a part that was not pushed.",
        ["record"], rpc(mcp_result(ANSWER)), "transport_condition")
    mcp("neg-mcp-extra-answer-member", "A member of the record answer beyond the seven of §2.2.",
        ["record"], rpc(mcp_result({"record": with_(ANSWER["record"], extra=True)})), "transport_condition")
    mcp("neg-mcp-missing-answer-member", "A record answer without its ask_for_book member.",
        ["record"], rpc(mcp_result({"record": without(ANSWER["record"], "ask_for_book")})), "transport_condition")
    mcp("neg-mcp-wrong-member-type", "A record answer whose stored member is a string.",
        ["record"], rpc(mcp_result({"record": with_(ANSWER["record"], stored="false")})), "transport_condition")
    mcp("neg-mcp-unregistered-refusal", "A proof answer whose refused value is not one of its classes.",
        ["stamp_proof"], rpc(mcp_result({"stamp_proof": with_(ANSWER["stamp_proof"], refused="over_limit")})),
        "transport_condition")

    ok_art = a2a_artifact(ANSWER)
    a2a("pos-a2a-completed-answer", "A completed task with one Artifact of the extension: the answer.",
        both, rpc({"task": a2a_task(artifacts=[ok_art])}), "answer", ANSWER)
    a2a("pos-a2a-record-only", "One member per part pushed, over A2A too.",
        ["record"], rpc({"task": a2a_task(artifacts=[a2a_artifact(RECORD_ONLY)])}), "answer", RECORD_ONLY)
    a2a("pos-a2a-refused-is-an-answer", "A refused part is an answer: the task still completes (§4.3).",
        both, rpc({"task": a2a_task(artifacts=[a2a_artifact(refused)])}), "answer", refused)
    for state in ("TASK_STATE_FAILED", "TASK_STATE_REJECTED", "TASK_STATE_WORKING", "TASK_STATE_CANCELED"):
        a2a(f"pos-a2a-artifact-on-{state.removeprefix('TASK_STATE_').lower()}-task",
            f"An Artifact of the extension on a task in {state} is still the answer: the sender looks for "
            "the Artifact whatever the task state (§4.3, §2.3 rule 5).",
            both, rpc({"task": a2a_task(state, [ok_art])}), "answer", ANSWER)
    a2a("neg-a2a-completed-no-artifact", "A completed task with no Artifact: a transport condition.",
        both, rpc({"task": a2a_task()}), "transport_condition")
    a2a("neg-a2a-failed-no-artifact", "A task in a failed state with no Artifact: a transport condition.",
        both, rpc({"task": a2a_task("TASK_STATE_FAILED")}), "transport_condition")
    a2a("neg-a2a-artifact-without-extension", "An Artifact that does not list the extension URI is not the answer.",
        both, rpc({"task": a2a_task(artifacts=[a2a_artifact(ANSWER, uri=None)])}), "transport_condition")
    a2a("neg-a2a-artifact-other-extension", "An Artifact listing another extension URI is not the answer.",
        both, rpc({"task": a2a_task(artifacts=[a2a_artifact(ANSWER, uri="urn:other")])}), "transport_condition")
    a2a("neg-a2a-two-parts", "An Artifact with two parts is not of the answer's form.",
        both, rpc({"task": a2a_task(artifacts=[a2a_artifact(None, parts=[
            {"mediaType": "application/json", "data": ANSWER}, {"mediaType": "application/json", "data": ANSWER}])])}),
        "transport_condition")
    a2a("neg-a2a-text-part", "An Artifact whose one part is text, not data.",
        both, rpc({"task": a2a_task(artifacts=[a2a_artifact(None, parts=[
            {"mediaType": "application/json", "text": json.dumps(ANSWER)}])])}), "transport_condition")
    a2a("neg-a2a-other-media-type", "An Artifact whose data part is not application/json.",
        both, rpc({"task": a2a_task(artifacts=[a2a_artifact(ANSWER, media="application/cbor")])}),
        "transport_condition")
    a2a("neg-a2a-direct-message", "A direct Message instead of a Task: a transport condition (§4.3).",
        both, rpc({"message": {"messageId": "m-9", "role": "ROLE_AGENT",
                               "parts": [{"mediaType": "application/json", "data": ANSWER}]}}),
        "transport_condition")
    a2a("neg-a2a-error", "An A2A error is a transport condition, never a refusal.",
        both, rpc(error={"code": -32602, "message": "invalid params"}), "transport_condition")
    a2a("neg-a2a-extra-part-member", "An Artifact answer with a member for a part that was not pushed.",
        ["record"], rpc({"task": a2a_task(artifacts=[ok_art])}), "transport_condition")
    return out


def declaration_cases() -> list[dict]:
    tool = {
        "name": "record_push", "title": "Record push", "description": "Takes a record push.",
        "inputSchema": {"type": "object", "properties": {
            "record": {"type": "string", "pattern": "^[A-Za-z0-9_-]+$"},
            "stamp_proof": {"type": "string", "pattern": "^[A-Za-z0-9_-]+$"}},
            "minProperties": 1, "additionalProperties": False},
        "outputSchema": copy.deepcopy(OUTPUT_SCHEMA),
    }
    ext = {"uri": URI, "description": "Takes a record push.", "required": False}

    def mutated(base, path, value):
        out = copy.deepcopy(base)
        target = out
        for key in path[:-1]:
            target = target[key]
        if value is _DELETE:
            del target[path[-1]]
        else:
            target[path[-1]] = value
        return out

    cases = [
        ("pos-mcp-tool", "mcp", "§3.1", "The tool as listed: fixed name and schemas.", tool, True),
        ("neg-mcp-other-name", "mcp", "§3.1", "Another tool name.", mutated(tool, ["name"], "push_record"), False),
        ("neg-mcp-header-annotation", "mcp", "§3.1",
         "An x-mcp-header annotation on a property would copy a record into an HTTP header.",
         mutated(tool, ["inputSchema", "properties", "record", "x-mcp-header"], "Record"), False),
        ("neg-mcp-open-input", "mcp", "§3.1", "An input schema that allows other members.",
         mutated(tool, ["inputSchema", "additionalProperties"], True), False),
        ("neg-mcp-no-min-properties", "mcp", "§3.1", "An input schema that allows a push with neither part.",
         mutated(tool, ["inputSchema", "minProperties"], _DELETE), False),
        ("neg-mcp-loose-output-schema", "mcp", "§3.1", "An outputSchema that lists the members but not their fixed shape.",
         mutated(tool, ["outputSchema"], {"type": "object", "properties": {"record": {"type": "object"},
                                                                          "stamp_proof": {"type": "object"}},
                                          "minProperties": 1, "additionalProperties": False}), False),
        ("neg-mcp-widened-refusal-class", "mcp", "§3.1", "The proof's refused enum widened to the record's classes.",
         mutated(tool, ["outputSchema", "properties", "stamp_proof", "properties", "refused"],
                 {"enum": ["", "invalid", "refused", "over_limit", "busy"]}), False),
        ("neg-mcp-output-required-dropped", "mcp", "§3.1", "The record answer's required list dropped.",
         mutated(tool, ["outputSchema", "properties", "record", "required"], _DELETE), False),
        ("neg-mcp-output-header-annotation", "mcp", "§3.1",
         "An x-mcp-header annotation on an outputSchema property.",
         mutated(tool, ["outputSchema", "properties", "record", "properties", "digest", "x-mcp-header"], "Digest"),
         False),
        ("neg-mcp-no-output-schema", "mcp", "§3.1", "A tool without an outputSchema.",
         mutated(tool, ["outputSchema"], _DELETE), False),
        ("pos-a2a-extension", "a2a", "§4.1", "The extension entry as listed.", ext, True),
        ("neg-a2a-other-uri", "a2a", "§4.1", "The binding under another URI.",
         mutated(ext, ["uri"], "https://example.invalid/record-push"), False),
        ("neg-a2a-required", "a2a", "§4.1", "required true: a push is opted into per message.",
         mutated(ext, ["required"], True), False),
        ("neg-a2a-params", "a2a", "§4.1", "params present: the entry says nothing about the receiver.",
         mutated(ext, ["params"], {"count": 3}), False),
    ]
    return [{"id": i.replace("-", "-declared-", 1), "kind": "declaration", "carriage": c, "section": [s, "§2.3"], "description": d,
             "input": v, "expect": {"conforms": ok}} for i, c, s, d, v, ok in cases]


class _Delete:
    pass


_DELETE = _Delete()


def cases() -> list[dict]:
    out = push_cases() + classify_cases() + declaration_cases()
    ids = [c["id"] for c in out]
    if len(set(ids)) != len(ids):
        raise SystemExit("duplicate case id")
    return out


def write(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    doc = {
        "binding": "spec/bindings/record-push-v0.md",
        "provenance": "spec-derived",
        "generator": "python/scripts/generate_record_push_vectors.py",
        "description": (
            "Carriage vectors for the record push binding over MCP and A2A (open point RP-1). "
            "Kinds: push (what a receiver does with a tool call or Message: hand the decoded octets to "
            "SF section 6, or answer an error and no answer object), classify (what a sender received, "
            "classified by the answer position alone), declaration (the tool definition and the extension "
            "entry). They pin nothing about records, stamp proofs, the push rule or the answers' values."
        ),
        "extension_uri": URI,
        "cases": cases(),
    }
    text = dumps(doc)
    (out / "carriage.json").write_text(text, encoding="utf-8")
    manifest = {
        "binding": "spec/bindings/record-push-v0.md",
        "provenance": "spec-derived",
        "generator": "python/scripts/generate_record_push_vectors.py",
        "files": [{"path": "carriage.json", "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                   "count": len(doc["cases"])}],
    }
    (out / "manifest.json").write_text(dumps(manifest), encoding="utf-8")
    lines = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}"
             for p in sorted(out.iterdir()) if p.is_file() and p.name != "SHA256SUMS"]
    (out / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=OUT)
    write(parser.parse_args().out)


if __name__ == "__main__":
    main()
