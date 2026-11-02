# SPDX-License-Identifier: BSD-3-Clause
"""Carriage over the native stream, A2A and MCP, and the manifest properties (profile §11.4).

A carriage moves request and reply octets as opaque bytes (§11.4.1 rule 1). These functions take
the carriage's own JSON values, find the octets in the reply position, and classify what came
back by the octets alone (rule 6): a reply, pending, or a transport condition. A2A task states,
the MCP ``isError`` flag and any human-readable text never make a reply an envelope, a refusal or
absent. The replies found are then verified like any other (``InteropVerifier``).
"""
from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from ._common import (
    FAIL,
    MEDIA_CBOR,
    MEDIA_JSON,
    NOT_CHECKED,
    PASS,
    PropertyReport,
    b64_any_decode,
    b64url_decode,
    jcs_or_none,
    member_of,
)

__all__ = [
    "EXTENSION_URI",
    "Classified",
    "a2a_request_octets",
    "classify_a2a_task",
    "mcp_request_octets",
    "classify_mcp_result",
    "manifest_form",
    "manifest_consistency",
    "manifest_from_http",
]

EXTENSION_URI = "https://datatracker.ietf.org/doc/draft-mih-agent-evidence-request/"
_MEDIA = (MEDIA_CBOR, MEDIA_JSON)
_A2A_PENDING = frozenset({"TASK_STATE_SUBMITTED", "TASK_STATE_WORKING", "TASK_STATE_INPUT_REQUIRED",
                          "TASK_STATE_AUTH_REQUIRED", "TASK_STATE_UNSPECIFIED"})
_MANIFEST_REQUIRED = frozenset({"profiles", "drafts", "subject_forms", "bindings"})
_MANIFEST_MEMBERS = _MANIFEST_REQUIRED | {"derivations", "refusal_policy", "retention"}
_ARRAY_MEMBERS = frozenset({"profiles", "drafts", "subject_forms", "derivations", "bindings"})
_SUBJECT_FORMS = frozenset({"full_history", "checkpoints", "record", "range", "correlation", "exchange"})
_BINDINGS = frozenset({"evidence-request/1", "http", "a2a", "mcp"})


@dataclass
class Classified:
    """What a carriage delivered in its reply position (§11.4.1 rule 6).

    ``outcome`` is ``reply``, ``pending`` or ``transport_condition``. ``replies`` holds the reply
    octets, one per distinct reply (rule 8); ``rejected`` says why anything else was set aside.
    """

    outcome: str
    replies: list = field(default_factory=list)
    rejected: list = field(default_factory=list)


def _extensions(obj: Mapping[str, Any]) -> list:
    exts = obj.get("extensions")
    return exts if isinstance(exts, list) else []


def a2a_request_octets(message: Any) -> tuple[bytes, str] | None:
    """The request octets and media type of an A2A ``Message`` under §11.4.4, or None when the
    ``Message`` is not a request under this profile."""
    if not isinstance(message, dict):
        return None
    parts = message.get("parts")
    if message.get("role") != "ROLE_USER" or EXTENSION_URI not in _extensions(message):
        return None
    if "taskId" in message or not isinstance(parts, list) or len(parts) != 1 or not isinstance(parts[0], dict):
        return None
    part = parts[0]
    octets = b64_any_decode(part.get("raw"))
    if octets is None or part.get("mediaType") not in _MEDIA:
        return None
    return octets, part["mediaType"]


def classify_a2a_task(task: Any, media_type: str) -> Classified:
    """§11.4.4: reply Artifacts are found by the extension URI, whatever the task state.

    Artifacts with one ``artifactId`` are one Artifact, so a repeat delivery of the same octets
    under one id is one reply. Every other reply Artifact is a reply on its own, including two
    under one id that carry different octets (each is verified, and ``caller_invariance`` compares
    them) and any without an id.
    """
    if not isinstance(task, dict):
        return Classified("transport_condition", [], ["the task is not an object"])
    found: list = []
    seen: set = set()
    rejected = []
    artifacts = task.get("artifacts")
    for artifact in artifacts if isinstance(artifacts, list) else []:
        if not isinstance(artifact, dict) or EXTENSION_URI not in _extensions(artifact):
            continue
        parts = artifact.get("parts")
        part = parts[0] if isinstance(parts, list) and len(parts) == 1 and isinstance(parts[0], dict) else None
        octets = b64_any_decode(part.get("raw")) if part is not None else None
        if part is None or octets is None or part.get("mediaType") != media_type:
            rejected.append(f"artifact {artifact.get('artifactId')!r}: not one raw part of the request's media type")
            continue
        artifact_id = jcs_or_none(artifact.get("artifactId")) if "artifactId" in artifact else None
        if artifact_id is not None and (artifact_id, octets) in seen:
            continue
        if artifact_id is not None:
            if any(a == artifact_id for a, _ in seen):
                rejected.append(f"artifact {artifact.get('artifactId')!r}: one id, different octets; each verified")
            seen.add((artifact_id, octets))
        found.append(octets)
    if found:
        return Classified("reply", found, rejected)
    status = task.get("status")
    state = status.get("state") if isinstance(status, dict) else None
    if member_of(state, _A2A_PENDING) and not rejected:
        return Classified("pending", [], rejected)
    rejected.append(f"no reply Artifact; task state {state!r} is never a refusal (§11.4.4)")
    return Classified("transport_condition", [], rejected)


def mcp_request_octets(call: Any) -> tuple[bytes, str] | None:
    """The request octets and media type of an MCP ``evidence_request`` call (§11.4.5)."""
    if not isinstance(call, dict):
        return None
    args = call.get("arguments")
    if call.get("name") != "evidence_request" or not isinstance(args, dict) or set(args) != {"request", "media_type"}:
        return None
    octets = b64url_decode(args.get("request"))
    if octets is None or args.get("media_type") not in _MEDIA:
        return None
    return octets, args["media_type"]


def classify_mcp_result(result: Any, media_type: str, input_required: bool = False) -> Classified:
    """§11.4.5: a result whose ``structuredContent.reply`` is base64url and whose ``media_type``
    is the request's is the reply, whatever ``isError`` says.

    ``input_required`` is the caller's MCP client saying the result is an interim
    ``input_required`` result; with no reply in it, the request is pending. This module does not
    read that state from the result itself.
    """
    if not isinstance(result, dict):
        return Classified("transport_condition", [], ["the result is not an object"])
    content = result.get("structuredContent")
    if isinstance(content, dict) and "reply" in content:
        octets = b64url_decode(content.get("reply"))
        if octets is not None and content.get("media_type") == media_type:
            return Classified("reply", [octets])
        return Classified("transport_condition", [], ["structuredContent.reply is not a well-formed reply"])
    if input_required:
        return Classified("pending")
    return Classified("transport_condition", [], ["no structuredContent.reply; isError and text are never a refusal"])


def _sorted_unique(values: Sequence[str]) -> bool:
    return list(values) == sorted(set(values))


def _no_duplicate_members(pairs: list) -> dict:
    out: dict = {}
    for k, v in pairs:
        if k in out:
            raise ValueError(f"duplicate member {k!r}")
        out[k] = v
    return out


def manifest_from_http(body: bytes, media_type: str) -> tuple[Any, bool]:
    """The manifest value of a ``GET`` at ``/.well-known/evidence-manifest`` and whether the
    response has the form §11.4.2 fixes: media type ``application/json`` and a body that is
    exactly the JCS serialization of the parsed value. The value is None when the body does not
    parse as JSON without duplicate members, so ``manifest_form`` and ``manifest_consistency``
    both ``FAIL`` on it."""
    try:
        value = json.loads(body.decode("utf-8"), object_pairs_hook=_no_duplicate_members)
    except ValueError:
        return None, False
    essence = media_type.split(";", 1)[0].strip().lower()  # RFC 9110: parameters are not the media type
    return value, essence == MEDIA_JSON and jcs_or_none(value) == body


def manifest_form(manifest: Any, profiles_implemented: frozenset,
                  recipient_specific: frozenset = frozenset()) -> PropertyReport:
    """``manifest_form`` (§11.4.7): required members, value forms, sorted unique arrays, and
    nothing outside §11.4.2 (``FAIL`` when every listed profile is implemented, else
    ``NOT_CHECKED``)."""
    method = "§11.4.2 manifest members and value forms"
    if not isinstance(manifest, dict):
        return PropertyReport("manifest_form", FAIL, method, "not a JSON object")
    missing = _MANIFEST_REQUIRED - set(manifest)
    if missing:
        return PropertyReport("manifest_form", FAIL, method, f"required members are absent: {sorted(missing)}")
    for name, value in manifest.items():
        if name in _ARRAY_MEMBERS or not isinstance(value, str):
            # §11.4.2: the list members are non-empty arrays of text, sorted and unique; any
            # other member that is not text is not of the form given there either.
            if not (isinstance(value, list) and value and all(isinstance(x, str) for x in value)):
                return PropertyReport("manifest_form", FAIL, method,
                                      f"{name} is not of its §11.4.2 form (no number, boolean or map)")
            if name in _MANIFEST_MEMBERS and name not in _ARRAY_MEMBERS:
                return PropertyReport("manifest_form", FAIL, method, f"{name} is not a text string")
            if not _sorted_unique(value):
                return PropertyReport("manifest_form", FAIL, method, f"{name} is not sorted by code point, unique")
    if recipient_specific & set(manifest.get("derivations") or []):
        return PropertyReport("manifest_form", FAIL, method, "derivations lists a recipient-specific derivation")
    extra = set(manifest) - _MANIFEST_MEMBERS
    unknown_tokens = (set(manifest["subject_forms"]) - _SUBJECT_FORMS) | (set(manifest["bindings"]) - _BINDINGS)
    if manifest.get("refusal_policy") not in (None, "uniform", "specific"):
        unknown_tokens.add(manifest["refusal_policy"])
    if extra or unknown_tokens:
        what = f"members {sorted(extra)}" if extra else f"tokens {sorted(unknown_tokens)}"
        if set(manifest["profiles"]) <= profiles_implemented:
            return PropertyReport("manifest_form", FAIL, method, f"{what} outside §11.4.2")
        return PropertyReport("manifest_form", NOT_CHECKED, method,
                              f"{what} may be defined by a profile listed that is not implemented")
    return PropertyReport("manifest_form", PASS, method)


def manifest_consistency(manifests: Sequence[Any]) -> PropertyReport:
    """``manifest_consistency`` (§11.4.7): equal JCS serializations across two or more copies."""
    method = "equal JCS serializations (§11.4.2)"
    if len(manifests) < 2:
        return PropertyReport("manifest_consistency", NOT_CHECKED, method, "fewer than two manifests are held")
    forms = [jcs_or_none(m) for m in manifests]
    if None in forms or len(set(forms)) > 1:
        return PropertyReport("manifest_consistency", FAIL, method,
                              "the copies differ; attributable to the responder only if each was authenticated")
    return PropertyReport("manifest_consistency", PASS, method)
