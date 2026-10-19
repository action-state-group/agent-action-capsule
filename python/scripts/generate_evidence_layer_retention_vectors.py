#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate the Evidence Layer UNDISCLOSED retention vectors.

draft-mih-agent-evidence-layer-01, "UNDISCLOSED and policy_uri", adds the
retention state ``UNDISCLOSED``: the store does not state which other
retention state applies, under the policy ``policy_uri`` names. A record
carrying ``retention_state`` ``UNDISCLOSED`` MUST carry ``policy_uri``, a URI
(RFC 3986, Section 3) and not a relative reference; a reader treats one
without it, or with a ``policy_uri`` that is not such a URI, as malformed.
``policy_uri`` MAY accompany any other retention state.

The draft fixes the header members but not a serialization. Each case is the
JSON object of ``retention_state``, ``payload_commitments`` (whose presence
makes ``retention_state`` REQUIRED; the rules here do not otherwise read it)
and, when present, ``policy_uri``. Other header members do not affect these
rules and are left out.

Usage: python python/scripts/generate_evidence_layer_retention_vectors.py [--out DIR]
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "vectors" / "evidence-layer" / "retention"
DRAFT = "draft-mih-agent-evidence-layer-01"
SECTION = "Record/Payload Separation, Retention, and Disclosure, UNDISCLOSED and policy_uri"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def payload_digest(label: str) -> str:
    """A fixed stand-in payload digest, derived from a label so a run is reproducible."""
    return sha256_hex(f"evidence-layer-retention:{label}".encode())


def header(state: Any, label: str, **extra: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "retention_state": state,
        "payload_commitments": [payload_digest(label)],
    }
    record.update(extra)
    return record


def positive(case_id: str, description: str, record: dict[str, Any]) -> dict[str, Any]:
    return {"id": case_id, "kind": "positive", "description": description,
            "record": record, "expected": {"valid": True}}


def negative(case_id: str, description: str, record: dict[str, Any], reason: str) -> dict[str, Any]:
    return {"id": case_id, "kind": "negative", "description": description,
            "record": record,
            "expected": {"valid": False, "reason": reason, "member": "policy_uri"}}


def cases() -> list[dict[str, Any]]:
    return [
        positive("pos-undisclosed-https",
                 "UNDISCLOSED with an https policy_uri.",
                 header("UNDISCLOSED", "a", policy_uri="https://example.com/policies/retention")),
        positive("pos-undisclosed-urn",
                 "UNDISCLOSED with a urn policy_uri: any URI with a scheme qualifies.",
                 header("UNDISCLOSED", "b", policy_uri="urn:example:policy:retention:7")),
        positive("pos-undisclosed-fragment",
                 "UNDISCLOSED with a policy_uri carrying a fragment: still a URI, not a relative reference.",
                 header("UNDISCLOSED", "c", policy_uri="https://example.com/policies#retention")),
        positive("pos-withheld-no-policy-uri",
                 "WITHHELD without policy_uri: only UNDISCLOSED requires it.",
                 header("WITHHELD", "d")),
        positive("pos-withheld-with-policy-uri",
                 "WITHHELD with policy_uri: policy_uri MAY accompany any other state.",
                 header("WITHHELD", "e", policy_uri="https://example.com/policies/access")),
        negative("neg-undisclosed-missing-policy-uri",
                 "UNDISCLOSED with no policy_uri.",
                 header("UNDISCLOSED", "f"), "missing_policy_uri"),
        negative("neg-undisclosed-policy-uri-empty",
                 "UNDISCLOSED with an empty policy_uri.",
                 header("UNDISCLOSED", "g", policy_uri=""), "policy_uri_form"),
        negative("neg-undisclosed-policy-uri-relative-path",
                 "UNDISCLOSED with a relative reference (a path) as policy_uri.",
                 header("UNDISCLOSED", "h", policy_uri="/policies/retention"), "policy_uri_form"),
        negative("neg-undisclosed-policy-uri-network-path",
                 "UNDISCLOSED with a network-path relative reference (no scheme) as policy_uri.",
                 header("UNDISCLOSED", "i", policy_uri="//example.com/policies/retention"),
                 "policy_uri_form"),
        negative("neg-undisclosed-policy-uri-whitespace",
                 "UNDISCLOSED with a policy_uri containing a space, which no URI contains.",
                 header("UNDISCLOSED", "j", policy_uri="https://example.com/retention policy"),
                 "policy_uri_form"),
        negative("neg-undisclosed-policy-uri-not-string",
                 "UNDISCLOSED with a non-string policy_uri.",
                 header("UNDISCLOSED", "k", policy_uri=["https://example.com/policies/retention"]),
                 "policy_uri_form"),
        negative("neg-undisclosed-policy-uri-null",
                 "UNDISCLOSED with a null policy_uri: present but not a URI.",
                 header("UNDISCLOSED", "l", policy_uri=None), "policy_uri_form"),
    ]


def _dump(value: Any) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def build() -> dict[str, bytes]:
    case_list = cases()
    files = {
        "cases.json": _dump({
            "draft": DRAFT,
            "section": SECTION,
            "provenance": "spec-derived",
            "rules": {
                "UNDISCLOSED": "policy_uri is REQUIRED",
                "policy_uri": "a URI (RFC 3986, Section 3), not a relative reference; these "
                              "cases check only a string that is a scheme, then ':', with no "
                              "whitespace, not full RFC 3986 syntax",
                "other_states": "policy_uri is OPTIONAL",
                "serialization": "JSON object of the header members these rules read; other "
                                 "header members are left out",
            },
            "reasons": {
                "missing_policy_uri": "retention_state is UNDISCLOSED and the record has no policy_uri",
                "policy_uri_form": "retention_state is UNDISCLOSED and policy_uri is not a URI",
            },
            "count": len(case_list),
            "cases": case_list,
        }),
    }
    files["manifest.json"] = _dump({
        "draft": DRAFT,
        "provenance": "spec-derived",
        "generator": "python/scripts/generate_evidence_layer_retention_vectors.py",
        "files": [{"path": name, "sha256": sha256_hex(data), "count": json.loads(data).get("count")}
                  for name, data in sorted(files.items())],
    })
    return files


def write(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for name, data in build().items():
        (out / name).write_bytes(data)
    lines = [f"{sha256_hex(p.read_bytes())}  {p.name}"
             for p in sorted(out.iterdir()) if p.is_file() and p.name != "SHA256SUMS"]
    (out / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    write(parser.parse_args().out)


if __name__ == "__main__":
    main()
