#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate the Evidence Layer padding record vectors.

draft-mih-agent-evidence-layer-00, "What a Checkpoint Reveals", defines a
padding record: ``record_type`` ``padding``, ``epistemic_type``
``producer_claim``, and as its only content a fresh random value in the
member ``store_nonce``, 32 bytes encoded as 64 lowercase hexadecimal
characters. It carries no ``payload_commitments``, no links, no
``subject_ref`` and no ``principal_ref``.

The cases use the JSON serialization the existing padding writers share::

    {"capsule_id": <id>, "record_type": "padding",
     "epistemic_type": "producer_claim", "store_nonce": <64 lowercase hex>}

``capsule_id`` is the record's content-derived ``record_id``: the draft's
Digest (lowercase-hex SHA-256 of ``UTF8(JCS(value))``, RFC 8785) of the record
without ``capsule_id``. Every case records that preimage's literal JCS string.

Every negative case carries a ``capsule_id`` that recomputes over its own
members, so the only reason it fails is the padding shape named in
``expected.reason``, except ``neg-capsule-id-mismatch``, whose only defect is
its id.

The nonces are fixed values derived from a label, so the run is reproducible.
A real store draws each nonce from a cryptographically secure random source;
no vector can test that.

Output: ``vectors/evidence-layer/padding/`` (or ``--out DIR``). Deterministic:
no clock, no randomness, no keys. ``README.md`` is hand-written; when present in
the output directory it is included in ``SHA256SUMS`` but never rewritten.
Dependencies: the standard library only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "vectors" / "evidence-layer" / "padding"
DRAFT = "draft-mih-agent-evidence-layer-00"
SECTION = "Privacy Considerations, What a Checkpoint Reveals"


def jcs(value: Any) -> str:
    """RFC 8785 for these vectors' value space (ASCII keys and strings, no floats)."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_digest(value: Any) -> str:
    return sha256_hex(jcs(value).encode())


def nonce(label: str) -> str:
    """A fixed 64-lowercase-hex stand-in for a fresh store nonce."""
    return sha256_hex(f"evidence-layer padding vector nonce: {label}".encode())


def body(label: str) -> dict:
    return {"record_type": "padding", "epistemic_type": "producer_claim", "store_nonce": nonce(label)}


def seal(members: dict) -> dict:
    """The record with ``capsule_id`` first, as the writers emit it."""
    return {"capsule_id": json_digest(members), **members}


def case(case_id: str, description: str, members: dict, *, reason: str | None = None,
         member: str | None = None, capsule_id: str | None = None) -> dict:
    record = seal(members)
    if capsule_id is not None:
        record["capsule_id"] = capsule_id
    expected: dict[str, Any] = {"valid": reason is None}
    if reason is not None:
        expected["reason"] = reason
    if member is not None:
        expected["member"] = member
    return {
        "id": case_id,
        "kind": "positive" if reason is None else "negative",
        "description": description,
        "record": record,
        "capsule_id_preimage": jcs(members),
        "expected": expected,
    }


def without(members: dict, name: str) -> dict:
    return {k: v for k, v in members.items() if k != name}


def cases() -> list[dict]:
    link_target = json_digest({"example": "link target"})
    return [
        case("pos-padding-a", "A padding record.", body("a")),
        case("pos-padding-b", "A second padding record: a different nonce gives a different capsule_id.",
             body("b")),
        case("pos-padding-digits-only", "A nonce whose hex digits are all 0-9 is still 64 lowercase hex.",
             {**body("c"), "store_nonce": "0123456789" * 6 + "0123"}),
        case("neg-missing-store-nonce", "No store_nonce member.",
             without(body("d"), "store_nonce"), reason="missing_store_nonce", member="store_nonce"),
        case("neg-store-nonce-uppercase", "store_nonce in uppercase hex.",
             {**body("e"), "store_nonce": nonce("e").upper()}, reason="store_nonce_encoding",
             member="store_nonce"),
        case("neg-store-nonce-short", "store_nonce of 16 bytes (32 hex characters), not 32 bytes.",
             {**body("f"), "store_nonce": nonce("f")[:32]}, reason="store_nonce_encoding",
             member="store_nonce"),
        case("neg-store-nonce-long", "store_nonce of 33 bytes (66 hex characters).",
             {**body("g"), "store_nonce": nonce("g") + "00"}, reason="store_nonce_encoding",
             member="store_nonce"),
        case("neg-store-nonce-not-hex", "store_nonce of 64 characters that are not all hex digits.",
             {**body("h"), "store_nonce": "g" + nonce("h")[1:]}, reason="store_nonce_encoding",
             member="store_nonce"),
        case("neg-store-nonce-not-string", "store_nonce is a JSON number.",
             {**body("i"), "store_nonce": 1234}, reason="store_nonce_encoding", member="store_nonce"),
        case("neg-extra-member", "A member beyond the padding record's own.",
             {**body("j"), "note": "padding"}, reason="extra_member", member="note"),
        case("neg-links", "A padding record carrying a link.",
             {**body("k"), "links": [{"type": "cites", "target": link_target}]},
             reason="extra_member", member="links"),
        case("neg-payload-commitments", "A padding record carrying payload commitments.",
             {**body("l"), "payload_commitments": [json_digest({"example": "payload"})]},
             reason="extra_member", member="payload_commitments"),
        case("neg-subject-ref", "A padding record carrying a subject_ref.",
             {**body("m"), "subject_ref": "subject-0001"}, reason="extra_member", member="subject_ref"),
        case("neg-principal-ref", "A padding record carrying a principal_ref.",
             {**body("n"), "principal_ref": "principal-0001"}, reason="extra_member",
             member="principal_ref"),
        case("neg-epistemic-type-observed-event", "epistemic_type is observed_event, not producer_claim.",
             {**body("o"), "epistemic_type": "observed_event"}, reason="epistemic_type",
             member="epistemic_type"),
        case("neg-epistemic-type-missing", "No epistemic_type member.",
             without(body("p"), "epistemic_type"), reason="epistemic_type", member="epistemic_type"),
        case("neg-capsule-id-mismatch", "A well-formed padding record whose capsule_id does not recompute.",
             body("q"), reason="capsule_id_mismatch", member="capsule_id",
             capsule_id=json_digest(body("q-other"))),
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
                "record_type": "padding",
                "epistemic_type": "producer_claim",
                "store_nonce": "string of 64 lowercase hexadecimal characters (32 bytes)",
                "members": ["capsule_id", "record_type", "epistemic_type", "store_nonce"],
                "capsule_id": "lowercase hex SHA-256 of UTF8(JCS(record without capsule_id)) (RFC 8785)",
            },
            "reasons": {
                "missing_store_nonce": "the record has no store_nonce member",
                "store_nonce_encoding": "store_nonce is not a string of 64 lowercase hexadecimal characters",
                "extra_member": "the record carries a member other than the four above",
                "epistemic_type": "epistemic_type is absent or is not producer_claim",
                "capsule_id_mismatch": "capsule_id does not recompute from the record",
            },
            "count": len(case_list),
            "cases": case_list,
        }),
    }
    files["manifest.json"] = _dump({
        "draft": DRAFT,
        "provenance": "spec-derived",
        "generator": "python/scripts/generate_evidence_layer_padding_vectors.py",
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
