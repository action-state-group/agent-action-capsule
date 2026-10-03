#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate the Evidence Bundle ``producer-key/v1`` conformance vectors.

The extension and the expected results come from
``spec/draft-mih-zhang-agent-disclosure-bundle-01.md``, "The producer-key/v1
Extension" and "Self-Countersignature". Every expected stamp below is written
by hand from that text; nothing here imports or runs an implementation of the
classification. The script only builds the literal Bundles, hashes them
(RFC 8785 JCS, SHA-256) and signs one ``countersign/v1`` entry per case with a
fixed, test-only Ed25519 key.

Base Bundle: the positive case of ``vectors/bundle/report-single-record.json``,
read as committed (that file is a released vector and is never rewritten
here). Keys: 32 bytes of 0x0b (the producer, the same test seed as the AAC
TypeScript derived fixture ``week-bundle-producer-countersigned.json``) and 32
bytes of 0x21 (another signer). Neither is a production key.

Output: ``vectors/bundle/producer-key/`` (or ``--out DIR``). The run is a pure
function of this file and the base Bundle: no clock, no randomness (Ed25519
signatures are deterministic). ``README.md`` is hand-written; when present in
the output directory it is included in ``SHA256SUMS`` but never rewritten.

Dependencies: the standard library and ``cryptography`` (Ed25519 only).
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "vectors" / "bundle" / "producer-key"
BASE = ROOT / "vectors" / "bundle" / "report-single-record.json"
BASE_CASE = "pos-single-record-report"
DRAFT = "draft-mih-zhang-agent-disclosure-bundle-01"
KIND = "producer-key/v1"

PRODUCER_SEED = bytes([0x0B]) * 32
OTHER_SEED = bytes([0x21]) * 32
SIGNER_ID = "did:web:countersign.example"
STATEMENT = {
    "checks": [
        {"name": "chain consistency", "result": "established"},
        {"name": "range membership", "result": "failed"},
    ],
    "recomputed_at": "2026-10-01T00:00:00Z",
    "scope": {"ledger_id": "ledger:test", "closure_depth": 0},
}


def _check_json_value(value: Any) -> None:
    if isinstance(value, float):
        raise TypeError("the vectors use no floating-point numbers")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or not key.isascii():
                raise TypeError("map keys in these vectors are ASCII text")
            _check_json_value(item)
    elif isinstance(value, list):
        for item in value:
            _check_json_value(item)


def jcs(value: Any) -> bytes:
    """RFC 8785 for the value space these vectors use (no floats, ASCII keys).

    With ASCII keys, UTF-16 code-unit order equals code-point order, so
    ``sort_keys`` is the RFC 8785 member order; the separators and string
    escaping of ``json.dumps(ensure_ascii=False)`` match RFC 8785 for these
    values.
    """
    _check_json_value(value)
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _key(seed: bytes) -> tuple[Ed25519PrivateKey, str]:
    private = Ed25519PrivateKey.from_private_bytes(seed)
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return private, public.hex()


def bundle_digest(bundle: dict) -> str:
    """SHA-256(UTF8(JCS(bundle with countersignatures omitted))), 64 lowercase hex."""
    return hashlib.sha256(jcs({k: v for k, v in bundle.items() if k != "countersignatures"})).hexdigest()


def _base_bundle() -> dict:
    corpus = json.loads(BASE.read_text(encoding="utf-8"))
    (case,) = [c for c in corpus["cases"] if c["name"] == BASE_CASE]
    bundle = copy.deepcopy(case["bundle"])
    for member in ("extensions", "countersignatures"):
        if member in bundle:
            raise ValueError(f"the base bundle unexpectedly carries {member}")
    return bundle


def _countersigned(bundle: dict, private: Ed25519PrivateKey, key_id: str) -> tuple[dict, str]:
    over = bundle_digest(bundle)
    signer = {"id": SIGNER_ID, "key_id": key_id}
    signing_input = jcs({"over": over, "signer": signer, "statement": STATEMENT, "type": "countersign/v1"})
    entry = {
        "type": "countersign/v1",
        "signer": signer,
        "over": over,
        "statement": STATEMENT,
        "signature": private.sign(signing_input).hex(),
    }
    return {**bundle, "countersignatures": [entry]}, over


def cases() -> list[dict]:
    producer, producer_hex = _key(PRODUCER_SEED)
    other, other_hex = _key(OTHER_SEED)
    base = _base_bundle()

    def case(case_id: str, description: str, extensions: Any, signer: str, expect: dict) -> dict:
        bundle = dict(base) if extensions is _ABSENT else {**base, "extensions": extensions}
        private, key_id = (producer, producer_hex) if signer == "producer" else (other, other_hex)
        bundle, over = _countersigned(bundle, private, key_id)
        return {
            "id": case_id,
            "section": ["The producer-key/v1 Extension", "Self-Countersignature"],
            "description": description,
            "bundle": bundle,
            "bundle_digest": over,
            "expect": {"signature": "valid", **expect},
        }

    def declared(value: Any) -> dict:
        return {KIND: value}

    return [
        case(
            "declared-self-countersignature",
            "the Bundle declares the producer key, and the countersign/v1 entry is signed by that key",
            declared({"public_key": producer_hex}),
            "producer",
            {"declared_producer_keys": [producer_hex], "stamp": "not independent"},
        ),
        case(
            "undeclared-self-countersignature",
            "the same Bundle without the extension, signed by the same key; with no declaration and no "
            "countersigner directory consulted the key is an unlisted signer",
            _ABSENT,
            "producer",
            {"declared_producer_keys": [], "stamp": "unresolved signer"},
        ),
        case(
            "declared-other-signer",
            "the Bundle declares the producer key, and the entry is signed by a different key; the declaration "
            "changes nothing for a signer whose key differs",
            declared({"public_key": producer_hex}),
            "other",
            {"declared_producer_keys": [producer_hex], "stamp": "unresolved signer"},
        ),
        case(
            "malformed-uppercase-hex",
            "public_key is the producer key in uppercase hex; not 64 lowercase hex, so the block is ignored "
            "(never case-folded) and the Bundle does not fail",
            declared({"public_key": producer_hex.upper()}),
            "producer",
            {"declared_producer_keys": [], "stamp": "unresolved signer"},
        ),
        case(
            "malformed-short-hex",
            "public_key is 63 hex characters; malformed, ignored",
            declared({"public_key": producer_hex[:63]}),
            "producer",
            {"declared_producer_keys": [], "stamp": "unresolved signer"},
        ),
        case(
            "malformed-key-list",
            "public_key is a list holding the producer key; the block carries one key as a string, so this "
            "is malformed and ignored",
            declared({"public_key": [producer_hex]}),
            "producer",
            {"declared_producer_keys": [], "stamp": "unresolved signer"},
        ),
        case(
            "malformed-block-not-object",
            "the extension value is the bare key string, not a block object; malformed, ignored",
            declared(producer_hex),
            "producer",
            {"declared_producer_keys": [], "stamp": "unresolved signer"},
        ),
        case(
            "malformed-missing-public-key",
            "the block is empty; malformed, ignored",
            declared({}),
            "producer",
            {"declared_producer_keys": [], "stamp": "unresolved signer"},
        ),
    ]


class _Absent:
    pass


_ABSENT = _Absent()


def build() -> dict[str, bytes]:
    _, producer_hex = _key(PRODUCER_SEED)
    _, other_hex = _key(OTHER_SEED)
    built = cases()
    corpus = {
        "format_version": "1",
        "spec": DRAFT,
        "extension_kind": KIND,
        "provenance": "spec-derived",
        "description": (
            "producer-key/v1 declares the producer's Ed25519 public key. A verifier uses it only to classify a "
            "countersign/v1 entry signed by that key as not independent; a malformed block is ignored and never "
            "fails the Bundle. Stamps use the draft's four countersign/v1 states; no countersigner directory is "
            "consulted, so an independent valid entry is an unresolved signer."
        ),
        "keys": {
            "producer_seed_hex": PRODUCER_SEED.hex(),
            "producer_public_key_hex": producer_hex,
            "other_seed_hex": OTHER_SEED.hex(),
            "other_public_key_hex": other_hex,
            "note": "TEST-ONLY keys",
        },
        "extension_block_jcs": jcs({KIND: {"public_key": producer_hex}}).decode("utf-8"),
        "count": len(built),
        "cases": built,
    }
    return {"vectors.json": (json.dumps(corpus, indent=2, ensure_ascii=False) + "\n").encode("utf-8")}


def write(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for name, data in build().items():
        (out / name).write_bytes(data)
    lines = []
    for path in sorted(p for p in out.iterdir() if p.is_file() and p.name != "SHA256SUMS"):
        lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}")
    (out / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    write(parser.parse_args().out)


if __name__ == "__main__":
    main()
