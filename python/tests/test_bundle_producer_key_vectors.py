# SPDX-License-Identifier: BSD-3-Clause
"""The Evidence Bundle ``producer-key/v1`` vectors (``vectors/bundle/producer-key``).

Checks that the committed files are pinned and regenerate byte for byte, that
every case's ``bundle_digest`` is the reference library's bundle digest and its
``countersign/v1`` signature verifies, and that applying the draft's rule
("The producer-key/v1 Extension", "Self-Countersignature") gives each case's
expected key and stamp. The bundle core still treats the block as an
uninterpreted, digest-covered extension and never fails because of it.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import re
from pathlib import Path

import pytest

from agent_action_capsule.bundle import bundle_digest, verify_bundle
from agent_action_capsule.canonical import jcs

pytest.importorskip("cryptography")
from cryptography.exceptions import InvalidSignature  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "vectors" / "bundle" / "producer-key"
GENERATOR = ROOT / "python" / "scripts" / "generate_bundle_producer_key_vectors.py"
KEY = re.compile(r"[0-9a-f]{64}")

pytestmark = pytest.mark.skipif(not VECTORS.exists(), reason="source-tree vectors not present")


def _corpus() -> dict:
    return json.loads((VECTORS / "vectors.json").read_text(encoding="utf-8"))


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def declared_producer_keys(bundle: dict) -> list[str]:
    """The draft's rule: one well-formed ``public_key`` string, else nothing."""
    extensions = bundle.get("extensions")
    block = extensions.get("producer-key/v1") if isinstance(extensions, dict) else None
    key = block.get("public_key") if isinstance(block, dict) else None
    return [key] if isinstance(key, str) and KEY.fullmatch(key) else []


def stamp(entry: dict, digest: str, producer_keys: list[str]) -> str:
    """Classify one countersign/v1 entry with no countersigner directory consulted."""
    if entry["over"] != digest:
        return "invalid"
    signed = jcs(
        {"over": entry["over"], "signer": entry["signer"], "statement": entry["statement"], "type": "countersign/v1"}
    )
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(entry["signer"]["key_id"])).verify(
            bytes.fromhex(entry["signature"]), signed
        )
    except InvalidSignature:
        return "invalid"
    return "not independent" if entry["signer"]["key_id"] in producer_keys else "unresolved signer"


def test_files_are_pinned_and_regenerate_byte_for_byte(tmp_path: Path) -> None:
    listed = dict(reversed(line.split("  ", 1)) for line in (VECTORS / "SHA256SUMS").read_text().splitlines())
    on_disk = {p.name for p in VECTORS.iterdir() if p.is_file() and p.name != "SHA256SUMS"}
    assert set(listed) == on_disk
    for name, digest in listed.items():
        assert _sha((VECTORS / name).read_bytes()) == digest, name
    top = dict(reversed(line.split("  ", 1)) for line in (ROOT / "vectors" / "SHA256SUMS").read_text().splitlines())
    for name in on_disk:
        assert top.get(f"bundle/producer-key/{name}") == listed[name], name

    spec = importlib.util.spec_from_file_location("gen_producer_key", GENERATOR)
    assert spec is not None and spec.loader is not None
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    for name, data in generator.build().items():
        assert data == (VECTORS / name).read_bytes(), name


def test_extension_block_matches_the_emitted_form() -> None:
    corpus = _corpus()
    producer = corpus["keys"]["producer_public_key_hex"]
    # capsulectl (capsule-cli internal/cli producer_key_test.go) asserts exactly this JCS form.
    assert corpus["extension_block_jcs"] == '{"producer-key/v1":{"public_key":"' + producer + '"}}'
    declared = corpus["cases"][0]["bundle"]["extensions"]
    assert jcs(declared).decode("utf-8") == corpus["extension_block_jcs"]


@pytest.mark.parametrize("case", _corpus()["cases"], ids=lambda c: c["id"])
def test_case(case: dict) -> None:
    bundle = case["bundle"]
    digest = bundle_digest(bundle)
    assert digest == case["bundle_digest"]
    keys = declared_producer_keys(bundle)
    assert keys == case["expect"]["declared_producer_keys"]
    (entry,) = bundle["countersignatures"]
    assert stamp(entry, digest, keys) == case["expect"]["stamp"]

    # The block is digest-covered and never fails the bundle: the core reports
    # it as an uninterpreted extension, and dropping it changes the digest.
    result = verify_bundle(bundle)
    if "extensions" in bundle:
        assert [(e.kind, e.status) for e in result.extensions] == [("producer-key/v1", "uninterpreted")]
        stripped = {k: v for k, v in bundle.items() if k != "extensions"}
        assert bundle_digest(stripped) != digest
        # Re-signing is not needed to see the binding: the entry no longer covers the stripped bundle.
        assert stamp(entry, bundle_digest(stripped), keys) == "invalid"


def test_declaration_only_downgrades() -> None:
    cases = {c["id"]: c for c in _corpus()["cases"]}
    with_ext = cases["declared-self-countersignature"]["bundle"]
    without = cases["undeclared-self-countersignature"]["bundle"]
    # The only difference between the two is the extension (and the entry that signs each digest).
    strip = lambda b: {k: v for k, v in b.items() if k not in ("extensions", "countersignatures")}  # noqa: E731
    assert strip(with_ext) == strip(without)
    assert cases["declared-self-countersignature"]["expect"]["stamp"] == "not independent"
    assert cases["undeclared-self-countersignature"]["expect"]["stamp"] != "not independent"
