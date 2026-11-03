# SPDX-License-Identifier: BSD-3-Clause
"""The ``parent-log-witness/v1`` extension (Evidence Bundle draft -03, "The
parent-log-witness/v1 Extension").

A producer can have its checkpoint witnessed without sending it to a witness:
the checkpoint (the Bundle's, or an earlier one of the same log with a
consistency proof) is a salted leaf of a Merkle tree whose root is one entry
of a parent log signed by the same key, and the parent log's checkpoint
carries the Receipts. :func:`verify_parent_log_witness` checks every link of
that chain, then the Receipts over the parent checkpoint with
:func:`agent_action_capsule.witness.verify_witness_receipts`, and computes the
extent itself. Nothing the block states about its extent is read.

Strict :func:`agent_action_capsule.bundle.verify_bundle` calls it when the
Bundle carries the block; see ``vectors/bundle/parent-log-witness/``.
"""

from __future__ import annotations

import binascii
import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .canonical import jcs
from .witness import WitnessReceiptResult, verify_witness_receipts

#: The extension kind.
PARENT_LOG_WITNESS_KIND = "parent-log-witness/v1"
#: The most hashes a path may hold.
MAX_PATH = 32

_SIGNED_FIELDS = ("log_id", "mmr_size", "root", "key_id", "timestamp", "prev_size", "prev_root")
_B64URL = re.compile(r"^[A-Za-z0-9_-]*$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class ParentWitnessResult:
    """The block's result: ``status`` is ``pass``, ``withheld`` or ``fail``.

    ``extent`` is ``(entries, of)`` when the result passed: the leaf counts
    of the covered checkpoint and of the Bundle's checkpoint. ``receipts``
    are the Receipts over the parent checkpoint, once every link held.
    """

    status: str
    findings: tuple[str, ...] = ()
    extent: tuple[int, int] | None = None
    receipts: tuple[WitnessReceiptResult, ...] = ()


def _fail(finding: str) -> ParentWitnessResult:
    return ParentWitnessResult("fail", (finding,))


def _uint(value: Any) -> bool:
    """A JSON integer from 0 to 2^53 - 1 (not a boolean or a float)."""
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 2**53 - 1


def leaf(log_id: Any, size: Any, checkpoint_cose: bytes, salt: Any) -> bytes:
    """The tree leaf naming a checkpoint: SHA-256(0x00 || JCS(...))."""
    body = {
        "checkpoint_sha256": hashlib.sha256(checkpoint_cose).hexdigest(),
        "log_id": log_id,
        "salt": salt,
        "size": size,
    }
    return hashlib.sha256(b"\x00" + jcs(body)).digest()


def node(left: bytes, right: bytes) -> bytes:
    """An interior node: SHA-256(0x01 || left || right)."""
    return hashlib.sha256(b"\x01" + left + right).digest()


def tree_root(leaf_hash: bytes, index: int, path: list[bytes]) -> bytes:
    """The root from a leaf, its position and its path (leaf first)."""
    h = leaf_hash
    for level, sibling in enumerate(path):
        h = node(h, sibling) if (index >> level) & 1 == 0 else node(sibling, h)
    return h


def _signed_checkpoint(stated: Any) -> tuple[str | None, dict[str, Any], bytes]:
    """Verify ``stated["checkpoint"]["cose"]``: ``("malformed", ...)`` when it
    is not unpadded canonical base64url, ``("invalid", ...)`` when the octets
    do not verify, else ``(None, signed fields, octets)``."""
    from cll.checkpoint import verify_checkpoint_cose_offline

    from .bundle import _b64url_decode

    checkpoint = stated.get("checkpoint") if isinstance(stated, Mapping) else None
    encoded = checkpoint.get("cose") if isinstance(checkpoint, Mapping) else None
    if not isinstance(encoded, str) or not _B64URL.fullmatch(encoded):
        return "malformed", {}, b""
    try:
        cose = _b64url_decode(encoded)
    except (ValueError, binascii.Error):
        return "malformed", {}, b""
    try:
        verified = verify_checkpoint_cose_offline(cose)
    except (ValueError, TypeError):
        return "invalid", {}, b""
    if not verified.ok or verified.decoded is None:
        return "invalid", {}, b""
    return None, {name: getattr(verified.decoded, name) for name in _SIGNED_FIELDS}, cose


def _consistency_proof(raw: Any) -> Any:
    """The block's consistency proof as CLL's, or ``None`` when its shape is
    not the draft's."""
    from cll.checkpoint import ConsistencyProof

    if not isinstance(raw, Mapping):
        return None
    peaks_ok = all(
        isinstance(raw.get(name), list) and all(isinstance(h, str) and _HEX64.fullmatch(h) for h in raw[name])
        for name in ("old_peaks", "new_peaks")
    )
    witness = raw.get("witness")
    witness_ok = isinstance(witness, list) and all(
        isinstance(path, list) and all(isinstance(h, str) and _HEX64.fullmatch(h) for h in path) for path in witness
    )
    if (
        raw.get("kind") != "consistency"
        or not _uint(raw.get("v"))
        or raw.get("v") != 1
        or not _uint(raw.get("old_size"))
        or not _uint(raw.get("new_size"))
        or not peaks_ok
        or not witness_ok
    ):
        return None
    return ConsistencyProof(
        v=1,
        kind="consistency",
        size_a=raw["old_size"],
        size_b=raw["new_size"],
        old_peaks=tuple(raw["old_peaks"]),
        witness=tuple(tuple(path) for path in witness),
        new_peaks=tuple(raw["new_peaks"]),
    )


def verify_parent_log_witness(
    block: Any,
    signed: Mapping[str, Any] | None,
    checkpoint_cose: bytes | None,
    directory: Any = None,
) -> ParentWitnessResult:
    """Check a ``parent-log-witness/v1`` block against the Bundle's SIGNED
    checkpoint (``signed``, its fields as ``checkpoint.cose`` states them, and
    ``checkpoint_cose``, its octets; ``None`` when it did not verify), and the
    Receipts over the parent checkpoint under ``directory`` (``None`` trusts
    no witness). Never raises on its input."""
    if signed is None or checkpoint_cose is None:
        return ParentWitnessResult("withheld", ("checkpoint_unverified",))
    # A verified checkpoint means cll is installed.
    from cll.checkpoint import verify_consistency, verify_inclusion
    from cll.checkpoint.core import leaf_count

    if not isinstance(block, Mapping):
        return _fail("parent_witness_malformed")

    covered, covered_cose = signed, checkpoint_cose
    if "earlier" in block:
        earlier = block["earlier"]
        error, prior, prior_cose = _signed_checkpoint(earlier)
        if error == "malformed":
            return _fail("parent_witness_earlier_checkpoint_malformed")
        if error == "invalid":
            return _fail("parent_witness_earlier_checkpoint_signature_invalid")
        if prior["key_id"] != signed["key_id"] or prior["log_id"] != signed["log_id"] or prior["mmr_size"] >= signed["mmr_size"]:
            return _fail("parent_witness_earlier_checkpoint_not_this_log")
        proof = _consistency_proof(earlier.get("consistency_proof"))
        if (
            proof is None
            or proof.size_a != prior["mmr_size"]
            or proof.size_b != signed["mmr_size"]
            or not verify_consistency(
                bytes.fromhex(prior["root"]), prior["mmr_size"], bytes.fromhex(signed["root"]), signed["mmr_size"], proof
            )
        ):
            return _fail("parent_witness_earlier_checkpoint_not_a_prefix")
        covered, covered_cose = prior, prior_cose

    log_id, size = block.get("log_id"), block.get("size")
    if not isinstance(log_id, str) or log_id != covered["log_id"] or not _uint(size) or size != covered["mmr_size"]:
        return _fail("parent_witness_leaf_does_not_name_this_checkpoint")
    path = block.get("path")
    if (
        not isinstance(path, list)
        or len(path) > MAX_PATH
        or not all(isinstance(h, str) and _HEX64.fullmatch(h) for h in path)
    ):
        return _fail("parent_witness_path_malformed")
    salt, index = block.get("salt"), block.get("index")
    if not isinstance(salt, str) or salt == "" or not _uint(index) or index >= 1 << len(path):
        return _fail("parent_witness_leaf_malformed")
    try:
        leaf_hash = leaf(log_id, size, covered_cose, salt)
    except ValueError:
        # A salt JCS cannot write (an unpaired surrogate) names no leaf.
        return _fail("parent_witness_leaf_malformed")
    root = tree_root(leaf_hash, index, [bytes.fromhex(h) for h in path])

    parent = block.get("parent")
    error, parent_signed, parent_cose = _signed_checkpoint(parent)
    if error == "malformed":
        return _fail("parent_witness_parent_checkpoint_malformed")
    if error == "invalid":
        return _fail("parent_witness_parent_checkpoint_signature_invalid")
    if parent_signed["key_id"] != signed["key_id"]:
        return _fail("parent_witness_parent_signer_differs")
    if not isinstance(parent.get("log_id"), str) or parent["log_id"] != parent_signed["log_id"]:
        return _fail("parent_witness_parent_log_id_mismatch")
    entry_index = parent.get("entry_index")
    from .bundle import _inclusion_proof

    try:
        inclusion = _inclusion_proof(parent.get("inclusion_proof"))
    except (KeyError, TypeError, ValueError):
        inclusion = None
    if (
        not _uint(entry_index)
        or inclusion is None
        or inclusion.size != parent_signed["mmr_size"]
        or inclusion.leaf_index != entry_index
        or not verify_inclusion(bytes.fromhex(parent_signed["root"]), parent_signed["mmr_size"], entry_index, root, inclusion)
    ):
        return _fail("parent_witness_entry_not_included")

    status, findings, receipts = verify_witness_receipts(parent.get("witnesses"), parent_signed, parent_cose, directory)
    extent = (leaf_count(covered["mmr_size"]), leaf_count(signed["mmr_size"])) if status == "pass" else None
    return ParentWitnessResult(status, findings, extent, receipts)
