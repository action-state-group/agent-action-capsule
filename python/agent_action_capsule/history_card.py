# SPDX-License-Identifier: Apache-2.0
"""``history_card/2`` of ``draft-mih-agent-evidence-request-03`` §8.1.2.

A ``history_card/2`` lists a sample of an evidence stream's checkpoints: the first, the ones 1, 2,
4, 8 and so on positions back from the anchor, and the latest ``window`` in full, each with its
receipts and the consistency proof from the entry listed before it.

* :func:`positions`: the positions P(n, W) a card at anchor position ``n`` with window ``W`` lists.
* :func:`check_history_card_2`: whether a card in Checkpointed Local Log form verifies, or the
  first check of §8.1.2 "Verifying" it fails.

The checkpoint, receipt and proof encodings are the evidence mechanism's (§8.1.2). This module
reads the Checkpointed Local Log form of the interop profile (§6.2.1): checkpoints are COSE_Sign1
``cll-checkpoint`` statements and proofs ``cll-consistency-proof`` octets, both as lowercase hex.
Receipts are read in the form ``vectors/evidence-request/history-card-2.json`` fixes:
``{checkpoint, witness, sig}``, Ed25519 by ``witness`` over UTF-8 of JCS of ``{checkpoint,
witness}``, where ``checkpoint`` is SHA-256 of the checkpoint octets.
"""
from __future__ import annotations

import hashlib
import re
from collections.abc import Collection, Mapping
from typing import Any

from .interop_profile._common import ed25519_verify, is_uint, jcs_or_none
from .interop_profile.cll import _decode_checkpoint, _Malformed, _sig_structure, consistency_failure

__all__ = ["DERIVATION_HISTORY_CARD_2", "MAX_WINDOW", "FINDINGS", "positions", "check_history_card_2"]

DERIVATION_HISTORY_CARD_2 = "history_card/2"
#: The largest window a card may state (§8.1.2).
MAX_WINDOW = 64
#: The findings of :func:`check_history_card_2`, in the order the checks run.
FINDINGS = (
    "card_malformed", "window_out_of_range", "positions_not_increasing_from_zero", "position_missing",
    "position_unexpected", "checkpoint_invalid", "first_checkpoint_has_predecessor", "checkpoint_shrinks",
    "proof_invalid",
    "receipt_invalid", "anchor_mismatch",
)

_ENTRY_MEMBERS = ("position", "checkpoint", "receipts", "consistency_from_previous")
_LOWER_HEX = re.compile(r"(?:[0-9a-f]{2})*")


def positions(n: int, window: int) -> list[int]:
    """P(n, W) (§8.1.2): 0, n - 2^k for every 2^k <= n, and max(0, n - W + 1) through n, in
    ascending order, each once."""
    if not (is_uint(n) and is_uint(window)):
        raise ValueError("n and window are unsigned integers")
    out = {0}
    step = 1
    while step <= n:
        out.add(n - step)
        step <<= 1
    out.update(range(max(0, n - window + 1), n + 1))
    return sorted(out)


def _hex(value: Any) -> bytes | None:
    # fullmatch, not bytes.fromhex alone, which skips whitespace
    if not isinstance(value, str) or not _LOWER_HEX.fullmatch(value):
        return None
    return bytes.fromhex(value)


def _well_formed(card: Any) -> bool:
    if not isinstance(card, Mapping) or not is_uint(card.get("window")) or not isinstance(card.get("history"), list):
        return False
    for entry in card["history"]:
        if not isinstance(entry, Mapping) or not all(m in entry for m in _ENTRY_MEMBERS):
            return False
        proof = entry["consistency_from_previous"]
        if not is_uint(entry["position"]) or _hex(entry["checkpoint"]) is None or \
                not isinstance(entry["receipts"], list) or (proof is not None and _hex(proof) is None):
            return False
    return True


def _receipt_covers(receipt: Any, checkpoint: bytes) -> bool:
    if not isinstance(receipt, Mapping) or set(receipt) != {"checkpoint", "witness", "sig"}:
        return False
    if receipt["checkpoint"] != hashlib.sha256(checkpoint).hexdigest():
        return False
    key, sig = _hex(receipt["witness"]), _hex(receipt["sig"])
    body = jcs_or_none({"checkpoint": receipt["checkpoint"], "witness": receipt["witness"]})
    return key is not None and len(key) == 32 and sig is not None and len(sig) == 64 and body is not None \
        and ed25519_verify(key, sig, body)


def _proof_sizes(octets: bytes) -> tuple[Any, Any] | None:
    from .interop_profile._cbor import CborError, decode
    try:
        value = decode(octets).value
    except CborError:
        return None
    if not isinstance(value, list) or len(value) != 4:
        return None
    return value[0], value[1]


def check_history_card_2(card: Any, anchor: str, log_keys: Collection[str]) -> str | None:
    """Check ``card``, the result map of a ``history_card/2`` in Checkpointed Local Log form,
    against ``anchor`` (SHA-256 of the octets of the checkpoint the response resolved, 64 lowercase
    hex) and the log keys the requester accepts for the stream (64 lowercase hex each).

    Returns None when every check of §8.1.2 "Verifying" passes, else the first finding of
    :data:`FINDINGS`: ``card_malformed`` for a result or entry that is not the maps and types of
    §8.1.2, then checks 1 to 7 in order. Members a profile adds are ignored."""
    if not _well_formed(card):
        return "card_malformed"
    window, history = card["window"], card["history"]
    if not 1 <= window <= MAX_WINDOW:
        return "window_out_of_range"
    listed = [entry["position"] for entry in history]
    if not listed or listed[0] != 0 or any(b <= a for a, b in zip(listed, listed[1:])):
        return "positions_not_increasing_from_zero"
    expected = positions(listed[-1], window)
    if not set(expected) <= set(listed):
        return "position_missing"
    if set(listed) != set(expected):
        return "position_unexpected"

    decoded = []
    for entry in history:
        octets = bytes.fromhex(entry["checkpoint"])
        try:
            cp = _decode_checkpoint(octets)
        except _Malformed:
            return "checkpoint_invalid"
        kid = cp.kid if isinstance(cp.kid, bytes) else b""
        if cp.alg != -8 or cp.crit or len(kid) != 32 or kid.hex() not in log_keys or \
                not ed25519_verify(kid, cp.signature, _sig_structure(cp.protected, cp.payload)):
            return "checkpoint_invalid"
        if not decoded and cp.claims["prev_size"] != 0:
            return "first_checkpoint_has_predecessor"
        if decoded and cp.claims["log_size"] < decoded[-1][1].claims["log_size"]:
            return "checkpoint_shrinks"
        decoded.append((octets, cp))

    for i, entry in enumerate(history):
        proof = entry["consistency_from_previous"]
        if i == 0:
            if proof is not None:
                return "proof_invalid"
            continue
        if proof is None:
            return "proof_invalid"
        octets = bytes.fromhex(proof)
        previous, current = decoded[i - 1][1], decoded[i][1]
        if _proof_sizes(octets) != (previous.claims["log_size"], current.claims["log_size"]) or \
                consistency_failure(previous.commitment, current.commitment, octets) is not None:
            return "proof_invalid"

    for entry, (octets, _) in zip(history, decoded):
        if not all(_receipt_covers(r, octets) for r in entry["receipts"]):
            return "receipt_invalid"

    if hashlib.sha256(decoded[-1][0]).hexdigest() != anchor:
        return "anchor_mismatch"
    return None
