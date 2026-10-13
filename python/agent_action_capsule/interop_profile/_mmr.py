# SPDX-License-Identifier: BSD-3-Clause
"""The Merkle Mountain Range functions the profile's CLL material uses (profile §6.2.1).

Written from the algorithms of the pinned MMR revision (draft -02): ``index_height`` (§9),
``included_root`` (§5.2), ``peaks`` (§7.1.1) and ``consistent_roots`` (§7.1). Node positions are
one-based in the hash (``pos = index + 1``), and an interior node is
``SHA-256(pos as 8 big-endian octets || left || right)`` (§8.2.1).

The misprinted ``all_ones`` primitive of MMR Appendix B.4 is read as the profile reads it (P-31):
``pos`` has every bit set below its most significant bit, that is ``pos & (pos + 1) == 0``.
"""
from __future__ import annotations

import hashlib

__all__ = ["index_height", "included_root", "peaks", "consistent_roots", "leaf_value"]


def _all_ones(pos: int) -> bool:
    return pos != 0 and pos & (pos + 1) == 0


def index_height(i: int) -> int:
    """The height of the node at zero-based MMR index ``i``; leaves have height 0."""
    pos = i + 1
    while not _all_ones(pos):
        pos = pos - (1 << (pos.bit_length() - 1)) + 1
    return pos.bit_length() - 1


def _hash_pospair(pos: int, left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(pos.to_bytes(8, "big") + left + right).digest()


def included_root(i: int, node: bytes, proof: list[bytes]) -> bytes:
    """The root reached from ``node`` at index ``i`` by the inclusion path ``proof``."""
    root, g = node, index_height(i)
    for sibling in proof:
        if index_height(i + 1) > g:
            i += 1
            root = _hash_pospair(i + 1, sibling, root)
        else:
            i += 2 << g
            root = _hash_pospair(i + 1, root, sibling)
        g += 1
    return root


def peaks(i: int) -> list[int]:
    """The indices of the peaks of the MMR whose last node is at index ``i``."""
    out: list[int] = []
    peak, size = 0, i + 1
    while size:
        highest = (1 << ((size + 1).bit_length() - 1)) - 1
        peak += highest
        out.append(peak - 1)
        size -= highest
    return out


def consistent_roots(ifrom: int, accumulator: list[bytes], proofs: list[list[bytes]]) -> list[bytes]:
    """The roots each old peak reaches by its consistency path, with adjacent repeats merged."""
    roots: list[bytes] = []
    for index, peak, path in zip(peaks(ifrom), accumulator, proofs):
        root = included_root(index, peak, path)
        if not roots or roots[-1] != root:
            roots.append(root)
    return roots


def leaf_value(entry: bytes) -> bytes:
    """The profile's leaf for a logged entry: SHA-256(0x00 || E) (profile §6.2.1, P-31)."""
    return hashlib.sha256(b"\x00" + entry).digest()
