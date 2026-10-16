#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate the CLL material encoding vectors.

Profile ``evidence-interop/0`` §6.2.1 carries a Checkpointed Local Log's proofs
as deterministic CBOR:

- ``cll-inclusion-proof``: ``[index, inclusion-path]``, where ``index`` is the
  zero-based MMR node index of the leaf and the path runs from the leaf to its
  peak;
- ``cll-consistency-proof``: ``[tree-size-1, tree-size-2, consistency-paths,
  right-peaks]``, where ``consistency-paths`` holds each old peak's path into
  the new MMR and ``right-peaks`` the new peaks no old peak reaches (MMR -02
  §7.1).

Each case gives a responder's inputs (the leaf and its path, or the two sizes,
both peak lists and the paths) and the octets an encoder must produce, so Go,
Rust and Python encoders can be checked byte for byte against one corpus.

The log is built here from MMR -02 (§5.2, §7.1, §8.2.1, §9). Leaves are the
profile's leaf value SHA-256(0x00 || E) (§6.2.1). The first two cases are the
§10.1 worked example's proofs: their SHA-256 values are the ones the profile
states, which anchors the MMR code below.

Output: ``vectors/cll-material/`` (or ``--out DIR``). Deterministic: no clock,
no randomness, no keys. ``README.md`` is hand-written; when present in the
output directory it is included in ``SHA256SUMS`` but never rewritten.
Dependencies: the standard library only; it runs no repository implementation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "vectors" / "cll-material"
SPEC = "spec/interop-profile-v0.md"
SECTION = "§6.2.1"
# The §10.1 proofs' SHA-256 values, as the profile states them.
WORKED_INCLUSION = "013ac5a3bdff9cf62a3ea2816b3cd197151930f6dd49d67d9286f12c3c47527a"
WORKED_CONSISTENCY = "06550cca75319242ea40e7f3fd9ff0b8e5e3bfa8a06122f678578a57cb4bdc71"
# The general log: leaf counts 1 to LEAVES, every leaf at every count, every
# pair of counts.
LEAVES = 13


def sha(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --- Deterministic CBOR for unsigned integers, byte strings and arrays ---------------------


def _head(major: int, arg: int) -> bytes:
    if arg < 24:
        return bytes([major << 5 | arg])
    for extra, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if arg < 1 << (8 * width):
            return bytes([major << 5 | extra]) + arg.to_bytes(width, "big")
    raise ValueError(arg)


def cbor(value: Any) -> bytes:
    if isinstance(value, int):
        return _head(0, value)
    if isinstance(value, bytes):
        return _head(2, len(value)) + value
    if isinstance(value, list):
        return _head(4, len(value)) + b"".join(cbor(v) for v in value)
    raise TypeError(type(value))


# --- MMR -02 ------------------------------------------------------------------------------


def all_ones(pos: int) -> bool:
    return pos != 0 and pos & (pos + 1) == 0


def index_height(i: int) -> int:
    pos = i + 1
    while not all_ones(pos):
        pos = pos - (1 << (pos.bit_length() - 1)) + 1
    return pos.bit_length() - 1


def hash_pospair64(pos: int, a: bytes, b: bytes) -> bytes:
    return sha(pos.to_bytes(8, "big") + a + b)


def mmr_peaks(i: int) -> list[int]:
    out, peak, size = [], 0, i + 1
    while size:
        highest = (1 << ((size + 1).bit_length() - 1)) - 1
        peak += highest
        out.append(peak - 1)
        size -= highest
    return out


def inclusion_path(i: int, last: int) -> list[int]:
    """Sibling indices from node ``i`` to its peak in the MMR whose last node is ``last``."""
    path, g = [], index_height(i)
    while True:
        off = 2 << g
        if index_height(i + 1) > g:
            sib = i - off + 1
            i += 1
        else:
            sib = i + off - 1
            i += off
        if sib > last:
            return path
        path.append(sib)
        g += 1


def included_root(i: int, node: bytes, proof: list[bytes]) -> bytes:
    root, g = node, index_height(i)
    for sib in proof:
        if index_height(i + 1) > g:
            i += 1
            root = hash_pospair64(i + 1, sib, root)
        else:
            i += 2 << g
            root = hash_pospair64(i + 1, root, sib)
        g += 1
    return root


class Log:
    """An MMR over ``entries``, keeping each leaf count's node count."""

    def __init__(self, entries: list[bytes]) -> None:
        self.entries = entries
        self.db: list[bytes] = []
        self.leaf_index: list[int] = []
        self.sizes: dict[int, int] = {}
        for n, entry in enumerate(entries):
            self.leaf_index.append(len(self.db))
            self.db.append(sha(b"\x00" + entry))
            g = 0
            while index_height(len(self.db)) > g:
                i = len(self.db)
                self.db.append(hash_pospair64(i + 1, self.db[i - (2 << g)], self.db[i - 1]))
                g += 1
            self.sizes[n + 1] = len(self.db)

    def peaks(self, size: int) -> list[bytes]:
        return [self.db[p] for p in mmr_peaks(size - 1)]

    def inclusion(self, leaf: int, size: int) -> tuple[list[bytes], bytes]:
        i = self.leaf_index[leaf]
        path = [self.db[j] for j in inclusion_path(i, size - 1)]
        assert included_root(i, self.db[i], path) in self.peaks(size)
        return path, cbor([i, path])

    def consistency(self, old: int, new: int) -> tuple[list[list[bytes]], bytes]:
        paths, roots = [], []
        for p in mmr_peaks(old - 1):
            path = [self.db[j] for j in inclusion_path(p, new - 1)]
            paths.append(path)
            root = included_root(p, self.db[p], path)
            if not roots or roots[-1] != root:
                roots.append(root)
        new_peaks = self.peaks(new)
        assert new_peaks[:len(roots)] == roots
        return paths, cbor([old, new, paths, new_peaks[len(roots):]])


def _hexes(nodes: list[bytes]) -> list[str]:
    return [n.hex() for n in nodes]


def inclusion_case(case_id: str, log: Log, leaf: int, leaves: int) -> dict:
    size = log.sizes[leaves]
    path, octets = log.inclusion(leaf, size)
    return {
        "id": case_id,
        "kind": "cll-inclusion-proof",
        "inputs": {"leaf": leaf, "path": _hexes(path)},
        "context": {"leaf_count": leaves, "tree_size": size, "entry": log.entries[leaf].hex(),
                    "peaks": _hexes(log.peaks(size))},
        "expected": {"octets_hex": octets.hex(), "sha256": sha256_hex(octets)},
    }


def consistency_case(case_id: str, log: Log, old_leaves: int, new_leaves: int) -> dict:
    old, new = log.sizes[old_leaves], log.sizes[new_leaves]
    paths, octets = log.consistency(old, new)
    return {
        "id": case_id,
        "kind": "cll-consistency-proof",
        "inputs": {"old_size": old, "new_size": new, "old_peaks": _hexes(log.peaks(old)),
                   "paths": [_hexes(p) for p in paths], "new_peaks": _hexes(log.peaks(new))},
        "context": {"old_leaf_count": old_leaves, "new_leaf_count": new_leaves},
        "expected": {"octets_hex": octets.hex(), "sha256": sha256_hex(octets)},
    }


def _jcs_artifact() -> bytes:
    # The §10.1 artifact, {"example":"evidence record","seq":1} in RFC 8785 form.
    return json.dumps({"example": "evidence record", "seq": 1}, separators=(",", ":"), sort_keys=True).encode()


def cases() -> list[dict]:
    worked_entries = [sha(f"evidence-interop/0 worked example: log entry {k}".encode()) for k in range(7)]
    worked_entries[2] = sha(_jcs_artifact())
    worked = Log(worked_entries)
    out = [inclusion_case("worked-example-inclusion", worked, 2, 7),
           consistency_case("worked-example-consistency", worked, 3, 7)]
    assert out[0]["expected"]["sha256"] == WORKED_INCLUSION, "§10.1 inclusion proof drifted"
    assert out[1]["expected"]["sha256"] == WORKED_CONSISTENCY, "§10.1 consistency proof drifted"
    # entry k is SHA-256 of the single octet k.
    log = Log([sha(bytes([k])) for k in range(LEAVES)])
    for leaves in range(1, LEAVES + 1):
        for leaf in range(leaves):
            out.append(inclusion_case(f"inclusion-n{leaves}-leaf{leaf}", log, leaf, leaves))
    for old in range(1, LEAVES + 1):
        for new in range(old, LEAVES + 1):
            out.append(consistency_case(f"consistency-n{old}-n{new}", log, old, new))
    return out


def _dump(value: Any) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def build() -> dict[str, bytes]:
    case_list = cases()
    files = {
        "cases.json": _dump({
            "spec": SPEC,
            "section": SECTION,
            "provenance": "spec-derived",
            "rules": {
                "cll-inclusion-proof": "deterministic CBOR of [MMR node index of the leaf, [path nodes]]; "
                                       "the node index of zero-based leaf n is 2n - popcount(n)",
                "cll-consistency-proof": "deterministic CBOR of [tree-size-1, tree-size-2, [one path per old "
                                         "peak], right-peaks]; right-peaks are the new peaks after the roots "
                                         "the old peaks' paths reach, adjacent repeats merged (MMR -02 §7.1)",
                "nodes": "32-octet byte strings, given here as lowercase hex",
                "leaf": "SHA-256(0x00 || E) (§6.2.1)",
            },
            "count": len(case_list),
            "cases": case_list,
        }),
    }
    files["manifest.json"] = _dump({
        "spec": SPEC,
        "provenance": "spec-derived",
        "generator": "python/scripts/generate_cll_material_vectors.py",
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
