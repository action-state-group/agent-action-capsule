#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate the parent-log-witness/v1 vectors (``vectors/bundle/parent-log-witness/``).

Evidence Bundle -03, "The parent-log-witness/v1 Extension": a Bundle's
checkpoint, or an earlier checkpoint of the same log, is a salted leaf of a
Merkle tree whose root is an entry of a parent log signed by the same key, and
a witness Receipt is over the parent log's checkpoint. Strict ``verify_bundle``
checks every link and reports ``parent_witness`` beside the claims.

Every expected result below is written by hand, per case, from the draft's
rules; nothing here runs a verifier. The script builds the literal Bundles with
the strict vectors' helpers (``generate_bundle_strict_vectors.py``): the same
fixed test keys, CLL logs and COSE checkpoints, and ``cll`` witness receipts.
Every signature is deterministic, so the output is a pure function of this
file and that one. ``README.md`` is hand-written and never rewritten here.

Dependencies: ``agent-action-capsule[bundle,envelope]``, ``scitt-cose`` 0.3.0 or
later and ``cryptography``.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from cll.checkpoint import (
    CheckpointRecord,
    MemoryNodeStore,
    add_leaf,
    checkpoint_to_cose,
    core,
    leaf_hash,
    peaks,
    root_from_peaks,
)

sys.path.insert(0, str(Path(__file__).resolve().parent))
import generate_bundle_strict_vectors as strict  # noqa: E402

from agent_action_capsule.canonical import jcs  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "vectors" / "bundle" / "parent-log-witness"
KIND = "parent-log-witness/v1"
PARENT_LOG_ID = "log:parent-vectors"
DEPTH = 4
POSITION = 5
SALT = hashlib.sha256(b"parent-log-witness salt").hexdigest()
IAT = strict.TIMESTAMP_SECONDS + 60

DIRECTORY = {
    "directory_version": "1",
    "witnesses": [
        {"name": "CLL witness", "endpoint": strict.CLL_URL, "since": "2026-01-01",
         "key_ids": [strict.raw_public(strict.CLL_WITNESS).hex()]},
    ],
}


# -- logs and the tree --------------------------------------------------------


def signed_checkpoint(values: list[bytes], key: Any, log_id: str, *, prior_after: int | None = None) -> dict:
    """A CLL log over ``values`` (leaf values, 32 bytes each) and its signed
    checkpoint: ``{"fields", "cose", "store"}``. With ``prior_after``, the
    checkpoint follows a prior one taken after that many values."""
    store = MemoryNodeStore()
    prev_size, prev_root, prev_peaks = 0, "", None
    for i, value in enumerate(values):
        if prior_after is not None and i == prior_after:
            prev_size = store.size()
            prev_peaks = [store.node(p) for p in peaks(prev_size)]
            prev_root = root_from_peaks(prev_peaks).hex()
        add_leaf(store, leaf_hash(value))
    size = store.size()
    peak_hashes = [store.node(p) for p in peaks(size)]
    signer = strict._StatementSigner(key)
    fields = {
        "log_id": log_id, "mmr_size": size, "root": root_from_peaks(peak_hashes).hex(), "prev_size": prev_size,
        "prev_root": prev_root, "key_id": signer.key_id, "timestamp": strict.TIMESTAMP,
    }
    cp = CheckpointRecord(v=1, kind="mmr_checkpoint", signature="", **fields)
    proof = core.consistency_proof(store, prev_size, size) if prev_size else None
    cose = checkpoint_to_cose(cp, signer, peak_hashes, prev_peak_hashes=prev_peaks, consistency_proof=proof)
    return {"fields": fields, "cose": cose, "store": store}


def tree_leaf(log_id: str, size: int, cose: bytes, salt: str) -> bytes:
    body = {"checkpoint_sha256": hashlib.sha256(cose).hexdigest(), "log_id": log_id, "salt": salt, "size": size}
    return hashlib.sha256(b"\x00" + jcs(body)).digest()


def tree_node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def tree(leaf: bytes, depth: int, position: int) -> tuple[bytes, list[str]]:
    """A full tree of ``2**depth`` leaves with ``leaf`` at ``position`` and
    filler leaves elsewhere: its root and the leaf's path (leaf first)."""
    level = [hashlib.sha256(b"filler %d" % i).digest() for i in range(2**depth)]
    level[position] = leaf
    path, index = [], position
    while len(level) > 1:
        path.append(level[index ^ 1].hex())
        level = [tree_node(level[i], level[i + 1]) for i in range(0, len(level), 2)]
        index >>= 1
    return level[0], path


def consistency_wire(p: Any) -> dict:
    return {
        "v": p.v, "kind": p.kind, "old_size": p.size_a, "new_size": p.size_b, "old_peaks": list(p.old_peaks),
        "witness": [list(w) for w in p.witness], "new_peaks": list(p.new_peaks),
    }


# -- the Bundles ----------------------------------------------------------------

RECORDS = [strict.signed(strict.capsule(f"parent-witness-{i}")) for i in range(1, 4)]
IDS = [bytes.fromhex(r["capsule_id"]) for r in RECORDS]
BASE = strict.bundle_over(RECORDS)
BUNDLE_LOG = signed_checkpoint(IDS, strict.LOG_KEY, strict.LOG_ID)
EARLIER_LOG = signed_checkpoint(IDS[:2], strict.LOG_KEY, strict.LOG_ID)
assert strict.b64u(BUNDLE_LOG["cose"]) == BASE["checkpoint"]["cose"]


def chain(
    *,
    covered: dict = BUNDLE_LOG,
    depth: int = DEPTH,
    position: int = POSITION,
    salt: str = SALT,
    parent_key: Any = strict.LOG_KEY,
    receipts: list[dict] | None = None,
) -> dict:
    """A block covering ``covered`` (the Bundle's checkpoint, or the earlier
    one with a consistency proof), and a parent log whose entry 1 is the tree
    root (entry 0 is another tree's), witnessed by the CLL witness."""
    leaf = tree_leaf(covered["fields"]["log_id"], covered["fields"]["mmr_size"], covered["cose"], salt)
    root, path = tree(leaf, depth, position)
    parent = signed_checkpoint([hashlib.sha256(b"earlier tree").digest(), root], parent_key, PARENT_LOG_ID)
    if receipts is None:
        receipts = [strict.cll_receipt(strict.entry_hash(parent["fields"]), iat=IAT)]
    block: dict[str, Any] = {
        "log_id": covered["fields"]["log_id"], "size": covered["fields"]["mmr_size"], "salt": salt,
        "index": position, "path": path,
    }
    if covered is not BUNDLE_LOG:
        proof = core.consistency_proof(BUNDLE_LOG["store"], covered["fields"]["mmr_size"], BUNDLE_LOG["fields"]["mmr_size"])
        block["earlier"] = {"checkpoint": {"cose": strict.b64u(covered["cose"])}, "consistency_proof": consistency_wire(proof)}
    block["parent"] = {
        "log_id": PARENT_LOG_ID, "checkpoint": {"cose": strict.b64u(parent["cose"])}, "entry_index": 1,
        "inclusion_proof": strict.proof_dict(core.inclusion_proof(parent["store"], 1, parent["fields"]["mmr_size"])),
        "witnesses": receipts,
    }
    return block


def with_block(block: Any, bundle: dict = BASE) -> dict:
    out = copy.deepcopy(bundle)
    out["extensions"] = {KIND: block}
    return out


def edited(block: dict, *steps: tuple[tuple[str, ...], Any]) -> dict:
    """``block`` with each JSON path set to a value (``...`` deletes it)."""
    out = copy.deepcopy(block)
    for path, value in steps:
        target = out
        for name in path[:-1]:
            target = target[name]
        if value is ...:
            del target[path[-1]]
        else:
            target[path[-1]] = value
    return out


def flip_last(text: str) -> str:
    """A base64url COSE text with one bit of its signature flipped."""
    raw = bytearray(strict.base64.urlsafe_b64decode(text + "=" * (-len(text) % 4)))
    raw[-1] ^= 0x01
    return strict.b64u(bytes(raw))


# -- expectations ---------------------------------------------------------------

RECEIPT_PASS = {
    "ts_url": strict.CLL_URL, "binding": "cll", "status": "pass", "grade": "mmr-verified",
    "key_id": strict.raw_public(strict.CLL_WITNESS).hex(), "registration_time": IAT, "registration_time_reason": None,
}


def passed(entries: int, of: int) -> dict:
    return {"status": "pass", "findings": [], "extent": {"entries": entries, "of": of}, "receipts": [RECEIPT_PASS]}


def failed(finding: str) -> dict:
    return {"status": "fail", "findings": [finding], "extent": None, "receipts": []}


def case(case_id: str, description: str, bundle: dict, verdict: str, parent_witness: dict | None, *,
         directory: bool = True, witnesses: dict | None = None) -> dict:
    expect: dict[str, Any] = {"verdict": verdict, "parent_witness": parent_witness}
    if witnesses is not None:
        expect["witnesses"] = witnesses
    if parent_witness is not None:
        expect["extension_status"] = parent_witness["status"]
    return {"id": case_id, "description": description, "options": {"witness_directory": directory},
            "bundle": bundle, "expect": expect}


def build_cases() -> list[dict]:
    whole = chain()
    part = chain(covered=EARLIER_LOG)
    other_log = signed_checkpoint(IDS[:2], strict.OTHER, strict.LOG_ID)
    cases = [
        case("pos-unwitnessed", "No parent-log-witness/v1 block: parent_witness is null.", BASE, "VALID", None),
        case("pos-witnessed-whole", "The Bundle's own checkpoint is the leaf: every entry witnessed.",
             with_block(whole), "VALID", passed(3, 3)),
        case("pos-witnessed-part", "An earlier checkpoint (2 of 3 entries) is the leaf, with a consistency proof.",
             with_block(part), "VALID", passed(2, 3)),
        case("pos-stated-extent-ignored", "Members the draft does not define, a stated extent among them, are ignored.",
             with_block({**part, "extent": "whole", "state": "witnessed", "steps": 3, "steps_witnessed": 3}),
             "VALID", passed(2, 3)),
        case("pos-path-empty", "A path of no hashes: the leaf is the root.",
             with_block(chain(depth=0, position=0)), "VALID", passed(3, 3)),
        case("pos-no-directory", "Every link holds; no witness directory, so the receipt is not checked.",
             with_block(whole), "VALID",
             {"status": "withheld", "findings": [f"witness_unverified:{strict.CLL_URL}"], "extent": None,
              "receipts": [{**RECEIPT_PASS, "status": "withheld", "grade": None, "key_id": None,
                            "registration_time": None, "registration_time_reason": "receipt_not_passed"}]},
             directory=False),
        case("pos-no-receipts", "Every link holds; the parent checkpoint carries no receipt.",
             with_block(chain(receipts=[])), "VALID",
             {"status": "withheld", "findings": ["witness_receipt_absent"], "extent": None, "receipts": []}),
    ]
    unsigned = with_block(whole)
    del unsigned["checkpoint"]["cose"]
    cases.append(case("incomplete-bundle-checkpoint-unsigned",
                      "The Bundle's checkpoint has no cose: the chain has nothing verified to start from.",
                      unsigned, "INCOMPLETE",
                      {"status": "withheld", "findings": ["checkpoint_unverified"], "extent": None, "receipts": []}))

    earlier_cose = ("earlier", "checkpoint", "cose")
    parent_cose = ("parent", "checkpoint", "cose")
    negatives = [
        ("neg-malformed", "The block is an array.", [whole], "parent_witness_malformed"),
        ("neg-earlier-checkpoint-malformed", "earlier.checkpoint.cose is not base64url.",
         edited(part, (earlier_cose, "!!")), "parent_witness_earlier_checkpoint_malformed"),
        ("neg-earlier-not-an-object", "earlier is null.",
         edited(part, (("earlier",), None)), "parent_witness_earlier_checkpoint_malformed"),
        ("neg-earlier-checkpoint-signature-invalid", "One bit of the earlier checkpoint's signature flipped.",
         edited(part, (earlier_cose, flip_last(part["earlier"]["checkpoint"]["cose"]))),
         "parent_witness_earlier_checkpoint_signature_invalid"),
        ("neg-earlier-checkpoint-other-key", "The earlier checkpoint is signed by another key.",
         chain(covered=other_log), "parent_witness_earlier_checkpoint_not_this_log"),
        ("neg-earlier-checkpoint-not-earlier", "earlier carries the Bundle's own checkpoint, which is not below it.",
         edited(part, (earlier_cose, BASE["checkpoint"]["cose"])), "parent_witness_earlier_checkpoint_not_this_log"),
        ("neg-earlier-not-a-prefix", "The consistency proof's first new peak edited.",
         edited(part, (("earlier", "consistency_proof", "new_peaks", 0), "00" * 32)),
         "parent_witness_earlier_checkpoint_not_a_prefix"),
        ("neg-earlier-proof-sizes", "The consistency proof states other sizes.",
         edited(part, (("earlier", "consistency_proof", "old_size"), 1)), "parent_witness_earlier_checkpoint_not_a_prefix"),
        ("neg-leaf-size", "size is the earlier checkpoint's, with no earlier member.",
         edited(whole, (("size",), EARLIER_LOG["fields"]["mmr_size"])), "parent_witness_leaf_does_not_name_this_checkpoint"),
        ("neg-leaf-size-float", "size is a float.",
         edited(whole, (("size",), float(BUNDLE_LOG["fields"]["mmr_size"]))),
         "parent_witness_leaf_does_not_name_this_checkpoint"),
        ("neg-leaf-log-id", "log_id names another log.",
         edited(whole, (("log_id",), "log:other")), "parent_witness_leaf_does_not_name_this_checkpoint"),
        ("neg-path-uppercase", "A path hash in uppercase hexadecimal.",
         edited(whole, (("path", 0), whole["path"][0].upper())), "parent_witness_path_malformed"),
        ("neg-path-too-long", "A path of 33 hashes.",
         edited(whole, (("path",), whole["path"] * 8 + whole["path"][:1])), "parent_witness_path_malformed"),
        ("neg-leaf-salt-empty", "salt is the empty string.",
         edited(whole, (("salt",), "")), "parent_witness_leaf_malformed"),
        ("neg-leaf-index-out-of-range", "index is 2^4 with a path of 4 hashes.",
         edited(whole, (("index",), 16)), "parent_witness_leaf_malformed"),
        ("neg-leaf-index-boolean", "index is true.",
         edited(whole, (("index",), True)), "parent_witness_leaf_malformed"),
        ("neg-parent-checkpoint-malformed", "parent.checkpoint.cose is padded.",
         edited(whole, (parent_cose, whole["parent"]["checkpoint"]["cose"] + "=")),
         "parent_witness_parent_checkpoint_malformed"),
        ("neg-parent-missing", "No parent member.",
         edited(whole, (("parent",), ...)), "parent_witness_parent_checkpoint_malformed"),
        ("neg-parent-checkpoint-signature-invalid", "One bit of the parent checkpoint's signature flipped.",
         edited(whole, (parent_cose, flip_last(whole["parent"]["checkpoint"]["cose"]))),
         "parent_witness_parent_checkpoint_signature_invalid"),
        ("neg-parent-signer-differs", "The parent log is signed by another key.",
         chain(parent_key=strict.OTHER), "parent_witness_parent_signer_differs"),
        ("neg-parent-log-id-mismatch", "parent.log_id is not the parent checkpoint's.",
         edited(whole, (("parent", "log_id"), "log:other")), "parent_witness_parent_log_id_mismatch"),
        ("neg-leaf-salt-other", "Another salt: the root is not the parent log's entry.",
         edited(whole, (("salt",), "00" * 32)), "parent_witness_entry_not_included"),
        ("neg-path-edited", "A path hash edited: the root is not the parent log's entry.",
         edited(whole, (("path", 2), "00" * 32)), "parent_witness_entry_not_included"),
        ("neg-entry-other", "entry_index names the parent log's other entry.",
         edited(whole, (("parent", "entry_index"), 0)), "parent_witness_entry_not_included"),
        ("neg-entry-index-string", "entry_index is a string.",
         edited(whole, (("parent", "entry_index"), "1")), "parent_witness_entry_not_included"),
        ("neg-entry-proof-malformed", "The inclusion proof has no kind.",
         edited(whole, (("parent", "inclusion_proof", "kind"), ...)), "parent_witness_entry_not_included"),
    ]
    for case_id, description, block, finding in negatives:
        cases.append(case(case_id, description, with_block(block), "INVALID", failed(finding)))

    other = strict.cll_receipt(strict.entry_hash(BASE["checkpoint"]), iat=IAT)
    cases.append(case("neg-receipt-other-checkpoint",
                      "Every link holds; the receipt is over the Bundle's checkpoint, not the parent's.",
                      with_block(chain(receipts=[other])), "INVALID",
                      {"status": "fail", "findings": [f"witness_receipt_invalid:{strict.CLL_URL}"], "extent": None,
                       "receipts": [{**RECEIPT_PASS, "status": "fail", "grade": None, "key_id": None,
                                     "registration_time": None, "registration_time_reason": "receipt_not_passed"}]}))
    moved = copy.deepcopy(BASE)
    moved["checkpoint"]["witnesses"] = whole["parent"]["witnesses"]
    cases.append(case("neg-parent-receipt-on-bundle-checkpoint",
                      "The parent checkpoint's receipt carried in checkpoint.witnesses: it is not over that checkpoint.",
                      moved, "INVALID", None,
                      witnesses={"status": "fail", "findings": [f"witness_receipt_invalid:{strict.CLL_URL}"]}))
    return cases


def dump(value: Any) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    out = parser.parse_args().out
    out.mkdir(parents=True, exist_ok=True)
    cases = build_cases()
    vectors = {
        "format_version": "1",
        "description": "Strict verify_bundle on the parent-log-witness/v1 extension (Evidence Bundle -03). "
        "See README.md.",
        "keys": {
            "log_public_key": strict.raw_public(strict.LOG_KEY).hex(),
            "other_public_key": strict.raw_public(strict.OTHER).hex(),
            "cll_witness_public_key": strict.raw_public(strict.CLL_WITNESS).hex(),
        },
        "witness_directory": DIRECTORY,
        "cases": cases,
    }
    files = {"vectors.json": dump(vectors)}
    files["manifest.json"] = dump({
        "format_version": "1",
        "files": {name: {"sha256": hashlib.sha256(data).hexdigest()} for name, data in files.items()},
        "case_count": len(cases),
    })
    for name, data in files.items():
        (out / name).write_bytes(data)
    names = sorted(p.name for p in out.iterdir() if p.is_file() and p.name != "SHA256SUMS")
    sums = "".join(f"{hashlib.sha256((out / n).read_bytes()).hexdigest()}  {n}\n" for n in names)
    (out / "SHA256SUMS").write_text(sums)


if __name__ == "__main__":
    main()
