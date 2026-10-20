#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate ``vectors/cross-language/bundle-producer-log.json``.

The fixture is the input of the Evidence Bundle producer step of
``scripts/cross-language-interlock.sh``: one checkpointed log that every
implementation loads into an in-memory CLL backend and record store, then
builds the same Bundles from with its own ``proof_source_from_cll`` and
``build_evidence_bundle``.

The log holds seven signed records, each following the one before through
``chain.parent_capsule_id``; the fourth and the last also cite an earlier
record through ``references[]``, and the first commits an agent input digest.
Every leaf is a record, and one signed COSE checkpoint covers them all.
``builds`` names the three Bundles each producer builds around ``root``: the
whole log, a suffix whose closure stays inside its interval, and a
producer-selected Bundle with no range proof.

Keys are fixed test seeds and Ed25519 signatures are deterministic, so the
output is a pure function of this file. Dependencies:
``agent-action-capsule[bundle,envelope]`` and ``cryptography``.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from cll.checkpoint import (
    CheckpointRecord,
    MemoryNodeStore,
    add_leaf,
    checkpoint_to_cose,
    leaf_hash,
    peaks,
    root_from_peaks,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scitt_cose.cose_sign1 import sign_sign1
from scitt_cose.statement import build_signed_statement

from agent_action_capsule.canonical import compute_capsule_id, jcs, json_digest

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "vectors" / "cross-language" / "bundle-producer-log.json"

PRODUCER = Ed25519PrivateKey.from_private_bytes(bytes([0x0B]) * 32)
LOG_KEY = Ed25519PrivateKey.from_private_bytes(bytes([0x2C]) * 32)
LOG_ID = "log:cross-language-producer"
TIMESTAMP = "2026-10-19T00:00:00Z"
CAPSULE_ID_MEDIA_TYPE = "application/agent-action-capsule-id"


def _raw(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _pem(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def capsule(action_id: str, *, parent: str | None = None, cites: tuple[str, ...] = (), agent_input: Any = None) -> dict:
    record: dict = {
        "spec_version": "draft-mih-scitt-agent-action-capsule-04",
        "format_version": "4",
        "canonicalization_id": "jcs",
        "action_id": action_id,
        "action_type": "fyi",
        "operator": "ACME-CO",
        "developer": "agent@v1",
        "timestamp": TIMESTAMP,
        "assurance": {"effect_mode": "not_applicable", "attestation_mode": "self_attested", "ledger_mode": "standalone"},
        "disposition": {"verdict_class": "not_applicable", "decision": "report", "approver": "policy", "human_disposed": False},
    }
    if parent:
        record["chain"] = {"parent_capsule_id": parent, "relation": "follows"}
    if cites:
        record["references"] = [{"type": "agent-action-capsule", "digest_alg": "SHA-256", "digest": c} for c in cites]
    if agent_input is not None:
        record["model_attestation"] = {"compute_attestation": {"agent_input_digest": json_digest(agent_input)}}
    record["capsule_id"] = compute_capsule_id(record)
    return record


def envelope(capsule_id: str) -> bytes:
    """The record's Producer Envelope: COSE_Sign1 over the Capsule ID bytes."""
    return bytes.fromhex(
        sign_sign1(
            bytes.fromhex(capsule_id),
            alg="EdDSA",
            private_key_pem=_pem(PRODUCER),
            protected={3: CAPSULE_ID_MEDIA_TYPE, 4: _raw(PRODUCER)},
            unprotected={},
        ).hex()
    )


class _Signer:
    """``checkpoint_to_cose``'s signer: a Signed Statement under the log key."""

    key_id = _raw(LOG_KEY).hex()

    def sign_cose_statement(self, payload, *, content_type, issuer, subject, extra_cwt_claims=None):
        return build_signed_statement(
            payload, alg="EdDSA", private_key_pem=_pem(LOG_KEY), issuer=issuer, subject=subject,
            content_type=content_type, extra_cwt_claims=extra_cwt_claims, kid=_raw(LOG_KEY),
        )


def records() -> list[dict]:
    chain: list[dict] = [capsule("step-1", agent_input={"step": 1})]
    for n in range(2, 8):
        cites = (chain[0]["capsule_id"],) if n == 4 else (chain[4]["capsule_id"],) if n == 7 else ()
        chain.append(capsule(f"step-{n}", parent=chain[-1]["capsule_id"], cites=cites))
    return chain


def fixture() -> dict:
    chain = records()
    ids = [r["capsule_id"] for r in chain]
    nodes = MemoryNodeStore()
    for cid in ids:
        add_leaf(nodes, leaf_hash(bytes.fromhex(cid)))
    size = nodes.size()
    peak_hashes = [nodes.node(p) for p in peaks(size)]
    cp = CheckpointRecord(
        v=1, kind="mmr_checkpoint", log_id=LOG_ID, mmr_size=size, root=root_from_peaks(peak_hashes).hex(),
        prev_size=0, prev_root="", key_id=_Signer.key_id, timestamp=TIMESTAMP, signature="",
    )
    cose = checkpoint_to_cose(cp, _Signer(), peak_hashes)
    return {
        "description": (
            "One checkpointed log of seven signed records, input of the Evidence Bundle producer step "
            "of scripts/cross-language-interlock.sh. Byte strings are lowercase hex. "
            "python/scripts/generate_bundle_producer_fixture.py regenerates it."
        ),
        "root": ids[-1],
        # The root cites the fifth record, so a suffix from seq 5 with closure
        # depth 1 carries no record below its interval.
        "builds": {
            "whole-log": {"interval_from": 1, "closure_depth": 2},
            "suffix": {"interval_from": 5, "closure_depth": 1},
            "producer-selected": {"interval_from": None, "closure_depth": 2},
        },
        "log": {
            "entries": ids,
            "state": {
                "size": size,
                "nodes": [nodes.node(i).hex() for i in range(size)],
                "indexed_seq": len(ids),
                "checkpoint": {
                    "cose": cose.hex(),
                    "size": size,
                    "indexed_seq": len(ids),
                    "peaks": [p.hex() for p in peak_hashes],
                },
            },
        },
        "records": {
            r["capsule_id"]: {"capsule": jcs(r).hex(), "producer_envelope": envelope(r["capsule_id"]).hex()}
            for r in chain
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    args.out.write_text(json.dumps(fixture(), indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
