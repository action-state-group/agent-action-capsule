# SPDX-License-Identifier: BSD-3-Clause
"""Generate the spec_version -05 cases of the cross-language capsule corpus.

The -05 wire bump ("Identity and parties": producers emit the newest
published spec_version; verifiers accept every published value) leaves the
existing -04 cases in ../../vectors/capsule/ frozen: they are the evidence
that -04 Capsules still verify. This script adds the -05 cases next to them.
Each is sealed with the reference compute_capsule_id and its expected.json is
derived from the reference verify(), then frozen ("reference-derived").

The first case is the -04 case pos-v4-jcs-chain-committed with only
spec_version changed, so the pair shows spec_version participates in
capsule_id while selecting no verification algorithm. The rest exercise the
registrations -05 adds (chain.relation follows; citation_purpose
counterparty_half and counterparty_inclusion; effect.type
inference_completion; effect_attestation host_served_observed), so every
implementation that reads this corpus must carry the -05 registry values to
match the expected findings.

The manifest (vectors.json; its "spec_versions" lists every spec_version the
corpus carries) and the SHA256SUMS in vectors/capsule/ and vectors/ are
updated in place; existing entries are kept.

Run:  cd python && PYTHONPATH=. python3 scripts/generate_v05_vectors.py
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from agent_action_capsule import DEFAULT_SPEC_VERSION, compute_capsule_id, verify

VECTORS = Path(__file__).resolve().parents[2] / "vectors"
OUT = VECTORS / "capsule"
SPEC_V05 = "draft-mih-scitt-agent-action-capsule-05"
PROVENANCE = "reference-derived"
HEX_1 = "1" * 64
HEX_2 = "2" * 64
HEX_3 = "3" * 64
HEX_4 = "4" * 64
PARENT = "a" * 64

assert DEFAULT_SPEC_VERSION == SPEC_V05, "the reference producer must emit -05"


def seal(capsule: dict) -> dict:
    body = {k: v for k, v in capsule.items() if k != "capsule_id"}
    body["capsule_id"] = compute_capsule_id(body)
    return body


def ident(action_id: str) -> dict:
    return {
        "spec_version": SPEC_V05,
        "format_version": "4",
        "canonicalization_id": "jcs",
        "action_id": action_id,
        "action_type": "decide",
        "operator": "ACME-CO",
        "developer": "agent@v1",
        "timestamp": "2026-09-26T00:00:00Z",
    }


def policy_executed() -> dict:
    return {"decision": "accept", "approver": "policy", "human_disposed": False, "verdict_class": "executed"}


def assurance(effect_mode: str, ledger_mode: str) -> dict:
    return {"attestation_mode": "self_attested", "effect_mode": effect_mode, "ledger_mode": ledger_mode}


def reference(purpose: str, digest: str) -> dict:
    return {"type": "agent-action-capsule", "digest_alg": "SHA-256", "digest": digest, "citation_purpose": purpose}


def build_cases() -> list[dict]:
    frozen_v4 = json.loads((OUT / "pos-v4-jcs-chain-committed" / "input.json").read_text(encoding="utf-8"))
    return [
        {
            "name": "pos-v05-spec-version-chain-committed",
            "description": (
                "pos-v4-jcs-chain-committed with only spec_version changed to -05: spec_version "
                "participates in capsule_id but selects no verification algorithm, so both verify."
            ),
            "input": seal({**frozen_v4, "spec_version": SPEC_V05}),
        },
        {
            "name": "pos-v05-chain-follows",
            "description": "-05 chain.relation 'follows' (the bare next-link) is a registered value.",
            "input": seal({
                **ident("v05-follows"),
                "assurance": assurance("not_applicable", "chained"),
                "disposition": policy_executed(),
                "chain": {"parent_capsule_id": PARENT, "relation": "follows"},
            }),
        },
        {
            "name": "pos-v05-effect-inference-completion-host-served",
            "description": (
                "-05 effect.type 'inference_completion' with effect_attestation "
                "'host_served_observed' (registered, runtime_claimed grade) and a response_digest."
            ),
            "input": seal({
                **ident("v05-inference"),
                "effect": {
                    "status": "confirmed",
                    "type": "inference_completion",
                    "request_digest": HEX_1,
                    "response_digest": HEX_2,
                    "effect_attestation": "host_served_observed",
                    "irreversibility_class": "two_way",
                },
                "assurance": assurance("confirmed", "standalone"),
                "disposition": policy_executed(),
            }),
        },
        {
            "name": "pos-v05-reference-counterparty-half",
            "description": (
                "-05 citation_purpose 'counterparty_half': a record holding a counterparty's half "
                "chains to its own head with 'follows' and cites the half by digest."
            ),
            "input": seal({
                **ident("v05-counterparty-half"),
                "action_type": "fyi",
                "assurance": assurance("not_applicable", "chained"),
                "chain": {"parent_capsule_id": PARENT, "relation": "follows"},
                "references": [reference("counterparty_half", HEX_3)],
            }),
        },
        {
            "name": "pos-v05-reference-counterparty-inclusion",
            "description": (
                "-05 citation_purpose 'counterparty_inclusion': a later record cites the "
                "counterparty's inclusion proof for a half already held, chaining via 'follows'."
            ),
            "input": seal({
                **ident("v05-counterparty-inclusion"),
                "action_type": "fyi",
                "assurance": assurance("not_applicable", "chained"),
                "chain": {"parent_capsule_id": PARENT, "relation": "follows"},
                "references": [reference("counterparty_inclusion", HEX_4)],
            }),
        },
    ]


def expected_for(description: str, capsule: dict) -> dict:
    res = verify(capsule)
    return {
        "description": description,
        "kind": "positive" if res.ok else "negative",
        "provenance": PROVENANCE,
        "ok": res.ok,
        "derived": res.assurance,
        "capsule_id_recomputed": res.capsule_id,
        "findings": [
            {"check": f.check, "severity": f.severity, "code": f.code, "detail": f.detail} for f in res.findings
        ],
    }


def write_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha256_lines(root: Path, files: list[Path]) -> list[str]:
    rel = sorted((p.relative_to(root).as_posix() for p in files), key=lambda s: s.encode("utf-8"))
    return [f"{hashlib.sha256((root / r).read_bytes()).hexdigest()}  {r}" for r in rel]


def update_sums(sums: Path, root: Path, paths: list[Path]) -> None:
    """Rewrite entries for ``paths`` (relative to ``root``), keeping all others."""
    entries = {}
    for line in sums.read_text(encoding="utf-8").splitlines():
        digest, name = line.split("  ", 1)
        entries[name] = digest
    for line in sha256_lines(root, paths):
        digest, name = line.split("  ", 1)
        entries[name] = digest
    ordered = sorted(entries, key=lambda s: s.encode("utf-8"))
    sums.write_text("".join(f"{entries[n]}  {n}\n" for n in ordered), encoding="utf-8")


def main() -> None:
    manifest_path = OUT / "vectors.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    by_name = {case["name"]: i for i, case in enumerate(manifest["cases"])}
    touched: list[Path] = []
    for case in build_cases():
        expected = expected_for(case["description"], case["input"])
        if not expected["ok"]:
            raise SystemExit(f"{case['name']}: reference verify() rejected a -05 positive case: {expected['findings']}")
        case_dir = OUT / case["name"]
        case_dir.mkdir(exist_ok=True)
        write_json(case_dir / "input.json", case["input"])
        write_json(case_dir / "expected.json", expected)
        touched += [case_dir / "input.json", case_dir / "expected.json"]
        entry = {"name": case["name"], "kind": expected["kind"], "description": case["description"],
                 "provenance": PROVENANCE}
        if case["name"] in by_name:
            manifest["cases"][by_name[case["name"]]] = entry
        else:
            manifest["cases"].append(entry)
    manifest["count"] = len(manifest["cases"])
    spec_versions = manifest.get("spec_versions", [manifest.get("spec")])
    manifest["spec_versions"] = sorted({*filter(None, spec_versions), SPEC_V05})
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    touched.append(manifest_path)

    update_sums(OUT / "SHA256SUMS", OUT, touched)
    update_sums(VECTORS / "SHA256SUMS", VECTORS, touched)
    print(f"wrote {len(build_cases())} -05 vectors to {OUT}")


if __name__ == "__main__":
    main()
