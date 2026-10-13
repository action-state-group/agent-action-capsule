# SPDX-License-Identifier: BSD-3-Clause
"""Generate vectors/registry-conformance/: one positive and one negative per
registry-governed Capsule field, plus cross-axis and legacy-alias negatives.

Every case is a sealed Capsule (capsule_id recomputes). Each negative differs
from its positive twin in exactly one registry-governed value, so the pair
shows that value, and nothing else, decides conformance. expected.json records
the classification from agent_action_capsule.registry_conformance and, beside
it, what verify() says about the same bytes: for every negative except the
closed provenance_mode enum, verify() accepts the record. That is the gap the
set exists to show: a wrong token is silent at verify by design (the
never-reject invariant), so only a producer-side conformance check sees it.

Run:  cd python && PYTHONPATH=. python3 scripts/generate_registry_conformance_vectors.py
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

from agent_action_capsule import compute_capsule_id, verify
from agent_action_capsule.registry_conformance import check_capsule, is_conformant

VECTORS = Path(__file__).resolve().parents[2] / "vectors"
OUT = VECTORS / "registry-conformance"
SPEC_V05 = "draft-mih-scitt-agent-action-capsule-05"
PROVENANCE = "reference-derived"


def seal(capsule: dict) -> dict:
    body = {k: v for k, v in capsule.items() if k != "capsule_id"}
    body["capsule_id"] = compute_capsule_id(body)
    return body


def base() -> dict:
    """A Capsule carrying every registry-governed field, each registered."""
    return {
        "spec_version": SPEC_V05,
        "format_version": "4",
        "canonicalization_id": "jcs",
        "action_id": "registry-conformance",
        "action_type": "decide",
        "operator": "ACME-CO",
        "developer": "agent@v1",
        "timestamp": "2026-10-13T00:00:00Z",
        "domain": "action",
        "provenance": "gate",
        "provenance_mode": {"mode": "contemporaneous"},
        "disposition": {"decision": "accept", "approver": "policy", "human_disposed": False,
                        "verdict_class": "executed"},
        "effect": {"status": "confirmed", "type": "write_order", "request_digest": "1" * 64, "response_digest": "2" * 64,
                   "effect_attestation": "gate_executed", "irreversibility_class": "two_way"},
        "assurance": {"attestation_mode": "self_attested", "effect_mode": "confirmed",
                      "ledger_mode": "chained"},
        "chain": {"parent_capsule_id": "a" * 64, "relation": "follows"},
        "references": [{"type": "agent-action-capsule", "digest_alg": "SHA-256", "digest": "3" * 64,
                        "citation_purpose": "acted_on"}],
    }


def with_value(path: str, value) -> dict:
    capsule = base()
    node = capsule
    keys = path.split(".")
    for key in keys[:-1]:
        node = node[0][key] if isinstance(node, list) else node[key]
    if isinstance(node, list):
        node = node[0]
    node[keys[-1]] = value
    return capsule


# (case name, field path to change, registered value, unregistered value). One
# pair per axis; the positive uses a registered value other than base()'s. A
# registered value of None means the positive twin is pos-all-fields-registered:
# every other verdict_class value conflicts with base()'s confirmed effect
# (§5.4.2), and provenance_mode's other value, backfilled, needs four more
# members.
PAIRS = [
    ("verdict-class", "disposition.verdict_class", None, "approved"),
    ("disposition-decision", "disposition.decision", "reject", "approve"),
    ("effect-type", "effect.type", "send_payment", "send_email"),
    ("irreversibility-class", "effect.irreversibility_class", "one_way_terminal", "reversible"),
    ("effect-attestation", "effect.effect_attestation", "runtime_claimed", "sensor_confirmed"),
    ("chain-relation", "chain.relation", "supersedes", "replaces"),
    ("citation-purpose", "references.citation_purpose", "responds_to", "mentions"),
    ("domain", "domain", "memory", "tool_call"),
    ("provenance", "provenance", "runtime", "sidecar"),
    ("provenance-mode", "provenance_mode.mode", None, "imported"),
]

# Negatives that are not plain unregistered values.
EXTRA = [
    ("neg-disposition-decision-cross-axis-verdict-class",
     "disposition.decision carries hitl_dispatched, a registered verdict_class value that is not a "
     "registered disposition.decision value. The registered pairing is decision needs_input with "
     "verdict_class hitl_dispatched.",
     "disposition.decision", "hitl_dispatched"),
    ("neg-chain-relation-cross-axis-link-type",
     "chain.relation carries cites, a registered Evidence Layer link type (§18) that is not a "
     "registered chain.relation value.",
     "chain.relation", "cites"),
    ("neg-citation-purpose-cross-axis-link-type",
     "references[].citation_purpose carries cites, a registered Evidence Layer link type (§18) that "
     "is not a registered citation_purpose value.",
     "references.citation_purpose", "cites"),
    ("neg-chain-relation-legacy-resolves",
     "chain.relation carries resolves, a read-only legacy alias (§6): producers MUST emit "
     "supersedes, the registered value it maps to.",
     "chain.relation", "resolves"),
    ("neg-chain-relation-legacy-sequence",
     "chain.relation carries sequence, a deployed legacy alias (§6): producers emit follows.",
     "chain.relation", "sequence"),
    ("neg-verdict-class-not-a-string",
     "disposition.verdict_class carries a list holding a registered value: a present value that "
     "is not a string is unregistered, whatever it contains.",
     "disposition.verdict_class", ["executed"]),
]


def build_cases() -> list[dict]:
    cases = [{
        "name": "pos-all-fields-registered",
        "description": "Every registry-governed Capsule field present, each with a registered value.",
        "input": seal(base()),
    }]
    for axis, path, good, bad in PAIRS:
        if good is not None:
            cases.append({"name": f"pos-{axis}-registered",
                          "description": f"{path.replace('references.', 'references[].')} = {good!r}, registered.",
                          "input": seal(with_value(path, good))})
        cases.append({"name": f"neg-{axis}-unregistered",
                      "description": f"{path.replace('references.', 'references[].')} = {bad!r}, "
                                     f"registered on no axis.",
                      "input": seal(with_value(path, bad))})
    cases.append({"name": "pos-domain-private-extension",
                  "description": "domain = 'x-acme-experiment': an x- value is private (§8), never "
                                 "registered, and not a conformance failure.",
                  "input": seal(with_value("domain", "x-acme-experiment"))})
    for name, description, path, value in EXTRA:
        cases.append({"name": name, "description": description, "input": seal(with_value(path, value))})
    return cases


def expected_for(case: dict) -> dict:
    findings = check_capsule(case["input"])
    result = verify(copy.deepcopy(case["input"]))
    conformant = is_conformant(findings)
    return {
        "description": case["description"],
        "kind": "positive" if conformant else "negative",
        "provenance": PROVENANCE,
        "conformant": conformant,
        "findings": [f.as_dict() for f in findings],
        "verify_ok": result.ok,
    }


def write_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha256_lines(root: Path, files: list[Path]) -> list[str]:
    rel = sorted((p.relative_to(root).as_posix() for p in files), key=lambda s: s.encode("utf-8"))
    return [f"{hashlib.sha256((root / r).read_bytes()).hexdigest()}  {r}" for r in rel]


def update_sums(sums: Path, root: Path, paths: list[Path]) -> None:
    """Rewrite entries for ``paths`` (relative to ``root``), keeping all others."""
    entries = {}
    if sums.exists():
        for line in sums.read_text(encoding="utf-8").splitlines():
            digest, name = line.split("  ", 1)
            entries[name] = digest
    for line in sha256_lines(root, paths):
        digest, name = line.split("  ", 1)
        entries[name] = digest
    ordered = sorted(entries, key=lambda s: s.encode("utf-8"))
    sums.write_text("".join(f"{entries[n]}  {n}\n" for n in ordered), encoding="utf-8")


def main() -> None:
    OUT.mkdir(exist_ok=True)
    touched: list[Path] = [OUT / "README.md"]
    manifest = {"spec": SPEC_V05, "registry": "spec/REGISTRY.md", "cases": []}
    for case in build_cases():
        expected = expected_for(case)
        if case["name"].startswith("pos-") != expected["conformant"]:
            raise SystemExit(f"{case['name']}: classified conformant={expected['conformant']}")
        case_dir = OUT / case["name"]
        case_dir.mkdir(exist_ok=True)
        write_json(case_dir / "input.json", case["input"])
        write_json(case_dir / "expected.json", expected)
        touched += [case_dir / "input.json", case_dir / "expected.json"]
        manifest["cases"].append({"name": case["name"], "kind": expected["kind"],
                                  "description": case["description"], "provenance": PROVENANCE})
    manifest["count"] = len(manifest["cases"])
    manifest_path = OUT / "vectors.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    touched.append(manifest_path)

    update_sums(OUT / "SHA256SUMS", OUT, touched)
    update_sums(VECTORS / "SHA256SUMS", VECTORS, touched)
    print(f"wrote {manifest['count']} registry-conformance vectors to {OUT}")


if __name__ == "__main__":
    main()
