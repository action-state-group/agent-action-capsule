# SPDX-License-Identifier: BSD-3-Clause
"""Generate the negative cases for a non-string in a string-typed field.

Check 1 requires REQUIRED fields "present and typed" (§6). The never-reject
rule for unregistered values (§4, §12) covers well-typed strings only: a list
or an object where a string belongs is a type error, not an unknown value, so
every verifier rejects it in check 1 with ``field_not_string``. Each case is
otherwise a verifying record, sealed with the reference compute_capsule_id;
its expected.json is derived from the reference verify() and then frozen
("reference-derived").

Two corpora:

- vectors/capsule/ (Python, Go, TypeScript and Rust): a list and an object in
  disposition.decision, effect.type and chain.relation; one shape in each of
  epoch_id, effect.external_ref and cross_party.correlator; and one shape in
  each member of a references[] entry's retention object; and the §5.5.5
  retention rules: no bound (retention_empty), not an object
  (field_not_object), declarant absent or null (missing_required_field).
- provenance-mode-vectors/ (Python and Go, the verifiers that implement
  check 9): one shape in each of provenance_mode.source_asserted_at,
  import_batch and imported_at on an otherwise well-formed backfilled record.
  TypeScript and Rust do not derive provenance_mode, so these cases cannot
  join the four-way corpus; their check-1 finding is unit-tested there.

Each corpus's manifest (vectors.json) and SHA256SUMS (and vectors/SHA256SUMS
for vectors/capsule/) are updated in place; existing entries are kept.

Run:  cd python && PYTHONPATH=. python3 scripts/generate_typed_field_vectors.py
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from generate_v05_vectors import (  # noqa: E402
    OUT,
    VECTORS,
    assurance,
    expected_for,
    ident,
    policy_executed,
    seal,
    update_sums,
    write_json,
)

PM_OUT = VECTORS.parent / "provenance-mode-vectors"
HEX_1 = "1" * 64
PARENT = "a" * 64


def confirmed_effect(**overrides) -> dict:
    return {
        "status": "confirmed",
        "type": "write_order",
        "request_digest": HEX_1,
        "response_digest": HEX_1,
        "effect_attestation": "gate_executed",
        "irreversibility_class": "two_way",
        **overrides,
    }


def build_cases() -> list[dict]:
    cases = []
    for shape, decision, effect_type, relation in (
        ("list", ["accept"], ["write_order"], ["follows"]),
        ("object", {"value": "accept"}, {"value": "write_order"}, {"value": "follows"}),
    ):
        cases += [
            {
                "name": f"neg-field-not-string-decision-{shape}",
                "description": (
                    f"disposition.decision is a JSON {shape}, not a string: a type error, "
                    "not an unregistered value -> field_not_string (check 1)."
                ),
                "input": seal({
                    **ident(f"typed-decision-{shape}"),
                    "assurance": assurance("not_applicable", "standalone"),
                    "disposition": {**policy_executed(), "decision": decision},
                }),
            },
            {
                "name": f"neg-field-not-string-effect-type-{shape}",
                "description": (
                    f"effect.type is a JSON {shape}, not a string: a type error, "
                    "not an unregistered value -> field_not_string (check 1)."
                ),
                "input": seal({
                    **ident(f"typed-effect-type-{shape}"),
                    "effect": confirmed_effect(type=effect_type),
                    "assurance": assurance("confirmed", "standalone"),
                    "disposition": policy_executed(),
                }),
            },
            {
                "name": f"neg-field-not-string-chain-relation-{shape}",
                "description": (
                    f"chain.relation is a JSON {shape}, not a string: a type error, "
                    "not an unregistered value -> field_not_string (check 1)."
                ),
                "input": seal({
                    **ident(f"typed-chain-relation-{shape}"),
                    "assurance": assurance("not_applicable", "chained"),
                    "disposition": policy_executed(),
                    "chain": {"parent_capsule_id": PARENT, "relation": relation},
                }),
            },
        ]
    cases += [
        {
            "name": "neg-field-not-string-epoch-id-list",
            "description": (
                "epoch_id is a JSON list, not a string -> field_not_string (check 1)."
            ),
            "input": seal({
                **ident("typed-epoch-id-list"),
                "epoch_id": ["epoch-1"],
                "assurance": assurance("not_applicable", "standalone"),
                "disposition": policy_executed(),
            }),
        },
        {
            "name": "neg-field-not-string-external-ref-object",
            "description": (
                "effect.external_ref is a JSON object, not a string -> field_not_string (check 1)."
            ),
            "input": seal({
                **ident("typed-external-ref-object"),
                "effect": confirmed_effect(external_ref={"value": "order-7"}),
                "assurance": assurance("confirmed", "standalone"),
                "disposition": policy_executed(),
            }),
        },
        {
            "name": "neg-field-not-string-correlator-list",
            "description": (
                "cross_party.correlator is a JSON list, not a string -> field_not_string "
                "(check 1); the derived cross_party_rung is unilateral_fallback."
            ),
            "input": seal({
                **ident("typed-correlator-list"),
                "assurance": assurance("not_applicable", "standalone"),
                "disposition": policy_executed(),
                "cross_party": {
                    "initiator_ref": HEX_1,
                    "counterparty_ref": "2" * 64,
                    "correlator": ["exchange-corr-1"],
                    "substantive": False,
                },
            }),
        },
    ]
    retention_ref = {"type": "agent-action-capsule", "digest_alg": "SHA-256", "digest": "3" * 64}
    for field, shape, value in (
        ("declarant", "list", ["ACME-CO"]),
        ("retained-until", "object", {"value": "2027-01-01T00:00:00Z"}),
        ("not-retained-after", "list", ["2030-01-01T00:00:00Z"]),
    ):
        member = field.replace("-", "_")
        retention = {"declarant": "ACME-CO", "retained_until": "2027-01-01T00:00:00Z", member: value}
        # The bad entry is the second one, so the finding names references[1].
        cases.append({
            "name": f"neg-field-not-string-retention-{field}-{shape}",
            "description": (
                f"references[1].retention.{member} is a JSON {shape}, not a string -> "
                "field_not_string (check 1)."
            ),
            "input": seal({
                **ident(f"typed-retention-{field}-{shape}"),
                "assurance": assurance("not_applicable", "standalone"),
                "disposition": policy_executed(),
                "references": [
                    {**retention_ref, "digest": "4" * 64},
                    {**retention_ref, "retention": retention},
                ],
            }),
        })
    # §5.5.5 structural rules for a retention declaration, each on references[1].
    for name, retention, codes, what in (
        ("neg-retention-empty", {"declarant": "ACME-CO"}, ["retention_empty"],
         "carries neither retained_until nor not_retained_after"),
        ("neg-retention-not-object", ["ACME-CO", "2027-01-01T00:00:00Z"], ["field_not_object"],
         "is a JSON list, not an object"),
        ("neg-retention-declarant-missing", {"retained_until": "2027-01-01T00:00:00Z"}, ["missing_required_field"],
         "has no declarant, which is REQUIRED"),
        ("neg-retention-declarant-null", {"declarant": None, "retained_until": "2027-01-01T00:00:00Z"},
         ["missing_required_field"], "has a null declarant, which counts as missing (as for disposition.approver)"),
        ("neg-retention-null", None, ["field_not_object"],
         "is null: present but not an object, so its members are not checked"),
        ("neg-retention-declarant-missing-and-empty", {}, ["missing_required_field", "retention_empty"],
         "is an empty object: no declarant and no bound, reported in that order"),
    ):
        cases.append({
            "name": name,
            "expect": codes,
            "description": f"references[1].retention {what} -> {', '.join(codes)} (check 1, §5.5.5).",
            "input": seal({
                **ident(f"typed-{name[4:]}"),
                "assurance": assurance("not_applicable", "standalone"),
                "disposition": policy_executed(),
                "references": [
                    {**retention_ref, "digest": "4" * 64},
                    {**retention_ref, "retention": retention},
                ],
            }),
        })
    return cases


def build_provenance_cases() -> list[dict]:
    cases = []
    for field, shape, value in (
        ("source-asserted-at", "object", {"value": "2026-01-01T00:00:00Z"}),
        ("import-batch", "list", ["import-2026-09"]),
        ("imported-at", "list", ["2026-09-22T00:00:00Z"]),
    ):
        member = field.replace("-", "_")
        provenance_mode = {
            "mode": "backfilled",
            "source_ref": {"type": "x-external-ledger-entry", "digest_alg": "SHA-256", "digest": "3" * 64},
            "source_asserted_at": "2026-01-01T00:00:00Z",
            "import_batch": "import-2026-09",
            "imported_at": "2026-09-22T00:00:00Z",
            member: value,
        }
        cases.append({
            "name": f"neg-field-not-string-provenance-{field}-{shape}",
            "description": (
                f"provenance_mode.{member} is a JSON {shape}, not a string, on an otherwise "
                "well-formed backfilled record -> field_not_string (check 1)."
            ),
            "input": seal({
                **ident(f"typed-provenance-{field}-{shape}"),
                "assurance": assurance("not_applicable", "standalone"),
                "disposition": policy_executed(),
                "provenance_mode": provenance_mode,
            }),
        })
    return cases


def update_listed_case_sums(sums: Path, root: Path, paths: list[Path]) -> None:
    """provenance-mode-vectors/SHA256SUMS style: case files only (no manifest),
    ordered by path component, so every existing line keeps its place."""
    lines = {line.split("  ", 1)[1]: line for line in sums.read_text(encoding="utf-8").splitlines()}
    for path in paths:
        if path.parent == root:
            continue
        name = path.relative_to(root).as_posix()
        lines[name] = f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {name}"
    ordered = sorted(lines, key=lambda name: tuple(name.split("/")))
    sums.write_text("".join(lines[n] + "\n" for n in ordered), encoding="utf-8")


def write_corpus(out: Path, cases: list[dict], sums: list[tuple], ensure_ascii: bool) -> None:
    """Write ``cases`` into ``out`` and its manifest; apply each (updater, SHA256SUMS, root).

    ``ensure_ascii`` is the manifest's existing style: each manifest is frozen
    byte for byte except for the entries appended here.
    """
    manifest_path = out / "vectors.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    by_name = {case["name"]: i for i, case in enumerate(manifest["cases"])}
    touched: list[Path] = []
    for case in cases:
        expected = expected_for(case["description"], case["input"])
        codes = [(f["check"], f["severity"], f["code"]) for f in expected["findings"] if f["severity"] == "error"]
        want = case.get("expect", ["field_not_string"])
        if expected["ok"] or codes != [(1, "error", code) for code in want]:
            raise SystemExit(f"{case['name']}: expected check-1 {want}, got {expected['findings']}")
        case_dir = out / case["name"]
        case_dir.mkdir(exist_ok=True)
        write_json(case_dir / "input.json", case["input"])
        write_json(case_dir / "expected.json", expected)
        touched += [case_dir / "input.json", case_dir / "expected.json"]
        entry = {"name": case["name"], "kind": expected["kind"], "description": case["description"],
                 "provenance": expected["provenance"]}
        if case["name"] in by_name:
            manifest["cases"][by_name[case["name"]]] = entry
        else:
            manifest["cases"].append(entry)
    manifest["count"] = len(manifest["cases"])
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=ensure_ascii) + "\n", encoding="utf-8")
    touched.append(manifest_path)
    for updater, sums_file, root in sums:
        updater(sums_file, root, touched)
    print(f"wrote {len(cases)} typed-field vectors to {out}")


def main() -> None:
    write_corpus(OUT, build_cases(), [(update_sums, OUT / "SHA256SUMS", OUT),
                                      (update_sums, VECTORS / "SHA256SUMS", VECTORS)], ensure_ascii=False)
    write_corpus(PM_OUT, build_provenance_cases(), [(update_listed_case_sums, PM_OUT / "SHA256SUMS", PM_OUT)],
                 ensure_ascii=True)


if __name__ == "__main__":
    main()
