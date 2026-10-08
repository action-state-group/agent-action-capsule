#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""
check_presentation_manifest_examples.py

Validates every committed presentation manifest fixture
(schemas/examples/presentation-manifest-v0/) against
schemas/presentation-manifest-v0.json, runs the resolution rule of
spec/presentation-contract-v0.md section 4 over them, and proves each
rejection is load-bearing rather than a check that can never fire.

What this enforces (spec/presentation-contract-v0.md is normative; this is the
mechanical half):

  1. POSITIVE: the six built-in manifests (appendix A) and the four example
     manifests (appendix B: a unilateral module that forbids composed/v1, a
     module that declares it understands a composition, a generic fallback,
     a declarative rules module) validate against $defs/PresentationManifest.
     The two halves of the ambiguous pair validate too: their defect is not
     one a schema can see. example-wording-pack.json validates against
     $defs/WordingPack.
  2. SCHEMA NEGATIVES, each a copy of a positive with one change, MUST fail:
       - neg-unknown-field.json: a `title` member (presentation words belong
         in a wording pack, and the manifest is closed).
       - neg-fallback-with-priority.json: a fallback carrying `priority`.
       - neg-missing-id.json: `id` removed.
       - neg-presentation-v1-namespace.json: `spec_version` set to
         `presentation/v1`, the bundle extension kind for header chrome.
     MUTANT CHECK: each rejection is re-tested with the one schema rule it
     depends on removed (in memory; the committed schema is never modified).
     The same fixture MUST then validate, and the restored schema MUST
     reject it again.
  3. WORDING BINDING: the declarative example's `wording_sha256` equals the
     SHA-256 of example-wording-pack.json's exact bytes, every `label_key`
     names an entry in that pack, and every `value_key_prefix` prefixes at
     least one entry. A one-character edit of the pack (in memory) MUST
     change the digest.
  4. STATIC RESOLUTION TEST (section 4.5): within each registry (the six
     built-ins; the four examples), no two manifests of the same tier
     (specific or fallback) can match one descriptor. A manifest whose
     requires and forbids intersect, or which requires two tokens of one
     profile key, can never match and is a finding.
  5. AMBIGUOUS PAIR: neg-ambiguous-pair/a.json and b.json are schema-valid,
     both specific, with priorities 1 and 9. The static test MUST report
     them co-matchable, and resolving the witness descriptor (the union of
     their requirements) MUST raise the ambiguity error: priority does not
     break a tie. MUTANT: a first-wins resolver returns a module for the
     same descriptor, proving the check is the error, not an accident.
  6. BEHAVIOUR PRESERVATION (appendix A.3): for every descriptor in a
     finite universe (verified or not; every root profile combination the
     current viewer distinguishes; every subset of the extensions it reads
     plus composed/v1; whether the evaluation-summary model builds; two
     audiences; three formats), resolving over the six built-ins gives
     exactly what renderEvidenceGraph's if-chain gives today
     (ts/src/evidence-graph-view.ts), transcribed below as `legacy`.
     MUTANT: four forbids are each removed in turn (compliance's
     outcome-report/v1, result's two extensions, graph's result_version,
     outcome-report's report/v1). Each removal MUST make the static test
     report a pair and the enumeration raise an ambiguity error.

Usage:
    python3 schemas/check_presentation_manifest_examples.py       # from repo root
    python3 check_presentation_manifest_examples.py                # from schemas/

Exit 0: every check above passed. Exit 1: a finding was printed. Exit 2: a
harness error (missing dependency, missing fixture).

NOT covered here (explicitly named, not silently skipped):
  - canRender, buildModel and render are code; this checker models
    canRender as a flag (only the evaluation-summary graph can decline
    today). The registry implementation and the page goldens prove the code.
  - The digests in the example executable manifests are placeholders: no
    script is committed beside them. A builder checks a module-slot pin
    against the bytes it inlines (the emitter refuses a mismatch).
  - JSON Pointer sources in the declarative example are not resolved against
    a payload here; no rules-comparison payload is committed in this repo.
"""
from __future__ import annotations

import copy
import hashlib
import itertools
import json
import sys
from dataclasses import dataclass
from pathlib import Path

SCHEMAS_DIR = (
    Path(__file__).parent
    if Path(__file__).parent.name == "schemas"
    else Path(__file__).parent / "schemas"
)
EXAMPLES_DIR = SCHEMAS_DIR / "examples" / "presentation-manifest-v0"
SCHEMA_PATH = SCHEMAS_DIR / "presentation-manifest-v0.json"

BUILTINS = [
    "builtin-report-rows",
    "builtin-result-outcome-report",
    "builtin-result-compliance",
    "builtin-result",
    "builtin-evaluation-summary-graph",
    "builtin-no-aggregate",
]
EXAMPLES = [
    "example-unilateral",
    "example-composition-aware",
    "example-generic-fallback",
    "example-declarative-rules",
]
AMBIGUOUS_PAIR = ["neg-ambiguous-pair/a", "neg-ambiguous-pair/b"]
WORDING_PACK = "example-wording-pack"

ID_ROWS = "aac.builtin.report-rows/v0"
ID_OUTCOME = "aac.builtin.result-outcome-report/v0"
ID_COMPLIANCE = "aac.builtin.result-compliance/v0"
ID_RESULT = "aac.builtin.result/v0"
ID_GRAPH = "aac.builtin.evaluation-summary-graph/v0"
ID_NO_AGGREGATE = "aac.builtin.no-aggregate/v0"

REFUSAL = "<refusal>"
NO_PRESENTATION = "<no-presentation>"


def _strip_additional(schema: dict) -> None:
    del schema["$defs"]["PresentationManifest"]["additionalProperties"]


def _strip_fallback_priority(schema: dict) -> None:
    schema["$defs"]["PresentationManifest"]["allOf"].pop(0)


def _strip_id_required(schema: dict) -> None:
    schema["$defs"]["PresentationManifest"]["required"].remove("id")


def _strip_namespace_const(schema: dict) -> None:
    schema["$defs"]["PresentationManifest"]["properties"]["spec_version"] = {
        "type": "string"
    }


# (fixture, the rule it depends on, how to remove that rule in memory)
SCHEMA_NEGATIVES = [
    ("neg-unknown-field", "additionalProperties: false", _strip_additional),
    ("neg-fallback-with-priority", "fallback => no priority", _strip_fallback_priority),
    ("neg-missing-id", "id required", _strip_id_required),
    ("neg-presentation-v1-namespace", "spec_version const", _strip_namespace_const),
]


class AmbiguityError(Exception):
    """Two or more manifests of one tier matched: a hard error, never first-wins."""


@dataclass(frozen=True)
class Descriptor:
    """The resolution inputs a VerifiedBundleContext yields (spec section 4.2)."""

    verified: bool
    bundle_kind: str
    profiles: frozenset[str]
    extensions: frozenset[str]


# A manifest is arbitrary validated JSON; the fields read here are the ones
# the schema requires, so plain dict access is the honest type.
def _load(name: str) -> dict:
    return json.loads((EXAMPLES_DIR / f"{name}.json").read_text(encoding="utf-8"))


def _validator_for(schema: dict, defn: str):
    try:
        import jsonschema
    except ImportError as exc:  # pragma: no cover - environment problem, not a finding
        print(f"ERROR: the 'jsonschema' package is required to run this check: {exc}")
        sys.exit(2)
    sub_schema = dict(schema)
    sub_schema["$ref"] = f"#/$defs/{defn}"
    return jsonschema.Draft202012Validator(sub_schema)


def _req_profiles(m: dict) -> set[str]:
    return set(m["requires"].get("profiles", []))


def _req_extensions(m: dict) -> set[str]:
    return set(m["requires"].get("extensions", {}).get("required", []))


def _forb_profiles(m: dict) -> set[str]:
    return set(m.get("forbids", {}).get("profiles", []))


def _forb_extensions(m: dict) -> set[str]:
    return set(m.get("forbids", {}).get("extensions", []))


def _profile_key(token: str) -> str:
    return token.split(":", 1)[0]


def _one_per_key(tokens: set[str]) -> bool:
    keys = [_profile_key(t) for t in tokens]
    return len(keys) == len(set(keys))


def _intersects(a: list[str], b: list[str], wildcard: str | None) -> bool:
    if wildcard is not None and (wildcard in a or wildcard in b):
        return True
    return bool(set(a) & set(b))


def matches(m: dict, d: Descriptor, audience: str, fmt: str) -> bool:
    """Section 4.3 step 2: the declarative match, nothing else."""
    return (
        m["requires"]["bundle_kind"] == d.bundle_kind
        and _req_profiles(m) <= d.profiles
        and _req_extensions(m) <= d.extensions
        and not (_forb_profiles(m) & d.profiles)
        and not (_forb_extensions(m) & d.extensions)
        and ("*" in m["audiences"] or audience in m["audiences"])
        and fmt in m["formats"]
    )


def resolve(registry, d, audience, fmt, can_render, first_wins=False):
    """Section 4.3, exactly. `first_wins` is the MUTANT only (check 5)."""
    if not d.verified:
        return REFUSAL
    matched = [m for m in registry if matches(m, d, audience, fmt)]
    for fallback_tier in (False, True):
        tier = [m for m in matched if m["fallback"] is fallback_tier]
        if len(tier) > 1 and not first_wins:
            raise AmbiguityError(sorted(m["id"] for m in tier))
        if tier:
            if can_render(tier[0]["id"], d):
                return tier[0]["id"]
    return NO_PRESENTATION


def self_consistent(m: dict) -> list[str]:
    problems = []
    if _req_profiles(m) & _forb_profiles(m):
        problems.append("requires and forbids share a profile")
    if _req_extensions(m) & _forb_extensions(m):
        problems.append("requires and forbids share an extension")
    if not _one_per_key(_req_profiles(m)):
        problems.append("requires two tokens of one profile key")
    return problems


def co_matchable(a: dict, b: dict) -> bool:
    """Section 4.5: true exactly when some descriptor matches both."""
    if a["requires"]["bundle_kind"] != b["requires"]["bundle_kind"]:
        return False
    if not _intersects(a["audiences"], b["audiences"], "*"):
        return False
    if not _intersects(a["formats"], b["formats"], None):
        return False
    req_p = _req_profiles(a) | _req_profiles(b)
    req_e = _req_extensions(a) | _req_extensions(b)
    if req_p & (_forb_profiles(a) | _forb_profiles(b)):
        return False
    if req_e & (_forb_extensions(a) | _forb_extensions(b)):
        return False
    return _one_per_key(req_p)


def static_findings(registry: list[dict]) -> list[str]:
    out = []
    for m in registry:
        for p in self_consistent(m):
            out.append(f"DEAD-MANIFEST {m['id']}: {p}")
    for a, b in itertools.combinations(registry, 2):
        if a["fallback"] == b["fallback"] and co_matchable(a, b):
            tier = "fallback" if a["fallback"] else "specific"
            out.append(f"AMBIGUOUS {tier} pair {a['id']} / {b['id']}")
    return out


# --- today's dispatch, transcribed from renderEvidenceGraph -----------------
SPEC_TOKENS = [None, "report/v1", "evaluation-summary/v1", "org.example.other/v1"]
READ_EXTENSIONS = ["outcome-report/v1", "eu-ai-act-compliance/v1", "composed/v1"]


def legacy(d: Descriptor, graph_builds: bool) -> str:
    """ts/src/evidence-graph-view.ts renderEvidenceGraph, branch for branch."""
    if not d.verified:
        return REFUSAL
    if "spec_version:report/v1" in d.profiles:
        return ID_ROWS
    if "result_version:evidence-result-v0" in d.profiles:
        if "outcome-report/v1" in d.extensions:
            return ID_OUTCOME
        # compliance is read only when outcome-report is absent
        if "eu-ai-act-compliance/v1" in d.extensions:
            return ID_COMPLIANCE
        return ID_RESULT
    if "spec_version:evaluation-summary/v1" in d.profiles and graph_builds:
        return ID_GRAPH
    return ID_NO_AGGREGATE


def universe():
    for verified, spec, result in itertools.product(
        (True, False), SPEC_TOKENS, (False, True)
    ):
        profiles = set()
        if spec is not None:
            profiles.add(f"spec_version:{spec}")
        if result:
            profiles.add("result_version:evidence-result-v0")
        for n in range(len(READ_EXTENSIONS) + 1):
            for exts in itertools.combinations(READ_EXTENSIONS, n):
                for graph_builds in (True, False):
                    yield (
                        Descriptor(
                            verified,
                            "evidence-bundle/v2",
                            frozenset(profiles),
                            frozenset(exts),
                        ),
                        graph_builds,
                    )


def preservation_findings(registry: list[dict]) -> tuple[list[str], int]:
    out, cases = [], 0
    for d, graph_builds in universe():
        def can_render(module_id: str, _d: Descriptor, gb: bool = graph_builds) -> bool:
            return gb if module_id == ID_GRAPH else True

        want = legacy(d, graph_builds)
        for audience, fmt in itertools.product(
            ("owner", "counterparty"), ("html", "fragment", "embedded")
        ):
            cases += 1
            try:
                got = resolve(registry, d, audience, fmt, can_render)
            except AmbiguityError as err:
                out.append(f"AMBIGUITY {sorted(d.profiles)} {sorted(d.extensions)}: {err}")
                continue
            if got != want:
                out.append(
                    f"BEHAVIOUR-CHANGED {sorted(d.profiles)} {sorted(d.extensions)} "
                    f"graph_builds={graph_builds} {audience}/{fmt}: today {want}, resolved {got}"
                )
    return out, cases


def _drop_forbid(registry, module_id, field, token):
    mutated = copy.deepcopy(registry)
    for m in mutated:
        if m["id"] == module_id:
            m["forbids"][field].remove(token)
            if not m["forbids"][field]:
                del m["forbids"][field]
            if not m["forbids"]:
                del m["forbids"]
    return mutated


def main() -> int:
    if not SCHEMA_PATH.exists():
        print(f"ERROR: schema not found at {SCHEMA_PATH}")
        return 2
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    try:
        builtins = [_load(n) for n in BUILTINS]
        examples = [_load(n) for n in EXAMPLES]
        pair = [_load(n) for n in AMBIGUOUS_PAIR]
        pack_bytes = (EXAMPLES_DIR / f"{WORDING_PACK}.json").read_bytes()
    except FileNotFoundError as exc:
        print(f"ERROR: fixture missing: {exc}")
        return 2
    findings: list[str] = []

    # --- 1. POSITIVE ---
    manifest_validator = _validator_for(schema, "PresentationManifest")
    for name, instance in zip(
        BUILTINS + EXAMPLES + AMBIGUOUS_PAIR, builtins + examples + pair
    ):
        errors = list(manifest_validator.iter_errors(instance))
        if errors:
            findings.append(f"POSITIVE-REJECTED {name}: {errors[0].message}")
        else:
            print(f"OK  PresentationManifest {name}.json")
    pack = json.loads(pack_bytes)
    errors = list(_validator_for(schema, "WordingPack").iter_errors(pack))
    if errors:
        findings.append(f"POSITIVE-REJECTED {WORDING_PACK}: {errors[0].message}")
    else:
        print(f"OK  WordingPack          {WORDING_PACK}.json")

    # --- 2. SCHEMA NEGATIVES + MUTANTS ---
    for name, rule, strip in SCHEMA_NEGATIVES:
        instance = _load(name)
        errors = list(manifest_validator.iter_errors(instance))
        if not errors:
            findings.append(f"NEGATIVE-DID-NOT-FAIL {name}: validated clean")
            continue
        print(f"OK  PresentationManifest {name}.json correctly REJECTED "
              f"(e.g. {errors[0].message!r})")
        mutant = copy.deepcopy(schema)
        strip(mutant)
        mutant_errors = list(_validator_for(mutant, "PresentationManifest").iter_errors(instance))
        if mutant_errors:
            findings.append(
                f"MUTANT-DID-NOT-FLIP {name}: with '{rule}' removed it still fails "
                f"({mutant_errors[0].message!r}) -- the rejection is not that rule's"
            )
        else:
            print(f"OK  MUTANT        '{rule}' removed: {name}.json VALIDATES CLEAN")
        if not list(manifest_validator.iter_errors(instance)):
            findings.append(f"MUTANT-RESTORE-FAILED {name}")

    # --- 3. WORDING BINDING ---
    declarative = next(m for m in examples if m["trust_class"] == "declarative")
    digest = hashlib.sha256(pack_bytes).hexdigest()
    if declarative["declarative"]["wording_sha256"] != digest:
        findings.append(
            f"WORDING-DIGEST-MISMATCH {declarative['id']}: manifest says "
            f"{declarative['declarative']['wording_sha256']}, pack bytes hash to {digest}"
        )
    else:
        print(f"OK  wording_sha256 of {declarative['id']} = SHA-256 of the pack's exact bytes")
    edited = pack_bytes.replace(b"Rules compared", b"Rules  compared")
    if hashlib.sha256(edited).hexdigest() == digest:
        findings.append("WORDING-EDIT-UNDETECTED: a one-character pack edit kept the digest")
    else:
        print("OK  a one-character pack edit changes wording_sha256")
    entries = pack["entries"]
    fields = declarative["declarative"]["fields"]
    for item in fields + [c for f in fields for c in f.get("columns", [])]:
        if item["label_key"] not in entries:
            findings.append(f"WORDING-KEY-MISSING {item['label_key']}")
        prefix = item.get("value_key_prefix")
        if prefix is not None and not any(k.startswith(prefix) for k in entries):
            findings.append(f"WORDING-PREFIX-EMPTY {prefix}")

    # --- 4. STATIC RESOLUTION TEST ---
    for label, registry in (("built-ins", builtins), ("examples", examples)):
        found = static_findings(registry)
        findings.extend(found)
        if not found:
            pairs = len(list(itertools.combinations(registry, 2)))
            print(f"OK  static test   {label}: {len(registry)} manifests, {pairs} pairs, "
                  "no same-tier pair can match one descriptor")

    # --- 5. AMBIGUOUS PAIR ---
    a, b = pair
    if not (a["fallback"] is False and b["fallback"] is False and a["priority"] != b["priority"]):
        findings.append("AMBIGUOUS-PAIR-HARNESS: the pair must be two specifics with different priorities")
    if not co_matchable(a, b):
        findings.append("AMBIGUOUS-PAIR-NOT-DETECTED: the static test calls the pair disjoint")
    else:
        print("OK  static test   neg-ambiguous-pair: a/b reported co-matchable")
    witness = Descriptor(
        True,
        a["requires"]["bundle_kind"],
        frozenset(_req_profiles(a) | _req_profiles(b)),
        frozenset(_req_extensions(a) | _req_extensions(b)),
    )
    try:
        got = resolve(pair, witness, "owner", "html", lambda _i, _d: True)
        findings.append(f"AMBIGUOUS-PAIR-RESOLVED: resolve returned {got} instead of raising")
    except AmbiguityError as err:
        print(f"OK  resolve       witness descriptor raises the ambiguity error {err}; "
              "priorities 1 and 9 did not break the tie")
    mutant_got = resolve(pair, witness, "owner", "html", lambda _i, _d: True, first_wins=True)
    if mutant_got in (a["id"], b["id"]):
        print(f"OK  MUTANT        a first-wins resolver silently picks {mutant_got}: "
              "the error above is load-bearing")
    else:
        findings.append("MUTANT-HARNESS-BROKEN: the first-wins resolver picked nothing")

    # --- 6. BEHAVIOUR PRESERVATION ---
    found, cases = preservation_findings(builtins)
    findings.extend(found[:20])
    if not found:
        print(f"OK  preservation  {cases} (descriptor, audience, format) cases resolve "
              "exactly as renderEvidenceGraph dispatches today")
    for module_id, field, token in (
        (ID_COMPLIANCE, "extensions", "outcome-report/v1"),
        (ID_RESULT, "extensions", "eu-ai-act-compliance/v1"),
        (ID_RESULT, "extensions", "outcome-report/v1"),
        (ID_GRAPH, "profiles", "result_version:evidence-result-v0"),
        (ID_OUTCOME, "profiles", "spec_version:report/v1"),
    ):
        mutated = _drop_forbid(builtins, module_id, field, token)
        static = static_findings(mutated)
        dynamic, _ = preservation_findings(mutated)
        if static and any(f.startswith("AMBIGUITY") for f in dynamic):
            print(f"OK  MUTANT        without {module_id} forbidding {token}: "
                  f"static test reports {len(static)} pair(s), enumeration raises the error")
        else:
            findings.append(
                f"MUTANT-DID-NOT-FLIP {module_id} forbids {token}: removing it left "
                f"static={len(static)} dynamic={len(dynamic)} -- that forbid is not load-bearing"
            )
    if static_findings(builtins) or preservation_findings(builtins)[0]:
        findings.append("MUTANT-RESTORE-FAILED built-ins")

    if findings:
        print("\nFAIL — findings:")
        for f in findings:
            print(f"  {f}")
        return 1
    print(f"\nOK — {len(BUILTINS)} built-in and {len(EXAMPLES)} example manifests, "
          f"{len(SCHEMA_NEGATIVES)} schema negatives with mutants, the wording binding, "
          "the static and runtime ambiguity tests, and behaviour preservation all passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
