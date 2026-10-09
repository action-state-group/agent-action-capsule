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

  1. POSITIVE: the six built-in manifests (appendix A) and the five example
     manifests (appendix B: a unilateral module that forbids composed/v1, a
     module that declares it understands a composition, a generic fallback,
     a declarative rules module reading agent_input, a declarative module
     reading rows from agent_output) validate against
     $defs/PresentationManifest. The two halves of the ambiguous pair
     validate too: their defect is not one a schema can see. Both example
     wording packs validate against $defs/WordingPack.
  2. SCHEMA NEGATIVES, each a copy of a positive with one change, MUST fail:
       - neg-unknown-field.json: a `title` member (presentation words belong
         in a wording pack, and the manifest is closed).
       - neg-fallback-with-priority.json: a fallback carrying `priority`.
       - neg-missing-id.json: `id` removed.
       - neg-presentation-v1-namespace.json: `spec_version` set to
         `presentation/v1`, the bundle extension kind for header chrome.
       - neg-missing-presentation-api.json: `presentation_api` removed (a
         malformed manifest, not a refused one).
       - neg-hint-wording-source.json: a declarative module naming the
         `presentation/v1` block as a wording source; wording comes only
         from the pack `wording_sha256` binds (spec section 6).
       - neg-declarative-member.json: a declarative field whose `member` is
         neither agent_input nor agent_output (spec section 5.2).
     MUTANT CHECK: each rejection is re-tested with the one schema rule it
     depends on removed (in memory; the committed schema is never modified).
     The same fixture MUST then validate, and the restored schema MUST
     reject it again.
  3. WORDING BINDING: each declarative example's `wording_sha256` equals the
     SHA-256 of its pack's exact bytes, every `label_key` names an entry in
     that pack, and every `value_key_prefix` prefixes at least one entry.
     Each pack carries both reserved keys (spec section 7.4), `page.title`
     and `module.title`, with different strings. A one-character edit of a
     pack (in memory) MUST change the digest.
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
  7. PRESENTATION ABI (spec section 3.2): every built-in and example
     manifest declares a presentation_api the reference runtime implements
     and a runtime_min it meets. neg-unsupported-presentation-api.json is
     schema-valid, declares aac.presentation-api/v99 and, registered beside
     the examples, is co-matchable with none of them. In a runtime that
     implements only aac.presentation-api/v0 it is refused
     (presentation_api_unsupported); the descriptor it matches resolves to
     the generic fallback WITH the refusal in the result, and the row of its
     required extension reads exactly as section 3.2 words it. A copy with
     a supported API and a too-high runtime_min is refused as
     runtime_too_old, with the section 3.2 line. MUTANT: a resolver that
     ignores presentation_api selects the unsupported module.
  8. DECLARATIVE SOURCES (spec section 5.2): canRender for a declarative
     module, modelled over a root whose members are given as (state,
     payload). A field with no `member` reads agent_input; a field with
     `member: agent_output` reads agent_output; a member that is not
     `disclosed` resolves nothing. The agent_input example renders over a
     root whose rows are in agent_input; the agent_output example renders
     over a root whose rows are in agent_output and declines when that
     member is withheld or mismatched. MUTANT: a renderer that ignores
     `member` declines the agent_output example over the same root.

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
  - The declarative renderer is not implemented in this repository; check 8
    models only canRender's source rule (member, disclosure state, RFC 6901
    resolution, the kind of the value) over in-memory roots, not a
    committed bundle.
  - Whether a trusted-executable module's code reads a bundle-carried
    presentation setting for wording or depth: code is not visible to a
    schema. Spec section 6 gives the behavioural test a reviewer or a
    conformance harness applies; the schema half (no manifest can name such
    a source) is neg-hint-wording-source.json.
  - Immutability of the context (spec section 3.1) is a property of the
    runtime's code and is tested there, not here.
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
    "example-declarative-outcome",
]
AMBIGUOUS_PAIR = ["neg-ambiguous-pair/a", "neg-ambiguous-pair/b"]
UNSUPPORTED_API = "neg-unsupported-presentation-api"

# The reference runtime's declaration (spec section 3.2).
RUNTIME_APIS = frozenset({"aac.presentation-api/v0"})
RUNTIME_VERSION = "0.1.0"
# Each declarative example, with the wording pack its wording_sha256 binds.
WORDING_PACKS = {
    "example-declarative-rules": "example-wording-pack",
    "example-declarative-outcome": "example-wording-pack-outcome",
}
# The keys every aac.wording-pack/v0 pack reserves (spec section 7.4).
RESERVED_WORDING_KEYS = ("page.title", "module.title")

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


def _strip_presentation_api_required(schema: dict) -> None:
    schema["$defs"]["PresentationManifest"]["required"].remove("presentation_api")


def _strip_declarative_additional(schema: dict) -> None:
    del schema["$defs"]["Declarative"]["additionalProperties"]


def _strip_member_enum(schema: dict) -> None:
    schema["$defs"]["DeclarativeField"]["properties"]["member"] = {"type": "string"}


# (fixture, the rule it depends on, how to remove that rule in memory)
SCHEMA_NEGATIVES = [
    ("neg-unknown-field", "additionalProperties: false", _strip_additional),
    ("neg-fallback-with-priority", "fallback => no priority", _strip_fallback_priority),
    ("neg-missing-id", "id required", _strip_id_required),
    ("neg-presentation-v1-namespace", "spec_version const", _strip_namespace_const),
    ("neg-missing-presentation-api", "presentation_api required", _strip_presentation_api_required),
    ("neg-hint-wording-source", "declarative closed", _strip_declarative_additional),
    ("neg-declarative-member", "member enum", _strip_member_enum),
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


def _version(text: str) -> tuple[int, int, int]:
    major, minor, patch = (int(part) for part in text.split("."))
    return major, minor, patch


def refusal_reason(m: dict, apis=RUNTIME_APIS, version=RUNTIME_VERSION) -> str | None:
    """Section 3.2: why a runtime refuses this module, or None."""
    if m["presentation_api"] not in apis:
        return "presentation_api_unsupported"
    if _version(version) < _version(m["runtime_min"]):
        return "runtime_too_old"
    return None


def _need(m: dict, reason: str, version: str) -> str:
    if reason == "presentation_api_unsupported":
        return (f"needs presentation API {m['presentation_api']}, "
                "which this viewer does not implement")
    return f"needs runtime {m['runtime_min']} or later; this viewer is {version}"


def refusal_row(m: dict, reason: str, covered: bool = True, version=RUNTIME_VERSION) -> str:
    """Section 3.2: the semantics cell of a required extension's row."""
    integrity = "Integrity verified" if covered else "Integrity not verified"
    return (f"{integrity}; meaning not interpreted: presentation module {m['id']} "
            f"{_need(m, reason, version)}")


def refusal_line(m: dict, reason: str, version=RUNTIME_VERSION) -> str:
    """Section 3.2: the line for a refused module that requires no extension."""
    return (f"Presentation module {m['id']} was not used: it "
            f"{_need(m, reason, version)}")


def resolve(registry, d, audience, fmt, can_render, first_wins=False,
            refused=None, honour_api=True):
    """Section 4.3, exactly. `first_wins` is the MUTANT only (check 5);
    `honour_api=False` is the MUTANT only (check 7). Refusals recorded on the
    way are appended to `refused` as (id, reason)."""
    if not d.verified:
        return REFUSAL
    matched = [m for m in registry if matches(m, d, audience, fmt)]
    for fallback_tier in (False, True):
        tier = [m for m in matched if m["fallback"] is fallback_tier]
        if len(tier) > 1 and not first_wins:
            raise AmbiguityError(sorted(m["id"] for m in tier))
        if tier:
            reason = refusal_reason(tier[0]) if honour_api else None
            if reason is not None:
                if refused is not None:
                    refused.append((tier[0]["id"], reason))
                continue
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


# --- declarative sources (spec section 5.2) ---------------------------------
DEFAULT_MEMBER = "agent_input"
_MISSING = object()


def _pointer(doc, pointer: str):
    """RFC 6901 resolution; _MISSING when the pointer names nothing."""
    if pointer == "":
        return doc
    for raw in pointer.split("/")[1:]:
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(doc, dict) and token in doc:
            doc = doc[token]
        elif isinstance(doc, list) and token.isdigit() and (token == "0" or token[0] != "0") \
                and int(token) < len(doc):
            doc = doc[int(token)]
        else:
            return _MISSING
    return doc


def _of_kind(value, item: dict) -> bool:
    """The minimal shape of each kind; the renderer's code is the authority."""
    kind = item["kind"]
    if kind == "count":
        return isinstance(value, int) and not isinstance(value, bool) and value >= 0
    if kind in ("enum", "digest"):
        return isinstance(value, str) and value != ""
    if kind == "identifier":
        return (isinstance(value, str) and 0 < len(value) <= 128
                and not any(c.isspace() for c in value))
    if kind == "rows":
        return isinstance(value, list) and all(
            isinstance(row, dict)
            and all(_of_kind(_pointer(row, c["source"]), c) for c in item["columns"])
            for row in value
        )
    return False


def declarative_can_render(m: dict, root: dict, honour_member: bool = True) -> bool:
    """canRender for a declarative module. `root` maps a member name to
    (state, payload). `honour_member=False` is the MUTANT only (check 8)."""
    for field in m["declarative"]["fields"]:
        member = field.get("member", DEFAULT_MEMBER) if honour_member else DEFAULT_MEMBER
        state, payload = root.get(member, ("withheld", None))
        if state != "disclosed":
            return False
        if not _of_kind(_pointer(payload, field["source"]), field):
            return False
    return True


DIGEST = "sha256:" + "0" * 64
RULES_ROOT = {
    "agent_input": ("disclosed", {
        "spec_version": "org.example.rules-comparison/v0",
        "rule_count": 2,
        "rules": [
            {"rule_id": "r-1", "state": "controlled", "cites": DIGEST},
            {"rule_id": "r-2", "state": "unknown", "cites": DIGEST},
        ],
    }),
    "agent_output": ("withheld", None),
}
OUTCOME_INPUT = {"spec_version": "org.example.rules-run/v0", "run_id": "run-7"}
OUTCOME_OUTPUT = {
    "failed_count": 1,
    "rules": [
        {"rule_id": "r-1", "outcome": "pass", "evidence": DIGEST},
        {"rule_id": "r-2", "outcome": "fail", "evidence": DIGEST},
    ],
}


def _outcome_root(output_state: str) -> dict:
    return {
        "agent_input": ("disclosed", OUTCOME_INPUT),
        "agent_output": (output_state,
                         OUTCOME_OUTPUT if output_state == "disclosed" else None),
    }


def main() -> int:
    if not SCHEMA_PATH.exists():
        print(f"ERROR: schema not found at {SCHEMA_PATH}")
        return 2
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    try:
        builtins = [_load(n) for n in BUILTINS]
        examples = [_load(n) for n in EXAMPLES]
        pair = [_load(n) for n in AMBIGUOUS_PAIR]
        unsupported = _load(UNSUPPORTED_API)
        pack_bytes = {
            name: (EXAMPLES_DIR / f"{pack}.json").read_bytes()
            for name, pack in WORDING_PACKS.items()
        }
    except FileNotFoundError as exc:
        print(f"ERROR: fixture missing: {exc}")
        return 2
    findings: list[str] = []

    # --- 1. POSITIVE ---
    manifest_validator = _validator_for(schema, "PresentationManifest")
    for name, instance in zip(
        BUILTINS + EXAMPLES + AMBIGUOUS_PAIR + [UNSUPPORTED_API],
        builtins + examples + pair + [unsupported],
    ):
        errors = list(manifest_validator.iter_errors(instance))
        if errors:
            findings.append(f"POSITIVE-REJECTED {name}: {errors[0].message}")
        else:
            print(f"OK  PresentationManifest {name}.json")
    pack_validator = _validator_for(schema, "WordingPack")
    for name, raw in pack_bytes.items():
        errors = list(pack_validator.iter_errors(json.loads(raw)))
        if errors:
            findings.append(f"POSITIVE-REJECTED {WORDING_PACKS[name]}: {errors[0].message}")
        else:
            print(f"OK  WordingPack          {WORDING_PACKS[name]}.json")

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
    declaratives = [m for m in examples if m["trust_class"] == "declarative"]
    if sorted(m["id"] for m in declaratives) != sorted(
        _load(name)["id"] for name in WORDING_PACKS
    ):
        findings.append("WORDING-HARNESS: every declarative example needs a pack in WORDING_PACKS")
    for name in WORDING_PACKS:
        declarative = _load(name)
        raw = pack_bytes[name]
        digest = hashlib.sha256(raw).hexdigest()
        if declarative["declarative"]["wording_sha256"] != digest:
            findings.append(
                f"WORDING-DIGEST-MISMATCH {declarative['id']}: manifest says "
                f"{declarative['declarative']['wording_sha256']}, pack bytes hash to {digest}"
            )
        else:
            print(f"OK  wording_sha256 of {declarative['id']} = SHA-256 of the pack's exact bytes")
        edited = raw.replace(b'"en"', b'"en "', 1)
        if edited == raw or hashlib.sha256(edited).hexdigest() == digest:
            findings.append(f"WORDING-EDIT-UNDETECTED {name}: a one-character pack edit kept the digest")
        else:
            print(f"OK  a one-character edit of {WORDING_PACKS[name]}.json changes wording_sha256")
        entries = json.loads(raw)["entries"]
        reserved = [entries.get(k) for k in RESERVED_WORDING_KEYS]
        if None in reserved or reserved[0] == reserved[1]:
            findings.append(
                f"WORDING-RESERVED {WORDING_PACKS[name]}: page.title and module.title must "
                f"both be present and differ, got {reserved}"
            )
        else:
            print(f"OK  {WORDING_PACKS[name]}.json names the page ({reserved[0]!r}) and the "
                  f"module ({reserved[1]!r}) separately")
        fields = declarative["declarative"]["fields"]
        for item in fields + [c for f in fields for c in f.get("columns", [])]:
            if item["label_key"] not in entries:
                findings.append(f"WORDING-KEY-MISSING {name} {item['label_key']}")
            prefix = item.get("value_key_prefix")
            if prefix is not None and not any(k.startswith(prefix) for k in entries):
                findings.append(f"WORDING-PREFIX-EMPTY {name} {prefix}")

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

    # --- 7. PRESENTATION ABI ---
    for m in builtins + examples:
        reason = refusal_reason(m)
        if reason is not None:
            findings.append(f"ABI-REFUSED {m['id']}: the reference runtime refuses it ({reason})")
    if not any(f.startswith("ABI-REFUSED") for f in findings):
        print(f"OK  ABI           every built-in and example declares a presentation_api in "
              f"{sorted(RUNTIME_APIS)} and runtime_min <= {RUNTIME_VERSION}")
    with_unsupported = examples + [unsupported]
    found = static_findings(with_unsupported)
    findings.extend(found)
    if refusal_reason(unsupported) != "presentation_api_unsupported":
        findings.append(f"ABI-NOT-REFUSED {unsupported['id']}: {refusal_reason(unsupported)}")
    witness = Descriptor(
        True,
        unsupported["requires"]["bundle_kind"],
        frozenset(_req_profiles(unsupported)),
        frozenset(_req_extensions(unsupported)),
    )
    refused: list[tuple[str, str]] = []
    got = resolve(with_unsupported, witness, "owner", "html", lambda _i, _d: True,
                  refused=refused)
    fallback_id = next(m["id"] for m in examples if m["fallback"])
    if got != fallback_id or refused != [(unsupported["id"], "presentation_api_unsupported")]:
        findings.append(
            f"ABI-RESOLUTION {unsupported['id']}: resolved {got} with refusals {refused}; "
            f"want {fallback_id} with the refusal recorded"
        )
    else:
        print(f"OK  ABI           {unsupported['id']} ({unsupported['presentation_api']}) is "
              f"refused; its descriptor resolves to {got} with the refusal in the result")
    row = refusal_row(unsupported, "presentation_api_unsupported")
    want_row = ("Integrity verified; meaning not interpreted: presentation module "
                "org.example.future-view/v1 needs presentation API aac.presentation-api/v99, "
                "which this viewer does not implement")
    if row != want_row:
        findings.append(f"ABI-ROW-WORDING: {row!r}")
    else:
        print(f"OK  ABI           row for {_req_extensions(unsupported)}: {row!r}")
    too_new = dict(unsupported, presentation_api="aac.presentation-api/v0", runtime_min="0.2.0")
    line = refusal_line(too_new, refusal_reason(too_new) or "")
    want_line = ("Presentation module org.example.future-view/v1 was not used: it needs "
                 "runtime 0.2.0 or later; this viewer is 0.1.0")
    if refusal_reason(too_new) != "runtime_too_old" or line != want_line:
        findings.append(f"ABI-RUNTIME-MIN: {refusal_reason(too_new)} {line!r}")
    else:
        print(f"OK  ABI           runtime_min 0.2.0 on runtime 0.1.0 is refused: {line!r}")
    mutant_got = resolve(with_unsupported, witness, "owner", "html", lambda _i, _d: True,
                         honour_api=False)
    if mutant_got == unsupported["id"]:
        print(f"OK  MUTANT        a resolver that ignores presentation_api selects "
              f"{mutant_got}: the refusal is load-bearing")
    else:
        findings.append(f"MUTANT-HARNESS-BROKEN: the API-blind resolver picked {mutant_got}")

    # --- 8. DECLARATIVE SOURCES ---
    rules = _load("example-declarative-rules")
    outcome = _load("example-declarative-outcome")
    if any("member" in f for f in rules["declarative"]["fields"]):
        findings.append("DECLARATIVE-HARNESS: the rules example must leave member to its default")
    if not any(f.get("member") == "agent_output" for f in outcome["declarative"]["fields"]):
        findings.append("DECLARATIVE-HARNESS: the outcome example must read agent_output")
    cases = [
        (rules, RULES_ROOT, True, "agent_input rows, no member named"),
        (outcome, _outcome_root("disclosed"), True, "agent_output rows, member agent_output"),
        (outcome, _outcome_root("withheld"), False, "agent_output withheld"),
        (outcome, _outcome_root("disclosure_mismatch"), False, "agent_output mismatched"),
        # The rows exist, but in the member the field does not name.
        (outcome, {"agent_input": ("disclosed", dict(OUTCOME_INPUT, **OUTCOME_OUTPUT)),
                   "agent_output": ("withheld", None)}, False,
         "rows only in agent_input, field names agent_output"),
    ]
    for m, root, want, label in cases:
        got = declarative_can_render(m, root)
        if got != want:
            findings.append(f"DECLARATIVE-CANRENDER {m['id']} ({label}): got {got}, want {want}")
        else:
            print(f"OK  declarative   {m['id']}: canRender {got} ({label})")
    if declarative_can_render(outcome, _outcome_root("disclosed"), honour_member=False):
        findings.append("MUTANT-HARNESS-BROKEN: a member-blind renderer rendered the "
                        "agent_output example")
    else:
        print("OK  MUTANT        a renderer that ignores member declines the agent_output "
              "example over the same root: member is load-bearing")

    if findings:
        print("\nFAIL — findings:")
        for f in findings:
            print(f"  {f}")
        return 1
    print(f"\nOK — {len(BUILTINS)} built-in and {len(EXAMPLES)} example manifests, "
          f"{len(SCHEMA_NEGATIVES)} schema negatives with mutants, the wording binding, "
          "the static and runtime ambiguity tests, behaviour preservation, the "
          "presentation ABI refusal and the declarative source rule all passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
