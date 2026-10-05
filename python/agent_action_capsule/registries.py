# SPDX-License-Identifier: BSD-3-Clause
"""Every registry of record in ``spec/REGISTRY.md``, as importable value sets.

Downstream code imports the sets instead of vendoring copies::

    from agent_action_capsule.registries import EPISTEMIC_TYPES, LINK_TYPES
    from agent_action_capsule.registries import CHAIN_RELATIONS, CITATION_PURPOSES
    from agent_action_capsule.registries import values
    values("epistemic_type")  # -> frozenset[str]

``ALL_REGISTRY_NAMES`` lists every name ``values()`` accepts. The same data
ships as ``agent_action_capsule/data/registries.json`` (generated from
REGISTRY.md) for consumers in other languages.

The seeded values are NOT hard-coded here: they are parsed at load time from the
interim registry of record (``spec/REGISTRY.md``) so the code and the spec cannot
drift. The binding invariant (§4, §12) — unregistered values are informational
and never a rejection — is applied by the verifier, not here; this module only
reports which values are seeded.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

__all__ = [
    "ALL_REGISTRY_NAMES",
    "CHAIN_RELATIONS",
    "CITATION_PURPOSES",
    "DISCLOSURE_ELIGIBLE_FIELDS",
    "EPISTEMIC_TYPES",
    "LINK_TYPES",
    "REGISTRY_NAMES",
    "RegistryTable",
    "load_registries",
    "ordered_values",
    "parse_registry_tables",
    "registries_document",
    "values",
    "find_registry_md",
    "load_cpb_provisional_values",
    "find_cpb_provisional",
]

# Companion Disclosure Envelope registry table. Values are dotted paths below
# the Capsule root so other language references can expose the same table.
DISCLOSURE_ELIGIBLE_FIELDS = {
    "agent_input": "model_attestation.compute_attestation.agent_input_digest",
    "agent_output": "model_attestation.compute_attestation.agent_output_digest",
}

# The seven registry-governed vocabularies a Capsule's own fields carry (§4),
# checked by the verifier. approver is deliberately NOT here: it is a closed enum
# fixed by the spec (§5.4), not registry-governed. Every registry in
# REGISTRY.md (not only these seven) is listed in ALL_REGISTRY_NAMES.
REGISTRY_NAMES = (
    "verdict_class",
    "disposition.decision",
    "effect.type",
    "irreversibility_class",
    "effect_attestation",
    "chain.relation",
    "citation_purpose",
)

# Every table REGISTRY.md records, in document order, keyed by a stable name.
# A section headed "## N. `name`" is keyed by that name. A section with a prose
# title is keyed by the name below; a section holding more than one table maps
# to one name per table, in order. Section NUMBERS are not used: they have
# shifted between snapshots (e.g. Evidence Bundle kind was §12, now §13).
_TITLE_KEYS: dict[str, tuple[str, ...]] = {
    "Reserved payload members — selective disclosure": ("sel_disc.reserved_member",),
    "Reserved wrapper members and disclosable fields — disclosure envelope": (
        "disclosure_envelope.reserved_member",
        "disclosure_envelope.disclosable_field",
    ),
    "Evidence Bundle kind": ("evidence_bundle.kind",),
    "Evidence Bundle extension kind": ("evidence_bundle.extension_kind",),
    "Evidence Bundle countersignature type": ("evidence_bundle.countersignature_type",),
    "Evidence Request derivation": ("evidence_request.derivation",),
    "Evidence Layer epistemic type": ("epistemic_type",),
    "Evidence Layer link type": ("link_type",),
}

ALL_REGISTRY_NAMES = (
    "verdict_class",                          # §1
    "disposition.decision",                   # §2
    "effect.type",                            # §3
    "irreversibility_class",                  # §4 (ordered)
    "effect_attestation",                     # §5
    "chain.relation",                         # §6
    "sel_disc.reserved_member",               # §7
    "domain",                                 # §8
    "provenance",                             # §9
    "disclosure_envelope.reserved_member",    # §10, first table
    "disclosure_envelope.disclosable_field",  # §10, second table
    "citation_purpose",                       # §11
    "provenance_mode",                        # §12 (provenance_mode.mode)
    "evidence_bundle.kind",                   # §13
    "evidence_bundle.extension_kind",         # §14
    "evidence_bundle.countersignature_type",  # §15
    "evidence_request.derivation",            # §16
    "epistemic_type",                         # §17
    "link_type",                              # §18
)

# Registries every snapshot of REGISTRY.md has carried since the first drop. A
# pinned snapshot missing one of these is malformed; any other registry may be
# absent from an older snapshot that predates it.
_ALWAYS_PRESENT = REGISTRY_NAMES[:6]

_HEADER_RE = re.compile(r"^##\s+\d+\.\s+(.+?)\s*$")
_TICK_RE = re.compile(r"`([^`]+)`")
_OL_ITEM_RE = re.compile(r"^\s*\d+\.\s+`([^`]+)`\s*$")
_DRAFT_RE = re.compile(r"draft-[a-z0-9]+(?:-[a-z0-9]+)*[a-z0-9]")
_BASE_DRAFT = "draft-mih-scitt-agent-action-capsule"


def find_registry_md(start: Path | None = None) -> Path:
    """Locate ``spec/REGISTRY.md``. Search order:
    1. ``AAC_REGISTRY_PATH`` env var (explicit override).
    2. Bundled ``data/REGISTRY.md`` next to this module (wheel install path).
    3. Walk up from this module looking for ``spec/REGISTRY.md`` (dev/source tree).
    """
    override = os.environ.get("AAC_REGISTRY_PATH")
    if override:
        return Path(override)
    # Bundled copy included in the wheel (agent_action_capsule/data/REGISTRY.md).
    bundled = Path(__file__).resolve().parent / "data" / "REGISTRY.md"
    if bundled.is_file():
        return bundled
    # Source-tree fallback: walk up looking for spec/REGISTRY.md.
    here = (start or Path(__file__)).resolve()
    for parent in [here, *here.parents]:
        candidate = parent / "spec" / "REGISTRY.md"
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(
        "spec/REGISTRY.md not found by walking up from "
        f"{here}; set AAC_REGISTRY_PATH to point at it"
    )


def _seeded_values_in_section(lines: list[str]) -> list[str]:
    """Extract seeded vocabulary tokens from one registry section.

    Tokens come ONLY from structured loci — table data rows (first column),
    ordered-list items, and an 'Initial contents' line — never from prose
    backticks (which carry guidance, not seeded values).
    """
    values: list[str] = []
    seen: set[str] = set()

    def add(tok: str) -> None:
        if tok not in seen:
            seen.add(tok)
            values.append(tok)

    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        stripped = line.strip()
        # Markdown table data row: first cell is a backticked token, and the row
        # is neither the header (first cell "Value") nor the |---| separator.
        if stripped.startswith("|"):
            cells = [c.strip() for c in stripped.strip("|").split("|")]
            first = cells[0] if cells else ""
            if first and first != "Value" and not (set(first) <= set("-: ")):
                m = _TICK_RE.fullmatch(first)
                if m:
                    add(m.group(1))
            i += 1
            continue
        # Ordered-list item: "N. `token`"
        m = _OL_ITEM_RE.match(line)
        if m:
            add(m.group(1))
            i += 1
            continue
        # Inline "Initial contents ...: `a`, `b`, ..." — the value list may wrap
        # across lines; collect backticks from AFTER the marker on the marker
        # line, then through the rest of the paragraph (until a blank line). Only
        # text after the marker is the value list — prose backticks before it
        # (e.g. guidance naming a value) are not seeded values.
        if "Initial contents" in stripped:
            first = True
            while i < n and lines[i].strip() != "":
                text = lines[i]
                if first:
                    text = text[text.find("Initial contents"):]
                    first = False
                for tok in _TICK_RE.findall(text):
                    add(tok)
                i += 1
            continue
        i += 1
    return values


@dataclass(frozen=True)
class RegistryTable:
    """One parsed registry: its seeded values in document order, plus provenance."""

    name: str
    section: str
    title: str
    defined_in: str
    values: tuple[str, ...]


def _section_key_title(header_text: str) -> tuple[str, ...] | None:
    m = _TICK_RE.fullmatch(header_text)
    if m:
        return (m.group(1),)
    return _TITLE_KEYS.get(header_text)


def _split_tables(lines: list[str]) -> list[list[str]]:
    """Split a section into runs, one per Markdown table. Non-table lines before
    the first table go with it, so inline-list and ordered-list loci still parse;
    used only for sections that hold more than one table."""
    runs: list[list[str]] = [[]]
    in_table = False
    for line in lines:
        is_row = line.strip().startswith("|")
        if is_row and not in_table and any(prev.strip().startswith("|") for prev in runs[-1]):
            runs.append([])
        in_table = is_row
        runs[-1].append(line)
    return runs


def parse_registry_tables(md: str) -> dict[str, RegistryTable]:
    """Parse REGISTRY.md text into ``{name: RegistryTable}`` for every registry
    the text defines.

    A ``### Provisional...`` subsection (held for ratification, not yet
    registered) is skipped up to the next heading: its values are not seeded.
    A registry whose heading is absent is not in the result. A registry whose
    heading is present but which seeds no values (e.g. §14 before its first
    registration: "No initial extension kind is defined") maps to an empty
    tuple; the callers below decide where that is an error.
    """
    lines = md.splitlines()
    sections: list[tuple[str, str, tuple[str, ...], list[str]]] = []
    current: list[str] | None = None
    skipping = False
    for line in lines:
        h = _HEADER_RE.match(line)
        if h:
            keys = _section_key_title(h.group(1))
            number = line.split(".", 1)[0].lstrip("#").strip()
            if keys is not None:
                current = []
                sections.append((number, h.group(1).strip("`"), keys, current))
            else:
                current = None
            skipping = False
            continue
        if line.startswith("## "):
            current = None
            skipping = False
            continue
        if line.startswith("### "):
            skipping = line[4:].lstrip().startswith("Provisional")
            continue
        if current is not None and not skipping:
            current.append(line)

    out: dict[str, RegistryTable] = {}
    for number, title, keys, body in sections:
        m = _DRAFT_RE.search("\n".join(body))
        defined_in = m.group(0) if m else _BASE_DRAFT
        runs = [body] if len(keys) == 1 else _split_tables(body)
        if len(runs) < len(keys):
            raise ValueError(f"REGISTRY.md §{number} ({title}): expected {len(keys)} tables, found {len(runs)}")
        for key, run in zip(keys, runs):
            vals = _seeded_values_in_section(run)
            out[key] = RegistryTable(key, number, title, defined_in, tuple(vals))
    return out


def load_registries(path: Path | None = None) -> dict[str, frozenset[str]]:
    """Parse ``spec/REGISTRY.md`` and return ``{registry_name: frozenset(values)}``
    for every registry it defines (see ``ALL_REGISTRY_NAMES``).

    The seven Capsule-field registries in ``REGISTRY_NAMES`` are what the
    verifier checks. The first six are in every snapshot; their absence, or a
    parse that seeds none of their values, raises. Any other registry, ``citation_purpose`` included, may be absent
    from an older pinned snapshot that predates it: it is then left OUT of the
    result, never mapped to an empty set, so a caller can tell "this snapshot
    predates the registry" from "the registry is empty". The verifier treats an
    absent registry's values as informationally unknown, as before.
    """
    tables = parse_registry_tables((path or find_registry_md()).read_text(encoding="utf-8"))
    for name in _ALWAYS_PRESENT:
        if name not in tables:
            raise ValueError(f"registry {name!r} not found in REGISTRY.md")
        if not tables[name].values:
            raise ValueError(f"registry {name!r} parsed with no seeded values")
    return {name: frozenset(t.values) for name, t in tables.items()}


def _bundled_registry_md() -> Path:
    bundled = Path(__file__).resolve().parent / "data" / "REGISTRY.md"
    if bundled.is_file():
        return bundled
    return find_registry_md()


@lru_cache(maxsize=1)
def _authoritative_tables() -> dict[str, RegistryTable]:
    tables = parse_registry_tables(_bundled_registry_md().read_text(encoding="utf-8"))
    missing = [n for n in ALL_REGISTRY_NAMES if n not in tables]
    extra = [n for n in tables if n not in ALL_REGISTRY_NAMES]
    empty = [n for n, t in tables.items() if not t.values]
    if missing or extra or empty:
        raise ValueError(
            "bundled REGISTRY.md registries differ from ALL_REGISTRY_NAMES: "
            f"missing={missing} extra={extra} empty={empty}"
        )
    return tables


def values(name: str) -> frozenset[str]:
    """The seeded values of registry ``name`` in this package's bundled
    REGISTRY.md (the authoritative copy, not ``AAC_REGISTRY_PATH``). Raises
    ``KeyError`` for a name not in ``ALL_REGISTRY_NAMES``."""
    tables = _authoritative_tables()
    if name not in tables:
        raise KeyError(f"unknown registry {name!r}; known: {', '.join(ALL_REGISTRY_NAMES)}")
    return frozenset(tables[name].values)


def ordered_values(name: str) -> tuple[str, ...]:
    """As :func:`values`, in REGISTRY.md document order (meaningful for the
    ordered ``irreversibility_class`` registry)."""
    tables = _authoritative_tables()
    if name not in tables:
        raise KeyError(f"unknown registry {name!r}; known: {', '.join(ALL_REGISTRY_NAMES)}")
    return tables[name].values


def registries_document(md: str | None = None) -> dict:
    """The machine-readable form shipped as ``data/registries.json``: every
    registry with its section, title, defining draft and ordered values.
    ``md`` defaults to the bundled REGISTRY.md."""
    tables = parse_registry_tables(md) if md is not None else _authoritative_tables()
    return {
        "source": "spec/REGISTRY.md",
        "generated_by": "python/scripts/generate_registries_json.py",
        "registries": {
            name: {
                "section": t.section,
                "title": t.title,
                "defined_in": t.defined_in,
                "values": list(t.values),
            }
            for name, t in tables.items()
        },
    }


EPISTEMIC_TYPES: frozenset[str] = values("epistemic_type")
"""REGISTRY.md §17, owned by draft-mih-agent-evidence-layer ("Epistemic Type")."""
LINK_TYPES: frozenset[str] = values("link_type")
"""REGISTRY.md §18, owned by draft-mih-agent-evidence-layer ("Typed Links")."""
CHAIN_RELATIONS: frozenset[str] = values("chain.relation")
"""REGISTRY.md §6 (`chain.relation`), base profile §5.5.4."""
CITATION_PURPOSES: frozenset[str] = values("citation_purpose")
"""REGISTRY.md §11 (`citation_purpose`), base profile Cross-record references."""


# --------------------------------------------------------------------------- #
# Vendored CPB provisional registry (§12 known-provisional resolution).
#
# The machine-readable CPB registry of record lives in
# ``action-state-group/scitt-payload-binding``; its *provisional* (Rung 3)
# artifact-type entries are vendored here as a local, no-network snapshot
# (``data/cpb_provisional.json``, refreshed by ``scripts/vendor_cpb_registry.py``,
# pinned to an upstream commit). The verifier consults it so that a value a
# provisional payload class is known to set — e.g. the mesh-inference-exchange
# class's ``effect.type='inference_completion'`` — resolves as *known with
# status provisional* rather than unknown. The never-reject invariant (§4, §12)
# is unchanged: a provisional value is still informational, never a rejection,
# and a genuinely unknown value still surfaces as ``unknown_registry_value``.
# --------------------------------------------------------------------------- #
def find_cpb_provisional(start: Path | None = None) -> Path | None:
    """Locate the vendored ``data/cpb_provisional.json``. Returns ``None`` if it
    is not present (the snapshot is optional; absence means no provisional
    resolution, never an error). Honors ``AAC_CPB_PROVISIONAL_PATH`` override."""
    override = os.environ.get("AAC_CPB_PROVISIONAL_PATH")
    if override:
        p = Path(override)
        return p if p.is_file() else None
    bundled = Path(__file__).resolve().parent / "data" / "cpb_provisional.json"
    return bundled if bundled.is_file() else None


def load_cpb_provisional_values(
    path: Path | None = None,
) -> dict[str, dict[str, str]]:
    """Return ``{aac_registry_name: {value: payload_class_name}}`` for the values
    that vendored *provisional* CPB payload classes are known to set on the
    surrounding capsule's six AAC registry fields.

    Returns an empty dict if the vendored snapshot is absent or malformed —
    provisional resolution is a best-effort enrichment, never a hard dependency
    (the verifier must still run, and never reject, without it)."""
    p = path or find_cpb_provisional()
    if p is None:
        return {}
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    out: dict[str, dict[str, str]] = {}
    types = doc.get("provisional_artifact_types", {})
    if not isinstance(types, dict):
        return {}
    for type_name, entry in types.items():
        if not isinstance(entry, dict):
            continue
        cfv = entry.get("capsule_field_values", {})
        if not isinstance(cfv, dict):
            continue
        for reg_name, values in cfv.items():
            if reg_name not in REGISTRY_NAMES or not isinstance(values, list):
                continue
            bucket = out.setdefault(reg_name, {})
            for v in values:
                if isinstance(v, str):
                    bucket.setdefault(v, type_name)
    return out
