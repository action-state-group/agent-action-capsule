# SPDX-License-Identifier: BSD-3-Clause
"""Registry conformance: is every registry-governed value a Capsule carries
registered on the axis it is carried on?

This is a PRODUCER-SIDE conformance check, for a producer's own CI. It is not
verification. A verifier MUST NOT reject a record solely because it carries an
unregistered value (``spec/REGISTRY.md``, "The never-reject invariant"), and ``verify()``
does not: it reports such a value as informational. That is why a wrong token
is silent at seal and at verify, and why a producer that wants to know it emits
only registered values has to ask this module.

The registered sets are parsed from ``spec/REGISTRY.md`` (the same file
``registries.py`` reads), never hard-coded. A value is classified per field:

- ``registered``: in the registered set for the field's own axis.
- ``legacy_alias``: a deployed spelling the registry names as a read-only
  legacy alias (``chain.relation``, §6). Producers MUST emit the registered
  value it maps to; the finding names that value.
- ``cross_axis``: not registered on this axis, but registered on another one
  (for example a ``verdict_class`` value carried in ``disposition.decision``).
  The finding names the axes it is registered on.
- ``private``: an ``x-`` prefixed ``domain`` value, reserved for private
  experiments (§8). Not a conformance failure.
- ``unregistered``: none of the above.

``legacy_alias``, ``cross_axis`` and ``unregistered`` fail conformance.
"""
from __future__ import annotations

import json
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .registries import _HEADER_RE, _seeded_values_in_section, find_registry_md

__all__ = [
    "CAPSULE_FIELDS",
    "ConformanceFinding",
    "check_capsule",
    "is_conformant",
    "legacy_aliases",
    "load_axes",
]

# Each registry-governed Capsule field, as (field path, registry section name).
# A path segment "[]" means every element of that array.
CAPSULE_FIELDS = (
    ("disposition.verdict_class", "verdict_class"),
    ("disposition.decision", "disposition.decision"),
    ("effect.type", "effect.type"),
    ("effect.irreversibility_class", "irreversibility_class"),
    ("effect.effect_attestation", "effect_attestation"),
    ("chain.relation", "chain.relation"),
    ("references[].citation_purpose", "citation_purpose"),
    ("domain", "domain"),
    ("provenance", "provenance"),
    ("provenance_mode.mode", "provenance_mode"),
)

# Registries whose values are never carried in a Capsule field this module
# checks, but which still count as "another axis" for the cross-axis case: a
# Capsule field carrying an Evidence Layer link type is a cross-axis value.
_OTHER_AXES = (
    "Evidence Bundle kind",
    "Evidence Bundle extension kind",
    "Evidence Bundle countersignature type",
    "Evidence Request derivation",
    "Evidence Layer epistemic type",
    "Evidence Layer link type",
)

_PLAIN_HEADER_RE = re.compile(r"^##\s+\d+\.\s+(.+?)\s*$")
_ALIAS_RE = re.compile(r"^-\s+`([^`]+)`\s+→\s+`([^`]+)`")
# §6 states the `sequence` alias in prose rather than as a mapping bullet.
_SEQUENCE_HEADING = "**Deployed legacy alias — `sequence`.**"


@dataclass(frozen=True)
class ConformanceFinding:
    path: str
    axis: str
    value: Any
    status: str
    detail: str
    # cross_axis: the other axes the value is registered on.
    registered_on: tuple[str, ...] = ()
    # legacy_alias: the registered value a producer emits instead.
    emit_instead: str | None = None

    @property
    def conformant(self) -> bool:
        return self.status in ("registered", "private")

    def as_dict(self) -> dict[str, Any]:
        """The language-neutral form the vectors pin; ``detail`` is prose and
        is left out."""
        out = {"path": self.path, "axis": self.axis, "value": self.value, "status": self.status}
        if self.registered_on:
            out["registered_on"] = list(self.registered_on)
        if self.emit_instead is not None:
            out["emit_instead"] = self.emit_instead
        return out


def _sections(md: str) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for line in md.splitlines():
        if line.startswith("## "):
            m = _HEADER_RE.match(line) or _PLAIN_HEADER_RE.match(line)
            current = m.group(1) if m else None
            if current is not None:
                sections[current] = []
        elif current is not None:
            if line.startswith("### "):  # a provisional subsection is not the registered set
                current = None
            else:
                sections[current].append(line)
    return sections


def load_axes(path: Path | None = None) -> dict[str, frozenset[str]]:
    """Return ``{axis: registered values}`` for every Capsule-field axis and
    every other axis used for the cross-axis case. Raises if any is missing
    or parses empty, so a renamed section fails loudly rather than emptying a
    set."""
    sections = _sections((path or find_registry_md()).read_text(encoding="utf-8"))
    out: dict[str, frozenset[str]] = {}
    for axis in (*(a for _, a in CAPSULE_FIELDS), *_OTHER_AXES):
        if axis not in sections:
            raise ValueError(f"registry section {axis!r} not found in REGISTRY.md")
        values = _seeded_values_in_section(sections[axis])
        if not values:
            raise ValueError(f"registry section {axis!r} parsed with no values")
        out[axis] = frozenset(values)
    return out


def legacy_aliases(path: Path | None = None) -> dict[str, str]:
    """Return ``{legacy chain.relation token: registered value}`` from §6."""
    lines = _sections((path or find_registry_md()).read_text(encoding="utf-8"))["chain.relation"]
    out: dict[str, str] = {}
    for line in lines:
        m = _ALIAS_RE.match(line)
        if m:
            out[m.group(1)] = m.group(2)
        if line.startswith(_SEQUENCE_HEADING):
            out["sequence"] = "follows"
    return out


def _values_at(record: Mapping[str, Any], path: str) -> list[tuple[str, Any]]:
    nodes: list[tuple[str, Any]] = [("", record)]
    for seg in path.split("."):
        is_array = seg.endswith("[]")
        key = seg[:-2] if is_array else seg
        nxt: list[tuple[str, Any]] = []
        for prefix, node in nodes:
            if not isinstance(node, Mapping) or key not in node:
                continue
            here = f"{prefix}.{key}" if prefix else key
            child = node[key]
            if is_array:
                if isinstance(child, list):
                    nxt.extend((f"{here}[{i}]", item) for i, item in enumerate(child))
            else:
                nxt.append((here, child))
        nodes = nxt
    return nodes


def check_capsule(
    capsule: Mapping[str, Any],
    *,
    axes: Mapping[str, frozenset[str]] | None = None,
    aliases: Mapping[str, str] | None = None,
) -> list[ConformanceFinding]:
    """Classify every registry-governed value present in ``capsule``. A field
    that is absent produces no finding; a present value that is not a string
    is reported ``unregistered``."""
    if axes is None:
        axes = load_axes()
    if aliases is None:
        aliases = legacy_aliases()
    findings: list[ConformanceFinding] = []
    for field, axis in CAPSULE_FIELDS:
        for path, value in _values_at(capsule, field):
            findings.append(_classify(path, axis, value, axes, aliases))
    return findings


def _classify(path, axis, value, axes, aliases) -> ConformanceFinding:
    def finding(status: str, detail: str, **extra: Any) -> ConformanceFinding:
        return ConformanceFinding(path, axis, value, status, detail, **extra)

    if not isinstance(value, str):
        return finding("unregistered", f"{path} is not a string")
    if value in axes[axis]:
        return finding("registered", f"{value!r} is registered on {axis}")
    if axis == "chain.relation" and value in aliases:
        return finding("legacy_alias", f"{value!r} is a read-only legacy alias on chain.relation (§6); "
                                       f"emit the registered {aliases[value]!r}",
                       emit_instead=aliases[value])
    if axis == "domain" and value.startswith("x-"):
        return finding("private", f"{value!r} is a private x- domain value (§8), never registered")
    elsewhere = sorted(a for a, vals in axes.items() if a != axis and value in vals)
    if elsewhere:
        return finding("cross_axis", f"{value!r} is not registered on {axis}; it is registered on "
                                     f"{', '.join(elsewhere)}", registered_on=tuple(elsewhere))
    return finding("unregistered", f"{value!r} is not registered on {axis}")


def is_conformant(findings: list[ConformanceFinding]) -> bool:
    return all(f.conformant for f in findings)


def main(argv: list[str] | None = None) -> int:
    """``python -m agent_action_capsule.registry_conformance FILE...``: check
    each Capsule (a JSON object, or a JSON array of them) and print every
    non-conformant value. Exit 1 if any, else 0."""
    args = sys.argv[1:] if argv is None else argv
    if not args:
        print("usage: python -m agent_action_capsule.registry_conformance FILE...", file=sys.stderr)
        return 2
    axes, aliases = load_axes(), legacy_aliases()
    failed = False
    for name in args:
        doc = json.loads(Path(name).read_text(encoding="utf-8"))
        for i, capsule in enumerate(doc if isinstance(doc, list) else [doc]):
            label = f"{name}[{i}]" if isinstance(doc, list) else name
            if not isinstance(capsule, Mapping):
                print(f"{label}: not a JSON object")
                failed = True
                continue
            for f in check_capsule(capsule, axes=axes, aliases=aliases):
                if not f.conformant:
                    failed = True
                    print(f"{label}: {f.status}: {f.detail}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
