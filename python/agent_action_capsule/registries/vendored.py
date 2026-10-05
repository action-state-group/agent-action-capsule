# SPDX-License-Identifier: BSD-3-Clause
"""Check that a vendored registry value-set file still equals its registry.

A downstream repo that keeps a machine-readable copy of one registry (for
example evidencebook's ``schemas/vendor/epistemic-types.json``) can pin the
copy's provenance and its tests to it, but a three-way parity test inside that
repo cannot catch a re-vendor that never happened: all its copies agree and are
wrong together. This check compares the copy with the NAMED section of
``spec/REGISTRY.md`` at a PINNED agent-action-capsule ref.

    python -m agent_action_capsule.registries check-vendored FILE
        [--ref REF] [--registry PATH] [--json]

Limit: a pass proves the copy equals the registry at the pinned ref. It does not
prove the pin is current. Moving the pin is a deliberate change, made with a
re-vendor in the same commit.

Vendored file format (evidencebook's, unchanged)
------------------------------------------------

``values`` (required)
    The value set, a list of strings. Compared with the registry as a set,
    case-insensitively: registry tokens are lower case and a copy may re-case
    them (evidencebook upper-cases). Pinning the wire casing is the consumer's
    own test.
``source.interim_registry`` (required unless ``source.registry`` is given)
    Free text naming the interim registry; the ``(section N)`` in it is the
    REGISTRY.md section number AT THE PINNED REF (numbers have shifted between
    snapshots, so the number is resolved against the pinned copy, never the
    current one).
``source.document`` (checked when present)
    The owning draft, with revision, e.g. ``draft-mih-agent-evidence-layer-00``.
    With the revision removed it must equal the defining draft REGISTRY.md
    records for that section, so a wrong section number fails.
``source.section``, ``source.url``, ``source.owning_field``, ``$comment``
    Informational: the draft's own section, its datatracker URL, and the
    consumer field the set governs. Not compared.

Optional additions (an existing evidencebook file passes without them):

``source.registry_ref``
    The agent-action-capsule ref (tag, version or commit) the copy was vendored
    from. This is the one field to add so the pin lives in the file; without it
    the pin must be passed as ``--ref``. When both are present and differ the
    check fails as ``STALE_REF``.
``source.registry``
    The registry name (``ALL_REGISTRY_NAMES``). Needed only for a section that
    holds two tables (§10); when given it must agree with the section number.

Resolving the pinned ref
------------------------

With ``--registry PATH`` (a REGISTRY.md, or a registries.json generated from
one), the caller asserts that file is at the pinned ref; fetch it at that ref,
e.g. from raw.githubusercontent.com. Without it, the copy bundled in this
package is used, and only when the pin names the installed version (``v0.6.0``,
``0.6.0`` and ``go/v0.6.0`` compare equal); any other pin fails as
``REF_UNRESOLVABLE`` rather than silently checking against a different ref.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

__all__ = [
    "PROBLEM_CODES",
    "VendoredCheck",
    "check_vendored",
    "check_vendored_file",
    "main",
    "normalize_ref",
]

VALUES_DIFFER = "VALUES_DIFFER"
STALE_REF = "STALE_REF"
UNPINNED = "UNPINNED"
REF_UNRESOLVABLE = "REF_UNRESOLVABLE"
SECTION_NOT_FOUND = "SECTION_NOT_FOUND"
SECTION_AMBIGUOUS = "SECTION_AMBIGUOUS"
DOCUMENT_MISMATCH = "DOCUMENT_MISMATCH"
MALFORMED = "MALFORMED"
PROBLEM_CODES = (
    VALUES_DIFFER, STALE_REF, UNPINNED, REF_UNRESOLVABLE,
    SECTION_NOT_FOUND, SECTION_AMBIGUOUS, DOCUMENT_MISMATCH, MALFORMED,
)

_SECTION_RE = re.compile(r"\(section\s+(\d+)\)", re.IGNORECASE)
_REVISION_RE = re.compile(r"-\d\d$")


@dataclass(frozen=True)
class _Table:
    name: str
    section: str
    defined_in: str
    values: tuple[str, ...]


@dataclass
class VendoredCheck:
    """The outcome. ``ok`` is true only when ``problems`` is empty."""

    registry: str | None = None
    section: str | None = None
    ref: str | None = None
    added: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    detail: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems

    def to_dict(self) -> dict[str, Any]:
        """The vector form (``detail`` is human text and not part of it)."""
        return {
            "ok": self.ok,
            "registry": self.registry,
            "section": self.section,
            "ref": self.ref,
            "added": self.added,
            "missing": self.missing,
            "problems": self.problems,
        }

    def fail(self, code: str, detail: str) -> VendoredCheck:
        if code not in self.problems:
            self.problems.append(code)
        self.detail.append(detail)
        return self


def normalize_ref(ref: str) -> str:
    """``go/v0.6.0``, ``v0.6.0`` and ``0.6.0`` all name version 0.6.0."""
    ref = ref.strip()
    if ref.startswith("go/"):
        ref = ref[3:]
    if re.fullmatch(r"v\d+(\.\d+)*([-+].*)?", ref):
        ref = ref[1:]
    return ref


def _tables(registry_text: str) -> list[_Table]:
    """Parse a REGISTRY.md, or a registries.json generated from one."""
    from . import parse_registry_tables

    if registry_text.lstrip().startswith("{"):
        doc = json.loads(registry_text)
        return [
            _Table(name, str(t["section"]), t["defined_in"], tuple(t["values"]))
            for name, t in doc["registries"].items()
        ]
    return [
        _Table(t.name, t.section, t.defined_in, t.values)
        for t in parse_registry_tables(registry_text).values()
    ]


def check_vendored(
    vendored: Any,
    registry_text: str,
    registry_ref: str,
    ref: str | None = None,
) -> VendoredCheck:
    """Compare a parsed vendored file with ``registry_text``.

    ``registry_text`` is REGISTRY.md (or registries.json) as of
    ``registry_ref``. ``ref`` is the pin the caller checks against (``--ref``);
    the file's own ``source.registry_ref`` is used when ``ref`` is None.
    """
    out = VendoredCheck()
    if not isinstance(vendored, Mapping):
        return out.fail(MALFORMED, "vendored file is not a JSON object")
    source = vendored.get("source")
    values = vendored.get("values")
    if not isinstance(source, Mapping):
        return out.fail(MALFORMED, "vendored file has no source object")
    if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
        return out.fail(MALFORMED, "vendored values is not a list of strings")

    file_ref = source.get("registry_ref")
    if file_ref is not None and not isinstance(file_ref, str):
        return out.fail(MALFORMED, "source.registry_ref is not a string")
    pinned = ref if ref is not None else file_ref
    if pinned is None:
        return out.fail(UNPINNED, "no pin: pass --ref or record source.registry_ref in the file")
    out.ref = pinned
    if file_ref is not None and normalize_ref(file_ref) != normalize_ref(pinned):
        out.fail(STALE_REF, f"file was vendored at {file_ref!r} but the check pins {pinned!r}: "
                            "re-vendor at the pin, or move the pin deliberately")
    if normalize_ref(registry_ref) != normalize_ref(pinned):
        return out.fail(REF_UNRESOLVABLE, f"the registry copy available is at {registry_ref!r}, not the pin "
                                          f"{pinned!r}: pass --registry with REGISTRY.md at {pinned!r}")

    tables = _tables(registry_text)
    want_name = source.get("registry")
    interim = source.get("interim_registry")
    section = None
    if isinstance(interim, str):
        m = _SECTION_RE.search(interim)
        if m:
            section = m.group(1)
    if section is None and not isinstance(want_name, str):
        return out.fail(MALFORMED, "source.interim_registry names no '(section N)' and source.registry is absent")
    candidates = [t for t in tables if section is None or t.section == section]
    if isinstance(want_name, str):
        candidates = [t for t in candidates if t.name == want_name]
    if not candidates:
        where = f"section {section}" if section else f"registry {want_name!r}"
        return out.fail(SECTION_NOT_FOUND, f"REGISTRY.md at {pinned!r} has no {where}"
                        + (f" holding {want_name!r}" if section and isinstance(want_name, str) else ""))
    if len(candidates) > 1:
        names = ", ".join(t.name for t in candidates)
        return out.fail(SECTION_AMBIGUOUS, f"section {section} holds {names}: add source.registry")
    table = candidates[0]
    out.registry, out.section = table.name, table.section

    document = source.get("document")
    if isinstance(document, str) and _REVISION_RE.sub("", document) != table.defined_in:
        out.fail(DOCUMENT_MISMATCH, f"source.document {document!r} does not own section {table.section} "
                                    f"({table.name}, defined in {table.defined_in})")

    have = {v.lower(): v for v in values}
    registered = {v.lower(): v for v in table.values}
    out.added = sorted(have[k] for k in have.keys() - registered.keys())
    out.missing = sorted(registered[k] for k in registered.keys() - have.keys())
    if out.added or out.missing:
        out.fail(VALUES_DIFFER, f"{table.name} at {pinned!r}: added {out.added}, missing {out.missing}")
    return out


def _installed_version() -> str:
    from .. import __version__

    return __version__


def check_vendored_file(
    path: Path,
    ref: str | None = None,
    registry: Path | None = None,
) -> VendoredCheck:
    """As :func:`check_vendored`, reading files. Without ``registry`` the
    bundled REGISTRY.md is used, at the installed package version."""
    from . import _bundled_registry_md

    vendored = json.loads(path.read_text(encoding="utf-8"))
    if registry is not None:
        text = registry.read_text(encoding="utf-8")
        # The caller asserts the supplied copy is at the pin.
        pinned = ref if ref is not None else (vendored.get("source") or {}).get("registry_ref")
        registry_ref = pinned if isinstance(pinned, str) else ""
    else:
        text = _bundled_registry_md().read_text(encoding="utf-8")
        registry_ref = _installed_version()
    return check_vendored(vendored, text, registry_ref, ref)


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m agent_action_capsule.registries")
    sub = ap.add_subparsers(dest="command", required=True)
    cv = sub.add_parser(
        "check-vendored",
        help="check a vendored registry value-set file against REGISTRY.md at a pinned ref",
        description="Fails when the vendored values differ from the named REGISTRY.md section at the "
                    "pinned ref. A pass does not mean the pin is current.",
    )
    cv.add_argument("files", nargs="+", metavar="FILE")
    cv.add_argument("--ref", help="the pinned agent-action-capsule ref or version "
                                  "(default: the file's source.registry_ref)")
    cv.add_argument("--registry", type=Path, metavar="PATH",
                    help="REGISTRY.md or registries.json at the pinned ref "
                         "(default: the bundled copy, valid only when the pin is the installed version)")
    cv.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    results = []
    failed = False
    for name in args.files:
        try:
            res = check_vendored_file(Path(name), args.ref, args.registry)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            print(f"error: {name}: {exc}", file=sys.stderr)
            return 2
        failed = failed or not res.ok
        results.append((name, res))

    if args.json:
        json.dump([{"file": n, **r.to_dict(), "detail": r.detail} for n, r in results],
                  sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        for name, res in results:
            if res.ok:
                print(f"{name}: ok ({res.registry}, REGISTRY.md section {res.section} at {res.ref})")
            for d in res.detail:
                print(f"{name}: FAIL: {d}")
    return 1 if failed else 0
