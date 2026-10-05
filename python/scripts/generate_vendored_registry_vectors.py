#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate vectors/vendored-registry/: the check-vendored conformance cases.

Each case is a vendored value-set file (evidencebook's format), the registry
copy it is checked against, the ref that copy is at, the pin passed as --ref,
and the expected outcome. The expected outcomes are written here by hand from
the rule in agent_action_capsule.registries.vendored, then confirmed against the
Python reference; the Go tests read the same files.

The registry fixture is §6, §10, §17 and §18 of spec/REGISTRY.md, extracted at
generation time and then frozen: §10 holds two tables and a Provisional
subsection, so it exercises both.
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "vectors" / "vendored-registry"
sys.path.insert(0, str(ROOT / "python"))

from agent_action_capsule.registries import registries_document  # noqa: E402
from agent_action_capsule.registries.vendored import check_vendored  # noqa: E402

FIXTURE_MD = "REGISTRY.fixture.md"
FIXTURE_JSON = "registries.fixture.json"
KEEP_SECTIONS = ("## 6. ", "## 10. ", "## 17. ", "## 18. ")


def fixture_markdown() -> str:
    lines = (ROOT / "spec" / "REGISTRY.md").read_text(encoding="utf-8").splitlines()
    out = [
        "# Registries of record (conformance fixture)",
        "",
        "Sections 6, 10, 17 and 18 of spec/REGISTRY.md, frozen for",
        "vectors/vendored-registry/. Not a registry of record.",
        "",
    ]
    keep = False
    for line in lines:
        if line.startswith("## "):
            keep = line.startswith(KEEP_SECTIONS)
        if keep:
            out.append(line)
    return "\n".join(out).rstrip("\n") + "\n"


# evidencebook origin/main 997d351 schemas/vendor/epistemic-types.json, verbatim.
EVIDENCEBOOK = {
    "$comment": "Vendored, not owned here. The closed value set of record.epistemic_type is owned by the Internet-Draft draft-mih-agent-evidence-layer-00 (Evidence Layer, posted to the IETF datatracker as revision 00), section 4.1 'Epistemic Type' (\"epistemic_type is closed and is this document's\"). Until IANA creates the 'Evidence Layer Epistemic Types' registry, the interim registry is agent-action-capsule spec/REGISTRY.md section 17. This file lists the same eight values, as a machine-readable list, so tests read it instead of a second hand-typed enum. The draft's tokens are lower case; the upper-case spelling here is this library's own convention. A change to the set is made in the draft first and re-vendored here.",
    "source": {
        "document": "draft-mih-agent-evidence-layer-00",
        "section": "4.1 Epistemic Type",
        "url": "https://datatracker.ietf.org/doc/draft-mih-agent-evidence-layer/",
        "interim_registry": "https://github.com/action-state-group/agent-action-capsule/blob/main/spec/REGISTRY.md (section 17)",
        "owning_field": "record.epistemic_type",
    },
    "values": [
        "OBSERVED_EVENT",
        "SYSTEM_OF_RECORD_FACT",
        "PRODUCER_CLAIM",
        "HUMAN_REPORT",
        "SEMANTIC_JUDGMENT",
        "DERIVED_METRIC",
        "ADJUDICATION",
        "OBLIGATION_REFERENCE",
    ],
}

PIN = "v0.7.0"


def eb(**changes) -> dict:
    doc = copy.deepcopy(EVIDENCEBOOK)
    for key, value in changes.items():
        if key == "values":
            doc["values"] = value
        elif value is None:
            doc["source"].pop(key, None)
        else:
            doc["source"][key] = value
    return doc


def chain_relation(values: list[str], **extra) -> dict:
    return {
        "source": {
            "document": "draft-mih-scitt-agent-action-capsule-05",
            "section": "5.5.4 Chained Capsules",
            "interim_registry": "agent-action-capsule spec/REGISTRY.md (section 6)",
            "owning_field": "capsule.chain.relation",
            "registry_ref": PIN,
            **extra,
        },
        "values": values,
    }


EPI = list(EVIDENCEBOOK["values"])
CHAIN = ["follows", "confirms", "supersedes", "epoch_opens", "duplicates"]


def ok(registry: str, section: str, ref: str) -> dict:
    return {"ok": True, "registry": registry, "section": section, "ref": ref,
            "added": [], "missing": [], "problems": []}


def bad(problems: list[str], registry=None, section=None, ref=None, added=(), missing=()) -> dict:
    return {"ok": False, "registry": registry, "section": section, "ref": ref,
            "added": list(added), "missing": list(missing), "problems": problems}


CASES = [
    {
        "name": "pass-evidencebook-unchanged",
        "description": "evidencebook's vendored epistemic-types.json, byte-for-byte its content, pinned by --ref: upper-case copy of §17 compares case-insensitively; no file change needed.",
        "vendored": EVIDENCEBOOK, "registry": FIXTURE_MD, "registry_ref": PIN, "ref": PIN,
        "expected": ok("epistemic_type", "17", PIN),
    },
    {
        "name": "pass-registry-ref-in-file",
        "description": "the one added field, source.registry_ref, carries the pin in the file; no --ref. go/v0.7.0 and v0.7.0 name the same version.",
        "vendored": eb(registry_ref="go/v0.7.0"), "registry": FIXTURE_MD, "registry_ref": PIN, "ref": None,
        "expected": ok("epistemic_type", "17", "go/v0.7.0"),
    },
    {
        "name": "pass-registries-json",
        "description": "the registry copy may be registries.json generated from REGISTRY.md at the pin.",
        "vendored": eb(), "registry": FIXTURE_JSON, "registry_ref": PIN, "ref": PIN,
        "expected": ok("epistemic_type", "17", PIN),
    },
    {
        "name": "pass-chain-relation",
        "description": "a lower-case copy of §6 chain.relation owned by the base draft.",
        "vendored": chain_relation(CHAIN), "registry": FIXTURE_MD, "registry_ref": PIN, "ref": None,
        "expected": ok("chain.relation", "6", PIN),
    },
    {
        "name": "pass-section-10-named-registry",
        "description": "§10 holds two tables; source.registry picks one. The Provisional subsection's discriminator is not a value.",
        "vendored": {
            "source": {"document": "draft-mih-agent-disclosure-envelope-00",
                       "interim_registry": "agent-action-capsule spec/REGISTRY.md (section 10)",
                       "registry": "disclosure_envelope.disclosable_field", "registry_ref": PIN},
            "values": ["agent_input", "agent_output"],
        },
        "registry": FIXTURE_MD, "registry_ref": PIN, "ref": None,
        "expected": ok("disclosure_envelope.disclosable_field", "10", PIN),
    },
    {
        "name": "fail-added",
        "description": "the copy carries a value the registry at the pin does not.",
        "vendored": eb(values=EPI + ["VERIFIED_FACT"]), "registry": FIXTURE_MD, "registry_ref": PIN, "ref": PIN,
        "expected": bad(["VALUES_DIFFER"], "epistemic_type", "17", PIN, added=["VERIFIED_FACT"]),
    },
    {
        "name": "fail-missing",
        "description": "the registry at the pin has a value the copy lacks: the re-vendor that never happened.",
        "vendored": eb(values=EPI[:-1]), "registry": FIXTURE_MD, "registry_ref": PIN, "ref": PIN,
        "expected": bad(["VALUES_DIFFER"], "epistemic_type", "17", PIN, missing=["obligation_reference"]),
    },
    {
        "name": "fail-added-and-missing",
        "description": "a renamed value shows as one added and one missing.",
        "vendored": eb(values=EPI[:-1] + ["OBLIGATION_REF"]), "registry": FIXTURE_MD, "registry_ref": PIN, "ref": PIN,
        "expected": bad(["VALUES_DIFFER"], "epistemic_type", "17", PIN,
                        added=["OBLIGATION_REF"], missing=["obligation_reference"]),
    },
    {
        "name": "fail-chain-relation-legacy-token",
        "description": "a copy of chain.relation that carries the legacy alias resolves (REGISTRY.md §6 alias notes) fails: an alias is not a registered value, and no registered set is widened to admit it.",
        "vendored": chain_relation(CHAIN + ["resolves"]), "registry": FIXTURE_MD, "registry_ref": PIN, "ref": None,
        "expected": bad(["VALUES_DIFFER"], "chain.relation", "6", PIN, added=["resolves"]),
    },
    {
        "name": "fail-stale-ref",
        "description": "the file records vendoring at v0.6.0; CI pins v0.7.0. Values happen to match, but the pin moved without a re-vendor.",
        "vendored": eb(registry_ref="v0.6.0"), "registry": FIXTURE_MD, "registry_ref": PIN, "ref": PIN,
        "expected": bad(["STALE_REF"], "epistemic_type", "17", PIN),
    },
    {
        "name": "fail-ref-unresolvable",
        "description": "the pin is v0.7.0 but the only registry copy available is at v0.6.0 (e.g. the bundled copy of an older install): never checked against the wrong ref.",
        "vendored": eb(), "registry": FIXTURE_MD, "registry_ref": "v0.6.0", "ref": PIN,
        "expected": bad(["REF_UNRESOLVABLE"], ref=PIN),
    },
    {
        "name": "fail-unpinned",
        "description": "neither --ref nor source.registry_ref: nothing to check against.",
        "vendored": eb(), "registry": FIXTURE_MD, "registry_ref": PIN, "ref": None,
        "expected": bad(["UNPINNED"]),
    },
    {
        "name": "fail-document-mismatch",
        "description": "the section number points at a registry the named draft does not own (§18 link types under an evidence-layer document is fine; §6 is not).",
        "vendored": eb(interim_registry="agent-action-capsule spec/REGISTRY.md (section 6)"),
        "registry": FIXTURE_MD, "registry_ref": PIN, "ref": PIN,
        "expected": bad(["DOCUMENT_MISMATCH", "VALUES_DIFFER"], "chain.relation", "6", PIN,
                        added=sorted(EPI), missing=sorted(CHAIN)),
    },
    {
        "name": "fail-section-not-found",
        "description": "the pinned registry has no such section.",
        "vendored": eb(interim_registry="agent-action-capsule spec/REGISTRY.md (section 99)"),
        "registry": FIXTURE_MD, "registry_ref": PIN, "ref": PIN,
        "expected": bad(["SECTION_NOT_FOUND"], ref=PIN),
    },
    {
        "name": "fail-section-ambiguous",
        "description": "§10 holds two tables and the file does not name one.",
        "vendored": {
            "source": {"interim_registry": "agent-action-capsule spec/REGISTRY.md (section 10)", "registry_ref": PIN},
            "values": ["agent_input", "agent_output"],
        },
        "registry": FIXTURE_MD, "registry_ref": PIN, "ref": None,
        "expected": bad(["SECTION_AMBIGUOUS"], ref=PIN),
    },
    {
        "name": "fail-malformed",
        "description": "values is not a list of strings.",
        "vendored": {"source": {"interim_registry": "(section 17)", "registry_ref": PIN}, "values": "observed_event"},
        "registry": FIXTURE_MD, "registry_ref": PIN, "ref": None,
        "expected": bad(["MALFORMED"]),
    },
]


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    md = fixture_markdown()
    (OUT / FIXTURE_MD).write_text(md, encoding="utf-8")
    doc = registries_document(md)
    doc["source"] = f"vectors/vendored-registry/{FIXTURE_MD}"
    (OUT / FIXTURE_JSON).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    texts = {FIXTURE_MD: md, FIXTURE_JSON: (OUT / FIXTURE_JSON).read_text(encoding="utf-8")}
    for case in CASES:
        got = check_vendored(case["vendored"], texts[case["registry"]], case["registry_ref"], case["ref"]).to_dict()
        if got != case["expected"]:
            raise SystemExit(f"{case['name']}: reference disagrees with the hand-written expectation:\n"
                             f"  got      {got}\n  expected {case['expected']}")
    manifest = {
        "format_version": "1",
        "description": "check-vendored cases: a vendored registry value-set file against the named "
                       "REGISTRY.md section at a pinned ref. Python and Go both run every case.",
        "count": len(CASES),
        "cases": CASES,
    }
    (OUT / "cases.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {len(CASES)} cases to {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
