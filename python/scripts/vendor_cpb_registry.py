# SPDX-License-Identifier: BSD-3-Clause
"""Re-vendor the CPB registry snapshot from a local scitt-payload-binding checkout.

The machine-readable CPB registry of record is
``action-state-group/scitt-payload-binding/registry.json`` — generated from that
repo's ``REGISTRY.md`` by its own ``.github/gen_registry.py``. It is meant to be
*vendored* into consuming packages as a local, no-network snapshot so a verifier
can resolve a payload class's status offline. This mirrors the existing
``capsule_ledger/scripts/vendor_bundle_viewer.py`` pattern: one generated artifact
is copied in by hand, re-run when the upstream changes, and the exact upstream
commit is recorded for provenance.

Two artifacts are vendored, both under ``agent_action_capsule/data/``:

* ``cpb_registry.json`` — the live-table snapshot (``registry.json`` verbatim),
  covering the Payload Canonicalization Algorithm and (live) Artifact Type
  registries.
* ``cpb_provisional.json`` — a machine-readable projection of the *provisional*
  Artifact Type entries from ``spec/cpb-provisional-registry.md`` (Rung 3).
  ``registry.json`` deliberately carries only live-table entries, so provisional
  payload classes (e.g. ``mesh-inference-exchange``) are projected here with
  ``status: "provisional"`` and the field/vocabulary sets quoted from the
  provisional-registry markdown. This projection is intentionally lossy — it is
  a resolver index (name -> status + governed field values), not a re-encoding of
  the full entry — so the markdown stays the source of truth.

Both repos are the same license family (Action State Group). Each vendored file
records the exact scitt-payload-binding commit it came from.

Usage:
    python scripts/vendor_cpb_registry.py [path-to-scitt-payload-binding-checkout]

If no path is given, tries ``$SCITT_PAYLOAD_BINDING_PATH``, else
``../../scitt-payload-binding`` relative to this repo, else a sibling checkout.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent  # .../agent-action-capsule/python
DATA_DIR = REPO_ROOT / "agent_action_capsule" / "data"
LIVE_OUT = DATA_DIR / "cpb_registry.json"
PROVISIONAL_OUT = DATA_DIR / "cpb_provisional.json"


def _find_spb(explicit: str | None) -> Path:
    candidates = [Path(explicit)] if explicit else []
    env = os.environ.get("SCITT_PAYLOAD_BINDING_PATH")
    if env:
        candidates.append(Path(env))
    # This package lives at <repo>/python; the sibling asg checkout is two up.
    candidates.append(REPO_ROOT.parent.parent / "scitt-payload-binding")
    candidates.append(REPO_ROOT.parent / "scitt-payload-binding")
    for c in candidates:
        if c and (c / "registry.json").exists() and (c / "REGISTRY.md").exists():
            return c.resolve()
    raise SystemExit(
        "no scitt-payload-binding checkout found -- pass a path, set "
        "$SCITT_PAYLOAD_BINDING_PATH, or place a checkout next to this repo"
    )


def _pinned_commit(spb: Path) -> str:
    commit = subprocess.run(
        ["git", "-C", str(spb), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    dirty = subprocess.run(
        ["git", "-C", str(spb), "status", "--porcelain", "registry.json",
         "REGISTRY.md", "spec/cpb-provisional-registry.md"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    if dirty:
        raise SystemExit(
            f"refusing to vendor from a dirty scitt-payload-binding checkout ({spb}) -- "
            "commit or stash the registry sources first so the recorded commit sha "
            "is meaningful"
        )
    return commit


# --------------------------------------------------------------------------- #
# Provisional projection: parse spec/cpb-provisional-registry.md.
#
# We deliberately extract only what a *resolver* needs — the artifact-type name
# and the closed-set vocabularies it governs — not the full prose entry. The
# markdown remains the normative source; this is an offline index over it.
# --------------------------------------------------------------------------- #
_PROP_HEADER = re.compile(r"^## Proposed:\s+`([^`]+)`\s*$")
_CLOSED_SET = re.compile(r"`([a-z_.]+)`\s*(?:∈|\\in|in)\s*`?\{([^}`]+)\}`?")
_REFERENCE = re.compile(r"\*\*Reference:\*\*\s*(.+?)\s*$", re.MULTILINE)


# Curated capsule-field-value bindings for provisional payload classes.
#
# The CPB provisional-registry markdown governs a payload class's *own* block
# vocabulary (e.g. ``terminal_state``, ``observation_point``). It does NOT
# restate the AAC six-registry field values (``effect.type``,
# ``effect_attestation``, ``chain.relation``) that a producer of that class
# sets on the surrounding capsule. Those are resolved here, hand-curated from
# the producer named in the entry's Reference, with an explicit source pin so
# provenance is honest (never fabricated into the CPB registry itself).
#
# Keys are AAC registry names (see agent_action_capsule.registries.REGISTRY_NAMES).
_CAPSULE_FIELD_VALUES: dict[str, dict] = {
    "mesh-inference-exchange": {
        "source": (
            "action-state-group/capsule-emit-mesh "
            "plugins/admission-policy/src/capsule_emit.rs "
            "(effect_type, effect_attestation, chain.relation) and "
            "capsule_sidecar.py"
        ),
        "values": {
            # From the Rust capsule-producer plugin that seals the real mesh
            # capsules (capsule_emit.rs / capsule.rs). The Python sidecar path
            # uses effect_attestation='gate_executed' and chain.relation=
            # 'confirms' (both already seeded), so only the wire-producer values
            # need provisional resolution here.
            "effect.type": ["inference_completion"],
            "effect_attestation": ["host_served_observed"],
            "chain.relation": ["follows"],
        },
    },
}


def _projection_from_markdown(md: str) -> dict:
    """Return {artifact_type_name: {status, reference, governed_values}}.

    ``governed_values`` maps a governed field name (as it appears in the entry,
    e.g. ``role``, ``terminal_state``, ``observation_point``) to the list of
    closed-set values quoted in the entry. A verifier consults this to downgrade
    an ``unknown_registry_value`` finding to a *known-provisional* note.

    ``capsule_field_values`` (added from ``_CAPSULE_FIELD_VALUES``) carries the
    surrounding-capsule AAC-registry values the payload class's producer sets;
    these are what check 8 of the AAC verifier actually consults.
    """
    entries: dict[str, dict] = {}
    lines = md.splitlines()
    current: str | None = None
    block: list[str] = []

    def flush() -> None:
        if current is None:
            return
        text = "\n".join(block)
        governed: dict[str, list[str]] = {}
        for m in _CLOSED_SET.finditer(text):
            field = m.group(1).split(".")[-1]
            vals = [v.strip().strip("`") for v in m.group(2).split(",")]
            vals = [v for v in vals if v and " " not in v]
            if vals:
                governed.setdefault(field, [])
                for v in vals:
                    if v not in governed[field]:
                        governed[field].append(v)
        ref_m = _REFERENCE.search(text)
        entry: dict = {
            "status": "provisional",
            "reference": ref_m.group(1) if ref_m else "",
            "governed_values": governed,
        }
        curated = _CAPSULE_FIELD_VALUES.get(current)
        if curated is not None:
            entry["capsule_field_values"] = curated["values"]
            entry["capsule_field_values_source"] = curated["source"]
        entries[current] = entry

    for line in lines:
        h = _PROP_HEADER.match(line)
        if h:
            flush()
            current = h.group(1)
            block = []
        elif current is not None:
            block.append(line)
    flush()
    return entries


def _body_digest(doc: dict) -> str:
    body = {k: v for k, v in doc.items() if k != "snapshot_sha256"}
    return hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def main(argv: list[str]) -> int:
    spb = _find_spb(argv[1] if len(argv) > 1 else None)
    commit = _pinned_commit(spb)

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    # 1) Live-table snapshot: registry.json verbatim, plus provenance envelope.
    live = json.loads((spb / "registry.json").read_text(encoding="utf-8"))
    live_out = {
        "_vendored_from": "action-state-group/scitt-payload-binding",
        "_vendored_source": "registry.json",
        "_vendored_commit": commit,
        "_vendored_note": (
            "Vendored verbatim by scripts/vendor_cpb_registry.py. Do not hand-edit; "
            "re-run against a scitt-payload-binding checkout instead."
        ),
        "registry": live,
    }
    LIVE_OUT.write_text(
        json.dumps(live_out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    # 2) Provisional projection over spec/cpb-provisional-registry.md.
    prov_md_path = spb / "spec" / "cpb-provisional-registry.md"
    projection = (
        _projection_from_markdown(prov_md_path.read_text(encoding="utf-8"))
        if prov_md_path.exists()
        else {}
    )
    prov_doc = {
        "schema_version": "1",
        "_vendored_from": "action-state-group/scitt-payload-binding",
        "_vendored_source": "spec/cpb-provisional-registry.md",
        "_vendored_commit": commit,
        "_vendored_note": (
            "Machine-readable resolver projection of the CPB *provisional* "
            "(Rung 3) Artifact Type entries. Lossy by design: name -> status + "
            "governed closed-set values. The markdown is normative; do not "
            "hand-edit -- re-run scripts/vendor_cpb_registry.py."
        ),
        "provisional_artifact_types": projection,
    }
    prov_doc["snapshot_sha256"] = _body_digest(prov_doc)
    PROVISIONAL_OUT.write_text(
        json.dumps(prov_doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    print(f"wrote {LIVE_OUT}")
    print(f"wrote {PROVISIONAL_OUT} ({len(projection)} provisional type(s))")
    print(f"vendored from scitt-payload-binding@{commit[:12]}")
    for name, e in projection.items():
        gv = ", ".join(f"{k}={v}" for k, v in e["governed_values"].items()) or "(no closed sets)"
        print(f"  - {name}: {gv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
