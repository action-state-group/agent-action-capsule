# SPDX-License-Identifier: BSD-3-Clause
"""Ledger-grade capsule history: list, verify chain completeness, export verifiable bundle."""

from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

__all__ = [
    "ChainReport",
    "list_capsules",
    "verify_chain_completeness",
    "export_verifiable_bundle",
]


@dataclass
class ChainReport:
    complete: bool
    gaps: list[str] = field(default_factory=list)          # capsule_ids where chain.parent is missing from the window
    epoch_opens: list[str] = field(default_factory=list)   # capsule_ids where chain.relation == "epoch_opens"
    warnings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _read_jsonl(ledger_path: str) -> list[dict]:
    """Read a JSONL file and return parsed records. Returns [] when not found."""
    records: list[dict] = []
    try:
        with open(ledger_path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
    except FileNotFoundError:
        pass
    return records


def _parse_rfc3339(ts: str) -> float | None:
    """Parse an RFC 3339 / ISO-8601 UTC string to a POSIX timestamp.

    Accepts the common forms produced by ``emit()``'s ``_utc_now()``:
    ``2024-01-15T12:00:00Z`` and ``2024-01-15T12:00:00.123456Z``.
    Returns ``None`` when the string cannot be parsed rather than raising.
    """
    if not isinstance(ts, str):
        return None
    # Normalise the trailing offset variants that datetime.fromisoformat
    # handles in Python 3.11+ but not in 3.9/3.10.
    ts = ts.strip()
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except ValueError:
        return None


def _capsule_epoch_id(capsule: dict) -> str | None:
    """Extract epoch_id from a capsule, checking both top-level and
    compute_attestation (the interim location before the identity-epochs work
    lands in emit())."""
    if "epoch_id" in capsule:
        return capsule["epoch_id"]
    ma = capsule.get("model_attestation")
    if isinstance(ma, dict):
        ca = ma.get("compute_attestation")
        if isinstance(ca, dict):
            return ca.get("epoch_id")
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def list_capsules(
    operator: str,
    window_start: str,       # RFC3339 UTC
    window_end: str,         # RFC3339 UTC
    epoch_id: str | None = None,
    ledger_path: str = "capsule_ledger.jsonl",
) -> list[dict]:
    """Return all capsules for the given operator in the time window.

    Filters on the ``operator`` field. If *epoch_id* is given, also filters on
    ``compute_attestation.epoch_id`` (or top-level ``epoch_id`` when present —
    the latter is the target location once the identity-epochs work lands).

    *window_start* / *window_end* filter on the ``created_at`` or ``timestamp``
    field when present.  If a capsule carries neither field it is included
    conservatively (do not exclude capsules just because they lack a timestamp).
    """
    ws = _parse_rfc3339(window_start)
    we = _parse_rfc3339(window_end)

    results: list[dict] = []
    for capsule in _read_jsonl(ledger_path):
        # --- operator filter ---
        if capsule.get("operator") != operator:
            continue

        # --- epoch_id filter ---
        if epoch_id is not None and _capsule_epoch_id(capsule) != epoch_id:
            continue

        # --- timestamp window filter ---
        ts_str = capsule.get("created_at") or capsule.get("timestamp")
        ts_val = _parse_rfc3339(ts_str) if ts_str else None

        if ts_val is not None and ws is not None and we is not None:
            if ts_val < ws or ts_val > we:
                continue
        # No timestamp → include conservatively.

        results.append(capsule)

    return results


def verify_chain_completeness(
    capsules: list[dict],
    epoch_id: str | None = None,
) -> ChainReport:
    """Check that *capsules* form a complete chain (no gaps).

    A *gap* is a capsule whose ``chain.parent_capsule_id`` references a
    ``capsule_id`` NOT in the provided list — unless that capsule itself carries
    ``chain.relation == "epoch_opens"``, which is a legal chain-starter.

    When *epoch_id* is given the list is pre-filtered to capsules matching that
    epoch before completeness is evaluated.
    """
    # Optional epoch-scope narrowing.
    if epoch_id is not None:
        capsules = [
            cap for cap in capsules
            if _capsule_epoch_id(cap) == epoch_id
        ]

    # Build the full set of capsule_ids visible in this window.
    ids_in_window: set[str] = set()
    for cap in capsules:
        cid = cap.get("capsule_id")
        if isinstance(cid, str) and cid:
            ids_in_window.add(cid)

    gaps: list[str] = []
    epoch_opens: list[str] = []
    warnings: list[str] = []

    for cap in capsules:
        cid = cap.get("capsule_id", "<unknown>")
        chain = cap.get("chain")
        if not isinstance(chain, dict):
            # Standalone capsule — not chained, not a gap.
            continue

        relation = chain.get("relation")

        # epoch_opens is a legal chain-start; never a gap.
        if relation == "epoch_opens":
            epoch_opens.append(cid)
            continue

        parent_id = chain.get("parent_capsule_id")
        if isinstance(parent_id, str) and parent_id and parent_id not in ids_in_window:
            gaps.append(cid)

    return ChainReport(
        complete=len(gaps) == 0,
        gaps=gaps,
        epoch_opens=epoch_opens,
        warnings=warnings,
    )


def export_verifiable_bundle(
    capsules: list[dict],
    inclusion_proofs: list[dict] | None = None,
) -> dict:
    """Export a self-contained verifiable bundle.

    Returns::

        {
          "version": "1",
          "capsules": [...],
          "inclusion_proofs": [...] or [],
          "chain_report": ChainReport as dict,
        }

    The bundle is designed to be re-verified by passing ``bundle["capsules"]``
    back through ``verify_chain_completeness()``.
    """
    chain_report = verify_chain_completeness(capsules)
    return {
        "version": "1",
        "capsules": capsules,
        "inclusion_proofs": inclusion_proofs if inclusion_proofs is not None else [],
        "chain_report": dataclasses.asdict(chain_report),
    }
