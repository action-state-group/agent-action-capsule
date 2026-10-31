#!/usr/bin/env python3
"""Minimal stdin/stdout adapter for the CI language interlock.

``seal`` and ``verify`` read a Capsule. ``bundle-produce <kind>`` reads a
producer fixture (``vectors/cross-language/bundle-producer-log.json`` or
``bundle-producer-padded-log.json``) and writes the JCS bytes of the Bundle
``kind`` names in its ``builds``.
``bundle-verify`` reads a Bundle's JSON text and prints its strict verdict.
"""
import json
import sys

from agent_action_capsule import compute_capsule_id, verify

USAGE = "usage: cross_language.py seal|verify|bundle-produce <kind>|bundle-verify|composed-verify"


class _FixtureBackend:
    """A CLL backend (``scan_entries`` and ``load_cll``) over the fixture's log."""

    def __init__(self, log: dict) -> None:
        from datetime import datetime, timezone

        from cll.log import CheckpointState, CllState, Entry

        appended_at = datetime(2026, 10, 19, tzinfo=timezone.utc)
        self._entries = [
            Entry(seq=seq, value=bytes.fromhex(value), appended_at=appended_at)
            for seq, value in enumerate(log["entries"], 1)
        ]
        state, checkpoint = log["state"], log["state"]["checkpoint"]
        self._state = CllState(
            size=state["size"],
            nodes=tuple(bytes.fromhex(node) for node in state["nodes"]),
            indexed_seq=state["indexed_seq"],
            checkpoint=CheckpointState(
                bytes=bytes.fromhex(checkpoint["cose"]),
                size=checkpoint["size"],
                indexed_seq=checkpoint["indexed_seq"],
                peaks=tuple(bytes.fromhex(peak) for peak in checkpoint["peaks"]),
            ),
        )

    def scan_entries(self, after_seq: int, limit: int) -> list:
        return self._entries[after_seq : after_seq + limit]

    def load_cll(self):
        return self._state


class _NotFound(Exception):
    code = "not_found"


class _FixtureRecords:
    """A record store over the fixture's ``records``."""

    def __init__(self, records: dict) -> None:
        from agent_action_capsule.bundle import StoredRecord

        self._held = {
            cid: StoredRecord(bytes.fromhex(r["capsule"]), bytes.fromhex(r["producer_envelope"]))
            for cid, r in records.items()
        }

    def get(self, capsule_id: str):
        if capsule_id not in self._held:
            raise _NotFound(capsule_id)
        return self._held[capsule_id]


class _WithLeafContent:
    """A proof source with the optional ``leaf_content`` capability, over the
    fixture's ``leaf_contents``."""

    def __init__(self, source, contents: dict) -> None:
        self._source, self._contents = source, contents

    def __getattr__(self, name):
        return getattr(self._source, name)

    def leaf_content(self, seq: int):
        return self._contents.get(str(seq))


def bundle_produce(kind: str, fixture: dict) -> int:
    from agent_action_capsule.bundle import build_evidence_bundle, proof_source_from_cll
    from agent_action_capsule.canonical import jcs

    if kind not in fixture["builds"]:
        print(f"unknown bundle kind {kind!r}", file=sys.stderr)
        return 2
    build = fixture["builds"][kind]
    source = proof_source_from_cll(_FixtureBackend(fixture["log"]), _FixtureRecords(fixture["records"]))
    if "leaf_contents" in fixture:
        source = _WithLeafContent(source, fixture["leaf_contents"])
    bundle = build_evidence_bundle(
        source,
        root=fixture["root"],
        interval_from=build["interval_from"],
        closure_depth=build["closure_depth"],
        carry_non_record_leaves=build.get("carry_non_record_leaves", False),
    )
    sys.stdout.buffer.write(jcs(bundle))
    return 0


def bundle_verify(raw: bytes) -> int:
    from agent_action_capsule.bundle import decode_fragment, verify_bundle

    # The Bundle's own strict reader: its URL-fragment decoder over these bytes.
    fragment = base64url(raw.strip())
    try:
        bundle = decode_fragment(fragment)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 1
    print(verify_bundle(bundle, strict=True).verdict)
    return 0


def composed_verify(value: dict) -> int:
    """Read ``{container, controller_bindings, binding_revocations}`` and print
    the container's composed/v1 block as one JCS line: its status, and per join
    the declared and derived state, result and corroboration."""
    from agent_action_capsule.bundle import verify_bundle
    from agent_action_capsule.canonical import jcs
    from agent_action_capsule.composed import ComposedOptions

    options = ComposedOptions(
        controller_bindings=value.get("controller_bindings", []),
        binding_revocations=value.get("binding_revocations", []),
    )
    extensions = verify_bundle(value["container"], composed_options=options).extensions
    composed = next(e.composed for e in extensions if e.composed is not None)
    print(
        jcs(
            {
                "status": composed.status,
                "findings": sorted(composed.findings),
                "joins": [
                    {"members": list(j.members), "declared": j.declared, "derived": j.derived or None,
                     "result": j.result, "corroboration": k.result, "reason": k.reason or None}
                    for j, k in zip(composed.joins, composed.corroboration)
                ],
            }
        ).decode()
    )
    return 0


def base64url(raw: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def main() -> int:
    args = sys.argv[1:]
    if args[:1] == ["bundle-produce"] and len(args) == 2:
        return bundle_produce(args[1], json.load(sys.stdin))
    if args == ["bundle-verify"]:
        return bundle_verify(sys.stdin.buffer.read())
    if args == ["composed-verify"]:
        return composed_verify(json.load(sys.stdin))
    if len(args) != 1 or args[0] not in {"seal", "verify"}:
        print(USAGE, file=sys.stderr)
        return 2
    value = json.load(sys.stdin)
    if args[0] == "seal":
        sealed = dict(value)
        sealed["capsule_id"] = compute_capsule_id(sealed)
        json.dump(sealed, sys.stdout, sort_keys=True, separators=(",", ":"))
        sys.stdout.write("\n")
        return 0
    result = verify(value)
    if not result.ok:
        print(", ".join(finding.code for finding in result.findings), file=sys.stderr)
        return 1
    print(result.capsule_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
