#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""The smallest honest producer -> verifier round trip.

Build two capsules with the typed builders, seal each (compute its capsule_id),
then run Class-1 verification on the result — the same path a relying party runs.
No web server, no framework: just the library. Run it with:

    cd python && pip install -e . && python ../examples/build_and_verify.py
"""
from agent_action_capsule import (
    AssuranceBlock,
    Capsule,
    Disposition,
    EffectRecord,
    json_digest,
    verify,
)

# Shared envelope identity fields (spec §5.1, all REQUIRED strings).
IDENT = dict(
    spec_version="draft-mih-scitt-agent-action-capsule-00",
    format_version="2",
    operator="ACME-CO",
    developer="agent@v1",
    timestamp="2026-06-14T00:00:00Z",
)


def executed() -> dict:
    """A clean executed action: a human accepted it, the effect confirmed with a
    digest over the observed response (the §5.2 confirmed-effect binding)."""
    capsule = Capsule(
        action_id="po-executed", action_type="decide", **IDENT,
        # response_digest is a JSON-DIGEST over the real response payload:
        effect=EffectRecord(
            status="confirmed", type="write_order",
            response_digest=json_digest({"order_id": "PO-1009", "status": "written"}),
            effect_attestation="gate_executed",
        ),
        assurance=AssuranceBlock("self_attested", "confirmed", "standalone"),
        disposition=Disposition(decision="accept", approver="human",
                                human_disposed=True, verdict_class="executed"),
    )
    return capsule.seal()  # computes capsule_id over the canonical capsule form


def blocked() -> dict:
    """A blocked action: a deterministic constraint stopped it before dispatch, so
    there is no effect and the verdict is `blocked` (effect_mode not_applicable)."""
    capsule = Capsule(
        action_id="po-blocked", action_type="decide", **IDENT,
        assurance=AssuranceBlock("self_attested", "not_applicable", "standalone"),
        disposition=Disposition(decision="reject", approver="policy",
                                human_disposed=False, verdict_class="blocked"),
    )
    return capsule.seal()


if __name__ == "__main__":
    for name, sealed in (("executed", executed()), ("blocked", blocked())):
        result = verify(sealed)  # Class-1 verification; never raises
        print(f"{name}: ok={result.ok}  capsule_id={sealed['capsule_id'][:16]}…  "
              f"effect_mode={result.assurance['effect_mode']}")
        for f in result.findings:
            print(f"    [{f.severity}] check {f.check} {f.code}: {f.detail}")
        assert result.ok, f"{name} should verify"
    print("round trip ok — both capsules sealed and verified")
