# SPDX-License-Identifier: BSD-3-Clause
"""§12 registries, single-sourced from spec/REGISTRY.md."""
from agent_action_capsule import REGISTRY_NAMES, load_registries

# Pinned expectation (the seeded values of §12). The production loader hard-codes
# NONE of these — it parses spec/REGISTRY.md — so this test fails loudly if the
# spec and the code ever drift.
EXPECTED = {
    "verdict_class": {
        "executed", "blocked", "hitl_dispatched", "denied", "timeout", "errored",
        "engine_failure", "deferred", "needs_decision", "expired", "escalated", "resolved",
    },
    "disposition.decision": {"accept", "reject", "needs_input", "deferred"},
    "effect.type": {"write_order", "send_payment"},
    "irreversibility_class": {"two_way", "one_way_recoverable", "one_way_consequential", "one_way_terminal"},
    "effect_attestation": {"gate_executed", "runtime_claimed"},
    "chain.relation": {"supersedes"},
}


def test_six_registries_loaded():
    regs = load_registries()
    assert set(regs) == set(REGISTRY_NAMES) == set(EXPECTED)


def test_seeded_values_match_spec():
    regs = load_registries()
    for name, expected in EXPECTED.items():
        assert set(regs[name]) == expected, name


def test_chain_relation_is_supersedes_only():
    assert set(load_registries()["chain.relation"]) == {"supersedes"}
