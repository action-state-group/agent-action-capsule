# SPDX-License-Identifier: BSD-3-Clause
"""§12 registries, single-sourced from spec/REGISTRY.md.

Freeze-guard: the EXACT seeded value set (count AND membership) for every one of
the six registries is pinned here against a hard-coded expectation. The
production loader hard-codes NONE of these — it parses spec/REGISTRY.md — so a
future REGISTRY.md reflow that drops, adds, or mangles a value (including across
a line wrap) fails this test loudly instead of silently shrinking a vocabulary.
"""
from pathlib import Path

from agent_action_capsule import REGISTRY_NAMES, load_registries

# Pinned expectation = the seeded values of §12, verbatim.
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
# Pinned counts (the freeze surface — a dropped value changes the count).
EXPECTED_COUNTS = {
    "verdict_class": 12,
    "disposition.decision": 4,
    "effect.type": 2,
    "irreversibility_class": 4,
    "effect_attestation": 2,
    "chain.relation": 1,
}


def test_six_registries_loaded():
    regs = load_registries()
    assert set(regs) == set(REGISTRY_NAMES) == set(EXPECTED)


def test_seeded_values_exact_membership_and_count():
    regs = load_registries()
    for name, expected in EXPECTED.items():
        loaded = set(regs[name])
        assert len(loaded) == EXPECTED_COUNTS[name], f"{name}: count {len(loaded)} != {EXPECTED_COUNTS[name]}"
        assert loaded == expected, f"{name}: {loaded ^ expected}"


def test_chain_relation_is_supersedes_only():
    assert set(load_registries()["chain.relation"]) == {"supersedes"}


# --- Parser robustness: multi-line continuation for every locus shape -------
# The effect.type bug (a wrapped inline list dropping `send_payment`) must not
# recur in ANY registry. This synthetic REGISTRY.md wraps the inline-list and
# ordered-list forms across lines and asserts the loader still reads the full
# set. Each registry uses a different markdown locus (table / inline list /
# ordered list) so all three extraction paths are exercised under wrapping.
SYNTHETIC = """# Registries of record

## 1. `verdict_class`
Defined somewhere. Initial contents:

| Value | Semantics |
|---|---|
| `executed` | ran |
| `blocked` | stopped |

## 2. `disposition.decision`
Initial contents: `accept`, `reject`,
`needs_input`,
`deferred`.

## 3. `effect.type`
Defined in §5.2 (Effect Record and the confirmed-effect
binding). Initial contents (seeded examples): `write_order`,
`send_payment`.

## 4. `irreversibility_class`
An ordered vocabulary. Initial contents, in
order:

1. `two_way`
2. `one_way_recoverable`
3. `one_way_consequential`
4. `one_way_terminal`

## 5. `effect_attestation`
Prose mentioning `runtime_claimed` and `effect.status` in guidance. Initial contents:

| Value | Semantics |
|---|---|
| `gate_executed` | observed |
| `runtime_claimed` | claimed |

## 6. `chain.relation`
Defined in §5.4.4. Initial contents:

| Value | Semantics |
|---|---|
| `supersedes` | terminal |
"""


def test_parser_handles_multiline_wrapping(tmp_path: Path):
    p = tmp_path / "REGISTRY.md"
    p.write_text(SYNTHETIC, encoding="utf-8")
    regs = load_registries(path=p)
    # the wrapped inline lists must come through complete
    assert set(regs["disposition.decision"]) == {"accept", "reject", "needs_input", "deferred"}
    assert set(regs["effect.type"]) == {"write_order", "send_payment"}  # the wrapped-line bug
    assert set(regs["irreversibility_class"]) == {
        "two_way", "one_way_recoverable", "one_way_consequential", "one_way_terminal"
    }
    # prose backticks in the effect_attestation section must NOT leak in
    assert set(regs["effect_attestation"]) == {"gate_executed", "runtime_claimed"}
    assert set(regs["chain.relation"]) == {"supersedes"}
