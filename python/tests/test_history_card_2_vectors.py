# SPDX-License-Identifier: Apache-2.0
"""vectors/evidence-request/history-card-2.json against agent_action_capsule.history_card."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from agent_action_capsule import history_card as hc  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
CORPUS = json.loads((ROOT / "vectors" / "evidence-request" / "history-card-2.json").read_text("utf-8"))


def test_corpus_header() -> None:
    assert CORPUS["draft"] == "draft-mih-agent-evidence-request-03"
    assert CORPUS["findings"] == list(hc.FINDINGS)
    assert CORPUS["max_window"] == hc.MAX_WINDOW
    assert CORPUS["count"] == len(CORPUS["cases"])


@pytest.mark.parametrize("row", CORPUS["positions"], ids=lambda r: f"n{r['n']}-w{r['window']}")
def test_positions(row: dict) -> None:
    assert hc.positions(row["n"], row["window"]) == row["positions"]


@pytest.mark.parametrize("case", CORPUS["cases"], ids=lambda c: c["id"])
def test_case(case: dict) -> None:
    finding = hc.check_history_card_2(case["card"], case["anchor"], CORPUS["log_keys"])
    assert finding == case["expect"]["finding"]
    assert (finding is None) == case["expect"]["valid"]


def test_every_finding_has_a_case() -> None:
    assert {c["expect"]["finding"] for c in CORPUS["cases"]} - {None} == set(hc.FINDINGS)


def test_a_valid_card_spans_more_than_1024_checkpoints() -> None:
    big = [c for c in CORPUS["cases"] if c["expect"]["valid"] and c["card"]["history"][-1]["position"] >= 1024]
    assert big, "acceptance (4): one valid card over more than 1024 checkpoints"


@pytest.mark.parametrize("n", [1, 2, 5, 100, 1023, 1024, 4097, 10**6, 2**40 + 3])
@pytest.mark.parametrize("window", [1, 2, 8, 64])
def test_positions_are_bounded_and_end_at_the_anchor(n: int, window: int) -> None:
    got = hc.positions(n, window)
    assert got[0] == 0 and got[-1] == n and got == sorted(set(got))
    assert len(got) <= window + n.bit_length() + 1  # W + floor(log2 n) + 2
    assert set(range(max(0, n - window + 1), n + 1)) <= set(got)
    assert {n - (1 << k) for k in range(n.bit_length()) if (1 << k) <= n} <= set(got)


def test_unaccepted_log_key_fails() -> None:
    case = next(c for c in CORPUS["cases"] if c["id"] == "valid-1100-checkpoints")
    assert hc.check_history_card_2(case["card"], case["anchor"], []) == "checkpoint_invalid"


def test_positions_rejects_negative() -> None:
    with pytest.raises(ValueError):
        hc.positions(-1, 8)
