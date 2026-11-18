//! `history_card/2` of `draft-mih-agent-evidence-request-03` §8.1.2: the
//! positions a card lists. Checking a card in Checkpointed Local Log form
//! is `cll_material::check_history_card_2` (feature `cll`).

use std::collections::BTreeSet;

/// The bounded history card (§8.1.2).
pub const DERIVATION_HISTORY_CARD_2: &str = "history_card/2";

/// The largest window a card may state (§8.1.2).
pub const MAX_WINDOW: u64 = 64;

/// The findings of `cll_material::check_history_card_2`, in check order,
/// as `vectors/evidence-request/history-card-2.json` names them.
pub const FINDINGS: [&str; 10] = [
    "card_malformed",
    "window_out_of_range",
    "positions_not_increasing_from_zero",
    "position_missing",
    "position_unexpected",
    "checkpoint_invalid",
    "checkpoint_shrinks",
    "proof_invalid",
    "receipt_invalid",
    "anchor_mismatch",
];

/// P(n, W) (§8.1.2): 0, n - 2^k for every 2^k <= n, and max(0, n - W + 1)
/// through n, ascending, each once.
pub fn positions(n: u64, window: u64) -> Vec<u64> {
    let mut out = BTreeSet::from([0]);
    let mut step: u64 = 1;
    while step <= n {
        out.insert(n - step);
        match step.checked_mul(2) {
            Some(next) => step = next,
            None => break,
        }
    }
    let start = n.saturating_sub(window.saturating_sub(1));
    if window > 0 {
        out.extend(start..=n);
    }
    out.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::positions;

    #[test]
    fn positions_are_bounded_and_end_at_the_anchor() {
        for n in [1u64, 2, 5, 100, 1023, 1024, 4097, 1_000_000, (1 << 40) + 3] {
            for w in [1u64, 2, 8, 64] {
                let got = positions(n, w);
                assert_eq!(got.first(), Some(&0));
                assert_eq!(got.last(), Some(&n));
                let bound = w as usize + (64 - n.leading_zeros()) as usize + 1;
                assert!(got.len() <= bound, "n {n} w {w}");
            }
        }
        assert_eq!(positions(0, 1), vec![0]);
    }
}
