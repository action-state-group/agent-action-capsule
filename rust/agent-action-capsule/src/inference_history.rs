//! The inference-service history profile, Standard level
//! (`spec/inference-service-history-profile-v0.md`, cited as ISH): the
//! derivation of a Standard History's `period_counts` and artifact, and the
//! verifier's checks over one.
//!
//! A Standard History is the `history_card/1` artifact embedded unchanged and
//! a node's served exchanges counted per closed period, under a
//! `period_policy` (periods from an epoch, a floor under which a cell is
//! withheld, complementary suppression) that a Standard *definition* document
//! fixes (ISH §4.1). Nothing here is bound to one node's definition: every
//! function takes the [`Definition`] it works under, which
//! [`Definition::from_document`] checks against ISH §8.3 `definition_form`.
//!
//! **Deriving.** [`period_counts`] counts over the stream's checkpoints and
//! [`artifact`] builds ISH §8.2's object as its RFC 8785 octets, which depend
//! only on (subject, anchor, definition). A request that is no run of whole
//! closed periods at a pinned anchor is the caller's refusal; an anchor off a
//! boundary is [`Refusal::PolicyDeclined`] here, the same for every requester.
//!
//! **Checking.** [`check_artifact`] checks one artifact against the card it
//! embeds, whose checkpoints the caller has already checked (signatures,
//! consistency proofs, witness receipts): the members, `history_card_digest`,
//! the coverage declaration (ISH §4.2), and `period_alignment`,
//! `period_anchor` and `period_floor` (ISH §6.3). `period_fixed` compares two
//! Histories and is the caller's, over two [`Counts`].
//!
//! **Verdict counts.** A definition may carry the optional `verdict_counts`
//! member (ISH §4.3, §5.3), counting `referee_verdicts` over the same periods:
//! [`verdict_counts`] derives it, [`artifact_with_verdicts`] builds the artifact
//! that declares it, and [`check_artifact`] checks it, each result of
//! [`VERDICT_RESULTS`] as a floor table of its own, one cell per model hash and
//! a total. The member names its kind of check (`referee_verdict`) and that the
//! checker signs it. Which verdicts qualify is the caller's, from its own log.
//!
//! **Profile version.** A definition names `inference-service-history/0`
//! (frozen) or `/1` ([`PROFILE_V0`], [`PROFILE_V1`]). They differ in one
//! rule: under `/1`, `period_counts` withholds its total as `complementary`
//! where two or more models are withheld under the floor and the total fixes
//! each of them (ISH1 §6.2 item 3.2, SH-8), the rule the verdict tables already
//! follow; deriving applies it and `period_floor` rejects a total published
//! there. Under `/0` both stay as they were.
//!
//! **Which period a record is in.** The one the first checkpoint covering it
//! commits into (ISH §6.1). A checkpoint commits into the period holding its
//! time, except the first checkpoint at a boundary, which commits into the
//! period it ends. Checkpoint times are taken as never going back, so no
//! checkpoint after the one that closed a period adds to it.

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

/// The token of the embedded card's derivation.
const DERIVATION_HISTORY_CARD: &str = "history_card/1";

/// The profile a definition names: `/0`, frozen, or `/1`, which also
/// withholds a `period_counts` total that gives two or more withheld models
/// away (ISH1 §6.2 item 3.2, SH-8).
pub const PROFILE_V0: &str = "inference-service-history/0";
/// See [`PROFILE_V0`].
pub const PROFILE_V1: &str = "inference-service-history/1";

/// Why a History cannot be derived at this anchor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The anchor is not a period boundary (ISH §6.1 item 2), the same for
    /// every requester.
    PolicyDeclined,
    /// A limit or fault of the deriving node's own: a time that does not
    /// parse, a stream older than the most periods one answer lists, or a
    /// card that is not in canonical form.
    CapacityExceeded,
}

/// RFC 8785 text of `v`.
fn jcs_text(v: &Value) -> Result<String, ()> {
    let octets = crate::canonical::jcs(v).map_err(|_| ())?;
    String::from_utf8(octets).map_err(|_| ())
}

/// A definition's `period_policy` (ISH §6.1): the periods and the floor its
/// counts are checked against. A checker takes it from the definition it
/// is handed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    /// The start of period 0, in Unix seconds.
    pub epoch: i64,
    /// The period length in seconds.
    pub length_s: i64,
    /// The shortest length the policy allows.
    pub min_length_s: i64,
    /// The count below which a cell is withheld.
    pub floor: u64,
}

impl Policy {
    /// The policy of `definition`, or why its `period_policy` is not ISH
    /// §4.1's: exactly `epoch`, `length_s`, `min_length_s`, `floor` and
    /// `suppression` (`complementary`), a whole-second UTC epoch, positive
    /// integers, and `length_s` at least `min_length_s`.
    pub fn from_definition(definition: &Value) -> Result<Policy, String> {
        let bad = |why: &str| format!("definition_form: period_policy: {why}");
        let p = definition
            .get("period_policy")
            .and_then(Value::as_object)
            .ok_or_else(|| bad("missing"))?;
        let mut keys: Vec<&str> = p.keys().map(String::as_str).collect();
        keys.sort_unstable();
        if keys != ["epoch", "floor", "length_s", "min_length_s", "suppression"] {
            return Err(bad("not exactly the members §4.1 names"));
        }
        if p["suppression"] != json!("complementary") {
            return Err(bad("suppression is not complementary"));
        }
        let count = |name: &str| {
            p[name]
                .as_u64()
                .filter(|&n| n > 0 && n <= i64::MAX as u64)
                .ok_or_else(|| bad(&format!("{name} is not a positive integer")))
        };
        let (length_s, min_length_s, floor) =
            (count("length_s")?, count("min_length_s")?, count("floor")?);
        if length_s < min_length_s {
            return Err(bad("length_s is under min_length_s"));
        }
        let epoch = p["epoch"]
            .as_str()
            .filter(|e| e.ends_with('Z'))
            .and_then(unix_time)
            .filter(|&t| profile_time(t).as_deref() == p["epoch"].as_str())
            .ok_or_else(|| bad("epoch is not a whole-second UTC time"))?;
        Ok(Policy {
            epoch,
            length_s: length_s as i64,
            min_length_s: min_length_s as i64,
            floor,
        })
    }

    /// The period holding the Unix time `t`.
    pub fn period_of(&self, t: i64) -> i64 {
        (t - self.epoch).div_euclid(self.length_s)
    }

    /// The start of period `k`, or `None` past what a Unix time holds.
    pub fn start_of(&self, k: i64) -> Option<i64> {
        k.checked_mul(self.length_s)
            .and_then(|n| n.checked_add(self.epoch))
    }

    /// Whether the Unix time `t` is a period boundary.
    pub fn on_boundary(&self, t: i64) -> bool {
        (t - self.epoch).rem_euclid(self.length_s) == 0
    }

    /// Whether the checkpoint time `timestamp` is a period boundary: a whole
    /// second that starts a period (ISH §6.1 item 2).
    pub fn is_boundary(&self, timestamp: &str) -> bool {
        evidence_request::time::parse_utc(timestamp)
            .is_some_and(|t| t.nanos == 0 && self.on_boundary(t.seconds))
    }
}

/// The one counts member and the one unit it counts in.
const COUNTS: &str = "period_counts";
const UNIT: &str = "exchanges_served";
const LABEL: &str = "self_reported";

/// The optional verdict counts member (ISH §4.3, §5.3), its unit and the one
/// kind of check it counts today.
const VERDICTS: &str = "verdict_counts";
const VERDICT_UNIT: &str = "referee_verdicts";
const VERDICT_CHECK: &str = "referee_verdict";
const VERDICT_SIGNER: &str = "checker";
/// The four results of a referee verdict, in the order cells are listed
/// (ISH §5.3).
pub const VERDICT_RESULTS: [&str; 4] = [
    "corroborated",
    "contradicted",
    "inconclusive",
    "not_comparable",
];

/// The members an artifact declares, sorted: with or without the verdict
/// counts its definition carries.
const DECLARED: [&str; 2] = ["history_card", COUNTS];
const DECLARED_WITH_VERDICTS: [&str; 3] = ["history_card", COUNTS, VERDICTS];

/// The keys of every artifact, sorted.
const KEYS: [&str; 9] = [
    "anchor",
    "coverage_declaration",
    "declared",
    "derivation",
    "evidence_stream",
    "history_card",
    "history_card_digest",
    COUNTS,
    "subject",
];
const KEYS_WITH_VERDICTS: [&str; 10] = [
    "anchor",
    "coverage_declaration",
    "declared",
    "derivation",
    "evidence_stream",
    "history_card",
    "history_card_digest",
    COUNTS,
    "subject",
    VERDICTS,
];

/// The most periods one answer lists: over 190 years of weeks. A stream
/// whose first checkpoint is older is refused, never answered in part.
const MAX_PERIODS: i64 = 10_000;

/// A Standard definition a deriver or checker is handed: its digests and
/// policy.
#[derive(Debug)]
pub struct Definition {
    verdicts: bool,
    strict_counts: bool,
    policy: Policy,
    digest: String,
    policy_digest: String,
}

impl Definition {
    /// The definition at `document`, or the `definition_form` rule (ISH
    /// §8.3) it breaks: exactly the members of §4.1 for the Standard level,
    /// with the values it fixes, `reads` the union of the members' `reads`,
    /// and a `period_policy` that conforms.
    pub fn from_document(document: &Value) -> Result<Definition, String> {
        let bad = |why: &str| format!("definition_form: {why}");
        let d = document.as_object().ok_or_else(|| bad("not an object"))?;
        let mut keys: Vec<&str> = d.keys().map(String::as_str).collect();
        keys.sort_unstable();
        if keys
            != [
                "coverage_declaration",
                "embeds",
                "excludes",
                "kind",
                "level",
                "members",
                "name",
                "period_policy",
                "profile",
                "reads",
                "spec",
                "subjects",
            ]
        {
            return Err(bad("not exactly the members of a Standard definition"));
        }
        let strict_counts = d["profile"] == json!(PROFILE_V1);
        if !(strict_counts || d["profile"] == json!(PROFILE_V0))
            || d["kind"] != json!("projection")
            || d["level"] != json!("standard")
            || d["embeds"] != json!(["history_card/1"])
            || d["subjects"] != json!(["full_history"])
            || d["coverage_declaration"]
                != json!({"kind": "stream_interval", "rule": "all_records"})
            || !d["name"].as_str().is_some_and(is_definition_name)
            || !d["spec"].is_string()
        {
            return Err(bad("a member does not have the value the profile fixes"));
        }
        if !d["excludes"]
            .as_array()
            .is_some_and(|e| e.contains(&json!("requester identity")))
        {
            return Err(bad("excludes does not name requester identity"));
        }
        let members = d["members"]
            .as_array()
            .filter(|m| !m.is_empty())
            .ok_or_else(|| bad("no members"))?;
        let mut union: Vec<&Value> = Vec::new();
        let mut names: Vec<&str> = Vec::new();
        for member in members {
            let name = member["name"]
                .as_str()
                .ok_or_else(|| bad("a member has no name"))?;
            if names.contains(&name) || !member["required"].is_boolean() {
                return Err(bad("a member is listed twice or has no `required`"));
            }
            names.push(name);
            for read in member["reads"]
                .as_array()
                .ok_or_else(|| bad("a member has no reads"))?
            {
                if !union.contains(&read) {
                    union.push(read);
                }
            }
        }
        // This module derives and checks the form with exactly these two
        // members (the counts members' shapes are the host's, ISH §4.3), the
        // counts declaring their one unit.
        let mut sorted = names.clone();
        sorted.sort_unstable();
        let counts_unit = json!([{"where": "periods[].cells[]", "unit": UNIT}]);
        let verdicts = sorted == ["history_card", COUNTS, VERDICTS];
        if !(verdicts || sorted == ["history_card", COUNTS])
            || members
                .iter()
                .find(|m| m["name"] == json!(COUNTS))
                .is_none_or(|m| m["units"] != counts_unit || m["required"] != json!(true))
        {
            return Err(bad(
                "members are not a required history_card and a required period_counts counting exchanges_served, with an optional verdict_counts",
            ));
        }
        if verdicts
            && !members.iter().any(|m| {
                m["name"] == json!(VERDICTS)
                    && m["required"] == json!(true)
                    && m["units"] == json!([{"where": "periods[].cells[]", "unit": VERDICT_UNIT}])
            })
        {
            return Err(bad(
                "verdict_counts is not a required member counting referee_verdicts",
            ));
        }
        let history_card = members.iter().find(|m| m["name"] == json!("history_card"));
        if !history_card.is_some_and(|m| {
            m["required"] == json!(true) && m["derivation"] == json!(DERIVATION_HISTORY_CARD)
        }) {
            return Err(bad("history_card is not a required member"));
        }
        if d["reads"].as_array().map(|r| r.iter().collect::<Vec<_>>()) != Some(union) {
            return Err(bad("reads is not the union of the members' reads"));
        }
        let policy = Policy::from_definition(document)?;
        let digest_of = |v: &Value| {
            jcs_text(v)
                .map(|text| hex::encode(Sha256::digest(text.as_bytes())))
                .map_err(|_| bad("not canonicalizable"))
        };
        Ok(Definition {
            verdicts,
            strict_counts,
            policy,
            digest: digest_of(document)?,
            policy_digest: digest_of(&document["period_policy"])?,
        })
    }

    /// Whether an answer pinned to a checkpoint with time `timestamp` is
    /// `policy_declined`: only a period boundary is answered (ISH §6.1
    /// item 2).
    pub fn declines_anchor(&self, timestamp: &str) -> bool {
        !self.policy.is_boundary(timestamp)
    }

    /// The digest that names the definition on the wire.
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Whether the definition carries the `verdict_counts` member (ISH §4.3).
    pub fn has_verdict_counts(&self) -> bool {
        self.verdicts
    }

    /// Whether `period_counts` withholds a total that gives two or more
    /// withheld models away, as the verdict tables always do: true under
    /// `inference-service-history/1` (ISH1 §6.2 item 3.2), false under the
    /// frozen `/0`.
    pub fn strict_counts(&self) -> bool {
        self.strict_counts
    }

    /// The digest of the definition's `period_policy`, which the counts name.
    pub fn policy_digest(&self) -> &str {
        &self.policy_digest
    }

    /// The definition's `period_policy`.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// The first period boundary strictly after the Unix time `t`, or `None`
    /// past what a Unix time holds.
    pub fn next_boundary_after(&self, t: i64) -> Option<i64> {
        self.policy.start_of(self.policy.period_of(t) + 1)
    }
}

/// A definition `name`: lowercase ASCII letters, digits and `_`, then `/`
/// and a version number (ISH §4.1).
fn is_definition_name(name: &str) -> bool {
    name.split_once('/').is_some_and(|(stem, version)| {
        !stem.is_empty()
            && stem
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            && !version.is_empty()
            && version.bytes().all(|b| b.is_ascii_digit())
    })
}

/// A checkpoint time (`YYYY-MM-DDTHH:MM:SS[.f]Z`) in Unix seconds.
pub fn unix_time(timestamp: &str) -> Option<i64> {
    evidence_request::time::parse_utc(timestamp).map(|t| t.seconds)
}

/// A Unix time in the profile's form, `YYYY-MM-DDTHH:MM:SSZ` (IP §5.2), or
/// `None` before year 0001 or after year 9999.
fn profile_time(t: i64) -> Option<String> {
    if !(-62_135_596_800..=253_402_300_799).contains(&t) {
        return None;
    }
    let (days, rem) = (t.div_euclid(86_400), t.rem_euclid(86_400));
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3_600,
        rem % 3_600 / 60,
        rem % 60
    ))
}

// ---------------------------------------------------------------------
// Responder
// ---------------------------------------------------------------------

/// One checkpoint of the chain an answer reads: its time and the records
/// it covers (its leaf count).
pub struct Cut<'a> {
    pub timestamp: &'a str,
    pub leaves: u64,
}

/// The `period_counts` member at the anchor `chain.last()`. `chain` is the
/// stream's checkpoints from its first to the anchor, and `model(i)` the
/// model the record at leaf `i` states it served, `None` for a record that
/// is not a served exchange. `policy_declined` when the anchor is not at a
/// period boundary (ISH §6.1 item 2, the same for every requester);
/// `capacity_exceeded`, a limit or fault of the deriving node's own, when a
/// time does not parse or the stream is older than [`MAX_PERIODS`] periods.
pub fn period_counts(
    def: &Definition,
    chain: &[Cut<'_>],
    model: &dyn Fn(u64) -> Option<String>,
) -> Result<Value, Refusal> {
    let (first_period, counted) = count_periods(def, chain, model)?;
    let rows = counted
        .iter()
        .map(|by_model| cells(by_model, def.policy.floor, def.strict_counts))
        .collect();
    period_list(def, first_period, rows)
}

/// The `verdict_counts` member at the anchor `chain.last()` (ISH §5.3), over
/// the same periods as [`period_counts`]. `verdict(i)` is the `(model_hash,
/// result)` the verdict held at leaf `i` gives, `None` for a record that is
/// no qualifying verdict; `result` is one of [`VERDICT_RESULTS`], and
/// a record naming another is not counted. Each result is its own table of
/// one cell per model hash and one total, suppressed under ISH §6.2; no
/// total across results is listed. The member names the one kind of check it
/// counts and that its result is signed by the checker.
pub fn verdict_counts(
    def: &Definition,
    chain: &[Cut<'_>],
    verdict: &dyn Fn(u64) -> Option<(String, String)>,
) -> Result<Value, Refusal> {
    let keyed = |leaf: u64| verdict(leaf).filter(|(_, r)| VERDICT_RESULTS.contains(&r.as_str()));
    let (first_period, counted) = count_periods(def, chain, &keyed)?;
    let rows = counted
        .iter()
        .map(|by| {
            VERDICT_RESULTS
                .iter()
                .flat_map(|result| {
                    let models: std::collections::BTreeMap<String, u64> = by
                        .iter()
                        .filter(|((_, r), _)| r == result)
                        .map(|((m, _), &n)| (m.clone(), n))
                        .collect();
                    verdict_cells(&models, def.policy.floor, result)
                })
                .collect()
        })
        .collect();
    let mut member = period_list(def, first_period, rows)?;
    member["check"] = json!(VERDICT_CHECK);
    member["signed_by"] = json!(VERDICT_SIGNER);
    Ok(member)
}

/// Per counted period, the number of records for each key `key(leaf)` gives.
/// Returns the first counted period too. `policy_declined` and
/// `capacity_exceeded` as [`period_counts`] states.
fn count_periods<K: Ord>(
    def: &Definition,
    chain: &[Cut<'_>],
    key: &dyn Fn(u64) -> Option<K>,
) -> Result<(i64, Vec<std::collections::BTreeMap<K, u64>>), Refusal> {
    let policy = &def.policy;
    let anchor = chain.last().ok_or(Refusal::CapacityExceeded)?;
    if !policy.is_boundary(anchor.timestamp) {
        return Err(Refusal::PolicyDeclined);
    }
    let anchor_period =
        policy.period_of(unix_time(anchor.timestamp).ok_or(Refusal::CapacityExceeded)?);
    let last_counted = anchor_period - 1;
    let commits = commit_periods(policy, chain).ok_or(Refusal::CapacityExceeded)?;
    // The first period is the one that holds the stream's first record, and
    // none is listed when no checkpoint commits one (ISH §6.1 item 3).
    let first_period = first_record_period(chain, &commits).unwrap_or(last_counted + 1);
    if last_counted - first_period >= MAX_PERIODS {
        return Err(Refusal::CapacityExceeded);
    }
    let periods = (first_period..=last_counted).count();
    let mut counted: Vec<std::collections::BTreeMap<K, u64>> =
        (0..periods).map(|_| Default::default()).collect();
    let mut from_leaf = 0u64;
    for (cut, &k) in chain.iter().zip(&commits) {
        for leaf in from_leaf..cut.leaves {
            if k > last_counted {
                break;
            }
            if let Some(m) = key(leaf) {
                *counted[(k - first_period) as usize].entry(m).or_default() += 1;
            }
        }
        from_leaf = from_leaf.max(cut.leaves);
    }
    Ok((first_period, counted))
}

/// `{policy, periods}` over the periods from `first_period`, `rows[i]` the
/// cells of the i-th.
fn period_list(
    def: &Definition,
    first_period: i64,
    rows: Vec<Vec<Value>>,
) -> Result<Value, Refusal> {
    let policy = &def.policy;
    let mut list = Vec::with_capacity(rows.len());
    for (i, row) in rows.into_iter().enumerate() {
        let k = first_period + i as i64;
        let (Some(from), Some(to)) = (period_time(policy, k), period_time(policy, k + 1)) else {
            return Err(Refusal::CapacityExceeded);
        };
        list.push(json!({"from": from, "to": to, "cells": row}));
    }
    Ok(json!({"policy": def.policy_digest, "periods": list}))
}

/// The start of period `k` in the profile's time form.
fn period_time(policy: &Policy, k: i64) -> Option<String> {
    policy.start_of(k).and_then(profile_time)
}

/// The period each checkpoint of `chain` commits its records into, or `None`
/// when a time does not parse. A checkpoint commits into the period holding
/// its time, taken as never earlier than the one before; the first
/// checkpoint at a boundary commits into the period it closes, and every
/// period before its time is closed from then on (ISH §6.1 item 2).
fn commit_periods(policy: &Policy, chain: &[Cut<'_>]) -> Option<Vec<i64>> {
    let (mut committed_at, mut closed) = (i64::MIN, i64::MIN);
    let mut periods = Vec::with_capacity(chain.len());
    for cut in chain {
        committed_at = committed_at.max(unix_time(cut.timestamp)?);
        let mut k = policy.period_of(committed_at);
        if policy.on_boundary(committed_at) && k - 1 > closed {
            k -= 1;
        }
        closed = closed.max(policy.period_of(committed_at) - 1);
        periods.push(k);
    }
    Some(periods)
}

/// The period holding the stream's first record: the one the first
/// checkpoint that commits a record commits into.
fn first_record_period(chain: &[Cut<'_>], commits: &[i64]) -> Option<i64> {
    chain
        .iter()
        .zip(commits)
        .find(|(cut, _)| cut.leaves > 0)
        .map(|(_, &k)| k)
}

/// Each model's count, then the total, with what is withheld and why
/// (ISH §6.2): below the floor, and complementary where a published total
/// beside exactly one suppressed model would give that model away.
fn suppress(
    by_model: &std::collections::BTreeMap<String, u64>,
    floor: u64,
    strict: bool,
) -> Vec<(Option<&str>, u64, Option<&'static str>)> {
    let total: u64 = by_model.values().sum();
    let mut values: Vec<(Option<&str>, u64, Option<&'static str>)> = by_model
        .iter()
        .map(|(m, &n)| (Some(m.as_str()), n, (n < floor).then_some("below_floor")))
        .collect();
    values.push((None, total, (total < floor).then_some("below_floor")));
    let models = values.len() - 1;
    let suppressed = values[..models].iter().filter(|c| c.2.is_some()).count();
    // A published total beside exactly one suppressed model gives that
    // model away: the smallest other published model goes with it.
    if values[models].2.is_none() && suppressed == 1 {
        if let Some(smallest) = values[..models]
            .iter_mut()
            .filter(|c| c.2.is_none())
            .min_by_key(|c| c.1)
        {
            smallest.2 = Some("complementary");
        }
    }
    // Strict (the verdict tables, and `period_counts` under `/1`): two or
    // more models withheld under the floor beside a published total, whose
    // rest is nothing, 1 each or every one at the largest count a withheld
    // cell can hold, are each given away by the total, so the total goes too.
    if strict && values[models].2.is_none() {
        let hidden: Vec<u64> = values[..models]
            .iter()
            .filter(|c| c.2.is_some())
            .map(|c| c.1)
            .collect();
        let all_below = values[..models]
            .iter()
            .all(|c| c.2.is_none() || c.2 == Some("below_floor"));
        let rest = values[models].1
            - values[..models]
                .iter()
                .filter(|c| c.2.is_none())
                .map(|c| c.1)
                .sum::<u64>();
        if all_below && derivable(hidden.len(), rest, floor) {
            values[models].2 = Some("complementary");
        }
    }
    values
}

/// Whether `n` models withheld under `floor`, together holding `rest`, are
/// each given away by it: every one holds at least 1 (a model is listed only
/// when it has a record counted) and under `floor`, so `rest` of nothing, of 1 each
/// or of the most each can hold fixes them all.
fn derivable(n: usize, rest: u64, floor: u64) -> bool {
    let (n, rest, most) = (
        n as u128,
        u128::from(rest),
        u128::from(floor.saturating_sub(1)),
    );
    n >= 2 && (rest == 0 || rest == n || rest == n * most)
}

fn cell_json(dimension: Value, unit: &str, n: u64, why: Option<&str>) -> Value {
    let mut cell = json!({
        "dimension": dimension,
        "label": LABEL,
        "unit": unit,
        "value": if why.is_some() { Value::Null } else { json!(n) },
    });
    if let Some(why) = why {
        cell["suppressed"] = json!(why);
    }
    cell
}

/// One period's cells: one per model, by name, then the total, each
/// suppressed under ISH §6.2; `strict` under `/1` (ISH1 §6.2 item 3.2).
fn cells(
    by_model: &std::collections::BTreeMap<String, u64>,
    floor: u64,
    strict: bool,
) -> Vec<Value> {
    suppress(by_model, floor, strict)
        .into_iter()
        .map(|(model, n, why)| {
            cell_json(
                model.map(|m| json!({"model": m})).unwrap_or(Value::Null),
                UNIT,
                n,
                why,
            )
        })
        .collect()
}

/// One result's cells in a verdict period: one per model hash, then the
/// result's total (`dimension` `{"result": r}`), suppressed as [`cells`] are.
fn verdict_cells(
    by_model: &std::collections::BTreeMap<String, u64>,
    floor: u64,
    result: &str,
) -> Vec<Value> {
    suppress(by_model, floor, true)
        .into_iter()
        .map(|(model, n, why)| {
            let dimension = match model {
                Some(m) => json!({"model_hash": m, "result": result}),
                None => json!({"result": result}),
            };
            cell_json(dimension, VERDICT_UNIT, n, why)
        })
        .collect()
}

/// The artifact's octets: `card` is the direct `history_card/1` artifact's
/// octets at `anchor`, `counts` the `period_counts` member, and `log_size`
/// the records the anchor covers. `capacity_exceeded` when the card's octets
/// are not its own canonical form, so the embedded card could not be the
/// direct one.
pub fn artifact(
    def: &Definition,
    card: &[u8],
    counts: Value,
    anchor: &str,
    stream: &str,
    log_size: u64,
) -> Result<Vec<u8>, Refusal> {
    if def.verdicts {
        return Err(Refusal::CapacityExceeded);
    }
    build_artifact(def, card, counts, None, anchor, stream, log_size)
}

/// [`artifact`] for a definition that carries `verdict_counts`: `verdicts` is
/// that member (see [`verdict_counts`]). `capacity_exceeded` when the
/// definition carries no such member, so one artifact never declares a member
/// its definition does not.
pub fn artifact_with_verdicts(
    def: &Definition,
    card: &[u8],
    counts: Value,
    verdicts: Value,
    anchor: &str,
    stream: &str,
    log_size: u64,
) -> Result<Vec<u8>, Refusal> {
    if !def.verdicts {
        return Err(Refusal::CapacityExceeded);
    }
    build_artifact(def, card, counts, Some(verdicts), anchor, stream, log_size)
}

fn build_artifact(
    def: &Definition,
    card: &[u8],
    counts: Value,
    verdicts: Option<Value>,
    anchor: &str,
    stream: &str,
    log_size: u64,
) -> Result<Vec<u8>, Refusal> {
    let card_value: Value = serde_json::from_slice(card).map_err(|_| Refusal::CapacityExceeded)?;
    if jcs_text(&card_value)
        .map_err(|_| Refusal::CapacityExceeded)?
        .as_bytes()
        != card
    {
        return Err(Refusal::CapacityExceeded);
    }
    let card_text = jcs_text(&card_value).map_err(|_| Refusal::CapacityExceeded)?;
    let declared: &[&str] = if verdicts.is_some() {
        &DECLARED_WITH_VERDICTS
    } else {
        &DECLARED
    };
    let mut art = json!({
        "anchor": anchor,
        "coverage_declaration": coverage_declaration(anchor, stream, log_size),
        "declared": declared,
        "derivation": def.digest(),
        "evidence_stream": stream,
        "history_card": card_value,
        "history_card_digest": hex::encode(Sha256::digest(card_text.as_bytes())),
        COUNTS: counts,
        "subject": {"full_history": null},
    });
    if let Some(verdicts) = verdicts {
        art[VERDICTS] = verdicts;
    }
    jcs_text(&art)
        .map(String::into_bytes)
        .map_err(|_| Refusal::CapacityExceeded)
}

/// The anchor-dependent half of the Standard coverage declaration
/// (ISH §4.2).
fn coverage_declaration(anchor: &str, stream: &str, log_size: u64) -> Value {
    json!({
        "interval": {"from": null, "to": anchor},
        "kind": "stream_interval",
        "live_set": [{"checkpoint": anchor, "count": log_size, "start": 0, "stream": stream}],
        "rule": "all_records",
    })
}

// ---------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------

/// One checked cell.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cell {
    /// The model the provider states, `None` for the period's total.
    pub model: Option<String>,
    /// The count, or why it is suppressed.
    pub value: Result<u64, String>,
}

/// One checked period.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Period {
    pub from: String,
    pub to: String,
    pub cells: Vec<Cell>,
}

/// One checked verdict cell: a result and, but for the result's total, the
/// model hash it counts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerdictCell {
    /// One of [`VERDICT_RESULTS`].
    pub result: String,
    /// The model hash the verdicts state, `None` for the result's total.
    pub model_hash: Option<String>,
    /// The count, or why it is suppressed.
    pub value: Result<u64, String>,
}

/// One checked period of verdict counts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerdictPeriod {
    pub from: String,
    pub to: String,
    pub cells: Vec<VerdictCell>,
}

/// What a checked History counts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Counts {
    pub periods: Vec<Period>,
    /// The verdict counts, when the definition carries them.
    pub verdicts: Option<Vec<VerdictPeriod>>,
}

/// Check a Service History artifact `art` against its embedded card, already
/// checked by the caller (checkpoint signatures, consistency proofs, witness
/// receipts): its checkpoints `chain`, the stream's first to the anchor, each
/// with its time and the records it covers (the anchor's, the last, are the
/// records the coverage declaration counts); and the anchor digest and
/// stream. Every rule a verifier can check from one
/// History: that it names `def` and the `full_history` subject, the members,
/// the card's digest and subject, the coverage declaration (ISH §4.2), and
/// `period_alignment`, `period_anchor` and `period_floor` (ISH §6.3), with
/// every closed period from the one holding the stream's first record listed
/// and no cell twice.
pub fn check_artifact(
    def: &Definition,
    art: &Map<String, Value>,
    chain: &[Cut<'_>],
    anchor: &str,
    stream: &str,
) -> Result<Counts, String> {
    let mut keys: Vec<&str> = art.keys().map(String::as_str).collect();
    keys.sort_unstable();
    let (want_keys, want_declared): (&[&str], &[&str]) = if def.verdicts {
        (&KEYS_WITH_VERDICTS, &DECLARED_WITH_VERDICTS)
    } else {
        (&KEYS, &DECLARED)
    };
    let mut want_sorted = want_keys.to_vec();
    want_sorted.sort_unstable();
    if keys != want_sorted || art.get("declared") != Some(&json!(want_declared)) {
        return Err(
            "artifact_form: the artifact's members are not the ones the definition declares".into(),
        );
    }
    let anchor_cut = chain.last().ok_or("the card lists no checkpoint")?;
    if art.get("derivation") != Some(&json!(def.digest)) {
        return Err("definition_binding: the artifact names another derivation".into());
    }
    if art.get("subject") != Some(&json!({"full_history": null})) {
        return Err("artifact_form: the subject is not full_history".into());
    }
    let card = &art["history_card"];
    let text = jcs_text(card).map_err(|_| "the card is malformed".to_string())?;
    if art.get("history_card_digest").and_then(Value::as_str)
        != Some(hex::encode(Sha256::digest(text.as_bytes())).as_str())
    {
        return Err("the card does not match history_card_digest".into());
    }
    if card.get("subject") != art.get("subject")
        || card.get("derivation").and_then(Value::as_str) != Some(DERIVATION_HISTORY_CARD)
        || card.get("anchor") != art.get("anchor")
        || card.get("evidence_stream") != art.get("evidence_stream")
    {
        return Err("the card is not for this History's subject, stream and anchor".into());
    }
    if art.get("coverage_declaration")
        != Some(&coverage_declaration(anchor, stream, anchor_cut.leaves))
    {
        return Err("the coverage declaration is not the Standard one at this anchor".into());
    }
    if !def.policy.is_boundary(anchor_cut.timestamp) {
        return Err("period_anchor: the anchor's time is not a period boundary".into());
    }
    let mut counts = check_counts(def, &art[COUNTS], chain)?;
    if def.verdicts {
        counts.verdicts = Some(check_verdicts(def, &art[VERDICTS], chain)?);
    }
    Ok(counts)
}

/// `period_alignment` over a counts member whose own keys are `own` besides
/// `periods` and `policy`: the policy digest, and every closed period from the
/// one holding the stream's first record to the one the anchor closes, each
/// once, in order, none where no checkpoint commits a record (ISH §6.1 item
/// 3). Returns each period's `from`, `to` and `cells`.
fn check_periods<'a>(
    def: &Definition,
    member: &'a Value,
    own: &[&str],
    chain: &[Cut<'_>],
) -> Result<Vec<(String, String, &'a Value)>, String> {
    let policy = &def.policy;
    let malformed = |why: &str| format!("artifact_form: the period counts are malformed: {why}");
    let counts = member
        .as_object()
        .ok_or_else(|| malformed("not an object"))?;
    let mut keys: Vec<&str> = counts.keys().map(String::as_str).collect();
    keys.sort_unstable();
    let mut want: Vec<&str> = own.to_vec();
    want.extend(["periods", "policy"]);
    want.sort_unstable();
    if keys != want {
        return Err(malformed("unexpected members"));
    }
    if counts["policy"] != json!(def.policy_digest) {
        return Err("period_alignment: the counts name another policy".into());
    }
    let listed = counts["periods"]
        .as_array()
        .ok_or_else(|| malformed("periods is not a list"))?;
    let commits = commit_periods(policy, chain).ok_or_else(|| malformed("a checkpoint time"))?;
    let anchor =
        unix_time(chain[chain.len() - 1].timestamp).ok_or_else(|| malformed("the anchor time"))?;
    let end = policy.period_of(anchor);
    let start = first_record_period(chain, &commits).unwrap_or(end).min(end);
    let expected = start..end;
    if listed.len() as i64 != expected.end - expected.start {
        return Err("period_alignment: the closed periods are not each listed once".into());
    }
    let mut out = Vec::with_capacity(listed.len());
    for (period, k) in listed.iter().zip(expected) {
        let (from, to) = (period_time(policy, k), period_time(policy, k + 1));
        if period.get("from").and_then(Value::as_str) != from.as_deref()
            || period.get("to").and_then(Value::as_str) != to.as_deref()
            || period.as_object().map(Map::len) != Some(3)
        {
            return Err("period_alignment: a period is not the policy's next closed one".into());
        }
        out.push((
            from.unwrap_or_default(),
            to.unwrap_or_default(),
            &period["cells"],
        ));
    }
    Ok(out)
}

/// `period_alignment` and `period_floor` over the counts member.
fn check_counts(def: &Definition, counts: &Value, chain: &[Cut<'_>]) -> Result<Counts, String> {
    let mut out = Vec::new();
    for (from, to, cells) in check_periods(def, counts, &[], chain)? {
        out.push(Period {
            from,
            to,
            cells: check_cells(cells, def.policy.floor, UNIT, def.strict_counts)?,
        });
    }
    Ok(Counts {
        periods: out,
        verdicts: None,
    })
}

/// The same checks over `verdict_counts`: it names the one kind of check and
/// its signer; each period lists, for each result of [`VERDICT_RESULTS`] in
/// order, its cells (one per model hash, then the result's total), each result
/// under `period_floor` as a table of its own, in the unit `referee_verdicts`.
fn check_verdicts(
    def: &Definition,
    member: &Value,
    chain: &[Cut<'_>],
) -> Result<Vec<VerdictPeriod>, String> {
    let bad = |why: &str| format!("artifact_form: verdict_counts: {why}");
    if member.get("check") != Some(&json!(VERDICT_CHECK))
        || member.get("signed_by") != Some(&json!(VERDICT_SIGNER))
    {
        return Err(bad("not a count of referee verdicts signed by the checker"));
    }
    let mut out = Vec::new();
    for (from, to, cells) in check_periods(def, member, &["check", "signed_by"], chain)? {
        let list = cells.as_array().ok_or_else(|| bad("cells is not a list"))?;
        let mut checked = Vec::with_capacity(list.len());
        for result in VERDICT_RESULTS {
            // This result's cells as the plain counts' cells, which the one
            // floor check reads; a cell with another dimension shape is
            // not one of its results' and fails the result's own check.
            let mut plain = Vec::new();
            let mut hashes = Vec::new();
            for cell in list {
                let dim = cell.get("dimension").and_then(Value::as_object);
                let (Some(d), Some(c)) = (dim, cell.as_object()) else {
                    return Err(bad("a cell is malformed"));
                };
                if d.get("result").and_then(Value::as_str) != Some(result) {
                    continue;
                }
                let hash = match d.len() {
                    1 => None,
                    2 => Some(
                        d.get("model_hash")
                            .and_then(Value::as_str)
                            .ok_or_else(|| bad("a dimension is malformed"))?
                            .to_string(),
                    ),
                    _ => return Err(bad("a dimension is malformed")),
                };
                let mut c = c.clone();
                c.insert(
                    "dimension".into(),
                    hash.as_ref().map_or(Value::Null, |h| json!({ "model": h })),
                );
                hashes.push(hash);
                plain.push(Value::Object(c));
            }
            // As derived: the model hashes in increasing order, then the total.
            let models = hashes.iter().flatten().collect::<Vec<_>>();
            if !models.windows(2).all(|w| w[0] < w[1])
                || hashes
                    .iter()
                    .position(Option::is_none)
                    .is_some_and(|i| i + 1 != hashes.len())
            {
                return Err(bad(&format!(
                    "the {result} cells are not the model hashes in order, then the total"
                )));
            }
            // Each result's table ends in its one total; a period that lists none, or
            // lists it elsewhere, is not the artifact's form.
            if hashes.iter().filter(|h| h.is_none()).count() != 1 {
                return Err(bad(&format!("the {result} table has no single total")));
            }
            let cells = check_cells(&Value::Array(plain), def.policy.floor, VERDICT_UNIT, true)
                .map_err(|e| format!("{e} (in the {result} verdicts)"))?;
            for (cell, hash) in cells.into_iter().zip(hashes) {
                checked.push(VerdictCell {
                    result: result.to_string(),
                    model_hash: hash,
                    value: cell.value,
                });
            }
        }
        // Every cell is in some result's table, listed result by result.
        if checked.len() != list.len()
            || checked
                .iter()
                .zip(list)
                .any(|(c, raw)| raw["dimension"]["result"] != json!(c.result))
        {
            return Err(bad(
                "a cell is for no result of a referee verdict, or out of order",
            ));
        }
        out.push(VerdictPeriod {
            from,
            to,
            cells: checked,
        });
    }
    Ok(out)
}

/// `period_floor` over one period's cells: each in the counts unit and
/// label, a model at most once and exactly one total, every value at least
/// the floor, every suppressed cell without a value and with a reason, and
/// complementary suppression where it is due.
fn check_cells(cells: &Value, floor: u64, unit: &str, strict: bool) -> Result<Vec<Cell>, String> {
    let bad = |why: &str| format!("period_floor: {why}");
    let cells = cells.as_array().ok_or_else(|| bad("cells is not a list"))?;
    let mut out: Vec<Cell> = Vec::with_capacity(cells.len());
    for cell in cells {
        let c = cell.as_object().ok_or_else(|| bad("a cell is malformed"))?;
        if c.get("unit").and_then(Value::as_str) != Some(unit) {
            return Err(format!("units: a cell counts in another unit than {unit}"));
        }
        if c.get("label").and_then(Value::as_str) != Some(LABEL) {
            return Err(format!("labels: a count is labelled other than {LABEL}"));
        }
        let model = match c.get("dimension") {
            Some(Value::Null) => None,
            Some(Value::Object(d)) if d.len() == 1 => Some(
                d.get("model")
                    .and_then(Value::as_str)
                    .ok_or_else(|| bad("a dimension is not a model"))?
                    .to_string(),
            ),
            _ => return Err(bad("a dimension is malformed")),
        };
        if out.iter().any(|o| o.model == model) {
            return Err(bad("a cell is listed twice"));
        }
        let value = match (c.get("value"), c.get("suppressed").and_then(Value::as_str)) {
            (Some(Value::Null), Some(why @ ("below_floor" | "complementary"))) if c.len() == 5 => {
                Err(why.to_string())
            }
            (Some(v), None) if c.len() == 4 => match v.as_u64() {
                Some(n) if n >= floor => Ok(n),
                Some(_) => return Err(bad("a published cell is below the floor")),
                None => return Err(bad("a value is not a count")),
            },
            _ => return Err(bad("a cell is neither published nor suppressed")),
        };
        out.push(Cell { model, value });
    }
    let [total] = out.iter().filter(|c| c.model.is_none()).collect::<Vec<_>>()[..] else {
        return Err(bad("a period has no single total"));
    };
    let models: Vec<&Cell> = out.iter().filter(|c| c.model.is_some()).collect();
    if let Ok(total) = total.value {
        if models.iter().filter(|c| c.value.is_err()).count() == 1 {
            return Err(bad("a suppressed cell can be derived from the total"));
        }
        // The published models never exceed the total, and are the total
        // when none is suppressed. A sum past u64 is no count at all.
        let published = models
            .iter()
            .filter_map(|c| c.value.as_ref().ok())
            .try_fold(0u64, |sum, n| sum.checked_add(*n))
            .ok_or_else(|| bad("the models do not add up to the total"))?;
        let all_published = models.iter().all(|c| c.value.is_ok());
        if published > total || (all_published && published != total) {
            return Err(bad("the models do not add up to the total"));
        }
        let hidden = models.iter().filter(|c| c.value.is_err()).count();
        let all_below = models
            .iter()
            .all(|c| !matches!(&c.value, Err(why) if why != "below_floor"));
        if strict && all_below && derivable(hidden, total - published, floor) {
            return Err(bad("a suppressed cell can be derived from the total"));
        }
    }
    Ok(out)
}
