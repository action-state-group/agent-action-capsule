// SPDX-License-Identifier: BSD-3-Clause
//! The stdin/stdout adapter for `scripts/cross-language-interlock.sh`, the
//! Rust twin of `go/cmd/cross_language`. Needs feature `strict`.
//!
//! `seal`: read a capsule, set its `capsule_id`, write it back.
//! `verify`: read a capsule, print the recomputed `capsule_id` if it
//! verifies; otherwise print each finding code to stderr and exit 1.
//! `bundle-produce <kind>`: read a producer fixture
//! (`vectors/cross-language/bundle-producer-log.json` or
//! `bundle-producer-padded-log.json`) and write the JCS bytes of the Bundle
//! `kind` names in its `builds`.
//! `bundle-verify`: read a Bundle's JSON text and print its strict verdict.

use agent_action_capsule::bundle::{
    build_evidence_bundle, decode_fragment, proof_source_from_cll, verify_bundle_strict,
    BuildError, BuildOptions, InclusionProof, Interval, ProofSource, RangeProof, RecordSource,
    StoredRecord, StrictOptions,
};
use agent_action_capsule::{canonical, verify};
use base64::Engine as _;
use cll::log::{CheckpointState, CheckpointStateStore, Entry, EntrySource, State, Timestamp};
use serde_json::Value;
use std::collections::HashMap;
use std::convert::Infallible;
use std::io::{Read, Write};
use std::process::ExitCode;

const USAGE: &str = "usage: cross_language seal|verify|bundle-produce <kind>|bundle-verify";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut input = Vec::new();
    let command = match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        ["bundle-produce", _] | ["bundle-verify"] | ["seal"] | ["verify"] => args[0].as_str(),
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    if let Err(e) = std::io::stdin().read_to_end(&mut input) {
        eprintln!("{e}");
        return ExitCode::from(2);
    }
    match command {
        "bundle-produce" => return bundle_produce(&args[1], &input),
        "bundle-verify" => return bundle_verify(&input),
        _ => {}
    }
    let mut capsule = match verify::decode_capsule_json(&input) {
        Ok(Value::Object(map)) => map,
        Ok(_) => {
            eprintln!("input must be a JSON object");
            return ExitCode::from(2);
        }
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    if command == "seal" {
        return match canonical::compute_capsule_id(&capsule) {
            Ok(id) => {
                capsule.insert("capsule_id".to_string(), Value::String(id));
                println!("{}", Value::Object(capsule));
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("{e}");
                ExitCode::FAILURE
            }
        };
    }
    let result = verify::verify(&Value::Object(capsule), None);
    if !result.ok {
        for finding in &result.findings {
            eprintln!("{}", finding.code);
        }
        return ExitCode::FAILURE;
    }
    if let Some(id) = result.capsule_id {
        println!("{id}");
    }
    ExitCode::SUCCESS
}

/// A CLL backend (`scan_entries` and `load_cll`) over the fixture's log.
struct FixtureBackend {
    entries: Vec<Entry>,
    state: State,
}

impl EntrySource for FixtureBackend {
    fn scan_entries(&self, after_seq: u64, limit: usize) -> cll::log::Result<Vec<Entry>> {
        Ok(self
            .entries
            .iter()
            .filter(|entry| entry.seq > after_seq)
            .take(limit)
            .cloned()
            .collect())
    }
}

impl CheckpointStateStore for FixtureBackend {
    fn load_cll(&self) -> cll::log::Result<State> {
        Ok(self.state.clone())
    }

    fn commit_cll(&self, _: u64, _: Option<&[u8]>, _: &State) -> cll::log::Result<()> {
        Err(cll::log::Error::new(
            cll::log::ErrorCode::Unsupported,
            "the fixture log is read-only",
        ))
    }
}

/// A record store over the fixture's `records`.
struct FixtureRecords(HashMap<String, StoredRecord>);

impl RecordSource for FixtureRecords {
    type Error = Infallible;

    fn get_record(&self, id: &str) -> Result<Option<StoredRecord>, Infallible> {
        Ok(self.0.get(id).cloned())
    }
}

fn hex_bytes(value: &Value) -> Result<Vec<u8>, String> {
    let text = value.as_str().ok_or("expected a hex string")?;
    hex::decode(text).map_err(|e| e.to_string())
}

fn hex_list(value: &Value) -> Result<Vec<Vec<u8>>, String> {
    value
        .as_array()
        .ok_or("expected a list of hex strings")?
        .iter()
        .map(hex_bytes)
        .collect()
}

fn unsigned(value: &Value) -> Result<u64, String> {
    value
        .as_u64()
        .ok_or_else(|| format!("expected an unsigned integer, got {value}"))
}

fn fixture_source(fixture: &Value) -> Result<(FixtureBackend, FixtureRecords), String> {
    let log = &fixture["log"];
    let state = &log["state"];
    let checkpoint = &state["checkpoint"];
    let appended_at = Timestamp::from_unix_millis(1_792_368_000_000);
    let entries = hex_list(&log["entries"])?
        .into_iter()
        .zip(1..)
        .map(|(value, seq)| Entry {
            seq,
            value,
            appended_at,
        })
        .collect();
    let state = State {
        size: unsigned(&state["size"])?,
        nodes: hex_list(&state["nodes"])?,
        indexed_seq: unsigned(&state["indexed_seq"])?,
        first_pending_at: None,
        checkpoint: Some(CheckpointState {
            bytes: hex_bytes(&checkpoint["cose"])?,
            size: unsigned(&checkpoint["size"])?,
            indexed_seq: unsigned(&checkpoint["indexed_seq"])?,
            peaks: hex_list(&checkpoint["peaks"])?,
        }),
        witnesses: Vec::new(),
    };
    let mut records = HashMap::new();
    for (id, record) in fixture["records"]
        .as_object()
        .ok_or("records must be an object")?
    {
        records.insert(
            id.clone(),
            StoredRecord {
                capsule: hex_bytes(&record["capsule"])?,
                producer_envelope: hex_bytes(&record["producer_envelope"])?,
            },
        );
    }
    Ok((FixtureBackend { entries, state }, FixtureRecords(records)))
}

/// A proof source with the optional `leaf_content` capability, over the
/// fixture's `leaf_contents`.
struct WithLeafContent<'a, S> {
    source: S,
    contents: &'a serde_json::Map<String, Value>,
}

impl<S: ProofSource> ProofSource for WithLeafContent<'_, S> {
    fn checkpoint(&self) -> Result<Vec<u8>, BuildError> {
        self.source.checkpoint()
    }
    fn leaves(&self) -> Result<Vec<[u8; 32]>, BuildError> {
        self.source.leaves()
    }
    fn record(&self, capsule_id: &str) -> Result<Option<StoredRecord>, BuildError> {
        self.source.record(capsule_id)
    }
    fn inclusion_proof(&self, seq: u64) -> Result<InclusionProof, BuildError> {
        self.source.inclusion_proof(seq)
    }
    fn range_proof(&self, first_seq: u64) -> Result<RangeProof, BuildError> {
        self.source.range_proof(first_seq)
    }
    fn leaf_content(&self, seq: u64) -> Result<Option<Value>, BuildError> {
        Ok(self.contents.get(&seq.to_string()).cloned())
    }
}

fn bundle_produce(kind: &str, input: &[u8]) -> ExitCode {
    let fixture: Value = match serde_json::from_slice(input) {
        Ok(value) => value,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let Some(build) = fixture["builds"].get(kind) else {
        eprintln!("unknown bundle kind {kind:?}");
        return ExitCode::from(2);
    };
    let built = fixture_source(&fixture).and_then(|(backend, records)| {
        let interval = match &build["interval_from"] {
            Value::Null => Interval::ProducerSelected,
            seq => Interval::From(unsigned(seq)?),
        };
        let root = fixture["root"].as_str().ok_or("root must be a string")?;
        let mut options = BuildOptions::new(root, interval);
        options.closure_depth = unsigned(&build["closure_depth"])?;
        options.carry_non_record_leaves = build["carry_non_record_leaves"] == Value::Bool(true);
        let source = proof_source_from_cll(&backend, records).map_err(|e| e.to_string())?;
        let bundle = match fixture.get("leaf_contents").and_then(Value::as_object) {
            Some(contents) => {
                build_evidence_bundle(&WithLeafContent { source, contents }, &options)
            }
            None => build_evidence_bundle(&source, &options),
        }
        .map_err(|e| e.to_string())?;
        canonical::jcs(&bundle).map_err(|e| e.to_string())
    });
    match built {
        Ok(bytes) => match std::io::stdout().write_all(&bytes) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("{e}");
                ExitCode::FAILURE
            }
        },
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn bundle_verify(input: &[u8]) -> ExitCode {
    // The Bundle's own strict reader: its URL-fragment decoder over these bytes.
    let fragment = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(input.trim_ascii());
    match decode_fragment(&fragment) {
        Ok(bundle) => {
            println!(
                "{}",
                verify_bundle_strict(&bundle, &StrictOptions::default()).verdict()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
