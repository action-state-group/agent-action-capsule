// SPDX-License-Identifier: BSD-3-Clause
//! The stdin/stdout adapter for `scripts/cross-language-interlock.sh`, the
//! Rust twin of `go/cmd/cross_language`.
//!
//! `seal`: read a capsule, set its `capsule_id`, write it back.
//! `verify`: read a capsule, print the recomputed `capsule_id` if it
//! verifies; otherwise print each finding code to stderr and exit 1.

use agent_action_capsule::{canonical, verify};
use serde_json::Value;
use std::io::Read;
use std::process::ExitCode;

fn main() -> ExitCode {
    let command = std::env::args().nth(1).unwrap_or_default();
    if command != "seal" && command != "verify" {
        eprintln!("usage: cross_language seal|verify");
        return ExitCode::from(2);
    }
    let mut input = Vec::new();
    if let Err(e) = std::io::stdin().read_to_end(&mut input) {
        eprintln!("{e}");
        return ExitCode::from(2);
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
