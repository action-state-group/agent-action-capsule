//! The profile registries (§12), parsed from `spec/REGISTRY.md`. Port of
//! `go/registries`.
//!
//! The authoritative table is an embedded byte copy of `spec/REGISTRY.md`
//! (`data/REGISTRY.md`; a crate cannot package files outside its directory).
//! The `drift` test keeps it identical to its source. Callers that need a pinned
//! historical table parse that snapshot with [`Registries::parse`].

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::OnceLock;

const AUTHORITATIVE_REGISTRY: &str = include_str!("../data/REGISTRY.md");

/// The registry-governed vocabularies (§4), in order. `disposition.approver`
/// is absent: it is a closed enum (§5.4), not registry-governed.
pub const REGISTRY_NAMES: [&str; 7] = [
    "verdict_class",
    "disposition.decision",
    "effect.type",
    "irreversibility_class",
    "effect_attestation",
    "chain.relation",
    "citation_purpose",
];

/// Why a REGISTRY.md snapshot could not be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryError(String);

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for RegistryError {}

/// Seeded values per registry: `{registry name: values}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registries {
    seeded: BTreeMap<String, BTreeSet<String>>,
}

impl Registries {
    /// AAC's current registry table, parsed once from the embedded copy.
    pub fn authoritative() -> Result<&'static Registries, RegistryError> {
        static TABLE: OnceLock<Result<Registries, RegistryError>> = OnceLock::new();
        TABLE
            .get_or_init(|| Registries::parse(AUTHORITATIVE_REGISTRY))
            .as_ref()
            .map_err(Clone::clone)
    }

    /// Parses a REGISTRY.md snapshot. Values come only from structured loci
    /// (table data rows, ordered-list items, "Initial contents" lines), never
    /// from backticks in prose.
    pub fn parse(text: &str) -> Result<Registries, RegistryError> {
        let mut sections: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        let mut current: Option<&str> = None;
        for line in text.lines() {
            if let Some(name) = section_header(line) {
                sections.insert(name, Vec::new());
                current = Some(name);
            } else if let Some(name) = current {
                if line.starts_with("## ") {
                    current = None;
                } else if let Some(lines) = sections.get_mut(name) {
                    lines.push(line);
                }
            }
        }

        let mut seeded = BTreeMap::new();
        for name in REGISTRY_NAMES {
            let values = match sections.get(name) {
                Some(lines) => seeded_values(lines),
                // Older snapshots predate references. Their vocabulary stays
                // usable; every purpose is then informationally unknown.
                None if name == "citation_purpose" => BTreeSet::new(),
                None => {
                    return Err(RegistryError(format!(
                        "registry {name:?} not found in REGISTRY.md"
                    )))
                }
            };
            if values.is_empty() && sections.contains_key(name) {
                return Err(RegistryError(format!(
                    "registry {name:?} parsed with no seeded values"
                )));
            }
            seeded.insert(name.to_string(), values);
        }
        Ok(Registries { seeded })
    }

    /// True if `value` is seeded in `registry`.
    pub fn contains(&self, registry: &str, value: &str) -> bool {
        self.seeded
            .get(registry)
            .is_some_and(|values| values.contains(value))
    }

    /// The seeded values of `registry`, sorted.
    pub fn values(&self, registry: &str) -> impl Iterator<Item = &str> {
        self.seeded
            .get(registry)
            .into_iter()
            .flatten()
            .map(String::as_str)
    }
}

/// `## N. \`name\`` -> `name`.
fn section_header(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("##")?;
    let rest = strip_required_ws(rest)?;
    let rest = strip_ordinal(rest)?;
    let rest = strip_required_ws(rest)?;
    let (token, tail) = backtick_token(rest)?;
    tail.trim_matches(is_re2_space).is_empty().then_some(token)
}

/// `N. \`token\`` (an ordered-list item holding only a token) -> `token`.
fn ordered_list_item(line: &str) -> Option<&str> {
    let rest = strip_ordinal(line.trim_start_matches(is_re2_space))?;
    let rest = strip_required_ws(rest)?;
    let (token, tail) = backtick_token(rest)?;
    tail.trim_matches(is_re2_space).is_empty().then_some(token)
}

/// RE2's `\s`: ASCII space, tab, newline, form feed and carriage return.
fn is_re2_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\x0c' | '\r')
}

fn strip_required_ws(s: &str) -> Option<&str> {
    let trimmed = s.trim_start_matches(is_re2_space);
    (trimmed.len() < s.len()).then_some(trimmed)
}

/// Strips `\d+\.`.
fn strip_ordinal(s: &str) -> Option<&str> {
    let digits = s.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 {
        return None;
    }
    s[digits..].strip_prefix('.')
}

/// A leading `` `token` `` (non-empty, no inner backtick) and what follows.
fn backtick_token(s: &str) -> Option<(&str, &str)> {
    let rest = s.strip_prefix('`')?;
    let end = rest.find('`')?;
    (end > 0).then(|| (&rest[..end], &rest[end + 1..]))
}

/// Every `` `token` `` in `s`, in order.
fn backtick_tokens(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = s;
    while let Some(start) = rest.find('`') {
        let after = &rest[start + 1..];
        match after.find('`') {
            // An empty pair: the second backtick may open the next token.
            Some(0) => rest = after,
            Some(end) => {
                out.push(&after[..end]);
                rest = &after[end + 1..];
            }
            None => break,
        }
    }
    out
}

fn seeded_values(lines: &[&str]) -> BTreeSet<String> {
    let mut values = BTreeSet::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        let stripped = line.trim();

        // Table data row: the first cell is exactly one backtick-quoted token.
        if stripped.starts_with('|') {
            let first = stripped
                .trim_matches('|')
                .split('|')
                .next()
                .unwrap_or("")
                .trim();
            let separator = first.chars().all(|c| matches!(c, '-' | ':' | ' '));
            if !first.is_empty() && first != "Value" && !separator {
                if let Some((token, "")) = backtick_token(first) {
                    values.insert(token.to_string());
                }
            }
            i += 1;
            continue;
        }

        if let Some(token) = ordered_list_item(line) {
            values.insert(token.to_string());
            i += 1;
            continue;
        }

        // "Initial contents": the list starts after the marker and may wrap
        // across lines up to the next blank line.
        if let Some(at) = stripped.find("Initial contents") {
            let mut text = &stripped[at..];
            while i < lines.len() && !lines[i].trim().is_empty() {
                for token in backtick_tokens(text) {
                    values.insert(token.to_string());
                }
                i += 1;
                text = lines.get(i).copied().unwrap_or("");
            }
            continue;
        }
        i += 1;
    }
    values
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authoritative_table_has_every_registry() {
        let regs = Registries::authoritative().expect("embedded REGISTRY.md parses");
        for name in REGISTRY_NAMES {
            assert!(regs.values(name).next().is_some(), "{name} is empty");
        }
        assert!(regs.contains("chain.relation", "supersedes"));
        assert!(!regs.contains("chain.relation", "not-a-relation"));
    }

    #[test]
    fn parses_structured_loci_only() {
        let text = "\
## 1. `verdict_class`
Prose mentioning `not_a_value`.
| Value | Meaning |
|---|---|
| `executed` | ran |
1. `blocked`
Initial contents: `denied`,
`expired`

## 2. `disposition.decision`
| `accept` | |
## 3. `effect.type`
| `write` | |
## 4. `irreversibility_class`
| `two_way` | |
## 5. `effect_attestation`
| `gate_executed` | |
## 6. `chain.relation`
| `supersedes` | |
";
        let regs = Registries::parse(text).expect("parses");
        let verdicts: Vec<&str> = regs.values("verdict_class").collect();
        assert_eq!(verdicts, ["blocked", "denied", "executed", "expired"]);
        assert_eq!(regs.values("citation_purpose").count(), 0);
    }

    #[test]
    fn missing_registry_is_an_error() {
        assert!(Registries::parse("## 1. `verdict_class`\n| `x` |\n").is_err());
    }
}
