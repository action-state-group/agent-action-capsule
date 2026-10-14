// SPDX-License-Identifier: BSD-3-Clause
//! The embedded registry snapshots are byte copies of their sources. When one
//! of these fails, copy the source over `data/` (see the file names below).

fn assert_same(copy: &str, source: &str) {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let copy_bytes = std::fs::read(dir.join(copy)).expect(copy);
    let source_bytes = std::fs::read(dir.join("../..").join(source)).expect(source);
    assert!(
        copy_bytes == source_bytes,
        "{copy} differs from {source}; copy the source over it"
    );
}

#[test]
fn registry_is_spec_registry() {
    assert_same("data/REGISTRY.md", "spec/REGISTRY.md");
}

#[test]
fn cpb_snapshot_is_python_snapshot() {
    assert_same(
        "data/cpb_provisional.json",
        "python/agent_action_capsule/data/cpb_provisional.json",
    );
}
