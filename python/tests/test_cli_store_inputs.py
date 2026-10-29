# SPDX-License-Identifier: BSD-3-Clause
"""``verify --store`` inputs: ledger store directories, JSONL ledgers that
carry bookkeeping lines and padding, torn fragments, and JSON documents."""
import hashlib
import json
from pathlib import Path

import pytest

from agent_action_capsule.cli import LEDGER_BOOKKEEPING_KINDS, main

ROOT = Path(__file__).resolve().parents[2]
VEC = ROOT / "vectors" / "capsule"
PADDING = {c["id"]: c for c in json.loads((ROOT / "vectors/evidence-layer/padding/cases.json").read_text())["cases"]}


def _capsule(name: str = "pos-executed-confirmed") -> dict:
    return json.loads((VEC / name / "input.json").read_text())


def _line(obj) -> bytes:
    return json.dumps(obj, separators=(",", ":")).encode() + b"\n"


# The bookkeeping lines as capsule-emit writes them (witness.py, disclose.py).
STAMP = {"kind": "checkpoint_stamp", "v": 1, "capsule_id": "aa" * 32, "checkpoint": {"mmr_size": 1}}
DISCLOSURE = {
    "kind": "disclosure_record",
    "v": 1,
    "audience": "auditor",
    "selector": {"all": True},
    "disclosed_capsule_ids": [],
    "disclosed_fields": {},
    "suppressed_fields": [],
    "completeness": {},
    "timestamp": "2026-10-22T00:00:00Z",
    "capsule_id": "bb" * 32,
    "signature": "00",
    "key_id": "11" * 32,
}
_BACKFILL_BODY = {"checkpoint_entry_digest": "aa" * 32, "witness": {"url": "https://w.example"}}
BACKFILL = {
    "kind": "checkpoint_witness_backfill",
    "v": 1,
    "capsule_id": hashlib.sha256(json.dumps(_BACKFILL_BODY, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
    **_BACKFILL_BODY,
}


def _ledger_store(root: Path, segments: list, *, archived: tuple = ()) -> Path:
    """A managed checkpointed-local-log LedgerStore laid out by hand: the
    manifest lists the segments, the last one active."""
    (root / "segments").mkdir(parents=True)
    entries = []
    for i, data in enumerate(segments, start=1):
        name = f"seg-{i:06d}.jsonl"
        mounted = name not in archived
        target = root / "segments" / (name if mounted else f".archived/{name}")
        target.parent.mkdir(exist_ok=True)
        target.write_bytes(data)
        entries.append({"name": name, "mounted": mounted})
    manifest = {"log_id": "", "segments": entries, "active_segment": entries[-1]["name"]}
    (root / "manifest.json").write_text(json.dumps(manifest))
    (root / "index.sqlite3").write_bytes(b"not read")
    return root


def test_bookkeeping_kinds_are_the_three_capsule_emit_writes():
    assert sorted(LEDGER_BOOKKEEPING_KINDS) == ["checkpoint_stamp", "checkpoint_witness_backfill", "disclosure_record"]


def test_witnessed_jsonl_ledger_counts_bookkeeping(tmp_path, capsys):
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_bytes(_line(_capsule()) + _line(STAMP) + _line(STAMP | {"capsule_id": "dd" * 32}) + _line(DISCLOSURE))
    assert main(["verify", "--store", str(ledger)]) == 0
    out = capsys.readouterr().out
    assert "Store-level verification of 1 capsule(s)" in out
    assert "3 bookkeeping entries not checked (2 checkpoint stamps, 1 disclosure record); only capsules are checked" in out


def test_ledger_store_directory(tmp_path, capsys):
    store = _ledger_store(
        tmp_path / "capsule-ledger",
        [_line(_capsule()) + _line(STAMP) + _line(BACKFILL) + _line(PADDING["pos-padding-a"]["record"])],
    )
    assert main(["verify", "--store", str(store)]) == 0
    out = capsys.readouterr().out
    assert "1 capsule(s)" in out
    assert "2 bookkeeping entries not checked (1 checkpoint stamp, 1 witness backfill)" in out
    assert "1 padding record checked" in out


def test_ledger_store_reads_segments_in_manifest_order_and_skips_a_torn_tail(tmp_path, capsys):
    first, second = _capsule("pos-executed-confirmed"), _capsule("pos-blocked")
    store = _ledger_store(tmp_path / "s", [_line(first), _line(second) + b'{"capsule_id":"to'])
    assert main(["verify", "--store", str(store), "--json"]) == 0
    captured = capsys.readouterr()
    results = json.loads(captured.out)
    assert [r["capsule_id_recomputed"] for r in results] == [first["capsule_id"], second["capsule_id"]]
    assert "unterminated last line of the active segment, skipped" in captured.err


def test_parseable_unterminated_active_tail_is_not_an_entry(tmp_path, capsys):
    first, second = _capsule("pos-executed-confirmed"), _capsule("pos-blocked")
    store = _ledger_store(tmp_path / "s", [_line(first) + _line(second)[:-1]])
    assert main(["verify", "--store", str(store)]) == 0
    assert "1 capsule(s)" in capsys.readouterr().out


def test_flat_file_counts_a_parseable_last_line_without_newline(tmp_path, capsys):
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_bytes(_line(_capsule("pos-blocked")) + _line(_capsule())[:-1])
    assert main(["verify", "--store", str(ledger)]) == 0
    assert "2 capsule(s)" in capsys.readouterr().out


def test_store_line_that_is_not_json_is_a_problem(tmp_path, capsys):
    store = _ledger_store(tmp_path / "s", [b"not json\n" + _line(_capsule())])
    assert main(["verify", "--store", str(store)]) == 1
    assert "line 1: not JSON" in capsys.readouterr().out


def test_closed_segment_torn_tail_is_a_problem(tmp_path, capsys):
    store = _ledger_store(tmp_path / "s", [_line(_capsule("pos-blocked")) + b'{"capsule_id":"to', _line(_capsule())])
    assert main(["verify", "--store", str(store)]) == 1
    assert "seg-000001.jsonl line 2: not JSON" in capsys.readouterr().out


def test_store_different_line_under_one_capsule_id_is_a_problem(tmp_path, capsys):
    capsule = _capsule()
    other = dict(capsule, operator="someone-else")
    store = _ledger_store(tmp_path / "s", [_line(capsule) + _line(other)])
    assert main(["verify", "--store", str(store)]) == 1
    assert "a different line under capsule_id" in capsys.readouterr().out


def test_ledger_store_keeps_the_first_line_per_capsule_id(tmp_path, capsys):
    capsule = _capsule()
    store = _ledger_store(tmp_path / "s", [_line(capsule) + _line(capsule)])
    assert main(["verify", "--store", str(store)]) == 0
    out = capsys.readouterr().out
    assert "1 capsule(s)" in out and "repeats capsule_id" in out


def test_archived_segment_is_a_problem(tmp_path, capsys):
    store = _ledger_store(tmp_path / "s", [_line(_capsule("pos-blocked")), _line(_capsule())], archived=("seg-000001.jsonl",))
    assert main(["verify", "--store", str(store)]) == 1
    assert "segment seg-000001.jsonl is archived" in capsys.readouterr().out


@pytest.mark.parametrize(
    "manifest",
    [
        "not json",
        json.dumps({"segments": []}),
        json.dumps({"segments": [{"name": "a"}, {"name": "a"}], "active_segment": "a"}),
        json.dumps({"segments": [{"name": "a"}, {"name": "b"}], "active_segment": "a"}),
        json.dumps({"segments": [{"name": 5}], "active_segment": 5}),
        json.dumps({"segments": [{"name": ["x"]}], "active_segment": "x"}),
        json.dumps({"segments": [{"name": "../escape"}], "active_segment": "../escape"}),
        json.dumps({"segments": ["seg-000001.jsonl"], "active_segment": "seg-000001.jsonl"}),
        json.dumps({"segments": [{"name": "seg-000001.jsonl"}], "active_segment": "seg-000001.jsonl"}),
    ],
)
def test_bad_manifest_cannot_run(tmp_path, capsys, manifest):
    (tmp_path / "segments").mkdir()
    (tmp_path / "manifest.json").write_text(manifest)
    assert main(["verify", "--store", str(tmp_path)]) == 2
    assert "cannot read store" in capsys.readouterr().err


def test_unknown_kind_does_not_exempt_a_capsule(tmp_path, capsys):
    tampered = _capsule() | {"kind": "checkpoint_stamp"}
    stripped = {k: v for k, v in tampered.items() if k != "format_version"}
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_bytes(
        _line(_capsule("pos-blocked"))
        + _line(tampered)
        + _line(stripped)
        + _line({"kind": "x", "capsule_id": "ee" * 32})
    )
    assert main(["verify", "--store", str(ledger)]) == 1
    out = capsys.readouterr().out
    assert out.count("line does not have that kind's members") == 2
    assert out.count("is not a recognized bookkeeping line") == 1


def test_padding_relabelled_as_bookkeeping_is_a_problem(tmp_path, capsys):
    bad = PADDING["neg-capsule-id-mismatch"]["record"] | {"kind": "checkpoint_stamp", "v": 1}
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_bytes(_line(_capsule()) + _line(bad))
    assert main(["verify", "--store", str(ledger)]) == 1
    assert "does not have that kind's members" in capsys.readouterr().out


def test_witness_backfill_id_must_recompute(tmp_path, capsys):
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_bytes(_line(_capsule()) + _line(BACKFILL | {"capsule_id": "ff" * 32}))
    assert main(["verify", "--store", str(ledger)]) == 1
    assert "backfill capsule_id does not recompute" in capsys.readouterr().out


@pytest.mark.parametrize("kind", [[], {}, 3, None])
def test_non_string_kind_is_a_problem_not_a_crash(tmp_path, capsys, kind):
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_bytes(_line(_capsule()) + _line({"kind": kind, "capsule_id": "ee" * 32}))
    assert main(["verify", "--store", str(ledger)]) == 1
    assert "is not a recognized bookkeeping line" in capsys.readouterr().out


def test_problems_also_fail_focused_capsule_verification(tmp_path, capsys):
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_bytes(_line(_capsule()) + _line({"kind": "x", "capsule_id": "ee" * 32}))
    target = VEC / "pos-blocked" / "input.json"
    assert main(["verify", "--store", str(ledger), "--json", str(target)]) == 1
    captured = capsys.readouterr()
    assert json.loads(captured.out)["ok"] is True
    assert "problem:" in captured.err


def test_invalid_padding_is_a_problem(tmp_path, capsys):
    ledger = tmp_path / "ledger.jsonl"
    bad = PADDING["neg-capsule-id-mismatch"]["record"]
    ledger.write_bytes(_line(_capsule()) + _line(bad))
    assert main(["verify", "--store", str(ledger)]) == 1
    assert "padding record: capsule_id does not recompute" in capsys.readouterr().out


@pytest.mark.parametrize("case", sorted(PADDING))
def test_padding_rules_follow_the_vectors(tmp_path, capsys, case):
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_bytes(_line(_capsule()) + _line(PADDING[case]["record"]))
    expected = 0 if PADDING[case]["kind"] == "positive" else 1
    assert main(["verify", "--store", str(ledger)]) == expected


def test_torn_middle_fragment_is_skipped(tmp_path, capsys):
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_bytes(_line(_capsule("pos-blocked")) + b'{"capsule_id":"half\n' + _line(_capsule()))
    assert main(["verify", "--store", str(ledger)]) == 0
    out = capsys.readouterr().out
    assert "2 capsule(s)" in out and "line 2: not JSON, skipped" in out


def test_compact_ledger_wrapper_is_one_document(tmp_path, capsys):
    doc = tmp_path / "store.json"
    doc.write_text(json.dumps({"ledger": [_capsule(), _capsule("pos-blocked")]}, separators=(",", ":")))
    assert main(["verify", "--store", str(doc)]) == 0
    assert "2 capsule(s)" in capsys.readouterr().out


def test_pretty_printed_array_is_one_document(tmp_path, capsys):
    doc = tmp_path / "store.json"
    doc.write_text(json.dumps([_capsule(), _capsule("pos-blocked")], indent=2))
    assert main(["verify", "--store", str(doc)]) == 0
    assert "2 capsule(s)" in capsys.readouterr().out


@pytest.mark.parametrize("content", [b"", b"\n\n  \n"])
def test_empty_file_is_an_empty_ledger(tmp_path, capsys, content):
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_bytes(content)
    assert main(["verify", "--store", str(ledger)]) == 0
    assert "0 capsule(s)" in capsys.readouterr().out


def test_file_with_nothing_parseable_cannot_run(tmp_path, capsys):
    bad = tmp_path / "ledger.jsonl"
    bad.write_bytes(b"not json\nalso not\n")
    assert main(["verify", "--store", str(bad)]) == 2


def test_directory_without_manifest_keeps_reading_json_files(tmp_path, capsys):
    (tmp_path / "a.json").write_text(json.dumps(_capsule()))
    (tmp_path / "b.json").write_text(json.dumps(_capsule("pos-blocked")))
    assert main(["verify", "--store", str(tmp_path)]) == 0
    assert "2 capsule(s)" in capsys.readouterr().out


@pytest.mark.parametrize("swap", [("human_disposed", 1), ("human_disposed", 1.0)])
def test_typed_difference_under_one_capsule_id_is_a_problem(tmp_path, capsys, swap):
    capsule = _capsule()
    other = json.loads(json.dumps(capsule))
    assert other["disposition"][swap[0]] is True
    other["disposition"][swap[0]] = swap[1]
    store = _ledger_store(tmp_path / "s", [_line(capsule) + _line(other)])
    assert main(["verify", "--store", str(store), "--json"]) == 1
    assert "a different line under capsule_id" in capsys.readouterr().err


def test_bookkeeping_v_must_be_the_integer_one(tmp_path, capsys):
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_bytes(_line(_capsule()) + _line(STAMP | {"v": True}))
    assert main(["verify", "--store", str(ledger)]) == 1
    assert "bad v or capsule_id" in capsys.readouterr().out


def test_ledger_member_that_is_not_a_list_cannot_run(tmp_path, capsys):
    doc = tmp_path / "store.json"
    doc.write_text(json.dumps({"ledger": 5}))
    assert main(["verify", "--store", str(doc)]) == 2


def test_segment_missing_from_disk_cannot_run(tmp_path, capsys):
    store = _ledger_store(tmp_path / "s", [_line(_capsule())])
    (store / "segments" / "seg-000001.jsonl").unlink()
    assert main(["verify", "--store", str(store)]) == 2
    assert "missing" in capsys.readouterr().err
