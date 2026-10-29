import importlib.util
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SPEC = importlib.util.spec_from_file_location("check_vector_index", os.path.join(HERE, "check_vector_index.py"))
check = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check)


def run_with(tmp_path, monkeypatch, text, capsys):
    index = tmp_path / "VECTORS.md"
    index.write_text(text, encoding="utf-8")
    monkeypatch.setattr(check, "INDEX", str(index))
    code = check.main()
    return code, capsys.readouterr().out


def real_index():
    with open(os.path.join(os.path.dirname(HERE), "VECTORS.md"), encoding="utf-8") as f:
        return f.read()


def test_committed_index_passes(tmp_path, monkeypatch, capsys):
    code, out = run_with(tmp_path, monkeypatch, real_index(), capsys)
    assert code == 0, out


def test_missing_row_fails(tmp_path, monkeypatch, capsys):
    text = "\n".join(l for l in real_index().split("\n") if not l.startswith("| `vectors/judge/`"))
    code, out = run_with(tmp_path, monkeypatch, text, capsys)
    assert code == 1 and "no row for vectors/judge/" in out


def test_drifted_count_fails(tmp_path, monkeypatch, capsys):
    text = real_index().replace("| record, verify | 119 |", "| record, verify | 118 |")
    code, out = run_with(tmp_path, monkeypatch, text, capsys)
    assert code == 1 and "118 cases for vectors/capsule/" in out


def test_duplicate_and_garbled_rows_fail(tmp_path, monkeypatch, capsys):
    row = next(l for l in real_index().split("\n") if l.startswith("| `vectors/judge/`"))
    code, out = run_with(tmp_path, monkeypatch, real_index().replace(row, row + "\n" + row), capsys)
    assert code == 1 and "twice" in out
    code, out = run_with(tmp_path, monkeypatch, real_index().replace(row, row.replace("| 18 |", "| 18a |")), capsys)
    assert code == 1 and "no integer case count" in out
