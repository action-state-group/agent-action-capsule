import importlib.util
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SPEC = importlib.util.spec_from_file_location("run_vectors", os.path.join(HERE, "run_vectors.py"))
rv = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rv)


def index_counts():
    text = open(os.path.join(ROOT, "VECTORS.md"), encoding="utf-8").read().split("<!-- sibling-sets -->")[0]
    rows = {}
    for line in text.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        m = re.fullmatch(r"`([^`]+)`", cells[0]) if line.startswith("|") else None
        if m and cells[-1].replace(",", "").isdigit():
            rows[m.group(1)] = int(cells[-1].replace(",", ""))
    return rows


def test_printed_counts_are_the_index_counts():
    assert rv.load_counts() == index_counts()


def test_every_set_has_an_entry_and_only_known_languages():
    mapping = rv.load_map()
    assert set(mapping) == set(index_counts())
    for path, langs in mapping.items():
        assert set(langs) <= set(rv.LANGS), path
        assert all(langs.values()), path


def test_selectors_exist():
    for path, langs in rv.load_map().items():
        for s in langs.get("python", []):
            assert os.path.exists(os.path.join(ROOT, "python", "tests", s)), (path, s)
        for s in langs.get("ts", []):
            assert os.path.exists(os.path.join(ROOT, "ts", "test", s)), (path, s)
        for s in langs.get("go", []):
            assert os.path.isdir(os.path.join(ROOT, "go", s)), (path, s)
        for s in langs.get("rust", []):
            crate, test = s.split(":")
            assert os.path.exists(os.path.join(ROOT, "rust", crate, "tests", test + ".rs")), (path, s)
        crates = {s.split(":")[0] for s in langs.get("rust", [])}
        assert len(crates) <= 1, path


def test_break_one_byte_target_is_a_positive_vector_of_the_break_set():
    assert rv.BREAK_SET in index_counts()
    text = open(rv.BREAK_FILE, encoding="utf-8").read()
    assert rv.BREAK_KEY in text
    assert os.path.basename(os.path.dirname(rv.BREAK_FILE)).startswith("pos-")


def test_break_one_byte_restores_the_file_when_the_run_fails(monkeypatch, capsys):
    before = open(rv.BREAK_FILE, "rb").read()
    seen = {}

    def fake_run(lang, only=None):
        seen["during"] = open(rv.BREAK_FILE, "rb").read()
        return False

    monkeypatch.setattr(rv, "run_language", fake_run)
    assert rv.break_one_byte("go") is True
    assert open(rv.BREAK_FILE, "rb").read() == before
    assert len(seen["during"]) == len(before) and seen["during"] != before
    assert sum(a != b for a, b in zip(seen["during"], before)) == 1


def test_break_one_byte_reports_a_problem_when_the_mutation_is_not_caught(monkeypatch):
    before = open(rv.BREAK_FILE, "rb").read()
    monkeypatch.setattr(rv, "run_language", lambda lang, only=None: True)
    assert rv.break_one_byte("go") is False
    assert open(rv.BREAK_FILE, "rb").read() == before
