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


def test_each_mapped_test_reads_its_set():
    # A mapping to a test that never reads the set would print PASS for a set
    # that did not run. Tests that build the path from parts are listed.
    split_path = {"test_bundle_vectors.py", "bundle.test.ts", "bundle-report-vector.test.ts"}
    for path, langs in rv.load_map().items():
        name = os.path.basename(path.rstrip("/"))
        name = name[: -len(".json")] if name.endswith(".json") else name
        for lang, selectors in langs.items():
            files = []
            for s in selectors:
                if lang == "python":
                    files.append(os.path.join(ROOT, "python", "tests", s))
                elif lang == "ts":
                    files.append(os.path.join(ROOT, "ts", "test", s))
                elif lang == "rust":
                    crate, test = s.split(":")
                    files.append(os.path.join(ROOT, "rust", crate, "tests", test + ".rs"))
                else:
                    pkg = os.path.join(ROOT, "go", s)
                    files += [os.path.join(pkg, f) for f in os.listdir(pkg) if f.endswith("_test.go")]
            if all(os.path.basename(f) in split_path for f in files):
                continue
            text = "".join(open(f, encoding="utf-8").read() for f in files)
            assert name in text, (lang, path, selectors)


def test_go_bundle_testdata_copy_is_the_published_file():
    # go/bundle's test reads this pinned copy, not vectors/bundle/vectors.json.
    copy = os.path.join(ROOT, "go", "bundle", "testdata", "vectors.json")
    published = os.path.join(ROOT, "vectors", "bundle", "vectors.json")
    assert open(copy, "rb").read() == open(published, "rb").read()


def _fake(monkeypatch, results):
    calls = []

    def fake_run(lang, selectors):
        calls.append(open(rv.BREAK_FILE, "rb").read())
        return results[len(calls) - 1]

    monkeypatch.setattr(rv, "run_selector", fake_run)
    return calls


def test_break_one_byte_restores_the_file_when_the_case_fails(monkeypatch):
    before = open(rv.BREAK_FILE, "rb").read()
    calls = _fake(monkeypatch, [(True, [], ""), (False, ["x"], "FAIL " + rv.BREAK_CASE)])
    assert rv.break_one_byte("go") is True
    assert open(rv.BREAK_FILE, "rb").read() == before
    assert calls[0] == before and len(calls[1]) == len(before)
    assert sum(a != b for a, b in zip(calls[1], before)) == 1


def test_break_one_byte_reports_a_problem_when_the_mutation_is_not_caught(monkeypatch):
    before = open(rv.BREAK_FILE, "rb").read()
    _fake(monkeypatch, [(True, [], ""), (True, [], "")])
    assert rv.break_one_byte("go") is False
    assert open(rv.BREAK_FILE, "rb").read() == before


def test_break_one_byte_rejects_a_failure_that_is_not_the_mutated_case(monkeypatch):
    # Missing dependency, timeout or another case failing must not read as a catch.
    _fake(monkeypatch, [(True, [], ""), (False, ["vitest is not installed"], "")])
    assert rv.break_one_byte("ts") is False


def test_break_one_byte_needs_a_passing_baseline(monkeypatch):
    before = open(rv.BREAK_FILE, "rb").read()
    calls = _fake(monkeypatch, [(False, ["setup missing"], "")])
    assert rv.break_one_byte("ts") is False
    assert len(calls) == 1 and open(rv.BREAK_FILE, "rb").read() == before
