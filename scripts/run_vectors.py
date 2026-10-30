#!/usr/bin/env python3
"""Run the published conformance vectors in one language, offline.

    python3 scripts/run_vectors.py <python|ts|go|rust>
    python3 scripts/run_vectors.py <language> --break-one-byte

For every in-repo set in VECTORS.md it runs the language's existing conformance
tests (scripts/vector_sets.json maps set to tests) and prints PASS, FAIL or SKIP
with the set's case count, the count scripts/check_vector_index.py recomputes
from the files and VECTORS.md states. A set the language has no tests for is
SKIP, never omitted. A set passes when every test mapped to it passes; a case
count is a property of the vector files, not of the number of tests.

--break-one-byte changes one character of one positive vector
(vectors/capsule/pos-v4-jcs-chain-committed/input.json), runs the
vectors/capsule/ set, shows the failure and restores the file. It exits 0 only
when the set fails and the file is restored byte for byte.

Nothing here touches the network: Go runs with GOPROXY=off (and the vendor
directory when present), Cargo with --offline --locked, npm and pip are not
invoked. Setup (dependencies) is documented in VECTORS.md.
"""
import importlib.util
import json
import os
import re
import shutil
import signal
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LANGS = ("python", "ts", "go", "rust")
BREAK_SET = "vectors/capsule/"
BREAK_FILE = os.path.join(ROOT, "vectors", "capsule", "pos-v4-jcs-chain-committed", "input.json")
BREAK_KEY = '"action_id": "'
FAIL_LINE = re.compile(
    r"(FAIL|FAILED|Error|error|assert|panicked|mismatch|expected|--- FAIL)", re.IGNORECASE
)


SKIP_LINE = re.compile(r"(\b\d+ skipped\b|--- SKIP|\bskipped\b.*\btests?\b)", re.IGNORECASE)


def load_counts():
    spec = importlib.util.spec_from_file_location(
        "check_vector_index", os.path.join(ROOT, "scripts", "check_vector_index.py")
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return {path: fn() for path, fn in mod.COUNTERS.items()}


def load_map():
    with open(os.path.join(ROOT, "scripts", "vector_sets.json"), encoding="utf-8") as f:
        data = json.load(f)
    data.pop("_comment", None)
    return data


def python_exe():
    venv = os.path.join(ROOT, "python", ".venv", "bin", "python")
    return venv if os.path.exists(venv) else sys.executable


def command(lang, selectors):
    """Return (argv, cwd, env) running the selectors, or raise RuntimeError with a setup hint."""
    env = dict(os.environ)
    if lang == "python":
        return ([python_exe(), "-m", "pytest", "-q", "--tb=short", "-p", "no:cacheprovider"]
                + ["tests/" + s for s in selectors]), os.path.join(ROOT, "python"), env
    if lang == "ts":
        bin_ = os.path.join(ROOT, "ts", "node_modules", ".bin", "vitest")
        if not os.path.exists(bin_):
            raise RuntimeError("ts dependencies are not installed (run `npm ci` in ts/ once; see VECTORS.md)")
        return [bin_, "run"] + ["test/" + s for s in selectors], os.path.join(ROOT, "ts"), env
    if lang == "go":
        env.update(GOWORK="off", GOPROXY="off", GOFLAGS="-mod=vendor" if os.path.isdir(os.path.join(ROOT, "go", "vendor")) else env.get("GOFLAGS", ""))
        # -count=1: the corpus lives outside the module, so go's test cache would not see an edited vector.
        return ["go", "test", "-count=1"] + list(selectors), os.path.join(ROOT, "go"), env
    # rust: selectors are crate:test-binary; one cargo call per crate.
    argv = ["cargo", "test", "--offline", "--locked", "--all-features"]
    crates = {}
    for s in selectors:
        crate, test = s.split(":")
        crates.setdefault(crate, []).append(test)
    if len(crates) != 1:
        raise RuntimeError("rust selectors for one set must share a crate")
    crate, tests = next(iter(crates.items()))
    argv += ["-p", crate]
    for t in tests:
        argv += ["--test", t]
    return argv, os.path.join(ROOT, "rust"), env


def run_selector(lang, selectors):
    """Run once; return (ok, reason lines)."""
    try:
        argv, cwd, env = command(lang, selectors)
    except RuntimeError as e:
        return False, [str(e)]
    if shutil.which(argv[0]) is None and not os.path.isabs(argv[0]):
        return False, ["%s is not installed" % argv[0]]
    try:
        proc = subprocess.run(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              universal_newlines=True, timeout=1500)
    except subprocess.TimeoutExpired:
        return False, ["timed out after 1500 s"]
    if proc.returncode == 0:
        # A skipped test means part of the set did not run (a missing optional
        # dependency); that must not read as a pass.
        skips = [l.strip() for l in proc.stdout.splitlines() if SKIP_LINE.search(l)]
        if skips:
            return "partial", ["some tests were skipped, so part of the set did not run (see VECTORS.md setup):"] + skips[:4]
        return True, []
    lines = [l.rstrip() for l in proc.stdout.splitlines() if l.strip()]
    picked = [l for l in lines if FAIL_LINE.search(l)][:12] or lines[-12:]
    return False, picked


def run_language(lang, only=None):
    counts, mapping = load_counts(), load_map()
    results = {}  # selector tuple -> (ok, reasons), so shared tests run once
    tally = {"PASS": 0, "FAIL": 0, "SKIP": 0, "PARTIAL": 0}
    skipped = []
    print("vector runner: %s" % lang)
    for path in counts:
        if only and path != only:
            continue
        sel = tuple(mapping.get(path, {}).get(lang, ()))
        n = counts[path]
        if not sel:
            tally["SKIP"] += 1
            skipped.append(path)
            print("SKIP    %-52s %5d cases  (no %s tests for this set)" % (path, n, lang))
            continue
        if sel not in results:
            results[sel] = run_selector(lang, sel)
        ok, reasons = results[sel]
        word = "PARTIAL" if ok == "partial" else "PASS" if ok else "FAIL"
        tally[word] += 1
        print("%-7s %-52s %5d cases" % (word, path, n))
        for r in reasons:
            print("        " + r)
    print("\n%s: %d pass, %d fail, %d partial, %d skipped"
          % (lang, tally["PASS"], tally["FAIL"], tally["PARTIAL"], tally["SKIP"]))
    if skipped:
        print("skipped (not implemented in %s): %s" % (lang, ", ".join(skipped)))
    return tally["FAIL"] == 0


def break_one_byte(lang):
    with open(BREAK_FILE, "rb") as f:
        original = f.read()
    text = original.decode("utf-8")
    at = text.index(BREAK_KEY) + len(BREAK_KEY)
    end = text.index('"', at)
    old = text[end - 1]
    new = chr(ord(old) + 1)
    mutated = (text[:end - 1] + new + text[end:]).encode("utf-8")
    rel = os.path.relpath(BREAK_FILE, ROOT)

    def restore(*_):
        with open(BREAK_FILE, "wb") as f:
            f.write(original)

    previous = {s: signal.signal(s, lambda *a: (restore(), sys.exit(130))) for s in (signal.SIGINT, signal.SIGTERM)}
    try:
        with open(BREAK_FILE, "wb") as f:
            f.write(mutated)
        print("break-one-byte: %s, last character of action_id %r -> %r" % (rel, old, new))
        failed = not run_language(lang, only=BREAK_SET)
    finally:
        restore()
        for s, h in previous.items():
            signal.signal(s, h)
    with open(BREAK_FILE, "rb") as f:
        restored = f.read() == original
    if failed and restored:
        print("\nbreak-one-byte: OK, the mutated vector failed and %s is restored" % rel)
        return True
    print("\nbreak-one-byte: PROBLEM, failed=%s restored=%s" % (failed, restored))
    return False


def main(argv):
    args = [a for a in argv if not a.startswith("--")]
    flags = [a for a in argv if a.startswith("--")]
    if len(args) != 1 or args[0] not in LANGS or set(flags) - {"--break-one-byte"}:
        print(__doc__.strip().split("\n\n")[0], file=sys.stderr)
        return 2
    if "--break-one-byte" in flags:
        return 0 if break_one_byte(args[0]) else 1
    return 0 if run_language(args[0]) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
