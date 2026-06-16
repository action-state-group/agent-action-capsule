# SPDX-License-Identifier: BSD-3-Clause
"""CLI front door + optional two-layer composition.

The payload-only paths run with zero extras. The --transparent tests adapt to the
environment: the real two-layer path runs only when scitt-cose is installed
(importorskip); the graceful-missing-dependency path runs only when it is not.
"""
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from agent_action_capsule.cli import main

VEC = Path(__file__).resolve().parents[2] / "test-vectors"
EXAMPLE = Path(__file__).resolve().parents[2] / "examples" / "build_and_verify.py"
_SCITT = importlib.util.find_spec("scitt_cose") is not None


# ------------------------------------------------------------ payload-only core
def test_payload_positive(capsys):
    rc = main(["verify", str(VEC / "pos-executed-confirmed" / "input.json")])
    assert rc == 0
    assert "ok: True" in capsys.readouterr().out


def test_payload_negative_shows_check_number(capsys):
    rc = main(["verify", str(VEC / "neg-confirmed-without-response" / "input.json")])
    assert rc == 1
    out = capsys.readouterr().out
    assert "check 3" in out and "confirmed_without_response" in out


def test_json_output_is_machine_readable(capsys):
    rc = main(["verify", "--json", str(VEC / "pos-blocked" / "input.json")])
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["ok"] is True and doc["capsule_id_recomputed"]


def test_store_concurrent_supersedes(capsys):
    rc = main(["verify", "--store", str(VEC / "pos-concurrent-supersedes" / "input.json")])
    assert rc == 0
    assert "concurrent_supersedes" in capsys.readouterr().out


def test_malformed_input_is_exit_2_not_traceback(capsys, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{ not json")
    rc = main(["verify", str(bad)])
    assert rc == 2  # distinct "cannot run" code; no traceback


# ------------------------------------------------------------- transparent path
@pytest.mark.skipif(_SCITT, reason="scitt-cose installed; missing-dep path not exercised")
def test_transparent_missing_dependency_is_graceful(capsys, tmp_path):
    stmt = tmp_path / "s.cose"
    stmt.write_bytes(b"x")
    key = tmp_path / "k.pem"
    key.write_text("x")
    rc = main(["verify", "--transparent", str(stmt), "--issuer-key", str(key)])
    assert rc == 2
    assert "transparent" in capsys.readouterr().err.lower()


@pytest.mark.skipif(not _SCITT, reason="needs the optional [transparent] extra")
def test_transparent_requires_issuer_key(capsys, tmp_path):
    stmt = tmp_path / "s.cose"
    stmt.write_bytes(b"x")
    rc = main(["verify", "--transparent", str(stmt)])
    assert rc == 2
    assert "issuer-key" in capsys.readouterr().err


@pytest.mark.skipif(not _SCITT, reason="needs the optional [transparent] extra")
def test_transparent_two_layers_self_attested_then_anchored(capsys, tmp_path):
    import hashlib

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from scitt_cose import attach_receipts, build_receipt, build_signed_statement

    cap = (VEC / "pos-executed-confirmed" / "input.json").read_bytes()
    sk = ed25519.Ed25519PrivateKey.generate()
    priv = sk.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    pub = sk.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    pk = tmp_path / "pub.pem"
    pk.write_bytes(pub)

    stmt = build_signed_statement(
        cap, alg="EdDSA", private_key_pem=priv,
        issuer="https://issuer.example", subject="urn:agent-action-capsule:po",
        content_type="application/agent-action-capsule+json",
    )
    sf = tmp_path / "stmt.cose"
    sf.write_bytes(stmt)

    # signature only -> self_attested, payload ok
    rc = main(["verify", "--transparent", str(sf), "--issuer-key", str(pk)])
    out = capsys.readouterr().out
    assert rc == 0 and "self_attested" in out and "ok: True" in out
    assert "anchored" not in out  # no receipt -> never anchored

    # with a verified receipt -> anchored
    leaf = hashlib.sha256(stmt).hexdigest()
    receipt = build_receipt(leaf_entry_hex=leaf, leaf_index=0, tree_entries_hex=[leaf], alg="EdDSA", log_private_key_pem=priv)
    tf = tmp_path / "transparent.cose"
    tf.write_bytes(attach_receipts(stmt, [receipt]))
    rc = main(["verify", "--transparent", str(tf), "--issuer-key", str(pk), "--log-key", str(pk), "--leaf-entry-hex", leaf])
    out = capsys.readouterr().out
    assert rc == 0 and "anchored" in out

    # receipt verification requested, but the bare statement carries none ->
    # ok=False WITH an explanation (not a silent failure).
    rc = main(["verify", "--transparent", str(sf), "--issuer-key", str(pk), "--log-key", str(pk), "--leaf-entry-hex", leaf])
    out = capsys.readouterr().out
    assert rc == 1 and "carries no receipt" in out


# --------------------------------------------------------------------- example
def test_build_and_verify_example_runs():
    # Ensure the example is importable even in a clean env that hasn't run
    # `pip install -e .`: the subprocess doesn't inherit pytest's sys.path, so
    # we inject PYTHONPATH pointing at the package source tree.
    src = Path(__file__).resolve().parents[1]  # python/
    env = os.environ.copy()
    env["PYTHONPATH"] = str(src) + (os.pathsep + env["PYTHONPATH"] if "PYTHONPATH" in env else "")
    r = subprocess.run([sys.executable, str(EXAMPLE)], capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stderr
    assert "round trip ok" in r.stdout
