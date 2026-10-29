# SPDX-License-Identifier: BSD-3-Clause
"""The Evidence Bundle -02 ``controller_binding`` join vectors, rederived.

An independent reading of the draft text ("Controller Binding Records",
"Joins", "Observers and Redundancy"): the standard library, ``cryptography``
for Ed25519 and the bytes in ``vectors/bundle/composed-controller-binding/``.
Nothing is imported from the generator or from a verifier.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "vectors" / "bundle" / "composed-controller-binding"
GENERATOR = ROOT / "python" / "scripts" / "generate_bundle_composed_cb_vectors.py"
KIND = "composed/v1"

DATA = json.loads((VECTORS / "vectors.json").read_text(encoding="utf-8"))
CASES = {c["id"]: c for c in DATA["cases"]}

HEX64 = re.compile(r"[0-9a-f]{64}")
HEX128 = re.compile(r"[0-9a-f]{128}")
TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
# A root record's timestamp may carry fractional seconds; times compare as instants.
RECORD_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z")
METHODS = {"same_controller_asserted": ("dual_signature/0", set()),
           "delegated_by": ("dual_signature/0", {"delegator"}),
           "same_organization_credentialed": ("dual_signature_credential/0", {"credential"})}
BASE = {"binding_version", "claim", "method", "keys", "issued_at", "not_before", "not_after", "revocation",
        "nonce", "sigs"}


def _jcs(value: Any) -> bytes:
    # RFC 8785 for these vectors' value space (ASCII keys, no floats).
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _pointer(doc: Any, pointer: str) -> Any:
    cur = doc
    for token in pointer[1:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if not isinstance(cur, dict) or token not in cur:
            return None
        cur = cur[token]
    return cur


def _time(value: Any, form: re.Pattern[str] = TIME) -> datetime | None:
    if not isinstance(value, str) or not form.fullmatch(value):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _ed25519(key_hex: str, message: bytes, sig_hex: Any) -> bool:
    if not isinstance(sig_hex, str) or not HEX128.fullmatch(sig_hex):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex)).verify(bytes.fromhex(sig_hex), message)
    except (InvalidSignature, ValueError):
        return False
    return True


def _without(value: dict, name: str) -> dict:
    return {k: v for k, v in value.items() if k != name}


def _well_formed(record: dict) -> bool:
    """Controller Binding Records: members and values."""
    claim = record.get("claim")
    if claim not in METHODS or set(record) != BASE | METHODS[claim][1]:
        return False
    method = record["method"]
    if not isinstance(method, str) or any(m == method != METHODS[claim][0] for m, _ in METHODS.values()):
        return False
    keys = record["keys"]
    if not (isinstance(keys, list) and len(keys) == 2 and all(isinstance(k, str) and HEX64.fullmatch(k) for k in keys)
            and keys[0] < keys[1]):
        return False
    issued, before, after = (_time(record[k]) for k in ("issued_at", "not_before", "not_after"))
    if None in (issued, before, after) or not before <= issued < after:
        return False
    return (record["binding_version"] == "controller-binding/0"
            and record["revocation"] == "revocation_statement/0"
            and isinstance(record["nonce"], str) and record["nonce"] != ""
            and isinstance(record["sigs"], list)
            and all(isinstance(s, dict) and set(s) == {"key_id", "sig"} for s in record["sigs"]))


def _signed_by_both(record: dict) -> bool:
    sigs, keys = record["sigs"], record["keys"]
    message = _jcs(_without(record, "sigs"))
    return len(sigs) == 2 and all(s["key_id"] == k and _ed25519(k, message, s["sig"]) for s, k in zip(sigs, keys))


def _revokes(statement: dict, digest: str, keys: list[str], times: tuple[str, str]) -> bool:
    if set(statement) != {"revocation_version", "binding", "key_id", "revoked_at", "sig"}:
        return False
    revoked_at = _time(statement["revoked_at"])
    return (statement["revocation_version"] == "controller-binding-revocation/0"
            and statement["binding"] == digest and statement["key_id"] in keys and revoked_at is not None
            and _ed25519(statement["key_id"], _jcs(_without(statement, "sig")), statement["sig"])
            and any(revoked_at <= t for t in times))


def _link(join: dict, ra: dict, rb: dict, bindings: list[dict], revocations: list[dict]) -> bool | None:
    """Joins, controller_binding: linked, unjoined (False) or not derivable (None)."""
    va, vb = _pointer(ra, join["pointer"]), _pointer(rb, join["pointer"])
    times = (_time(ra.get("timestamp"), RECORD_TIME), _time(rb.get("timestamp"), RECORD_TIME))
    derivable = False
    for record in bindings:
        if _sha(_jcs(_without(record, "sigs"))) != join["identifier_digest"]:
            continue
        if not _well_formed(record):
            derivable = True
            continue
        if record["method"] not in ("dual_signature/0", "dual_signature_credential/0"):
            continue
        derivable = True
        keys = record["keys"]
        if not (isinstance(va, str) and isinstance(vb, str) and {va, vb} == set(keys)):
            continue
        if None in times or not all(_time(record["not_before"]) <= t < _time(record["not_after"]) for t in times):
            continue
        if not _signed_by_both(record):
            continue
        if not any(_revokes(s, join["identifier_digest"], keys, times) for s in revocations):
            return True
    return False if derivable else None


def _root(member: dict) -> dict:
    bundle = member["bundle"]
    return next(r for r in bundle["records"] if r["capsule_id"] == bundle["root"])


def _derive(case: dict, join: dict, by_id: dict) -> str | None:
    a, b = (by_id[i] for i in join["members"])
    ra, rb = _root(a), _root(b)
    linked = _link(join, ra, rb, case["controller_bindings"], case["binding_revocations"])
    if linked is None:
        return None
    if not linked:
        return "unjoined"
    same = all(_pointer(ra, p) is not None and _jcs(_pointer(ra, p)) == _jcs(_pointer(rb, p))
               for p in join.get("compare", []))
    return "agree" if same else "mismatch"


def _block(case: dict) -> dict:
    return case["container"]["extensions"][KIND]


def test_generator_reproduces_every_file_byte_for_byte(tmp_path):
    shutil.copyfile(VECTORS / "README.md", tmp_path / "README.md")
    subprocess.run([sys.executable, str(GENERATOR), "--out", str(tmp_path)], check=True)
    committed = sorted(p.name for p in VECTORS.iterdir() if p.is_file())
    assert committed == sorted(p.name for p in tmp_path.iterdir() if p.is_file())
    for name in committed:
        assert (tmp_path / name).read_bytes() == (VECTORS / name).read_bytes(), name


def test_the_three_required_join_states_are_present():
    derived = {c["expect"]["joins"][0]["derived"] for c in CASES.values()}
    assert {"agree", "unjoined", None} <= derived
    assert DATA["count"] == len(CASES) == 8


@pytest.mark.parametrize("case_id", sorted(CASES))
def test_join_is_rederived(case_id):
    case = CASES[case_id]
    block = _block(case)
    by_id = {m["id"]: m for m in block["members"]}
    (join,), (want,) = block["joins"], case["expect"]["joins"]
    assert join["basis"] == "controller_binding"
    derived = _derive(case, join, by_id)
    assert derived == want["derived"]
    assert join["state"] == want["declared"]
    result = "not_derivable" if derived is None else "derived_matches" if derived == join["state"] else \
        "join_state_mismatch"
    assert want["result"] == result
    assert case["expect"]["status"] == {"not_derivable": "withheld", "derived_matches": "pass",
                                        "join_state_mismatch": "fail"}[result]


@pytest.mark.parametrize("case_id", sorted(CASES))
def test_a_bound_agreement_is_redundant_never_corroborating(case_id):
    case = CASES[case_id]
    block = _block(case)
    by_id = {m["id"]: m for m in block["members"]}
    (want,) = case["expect"]["corroboration"]
    if _derive(case, block["joins"][0], by_id) != "agree":
        assert want["result"] == "not_applicable"
        return
    # Separate custody and keys: only the binding makes the pair redundant.
    custody = {o["id"]: o["custody_domain"] for o in block["observers"]}
    a, b = (by_id[i] for i in block["joins"][0]["members"])
    assert custody[a["observer"]] != custody[b["observer"]] and _root(a)["key_id"] != _root(b)["key_id"]
    assert want == {"members": ["responder-a", "responder-b"], "result": "redundant",
                    "reason": "controller_binding", "report": "redundant, not corroborating"}


@pytest.mark.parametrize("case_id", sorted(CASES))
def test_without_delivered_records_nothing_derives(case_id):
    case = dict(CASES[case_id], controller_bindings=[], binding_revocations=[])
    block = _block(case)
    assert _derive(case, block["joins"][0], {m["id"]: m for m in block["members"]}) is None


def test_the_binding_is_outside_the_composed_digest():
    linked, revoked = CASES["controller-binding-linked"], CASES["controller-binding-revoked-declared-agree"]
    assert linked["expect"]["composed_digest"] == revoked["expect"]["composed_digest"]
    assert linked["expect"]["canonical_preimage"] == _jcs({
        "kind": KIND,
        "members": sorted(({k: m[k] for k in ("id", "observer", "request_digest", "outcome", "digest")}
                           for m in _block(linked)["members"]), key=lambda m: m["id"]),
        "observers": sorted(_block(linked)["observers"], key=lambda o: o["id"]),
        "joins": _block(linked)["joins"],
        "not_requested": [],
    }).decode("utf-8")
