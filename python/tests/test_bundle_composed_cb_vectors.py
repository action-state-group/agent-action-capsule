# SPDX-License-Identifier: BSD-3-Clause
"""The Evidence Bundle -02 ``controller_binding`` join vectors, rederived.

An independent reading of the draft text ("Controller Binding Records",
"Joins", "Observers and Redundancy", "Empty-History Bundles"): the standard
library, ``cryptography`` for Ed25519, CLL's offline checkpoint verifier for
an empty-history member's signed checkpoint, and the bytes in
``vectors/bundle/composed-controller-binding/``. Nothing is imported from the
generator or from this repository's verifiers.
"""
from __future__ import annotations

import base64
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
from cll.checkpoint import verify_checkpoint_cose_offline
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


def _ed25519_keys(record: dict) -> bool:
    """No key_types, or ed25519 for both keys: the only key type -02 defines."""
    return record.get("key_types", ["ed25519", "ed25519"]) == ["ed25519", "ed25519"]


def _well_formed(record: dict) -> bool:
    """Controller Binding Records: members and values."""
    claim = record.get("claim")
    if claim not in METHODS or set(record) - {"key_types"} != BASE | METHODS[claim][1]:
        return False
    if "key_types" in record and not (isinstance(record["key_types"], list) and len(record["key_types"]) == 2
                                      and all(isinstance(k, str) for k in record["key_types"])):
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
    sigs_ok = isinstance(record["sigs"], list) and all(
        isinstance(s, dict) and set(s) == {"key_id", "sig"} and isinstance(s["key_id"], str)
        and HEX64.fullmatch(s["key_id"]) is not None
        and (not _ed25519_keys(record) or isinstance(s["sig"], str) and HEX128.fullmatch(s["sig"]) is not None)
        for s in record["sigs"])
    if claim == "delegated_by" and record["delegator"] not in keys:
        return False
    if claim == "same_organization_credentialed":
        credential = record["credential"]
        if not (isinstance(credential, dict) and set(credential) == {"issuer", "method", "digest"}
                and all(isinstance(credential[k], str) for k in credential)
                and HEX64.fullmatch(credential["issuer"]) and HEX64.fullmatch(credential["digest"])):
            return False
    return (record["binding_version"] == "controller-binding/0"
            and record["revocation"] == "revocation_statement/0"
            and isinstance(record["nonce"], str) and record["nonce"] != ""
            and sigs_ok)


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


def _link(join: dict, side_a: tuple[Any, Any], side_b: tuple[Any, Any], bindings: list[dict],
          revocations: list[dict]) -> bool | None:
    """Joins, controller_binding: linked, unjoined (False) or not derivable
    (None). Each side is (key identifier, time T)."""
    if "identifier_digest" not in join:
        return None
    (va, ta), (vb, tb) = side_a, side_b
    times = (ta, tb)
    derivable = False
    for record in bindings:
        if _sha(_jcs(_without(record, "sigs"))) != join["identifier_digest"]:
            continue
        if not _well_formed(record):
            derivable = True
            continue
        if record["method"] not in ("dual_signature/0", "dual_signature_credential/0") or not _ed25519_keys(record):
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


def _empty(member: dict) -> bool:
    """Empty-History Bundles: no records and no root."""
    bundle = member["bundle"]
    return bundle["records"] == [] and "root" not in bundle


def _checkpoint_side(member: dict) -> tuple[Any, Any] | None:
    """An empty-history member's key and T: the key that signed its
    checkpoint.cose, at that checkpoint's timestamp. None without one."""
    encoded = member["bundle"].get("checkpoint", {}).get("cose")
    if not isinstance(encoded, str):
        return None
    verified = verify_checkpoint_cose_offline(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    if not verified.ok:
        return None
    return verified.decoded.key_id, _time(verified.decoded.timestamp, RECORD_TIME)


def _record_side(record: dict, pointer: str) -> tuple[Any, Any]:
    return _pointer(record, pointer), _time(record.get("timestamp"), RECORD_TIME)


def _derive(case: dict, join: dict, by_id: dict) -> str | None:
    a, b = (by_id[i] for i in join["members"])
    bindings, revocations = case["controller_bindings"], case["binding_revocations"]
    if "pointer" not in join:
        return None
    if _empty(a) or _empty(b):
        # One member has records: one_sided when linked, never agree.
        full, empty = (b, a) if _empty(a) else (a, b)
        side = _checkpoint_side(empty)
        if side is None:
            return None
        linked = _link(join, _record_side(_root(full), join["pointer"]), side, bindings, revocations)
        return None if linked is None else "one_sided" if linked else "unjoined"
    ra, rb = _root(a), _root(b)
    linked = _link(join, _record_side(ra, join["pointer"]), _record_side(rb, join["pointer"]), bindings, revocations)
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
    assert {"agree", "unjoined", None, "one_sided"} <= derived
    assert DATA["count"] == len(CASES) == 14


def test_an_empty_member_whose_checkpoint_does_not_verify_has_no_key():
    member = next(m for m in _block(CASES["controller-binding-empty-member-linked"])["members"] if m["id"] == "responder-b")
    member = json.loads(json.dumps(member))
    cose = member["bundle"]["checkpoint"]["cose"]
    member["bundle"]["checkpoint"]["cose"] = cose[:-4] + ("AAAA" if cose[-4:] != "AAAA" else "BBBB")
    assert _checkpoint_side(member) is None


@pytest.mark.parametrize("case_id", sorted(c for c in CASES if "empty-member" in c))
def test_an_empty_member_shows_no_history(case_id):
    """Empty-History Bundles: well formed, no history since its checkpoint's
    timestamp (none without one), never failed and never an absence."""
    case = CASES[case_id]
    member = next(m for m in _block(case)["members"] if m["id"] == "responder-b")
    bundle = member["bundle"]
    assert member["outcome"] == "artifact" and _empty(member)
    assert bundle["completeness"]["records_mode"] == "complete" and bundle["completeness"]["payloads_mode"] == "none"
    assert not {"completeness_certificate", "disclosures", "disclosure_record"} & set(bundle)
    assert member["digest"] == _sha(_jcs({k: v for k, v in bundle.items() if k != "countersignatures"}))
    side = _checkpoint_side(member)
    want = case["expect"]["members"]["responder-b"]
    assert want["history"] == {"state": "none", "since": side and bundle["checkpoint"]["timestamp"]}
    assert want["claims"] == {"graph_closure": "pass", "interval_coverage": "withheld",
                              "per_record_membership": "withheld"}
    if side is not None:
        # The key that signed the checkpoint is responder-b's, the key its records were under.
        assert side[0] == DATA["keys"]["responder-b"]["public_key_hex"]


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
