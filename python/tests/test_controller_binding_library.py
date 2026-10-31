# SPDX-License-Identifier: BSD-3-Clause
"""``agent_action_capsule.controller_binding`` over vectors/controller-binding-v0.

Every case runs from its inputs alone, and the library's report is compared
with the case's whole expected binding block and its issuer_independence, as
``go/controllerbinding/vectors_test.go`` does. The BIP-340 check is run on the
BIP's own rows. ``test_controller_binding_v0_vectors.py`` is the independent
reading of the same vectors.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest

from agent_action_capsule import controller_binding as cb
from agent_action_capsule.canonical import jcs

ROOT = Path(__file__).resolve().parents[2]
CORPUS = json.loads((ROOT / "vectors" / "controller-binding-v0" / "vectors.json").read_text(encoding="utf-8"))
CASES = CORPUS["cases"]


def _time(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def _vector_credential(issuers):
    """The credential format the vectors fix for themselves (CB §10)."""

    def verify(octets, credential, keys):
        try:
            o = json.loads(octets)
        except ValueError:
            return cb.STATUS_FAIL
        if (not isinstance(o, dict) or len(o) != 5 or o.get("issuer") != credential.issuer
                or credential.issuer not in issuers):
            return cb.STATUS_FAIL
        if not all(isinstance(o.get(n), str) for n in ("issued_at", "organization", "sig")):
            return cb.STATUS_FAIL
        if o.get("keys") != list(keys):
            return cb.STATUS_FAIL
        signed = jcs({k: v for k, v in o.items() if k != "sig"})
        if not cb._verify_hex(credential.issuer, o["sig"], signed):
            return cb.STATUS_FAIL
        return cb.STATUS_PASS

    return verify


def _run(case):
    keys, times = [], []
    for half in case["inputs"]["halves"]:
        parsed = json.loads(half["octets_text"])
        keys.append(parsed["producer"])
        times.append(_time(parsed["issued_at"]))
    inputs = case["inputs"]
    opts = cb.Options(revocations=[r["octets_text"].encode() for r in inputs.get("revocations") or []])
    if inputs.get("credential"):
        opts.credential = inputs["credential"]["octets_text"].encode()
    if inputs.get("revocation_list"):
        lst = inputs["revocation_list"]
        opts.revocation_list = cb.RevocationList(
            json.dumps(lst["declaration"]).encode(), lst["octets_text"].encode(), _time(case["pins"]["evaluation_time"])
        )
    methods = case["pins"].get("verification_policy", {}).get("credential_methods_implemented", [])
    issuers = case["pins"].get("trust_policy", {}).get("credential_issuers", [])
    opts.credential_verifiers = {m: _vector_credential(issuers) for m in methods}
    return cb.verify(inputs["binding"]["octets_text"].encode(), times, opts), keys


def test_corpus_size():
    assert len(CASES) == 42


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_vectors(case):
    report, keys = _run(case)
    want = case["expected"]["binding"]
    assert report.claim == want["claim"]
    assert report.binding_digest == want["binding_digest"]
    assert report.properties == want["properties"]
    assert report.binds_pair(*keys) == want["binds_pair"]
    assert report.applies_to(*keys) == want["applies"]
    assert report.proves == want["proves"]
    if report.revocation_list is not None:
        assert report.revocation_list.counts == (report.revocation_list.reason == "")
    got = report.revocation_list.to_dict() if report.revocation_list else None
    assert got == want.get("revocation_list")
    # satisfied_becomes belongs to the interop profile verifier, not to this module.
    wanted = {k: v for k, v in case["expected"]["issuer_independence"].items() if k != "satisfied_becomes"}
    assert cb.pair_independence(keys[0], keys[1], report) == wanted
    failed = sorted(p for p, s in report.properties.items() if s == cb.STATUS_FAIL)
    assert failed == sorted(case["expected"]["fails"])


def test_no_credential_verifier_is_not_checked():
    for case in CASES:
        if not case["inputs"].get("credential"):
            continue
        times = [_time(json.loads(h["octets_text"])["issued_at"]) for h in case["inputs"]["halves"]]
        report = cb.verify(
            case["inputs"]["binding"]["octets_text"].encode(),
            times,
            cb.Options(credential=case["inputs"]["credential"]["octets_text"].encode()),
        )
        assert report.properties[cb.PROPERTY_CREDENTIAL] == cb.STATUS_NOT_CHECKED, case["id"]
        assert report.applies() == case["expected"]["binding"]["applies"], case["id"]


# The BIP's own rows 5, 6 and 12 of test-vectors.csv (two valid, three invalid).
BIP340_ROWS = [
    ("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
     True),
    ("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
     "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
     "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
     True),
    ("EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34",
     "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
     "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
     False),
    ("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
     "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
     "FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A14602975563CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2",
     False),
    ("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
     "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
     "0000000000000000000000000000000000000000000000000000000000000000123DDA8328AF9C23A94C1FEECFD123BA4FB73476F0D594DCB65C6425BD186051",
     False),
]


@pytest.mark.parametrize("key,message,signature,valid", BIP340_ROWS)
def test_bip340_agrees_with_the_bips_vectors(key, message, signature, valid):
    assert cb.verify_bip340(bytes.fromhex(key), bytes.fromhex(message), bytes.fromhex(signature)) is valid


def test_not_json_is_a_form_failure():
    report = cb.verify(b"not json")
    assert report.properties == {cb.PROPERTY_FORM: cb.STATUS_FAIL}
    assert report.binding_digest == ""
