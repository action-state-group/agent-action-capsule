# SPDX-License-Identifier: BSD-3-Clause
"""``agent_action_capsule.composed`` over the composed/v1 vectors.

The library runs every case of ``vectors/bundle/composed/`` (-01 joins) and
``vectors/bundle/composed-controller-binding/`` (-02 ``controller_binding``
joins and empty-history members) and is compared with each case's whole
``expect``, as ``go/bundle`` does. ``test_bundle_composed_cb_vectors.py`` and
``test_bundle_composed_vectors.py`` stay the independent readings.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

pytest.importorskip("cll")

from agent_action_capsule import composed as c  # noqa: E402
from agent_action_capsule.bundle import bundle_digest, verify_bundle  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]


def _cases(name: str) -> list:
    return json.loads((ROOT / "vectors" / "bundle" / name / "vectors.json").read_text(encoding="utf-8"))["cases"]


COMPOSED = _cases("composed")
BINDING = _cases("composed-controller-binding")


def _block(container: dict) -> dict:
    return container["extensions"][c.COMPOSED_KIND]


def expect_shape(result: c.ComposedResult) -> dict:
    """A ComposedResult in the vectors' ``expect`` vocabulary."""
    members = {}
    for m in result.members:
        claims = None
        if m.bundle is not None:
            claims = {
                "graph_closure": m.bundle.graph_closure.status,
                "interval_coverage": m.bundle.interval_coverage.status,
                "per_record_membership": m.bundle.per_record_membership.status,
            }
        member = {"outcome": m.outcome, "body": m.body, "digest": m.digest, "claims": claims}
        if m.bundle is not None and m.bundle.history is not None:
            member["history"] = {"state": m.bundle.history["state"], "since": m.bundle.history["since"]}
        if m.response_signature:
            def binding(finding: str, findings: list = m.findings) -> str:
                return "mismatch" if finding in findings else "matches"

            member["response"] = {
                "request_digest": binding("response_request_digest_mismatch"),
                "artifact_digest": binding("response_artifact_digest_mismatch"),
                "signature": m.response_signature,
            }
        members[m.id] = member
    closure = {"status": result.composition_closure.status, "missing": list(result.composition_closure.missing)}
    if result.composition_closure.status == "withheld":
        closure["finding"] = result.composition_closure.findings[0]
    corroboration = []
    for x in result.corroboration:
        value = {"members": list(x.members), "result": x.result}
        for key, field in (("reason", x.reason), ("report", x.report), ("qualifier", x.qualifier)):
            if field:
                value[key] = field
        corroboration.append(value)
    return {
        "composed_digest": result.composed_digest.recomputed,
        "status": result.status,
        "members": members,
        "composition_closure": closure,
        "joins": [
            {"members": list(j.members), "declared": j.declared, "derived": j.derived or None, "result": j.result}
            for j in result.joins
        ],
        "corroboration": corroboration,
    }


def _want(case: dict) -> dict:
    skip = {"canonical_preimage", "composed_digest_equals_case", "strict", "verdict"}
    return {k: v for k, v in case["expect"].items() if k not in skip}


def _composed(result):
    assert len(result.extensions) == 1
    extension = result.extensions[0]
    assert extension.kind == c.COMPOSED_KIND and extension.integrity_covered
    assert extension.composed.status == extension.status
    return extension.composed


@pytest.mark.parametrize("case", COMPOSED, ids=[x["id"] for x in COMPOSED])
def test_composed_vectors(case):
    block = _block(case["container"])
    assert c.composed_digest_preimage(block).decode() == case["expect"]["canonical_preimage"]
    assert c.composed_digest(block) == case["expect"]["composed_digest"] == block["composed_digest"]
    result = verify_bundle(case["container"])
    assert result.graph_closure.status == "pass"
    composed = _composed(result)
    assert composed.status == case["expect"]["status"], composed.findings
    assert composed.composed_digest.matches
    assert composed.composed_digest.recomputed != result.bundle_digest
    assert expect_shape(composed) == _want(case)
    for member in block["members"]:
        if "bundle" in member:
            assert member["digest"] == bundle_digest(member["bundle"])


def _options(case: dict) -> c.ComposedOptions:
    return c.ComposedOptions(
        controller_bindings=case["controller_bindings"], binding_revocations=case["binding_revocations"]
    )


@pytest.mark.parametrize("case", BINDING, ids=[x["id"] for x in BINDING])
def test_controller_binding_vectors(case):
    assert len(BINDING) == 14
    block = _block(case["container"])
    assert c.composed_digest_preimage(block).decode() == case["expect"]["canonical_preimage"]
    composed = _composed(verify_bundle(case["container"], composed_options=_options(case)))
    assert composed.status == case["expect"]["status"], composed.findings
    assert expect_shape(composed) == _want(case)


@pytest.mark.parametrize("case", BINDING, ids=[x["id"] for x in BINDING])
def test_controller_binding_needs_the_delivered_record(case):
    composed = _composed(verify_bundle(case["container"]))
    assert composed.joins[0].result == "not_derivable"
    assert composed.corroboration[0].result == "not_applicable"


def _linked() -> dict:
    return next(x for x in BINDING if x["id"] == "controller-binding-linked")


def _verify(container: dict, case: dict, bindings=None):
    options = c.ComposedOptions(
        controller_bindings=case["controller_bindings"] if bindings is None else bindings, binding_revocations=[]
    )
    return _composed(verify_bundle(container, composed_options=options))


def test_a_failed_signature_never_corroborates():
    case = _linked()
    mutations = {
        "second signature from the first key": lambda r: r["sigs"][1].update(sig=r["sigs"][0]["sig"]),
        "one signature": lambda r: r.update(sigs=r["sigs"][:1]),
        "third signature": lambda r: r.update(sigs=r["sigs"] + [r["sigs"][0]]),
        "sigs out of key order": lambda r: r.update(sigs=[r["sigs"][1], r["sigs"][0]]),
    }
    for name, mutate in mutations.items():
        record = copy.deepcopy(case["controller_bindings"][0])
        mutate(record)
        composed = _verify(case["container"], case, [record])
        assert composed.joins[0].derived == "unjoined", name
        assert composed.joins[0].result == "join_state_mismatch", name
        assert composed.corroboration[0].result == "not_applicable", name


def test_a_record_under_one_key_is_not_a_pair():
    case = _linked()
    container = copy.deepcopy(case["container"])
    members = _block(container)["members"]
    first = members[0]["bundle"]["records"][0]
    second = members[1]["bundle"]["records"][0]
    second["key_id"] = first["key_id"]
    assert _verify(container, case).joins[0].derived == "unjoined"


def test_a_join_without_digest_or_pointer_is_not_derivable():
    case = _linked()
    for member in ("identifier_digest", "pointer"):
        container = copy.deepcopy(case["container"])
        block = _block(container)
        join = block["joins"][0]
        del join[member]
        join["state"] = "unjoined"
        for m in block["members"]:
            if "bundle" in m:
                m["digest"] = bundle_digest(m["bundle"])
        block["composed_digest"] = c.composed_digest(block)
        assert _verify(container, case).joins[0].result == "not_derivable", member


def test_fractional_record_time_compares_as_an_instant():
    case = _linked()
    for stamp, derived in {
        "2026-10-02T12:10:00.5Z": "agree",
        "2027-09-30T23:59:59.999Z": "agree",
        "2027-10-01T00:00:00.0Z": "unjoined",
        "2026-09-30T23:59:59.9Z": "unjoined",
        "2026-10-02T12:10:00+00:00": "unjoined",
    }.items():
        container = copy.deepcopy(case["container"])
        _block(container)["members"][0]["bundle"]["records"][0]["timestamp"] = stamp
        assert _verify(container, case).joins[0].derived == derived, stamp


def test_binding_form_rules_of_minus_02():
    base = _linked()["controller_bindings"][0]
    keys = base["keys"]
    cases = {
        "empty nonce": lambda r: r.update(nonce=""),
        "keys descending": lambda r: r.update(keys=[keys[1], keys[0]]),
        "sig not hex": lambda r: r["sigs"][0].update(sig="zz"),
        "key_types one entry": lambda r: r.update(key_types=["ed25519"]),
        "extra member": lambda r: r.update(x="y"),
    }
    for name, mutate in cases.items():
        record = copy.deepcopy(base)
        mutate(record)
        assert c._binding_report(record, [], [])[1] is False, name
    typed = copy.deepcopy(base)
    typed["key_types"] = ["ed25519", "x-example-type"]
    typed["sigs"][1]["sig"] = {"x": "y"}
    assert c._binding_report(typed, [], [])[1] is True
    assert c._ed25519_keys(typed) is False
    # bip340 is not a -02 key type: its short nonce does not make the record malformed.
    typed["key_types"] = ["ed25519", "bip340"]
    assert c._binding_report(typed, [], [])[1] is True
    assert c._implemented(typed) is False


def test_a_delivered_record_that_is_not_an_object_is_skipped():
    case = next(x for x in BINDING if x["id"] == "controller-binding-linked")
    opts = c.ComposedOptions(controller_bindings=["not an object", 7, None, *case["controller_bindings"]])
    result = verify_bundle(case["container"], composed_options=opts)
    joins = next(e.composed for e in result.extensions if e.composed is not None).joins
    assert [j.derived for j in joins] == ["agree"]
