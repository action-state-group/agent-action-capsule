# SPDX-License-Identifier: BSD-3-Clause
"""Certificate modes and non-record leaves outside strict mode, and the
producer's optional ``leaf_content`` capability (Evidence Bundle -02).

Strict mode is pinned by ``vectors/bundle/non-record-leaves`` and
``vectors/bundle/certificate-mode``; the plain verifier reports the same
interval and membership claims, without a verdict."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

pytest.importorskip("cll.log")
pytest.importorskip("scitt_cose")

from test_bundle_producer import Records, capsule, make_log  # noqa: E402

from agent_action_capsule.bundle import BundleBuildError, build_evidence_bundle, verify_bundle  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]


def _case(directory: str, case_id: str) -> dict:
    cases = json.loads((ROOT / "vectors" / "bundle" / directory / "vectors.json").read_text())["cases"]
    return copy.deepcopy(next(c for c in cases if c["id"] == case_id)["bundle"])


def _plain(bundle: dict) -> tuple[tuple[str, tuple[str, ...]], tuple[str, tuple[str, ...]]]:
    result = verify_bundle(bundle)
    assert result.verdict is None
    return (
        (result.interval_coverage.status, result.interval_coverage.findings),
        (result.per_record_membership.status, result.per_record_membership.findings),
    )


# -- the plain verifier ------------------------------------------------------------


def test_plain_producer_selected_is_not_a_failure():
    bundle = _case("certificate-mode", "incomplete-producer-selected-padded-log")
    assert _plain(bundle) == (("withheld", ("selection_not_checkable",)), ("pass", ()))


def test_plain_producer_selected_without_cose_is_qualified():
    bundle = _case("certificate-mode", "incomplete-producer-selected-padded-log")
    del bundle["checkpoint"]["cose"]
    assert _plain(bundle)[1] == ("pass", ("checkpoint_unverified",))


def test_plain_producer_selected_with_a_bad_cose_fails():
    bundle = _case("certificate-mode", "incomplete-producer-selected-padded-log")
    bundle["checkpoint"]["cose"] = bundle["checkpoint"]["cose"][:-4] + "AAAA"
    assert _plain(bundle)[1] == ("fail", ("checkpoint_authentication_invalid",))


def test_plain_producer_selected_tampered_proof_fails():
    bundle = _case("certificate-mode", "neg-producer-selected-padded-log-tampered")
    assert _plain(bundle)[1] == ("fail", (f"membership_proof_invalid:{bundle['root']}",))


@pytest.mark.parametrize("value", ["x-sampled", 7, "", {"mode": "producer-selected"}])
def test_plain_unknown_mode_is_withheld(value):
    bundle = _case("certificate-mode", "incomplete-producer-selected-padded-log")
    bundle["completeness"]["selection"] = value
    unsupported = ("withheld", ("certificate_mode_unsupported",))
    assert _plain(bundle) == (unsupported, unsupported)


def test_plain_padded_range_passes_and_unknown_type_withholds():
    assert _plain(_case("non-record-leaves", "pos-padded-whole-log")) == (("pass", ()), ("pass", ()))
    unknown = _case("non-record-leaves", "incomplete-unknown-leaf-type")
    assert _plain(unknown)[1] == ("withheld", ("non_record_leaf_type_unsupported:20",))
    del unknown["checkpoint"]["cose"]
    assert _plain(unknown)[1] == ("withheld", ("non_record_leaf_type_unsupported:20", "checkpoint_unverified"))


def test_plain_member_on_producer_selected_is_invalid():
    bundle = _case("non-record-leaves", "neg-non-record-leaves-on-producer-selected")
    assert _plain(bundle)[1] == ("fail", ("completeness_certificate_invalid",))


def test_strict_member_on_producer_selected_without_cose_is_still_invalid():
    bundle = _case("non-record-leaves", "neg-non-record-leaves-on-producer-selected")
    del bundle["checkpoint"]["cose"]
    result = verify_bundle(bundle, strict=True)
    assert result.per_record_membership.findings == ("completeness_certificate_invalid",)
    assert result.verdict == "INVALID"


def test_unknown_completeness_certificate_members_are_ignored():
    bundle = _case("non-record-leaves", "pos-padded-whole-log")
    bundle["completeness_certificate"]["x-note"] = {"anything": [1, 2]}
    bundle["completeness_certificate"]["non_record_leaves"][0]["x-note"] = "ignored"
    assert verify_bundle(bundle, strict=True).verdict == "VALID"


# -- the producer: leaf_content ------------------------------------------------------


def _padding(label: str) -> dict:
    from agent_action_capsule.canonical import json_digest

    body = {"record_type": "padding", "epistemic_type": "producer_claim", "store_nonce": json_digest(label)}
    return {"capsule_id": json_digest(body), **body}


class _WithContent:
    """A source with the optional ``leaf_content`` capability over another."""

    def __init__(self, source, contents: dict[int, dict]) -> None:
        self._source, self._contents = source, contents

    def __getattr__(self, name):
        return getattr(self._source, name)

    def leaf_content(self, seq: int):
        return copy.deepcopy(self._contents.get(seq))


@pytest.fixture
def padded():
    """Records at seq 1 and 3, padding at 2 and at the tip, 4."""
    records = Records()
    a, b = capsule("a"), capsule("b")
    records.put(a)
    records.put(b)
    pads = {2: _padding("2"), 4: _padding("4")}
    leaves = [a["capsule_id"], pads[2]["capsule_id"], b["capsule_id"], pads[4]["capsule_id"]]
    return make_log(leaves, records), records, (a, b), pads


def test_a_source_with_leaf_content_carries_padding_when_asked(padded):
    source, _, (a, b), pads = padded
    stored = {seq: {**pad, "signature": "00", "key_id": "11"} for seq, pad in pads.items()}  # envelope dropped
    bundle = build_evidence_bundle(_WithContent(source, stored), root=b["capsule_id"], interval_from=1,
                                   carry_non_record_leaves=True)
    assert bundle["completeness_certificate"]["non_record_leaves"] == [
        {"seq": 2, "content": pads[2]}, {"seq": 4, "content": pads[4]},
    ]
    assert [r["capsule_id"] for r in bundle["records"]] == [a["capsule_id"], b["capsule_id"]]
    assert verify_bundle(bundle, strict=True).verdict == "VALID"


def test_carrying_is_off_by_default(padded):
    source, _, (_, b), pads = padded
    with pytest.raises(BundleBuildError, match="seq 2 in the interval is not a record"):
        build_evidence_bundle(_WithContent(source, pads), root=b["capsule_id"], interval_from=1)


def test_an_old_source_is_unchanged(padded):
    """A source without ``leaf_content`` refuses a padded range as before, even
    when asked to carry; and a Bundle with no range is the same whether or not
    the source has the capability and carrying is on."""
    source, _, (_, b), pads = padded
    assert not hasattr(source, "leaf_content")
    with pytest.raises(BundleBuildError, match="seq 2 in the interval is not a record"):
        build_evidence_bundle(source, root=b["capsule_id"], interval_from=1, carry_non_record_leaves=True)
    old = build_evidence_bundle(source, root=b["capsule_id"], interval_from=None, closure_depth=0)
    new = build_evidence_bundle(_WithContent(source, pads), root=b["capsule_id"], interval_from=None,
                                closure_depth=0, carry_non_record_leaves=True)
    assert new == old
    assert "non_record_leaves" not in new["completeness_certificate"]


def test_no_padding_in_the_interval_means_no_member(padded):
    source, _, (_, b), pads = padded
    with_content = _WithContent(source, pads)
    with pytest.raises(BundleBuildError, match="seq 4"):
        build_evidence_bundle(source, root=b["capsule_id"], interval_from=3)
    bundle = build_evidence_bundle(with_content, root=b["capsule_id"], interval_from=3, carry_non_record_leaves=True)
    assert bundle["completeness_certificate"]["non_record_leaves"] == [{"seq": 4, "content": pads[4]}]


@pytest.mark.parametrize(
    "content, message",
    [
        ({"record_type": "checkpoint_stamp"}, "not a padding record"),
        ("padding", "not a padding record"),
        ("wrong-nonce", "does not hash to the leaf"),
        ("no-id", "does not hash to the leaf"),
    ],
)
def test_leaf_content_that_is_not_that_padding_is_refused(padded, content, message):
    source, _, (_, b), pads = padded
    if content == "wrong-nonce":
        content = {**pads[2], "store_nonce": "00" * 32}
    elif content == "no-id":
        content = {k: v for k, v in pads[2].items() if k != "capsule_id"}
    with pytest.raises(BundleBuildError, match=message):
        build_evidence_bundle(_WithContent(source, {**pads, 2: content}), root=b["capsule_id"], interval_from=1,
                              carry_non_record_leaves=True)


def test_a_malformed_padding_shape_is_refused_by_the_self_check(padded):
    source, _, (_, b), pads = padded
    from agent_action_capsule.canonical import json_digest

    body = {"record_type": "padding", "epistemic_type": "producer_claim", "store_nonce": "AB" * 32}
    bad = {"capsule_id": json_digest(body), **body}
    # The leaf must be the bad record's id for the producer to accept it; build
    # a log where it is.
    records = Records()
    a = capsule("a")
    records.put(a)
    log = make_log([a["capsule_id"], bad["capsule_id"]], records)
    with pytest.raises(BundleBuildError, match="non_record_leaf_malformed:2"):
        build_evidence_bundle(_WithContent(log, {2: bad}), root=a["capsule_id"], interval_from=1,
                              carry_non_record_leaves=True)
