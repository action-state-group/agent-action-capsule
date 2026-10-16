# SPDX-License-Identifier: BSD-3-Clause
"""``agent_action_capsule.witness`` edges the strict Bundle vectors do not reach."""
from __future__ import annotations

import pytest

pytest.importorskip("scitt_cose")

from agent_action_capsule.witness import (  # noqa: E402
    binding_of,
    endpoint_of,
    row_for,
    row_public_keys_pem,
    verify_receipt,
    verify_scrapi_receipt,
    verify_witness_receipts,
)

SIGNED = {"log_id": "l", "mmr_size": 1, "root": "00" * 32, "prev_size": 0, "prev_root": "",
          "key_id": "11" * 32, "timestamp": "2026-10-15T00:00:00Z"}


def test_bindings_and_endpoints_come_from_the_url_scheme():
    assert binding_of("https://w.example/") == "cll"
    assert binding_of("REKOR+https://r.example") == "rekor"
    assert binding_of("scrapi+https://s.example") == "scrapi"
    assert binding_of("not a url") == "cll"
    assert endpoint_of("scrapi+https://s.example/") == "https://s.example"


def test_row_lookup_ignores_rows_of_another_binding_and_malformed_rows():
    directory = {"witnesses": ["junk", {"endpoint": "https://s.example/", "binding": "scrapi", "key_ids": []}]}
    assert row_for(directory, "https://s.example") is None
    assert row_for(directory, "scrapi+https://s.example") is not None
    assert row_for(None, "https://s.example") is None
    assert row_for([{"endpoint": "https://s.example"}], "https://s.example/") is not None


def test_a_rekor_row_key_id_without_its_public_key_is_refused():
    with pytest.raises(ValueError):
        row_public_keys_pem({"name": "r", "binding": "rekor", "key_ids": ["22" * 32]})
    assert len(row_public_keys_pem({"key_ids": ["22" * 32]})) == 1


def test_rekor_and_scrapi_receipts_need_the_checkpoint_cose():
    record = {"ts_url": "rekor+https://r.example", "receipt_b64": "", "entry_hash": "", "leaf_index": 0, "tree_size": 1}
    assert verify_receipt(SIGNED, record, b"", None) == (
        False, "not checked: checkpoint COSE statement not available", None)


def test_scrapi_without_a_pinned_key_checks_nothing():
    assert verify_scrapi_receipt(b"", checkpoint_cose=b"x", service_public_key_pem=None)[0] is False


def test_unreadable_receipts_fail_and_never_raise():
    directory = {"witnesses": [{"endpoint": "https://r.example", "binding": "rekor", "key_ids": ["22" * 32],
                                "public_keys": ["not base64!"]}]}
    record = {"ts_url": "rekor+https://r.example", "receipt_b64": "%%%", "entry_hash": "", "leaf_index": 0,
              "tree_size": 1}
    status, findings, receipts = verify_witness_receipts([record], SIGNED, b"cose", directory)
    assert status == "withheld" and receipts[0].reason.startswith("not checked: unusable key")
