"""Tests for the salted per-field commitment scheme (selective disclosure)."""

import hashlib
import json
import secrets

from agent_action_capsule.selective_disclosure import (
    commit_fields,
    disclose_subset,
    verify_disclosure,
)


def test_commit_and_verify_all_fields():
    fields = {"action": "book_slot", "vendor": "Acme", "amount_usd": 4800}
    commitments, salted = commit_fields(fields)
    assert verify_disclosure(commitments, salted)


def test_disclose_subset():
    fields = {"action": "book_slot", "vendor": "Acme", "amount_usd": 4800}
    commitments, salted = commit_fields(fields)
    disclosed = disclose_subset(salted, ["action", "vendor"])
    assert "amount_usd" not in disclosed
    assert verify_disclosure(commitments, disclosed)


def test_tampered_value_fails():
    fields = {"action": "book_slot"}
    commitments, salted = commit_fields(fields)
    tampered = {"action": {"salt": salted["action"]["salt"], "value": "TAMPERED"}}
    assert not verify_disclosure(commitments, tampered)


def test_wrong_salt_fails():
    fields = {"action": "book_slot"}
    commitments, salted = commit_fields(fields)
    wrong_salt = {"action": {"salt": secrets.token_hex(16), "value": salted["action"]["value"]}}
    assert not verify_disclosure(commitments, wrong_salt)


def test_undisclosed_field_guess_fails():
    fields = {"action": "book_slot", "secret": "hunter2"}
    commitments, salted = commit_fields(fields)
    # Attacker knows the value but not the salt
    guess = {"secret": {"salt": secrets.token_hex(16), "value": "hunter2"}}
    assert not verify_disclosure(commitments, guess)


def test_same_salt_same_commitment():
    fields = {"x": 42}
    _, salted = commit_fields(fields)
    salt = salted["x"]["salt"]
    value = salted["x"]["value"]
    # Manually recompute
    salt_bytes = bytes.fromhex(salt)
    val_bytes = json.dumps(value, separators=(",", ":")).encode("utf-8")
    expected = hashlib.sha256(salt_bytes + b"x" + b":" + val_bytes).hexdigest()
    # Compute a second time via commit_fields using fixed salt — not possible since salt is random
    # So instead: verify_disclosure with the known commitment works
    c = [expected]
    d = {"x": {"salt": salt, "value": value}}
    from agent_action_capsule.selective_disclosure import verify_disclosure  # noqa: F811
    assert verify_disclosure(c, d)
