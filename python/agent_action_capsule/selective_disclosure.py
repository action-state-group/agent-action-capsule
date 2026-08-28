"""Salted per-field commitment scheme for selective disclosure of capsule payload fields."""

import hashlib
import json
import secrets
from typing import Any


def commit_fields(fields: dict[str, Any]) -> tuple[list[str], dict[str, Any]]:
    """
    Commit to each field with a random salt.
    Returns:
      commitments: list of hex SHA-256 commitment strings (one per field) — goes in the capsule
      salted_disclosures: {field_name: {"salt": hex_salt, "value": value}} — kept private

    Commitment = SHA-256(salt_bytes + field_name.encode('utf-8') + b':' + json_value_bytes)
    where json_value_bytes = json.dumps(value, separators=(',', ':')).encode('utf-8')
    """
    commitments: list[str] = []
    salted_disclosures: dict[str, Any] = {}

    for field_name, value in fields.items():
        salt_bytes = secrets.token_bytes(16)
        hex_salt = salt_bytes.hex()
        val_bytes = json.dumps(value, separators=(",", ":")).encode("utf-8")
        digest = hashlib.sha256(
            salt_bytes + field_name.encode("utf-8") + b":" + val_bytes
        ).hexdigest()
        commitments.append(digest)
        salted_disclosures[field_name] = {"salt": hex_salt, "value": value}

    return commitments, salted_disclosures


def disclose_subset(salted_disclosures: dict[str, Any], fields_to_disclose: list[str]) -> dict[str, Any]:
    """
    Return only the requested fields from salted_disclosures.
    Raises KeyError if a requested field is not in salted_disclosures.
    """
    result: dict[str, Any] = {}
    for field_name in fields_to_disclose:
        if field_name not in salted_disclosures:
            raise KeyError(f"Field {field_name!r} not found in salted_disclosures")
        result[field_name] = salted_disclosures[field_name]
    return result


def verify_disclosure(commitments: list[str], disclosed: dict[str, Any]) -> bool:
    """
    Verify that each disclosed field+salt recomputes to one of the commitments.
    Returns True only if every disclosed field matches a commitment.
    Returns False if any field doesn't match (tampered value, wrong salt, guessed value).
    Does NOT require all commitments to be disclosed — subset disclosure is valid.
    """
    commitment_set = set(commitments)

    for field_name, entry in disclosed.items():
        try:
            hex_salt: str = entry["salt"]
            value: Any = entry["value"]
            salt_bytes = bytes.fromhex(hex_salt)
        except (KeyError, ValueError):
            return False

        val_bytes = json.dumps(value, separators=(",", ":")).encode("utf-8")
        digest = hashlib.sha256(
            salt_bytes + field_name.encode("utf-8") + b":" + val_bytes
        ).hexdigest()

        if digest not in commitment_set:
            return False

    return True
