"""Quickstart: seal content-private -> disclose subset -> verifier confirms."""
from agent_action_capsule.selective_disclosure import commit_fields, disclose_subset, verify_disclosure

fields = {"action": "book_slot", "vendor": "Acme", "amount_usd": 4800}
commitments, salted = commit_fields(fields)
# commitments go in the capsule payload; salted stays private

# Share only two fields with auditor
disclosed = disclose_subset(salted, ["action", "vendor"])

assert verify_disclosure(commitments, disclosed)
assert "amount_usd" not in disclosed
print("Disclosed:", list(disclosed.keys()))
print("Hidden: amount_usd")
print("Verification: OK")
