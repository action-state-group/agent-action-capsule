# SPDX-License-Identifier: Apache-2.0
"""Freeze session-scoped acceptance cases from the profile's Python verifier.

The corpus acceptance cases (vectors/interop-profile-v0) are all transaction
scoped. These cases run `evaluate_acceptance(session=True)` on the backdated
acceptance fixtures of a session (a positive case, a citation
alone, a late receipt, a self-admitted late acceptance, a receipt by the
acceptor's second key, an uncited exchange, an exchange outside the window)
and write the inputs and the reference verifier's report, so the Rust port
is compared with it. They are test fixtures for this crate, not corpus
vectors.

Run from the repository root:

    uv run --no-project --with cryptography --with rfc8785==0.1.4 --with cbor2 python -I \
        rust/evidence-request/tests/scripts/acceptance_session_cases.py
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "python"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402

from agent_action_capsule.interop_profile._common import (  # noqa: E402
    TrustPolicy, json_value_digest, unsigned_jcs)
from agent_action_capsule.interop_profile.acceptance import evaluate_acceptance  # noqa: E402

OUT = ROOT / "rust" / "evidence-request" / "tests" / "vectors" / "acceptance-session.json"
PROFILE = "evidence-interop/0"
EVALUATION = "2026-10-12T02:00:00Z"
CONTRACT = {"id": "C", "version": "1", "requirements": [
    {"id": "R-prior", "statement": "accepted before the action"},
    {"id": "R-served", "statement": "the served half is present and verifies"}]}
TRANSACTION = {"scheme": "x-example/session", "id": "session-1"}
SESSION = {"not_before": "2026-10-12T00:00:00Z", "not_after": "2026-10-12T01:00:00Z"}


def key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(f"acceptance session fixtures: {label}".encode()).digest())


def pub(k: Ed25519PrivateKey) -> str:
    return k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


P, Q, Q2 = key("P"), key("Q"), key("Q2")


def signed(body: dict, k: Ed25519PrivateKey) -> dict:
    return {**body, "sig": k.sign(unsigned_jcs(body)).hex()}


def text(obj: dict) -> str:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True)


COMMON = {"profile": PROFILE, "contract_ref": "C@1", "contract_digest": json_value_digest(CONTRACT),
          "transaction": TRANSACTION, "proposer": pub(P), "acceptor": pub(Q), "session": SESSION}


def answer(proposed: dict, at: str) -> dict:
    return signed({**COMMON, "state": "accepted", "issued_at": at, "proposal_digest": json_value_digest(proposed)}, Q)


def records(accepted_at: str) -> tuple[list[str], str, dict]:
    proposed = signed({**COMMON, "state": "proposed", "issued_at": "2026-10-12T00:00:00Z"}, P)
    accepted = answer(proposed, accepted_at)
    return [text(proposed), text(accepted)], json_value_digest(accepted), proposed


def execution(at: str, cites: str | None) -> str:
    links = [{"type": "cites", "target": cites}] if cites else []
    return text(signed({"action_at": at, "issuer": pub(Q), "links": links, "transaction": TRANSACTION}, Q))


def receipt(digest: str, at: str, k: Ed25519PrivateKey) -> str:
    return text(signed({"profile": PROFILE, "acceptance_digest": digest, "received_at": at, "receiver": pub(k)}, k))


def case(case_id: str, description: str, *, accepted_at="2026-10-12T00:05:00Z", served="2026-10-12T00:10:00Z",
         cite=True, receipt_at: str | None = "2026-10-12T00:06:00Z", receipt_key=P, form_ii=0,
         second_answer: str | None = None, duplicate=False, other_proposal=False) -> dict:
    recs, digest, proposed = records(accepted_at)
    if second_answer:  # a second, different answer to the same proposal: equivocation (§11.1.1)
        recs.append(text(answer(proposed, second_answer)))
    if duplicate:  # a second copy of the accepted record, byte for byte
        recs.append(recs[1])
    if other_proposal:  # a second, separate proposal and its verified answer
        other = signed({**COMMON, "state": "proposed", "issued_at": "2026-10-12T00:01:00Z"}, P)
        recs += [text(other), text(answer(other, "2026-10-12T00:02:00Z"))]
    receipts = [receipt(digest, receipt_at, receipt_key)] if receipt_at else []
    parties = {pub(P): "N_P", pub(Q): "N_Q", pub(Q2): "N_Q"}
    pin = {"parties": parties, "require_action_time_from_other_party": False}
    inputs = {"transaction": TRANSACTION, "proposer": pub(P), "acceptor": pub(Q), "acceptance_records": recs,
              "execution_records": [execution(served, digest if cite else None)], "acceptance_receipts": receipts,
              "form_ii_objects": form_ii}
    res = evaluate_acceptance(CONTRACT, TRANSACTION, pub(P), pub(Q), [r.encode() for r in recs],
                              [e.encode() for e in inputs["execution_records"]], [r.encode() for r in receipts],
                              TrustPolicy.from_dict(pin), EVALUATION, session=True,
                              form_ii_objects=[{}] * form_ii)
    expected = {
        "finding": res.finding,
        "candidates": [{"record_digest": c.record_digest, "properties": {p.property: p.status for p in c.properties}}
                       for c in res.candidates],
        "receipts": [{"receipt_digest": r.receipt_digest, "properties": {p.property: p.status for p in r.properties}}
                     for r in res.receipts]}
    if res.claim_fields is not None:
        expected["claim"] = res.claim_fields
    return {"id": case_id, "description": description,
            "pins": {"trust_policy": pin, "evaluation_time": EVALUATION}, "inputs": inputs, "expected": expected}


CASES = [
    case("session-P", "receipt at 00:06 before the served half at 00:10; the half cites"),
    case("session-F1", "the half cites, no receipt: a citation alone is not ordering evidence", receipt_at=None),
    case("session-L", "an honest late receipt at 00:20", receipt_at="2026-10-12T00:20:00Z"),
    case("session-D", "the accepted record states 00:20, after the served half", accepted_at="2026-10-12T00:20:00Z"),
    case("session-K", "the receipt is signed by the provider's second key", receipt_key=Q2),
    case("session-U", "the served half does not cite the acceptance", cite=False),
    case("session-W", "the served half is outside the session window", served="2026-10-12T01:00:01Z"),
    case("session-E", "two different verified answers to one proposal", second_answer="2026-10-12T00:05:30Z"),
    case("session-C", "two copies of one accepted record are one record", duplicate=True),
    case("session-E2", "equivocation on one proposal makes the finding not_accepted, whatever a separate verified answer gives",
         second_answer="2026-10-12T00:05:30Z", other_proposal=True),
    case("session-F2", "no receipt, one form (ii) object held: rule 6", receipt_at=None, form_ii=1),
]

OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(json.dumps({"contract": CONTRACT, "cases": CASES}, indent=1, ensure_ascii=False) + "\n",
               encoding="utf-8")
print(f"wrote {len(CASES)} cases to {OUT.relative_to(ROOT)}:",
      ", ".join(f"{c['id']}={c['expected']['finding']}" for c in CASES))
