#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate the minimum-necessary SD-JWT input vectors (``vectors/minimum-necessary/``).

One worked example, end to end: three records sealed once as SD-JWTs (RFC 9901),
two policy-scoped presentations of them, the policy decisions that name the
revealed and withheld fields, the Capsules that bind both by digest, a two-record
log, and four Evidence Bundles. The set exercises the provisional registry
entries in ``spec/REGISTRY.md``: the ``agent_input_version: "1"`` presentation
type (§10), the ``disclosure_policy_decisions/v1`` and ``sd_jwt_issuers/v1``
Evidence Bundle extension kinds (§14) and the ``minimum_necessary_report/1``
Evidence Request derivation (§16).

Every expected result is computed here from those registry entries, RFC 9901,
RFC 8785 and the base profile's rules. Nothing here imports or runs an
implementation from this repository or from the log reference: SD-JWT issuance,
the Producer Envelope, the two-leaf MMR and the COSE checkpoint are built with
the standard library and ``cryptography`` (Ed25519, deterministic).

Fixed inputs: every salt, decoy digest and key seed is SHA-256 over a fixed
label, so the run is a pure function of this file (no clock, no randomness).
``README.md`` is hand-written; when present in the output directory it is
included in ``SHA256SUMS`` but never rewritten.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "vectors" / "minimum-necessary"
SET = "aac-minimum-necessary-sd-jwt-v1"
AAC_SPEC_VERSION = "draft-mih-scitt-agent-action-capsule-05"
CAPSULE_ID_MEDIA_TYPE = "application/agent-action-capsule-id"
CLL_CHECKPOINT_CONTENT_TYPE = "application/cll-checkpoint+cbor"

# Registry entries exercised (spec/REGISTRY.md). Kept as constants so a rename
# at ratification is a one-line change plus a regeneration.
AGENT_INPUT_VERSION = "1"
EXT_POLICY_DECISIONS = "disclosure_policy_decisions/v1"
EXT_SD_JWT_ISSUERS = "sd_jwt_issuers/v1"
DERIVATION = "minimum_necessary_report/1"

# Constraint labels. Bare names are reserved for values seeded in the base
# profile (Internet-Draft "Namespacing convention"); none of these is seeded, so
# the producer namespaces them under its own reverse-DNS prefix.
CONSTRAINT_ID = "org.example.disclosure_policy"
CONSTRAINT_CHECK_TYPE = "org.example.minimum_necessary"
CONSTRAINT_METHOD = "org.example.sd_jwt_presentation"

OPERATOR = "EXAMPLE-ORG"
ISSUER = "https://data.example.org"
LOG_ID = "https://log.example.org/agent-actions"
CHECKPOINT_ISSUED_AT = "2026-09-15T14:10:00Z"
IAT = 1757808000

# ---------------------------------------------------------------------------
# Encodings
# ---------------------------------------------------------------------------


def _check_json_value(value: Any) -> None:
    if isinstance(value, float):
        raise TypeError("floats are not canonicalizable here")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or not key.isascii():
                raise TypeError("map keys in these vectors are ASCII text")
            _check_json_value(item)
    elif isinstance(value, list):
        for item in value:
            _check_json_value(item)


def jcs(value: Any) -> bytes:
    """RFC 8785 for the value space these vectors use (no floats, ASCII keys)."""
    _check_json_value(value)
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_digest(value: Any) -> str:
    """The base profile's JSON-DIGEST: lowercase-hex SHA-256 over UTF-8 JCS."""
    return sha256_hex(jcs(value))


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def fixed(label: str) -> bytes:
    return hashlib.sha256(f"{SET}: {label}".encode()).digest()


def _cbor_head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 0x100:
        return bytes([(major << 5) | 24]) + n.to_bytes(1, "big")
    if n < 0x10000:
        return bytes([(major << 5) | 25]) + n.to_bytes(2, "big")
    return bytes([(major << 5) | 26]) + n.to_bytes(4, "big")


def cbor(value: Any) -> bytes:
    """RFC 8949 section 4.2.1 deterministic CBOR for the values used here."""
    if isinstance(value, bool) or value is None or isinstance(value, float):
        raise TypeError("not used here")
    if isinstance(value, int):
        return _cbor_head(0, value) if value >= 0 else _cbor_head(1, -1 - value)
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return _cbor_head(3, len(raw)) + raw
    if isinstance(value, bytes):
        return _cbor_head(2, len(value)) + value
    if isinstance(value, list):
        return _cbor_head(4, len(value)) + b"".join(cbor(v) for v in value)
    if isinstance(value, dict):
        pairs = sorted((cbor(k), cbor(v)) for k, v in value.items())
        return _cbor_head(5, len(pairs)) + b"".join(k + v for k, v in pairs)
    raise TypeError(type(value).__name__)


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------


class Key:
    def __init__(self, name: str) -> None:
        self.name = name
        self.seed = fixed(f"{name} key")
        self.private = Ed25519PrivateKey.from_private_bytes(self.seed)
        self.public = self.private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    @property
    def public_hex(self) -> str:
        return self.public.hex()

    def jwk(self) -> dict[str, str]:
        return {"kty": "OKP", "crv": "Ed25519", "x": b64u(self.public)}


ISSUER_KEY = Key("record issuer")
PROCESSOR_RUNTIME = Key("claims-processor runtime")
AUDIT_RUNTIME = Key("claim-audit runtime")
LOG_KEY = Key("log checkpoint")
KEYS = [ISSUER_KEY, PROCESSOR_RUNTIME, AUDIT_RUNTIME, LOG_KEY]

# ---------------------------------------------------------------------------
# Worked data (one office visit, three records; values are illustrative)
# ---------------------------------------------------------------------------

CLAIM_ID = "CLM-2026-0914-0007"

RECORDS: dict[str, dict[str, Any]] = {
    "claim": {
        "claim_id": CLAIM_ID,
        "member_id": "M48213377",
        "patient_name": "J. Doe",
        "patient_dob": "1971-03-22",
        "provider_npi": "1234567893",
        "date_of_service": "2026-09-14",
        "place_of_service": "11",
        "cpt": "99213",
        "icd10": ["E11.9"],
        "charge": {"value": "150.00", "currency": "USD"},
        "units": 1,
    },
    "encounter_note": {
        "note_id": "ENC-77120",
        "claim_id": CLAIM_ID,
        "chief_complaint": "Follow-up, type 2 diabetes",
        "history": "Reports adherence; no hypoglycemic episodes.",
        "exam": "BP 128/82; foot exam normal.",
        "medications": ["metformin 500 mg BID"],
        "assessment": "E11.9, controlled",
        "plan": "Continue metformin; A1c in 3 months.",
    },
    "eligibility": {
        "member_id": "M48213377",
        "group_number": "G-55010",
        "plan_id": "PPO-STD-2026",
        "effective": {"from": "2026-01-01", "to": "2026-12-31"},
        "copay": {"value": "30.00", "currency": "USD"},
        "deductible_met": True,
        "prior_auth_required": False,
    },
}

# Correlation handles with no identity or content value stay in the clear.
CLEAR = {"claim": ["claim_id"], "encounter_note": ["note_id", "claim_id"], "eligibility": []}
VCT = {
    "claim": f"{ISSUER}/types/claim-837p/v1",
    "encounter_note": f"{ISSUER}/types/encounter-note/v1",
    "eligibility": f"{ISSUER}/types/eligibility/v1",
}
CASE_SUFFIX = {"claim": "claim", "encounter_note": "note", "eligibility": "eligibility"}
DECOYS_PER_RECORD = 2

# The member's identity: never in any Capsule, in clear or hashed.
MEMBER_IDENTIFIERS = {
    "member_id": "M48213377",
    "patient_name": "J. Doe",
    "patient_dob": "1971-03-22",
}

POLICIES: dict[str, dict[str, Any]] = {
    "P-1": {
        "case": "P1",
        "agent": "claims-processor@2.4.1",
        "role": "claims_processor",
        "policy_version": "2026-08-01",
        "decided_at": "2026-09-15T14:02:11Z",
        "revealed": {
            "claim": ["member_id", "patient_dob", "provider_npi", "date_of_service", "place_of_service",
                      "cpt", "icd10", "charge", "units"],
            "encounter_note": [],
            "eligibility": ["member_id", "group_number", "plan_id", "effective", "copay", "deductible_met",
                            "prior_auth_required"],
        },
    },
    "A-1": {
        "case": "A1",
        "agent": "claim-audit@1.2.0",
        "role": "claim_auditor",
        "policy_version": "2026-08-01",
        "decided_at": "2026-09-15T14:06:27Z",
        "revealed": {
            "claim": ["provider_npi", "date_of_service", "place_of_service", "cpt", "icd10", "charge", "units"],
            "encounter_note": ["chief_complaint", "history", "exam", "medications", "assessment", "plan"],
            "eligibility": [],
        },
    },
}

# ---------------------------------------------------------------------------
# SD-JWT (RFC 9901), Ed25519, fixed salts
# ---------------------------------------------------------------------------


def sealed_fields(record: str) -> list[str]:
    return [name for name in RECORDS[record] if name not in CLEAR[record]]


def salt(record: str, field: str) -> str:
    """128 bits, base64url (RFC 9901 section 4.2.1), from a fixed label."""
    return b64u(fixed(f"salt {record}.{field}")[:16])


def disclosure(record: str, field: str, value: Any = None) -> str:
    """base64url of the UTF-8 JSON array [salt, name, value] (RFC 9901 section 4.2.1)."""
    v = RECORDS[record][field] if value is None else value
    return b64u(jcs([salt(record, field), field, v]))


def disclosure_digest(disc: str) -> str:
    """base64url(SHA-256(ASCII(disclosure))) (RFC 9901 section 4.2.3, _sd_alg sha-256)."""
    return b64u(hashlib.sha256(disc.encode("ascii")).digest())


def decoys(record: str) -> list[str]:
    """Decoy digests (RFC 9901 section 4.2.5): fixed, never matched by a Disclosure."""
    return [b64u(fixed(f"decoy {record} {i}")) for i in range(DECOYS_PER_RECORD)]


def issue(record: str) -> dict[str, Any]:
    disclosures = {f: disclosure(record, f) for f in sealed_fields(record)}
    digests = {f: disclosure_digest(d) for f, d in disclosures.items()}
    payload: dict[str, Any] = {"iss": ISSUER, "iat": IAT, "vct": VCT[record]}
    for f in CLEAR[record]:
        payload[f] = RECORDS[record][f]
    payload["_sd_alg"] = "sha-256"
    # RFC 9901 section 4.2.4.1: the original order is hidden; here by sorting.
    payload["_sd"] = sorted(list(digests.values()) + decoys(record))
    header = {"alg": "EdDSA", "typ": "dc+sd-jwt"}
    signing_input = b64u(jcs(header)) + "." + b64u(jcs(payload))
    jwt = signing_input + "." + b64u(ISSUER_KEY.private.sign(signing_input.encode("ascii")))
    return {
        "header": header,
        "payload": payload,
        "jwt": jwt,
        "disclosures": disclosures,
        "digests": digests,
        "decoys": decoys(record),
    }


ISSUED = {r: issue(r) for r in RECORDS}


def presentation(record: str, fields: list[str], *, override: dict[str, str] | None = None) -> str:
    """Issuer-signed JWT, then the chosen Disclosures, each followed by '~' (RFC 9901 section 4)."""
    issued = ISSUED[record]
    discs = [issued["disclosures"][f] for f in sealed_fields(record) if f in fields]
    if override:
        discs = [override.get(d, d) for d in discs]
    return issued["jwt"] + "~" + "".join(d + "~" for d in discs)


def agent_input(presentations: list[str]) -> dict[str, Any]:
    return {"agent_input_version": AGENT_INPUT_VERSION, "presentations": presentations}


def policy_presentations(policy_id: str, *, extra: dict[str, list[str]] | None = None) -> list[str]:
    revealed = POLICIES[policy_id]["revealed"]
    out = []
    for record in RECORDS:
        fields = list(revealed[record]) + list((extra or {}).get(record, []))
        out.append(presentation(record, fields))
    return out


def policy_decision(policy_id: str) -> dict[str, Any]:
    p = POLICIES[policy_id]
    sources = []
    for record in RECORDS:
        revealed = p["revealed"][record]
        withheld = [f for f in sealed_fields(record) if f not in revealed]
        sources.append({"vct": VCT[record], "revealed": list(revealed), "withheld": withheld})
    return {
        "policy_decision_version": "1",
        "policy_id": policy_id,
        "policy_version": p["policy_version"],
        "agent": p["agent"],
        "role": p["role"],
        "subject": {"claim_id": CLAIM_ID},
        "sources": sources,
        "decided_at": p["decided_at"],
    }


# ---------------------------------------------------------------------------
# The presentation-type check (REGISTRY.md §10, agent_input_version "1")
# ---------------------------------------------------------------------------


def check_agent_input(value: Any, decision: dict[str, Any] | None, issuers: dict[str, Any]) -> dict[str, Any]:
    """Verify every SD-JWT in a revealed agent_input of this type.

    Per presentation: the issuer signature against the carried JWK, each
    Disclosure's digest against ``_sd``, and the set of disclosed names against
    the policy decision's ``revealed`` list for the presentation's ``vct``.
    """
    results = []
    by_vct = {s["vct"]: s for s in (decision or {}).get("sources", [])}
    ok = True
    for pres in value["presentations"]:
        parts = pres.split("~")
        jwt, discs = parts[0], parts[1:-1]
        h, p, s = jwt.split(".")
        payload = json.loads(b64u_decode(p))
        jwk = issuers.get(payload["iss"])
        signature_valid = False
        if jwk is not None:
            try:
                Ed25519PublicKey.from_public_bytes(b64u_decode(jwk["x"])).verify(
                    b64u_decode(s), (h + "." + p).encode("ascii"))
                signature_valid = True
            except InvalidSignature:
                signature_valid = False
        names = []
        bound = True
        for d in discs:
            if disclosure_digest(d) not in payload["_sd"]:
                bound = False
            names.append(json.loads(b64u_decode(d))[1])
        source = by_vct.get(payload["vct"])
        expected = sorted(source["revealed"]) if source else None
        set_equal = expected is not None and sorted(names) == expected
        entry = {
            "vct": payload["vct"],
            "issuer_signature": "valid" if signature_valid else "invalid",
            "disclosures_bound": bound,
            "disclosed": sorted(names),
            "decision_revealed": expected,
            "set_equal": set_equal,
        }
        ok = ok and signature_valid and bound and set_equal
        results.append(entry)
    return {"status": "pass" if ok else "fail", "presentations": results}


# ---------------------------------------------------------------------------
# Capsules and the Producer Envelope
# ---------------------------------------------------------------------------


def producer_envelope(capsule_id: str, key: Key) -> bytes:
    """Tagged COSE_Sign1 over the raw 32-byte Capsule ID (base profile Producer Envelope)."""
    protected = cbor({1: -8, 3: CAPSULE_ID_MEDIA_TYPE, 4: key.public})
    payload = bytes.fromhex(capsule_id)
    signature = key.private.sign(cbor(["Signature1", protected, b"", payload]))
    return b"\xd2" + cbor([protected, {}, payload, signature])


def constraint(result: str, evidence_digest: str) -> dict[str, Any]:
    return {
        "id": CONSTRAINT_ID,
        "check_type": CONSTRAINT_CHECK_TYPE,
        "method": CONSTRAINT_METHOD,
        "result": result,
        "severity": "high",
        "blocking": True,
        "evidence_digest": evidence_digest,
    }


def minimum_necessary_result(presentations: list[str], decision: dict[str, Any]) -> tuple[str, list[str]]:
    """The deterministic predicate: transmitted Disclosure set == the decision's revealed list."""
    check = check_agent_input(agent_input(presentations), decision, {ISSUER: ISSUER_KEY.jwk()})
    extra = []
    for entry in check["presentations"]:
        extra += [f"{entry['vct']}#{n}" for n in entry["disclosed"] if n not in (entry["decision_revealed"] or [])]
    return ("pass" if check["status"] == "pass" else "fail"), extra


PRICING_OUTPUT = {
    "claim_id": CLAIM_ID,
    "allowed_amount": {"value": "112.40", "currency": "USD"},
    "member_responsibility": {"value": "30.00", "currency": "USD"},
    "reason_codes": ["CO-45"],
}
AUDIT_OUTPUT = {"claim_id": CLAIM_ID, "finding": "99213 supported", "basis": ["exam", "assessment", "plan"]}


def capsule(*, action_id: str, developer: str, timestamp: str, input_value: dict[str, Any],
            output_value: dict[str, Any] | None, decision: dict[str, Any], result: str,
            references: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    compute = {"agent_input_digest": json_digest(input_value)}
    if output_value is not None:
        compute["agent_output_digest"] = json_digest(output_value)
    executed = result == "pass"
    body: dict[str, Any] = {
        "spec_version": AAC_SPEC_VERSION,
        "format_version": "4",
        "canonicalization_id": "jcs",
        "action_id": action_id,
        "action_type": "decide",
        "operator": OPERATOR,
        "developer": developer,
        "timestamp": timestamp,
        "epoch_id": "policy-" + decision["policy_version"],
        "model_attestation": {"compute_attestation": compute},
        "constraints": [constraint(result, json_digest(decision))],
        "disposition": {"approver": "policy", "decision": "accept" if executed else "reject",
                        "human_disposed": False, "verdict_class": "executed" if executed else "blocked"},
        "assurance": {"attestation_mode": "self_attested", "effect_mode": "not_applicable",
                      "ledger_mode": "standalone"},
    }
    if references:
        body["references"] = references
    body["capsule_id"] = json_digest(body)
    return body


def sealed(body: dict[str, Any], key: Key) -> dict[str, Any]:
    preimage = {k: v for k, v in body.items() if k != "capsule_id"}
    return {
        "capsule_id": body["capsule_id"],
        "canonical_preimage": jcs(preimage).decode("utf-8"),
        "producer_envelope_hex": producer_envelope(body["capsule_id"], key).hex(),
        "producer_key_hex": key.public_hex,
    }


DECISION_P1 = policy_decision("P-1")
DECISION_A1 = policy_decision("A-1")
INPUT_P1 = agent_input(policy_presentations("P-1"))
INPUT_A1 = agent_input(policy_presentations("A-1"))
FAIL_PRESENTATIONS = policy_presentations("P-1", extra={"claim": ["patient_name"]})
INPUT_FAIL = agent_input(FAIL_PRESENTATIONS)

P1_RESULT, _ = minimum_necessary_result(INPUT_P1["presentations"], DECISION_P1)
A1_RESULT, _ = minimum_necessary_result(INPUT_A1["presentations"], DECISION_A1)
FAIL_RESULT, FAIL_EXTRA = minimum_necessary_result(FAIL_PRESENTATIONS, DECISION_P1)

PRICING = capsule(action_id=f"price-{CLAIM_ID}", developer=POLICIES["P-1"]["agent"],
                  timestamp="2026-09-15T14:02:14Z", input_value=INPUT_P1, output_value=PRICING_OUTPUT,
                  decision=DECISION_P1, result=P1_RESULT)
AUDIT = capsule(action_id=f"audit-{CLAIM_ID}", developer=POLICIES["A-1"]["agent"],
                timestamp="2026-09-15T14:06:30Z", input_value=INPUT_A1, output_value=AUDIT_OUTPUT,
                decision=DECISION_A1, result=A1_RESULT,
                references=[{"type": "agent-action-capsule", "digest_alg": "SHA-256",
                             "digest": PRICING["capsule_id"], "citation_purpose": "acted_on"}])
POLICY_FAIL = capsule(action_id=f"price-{CLAIM_ID}", developer=POLICIES["P-1"]["agent"],
                      timestamp="2026-09-15T14:02:14Z", input_value=INPUT_FAIL, output_value=None,
                      decision=DECISION_P1, result=FAIL_RESULT)

# ---------------------------------------------------------------------------
# Two-record log: CLL MMR hashing and the COSE checkpoint
# ---------------------------------------------------------------------------


def leaf_hash(body_digest: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + body_digest).digest()


def interior_hash(left: bytes, right: bytes, position: int) -> bytes:
    return hashlib.sha256((position + 1).to_bytes(8, "big") + left + right).digest()


def build_log() -> dict[str, Any]:
    ids = [PRICING["capsule_id"], AUDIT["capsule_id"]]
    l0, l1 = (leaf_hash(bytes.fromhex(i)) for i in ids)
    n2 = interior_hash(l0, l1, 2)  # MMR positions 0, 1 (leaves), 2 (their parent)
    size = 3
    root = n2  # one peak: the bagged root of a single peak is the peak
    commitment = cbor([n2])
    claims = {"kind": "cll-checkpoint", "log_size": size, "commitment": commitment, "prev_size": 0,
              "prev_commitment": b"", "issued_at": CHECKPOINT_ISSUED_AT}
    payload = cbor(claims)
    protected = cbor({1: -8, 3: CLL_CHECKPOINT_CONTENT_TYPE, 4: LOG_KEY.public,
                      15: {1: LOG_ID, 2: f"{LOG_ID}#{size}"}})
    signature = LOG_KEY.private.sign(cbor(["Signature1", protected, b"", payload]))
    cose = b"\xd2" + cbor([protected, {}, payload, signature])
    memberships = {}
    for seq, (cid, sibling) in enumerate(zip(ids, [l1, l0]), start=1):
        memberships[cid] = {
            "log_coordinates": {"log_id": LOG_ID, "seq": seq, "leaf_index": seq - 1},
            "inclusion_proof": {"v": 1, "kind": "inclusion", "size": size, "leaf_index": seq - 1,
                                "witness": [sibling.hex()], "peaks_left": [], "peaks_right": []},
        }
    return {
        "log_id": LOG_ID,
        "entries": [{"seq": s, "leaf_index": s - 1, "capsule_id": cid, "leaf_hash": h.hex()}
                    for s, (cid, h) in enumerate(zip(ids, [l0, l1]), start=1)],
        "mmr_nodes": [l0.hex(), l1.hex(), n2.hex()],
        "mmr_size": size,
        "root": root.hex(),
        "commitment_hex": commitment.hex(),
        "checkpoint_claims_cbor_hex": payload.hex(),
        "checkpoint_cose": b64u(cose),
        "range_proof": {"from_seq": 1, "to_seq": 2, "size": size, "from_index": 0, "to_index": 1, "witness": []},
        "memberships": memberships,
    }


LOG = build_log()

# ---------------------------------------------------------------------------
# Evidence Bundles
# ---------------------------------------------------------------------------


def bundle(*, disclosures: dict[str, dict[str, Any]] | None, suppressed: list[str], signed_checkpoint: bool,
           payloads_mode: str) -> dict[str, Any]:
    b: dict[str, Any] = {
        "bundle_version": "2",
        "bundle_kind": "evidence-bundle/v2",
        "root": AUDIT["capsule_id"],
        "records": [copy.deepcopy(PRICING), copy.deepcopy(AUDIT)],
        "completeness": {"closure_depth": 2, "records_mode": "complete", "payloads_mode": payloads_mode,
                         "suppressed_fields": suppressed, "missing": []},
    }
    if disclosures is not None:
        b["disclosures"] = disclosures
    b["extensions"] = {
        EXT_POLICY_DECISIONS: {PRICING["capsule_id"]: DECISION_P1, AUDIT["capsule_id"]: DECISION_A1},
        EXT_SD_JWT_ISSUERS: {ISSUER: ISSUER_KEY.jwk()},
    }
    b["completeness_certificate"] = {
        "log_id": LOG_ID,
        "first_seq": 1,
        "last_seq": 2,
        "range_root": LOG["root"],
        "body_digests": [PRICING["capsule_id"], AUDIT["capsule_id"]],
        "range_proof": LOG["range_proof"],
        "memberships": LOG["memberships"],
    }
    checkpoint: dict[str, Any] = {"mmr_size": LOG["mmr_size"], "root": LOG["root"]}
    if signed_checkpoint:
        checkpoint["cose"] = LOG["checkpoint_cose"]
    b["checkpoint"] = checkpoint
    return b


def full_disclosures(*, tamper: bool = False) -> dict[str, dict[str, Any]]:
    pricing_input = INPUT_P1
    if tamper:
        # One Disclosure value altered after sealing: the claim's charge.
        original = ISSUED["claim"]["disclosures"]["charge"]
        altered = disclosure("claim", "charge", {"value": "175.00", "currency": "USD"})
        pricing_input = agent_input([presentation(r, POLICIES["P-1"]["revealed"][r],
                                                  override={original: altered})
                                     for r in RECORDS])
    return {
        PRICING["capsule_id"]: {"agent_input": pricing_input, "agent_output": PRICING_OUTPUT},
        AUDIT["capsule_id"]: {"agent_input": INPUT_A1, "agent_output": AUDIT_OUTPUT},
    }


def expected_bundle(b: dict[str, Any], description: str) -> dict[str, Any]:
    """Hand-derived results: the Evidence Bundle -00 checks, then the extension checks."""
    records = {r["capsule_id"]: r for r in b["records"]}
    qualifier = [] if "cose" in b["checkpoint"] else ["checkpoint_unverified"]
    committed = {"agent_input": "agent_input_digest", "agent_output": "agent_output_digest"}
    disclosures = []
    supplied = b.get("disclosures", {})
    for cid in sorted(records):
        for member, field in committed.items():
            stored = records[cid]["model_attestation"]["compute_attestation"].get(field)
            if stored is None:
                continue
            if member not in supplied.get(cid, {}):
                status = "withheld"
            else:
                status = "disclosure_match" if json_digest(supplied[cid][member]) == stored else "disclosure_mismatch"
            disclosures.append({"capsule_id": cid, "member": member, "status": status})
    decisions = b["extensions"][EXT_POLICY_DECISIONS]
    policy = {}
    for cid in sorted(records):
        digest = json_digest(decisions[cid])
        matches = [c for c in records[cid]["constraints"] if c.get("evidence_digest") == digest]
        policy[cid] = {"decision_digest": digest, "status": "match" if matches else "no_matching_constraint",
                       "constraint_result": matches[0]["result"] if matches else None}
    status_by = {(d["capsule_id"], d["member"]): d["status"] for d in disclosures}
    sd_jwt = {}
    for cid in sorted(records):
        state = status_by.get((cid, "agent_input"))
        if state == "withheld":
            sd_jwt[cid] = {"status": "not_evaluated", "reason": "agent_input_withheld"}
        elif state == "disclosure_mismatch":
            sd_jwt[cid] = {"status": "not_evaluated", "reason": "agent_input_disclosure_mismatch"}
        else:
            sd_jwt[cid] = check_agent_input(supplied[cid]["agent_input"], decisions[cid],
                                            b["extensions"][EXT_SD_JWT_ISSUERS])
    canonical = {k: v for k, v in b.items() if k != "countersignatures"}
    return {
        "description": description,
        "bundle_digest": json_digest(canonical),
        "graph_closure": {"status": "pass", "findings": []},
        "interval_coverage": {"status": "pass", "findings": qualifier},
        "per_record_membership": {"status": "pass", "findings": qualifier},
        "disclosures": disclosures,
        "extensions": sorted(b["extensions"]),
        "policy_decisions": policy,
        "sd_jwt_presentations": sd_jwt,
    }


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------


def cases() -> list[tuple[str, str, dict[str, Any], dict[str, Any]]]:
    out: list[tuple[str, str, dict[str, Any], dict[str, Any]]] = []

    for record in RECORDS:
        issued = ISSUED[record]
        out.append((
            f"sdjwt-issue-{CASE_SUFFIX[record]}",
            f"Seal the {record} record once as an SD-JWT: every non-correlation field is a salted Disclosure.",
            {"record": RECORDS[record], "clear_fields": CLEAR[record], "vct": VCT[record], "iss": ISSUER,
             "iat": IAT, "salts": {f: salt(record, f) for f in sealed_fields(record)},
             "decoy_digests": issued["decoys"], "issuer_key": "record issuer"},
            {"jwt_header": issued["header"], "jwt_payload": issued["payload"], "issuer_signed_jwt": issued["jwt"],
             "sd": issued["payload"]["_sd"],
             "disclosures": {f: {"disclosure": issued["disclosures"][f], "digest": issued["digests"][f]}
                             for f in sealed_fields(record)}},
        ))

    for pid, value in (("P-1", INPUT_P1), ("A-1", INPUT_A1)):
        out.append((
            f"presentation-{POLICIES[pid]['case']}",
            f"Build the {pid} presentations (only the Disclosures {pid} reveals) and the agent_input wrapper.",
            {"issuer_signed_jwts": {VCT[r]: ISSUED[r]["jwt"] for r in RECORDS},
             "policy_decision": policy_decision(pid)},
            {"presentations": value["presentations"], "agent_input": value,
             "agent_input_canonical": jcs(value).decode("utf-8"), "agent_input_digest": json_digest(value),
             "check": check_agent_input(value, policy_decision(pid), {ISSUER: ISSUER_KEY.jwk()})},
        ))

    for pid in ("P-1", "A-1"):
        decision = policy_decision(pid)
        cap = PRICING if pid == "P-1" else AUDIT
        out.append((
            f"policy-decision-{POLICIES[pid]['case']}",
            f"The {pid} policy decision document: field names only; its JSON-DIGEST is the constraint evidence_digest.",
            {"policy_decision": decision},
            {"canonical": jcs(decision).decode("utf-8"), "json_digest": json_digest(decision),
             "constraint_evidence_digest": cap["constraints"][0]["evidence_digest"]},
        ))

    for name, cap, key, value, output in (
        ("capsule-pricing", PRICING, PROCESSOR_RUNTIME, INPUT_P1, PRICING_OUTPUT),
        ("capsule-audit", AUDIT, AUDIT_RUNTIME, INPUT_A1, AUDIT_OUTPUT),
    ):
        payload = {k: v for k, v in cap.items() if k != "capsule_id"}
        out.append((
            name,
            "Seal the action's Capsule: input and output by digest, the disclosure-policy constraint record, no field values.",
            {"capsule_payload": payload, "agent_input": value, "agent_output": output, "producer_key": key.name},
            {"capsule": cap, **sealed(cap, key), "class1": {"ok": True}},
        ))

    payload = {k: v for k, v in POLICY_FAIL.items() if k != "capsule_id"}
    out.append((
        "capsule-policy-fail",
        "The transmitted presentation carries one Disclosure beyond the P-1 allow-list: the check fails and the agent does not run.",
        {"agent_input": INPUT_FAIL, "policy_decision": DECISION_P1, "capsule_payload": payload,
         "producer_key": PROCESSOR_RUNTIME.name},
        {"constraint_result": FAIL_RESULT, "extra_disclosures": FAIL_EXTRA,
         "verdict_class": POLICY_FAIL["disposition"]["verdict_class"],
         "capsule": POLICY_FAIL, **sealed(POLICY_FAIL, PROCESSOR_RUNTIME), "class1": {"ok": True}},
    ))

    out.append((
        "log-two-records",
        "Append the pricing and audit Capsules to a log (seq 1 and 2) and sign one checkpoint over the MMR.",
        {"log_id": LOG_ID, "capsule_ids": [PRICING["capsule_id"], AUDIT["capsule_id"]],
         "checkpoint_issued_at": CHECKPOINT_ISSUED_AT, "log_key": LOG_KEY.name},
        LOG,
    ))

    internal = bundle(disclosures=full_disclosures(), suppressed=[], signed_checkpoint=True, payloads_mode="all")
    external = bundle(disclosures=None, suppressed=["agent_input", "agent_output"], signed_checkpoint=True,
                      payloads_mode="selected")
    mismatch = bundle(disclosures=full_disclosures(tamper=True), suppressed=[], signed_checkpoint=True,
                      payloads_mode="all")
    unregistered = bundle(disclosures=full_disclosures(), suppressed=[], signed_checkpoint=False,
                          payloads_mode="all")
    for name, b, desc in (
        ("bundle-internal-audit", internal,
         "Both Capsules, both policy decisions, agent_input and agent_output revealed for both: every check passes."),
        ("bundle-external-auditor", external,
         "Both Capsules and both policy decisions; agent_input and agent_output withheld: no record field value anywhere."),
        ("bundle-mismatch", mismatch,
         "agent_input revealed with one Disclosure value altered: disclosure_mismatch on that Capsule, nothing else changes."),
        ("bundle-not-registered", unregistered,
         "The checkpoint is present but carries no signature and is not registered with a Transparency Service: "
         "interval coverage and membership are qualified checkpoint_unverified."),
    ):
        out.append((name, desc, {"bundle": b}, expected_bundle(b, desc)))
    return out


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------


def _dump(value: Any) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def build() -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    listing = []
    for name, description, inp, exp in cases():
        files[f"{name}/input.json"] = _dump({"description": description, **inp})
        files[f"{name}/expected.json"] = _dump({"provenance": "spec-derived", **exp})
        listing.append({"name": name, "description": description})
    files["manifest.json"] = _dump({
        "set": SET,
        "provenance": "spec-derived",
        "generator": "python/scripts/generate_min_necessary_vectors.py",
        "registry_entries": {
            "agent_input_presentation_type": {"agent_input_version": AGENT_INPUT_VERSION},
            "evidence_bundle_extension_kinds": [EXT_POLICY_DECISIONS, EXT_SD_JWT_ISSUERS],
            "evidence_request_derivation": DERIVATION,
        },
        "constraint_record": {"id": CONSTRAINT_ID, "check_type": CONSTRAINT_CHECK_TYPE,
                              "method": CONSTRAINT_METHOD},
        "sd_jwt": {"alg": "EdDSA", "typ": "dc+sd-jwt", "_sd_alg": "sha-256", "salt_bits": 128,
                   "decoys_per_record": DECOYS_PER_RECORD, "sd_order": "sorted"},
        "envelope_profile": "AAC Producer Envelope: tagged COSE_Sign1, protected {1: -8, 3: "
                            "'application/agent-action-capsule-id', 4: raw Ed25519 public key}, empty "
                            "unprotected map, attached payload = raw 32-byte capsule_id.",
        "keys": {k.name: {"seed_hex": k.seed.hex(), "public_key_hex": k.public_hex, "jwk": k.jwk()} for k in KEYS},
        "member_identifiers": MEMBER_IDENTIFIERS,
        "count": len(listing),
        "cases": listing,
        "files": [{"path": p, "sha256": sha256_hex(d)} for p, d in sorted(files.items())],
    })
    return files


def write(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for name, data in build().items():
        path = out / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    lines = [f"{sha256_hex(p.read_bytes())}  {p.relative_to(out).as_posix()}"
             for p in sorted(out.rglob("*")) if p.is_file() and p.name != "SHA256SUMS"]
    (out / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    write(parser.parse_args().out)


if __name__ == "__main__":
    main()
