#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate the conformance vectors of the Minimum Evidence Interoperability Profile v0.

The profile is ``spec/interop-profile-v0.md`` (identifier ``evidence-interop/0``); its §11.5
describes this corpus. Every expected status below is written by hand from the profile text, and
each case cites the sections it comes from. Nothing here imports or runs a verifier: the script
encodes literal inputs (JSON per RFC 8785, CBOR per RFC 8949 §4.2.1), builds two small
Checkpointed Local Logs with the MMR algorithms the profile pins, hashes, and signs with fixed
Ed25519 test keys. ``python/tests/test_interop_profile_v0_vectors.py`` recomputes from the vector
inputs, with its own code, every digest, signature and encoding a status depends on, and derives
every expected status with its own evaluator.

Each case pins its trust policy (test keys only), its verification policy, the contract version
(``contract_ref`` and ``contract_digest``), its evaluation time, and its inputs as octets.

Output: ``vectors/interop-profile-v0/`` (or ``--out DIR``). Deterministic: no clock, no
randomness. Every key is derived from a public seed and is for testing only. ``README.md`` is
hand-written; when present in the output directory it is included in ``SHA256SUMS`` but never
rewritten. Dependencies: the standard library and ``cryptography`` (Ed25519 only).
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "vectors" / "interop-profile-v0"
SET = "aac-interop-profile-v0"
PROFILE = "evidence-interop/0"
SPEC = "spec/interop-profile-v0.md"
STATUS = ("Conformance vectors for the pre-Internet-Draft profile evidence-interop/0. Every key is a "
          "test key derived from a public seed; never use one for anything else.")
EXT_URI = "https://datatracker.ietf.org/doc/draft-mih-agent-evidence-request/"
KINDS = ["cll-checkpoint", "cll-inclusion-proof", "cll-consistency-proof"]

# The Evidence Contract v0 schema this corpus's contract validates against (the profile's EC pin).
EC_SCHEMA = {
    "name": "evidence-contract-v0.json",
    "sha256": "6d10d5eb97e15421db0ab922b5f6d1f0a2e9f453fb64e52fb45306ba029ad480",
}

# ---------------------------------------------------------------------------
# Encodings
# ---------------------------------------------------------------------------


def _check_json_value(value: Any) -> None:
    if isinstance(value, float):
        raise TypeError("the profile allows no floating-point value (§5.2)")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or not key.isascii():
                raise TypeError("member names in these vectors are ASCII text")
            _check_json_value(item)
    elif isinstance(value, list):
        for item in value:
            _check_json_value(item)


def jcs(value: Any) -> str:
    """RFC 8785 for the value space these vectors use (no floats, ASCII member names)."""
    _check_json_value(value)
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _cbor_head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([(major << 5) | n])
    for ai, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * width):
            return bytes([(major << 5) | ai]) + n.to_bytes(width, "big")
    raise ValueError("integer too large")


def cbor(value: Any) -> bytes:
    """CBOR, RFC 8949 §4.2.1 core deterministic encoding, for the value space used here."""
    if value is None:
        return b"\xf6"
    if isinstance(value, bool):
        return b"\xf5" if value else b"\xf4"
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
    raise TypeError(f"no CBOR encoding for {type(value).__name__} in these vectors")


def sha(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def shx(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def json_digest(value: Any) -> str:
    return shx(jcs(value).encode("utf-8"))


def octets(media_type: str, data: bytes) -> dict:
    """An octet string as carried: JSON octets as their text, CBOR octets as hex."""
    if media_type == "application/json":
        return {"media_type": media_type, "octets_text": data.decode("utf-8")}
    return {"media_type": media_type, "octets_hex": data.hex()}


# ---------------------------------------------------------------------------
# Test keys (every one derived from a public seed)
# ---------------------------------------------------------------------------

SEED_LABELS = {
    "responder": "draft-mih-agent-evidence-request-00 conformance vectors: primary responder key",
    "log": "evidence-interop/0 worked example: CLL log key",
}
for _name in ("impostor", "foreign-signer", "P", "Q", "I", "N", "I2"):
    SEED_LABELS[_name] = f"evidence-interop/0 conformance vectors: key {_name}"

PRIV = {name: Ed25519PrivateKey.from_private_bytes(sha(label.encode())) for name, label in SEED_LABELS.items()}
PUB = {name: k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex() for name, k in PRIV.items()}


def sign(name: str, message: bytes) -> str:
    return PRIV[name].sign(message).hex()


# ---------------------------------------------------------------------------
# Checkpointed Local Log material (§6.2.1): MMR algorithms of the pinned MMR -02
# ---------------------------------------------------------------------------


def index_height(i: int) -> int:
    pos = i + 1
    while pos & (pos + 1):  # all_ones read as intended (§6.2.1 notes)
        pos = pos - (1 << (pos.bit_length() - 1)) + 1
    return pos.bit_length() - 1


def hash_pospair64(pos: int, a: bytes, b: bytes) -> bytes:
    return sha(pos.to_bytes(8, "big") + a + b)


def mmr_peaks(i: int) -> list[int]:
    peak, out, s = 0, [], i + 1
    while s != 0:
        highest = (1 << ((s + 1).bit_length() - 1)) - 1
        peak += highest
        out.append(peak - 1)
        s -= highest
    return out


def inclusion_path(i: int, last: int) -> list[int]:
    path, g = [], index_height(i)
    while True:
        off = 2 << g
        if index_height(i + 1) > g:
            sib = i - off + 1
            i += 1
        else:
            sib = i + off - 1
            i += off
        if sib > last:
            return path
        path.append(sib)
        g += 1


def included_root(i: int, node: bytes, proof: list[bytes]) -> bytes:
    root, g = node, index_height(i)
    for sib in proof:
        if index_height(i + 1) > g:
            i += 1
            root = hash_pospair64(i + 1, sib, root)
        else:
            i += 2 << g
            root = hash_pospair64(i + 1, root, sib)
        g += 1
    return root


def build_log(entries: list[bytes], prev_entries: int, sub: str) -> dict:
    """A Checkpointed Local Log over ``entries``; leaf value SHA-256(0x00 || E) (§6.2.1)."""
    db: list[bytes] = []
    leaf_index = []
    sizes = {}
    for n, e in enumerate(entries):
        leaf_index.append(len(db))
        db.append(sha(b"\x00" + e))
        g = 0
        while index_height(len(db)) > g:
            i = len(db)
            db.append(hash_pospair64(i + 1, db[i - (2 << g)], db[i - 1]))
            g += 1
        sizes[n + 1] = len(db)
    size, prev_size = sizes[len(entries)], sizes[prev_entries]
    commitment = [db[p] for p in mmr_peaks(size - 1)]
    prev_commitment = [db[p] for p in mmr_peaks(prev_size - 1)]
    protected = cbor({1: -8, 4: bytes.fromhex(PUB["log"]), 15: {1: "https://producer.example", 2: sub}})
    payload = cbor({"kind": "cll-checkpoint", "log_size": len(entries), "prev_size": prev_entries,
                    "issued_at": "2026-10-12T00:00:00Z", "cadence": 3600,
                    "commitment": cbor(commitment), "prev_commitment": cbor(prev_commitment)})
    cose_sig = bytes.fromhex(sign("log", cbor(["Signature1", protected, b"", payload])))
    checkpoint = b"\xd2" + cbor([protected, {}, payload, cose_sig])
    paths, roots = [], []
    for p in mmr_peaks(prev_size - 1):
        path = [db[j] for j in inclusion_path(p, size - 1)]
        paths.append(path)
        r = included_root(p, db[p], path)
        if not roots or roots[-1] != r:
            roots.append(r)
    right = commitment[len(roots):]
    assert roots + right == commitment
    return {"db": db, "leaf_index": leaf_index, "checkpoint": checkpoint, "commitment": commitment,
            "sub": sub, "size": size,
            "consistency": cbor([prev_size, size, paths, right])}


def inclusion_proof(log: dict, entry: int) -> bytes:
    i = log["leaf_index"][entry]
    path = [log["db"][j] for j in inclusion_path(i, log["size"] - 1)]
    assert included_root(i, log["db"][i], path) in log["commitment"]
    return cbor([i, path])


def material(log: dict, entry: int) -> list[tuple[str, bytes]]:
    return [("cll-checkpoint", log["checkpoint"]), ("cll-inclusion-proof", inclusion_proof(log, entry)),
            ("cll-consistency-proof", log["consistency"])]


# The §10.1 log and artifact, reproduced byte for byte.
ARTIFACT = jcs({"example": "evidence record", "seq": 1}).encode()
ART = shx(ARTIFACT)
_entries1 = [sha(f"evidence-interop/0 worked example: log entry {k}".encode()) for k in range(7)]
_entries1[2] = sha(ARTIFACT)
LOG1 = build_log(_entries1, 3, "evidence-stream-1")
ANCHOR1 = shx(LOG1["checkpoint"])
MATERIAL1 = material(LOG1, 2)
assert ANCHOR1 == "16f15dd5475d5e8ec1fb7a84470391e11d7663232365c1749c60ca7489cffe99", "§10.1 drifted"
assert shx(MATERIAL1[1][1]) == "013ac5a3bdff9cf62a3ea2816b3cd197151930f6dd49d67d9286f12c3c47527a"
assert shx(MATERIAL1[2][1]) == "06550cca75319242ea40e7f3fd9ff0b8e5e3bfa8a06122f678578a57cb4bdc71"

# A carried foreign object (§5.1, §8.1 rows 5 and 6): a JWS compact serialization (RFC 7515)
# signed with EdDSA (RFC 8037), carried verbatim as a JSON string inside the Artifact.
_jws_header = b64u(jcs({"alg": "EdDSA", "kid": PUB["foreign-signer"]}).encode())
_jws_payload_ok = b64u(jcs({"principal": "example-principal", "scope": "example action"}).encode())
_jws_payload_bad = b64u(jcs({"principal": "example-principal", "scope": "other action"}).encode())
_jws_sig = b64u(bytes.fromhex(sign("foreign-signer", f"{_jws_header}.{_jws_payload_ok}".encode("ascii"))))
JWS_OK = f"{_jws_header}.{_jws_payload_ok}.{_jws_sig}"
JWS_BAD = f"{_jws_header}.{_jws_payload_bad}.{_jws_sig}"  # payload changed after signing


def carrying(jws: str) -> bytes:
    return jcs({"carried": {"media_type": "application/jose", "object": jws},
                "example": "evidence record with a carried authorization"}).encode()


ARTIFACT_F_OK, ARTIFACT_F_BAD = carrying(JWS_OK), carrying(JWS_BAD)
_entries2 = [sha(f"evidence-interop/0 conformance vectors: log entry {k}".encode()) for k in range(7)]
_entries2[1], _entries2[5] = sha(ARTIFACT_F_OK), sha(ARTIFACT_F_BAD)
LOG2 = build_log(_entries2, 3, "evidence-stream-2")
ANCHOR2 = shx(LOG2["checkpoint"])

# ---------------------------------------------------------------------------
# The contract version every case pins
# ---------------------------------------------------------------------------

CONTRACT = {
    "id": "C",
    "version": "1",
    "requirements": [
        {"id": "r-record", "profile": "outcome",
         "statement": "The evidence record named by the request is served under a verified envelope.",
         "evidence_requirements": {"accepted_epistemic_types": ["system_of_record_fact"]}},
        {"id": "r-carried-signature", "profile": "outcome",
         "statement": "The authorization carried in the evidence record verifies under its own signature method.",
         "evidence_requirements": {"accepted_epistemic_types": ["producer_claim"]}},
        {"id": "r-authorized", "profile": "outcome",
         "statement": "The recorded action was authorized by the principal the carried authorization names.",
         "evidence_requirements": {"accepted_epistemic_types": ["producer_claim", "system_of_record_fact"]}},
    ],
}
CONTRACT_REF = f"{CONTRACT['id']}@{CONTRACT['version']}"
CONTRACT_DIGEST = json_digest(CONTRACT)

# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------

LOG_KEYS = [{"iss": "https://producer.example", "sub": "evidence-stream-1", "kid": PUB["log"]},
            {"iss": "https://producer.example", "sub": "evidence-stream-2", "kid": PUB["log"]}]


def trust_policy(**over: Any) -> dict:
    base = {"responder_keys": [PUB["responder"]], "log_keys": LOG_KEYS, "foreign_keys": [],
            "parties": {}, "successions": [],
            "require_action_time_from_other_party": False}
    base.update(over)
    return base


def verification_policy(**over: Any) -> dict:
    base = {"online": False, "profiles_implemented": [PROFILE], "kinds_implemented": KINDS}
    base.update(over)
    return base


def pins(evaluation_time: str, policy: dict | None = None, vpolicy: dict | None = None) -> dict:
    return {"trust_policy": policy or trust_policy(), "verification_policy": vpolicy or verification_policy(),
            "contract_ref": CONTRACT_REF, "contract_digest": CONTRACT_DIGEST,
            "evaluation_time": evaluation_time}


EVAL = "2026-10-12T01:00:00Z"

# ---------------------------------------------------------------------------
# Messages (§6)
# ---------------------------------------------------------------------------


def request(nonce: str, record: str, pin: str, *, profile: str | None = PROFILE) -> dict:
    r = {"coverage": {"expected_pin": pin}, "nonce": nonce, "subject": {"record": record}}
    if profile is not None:
        r["profile"] = profile
    return r


def encode(media_type: str, value: Any) -> bytes:
    return jcs(value).encode("utf-8") if media_type == "application/json" else cbor(value)


def envelope(req_octets: bytes, record: str, anchor: str, artifact: bytes, mat: list[tuple[str, bytes]],
             issued_at: str, media_type: str, *, key: str = "responder", profile: str | None = PROFILE,
             request_digest: str | None = None, signer: str | None = None) -> bytes:
    """An envelope (§6.2) in the encoding of ``media_type``. Signed over JCS whatever the frame (§5.1).

    ``signer`` differs from ``key`` only to forge one.
    """
    body: dict[str, Any] = {
        "anchor": {"digest": anchor},
        "artifact_digest": shx(artifact),
        "issued_at": issued_at,
        "request_digest": request_digest or shx(req_octets),
        "responder": PUB[key],
        "subject": {"record": record},
    }
    if mat:  # absent when there is no material (§6.2)
        body["verification"] = [{"digest": shx(b), "kind": k} for k, b in mat]
    if profile is not None:
        body["profile"] = profile
    sig = sign(signer or key, jcs(body).encode())
    as_bytes = b64u if media_type == "application/json" else (lambda b: b)
    full = dict(body, sig=sig, artifact=as_bytes(artifact))
    if mat:
        full["verification_content"] = [as_bytes(b) for _, b in mat]
    return encode(media_type, full)


def refusal(req_octets: bytes, reason: str, issued_at: str, *, key: str = "responder",
            signer: str | None = None) -> bytes:
    """A refusal (§6.3), JSON. ``signer`` differs from ``key`` only to forge one."""
    body = {"issued_at": issued_at, "reason": reason, "request_digest": shx(req_octets)}
    return jcs(dict(body, key_id=PUB[key], sig=sign(signer or key, jcs(body).encode()))).encode()


def signed_record(body: dict, signer: str) -> dict:
    """Any signed record of §11 or of the vector fixture formats: sig over JCS of the rest."""
    return dict(body, sig=sign(signer, jcs(body).encode()))


def ref(digest: str) -> dict:
    return {"digest_alg": "SHA-256", "digest": digest}


ENVELOPE_PROPS = ["profile_version", "envelope_signature", "responder_trust", "responder_key_current",
                  "issued_at_form", "request_binding", "subject_binding", "artifact_digest",
                  "verification_binding", "anchor_match", "anchor_inclusion"]
REFUSAL_PROPS = ["refusal_signature", "responder_trust", "responder_key_current", "request_binding",
                 "reason_registered", "issued_at_form"]


def env_props(**over: str) -> dict:
    """Envelope property statuses: every one PASS, offline, except those given (§7.2)."""
    props = dict.fromkeys(ENVELOPE_PROPS, "PASS")
    props["responder_key_current"] = "NOT_CHECKED"  # online; NOT_CHECKED offline (§7.2)
    props.update(over)
    return props


def env_props_after_version(version_status: str) -> dict:
    """§3.3 step 5 and §7.2: when profile_version is not PASS every other property is NOT_CHECKED."""
    props = dict.fromkeys(ENVELOPE_PROPS, "NOT_CHECKED")
    props["profile_version"] = version_status
    return props


def ref_props(**over: str) -> dict:
    props = dict.fromkeys(REFUSAL_PROPS, "PASS")
    props["responder_key_current"] = "NOT_CHECKED"
    props.update(over)
    return props


# §8.1 rows, by name.
ROW = {
    "envelope-1": ("CONTRADICTED", "GAP", "not_evaluable"),
    "envelope-2": ("INSUFFICIENT", "INSUFFICIENT", "not_evaluable"),
    "envelope-3": ("INSUFFICIENT", "INSUFFICIENT", "not_evaluable"),
    "envelope-4": ("UNKNOWN", "UNKNOWN", "not_evaluable"),
    "envelope-5": ("SATISFIED", "SATISFIED", "not_met"),
    "envelope-6": ("INSUFFICIENT", "INSUFFICIENT", "not_evaluable"),
    "envelope-7": (None, None, None),  # the contract evaluates the Artifact's content
    "refusal-no_such_subject": ("NOT_FOUND", "GAP", "not_evaluable"),
    "refusal-withheld": ("WITHHELD", "GAP", "not_evaluable"),
    "refusal-deadline_or_malformed": ("UNKNOWN", "UNKNOWN", "not_evaluable"),
    "refusal-failed": ("UNKNOWN", "UNKNOWN", "not_evaluable"),
    "absence": ("UNKNOWN", "UNKNOWN", "not_evaluable"),
}


def mapped(row: str) -> dict:
    status, sufficiency, verdict = ROW[row]
    out = {"row": row, "status": status, "sufficiency": sufficiency, "verdict": verdict}
    if row == "envelope-7":
        out["note"] = ("§8.1 row 7: the contract evaluates the Artifact's content; met or not_met only "
                       "if that gives SATISFIED, else not_evaluable [RES §1]. This profile fixes no content rule.")
    return out


def reply(carriage: str, data: bytes, media_type: str) -> dict:
    return {"carriage": carriage, **octets(media_type, data)}


def proofs_of(mat: list[tuple[str, bytes]]) -> list[dict]:
    """§8.3: the inclusion proof is the one entry of the CLL material RES can name."""
    return [{"kind": "inclusion_proof", "digest_alg": "SHA-256", "digest": shx(b)}
            for k, b in mat if k == "cll-inclusion-proof"]


# ---------------------------------------------------------------------------
# Cases: the exchange (§6 to §9)
# ---------------------------------------------------------------------------


def exchange_cases() -> list[dict]:
    out = []
    J, C = "application/json", "application/cbor"
    req_c = encode(J, request("2026-10-12T00:00:10Z/c", ART, ANCHOR1))
    env_c = envelope(req_c, ART, ANCHOR1, ARTIFACT, MATERIAL1, "2026-10-12T00:00:11Z", J)
    assert json.loads(env_c)["sig"] == ("d98fcb97d551c5accc5094baf58d8d6446d21b74228602a88392dcf1719cc9b9"
                                        "ab87f15e6f80792e1199e564a4f263dc35b2e8d015e65046bf2d095ec820800b")
    claim_ok = {"evidence": [ref(ART)], "proofs": proofs_of(MATERIAL1)}

    out.append({
        "id": "valid-exchange",
        "description": "Request C and its envelope from §10.1, the real Checkpointed Local Log bytes. "
                       "Every required envelope property PASS; §8.1 row 7.",
        "cites": ["§6.2", "§6.2.1", "§7.2", "§7.3", "§8.1 row 7", "§8.3", "§10.1"],
        "pins": pins(EVAL),
        "inputs": {"request": octets(J, req_c), "replies": [reply("http", env_c, J)]},
        "expected": {
            "request_digest": shx(req_c),
            "replies": [{"message_type": "envelope", "properties": env_props(),
                         "requirements": {"r-record": mapped("envelope-7")}, "claim": claim_ok}],
            "set_properties": {"caller_invariance": "NOT_CHECKED"},
        },
    })

    req_d = encode(C, request("2026-10-12T00:00:20Z/d", ART, ANCHOR1))
    env_d = envelope(req_d, ART, ANCHOR1, ARTIFACT, MATERIAL1, "2026-10-12T00:00:21Z", C)
    out.append({
        "id": "invariance-two-nonces-two-transports",
        "description": "Request C over the HTTP binding in JSON and request D, another nonce, over the "
                       "native stream in deterministic CBOR. Two envelopes, different request digests and "
                       "issuance, identical canonical Artifact octets and artifact digest.",
        "cites": ["§5.1", "§6.2 (what is invariant)", "§7.2 caller_invariance", "§11.4.1 rule 8"],
        "pins": pins(EVAL),
        "inputs": {"requests": [octets(J, req_c), octets(C, req_d)],
                   "replies": [reply("http", env_c, J), reply("evidence-request/1", env_d, C)]},
        "expected": {
            "request_digests": [shx(req_c), shx(req_d)],
            "artifact_digest": ART,
            "artifact_octets_identical": True,
            "replies": [{"message_type": "envelope", "request_index": i, "properties": env_props(),
                         "requirements": {"r-record": mapped("envelope-7")}, "claim": claim_ok}
                        for i in (0, 1)],
            "set_properties": {"caller_invariance": "PASS"},
        },
    })

    tampered = jcs({"example": "evidence record", "seq": 2}).encode()
    env_t = json.loads(env_c)
    env_t["artifact"] = b64u(tampered)
    env_t = jcs(env_t).encode()
    out.append({
        "id": "tampered-artifact",
        "description": "Envelope C with its artifact octets replaced after signing. artifact_digest FAIL, "
                       "so anchor_inclusion is never run (§6.2.1 step 4); §8.1 row 2.",
        "cites": ["§7.2 artifact_digest", "§6.2.1 step 4", "§8.1 row 2"],
        "pins": pins(EVAL),
        "inputs": {"request": octets(J, req_c), "replies": [reply("http", env_t, J)]},
        "expected": {
            "request_digest": shx(req_c),
            "replies": [{"message_type": "envelope",
                         "properties": env_props(artifact_digest="FAIL", anchor_inclusion="NOT_CHECKED"),
                         "requirements": {"r-record": mapped("envelope-2")},
                         "claim": {"evidence": [ref(ART)], "proofs": []}}],
            "set_properties": {"caller_invariance": "NOT_CHECKED"},
        },
    })

    req_a = encode(J, request("2026-10-12T00:00:00Z/a", ART, ANCHOR1))
    env_w = envelope(req_c, ART, ANCHOR1, ARTIFACT, MATERIAL1, "2026-10-12T00:00:11Z", J,
                     request_digest=shx(req_a))
    out.append({
        "id": "wrong-request-digest",
        "description": "A validly signed envelope for request C that binds the digest of another request. "
                       "request_binding FAIL; §8.1 row 2.",
        "cites": ["§7.2 request_binding", "§5.1 request digest", "§8.1 row 2"],
        "pins": pins(EVAL),
        "inputs": {"request": octets(J, req_c), "replies": [reply("http", env_w, J)],
                   "other_request": octets(J, req_a)},
        "expected": {
            "request_digest": shx(req_c),
            "replies": [{"message_type": "envelope", "properties": env_props(request_binding="FAIL"),
                         "requirements": {"r-record": mapped("envelope-2")}, "claim": claim_ok}],
            "set_properties": {"caller_invariance": "NOT_CHECKED"},
        },
    })

    def envelope_case(case_id: str, description: str, cites: list, data: bytes, props: dict,
                      req: bytes = req_c, policy: dict | None = None, proofs: bool = False) -> dict:
        return {"id": case_id, "description": description, "cites": cites, "pins": pins(EVAL, policy),
                "inputs": {"request": octets(J, req), "replies": [reply("http", data, J)]},
                "expected": {
                    "request_digest": shx(req),
                    "replies": [{"message_type": "envelope", "properties": props,
                                 "requirements": {"r-record": mapped("envelope-2")},
                                 "claim": {"evidence": [ref(ART)],
                                           "proofs": proofs_of(MATERIAL1) if proofs else []}}],
                    "set_properties": {"caller_invariance": "NOT_CHECKED"}}}

    out.append(envelope_case(
        "envelope-bad-signature",
        "Envelope C naming the trusted responder key, signed by another key. envelope_signature FAIL, "
        "so anchor_inclusion is never run (§6.2.1 step 4); §8.1 row 2. responder_trust checks the named "
        "key and passes (reading P-54).",
        ["§7.2 envelope_signature", "§6.2.1 step 4", "§8.1 row 2", "P-54"],
        envelope(req_c, ART, ANCHOR1, ARTIFACT, MATERIAL1, "2026-10-12T00:00:11Z", J, signer="impostor"),
        env_props(envelope_signature="FAIL", anchor_inclusion="NOT_CHECKED")))
    out.append(envelope_case(
        "envelope-untrusted-responder",
        "Envelope C signed by, and naming, a key the trust policy does not accept. responder_trust FAIL; "
        "§8.1 row 2. The material still proves the artifact (§6.2.1 step 4 does not depend on trust).",
        ["§7.2 responder_trust", "§8.1 row 2"],
        envelope(req_c, ART, ANCHOR1, ARTIFACT, MATERIAL1, "2026-10-12T00:00:11Z", J, key="impostor"),
        env_props(responder_trust="FAIL"), proofs=True))
    req_r1 = encode(J, request("2026-10-12T00:00:10Z/s", shx(b"evidence-interop/0 conformance vectors: "
                                                             b"another record"), ANCHOR1))
    out.append(envelope_case(
        "envelope-subject-mismatch",
        "A request for another record, answered with envelope C's subject. subject_binding FAIL; §8.1 row 2.",
        ["§7.2 subject_binding", "§8.1 row 2"],
        envelope(req_r1, ART, ANCHOR1, ARTIFACT, MATERIAL1, "2026-10-12T00:00:11Z", J),
        env_props(subject_binding="FAIL"), req=req_r1, proofs=True))
    req_pin = encode(J, request("2026-10-12T00:00:10Z/p", ART, ANCHOR2))
    out.append(envelope_case(
        "envelope-anchor-not-the-pin",
        "A request pinning another checkpoint, answered under §10.1's checkpoint. anchor_match FAIL; "
        "§8.1 row 2. The material proves the artifact under the checkpoint the envelope names.",
        ["§7.2 anchor_match", "§8.1 row 2"],
        envelope(req_pin, ART, ANCHOR1, ARTIFACT, MATERIAL1, "2026-10-12T00:00:11Z", J),
        env_props(anchor_match="FAIL"), req=req_pin, proofs=True))
    flipped = MATERIAL1[1][1][:-1] + bytes([MATERIAL1[1][1][-1] ^ 1])
    env_vt = json.loads(env_c)
    env_vt["verification_content"][1] = b64u(flipped)
    out.append(envelope_case(
        "verification-material-tampered",
        "Envelope C with one octet of its inclusion proof changed in transit. verification_binding FAIL, "
        "so anchor_inclusion is never run (§6.2.1 step 4); §8.1 row 2 (§10.1, last paragraph).",
        ["§7.2 verification_binding", "§6.2.1 step 4", "§8.1 row 2", "§10.1"],
        jcs(env_vt).encode(), env_props(verification_binding="FAIL", anchor_inclusion="NOT_CHECKED")))
    forged = [MATERIAL1[0], ("cll-inclusion-proof", flipped), MATERIAL1[2]]
    out.append(envelope_case(
        "inclusion-proof-forged-and-signed",
        "The changed inclusion proof, with the envelope re-signed over its digest. The material is bound, "
        "and does not prove the artifact: anchor_inclusion FAIL at §6.2.1 step 12; §8.1 row 2.",
        ["§6.2.1 step 12", "§8.1 row 2", "§10.1", "§12"],
        envelope(req_c, ART, ANCHOR1, ARTIFACT, forged, "2026-10-12T00:00:11Z", J),
        env_props(anchor_inclusion="FAIL")))

    def refusal_case(case_id: str, description: str, cites: list, data: bytes, props: dict, row: str,
                     extra: dict | None = None) -> dict:
        rep = {"message_type": "refusal", "properties": props, "requirements": {"r-record": mapped(row)},
               "claim": {"evidence": [ref(shx(data))], "proofs": []}}
        rep.update(extra or {})
        return {"id": case_id, "description": description, "cites": cites, "pins": pins(EVAL),
                "inputs": {"request": octets(J, req_c), "replies": [reply("http", data, J)]},
                "expected": {"request_digest": shx(req_c), "replies": [rep]}}

    out.append(refusal_case(
        "forged-refusal-untrusted-key",
        "A refusal that verifies under its own key_id, a key the trust policy does not accept. "
        "responder_trust FAIL: a response received and failed, UNKNOWN; never a refusal outcome.",
        ["§6.3", "§7.2 responder_trust", "§7.3 Refusal", "§8.1 refusal not PASS", "P-21"],
        refusal(req_c, "no_such_subject", "2026-10-12T00:00:11Z", key="impostor"),
        ref_props(responder_trust="FAIL"), "refusal-failed"))
    out.append(refusal_case(
        "forged-refusal-bad-signature",
        "A refusal naming the trusted responder key, signed by another key. refusal_signature FAIL; "
        "UNKNOWN. responder_trust checks the named key against the policy and passes (reading P-54).",
        ["§6.3", "§7.2 refusal_signature", "§8.1 refusal not PASS", "P-21", "P-54"],
        refusal(req_c, "no_such_subject", "2026-10-12T00:00:11Z", signer="impostor"),
        ref_props(refusal_signature="FAIL"), "refusal-failed"))
    out.append(refusal_case(
        "declined",
        "A conforming refusal with reason policy_declined. WITHHELD, which projects to GAP; the claim's "
        "carrier is analysis or story, never disclosure.",
        ["§6.3", "§8.1 policy_declined", "§8.2 invariant 4"],
        refusal(req_c, "policy_declined", "2026-10-12T00:00:11Z"), ref_props(), "refusal-withheld",
        {"presentation_kinds_allowed": ["analysis", "story"]}))
    out.append(refusal_case(
        "missing-evidence-no-such-subject",
        "A conforming refusal with reason no_such_subject: evidence not found. NOT_FOUND, projecting to GAP.",
        ["§6.3", "§8.1 no_such_subject"],
        refusal(req_c, "no_such_subject", "2026-10-12T00:00:11Z"), ref_props(), "refusal-no_such_subject"))

    absence = jcs({"outcome": "recorded_absence", "recorded_at": "2026-10-12T00:01:10Z",
                   "request_digest": shx(req_c), "route": "peer:example-responder",
                   "window": {"closed": "2026-10-12T00:01:10Z", "opened": "2026-10-12T00:00:10Z"}}).encode()
    out.append({
        "id": "missing-evidence-recorded-absence",
        "description": "Nothing arrived for request C within its one-minute window. The requester's "
                       "absence record maps to UNKNOWN, never to a refusal; the claim SHOULD use story.",
        "cites": ["§6.4", "§7.3 Absence", "§8.1 recorded absence", "§8.2 invariants 3 and 4", "§9.2"],
        "pins": pins(EVAL),
        "inputs": {"request": octets(J, req_c), "replies": [], "absence_record": octets(J, absence)},
        "expected": {
            "request_digest": shx(req_c),
            "replies": [],
            "absence": {"form": "conforming", "requirements": {"r-record": mapped("absence")},
                        "claim": {"evidence": [ref(shx(absence))], "proofs": []},
                        "presentation_kind_recommended": "story"},
        },
    })

    env_v1 = envelope(req_c, ART, ANCHOR1, ARTIFACT, MATERIAL1, "2026-10-12T00:00:11Z", J,
                      profile="evidence-interop/1")
    out.append({
        "id": "unsupported-version-mismatch",
        "description": "Request C asks for evidence-interop/0; the envelope names evidence-interop/1. The "
                       "verifier implements both, so only the mismatch rule of §3.3 step 5 applies: "
                       "profile_version FAIL and every other envelope property NOT_CHECKED; §8.1 row 2.",
        "cites": ["§3.3 step 5", "§7.2", "§8.1 row 2", "P-56"],
        "pins": pins(EVAL, vpolicy=verification_policy(profiles_implemented=[PROFILE, "evidence-interop/1"])),
        "inputs": {"request": octets(J, req_c), "replies": [reply("http", env_v1, J)]},
        "expected": {
            "request_digest": shx(req_c),
            "replies": [{"message_type": "envelope", "properties": env_props_after_version("FAIL"),
                         "requirements": {"r-record": mapped("envelope-2")},
                         "claim": {"evidence": [ref(ART)], "proofs": []}}],
            "set_properties": {"caller_invariance": "NOT_CHECKED"},
        },
    })
    env_none = envelope(req_c, ART, ANCHOR1, ARTIFACT, MATERIAL1, "2026-10-12T00:00:11Z", J, profile=None)
    out.append({
        "id": "unsupported-version-absent",
        "description": "An artifact response with no profile member, as from a responder implementing the "
                       "Evidence Request draft alone. profile_version NOT_PRESENT; §8.1 row 3.",
        "cites": ["§3.3 step 5", "§7.2", "§8.1 row 3"],
        "pins": pins(EVAL),
        "inputs": {"request": octets(J, req_c), "replies": [reply("http", env_none, J)]},
        "expected": {
            "request_digest": shx(req_c),
            "replies": [{"message_type": "envelope", "properties": env_props_after_version("NOT_PRESENT"),
                         "requirements": {"r-record": mapped("envelope-3")},
                         "claim": {"evidence": [ref(ART)], "proofs": []}}],
            "set_properties": {"caller_invariance": "NOT_CHECKED"},
        },
    })
    req_v1 = encode(J, request("2026-10-12T00:00:30Z/v1", ART, ANCHOR1, profile="evidence-interop/1"))
    env_v1b = envelope(req_v1, ART, ANCHOR1, ARTIFACT, MATERIAL1, "2026-10-12T00:00:31Z", J,
                       profile="evidence-interop/1")
    out.append({
        "id": "unsupported-version-unimplemented",
        "description": "A request and envelope under evidence-interop/1, checked by a verifier that "
                       "implements only evidence-interop/0. profile_version NOT_CHECKED, every other "
                       "property NOT_CHECKED, never checked under v0 rules; §8.1 row 4.",
        "cites": ["§3.3 step 5", "§7.2", "§8.1 row 4"],
        "pins": pins(EVAL),
        "inputs": {"request": octets(J, req_v1), "replies": [reply("http", env_v1b, J)]},
        "expected": {
            "request_digest": shx(req_v1),
            "replies": [{"message_type": "envelope", "properties": env_props_after_version("NOT_CHECKED"),
                         "requirements": {"r-record": mapped("envelope-4")},
                         "claim": {"evidence": [ref(ART)], "proofs": []}}],
            "set_properties": {"caller_invariance": "NOT_CHECKED"},
        },
    })
    req_v9 = encode(J, request("2026-10-12T00:00:40Z/v9", ART, ANCHOR1, profile="evidence-interop/9"))
    ref_v9 = refusal(req_v9, "request_malformed", "2026-10-12T00:00:41Z")
    out.append({
        "id": "unsupported-version-refused",
        "description": "A request naming evidence-interop/9, which the responder does not implement. It "
                       "refuses with request_malformed (§3.3 step 4); a conforming refusal, UNKNOWN.",
        "cites": ["§3.3 step 4", "§6.1 validation step 5", "§8.1 request_malformed"],
        "pins": pins(EVAL),
        "inputs": {"request": octets(J, req_v9),
                   "replies": [reply("http", ref_v9, J)]},
        "expected": {
            "request_digest": shx(req_v9),
            "replies": [{"message_type": "refusal", "properties": ref_props(),
                         "requirements": {"r-record": mapped("refusal-deadline_or_malformed")},
                         "claim": {"evidence": [ref(shx(ref_v9))],
                                   "proofs": []}}],
        },
    })
    return out


# ---------------------------------------------------------------------------
# Cases: a foreign object inside a verified Artifact (§5.1, §7.2 native_check, §8.1 rows 5 and 6)
# ---------------------------------------------------------------------------

RELATIONS = {"r-carried-signature": "is_check", "r-authorized": "supports"}


def foreign_cases() -> list[dict]:
    J = "application/json"
    policy = trust_policy(foreign_keys=[PUB["foreign-signer"]])
    out = []
    for case_id, art, entry, native, rows, description in (
        ("foreign-native-check-fails", ARTIFACT_F_BAD, 5, "FAIL",
         {"r-carried-signature": "envelope-5", "r-authorized": "envelope-6"},
         "Every envelope property PASS; the carried JWS fails its own signature check. The requirement "
         "that IS the check is SATISFIED and not_met (row 5); the one the check only SUPPORTS is "
         "INSUFFICIENT (row 6)."),
        ("foreign-native-check-passes", ARTIFACT_F_OK, 1, "PASS",
         {"r-carried-signature": "envelope-7", "r-authorized": "envelope-7"},
         "Control: the same envelope path with a JWS that verifies. Neither row 5 nor row 6 applies; "
         "both requirements go to row 7."),
    ):
        digest = shx(art)
        req = encode(J, request(f"2026-10-12T00:00:50Z/{entry}", digest, ANCHOR2))
        mat = material(LOG2, entry)
        env = envelope(req, digest, ANCHOR2, art, mat, "2026-10-12T00:00:51Z", J)
        out.append({
            "id": case_id, "description": description,
            "cites": ["§5.1 (as-transmitted rule)", "§7.2 native_check", "§7.3", "§8.1 rows 5 to 7"],
            "pins": pins(EVAL, policy),
            "inputs": {"request": octets(J, req), "replies": [reply("http", env, J)],
                       "requirement_relations": RELATIONS,
                       "foreign_object": {"path": "carried.object", "media_type": "application/jose",
                                          "native_method": "JWS compact serialization (RFC 7515), EdDSA "
                                                           "(RFC 8037), under the key its kid names, "
                                                           "accepted by the trust policy"}},
            "expected": {
                "request_digest": shx(req),
                "replies": [{"message_type": "envelope", "properties": env_props(),
                             "native_check": native,
                             "requirements": {r: mapped(row) for r, row in rows.items()},
                             "claim": {"evidence": [ref(digest)], "proofs": proofs_of(mat)}}],
                "set_properties": {"caller_invariance": "NOT_CHECKED"},
            },
        })
    other = encode(J, request("2026-10-12T00:00:00Z/x", shx(ARTIFACT_F_BAD), ANCHOR2))
    req = encode(J, request("2026-10-12T00:00:50Z/5", shx(ARTIFACT_F_BAD), ANCHOR2))
    mat = material(LOG2, 5)
    env = envelope(req, shx(ARTIFACT_F_BAD), ANCHOR2, ARTIFACT_F_BAD, mat, "2026-10-12T00:00:51Z", J,
                   request_digest=shx(other))
    out.append({
        "id": "foreign-native-check-fails-envelope-fails",
        "description": "The failing JWS again, under an envelope whose request_binding FAILs. The Artifact "
                       "is not usable evidence for any requirement, including the one that is the check: "
                       "row 2 for both, and native_check is not run.",
        "cites": ["§7.2 (native_check applies only after every envelope property passed)",
                  "§8.1 row 2", "§8.1 (rows 5 and 6 apply only when every envelope property passed)"],
        "pins": pins(EVAL, policy),
        "inputs": {"request": octets(J, req), "replies": [reply("http", env, J)],
                   "requirement_relations": RELATIONS,
                   "foreign_object": {"path": "carried.object", "media_type": "application/jose",
                                      "native_method": "JWS compact serialization (RFC 7515), EdDSA (RFC 8037)"}},
        "expected": {
            "request_digest": shx(req),
            "replies": [{"message_type": "envelope", "properties": env_props(request_binding="FAIL"),
                         "native_check": None,
                         "requirements": {r: mapped("envelope-2") for r in RELATIONS},
                         "claim": {"evidence": [ref(shx(ARTIFACT_F_BAD))], "proofs": proofs_of(mat)}}],
            "set_properties": {"caller_invariance": "NOT_CHECKED"},
        },
    })
    return out


# ---------------------------------------------------------------------------
# Cases: the acceptance record (§11.1), including §11.1.9 variants A to G
# ---------------------------------------------------------------------------

TXN = {"scheme": "example", "id": "T"}
ACC_EVAL = "2026-10-12T01:00:00Z"
ACC_PROPS = ["acceptance_form", "acceptance_signature", "acceptance_signer_trust", "acceptance_binding",
             "proposal_binding", "acceptance_unique", "execution_cites_acceptance", "acceptance_ordering"]


def acc_record(state: str, signer: str, issued_at: str, proposal: str | None = None) -> dict:
    body = {"profile": PROFILE, "state": state, "contract_ref": CONTRACT_REF, "contract_digest": CONTRACT_DIGEST,
            "transaction": TXN, "proposer": PUB["P"], "acceptor": PUB["Q"], "issued_at": issued_at}
    if proposal is not None:
        body["proposal_digest"] = proposal
    return signed_record(body, signer)


def execution_record(cites: list[str], action_at: str) -> dict:
    """The vector fixture execution record (§11.5): signed by the acceptor, cites by EL link shape."""
    return signed_record({"action_at": action_at, "issuer": PUB["Q"], "transaction": TXN,
                          "links": [{"type": "cites", "target": c} for c in cites]}, "Q")


def receipt(acceptance: str, receiver: str, received_at: str) -> dict:
    return signed_record({"profile": PROFILE, "acceptance_digest": acceptance, "received_at": received_at,
                          "receiver": PUB[receiver]}, receiver)


def acc_props(**over: str) -> dict:
    props = dict.fromkeys(ACC_PROPS, "PASS")
    props["acceptance_unique"] = "NOT_CHECKED"
    props.update(over)
    return props


def acceptance_cases() -> list[dict]:
    proposal = acc_record("proposed", "P", "2026-10-12T00:00:00Z")
    pd = json_digest(proposal)
    backdated = acc_record("accepted", "Q", "2026-10-12T00:05:00Z", pd)
    bd = json_digest(backdated)
    late = acc_record("accepted", "Q", "2026-10-12T00:20:00Z", pd)
    ld = json_digest(late)
    exe = execution_record([bd], "2026-10-12T00:10:00Z")
    exe_late = execution_record([ld], "2026-10-12T00:10:00Z")
    parties = {PUB["P"]: "party-proposer", PUB["Q"]: "party-acceptor"}
    same_party = {PUB["P"]: "party-acceptor", PUB["Q"]: "party-acceptor"}
    policy = trust_policy(responder_keys=[], parties=parties)
    r_q = receipt(bd, "Q", "2026-10-12T00:06:00Z")
    r_p_late = receipt(bd, "P", "2026-10-12T00:20:00Z")
    r_p = receipt(bd, "P", "2026-10-12T00:06:00Z")
    cites = ["§11.1.1", "§11.1.2", "§11.1.4", "§11.1.5", "§11.1.7", "§11.1.8", "§11.1.9"]

    def case(case_id: str, description: str, accepted: dict, execution: dict, receipts: list[dict],
             receipt_props: list[dict], props: dict, finding: str, *, pol: dict | None = None,
             extra_inputs: dict | None = None, claim: list[str] | None = None) -> dict:
        records = [proposal] + ([accepted] if accepted else [])
        exp = {"finding": finding,
               "candidates": ([{"record_digest": json_digest(accepted), "properties": props}]
                              if accepted else []),
               "receipts": [{"receipt_digest": json_digest(r), "properties": p}
                            for r, p in zip(receipts, receipt_props)]}
        if claim is not None:
            exp["claim"] = {"contract_ref": CONTRACT_REF, "evidence_includes": [ref(d) for d in claim]}
        return {"id": case_id, "description": description, "cites": cites,
                "pins": pins(ACC_EVAL, pol or policy),
                "inputs": {"transaction": TXN, "proposer": PUB["P"], "acceptor": PUB["Q"],
                           "acceptance_records": [jcs(r) for r in records],
                           "execution_records": [jcs(execution)],
                           "acceptance_receipts": [jcs(r) for r in receipts],
                           **(extra_inputs or {})},
                "expected": exp}

    out = [
        case("acceptance-absent",
             "A proposal and an execution record, and no answer from the acceptor. No candidate: "
             "not_accepted, and the requirements are the requester's own expectations.",
             {}, execution_record([], "2026-10-12T00:10:00Z"), [], [], {}, "not_accepted"),
        case("acceptance-backdated-A-no-ordering-evidence",
             "§11.1.9 A: an acceptance written after the action, dated before it, with no ordering "
             "evidence. It must not reach accepted_before_action.",
             backdated, exe, [], [], acc_props(acceptance_ordering="NOT_PRESENT"),
             "accepted_execution_cites", claim=[bd]),
        case("acceptance-backdated-B-receipt-by-acceptor",
             "§11.1.9 B: a receipt signed by the acceptor itself does not count as ordering evidence.",
             backdated, exe, [r_q], [{"receipt_signature": "PASS", "receipt_signer": "FAIL"}],
             acc_props(acceptance_ordering="NOT_PRESENT"), "accepted_execution_cites", claim=[bd]),
        case("acceptance-backdated-C-late-receipt",
             "§11.1.9 C: an honest receipt from the proposer, received after the action. It counts, and "
             "its ordering point is not earlier than the action: INCONCLUSIVE.",
             backdated, exe, [r_p_late], [{"receipt_signature": "PASS", "receipt_signer": "PASS"}],
             acc_props(acceptance_ordering="INCONCLUSIVE"), "accepted_execution_cites", claim=[bd]),
        case("acceptance-after-action-D",
             "§11.1.9 D: an accepted record whose own issued_at is after the action. The acceptor's own "
             "record admits it: acceptance_ordering FAIL, accepted_after_action.",
             late, exe_late, [], [], acc_props(acceptance_ordering="FAIL"), "accepted_after_action",
             claim=[ld]),
        case("acceptance-backdated-E-control",
             "§11.1.9 E: the same record bytes as A, with a proposer's receipt received before the action. "
             "PASS, accepted_before_action.",
             backdated, exe, [r_p], [{"receipt_signature": "PASS", "receipt_signer": "PASS"}],
             acc_props(), "accepted_before_action", claim=[bd, json_digest(r_p)]),
        case("acceptance-backdated-F-second-key",
             "§11.1.9 F: the trust policy maps the proposer key to the acceptor's party. Neither key is "
             "accepted in its role: not_accepted.",
             backdated, exe, [r_p], [{"receipt_signature": "PASS", "receipt_signer": "FAIL"}],
             acc_props(acceptance_signer_trust="FAIL", proposal_binding="FAIL",
                       acceptance_ordering="NOT_PRESENT"),
             "not_accepted", pol=trust_policy(responder_keys=[], parties=same_party)),
        case("acceptance-backdated-G-limit",
             "§11.1.9 G: the inputs of E, while the action truly took place at 00:01. The true time is not "
             "an input, so the result is E's: the limit of §11.1.10.",
             backdated, exe, [r_p], [{"receipt_signature": "PASS", "receipt_signer": "PASS"}],
             acc_props(), "accepted_before_action", claim=[bd, json_digest(r_p)],
             extra_inputs={"not_an_input_true_action_time": "2026-10-12T00:01:00Z"}),
        case("acceptance-backdated-G-policy-requires-other-party",
             "§11.1.9 G under a trust policy requiring a time for the action from a party other than the "
             "acceptor: none is held, so acceptance_ordering is NOT_PRESENT (§11.1.5 rule 3).",
             backdated, exe, [r_p], [{"receipt_signature": "PASS", "receipt_signer": "PASS"}],
             acc_props(acceptance_ordering="NOT_PRESENT"), "accepted_execution_cites",
             pol=trust_policy(responder_keys=[], parties=parties, require_action_time_from_other_party=True),
             claim=[bd]),
    ]
    return out


# ---------------------------------------------------------------------------
# Cases: lifecycle links (§11.2), §11.2.7 variants A to I
# ---------------------------------------------------------------------------

LC_EVAL = "2026-10-12T02:00:00Z"
LC_PROPS = ["lifecycle_form", "lifecycle_signature", "lifecycle_target", "lifecycle_issuer",
            "lifecycle_signer_trust", "lifecycle_unique"]


def producer_record() -> dict:
    """R0, the vector fixture producer record (§11.5): signed by ``producer`` over JCS of the rest."""
    return signed_record({"claim": "example claim", "issued_at": "2026-10-12T00:00:00Z",
                          "producer": PUB["I"]}, "I")


CONTENT_X = {"claim": "example correction x"}
CONTENT_Y = {"claim": "example correction y"}
PROCESS = {"scheme": "example", "id": "case-1"}


def statement(token: str, signer: str, target: str, *, issuer: str | None = None,
              content: dict | None = None, process: dict | None = None,
              issued_at: str = "2026-10-12T00:30:00Z") -> dict:
    body: dict[str, Any] = {"profile": PROFILE, "issuer": PUB[issuer or signer],
                            "link": {"type": token, "target": target}, "issued_at": issued_at}
    if content is not None:
        body["content"] = json_digest(content)
    if process is not None:
        body["process"] = process
    return signed_record(body, signer)


def lc_props(**over: str | None) -> dict:
    props = dict.fromkeys(LC_PROPS, "PASS")
    props["lifecycle_unique"] = "NOT_CHECKED"
    for k, v in over.items():
        if v is None:
            props.pop(k)
        else:
            props[k] = v
    return props


def lifecycle_cases() -> list[dict]:
    r0 = producer_record()
    d0 = json_digest(r0)
    x = json_digest(CONTENT_X)
    s_n = statement("supersedes", "N", d0, content=CONTENT_X)
    s_i = statement("supersedes", "I", d0, content=CONTENT_X)
    s_c = statement("supersedes", "N", d0, issuer="I", content=CONTENT_X)
    a_n = statement("amends", "N", d0, content=CONTENT_X)
    s_i2 = statement("supersedes", "I2", d0, content=CONTENT_X)
    d_n = statement("disputes", "N", d0, process=PROCESS)
    s_i_y = statement("supersedes", "I", d0, content=CONTENT_Y, issued_at="2026-10-12T00:40:00Z")
    parties = {PUB["I"]: "party-i", PUB["N"]: "party-n", PUB["I2"]: "party-i"}
    policy = trust_policy(responder_keys=[], parties=parties)
    nothing = {"historical_claim": d0, "latest_supported_state": {"element": d0, "contents": []},
               "forked_at": None, "branches": [], "challenges": []}
    a_props = lc_props(lifecycle_issuer="FAIL")
    cites = ["§11.2.2", "§11.2.3", "§11.2.4", "§11.2.5", "§11.2.6", "§11.2.7"]

    def case(variant: str, description: str, held: list[tuple[str, dict, dict, str]], display: dict,
             pol: dict | None = None) -> dict:
        return {"id": f"lifecycle-{variant}", "description": description, "cites": cites,
                "pins": pins(LC_EVAL, pol or policy),
                "inputs": {"target_record": jcs(r0), "content_documents": {"x": jcs(CONTENT_X), "y": jcs(CONTENT_Y)},
                           "process": PROCESS, "statements": [jcs(s) for _, s, _, _ in held]},
                "expected": {"target_digest": d0,
                             "statements": [{"name": name, "statement_digest": json_digest(s),
                                             "properties": props, "finding": finding}
                                            for name, s, props, finding in held],
                             "display": display}}

    def state(element: dict, contents: list[str]) -> dict:
        return dict(nothing, latest_supported_state={"element": json_digest(element), "contents": contents})

    return [
        case("A-non-issuer-supersedes", "§11.2.7 A: N supersedes I's record. lifecycle_not_issuer; no effect.",
             [("S_N", s_n, a_props, "lifecycle_not_issuer")], nothing),
        case("B-issuer-supersedes", "§11.2.7 B, control: I supersedes its own record.",
             [("S_I", s_i, lc_props(), "lifecycle_effective")], state(s_i, [x])),
        case("C-non-issuer-writes-issuer-key",
             "§11.2.7 C: issuer names I, the signature is N's. lifecycle_signature FAIL; the issuer is not "
             "established.",
             [("S_C", s_c, lc_props(lifecycle_signature="FAIL", lifecycle_issuer="NOT_CHECKED",
                                    lifecycle_signer_trust="NOT_CHECKED"), "lifecycle_not_effective")],
             nothing),
        case("D-both", "§11.2.7 D: S_N and S_I, in either order. Only S_I qualifies, so it is unique.",
             [("S_N", s_n, a_props, "lifecycle_not_issuer"),
              ("S_I", s_i, lc_props(lifecycle_unique="PASS"), "lifecycle_effective")], state(s_i, [x])),
        case("D-both-reversed", "§11.2.7 D in the other order of receipt: the same findings and state.",
             [("S_I", s_i, lc_props(lifecycle_unique="PASS"), "lifecycle_effective"),
              ("S_N", s_n, a_props, "lifecycle_not_issuer")], state(s_i, [x])),
        case("E-non-issuer-amends", "§11.2.7 E: N amends I's record. lifecycle_not_issuer.",
             [("A_N", a_n, a_props, "lifecycle_not_issuer")], nothing),
        case("F-second-key-same-party",
             "§11.2.7 F: I2, mapped to I's party but not a successor, supersedes. lifecycle_not_issuer.",
             [("S_I2", s_i2, a_props, "lifecycle_not_issuer")], nothing),
        case("G-rotated-key", "§11.2.7 G: the trust policy states that I2 succeeds I.",
             [("S_I2", s_i2, lc_props(), "lifecycle_effective")], state(s_i2, [x]),
             pol=trust_policy(responder_keys=[], parties=parties,
                              successions=[{"key": PUB["I2"], "succeeds": PUB["I"]}])),
        case("H-non-issuer-disputes",
             "§11.2.7 H: N disputes I's record through process p. Effective; one open dispute; content "
             "unchanged.",
             [("D_N", d_n, lc_props(lifecycle_issuer=None, lifecycle_unique=None), "lifecycle_effective")],
             dict(nothing, challenges=[{"statement_digest": json_digest(d_n), "type": "disputes",
                                        "issuer": PUB["N"], "on": d0, "lifecycle_signer_trust": "PASS",
                                        "scope": None, "content": None, "status": "open"}])),
        case("I-fork", "§11.2.7 I: two supersessions of R0 by I. Both forked; no latest supported state.",
             [("S_I", s_i, lc_props(lifecycle_unique="FAIL"), "lifecycle_forked"),
              ("S_I'", s_i_y, lc_props(lifecycle_unique="FAIL"), "lifecycle_forked")],
             dict(nothing, latest_supported_state=None, forked_at=d0,
                  branches=sorted([[json_digest(s_i)], [json_digest(s_i_y)]]))),
    ]


# ---------------------------------------------------------------------------
# Cases: carriage over the native stream, A2A and MCP (§11.4, §11.4.8)
# ---------------------------------------------------------------------------

MANIFEST = {"bindings": ["a2a", "evidence-request/1", "mcp"], "drafts": ["draft-mih-agent-evidence-request-00"],
            "profiles": [PROFILE], "subject_forms": ["record"]}


def opaque_id(label: str) -> str:
    """An unpredictable-looking carriage identifier that encodes no count or time (§11.4.3)."""
    return shx(f"evidence-interop/0 conformance vectors: carriage id {label}".encode())[:32]


def a2a_message(r: bytes) -> dict:
    return {"messageId": opaque_id("message"), "role": "ROLE_USER", "extensions": [EXT_URI],
            "parts": [{"mediaType": "application/cbor", "raw": base64.b64encode(r).decode("ascii")}]}


def a2a_task(state: str, replies: list[tuple[str, bytes]]) -> dict:
    task: dict[str, Any] = {"id": opaque_id("task"), "contextId": opaque_id("context"),
                            "status": {"state": state}}
    if replies:
        task["artifacts"] = [{"artifactId": opaque_id(f"artifact {label}"), "extensions": [EXT_URI],
                              "parts": [{"mediaType": "application/cbor",
                                         "raw": base64.b64encode(data).decode("ascii")}]}
                             for label, data in replies]
    return task


def mcp_call(r: bytes) -> dict:
    return {"name": "evidence_request", "arguments": {"request": b64u(r), "media_type": "application/cbor"}}


def mcp_result(data: bytes | None, *, is_error: bool = False, text: str | None = None) -> dict:
    res: dict[str, Any] = {"content": [{"type": "text", "text": text}] if text else [], "isError": is_error}
    if data is not None:
        res["structuredContent"] = {"reply": b64u(data), "media_type": "application/cbor"}
    return res


def carriage_cases() -> list[dict]:
    C = "application/cbor"
    req_obj = request("2026-10-12T00:00:10Z/c", ART, ANCHOR1)
    r = cbor(req_obj)
    rd = shx(r)
    reserialized = json.dumps({"example": "evidence record", "seq": 1}, indent=1).encode()
    e_native = envelope(r, ART, ANCHOR1, ARTIFACT, MATERIAL1, "2026-10-12T00:00:12Z", C)
    e_a2a = envelope(r, ART, ANCHOR1, ARTIFACT, MATERIAL1, "2026-10-12T00:00:13Z", C)
    e_mcp = envelope(r, ART, ANCHOR1, ARTIFACT, MATERIAL1, "2026-10-12T00:00:14Z", C)
    e_a2a_reser = envelope(r, ART, ANCHOR1, reserialized, MATERIAL1, "2026-10-12T00:00:13Z", C)
    e_mcp_rehash = envelope(r, ART, ANCHOR1, ARTIFACT, MATERIAL1, "2026-10-12T00:00:14Z", C,
                            request_digest=json_digest(req_obj))
    card_entry = {"uri": EXT_URI, "description": "Evidence request exchange, profile evidence-interop/0.",
                  "required": False, "params": MANIFEST}
    mcp_manifest = {"content": [], "isError": False, "structuredContent": MANIFEST}
    cites = ["§11.4.1", "§11.4.4", "§11.4.5", "§11.4.7", "§11.4.8"]
    ok = {"message_type": "envelope", "properties": env_props(),
          "requirements": {"r-record": mapped("envelope-7")},
          "claim": {"evidence": [ref(ART)], "proofs": proofs_of(MATERIAL1)}}
    contradicted = dict(ok, requirements={"r-record": mapped("envelope-1")})

    def carried(native: bytes | None, task: dict | None, result: dict | None,
                manifests: dict | None = None) -> dict:
        inputs: dict[str, Any] = {"request": octets(C, r)}
        if native is not None:
            inputs["native"] = {"request_frame_hex": r.hex(), "response_frame_hex": native.hex()}
        if task is not None:
            inputs["a2a"] = {"message": a2a_message(r), "task": task}
        if result is not None:
            inputs["mcp"] = {"call": mcp_call(r), "result": result}
        if manifests is not None:
            inputs["manifests"] = manifests
        return inputs

    def case(case_id: str, description: str, inputs: dict, classification: dict, replies: list,
             set_props: dict, extra: dict | None = None) -> dict:
        exp = {"request_digest": rd, "carriage_request_digests": dict.fromkeys(
                   [k for k in ("native", "a2a", "mcp") if k in inputs], rd),
               "classification": classification, "replies": replies}
        if replies:
            exp["set_properties"] = set_props
        exp.update(extra or {})
        return {"id": case_id, "description": description, "cites": cites, "pins": pins(EVAL),
                "inputs": inputs, "expected": exp}

    def absence_for(route: str) -> bytes:
        return jcs({"outcome": "recorded_absence", "recorded_at": "2026-10-12T00:01:10Z", "request_digest": rd,
                    "route": route, "window": {"closed": "2026-10-12T00:01:10Z",
                                               "opened": "2026-10-12T00:00:10Z"}}).encode()

    manifests_ok = {"a2a_extension": card_entry, "mcp_evidence_manifest": mcp_manifest}
    out = [
        case("carriage-invariance",
             "Request C as deterministic CBOR, sent once over each carriage; three envelopes with distinct "
             "issued_at. One request digest, one artifact, caller_invariance PASS; one manifest served twice.",
             carried(e_native, a2a_task("TASK_STATE_COMPLETED", [("1", e_a2a)]), mcp_result(e_mcp), manifests_ok),
             {"native": "reply", "a2a": "reply", "mcp": "reply"}, [ok, ok, ok],
             {"caller_invariance": "PASS"},
             {"manifest_properties": {"a2a_extension": {"manifest_form": "PASS"},
                                      "mcp_evidence_manifest": {"manifest_form": "PASS"},
                                      "manifest_consistency": "PASS"}}),
        case("carriage-mcp-rehashes-json",
             "§11.4.8: the MCP adapter hashes a JSON re-encoding of R instead of the octets received. That "
             "envelope's request_binding FAILs: row 2.",
             carried(e_native, a2a_task("TASK_STATE_COMPLETED", [("1", e_a2a)]), mcp_result(e_mcp_rehash)),
             {"native": "reply", "a2a": "reply", "mcp": "reply"},
             [ok, ok, dict(ok, properties=env_props(request_binding="FAIL"),
                           requirements={"r-record": mapped("envelope-2")})],
             {"caller_invariance": "PASS"}),
        case("carriage-a2a-reserializes-artifact",
             "§11.4.8: the A2A adapter re-serializes the canonical Artifact and the responder signs a valid "
             "envelope over it. caller_invariance FAIL over the three: row 1 for each. That envelope's own "
             "anchor_inclusion is NOT_CHECKED (§6.2.1 step 5).",
             carried(e_native, a2a_task("TASK_STATE_COMPLETED", [("1", e_a2a_reser)]), mcp_result(e_mcp)),
             {"native": "reply", "a2a": "reply", "mcp": "reply"},
             [contradicted,
              dict(contradicted, properties=env_props(anchor_inclusion="NOT_CHECKED"),
                   claim={"evidence": [ref(shx(reserialized))], "proofs": []}),
              contradicted],
             {"caller_invariance": "FAIL"}),
        case("carriage-a2a-task-rejected",
             "§11.4.8: the A2A task ends TASK_STATE_REJECTED with no reply Artifact. A transport condition: "
             "pending, then a recorded absence once the window closes; never a refusal.",
             dict(carried(None, a2a_task("TASK_STATE_REJECTED", []), None),
                  absence_record=octets("application/json", absence_for("a2a"))),
             {"a2a": "transport_condition"}, [], {"caller_invariance": "NOT_CHECKED"},
             {"absence": {"form": "conforming", "requirements": {"r-record": mapped("absence")},
                          "presentation_kind_recommended": "story",
                          "claim": {"evidence": [ref(shx(absence_for("a2a")))], "proofs": []}}}),
        case("carriage-mcp-error-no-reply",
             "§11.4.8: an MCP result with isError true, no structuredContent.reply, and text saying the caller "
             "is not authorized. A transport condition, never a refusal.",
             dict(carried(None, None, mcp_result(None, is_error=True, text="caller is not authorized")),
                  absence_record=octets("application/json", absence_for("mcp"))),
             {"mcp": "transport_condition"}, [], {"caller_invariance": "NOT_CHECKED"},
             {"absence": {"form": "conforming", "requirements": {"r-record": mapped("absence")},
                          "presentation_kind_recommended": "story",
                          "claim": {"evidence": [ref(shx(absence_for("mcp")))], "proofs": []}}}),
        case("carriage-mcp-error-with-reply",
             "§11.4.8: an MCP result with isError true and a valid structuredContent.reply. The reply, "
             "verified as in the positive case; isError is ignored.",
             carried(None, None, mcp_result(e_mcp, is_error=True)),
             {"mcp": "reply"}, [ok], {"caller_invariance": "NOT_CHECKED"}),
        case("carriage-a2a-two-artifacts",
             "§11.4.8: one A2A task carries two reply Artifacts with distinct artifactIds, whose envelopes "
             "sign different artifact octets. Each is verified on its own; caller_invariance FAIL; row 1.",
             carried(None, a2a_task("TASK_STATE_COMPLETED", [("1", e_a2a), ("2", e_a2a_reser)]), None),
             {"a2a": "reply"},
             [contradicted,
              dict(contradicted, properties=env_props(anchor_inclusion="NOT_CHECKED"),
                   claim={"evidence": [ref(shx(reserialized))], "proofs": []})],
             {"caller_invariance": "FAIL"}),
        case("carriage-manifest-count-member",
             "§11.4.8: the A2A extension params add a count member. manifest_form FAIL for that copy; "
             "manifest_consistency FAIL against the evidence_manifest result.",
             carried(None, None, None, {"a2a_extension": dict(card_entry, params=dict(MANIFEST, record_count=42)),
                                        "mcp_evidence_manifest": mcp_manifest}),
             {}, [], {"caller_invariance": "NOT_CHECKED"},
             {"manifest_properties": {"a2a_extension": {"manifest_form": "FAIL"},
                                      "mcp_evidence_manifest": {"manifest_form": "PASS"},
                                      "manifest_consistency": "FAIL"}}),
    ]
    return out


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------


def _dump(value: Any) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def build() -> dict[str, bytes]:
    cases = exchange_cases() + foreign_cases() + acceptance_cases() + lifecycle_cases() + carriage_cases()
    ids = [c["id"] for c in cases]
    assert len(ids) == len(set(ids)), "duplicate case id"
    corpus = {
        "set": SET,
        "status": STATUS,
        "provenance": "spec-derived",
        "profile": PROFILE,
        "spec": SPEC,
        "test_keys": {
            "note": "TEST-ONLY. Each private key is the 32-byte Ed25519 seed SHA-256(seed_label).",
            "keys": {name: {"seed_label": SEED_LABELS[name], "public": PUB[name]} for name in SEED_LABELS},
        },
        "contract": {
            "document": CONTRACT,
            "document_jcs": jcs(CONTRACT),
            "contract_ref": CONTRACT_REF,
            "contract_digest": CONTRACT_DIGEST,
            "schema": EC_SCHEMA,
        },
        "logs": {
            name: {"iss": "https://producer.example", "sub": log["sub"], "log_key": PUB["log"],
                   "entries": entries, "checkpoint_hex": log["checkpoint"].hex(),
                   "anchor_digest": shx(log["checkpoint"])}
            for name, log, entries in (("log-1", LOG1, [e.hex() for e in _entries1]),
                                       ("log-2", LOG2, [e.hex() for e in _entries2]))
        },
        "fixture_formats": {
            "execution_record": "members action_at, issuer, links (EL link shape, type cites), transaction, "
                                "sig; sig is Ed25519 by issuer over UTF-8 of JCS of the other members",
            "producer_record": "members claim, issued_at, producer, sig; sig is Ed25519 by producer over "
                               "UTF-8 of JCS of the other members; the producer is its issuer (§11.2.3)",
            "record_digest": "SHA-256 over UTF-8 of JCS of the whole object, sig included",
        },
        "count": len(cases),
        "cases": cases,
    }
    files = {"vectors.json": _dump(corpus)}
    files["manifest.json"] = _dump({
        "set": SET,
        "status": STATUS,
        "provenance": "spec-derived",
        "spec": SPEC,
        "generator": "python/scripts/generate_interop_profile_v0_vectors.py",
        "files": [{"path": name, "sha256": shx(data), "count": json.loads(data).get("count")}
                  for name, data in sorted(files.items())],
    })
    return files


def write(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for name, data in build().items():
        (out / name).write_bytes(data)
    lines = [f"{shx(p.read_bytes())}  {p.name}"
             for p in sorted(out.iterdir()) if p.is_file() and p.name != "SHA256SUMS"]
    (out / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    write(parser.parse_args().out)


if __name__ == "__main__":
    main()
