# SPDX-License-Identifier: BSD-3-Clause
"""Derive settlement states from two parties' leg records (verification only).

Verifier for "Two-Party Settlement Records for Agent Payments",
draft-mih-agent-settlement-records-00 (``spec/draft-mih-agent-settlement-records-00.md``).
The payer and the payee are two independent sealers; each seals only what its
own system observed, as a Capsule with a top-level ``settlement`` member::

    terms  <-terms_ref-  payer_observed, payee_observed, delivered

:func:`verify_settlements` checks each leg record on its own (the Capsule
checks, its Producer Envelope, the ``settlement`` structure and amounts, its
wrapped entries and, with a key policy, that its key may seal its role), then
groups the legs by ``terms_ref`` and derives the draft's states: payment
``terms_only`` / ``payer_stated`` / ``payee_stated`` / ``agreed`` /
``mismatch`` / ``unjoined``, and delivery ``none`` / ``stated`` / ``matched``
/ ``mismatch``. A pair whose two observed legs share a key is never
``agreed``: its state is ``None`` and ``sealer_conflation`` is a failure.
Whether each key belongs to its party is a separate result
(``key_policy_applied``). Building and sealing legs is a producer's job and is
not here.

Requires ``agent-action-capsule[envelope]`` (Producer Envelopes and the
Ed25519 check of re-signed wrapped objects).
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from .verify import verify

__all__ = [
    "SETTLEMENT_MEMBER",
    "SETTLEMENT_VERSION",
    "LEGS",
    "ROLES",
    "STATUSES",
    "DELIVERY_DIRECTIONS",
    "PAYMENT_REF_TYPES",
    "WRAPPED_TYPES",
    "MEMBERS",
    "ISO20022_STATUS",
    "SettlementReport",
    "amount_ok",
    "normal_payment_ref",
    "structure_failures",
    "verify_settlements",
]

SETTLEMENT_MEMBER = "settlement"
#: The settlement member's ``version`` for draft-mih-agent-settlement-records-00.
SETTLEMENT_VERSION = "0"

LEGS = ("terms", "payer_observed", "payee_observed", "delivered")
ROLES = ("payer", "payee")
STATUSES = ("pending", "settled", "failed", "reversed")
#: ``delivery.direction`` and the role that seals it.
DELIVERY_DIRECTIONS = {"sent": "payee", "received": "payer"}

#: Initial payment reference types: qualifier members, and whether a receive
#: fee may apply. ``x402.transaction`` is "not applicable" for the x402
#: ``exact`` scheme only; see :func:`_receive_fee_not_applicable`.
PAYMENT_REF_TYPES: dict[str, dict[str, Any]] = {
    "x402.transaction": {"qualifiers": ("network",), "receive_fee": "not_applicable"},
    "ln.payment_hash": {"qualifiers": (), "receive_fee": "may_apply"},
    "bolt12.invoice_payment_hash": {"qualifiers": (), "receive_fee": "may_apply"},
    "ap2.transaction_id": {"qualifiers": (), "receive_fee": "may_apply"},
    "ap2.payment_id": {"qualifiers": (), "receive_fee": "may_apply"},
    "ap2.network_confirmation_id": {"qualifiers": (), "receive_fee": "may_apply"},
    "acp.order_id": {"qualifiers": (), "receive_fee": "may_apply"},
    "ucp.order_id": {"qualifiers": (), "receive_fee": "may_apply"},
    "mpp.reference": {"qualifiers": ("method",), "receive_fee": "may_apply"},
    "iso20022.uetr": {"qualifiers": (), "receive_fee": "may_apply"},
    "iso20022.end_to_end_id": {"qualifiers": ("debtor_agent",), "receive_fee": "may_apply"},
    "open_payments.incoming_payment": {"qualifiers": (), "receive_fee": "may_apply"},
}

#: Initial wrapped object types and their issuer under their own specification.
WRAPPED_TYPES = {
    "x402.offer": "payee",
    "x402.receipt": "payee",
    "x402.payment-payload": "payer",
    "x402.settle-response": "other",
    "ap2.checkout-mandate": "payer",
    "ap2.payment-mandate": "payer",
    "ap2.checkout-receipt": "other",
    "ap2.payment-receipt": "other",
    "bolt12.invoice": "payee",
    "bolt12.payer-proof": "payer",
    "mpp.payment-receipt": "payee",
    "iso20022.message": "other",
    "delivery.proof": "other",
}

#: Required and optional ``settlement`` members per leg. Anything else is
#: ``settlement_malformed``.
MEMBERS: dict[str, dict[str, tuple[str, ...]]] = {
    "terms": {"required": ("version", "leg", "sealer_role", "amount"),
              "optional": ("payment_ref", "deliverable", "valid_until", "wrapped")},
    "payer_observed": {"required": ("version", "leg", "sealer_role", "terms_ref", "amount", "payment_ref",
                                    "status", "observed_at"),
                       "optional": ("routing_fee", "wrapped")},
    "payee_observed": {"required": ("version", "leg", "sealer_role", "terms_ref", "received", "payment_ref",
                                    "status", "observed_at"),
                       "optional": ("receive_fee", "wrapped")},
    "delivered": {"required": ("version", "leg", "sealer_role", "terms_ref", "observed_at", "delivery"),
                  "optional": ("wrapped",)},
}

#: The ISO 20022 code a reviewer reads for each observed status (pacs.002
#: ``TxSts``; a reversal is a pacs.004 return).
ISO20022_STATUS = {
    ("payer_observed", "pending"): "PDNG",
    ("payer_observed", "settled"): "ACSC",
    ("payer_observed", "failed"): "RJCT",
    ("payer_observed", "reversed"): "pacs.004",
    ("payee_observed", "pending"): "PDNG",
    ("payee_observed", "settled"): "ACCC",
    ("payee_observed", "failed"): "RJCT",
    ("payee_observed", "reversed"): "pacs.004",
}

_AMOUNT_MEMBERS = ("amount", "routing_fee", "received", "receive_fee")
_DELIVERY_MEMBERS = ("direction", "content_digest", "carrier", "tracking_digest", "status", "shipped_at",
                     "delivered_at", "address_digest")
_VALUE = re.compile(r"0|[1-9][0-9]*")
_HEX64 = re.compile(r"[0-9a-f]{64}")
# Patterns are matched against the whole string (fullmatch), ASCII digits only.
_B64URL = re.compile(r"[A-Za-z0-9_-]*")
_RFC3339_UTC = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z")



def amount_ok(a: Any) -> bool:
    return (isinstance(a, dict) and set(a) == {"value", "assetCode", "assetScale"}
            and isinstance(a["value"], str) and _VALUE.fullmatch(a["value"]) is not None
            and isinstance(a["assetCode"], str) and a["assetCode"] != ""
            and isinstance(a["assetScale"], int) and not isinstance(a["assetScale"], bool)
            and 0 <= a["assetScale"] <= 255)



def _b64u_decode(text: str) -> bytes:
    """Unpadded canonical base64url; anything else raises ``ValueError``."""
    if not isinstance(text, str) or not _B64URL.fullmatch(text):
        raise ValueError("not unpadded base64url")
    raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != text:
        raise ValueError("non-canonical base64url")
    return raw



def normal_payment_ref(ref: dict) -> dict:
    out = dict(ref)
    if ref.get("type") == "x402.transaction" and str(ref.get("network", "")).startswith("eip155:"):
        out["value"] = str(ref.get("value", "")).lower()
    return out


def structure_failures(member: Any) -> list[str]:
    """The draft's structural failure codes for one ``settlement`` member (empty if none)."""
    s = member
    if (not isinstance(s, dict) or s.get("version") != SETTLEMENT_VERSION or s.get("leg") not in LEGS
            or s.get("sealer_role") not in ROLES):
        return ["settlement_malformed"]
    out: list[str] = []
    leg, role = s["leg"], s["sealer_role"]
    allowed = MEMBERS[leg]
    if not set(allowed["required"]) <= set(s) or not set(s) <= set(allowed["required"]) | set(allowed["optional"]):
        out.append("settlement_malformed")
    if (leg == "payer_observed" and role != "payer") or (leg == "payee_observed" and role != "payee"):
        out.append("leg_role_mismatch")
    if any(m in s and not amount_ok(s[m]) for m in _AMOUNT_MEMBERS):
        out.append("amount_not_exact")
    if leg.endswith("_observed") and s.get("status") not in STATUSES:
        out.append("settlement_malformed")
    if "terms_ref" in s and not (isinstance(s["terms_ref"], str) and _HEX64.fullmatch(s["terms_ref"])):
        out.append("settlement_malformed")
    if "observed_at" in s and not (isinstance(s["observed_at"], str) and _RFC3339_UTC.fullmatch(s["observed_at"])):
        out.append("settlement_malformed")
    if leg == "delivered":
        d = s.get("delivery")
        if (not isinstance(d, dict) or not isinstance(d.get("direction"), str)
                or DELIVERY_DIRECTIONS.get(d["direction"]) != role
                or not set(d) <= set(_DELIVERY_MEMBERS)
                or ("content_digest" not in d and "carrier" not in d)
                or ("content_digest" in d and not (isinstance(d["content_digest"], str)
                                                   and _HEX64.fullmatch(d["content_digest"])))):
            out.append("settlement_malformed")
    if leg == "terms" and "deliverable" in s:
        dv = s["deliverable"]
        if (not isinstance(dv, dict) or not dv or not set(dv) <= {"content_digest", "description_digest"}
                or not all(isinstance(v, str) and _HEX64.fullmatch(v) for v in dv.values())):
            out.append("settlement_malformed")
    if "payment_ref" in s:
        ref = s["payment_ref"]
        if not isinstance(ref, dict) or not isinstance(ref.get("type"), str) or not isinstance(ref.get("value"), str):
            out.append("settlement_malformed")
        elif ref["type"] in PAYMENT_REF_TYPES and (
                set(ref) != {"type", "value", *PAYMENT_REF_TYPES[ref["type"]]["qualifiers"]}
                or not all(isinstance(ref[q], str) for q in PAYMENT_REF_TYPES[ref["type"]]["qualifiers"])):
            out.append("settlement_malformed")
    for w in s.get("wrapped", []) if isinstance(s.get("wrapped", []), list) else [None]:
        if (not isinstance(w, dict) or w.get("digest_alg") != "SHA-256"
                or not isinstance(w.get("type"), str) or w["type"] not in WRAPPED_TYPES
                or not isinstance(w.get("digest"), str) or not _HEX64.fullmatch(w["digest"])
                or ("content" in w and not isinstance(w["content"], str))
                or not set(w) <= {"type", "digest_alg", "digest", "content"}):
            out.append("settlement_malformed")
            break
    return sorted(set(out), key=out.index)



@dataclass
class SettlementReport:
    """What :func:`verify_settlements` derived, in the draft's terms.

    ``failures`` and ``findings`` are ``{"records": [capsule_id, ...], "code"}``.
    ``settlements`` has one entry per terms leg: ``terms`` (its capsule_id),
    ``payment_state``, ``delivery_state``, and where they apply
    ``agreed_status``, ``terms_amount`` (``equal`` / ``differs``), ``differs``
    (``amount`` / ``status`` / ``payment_ref``) and ``iso20022``.

    The key result is separate from the payment state, as the draft asks:
    ``key_policy_applied`` says whether a key policy bound each leg's key to
    its party (``False``: ``agreed`` means two distinct keys agree, not that
    the keys belong to the payer and the payee), and ``keys`` maps each
    authenticated record (``"<capsule_id>:<key>"``) to its key.
    ``diagnostics`` carries what the draft does not make a state:
    ``several_keys_for_role`` and ``delivery_sealed_under_one_key``.
    """

    conforming: bool
    failures: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    settlements: list[dict] = field(default_factory=list)
    keys: dict[str, str] = field(default_factory=dict)
    key_policy_applied: bool = False
    diagnostics: list[dict] = field(default_factory=list)


def _envelope_key(capsule: dict) -> str | None:
    """The authenticated key of the capsule's Producer Envelope, or None."""
    from .producer_envelope import verify_producer_envelope

    sig = capsule.get("signature")
    # Hex digit pairs only: bytes.fromhex would also take whitespace.
    if not isinstance(sig, str) or not re.fullmatch(r"(?:[0-9a-fA-F]{2})+", sig):
        return None
    try:
        env = verify_producer_envelope(capsule["capsule_id"], bytes.fromhex(sig))
    except Exception:  # a malformed envelope is a failure, not a crash
        return None
    return env.public_key.hex() if env.ok else None


def _jws_verifies(octets: bytes, public_hex: str) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    parts = octets.rstrip(b"~").split(b".")
    if len(parts) != 3:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(
            _b64u_decode(parts[2].decode("ascii")), parts[0] + b"." + parts[1])
        return True
    except (InvalidSignature, ValueError, UnicodeDecodeError):
        return False


def _wrapped_failures(s: dict, kid: str | None, objects: dict[str, bytes]) -> list[str]:
    out: list[str] = []
    for w in s.get("wrapped", []):
        octets = objects.get(w["digest"])
        if "content" in w:
            try:
                content = _b64u_decode(w["content"])
            except (ValueError, TypeError):
                # Content that does not decode matches no digest, the empty one included.
                out.append("wrapped_digest_mismatch")
                continue
            if hashlib.sha256(content).hexdigest() != w["digest"]:
                out.append("wrapped_digest_mismatch")
                continue
            octets = content
        if (octets is not None and kid is not None and WRAPPED_TYPES[w["type"]] != s["sealer_role"]
                and _jws_verifies(octets, kid)):
            out.append("wrapped_resigned")
    return out


def _x402_scheme(legs: list[dict], objects: dict[str, bytes]) -> str | None:
    """The x402 scheme, from a wrapped offer or payment payload whose octets are held."""
    for s in legs:
        for w in s.get("wrapped", []):
            try:
                octets = _b64u_decode(w["content"]) if "content" in w else objects.get(w["digest"])
            except ValueError:
                continue
            if octets is None or hashlib.sha256(octets).hexdigest() != w["digest"]:
                continue
            try:
                if w["type"] == "x402.offer":
                    if octets.count(b".") == 2 and not octets.lstrip().startswith(b"{"):  # JWS compact
                        return json.loads(_b64u_decode(octets.split(b".")[1].decode("ascii"))).get("scheme")
                    payload = json.loads(octets).get("payload", {})  # EIP-712 envelope, RFC 8785 octets
                    return payload.get("scheme") if isinstance(payload, dict) else None
                if w["type"] == "x402.payment-payload":
                    accepted = json.loads(octets).get("accepted", {})
                    return accepted.get("scheme") if isinstance(accepted, dict) else None
            except (ValueError, AttributeError, UnicodeDecodeError):
                continue
    return None


def _receive_fee_not_applicable(ref_type: str, terms: dict, payer: dict, objects: dict[str, bytes]) -> bool:
    if PAYMENT_REF_TYPES.get(ref_type, {}).get("receive_fee") != "not_applicable":
        return False
    return ref_type != "x402.transaction" or _x402_scheme([terms, payer], objects) == "exact"


def _scaled(a: dict, scale: int) -> int:
    return int(a["value"]) * 10 ** (scale - a["assetScale"])


def _amounts_equal(a: dict, b: dict) -> bool:
    if a["assetCode"] != b["assetCode"]:
        return False
    scale = max(a["assetScale"], b["assetScale"])
    return _scaled(a, scale) == _scaled(b, scale)


def _amount_rule_holds(payer: dict, payee: dict, receive_fee: dict) -> bool:
    """payer.amount == payee.received + payee.receive_fee, exactly, one asset. Never direct equality."""
    if not payer["amount"]["assetCode"] == payee["received"]["assetCode"] == receive_fee["assetCode"]:
        return False
    scale = max(payer["amount"]["assetScale"], payee["received"]["assetScale"], receive_fee["assetScale"])
    return _scaled(payer["amount"], scale) == _scaled(payee["received"], scale) + _scaled(receive_fee, scale)


def verify_settlements(
    capsules: Iterable[Any],
    *,
    key_policy: dict[str, str | Iterable[str]] | None = None,
    wrapped_objects: dict[str, bytes] | Iterable[bytes] | None = None,
) -> SettlementReport:
    """Derive settlement states from both parties' leg records, offline.

    Each record is checked on its own: the Capsule checks, its Producer
    Envelope (the authenticated key), the ``settlement`` structure and
    amounts, its wrapped entries, and, with *key_policy* (``{"payer": key or
    keys, "payee": ...}``), that its key is accepted for its role. A record
    that fails is reported and takes no part in any state. Records are
    grouped by ``terms_ref``.

    A record is identified by its ``capsule_id`` AND its authenticated key:
    the same content signed by another key is a different record (anyone can
    sign a copy of a genuine leg), and it never stands in for, or excludes,
    the original.

    *wrapped_objects* supplies the octets of wrapped objects the caller holds
    (by digest, or as a list of octets); they are used for the re-signing
    check and to read the x402 scheme. Receive fees are read as zero only for
    x402 ``exact``, established from such octets; otherwise an absent
    ``receive_fee`` leaves the pair ``unjoined`` (``fee_unstated``).
    """
    if wrapped_objects is None:
        objects: dict[str, bytes] = {}
    elif isinstance(wrapped_objects, dict):
        objects = dict(wrapped_objects)
    else:
        objects = {hashlib.sha256(o).hexdigest(): bytes(o) for o in wrapped_objects}
    policy = None
    if key_policy is not None:
        policy = {role: {keys} if isinstance(keys, str) else set(keys) for role, keys in key_policy.items()}

    report = SettlementReport(conforming=True, key_policy_applied=policy is not None)
    legs: dict[str, dict] = {}  # record id ("<capsule_id>:<key>") -> settlement member
    records: dict[str, dict] = {}  # record id -> capsule
    cid_of: dict[str, Any] = {}
    excluded: set[str] = set()
    for n, item in enumerate(capsules):
        capsule = item
        if not isinstance(capsule, dict):
            report.failures.append({"records": [None], "code": "capsule_invalid"})
            continue
        cid = capsule.get("capsule_id") if isinstance(capsule.get("capsule_id"), str) else None
        own: list[str] = []
        kid = None
        try:
            ok = isinstance(cid, str) and verify(capsule).ok
        except Exception:
            ok = False
        if not ok:
            own.append("capsule_invalid")
        else:
            kid = _envelope_key(capsule)
            if kid is None:
                own.append("envelope_invalid")
        rid = f"{cid}:{kid}" if kid is not None else f"{cid}:#{n}"
        if kid is not None and rid in records:
            continue  # the same capsule under the same key, passed again
        s = capsule.get(SETTLEMENT_MEMBER)
        structural = structure_failures(s)
        own += structural
        if not structural:
            own += _wrapped_failures(s, kid, objects)
            if policy is not None and kid is not None and kid not in policy.get(s["sealer_role"], set()):
                own.append("sealer_not_authorized_for_role")
            ref = s.get("payment_ref")
            if isinstance(ref, dict) and ref["type"] not in PAYMENT_REF_TYPES:
                report.findings.append({"records": [cid], "code": "payment_ref_type_unknown"})
        if kid is None and any(f["records"] == [cid] and f["code"] in own for f in report.failures):
            continue  # the same unauthenticated record again: report it once
        for code in own:
            report.failures.append({"records": [cid], "code": code})
        if own:
            excluded.add(rid)
        legs[rid] = s if isinstance(s, dict) else {}
        records[rid] = capsule
        cid_of[rid] = cid
        if kid is not None:
            report.keys[rid] = kid

    # Distinct keys: a payer-observed and a payee-observed leg for one terms leg
    # under the same key are not two sides. Needs no key policy.
    observed = [(r, s) for r, s in legs.items() if r in report.keys and str(s.get("leg", "")).endswith("_observed")]
    for p, ps in observed:
        for q, qs in observed:
            if (ps["leg"] == "payer_observed" and qs["leg"] == "payee_observed"
                    and report.keys[p] == report.keys[q] and ps.get("terms_ref") == qs.get("terms_ref")):
                report.failures.append({"records": [cid_of[p], cid_of[q]], "code": "sealer_conflation"})

    live = {r: s for r, s in legs.items() if r not in excluded}
    terms_by_cid: dict[str, str] = {}
    for r, s in live.items():
        if s["leg"] == "terms":
            terms_by_cid.setdefault(cid_of[r], r)  # a re-signed copy of a terms leg is the same terms
    for r, s in live.items():
        if s["leg"] != "terms" and s["terms_ref"] not in terms_by_cid:
            report.failures.append({"records": [cid_of[r]], "code": "terms_ref_unresolved"})
    for terms_cid, terms_rid in terms_by_cid.items():
        answering = {r: s for r, s in live.items() if s.get("terms_ref") == terms_cid}
        report.settlements.append(_settlement(terms_cid, live[terms_rid], answering, records, report,
                                              policy is not None, objects))
    report.conforming = not report.failures
    return report


def _heads(side: list[tuple[str, dict]], records: dict[str, dict], report: SettlementReport,
           terms_cid: str) -> list[tuple[str, dict]]:
    """Drop observed legs that a later leg of the same side supersedes.

    A ``supersedes`` link counts only when the superseding record is signed by
    the superseded record's own key: a sealer can replace its own observation,
    never someone else's. Any other link is ignored and reported.
    """
    superseded: set[str] = set()
    for r, _ in side:
        chain = records[r].get("chain") or {}
        if chain.get("relation") != "supersedes":
            continue
        parent = chain.get("parent_capsule_id")
        key = report.keys.get(r)
        targets = [t for t, _ in side if records[t]["capsule_id"] == parent and t != r]
        own = [t for t in targets if key is not None and report.keys.get(t) == key]
        superseded.update(own)
        if targets and not own:
            report.diagnostics.append({"terms": terms_cid, "code": "supersedes_ignored",
                                       "record": records[r]["capsule_id"], "key": key, "parent": parent})
    return [(r, s) for r, s in side if r not in superseded]


def _settlement(terms_cid: str, terms: dict, legs: dict[str, dict], records: dict[str, dict],
                report: SettlementReport, with_policy: bool, objects: dict[str, bytes]) -> dict:
    payer = _heads([(r, s) for r, s in legs.items() if s["leg"] == "payer_observed"], records, report, terms_cid)
    payee = _heads([(r, s) for r, s in legs.items() if s["leg"] == "payee_observed"], records, report, terms_cid)
    result: dict[str, Any] = {"terms": terms_cid}
    for role, side in (("payer", payer), ("payee", payee)):
        keys = sorted({report.keys[r] for r, _ in side if r in report.keys})
        if len(keys) > 1:
            report.diagnostics.append({"terms": terms_cid, "code": "several_keys_for_role", "role": role,
                                       "keys": keys, "key_policy_applied": with_policy})
    if not payer and not payee:
        result["payment_state"] = "terms_only"
    elif not payee:
        result["payment_state"] = "payer_stated"
    elif not payer:
        result["payment_state"] = "payee_stated"
    else:
        result.update(_pair(terms_cid, terms, payer, payee, report, objects))
    iso = {}
    for leg, side in (("payer_observed", payer), ("payee_observed", payee)):
        statuses = {s["status"] for _, s in side}
        if len(statuses) == 1:
            iso[leg] = ISO20022_STATUS[(leg, statuses.pop())]
    if iso:
        result["iso20022"] = iso

    pinned = terms.get("deliverable", {}).get("content_digest")
    delivered = [(r, s["delivery"]) for r, s in legs.items() if s["leg"] == "delivered"]
    values = {d["content_digest"] for _, d in delivered if "content_digest" in d}
    directions = {d["direction"] for _, d in delivered if "content_digest" in d}
    if not delivered:
        result["delivery_state"] = "none"
    elif (pinned is not None and any(v != pinned for v in values)) or len(values) > 1:
        result["delivery_state"] = "mismatch"
    elif directions == {"sent", "received"}:
        result["delivery_state"] = "matched"
        sent = {report.keys.get(r) for r, d in delivered if d["direction"] == "sent"}
        received = {report.keys.get(r) for r, d in delivered if d["direction"] == "received"}
        if sent & received:
            report.diagnostics.append({"terms": terms_cid, "code": "delivery_sealed_under_one_key",
                                       "keys": sorted(k for k in sent & received if k)})
    else:
        result["delivery_state"] = "stated"
    return result


def _pair(terms_cid: str, terms: dict, payer: list[tuple[str, dict]], payee: list[tuple[str, dict]], report: SettlementReport,
          objects: dict[str, bytes]) -> dict:
    out: dict[str, Any] = {}
    # The pair the state is derived from: the first payer head and payee head,
    # in input order, under distinct keys. If every combination shares a key,
    # the pair is conflated. The join and fee checks below read only this pair
    # and return unjoined before the heads of one side are compared, so unjoined
    # takes precedence over a mismatch between heads (as capsule-emit did).
    pairs = [(p, q) for p in payer for q in payee if report.keys.get(p[0]) != report.keys.get(q[0])]
    conflated = not pairs
    (_, a), (b_rid, b) = pairs[0] if pairs else (payer[0], payee[0])
    b_id = _cid(b_rid)
    ref_type = b["payment_ref"]["type"]
    receive_fee = b.get("receive_fee")
    if receive_fee is None and _receive_fee_not_applicable(ref_type, terms, a, objects):
        receive_fee = {"value": "0", "assetCode": b["received"]["assetCode"],
                       "assetScale": b["received"]["assetScale"]}
    if (a["payment_ref"]["type"] not in PAYMENT_REF_TYPES or ref_type not in PAYMENT_REF_TYPES
            or a["payment_ref"]["type"] != ref_type):
        out["payment_state"] = "unjoined"
        return out
    if receive_fee is None:
        report.findings.append({"records": [b_id], "code": "fee_unstated"})
        out["payment_state"] = "unjoined"
        return out
    if receive_fee["assetCode"] != b["received"]["assetCode"] or (
            "routing_fee" in a and a["routing_fee"]["assetCode"] != a["amount"]["assetCode"]):
        report.findings.append({"records": [b_id], "code": "fee_asset_differs"})
        out["payment_state"] = "unjoined"
        return out
    differs: list[str] = []
    if not _amount_rule_holds(a, b, receive_fee):
        differs.append("amount")
    if a["status"] != b["status"]:
        differs.append("status")
    if normal_payment_ref(a["payment_ref"]) != normal_payment_ref(b["payment_ref"]):
        differs.append("payment_ref")
    # More than one head on a side (no supersedes chain between them): each must
    # say the same thing.
    for side in (payer, payee):
        first = side[0][1]
        for _, other in side[1:]:
            for name in ("amount", "routing_fee", "received", "receive_fee"):
                x, y = first.get(name), other.get(name)
                # The same amount at another scale is the same amount (section 6).
                if (x is None) != (y is None) or (x is not None and not _amounts_equal(x, y)):
                    differs.append("amount")
            if first["status"] != other["status"]:
                differs.append("status")
            if normal_payment_ref(other["payment_ref"]) != normal_payment_ref(first["payment_ref"]):
                differs.append("payment_ref")
    differs = sorted(set(differs), key=differs.index)
    if differs:
        out["payment_state"] = "mismatch"
        out["differs"] = differs
    elif conflated:
        # The draft: a verifier MUST NOT report agreed for such a pair; it
        # reports sealer_conflation instead. sealer_conflation is a failure code,
        # not a state, and no row of the draft's state table fits a conflated
        # pair that otherwise matches, so no state is reported (an open question
        # for the draft); the failure is listed and a diagnostic says why.
        out["payment_state"] = None
        report.diagnostics.append({"terms": terms_cid, "code": "sealer_conflation",
                                   "note": "agreed withheld; no state of the draft applies"})
    else:
        out["payment_state"] = "agreed"
        out["agreed_status"] = a["status"]
        out["terms_amount"] = "equal" if _amounts_equal(a["amount"], terms["amount"]) else "differs"
    return out


def _cid(rid: str) -> str:
    """The capsule_id part of a record id."""
    return rid.rsplit(":", 1)[0]
