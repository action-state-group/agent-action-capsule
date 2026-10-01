#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate the draft-mih-agent-settlement-profile-00 conformance vectors.

Every expected result below is written by hand from the text of
``spec/draft-mih-agent-settlement-profile-00.md`` and cites the section it
comes from. Nothing here imports or runs an implementation of the profile: the
script builds leg records (format-4 Agent Action Capsules with a
``settlement`` member), computes each Capsule ID as SHA-256 over RFC 8785,
signs each one with a Producer Envelope (COSE_Sign1, Ed25519) from a fixed
seed, and builds the illustrative upstream objects that the legs wrap.

The upstream objects (x402 offer, payment payload and settlement response, AP2
mandate and receipt, BOLT 12 invoice and payer proof) are ILLUSTRATIVE: they
have the field names of their specifications but are not conformance vectors
for those specifications. A JWS here uses EdDSA so that every signature is
deterministic.

Output: ``vectors/settlement/`` (or ``--out DIR``). The run is a pure function
of this file: no clock, no randomness. ``README.md`` is hand-written; when
present in the output directory it is included in ``SHA256SUMS`` but never
rewritten.

Dependencies: the standard library and ``cryptography`` (Ed25519 only).
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "vectors" / "settlement"
DRAFT = "draft-mih-agent-settlement-profile-00"
AAC_SPEC_VERSION = "draft-mih-scitt-agent-action-capsule-05"
CAPSULE_ID_MEDIA_TYPE = "application/agent-action-capsule-id"

# ---------------------------------------------------------------------------
# Encodings
# ---------------------------------------------------------------------------


def _check_json_value(value: Any) -> None:
    if isinstance(value, float):
        raise TypeError("floats are not canonicalizable here (RFC 8785 subset without numbers with fractions)")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or not key.isascii():
                raise TypeError("map keys in these vectors are ASCII text")
            _check_json_value(item)
    elif isinstance(value, list):
        for item in value:
            _check_json_value(item)


def jcs(value: Any) -> bytes:
    """RFC 8785 for the value space these vectors use (no floats, ASCII keys).

    With ASCII keys, UTF-16 code-unit order equals code-point order, so
    ``sort_keys`` is the RFC 8785 member order; the separators and string
    escaping of ``json.dumps(ensure_ascii=False)`` match RFC 8785 for these
    values.
    """
    _check_json_value(value)
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def label_hex(label: str, nbytes: int = 32) -> str:
    """A fixed, reproducible hex string used as an example identifier."""
    return hashlib.sha256(f"{DRAFT} example: {label}".encode()).hexdigest()[: 2 * nbytes]


def _cbor_head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 0x100:
        return bytes([(major << 5) | 24]) + n.to_bytes(1, "big")
    if n < 0x10000:
        return bytes([(major << 5) | 25]) + n.to_bytes(2, "big")
    return bytes([(major << 5) | 26]) + n.to_bytes(4, "big")


def cbor(value: Any) -> bytes:
    """RFC 8949 section 4.2.1 deterministic CBOR for the values an envelope uses."""
    if isinstance(value, bool) or value is None:
        raise TypeError("not used in an envelope")
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
        self.seed = hashlib.sha256(f"{DRAFT} conformance vectors: {name} key".encode()).digest()
        self.private = Ed25519PrivateKey.from_private_bytes(self.seed)
        self.public = self.private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    @property
    def public_hex(self) -> str:
        return self.public.hex()


PAYER = Key("payer")
PAYEE = Key("payee")
PAYEE_OFFER = Key("payee x402 offer signing")
PAYER_MANDATE = Key("payer AP2 mandate signing")
PROCESSOR = Key("AP2 payment processor")
KEYS = [PAYER, PAYEE, PAYEE_OFFER, PAYER_MANDATE, PROCESSOR]
KEY_POLICY = {"payer": PAYER.public_hex, "payee": PAYEE.public_hex}


def producer_envelope(capsule_id: str, key: Key) -> bytes:
    """A bare Producer Envelope: tagged COSE_Sign1 over the raw 32-byte Capsule ID."""
    protected = cbor({1: -8, 3: CAPSULE_ID_MEDIA_TYPE, 4: key.public})
    payload = bytes.fromhex(capsule_id)
    sig_structure = cbor(["Signature1", protected, b"", payload])
    signature = key.private.sign(sig_structure)
    return b"\xd2" + cbor([protected, {}, payload, signature])


def jws(header: dict, payload: dict, key: Key) -> bytes:
    """A JWS compact serialization (EdDSA), returned as its ASCII octets."""
    signing_input = b64u(jcs(header)) + "." + b64u(jcs(payload))
    return (signing_input + "." + b64u(key.private.sign(signing_input.encode("ascii")))).encode("ascii")


# ---------------------------------------------------------------------------
# Illustrative upstream objects
# ---------------------------------------------------------------------------

NETWORK = "eip155:8453"
USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
USDC_ASSET = f"{NETWORK}/erc20:{USDC}"
OTHER_TOKEN = "0x" + label_hex("another token contract", 20)
OTHER_ASSET = f"{NETWORK}/erc20:{OTHER_TOKEN}"
PAY_TO = "0x" + label_hex("payee address", 20)
PAYER_ADDRESS = "0x" + label_hex("payer address", 20)
RESOURCE = "https://payee.example/v1/inference"


def x402_offer(amount: str = "1500000") -> bytes:
    return jws(
        {"alg": "EdDSA", "kid": "did:web:payee.example#offer-key"},
        {"version": 1, "resourceUrl": RESOURCE, "scheme": "exact", "network": NETWORK,
         "asset": USDC, "payTo": PAY_TO, "amount": amount, "validUntil": 1790000000},
        PAYEE_OFFER,
    )


def x402_payment_payload(amount: str = "1500000") -> bytes:
    return jcs({
        "x402Version": 2,
        "accepted": {"scheme": "exact", "network": NETWORK, "amount": amount, "asset": USDC,
                     "payTo": PAY_TO, "maxTimeoutSeconds": 60},
        "payload": {"signature": "0x" + label_hex("eip-3009 authorization signature") * 2 + "1b",
                    "authorization": {"from": PAYER_ADDRESS, "to": PAY_TO, "value": amount,
                                      "validAfter": "0", "validBefore": "1790000000",
                                      "nonce": "0x" + label_hex("eip-3009 nonce")}},
    })


def x402_settle_response(tx: str, amount: str = "1500000") -> bytes:
    return jcs({"success": True, "transaction": tx, "network": NETWORK, "payer": PAYER_ADDRESS,
                "amount": amount})


def ap2_payment_mandate() -> bytes:
    token = jws({"alg": "EdDSA", "typ": "dc+sd-jwt"},
                {"vct": "mandate.payment.1", "transaction_id": "txn_" + label_hex("ap2 transaction", 8),
                 "payee": "merchant.example", "amount": {"value": "4200", "currency": "USD"}},
                PAYER_MANDATE)
    return token + b"~"


def ap2_payment_receipt(signer: Key) -> bytes:
    return jws({"alg": "EdDSA", "typ": "JWT"},
               {"status": "Success", "iss": "https://processor.example", "iat": 1790000100,
                "reference": sha256_hex(ap2_payment_mandate()),
                "payment_id": "pay_" + label_hex("ap2 payment id", 8),
                "psp_confirmation_id": "psp_" + label_hex("ap2 psp confirmation", 8),
                "network_confirmation_id": "net_" + label_hex("ap2 network confirmation", 8)},
               signer)


def illustrative_tlv(label: str) -> bytes:
    """Fixed octets standing in for a BOLT 12 TLV stream (not a valid BOLT 12 object)."""
    return bytes.fromhex(label_hex(label) + label_hex(label + " continued"))


TX = "0x" + label_hex("x402 settlement transaction")
INVOICE_PAYMENT_HASH = label_hex("bolt12 invoice payment hash")
COMPLETION = jcs({"id": "cmpl-0001", "object": "completion", "output": "The answer is 42."})
OTHER_COMPLETION = jcs({"id": "cmpl-0001", "object": "completion", "output": "The answer is 41."})


def wrapped(typ: str, octets: bytes, *, include_content: bool, content_override: bytes | None = None) -> dict:
    entry = {"type": typ, "digest_alg": "SHA-256", "digest": sha256_hex(octets)}
    if include_content:
        entry["content"] = b64u(content_override if content_override is not None else octets)
    return entry


# ---------------------------------------------------------------------------
# Leg records
# ---------------------------------------------------------------------------

USDC_1_5 = {"value": "1500000", "assetCode": USDC_ASSET, "assetScale": 6}


def t(minute: int, second: int = 0) -> str:
    return f"2026-10-01T12:{minute:02d}:{second:02d}Z"


def capsule(action_id: str, operator: str, timestamp: str, settlement: dict, *,
            parent: dict | None = None, references: list[dict] | None = None) -> dict:
    c: dict[str, Any] = {
        "spec_version": AAC_SPEC_VERSION,
        "format_version": "4",
        "canonicalization_id": "jcs",
        "action_id": action_id,
        "action_type": "fyi",
        "operator": operator,
        "developer": "settlement-example-agent@1",
        "timestamp": timestamp,
        "assurance": {"attestation_mode": "self_attested", "effect_mode": "not_applicable",
                      "ledger_mode": "chained" if parent else "standalone"},
        "settlement": settlement,
    }
    if parent is not None:
        c["chain"] = {"parent_capsule_id": parent["capsule"]["capsule_id"], "relation": "follows"}
    if references:
        c["references"] = references
    return c


def seal(label: str, body: dict, key: Key | None) -> dict:
    """Compute the Capsule ID and, unless the body cannot be canonicalized, sign it."""
    body = copy.deepcopy(body)
    try:
        capsule_id: str | None = sha256_hex(jcs(body))
    except TypeError:
        capsule_id = None
    out: dict[str, Any] = {"label": label}
    if capsule_id is not None:
        body["capsule_id"] = capsule_id
    out["capsule"] = body
    out["capsule_id"] = capsule_id
    if capsule_id is not None and key is not None:
        out["envelope_hex"] = producer_envelope(capsule_id, key).hex()
        out["envelope_kid"] = key.public_hex
    return out


def cite(record: dict) -> dict:
    return {"type": "agent-action-capsule", "digest_alg": "SHA-256",
            "digest": record["capsule"]["capsule_id"], "citation_purpose": "counterparty_half"}


def terms_leg(label: str, role: str, key: Key, amount: dict, wraps: list[dict], **extra: Any) -> dict:
    s = {"version": "0", "leg": "terms", "sealer_role": role, "amount": amount}
    if wraps:
        s["wrapped"] = wraps
    s.update(extra)
    operator = "payee.example" if role == "payee" else "payer.example"
    return seal(label, capsule(f"{label}", operator, t(0), s), key)


def zero(amount: Any) -> dict:
    """A zero fee in the asset and scale of ``amount``."""
    return {"value": "0", "assetCode": amount["assetCode"], "assetScale": amount["assetScale"]}


ZERO = "zero"  # sentinel: an explicit zero fee in the amount's asset and scale


def observed_leg(label: str, role: str, key: Key, terms: dict, payment_ref: dict, amount: Any,
                 wraps: list[dict], *, fee: Any = ZERO, status: str = "settled", minute: int = 1,
                 references: list[dict] | None = None) -> dict:
    """A payer leg carries amount + routing_fee; a payee leg carries received + receive_fee.

    ``fee`` is an amount object, ``ZERO`` for an explicit zero, or None to omit the fee member.
    """
    gross, fee_name = ("amount", "routing_fee") if role == "payer" else ("received", "receive_fee")
    s = {"version": "0", "leg": f"{role}_observed", "sealer_role": role,
         "terms_ref": terms["capsule"]["capsule_id"], "payment_ref": payment_ref, gross: amount,
         "status": status, "observed_at": t(minute, 5)}
    if fee is not None:
        s[fee_name] = zero(amount) if fee == ZERO else fee
    if wraps:
        s["wrapped"] = wraps
    operator = "payee.example" if role == "payee" else "payer.example"
    return seal(label, capsule(label, operator, t(minute, 6), s, references=references), key)


def delivered_leg(label: str, role: str, key: Key, terms: dict, content: bytes, *,
                  parent: dict | None = None, minute: int = 3) -> dict:
    s = {"version": "0", "leg": "delivered", "sealer_role": role,
         "terms_ref": terms["capsule"]["capsule_id"], "observed_at": t(minute, 5),
         "delivery": {"direction": "sent" if role == "payee" else "received",
                      "content_digest": sha256_hex(content)}}
    operator = "payee.example" if role == "payee" else "payer.example"
    return seal(label, capsule(label, operator, t(minute, 6), s, parent=parent), key)


def x402_ref(tx: str = TX) -> dict:
    return {"type": "x402.transaction", "value": tx, "network": NETWORK}


def wobj(typ: str, octets: bytes, note: str) -> dict:
    return {"type": typ, "digest": sha256_hex(octets), "octets_b64u": b64u(octets), "note": note}


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------

S_SEALERS = "§3 Two Independent Sealers"
S_MEMBER = "§4.2 The settlement Member"
S_CITE = "§4.3 Citations Between Legs"
S_TERMS = "§5.1 Terms"
S_DELIVERED = "§5.4 Delivered"
S_AMOUNTS = "§6 Amounts"
S_FEES = "§6.1 Fees"
S_JOIN = "§7.1 Shape and Join Rule"
S_TYPES = "§7.2 Initial Types"
S_WRAP = "§8 Wrapping Existing Signed Objects"
S_INPUTS = "§9.1 Inputs"
S_PAYMENT = "§9.2 Payment State"
S_DELIVERY = "§9.3 Delivery State"
S_FAILURES = "§9.4 Failures"


def settlement(terms: str, payment_state: str, delivery_state: str, **extra: Any) -> dict:
    out: dict[str, Any] = {"terms": terms, "payment_state": payment_state}
    out.update(extra)
    out["delivery_state"] = delivery_state
    return out


def expect(*, conforming: bool, payment_state: str | None = None, delivery_state: str | None = None,
           failures: list[dict] | None = None, findings: list[dict] | None = None, terms: str = "x402-terms",
           settlements: list[dict] | None = None, **extra: Any) -> dict:
    if settlements is None:
        settlements = [settlement(terms, payment_state or "", delivery_state or "", **extra)]
    return {"conforming": conforming, "failures": failures or [], "findings": findings or [],
            "settlements": settlements}


def case(case_id: str, section: list[str], description: str, records: list[dict],
         wrapped_objects: list[dict], exp: dict) -> dict:
    return {"id": case_id, "section": section, "description": description, "key_policy": KEY_POLICY,
            "records": records, "wrapped_objects": wrapped_objects, "expect": exp}


def x402_base(amount_payer: Any = None, amount_payee: Any = None, payee_ref: dict | None = None,
              payer_ref: dict | None = None, payee_key: Key = PAYEE,
              payee_settle: bytes | None = None, settle_content: bool = False,
              settle_override: bytes | None = None) -> tuple:
    offer = x402_offer()
    payload = x402_payment_payload()
    settle = payee_settle if payee_settle is not None else x402_settle_response(TX)
    terms = terms_leg("x402-terms", "payee", PAYEE, USDC_1_5,
                      [wrapped("x402.offer", offer, include_content=False)],
                      deliverable={"description_digest": sha256_hex(jcs({"resource": RESOURCE,
                                                                         "description": "one completion"}))})
    payer = observed_leg("x402-payer-observed", "payer", PAYER, terms, payer_ref or x402_ref(),
                         amount_payer if amount_payer is not None else USDC_1_5,
                         [wrapped("x402.payment-payload", payload, include_content=False),
                          wrapped("x402.settle-response", x402_settle_response(TX), include_content=False)])
    payee = observed_leg("x402-payee-observed", "payee", payee_key, terms, payee_ref or x402_ref(),
                         amount_payee if amount_payee is not None else USDC_1_5,
                         [wrapped("x402.settle-response", settle, include_content=settle_content,
                                  content_override=settle_override)],
                         minute=2, references=[cite(payer)] if payer["capsule_id"] else None)
    objects = [wobj("x402.offer", offer, "illustrative x402 signed offer, JWS format (EdDSA)"),
               wobj("x402.payment-payload", payload, "illustrative decoded PAYMENT-SIGNATURE value"),
               wobj("x402.settle-response", settle, "illustrative decoded PAYMENT-RESPONSE value")]
    return terms, payer, payee, objects


def cases() -> list[dict]:
    out: list[dict] = []

    # 1. Two-sided x402, matching, with delivery on both sides.
    terms, payer, payee, objs = x402_base()
    sent = delivered_leg("x402-delivered-sent", "payee", PAYEE, terms, COMPLETION, parent=payee)
    received = delivered_leg("x402-delivered-received", "payer", PAYER, terms, COMPLETION, parent=payer, minute=4)
    out.append(case(
        "pos-x402-two-sided-agreed", [S_SEALERS, S_CITE, S_PAYMENT, S_DELIVERY],
        "x402 payment of 1.5 USDC on Base. The payee seals the terms (wrapping the signed offer by digest), "
        "the payer seals what its wallet observed, the payee seals what its facilitator reported and cites "
        "the payer's leg as counterparty_half, and each side seals its side of the delivery. Payment "
        "references, amounts and statuses agree; both content digests are equal.",
        [terms, payer, payee, sent, received], objs,
        expect(conforming=True, payment_state="agreed", agreed_status="settled", terms_amount="equal",
               delivery_state="matched")))

    # 2. One-sided: payee only.
    terms, payer, payee, objs = x402_base()
    out.append(case(
        "pos-x402-one-sided-payee", [S_PAYMENT],
        "Only the payee's observed leg is present. A stated claim by the payee, not an agreement.",
        [terms, payee], objs,
        expect(conforming=True, payment_state="payee_stated", delivery_state="none")))

    # 3. One-sided: payer only, with the payer's received delivery.
    terms, payer, payee, objs = x402_base()
    received = delivered_leg("x402-delivered-received", "payer", PAYER, terms, COMPLETION, parent=payer, minute=4)
    out.append(case(
        "pos-x402-one-sided-payer", [S_PAYMENT, S_DELIVERY],
        "Only the payer's legs are present: its payment observation and what it received. Both are stated "
        "claims.",
        [terms, payer, received], objs,
        expect(conforming=True, payment_state="payer_stated", delivery_state="stated")))

    # 4. Mismatch: the payee reports a different asset.
    other = {"value": "1500000", "assetCode": OTHER_ASSET, "assetScale": 6}
    terms, payer, payee, objs = x402_base(amount_payee=other)
    out.append(case(
        "state-x402-mismatch-asset", [S_AMOUNTS, S_PAYMENT],
        "Both sides are present and join on the transaction, but the payee's system reports a different "
        "asset. Amounts with different assetCode values are never equal.",
        [terms, payer, payee], objs,
        expect(conforming=True, payment_state="mismatch", differs=["amount"], delivery_state="none")))

    # 5. Equal amounts at different scales.
    rescaled = {"value": "150000000", "assetCode": USDC_ASSET, "assetScale": 8}
    terms, payer, payee, objs = x402_base(amount_payee=rescaled)
    out.append(case(
        "pos-x402-amount-equal-across-scales", [S_AMOUNTS, S_PAYMENT],
        "The payee's system reports the same amount at scale 8 (150000000 * 10^-8 = 1500000 * 10^-6). "
        "Equal in exact integer arithmetic at the common scale.",
        [terms, payer, payee], objs,
        expect(conforming=True, payment_state="agreed", agreed_status="settled", terms_amount="equal",
               delivery_state="none")))

    # 6. BOLT 12, two-sided, payer proof wrapped by digest.
    invoice = illustrative_tlv("bolt12 invoice")
    proof = illustrative_tlv("bolt12 payer proof")
    msat = {"value": "21000000", "assetCode": "BTC", "assetScale": 11}
    ref = {"type": "bolt12.invoice_payment_hash", "value": INVOICE_PAYMENT_HASH}
    bterms = terms_leg("bolt12-terms", "payee", PAYEE, msat, [wrapped("bolt12.invoice", invoice, include_content=False)],
                       payment_ref=ref)
    bpayer = observed_leg("bolt12-payer-observed", "payer", PAYER, bterms, ref, msat,
                          [wrapped("bolt12.payer-proof", proof, include_content=True)])
    bpayee = observed_leg("bolt12-payee-observed", "payee", PAYEE, bterms, ref, msat, [], minute=2)
    out.append(case(
        "pos-bolt12-two-sided-payer-proof", [S_TYPES, S_WRAP, S_PAYMENT],
        "A Lightning payment of 21000 sat (21000000 msat, assetScale 11). The terms fix the payment hash in "
        "advance; the payer wraps its BOLT 12 payer proof (octets and digest); the payee seals its own "
        "observation.",
        [bterms, bpayer, bpayee],
        [wobj("bolt12.invoice", invoice, "illustrative octets, not a valid BOLT 12 TLV stream"),
         wobj("bolt12.payer-proof", proof, "illustrative octets, not a valid BOLT 12 TLV stream")],
        expect(conforming=True, payment_state="agreed", agreed_status="settled", terms_amount="equal",
               delivery_state="none", terms="bolt12-terms")))

    # 7. AP2 receipt wrapped by digest only.
    mandate = ap2_payment_mandate()
    receipt = ap2_payment_receipt(PROCESSOR)
    usd = {"value": "4200", "assetCode": "USD", "assetScale": 2}
    pay_ref = {"type": "ap2.payment_id", "value": "pay_" + label_hex("ap2 payment id", 8)}
    aterms = terms_leg("ap2-terms", "payer", PAYER, usd,
                       [wrapped("ap2.payment-mandate", mandate, include_content=False)])
    apayee = observed_leg("ap2-payee-observed", "payee", PAYEE, aterms, pay_ref, usd,
                          [wrapped("ap2.payment-receipt", receipt, include_content=False)], minute=2)
    ap2_objects = [wobj("ap2.payment-mandate", mandate, "illustrative SD-JWT Payment Mandate (EdDSA, no disclosures)"),
                   wobj("ap2.payment-receipt", receipt, "illustrative Payment Receipt JWT signed by the processor key")]
    out.append(case(
        "pos-ap2-receipt-wrapped-by-digest", [S_TERMS, S_WRAP, S_PAYMENT],
        "AP2: the payer seals the terms, wrapping its Payment Mandate by digest. The payee's leg wraps the "
        "processor-signed Payment Receipt by digest only, without re-signing it, and joins on payment_id.",
        [aterms, apayee], ap2_objects,
        expect(conforming=True, payment_state="payee_stated", delivery_state="none", terms="ap2-terms")))

    # 8. Negative: the AP2 receipt re-signed by the payee's own leg key.
    resigned = ap2_payment_receipt(PAYEE)
    rpayee = observed_leg("ap2-payee-observed", "payee", PAYEE, aterms, pay_ref, usd,
                          [wrapped("ap2.payment-receipt", resigned, include_content=True)], minute=2)
    out.append(case(
        "neg-wrapped-object-resigned", [S_WRAP, S_FAILURES],
        "The payee replaced the processor's signature on the AP2 Payment Receipt with its own leg key. The "
        "receipt's issuer is the payment processor, so the leg fails and does not contribute.",
        [aterms, rpayee],
        [ap2_objects[0], wobj("ap2.payment-receipt", resigned, "the same receipt claims, signed by the payee leg key")],
        expect(conforming=False, payment_state="terms_only", delivery_state="none", terms="ap2-terms",
               failures=[{"records": ["ap2-payee-observed"], "code": "wrapped_resigned"}])))

    # 9. Negative: wrapped content does not hash to its digest.
    altered = x402_settle_response(TX, amount="1400000")
    terms, payer, payee, objs = x402_base(settle_content=True, settle_override=altered)
    out.append(case(
        "neg-wrapped-content-digest-mismatch", [S_WRAP, S_FAILURES],
        "The payee's wrapped settlement response carries content whose SHA-256 is not the stated digest. "
        "The payee leg fails; only the payer's leg remains.",
        [terms, payer, payee], objs,
        expect(conforming=False, payment_state="payer_stated", delivery_state="none",
               failures=[{"records": ["x402-payee-observed"], "code": "wrapped_digest_mismatch"}])))

    # 10. Negative: a JSON floating-point amount.
    float_amount = {"value": 1.5, "assetCode": USDC_ASSET, "assetScale": 0}
    terms, payer, payee, objs = x402_base(amount_payer=float_amount)
    out.append(case(
        "neg-amount-json-float", [S_AMOUNTS, S_FAILURES],
        "The payer's amount value is the JSON number 1.5. A float fails the base profile's digest rules, "
        "so the leg has no Capsule ID and no envelope, and it fails this profile's amount grammar.",
        [terms, payer, payee], objs,
        expect(conforming=False, payment_state="payee_stated", delivery_state="none",
               failures=[{"records": ["x402-payer-observed"], "code": "capsule_invalid"},
                         {"records": ["x402-payer-observed"], "code": "amount_not_exact"}])))

    # 11. Negative: a decimal-fraction string.
    fraction = {"value": "1.500000", "assetCode": USDC_ASSET, "assetScale": 6}
    terms, payer, payee, objs = x402_base(amount_payer=fraction)
    out.append(case(
        "neg-amount-decimal-fraction-string", [S_AMOUNTS, S_FAILURES],
        "The payer's amount value is the string \"1.500000\". It canonicalizes and seals, but it is not "
        "an integer string: amount_not_exact.",
        [terms, payer, payee], objs,
        expect(conforming=False, payment_state="payee_stated", delivery_state="none",
               failures=[{"records": ["x402-payer-observed"], "code": "amount_not_exact"}])))

    # 12. Unknown payment reference type: legs valid, pair not joined.
    unknown = {"type": "x-example.batch_ref", "value": "batch-0001/item-7"}
    terms, payer, payee, objs = x402_base(payer_ref=unknown, payee_ref=unknown)
    out.append(case(
        "neg-payment-ref-type-unknown", [S_JOIN, S_PAYMENT, S_FAILURES],
        "Both sides use an unregistered private payment reference type with identical values. The legs are "
        "not rejected (never-reject), but a verifier must not join on a type it does not recognize: unjoined.",
        [terms, payer, payee], objs,
        expect(conforming=True, payment_state="unjoined", delivery_state="none",
               findings=[{"records": ["x402-payer-observed"], "code": "payment_ref_type_unknown"},
                         {"records": ["x402-payee-observed"], "code": "payment_ref_type_unknown"}])))

    # 13. Negative: the payee leg sealed with the payer's key.
    terms, payer, payee, objs = x402_base(payee_key=PAYER)
    out.append(case(
        "neg-payee-leg-sealed-by-payer-key", [S_SEALERS, S_FAILURES],
        "The payee-observed leg's envelope is signed with the payer's key. The key policy rejects it for "
        "the payee role, and the pair is under one key (sealer_conflation, a failure of the pair): one party "
        "sealed both sides. The payee leg's own failure excludes it, so only the payer's claim remains.",
        [terms, payer, payee], objs,
        expect(conforming=False, payment_state="payer_stated", delivery_state="none",
               failures=[{"records": ["x402-payee-observed"], "code": "sealer_not_authorized_for_role"},
                         {"records": ["x402-payer-observed", "x402-payee-observed"],
                          "code": "sealer_conflation"}])))

    # 14. Delivery mismatch against pinned terms.
    offer = x402_offer()
    pterms = terms_leg("x402-terms", "payee", PAYEE, USDC_1_5, [wrapped("x402.offer", offer, include_content=False)],
                       deliverable={"content_digest": sha256_hex(COMPLETION)})
    _, payer0, payee0, objs = x402_base()
    ppayer = observed_leg("x402-payer-observed", "payer", PAYER, pterms, x402_ref(), USDC_1_5,
                          payer0["capsule"]["settlement"]["wrapped"])
    ppayee = observed_leg("x402-payee-observed", "payee", PAYEE, pterms, x402_ref(), USDC_1_5,
                          payee0["capsule"]["settlement"]["wrapped"], minute=2, references=[cite(ppayer)])
    psent = delivered_leg("x402-delivered-sent", "payee", PAYEE, pterms, COMPLETION, parent=ppayee)
    preceived = delivered_leg("x402-delivered-received", "payer", PAYER, pterms, OTHER_COMPLETION,
                              parent=ppayer, minute=4)
    out.append(case(
        "state-delivery-mismatch", [S_DELIVERED, S_DELIVERY],
        "The terms pin the content digest. The payee's sent digest equals it; the payer's received digest "
        "differs. The payment is agreed; the delivery is a mismatch.",
        [pterms, ppayer, ppayee, psent, preceived], objs,
        expect(conforming=True, payment_state="agreed", agreed_status="settled", terms_amount="equal",
               delivery_state="mismatch")))

    # 15-17. Lightning with a receive-side fee, from the numbers of a real two-payment run: the payer
    # sent 1000 msat with routing fee 0; the payee's wallet recorded 995 msat received, fee 5.
    msat_1000 = {"value": "1000", "assetCode": "BTC", "assetScale": 11}
    msat_995 = {"value": "995", "assetCode": "BTC", "assetScale": 11}
    msat_5 = {"value": "5", "assetCode": "BTC", "assetScale": 11}

    def ln_settlement(n: int, receive_fee: Any) -> list[dict]:
        ref = {"type": "ln.payment_hash", "value": label_hex(f"lightning payment hash {n}")}
        lterms = terms_leg(f"ln-terms-{n}", "payee", PAYEE, msat_1000, [], payment_ref=ref)
        lpayer = observed_leg(f"ln-payer-observed-{n}", "payer", PAYER, lterms, ref, msat_1000, [])
        lpayee = observed_leg(f"ln-payee-observed-{n}", "payee", PAYEE, lterms, ref, msat_995, [],
                              fee=receive_fee, minute=2, references=[cite(lpayer)])
        return [lterms, lpayer, lpayee]

    agreed_ln = {"payment_state": "agreed", "agreed_status": "settled", "terms_amount": "equal"}
    out.append(case(
        "pos-ln-receive-fee-two-payments", [S_FEES, S_PAYMENT],
        "Two Lightning payments of 1000 msat each. The payer's wallet reports 1000 sent with routing_fee 0; "
        "the payee's wallet reports 995 received with receive_fee 5. The amounts differ honestly: "
        "1000 = 995 + 5, so each settlement is agreed. Naive equality of the two amounts would misreport "
        "both as mismatch.",
        ln_settlement(1, msat_5) + ln_settlement(2, msat_5), [],
        expect(conforming=True, settlements=[
            settlement("ln-terms-1", delivery_state="none", **agreed_ln),
            settlement("ln-terms-2", delivery_state="none", **agreed_ln)])))
    out.append(case(
        "state-ln-receive-fee-mismatch", [S_FEES, S_PAYMENT],
        "The payee reports 995 received with receive_fee 0. 995 + 0 is not 1000: the fee does not explain "
        "the difference, so the settlement is a mismatch.",
        ln_settlement(1, ZERO), [],
        expect(conforming=True, payment_state="mismatch", differs=["amount"], delivery_state="none",
               terms="ln-terms-1")))
    out.append(case(
        "neg-ln-receive-fee-absent", [S_FEES, S_PAYMENT, S_FAILURES],
        "The payee reports 995 received and no receive_fee. Lightning receive fees may apply, so an absent "
        "fee is not read as zero: the pair is unjoined (never a false agreed), with finding fee_unstated.",
        ln_settlement(1, None), [],
        expect(conforming=True, payment_state="unjoined", delivery_state="none", terms="ln-terms-1",
               findings=[{"records": ["ln-payee-observed-1"], "code": "fee_unstated"}])))
    return out


def registry() -> dict:
    return {
        "settlement_version": "0",
        "legs": ["terms", "payer_observed", "payee_observed", "delivered"],
        "sealer_roles": ["payer", "payee"],
        "statuses": ["pending", "settled", "failed", "reversed"],
        "delivery_directions": {"sent": "payee", "received": "payer"},
        "payment_states": ["terms_only", "payer_stated", "payee_stated", "agreed", "mismatch", "unjoined"],
        "delivery_states": ["none", "stated", "matched", "mismatch"],
        "failure_codes": ["settlement_malformed", "amount_not_exact", "terms_ref_unresolved", "leg_role_mismatch",
                          "sealer_not_authorized_for_role", "sealer_conflation", "wrapped_digest_mismatch",
                          "wrapped_resigned"],
        "informational_codes": ["payment_ref_type_unknown", "fee_unstated", "fee_asset_differs"],
        "base_profile_codes": ["capsule_invalid", "envelope_invalid"],
        "payment_ref_types": {
            name: {"qualifiers": qualifiers,
                   "receive_fee": "not_applicable" if name == "x402.transaction" else "may_apply"}
            for name, qualifiers in (
                ("x402.transaction", ["network"]), ("ln.payment_hash", []),
                ("bolt12.invoice_payment_hash", []), ("ap2.transaction_id", []), ("ap2.payment_id", []),
                ("ap2.network_confirmation_id", []), ("acp.order_id", []), ("ucp.order_id", []),
                ("mpp.reference", ["method"]), ("iso20022.uetr", []), ("iso20022.end_to_end_id", ["debtor_agent"]),
                ("open_payments.incoming_payment", []))
        },
        "wrapped_types": {
            "x402.offer": "payee", "x402.receipt": "payee", "x402.payment-payload": "payer",
            "x402.settle-response": "other", "ap2.checkout-mandate": "payer", "ap2.payment-mandate": "payer",
            "ap2.checkout-receipt": "other", "ap2.payment-receipt": "other", "bolt12.invoice": "payee",
            "bolt12.payer-proof": "payer", "mpp.payment-receipt": "payee", "iso20022.message": "other",
            "delivery.proof": "other",
        },
        "settlement_members": {
            "terms": {"required": ["version", "leg", "sealer_role", "amount"],
                      "optional": ["payment_ref", "deliverable", "valid_until", "wrapped"]},
            "payer_observed": {"required": ["version", "leg", "sealer_role", "terms_ref", "amount", "payment_ref",
                                            "status", "observed_at"], "optional": ["routing_fee", "wrapped"]},
            "payee_observed": {"required": ["version", "leg", "sealer_role", "terms_ref", "received",
                                            "payment_ref", "status", "observed_at"],
                               "optional": ["receive_fee", "wrapped"]},
            "delivered": {"required": ["version", "leg", "sealer_role", "terms_ref", "observed_at", "delivery"],
                          "optional": ["wrapped"]},
        },
        "iso20022_status_map": {
            "pending": {"payer_pacs002": ["ACTC", "ACCP", "ACSP", "PDNG"], "payee_pacs002": ["ACSP", "PDNG"],
                        "payee_camt054": ["PDNG"]},
            "settled": {"payer_pacs002": ["ACSC"], "payee_pacs002": ["ACCC"], "payee_camt054": ["BOOK"]},
            "failed": {"payer_pacs002": ["RJCT"], "payee_pacs002": ["RJCT"], "payee_camt054": []},
            "reversed": {"payer_pacs002": [], "payee_pacs002": [], "payee_camt054": ["BOOK+reversal"]},
        },
        "section": [S_SEALERS, S_MEMBER, S_CITE, S_TERMS, S_DELIVERED, S_AMOUNTS, S_FEES, S_JOIN, S_TYPES, S_WRAP,
                    S_INPUTS, S_PAYMENT, S_DELIVERY, S_FAILURES],
    }


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------


def _dump(value: Any) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def build() -> dict[str, bytes]:
    case_list = cases()
    files: dict[str, bytes] = {
        "registry.json": _dump({"draft": DRAFT, "provenance": "spec-derived", **registry()}),
        "cases.json": _dump({
            "draft": DRAFT,
            "provenance": "spec-derived",
            "description": "Settlement leg sets: the records, the wrapped objects they cite, the key policy, "
                           "and the expected failures and derived states.",
            "envelope_profile": "AAC Producer Envelope: tagged COSE_Sign1, protected {1: -8, 3: "
                                "'application/agent-action-capsule-id', 4: raw Ed25519 public key}, empty "
                                "unprotected map, attached payload = raw 32-byte capsule_id.",
            "keys": {k.name: {"seed_hex": k.seed.hex(), "public_key_hex": k.public_hex} for k in KEYS},
            "count": len(case_list),
            "cases": case_list,
        }),
    }
    files["manifest.json"] = _dump({
        "draft": DRAFT,
        "provenance": "spec-derived",
        "generator": "python/scripts/generate_settlement_vectors.py",
        "files": [{"path": name, "sha256": sha256_hex(data), "count": json.loads(data).get("count")}
                  for name, data in sorted(files.items())],
    })
    return files


def write(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for name, data in build().items():
        (out / name).write_bytes(data)
    lines = [f"{sha256_hex(p.read_bytes())}  {p.name}"
             for p in sorted(out.iterdir()) if p.is_file() and p.name != "SHA256SUMS"]
    (out / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    write(parser.parse_args().out)


if __name__ == "__main__":
    main()
