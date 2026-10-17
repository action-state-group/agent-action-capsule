#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate the x402 adapter v0 vectors (spec/adapters/x402-v0.md).

Every expected result below is written by hand from the text of
``spec/adapters/x402-v0.md`` and cites the section it comes from. Nothing here
runs an adapter: the script builds an x402 v2 ``PaymentPayload`` and
``SettlementResponse``, signs the payload's EIP-3009 authorization with a
published development key, and builds the relying party's recorded transaction
lookup.

The payment is CONSTRUCTED, NOT RECORDED. No chain was called. The signing key
is the first default development account that Hardhat Network and Foundry anvil
derive from the mnemonic ``test test test test test test test test test test
test junk``: private key
``0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80``,
address ``0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266``, as used in
foundry-rs/foundry ``crates/script/src/lib.rs`` at
``131bd9d03941a79836653296d84921e2ab4d9fbb``. It is public and holds nothing.
A recorded Base Sepolia payment replaces the positive case when it is
available; the key then leaves the corpus.

Output: ``vectors/adapters/x402/`` (or ``--out DIR``). The run is a pure
function of this file: no clock and no randomness (signatures use RFC 6979
nonces). ``README.md`` is hand-written; when present in the output directory it
is included in ``SHA256SUMS`` but never rewritten.

Dependencies: the standard library only. Keccak-256 and secp256k1 are
implemented below for this generator; the test checks them against published
values.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "vectors" / "adapters" / "x402"
DOCUMENT = "spec/adapters/x402-v0.md"
PROVENANCE = "constructed, not recorded"

# ---------------------------------------------------------------------------
# Keccak-256 (the Ethereum variant: 0x01 domain padding, not SHA-3's 0x06)
# ---------------------------------------------------------------------------


def _rc_bit(t: int) -> int:
    if t % 255 == 0:
        return 1
    r = 1
    for _ in range(t % 255):
        r <<= 1
        if r & 0x100:
            r ^= 0x171
    return r & 1


_RC = [sum(_rc_bit(j + 7 * i) << ((1 << j) - 1) for j in range(7)) for i in range(24)]
# Rotation offsets, indexed x + 5y.
_ROT = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14]
_LANE = (1 << 64) - 1


def _rotl(value: int, n: int) -> int:
    return ((value << n) | (value >> (64 - n))) & _LANE if n else value


def _keccak_f(a: list[int]) -> list[int]:
    for rc in _RC:
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl(c[(x + 1) % 5], 1) for x in range(5)]
        a = [a[i] ^ d[i % 5] for i in range(25)]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl(a[x + 5 * y], _ROT[x + 5 * y])
        a = [b[i] ^ (~b[(i + 1) % 5 + 5 * (i // 5)] & b[(i + 2) % 5 + 5 * (i // 5)]) for i in range(25)]
        a[0] ^= rc
    return a


def keccak256(data: bytes) -> bytes:
    rate = 136
    msg = bytearray(data) + b"\x01"
    msg += b"\x00" * (-len(msg) % rate)
    msg[-1] |= 0x80
    state = [0] * 25
    for offset in range(0, len(msg), rate):
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(msg[offset + 8 * i:offset + 8 * i + 8], "little")
        state = _keccak_f(state)
    return b"".join(lane.to_bytes(8, "little") for lane in state[:4])


# ---------------------------------------------------------------------------
# secp256k1: RFC 6979 signing and public key recovery
# ---------------------------------------------------------------------------

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _add(p: tuple[int, int] | None, q: tuple[int, int] | None) -> tuple[int, int] | None:
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % P == 0:
        return None
    if p == q:
        lam = 3 * p[0] * p[0] * pow(2 * p[1], -1, P) % P
    else:
        lam = (q[1] - p[1]) * pow(q[0] - p[0], -1, P) % P
    x = (lam * lam - p[0] - q[0]) % P
    return x, (lam * (p[0] - x) - p[1]) % P


def _mul(k: int, p: tuple[int, int] | None) -> tuple[int, int] | None:
    result = None
    while k:
        if k & 1:
            result = _add(result, p)
        p = _add(p, p)
        k >>= 1
    return result


def address_of(point: tuple[int, int]) -> str:
    raw = keccak256(point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big"))[12:]
    return checksum_address(raw.hex())


def checksum_address(hex40: str) -> str:
    """EIP-55 mixed-case form of a 40-hex-character address."""
    lower = hex40.lower()
    nibbles = keccak256(lower.encode("ascii")).hex()
    return "0x" + "".join(ch.upper() if ch.isalpha() and int(nibbles[i], 16) >= 8 else ch
                          for i, ch in enumerate(lower))


def _rfc6979_k(key: int, z: bytes) -> int:
    x = key.to_bytes(32, "big")
    h = (int.from_bytes(z, "big") % N).to_bytes(32, "big")
    v, k = b"\x01" * 32, b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x + h, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + h, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        candidate = int.from_bytes(v, "big")
        if 0 < candidate < N:
            return candidate
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def sign(key: int, z: bytes) -> bytes:
    """65-byte ``r || s || v`` with low ``s`` and ``v`` in {27, 28}, as EVM wallets produce."""
    k = _rfc6979_k(key, z)
    point = _mul(k, G)
    r = point[0] % N
    s = pow(k, -1, N) * (int.from_bytes(z, "big") + r * key) % N
    parity = point[1] & 1
    if s > N // 2:
        s, parity = N - s, parity ^ 1
    return r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([27 + parity])


def recover(z: bytes, signature: bytes) -> str | None:
    """The signer address, with ``v`` 0/1 normalized to 27/28 (x402-v0.md §6.1)."""
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:64], "big")
    v = signature[64]
    if v in (0, 1):
        v += 27
    if v not in (27, 28) or not (0 < r < N and 0 < s < N):
        return None
    y = pow((r**3 + 7) % P, (P + 1) // 4, P)
    if y & 1 != v - 27:
        y = P - y
    r_inv = pow(r, -1, N)
    q = _add(_mul(s * r_inv % N, (r, y)), _mul(-int.from_bytes(z, "big") * r_inv % N, G))
    return address_of(q) if q else None


# ---------------------------------------------------------------------------
# EIP-712 TransferWithAuthorization (EIP-3009)
# ---------------------------------------------------------------------------

DOMAIN_TYPE = b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
TRANSFER_TYPE = (b"TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,"
                 b"uint256 validBefore,bytes32 nonce)")
TRANSFER_TOPIC = "0x" + keccak256(b"Transfer(address,address,uint256)").hex()
AUTHORIZATION_USED_TOPIC = "0x" + keccak256(b"AuthorizationUsed(address,bytes32)").hex()


def _word(n: int) -> bytes:
    return n.to_bytes(32, "big")


def _address_word(address: str) -> bytes:
    return bytes(12) + bytes.fromhex(address[2:])


def eip712_digest(domain: dict, authorization: dict) -> bytes:
    separator = keccak256(keccak256(DOMAIN_TYPE) + keccak256(domain["name"].encode("utf-8"))
                          + keccak256(domain["version"].encode("utf-8")) + _word(domain["chainId"])
                          + _address_word(domain["verifyingContract"]))
    struct = keccak256(keccak256(TRANSFER_TYPE) + _address_word(authorization["from"])
                       + _address_word(authorization["to"]) + _word(int(authorization["value"]))
                       + _word(int(authorization["validAfter"])) + _word(int(authorization["validBefore"]))
                       + bytes.fromhex(authorization["nonce"][2:]))
    return keccak256(b"\x19\x01" + separator + struct)


# ---------------------------------------------------------------------------
# The constructed payment
# ---------------------------------------------------------------------------

DEV_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
PAYER = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
# Second default development account; only its address is used.
PAY_TO = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
NETWORK = "eip155:84532"
CHAIN_ID = 84532
# The asset contract and its EIP-712 domain are the values of the x402 v2
# specification's own example (5.1.1, 5.2.1), whose signature recovers under them.
ASSET = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
DOMAIN = {"name": "USDC", "version": "2", "chainId": CHAIN_ID, "verifyingContract": ASSET}
AMOUNT = "10000"
VALID_AFTER = 1760000000
VALID_BEFORE = 1760000120
BLOCK_NUMBER = 32000000
BLOCK_TIMESTAMP = 1760000030


def _constructed(label: str, size: int) -> str:
    return "0x" + keccak256(f"x402-adapter-v0 constructed {label}".encode("ascii"))[:size].hex()


NONCE = _constructed("nonce", 32)
TRANSACTION = _constructed("transaction", 32)
FACILITATOR = checksum_address(_constructed("facilitator", 20)[2:])


def _compact(value: Any) -> bytes:
    """Member order as written and no whitespace, as a JSON.stringify client emits."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def authorization(value: str = AMOUNT) -> dict:
    return {"from": PAYER, "to": PAY_TO, "value": value, "validAfter": str(VALID_AFTER),
            "validBefore": str(VALID_BEFORE), "nonce": NONCE}


def payment_payload(signed: dict, sent: dict) -> dict:
    """A PaymentPayload whose signature covers ``signed`` and whose authorization member is ``sent``."""
    signature = sign(DEV_KEY, eip712_digest(DOMAIN, signed))
    return {
        "x402Version": 2,
        "resource": {"url": "https://api.example.com/premium-data", "description": "Access to premium data",
                     "mimeType": "application/json"},
        "accepted": {"scheme": "exact", "network": NETWORK, "amount": AMOUNT, "asset": ASSET, "payTo": PAY_TO,
                     "maxTimeoutSeconds": 60, "extra": {"name": DOMAIN["name"], "version": DOMAIN["version"]}},
        "payload": {"signature": "0x" + signature.hex(), "authorization": sent},
    }


def settle_response() -> dict:
    return {"success": True, "transaction": TRANSACTION, "network": NETWORK, "payer": PAYER}


def _topic_address(address: str) -> str:
    return "0x" + _address_word(address).hex().lower()


def lookup() -> dict:
    """The relying party's recorded observation of the chain (x402-v0.md §6.4), in RPC result shapes."""
    return {
        "provenance": PROVENANCE,
        "network": NETWORK,
        "source": "constructed observation; no chain endpoint was called",
        "transaction_receipt": {
            "transactionHash": TRANSACTION,
            "blockNumber": hex(BLOCK_NUMBER),
            "status": "0x1",
            "from": FACILITATOR,
            "to": ASSET,
            "logs": [
                {"address": ASSET, "topics": [AUTHORIZATION_USED_TOPIC, _topic_address(PAYER), NONCE], "data": "0x"},
                {"address": ASSET, "topics": [TRANSFER_TOPIC, _topic_address(PAYER), _topic_address(PAY_TO)],
                 "data": "0x" + _word(int(AMOUNT)).hex()},
            ],
        },
        "block": {"number": hex(BLOCK_NUMBER), "timestamp": hex(BLOCK_TIMESTAMP)},
        "code_at_payer": "0x",
    }


# ---------------------------------------------------------------------------
# Expected results (x402-v0.md §7)
# ---------------------------------------------------------------------------

PAYLOAD = "x402.payment-payload"
SETTLE = "x402.settle-response"
RECEIPT = "x402.receipt"

METHOD = {
    "payload_form": "x402 v2 PaymentPayload: JSON parse of the registered octets, no duplicate members",
    "payer_signature": "EIP-712 TransferWithAuthorization (EIP-3009), domain from policy, secp256k1 recovery, "
                       "v 0/1 normalized to 27/28",
    "authorization_terms": "x402 exact: authorization.to = accepted.payTo, authorization.value = accepted.amount",
    "authorization_window": "EIP-3009 validAfter < t < validBefore, t = block timestamp of the settling "
                            "transaction from the recorded lookup",
    "settle_response_form": "x402 v2 SettlementResponse: JSON parse, 5.3.2 member types",
    "settle_response_join": "x402 v2: network = accepted.network, payer = authorization.from",
    "settle_response_signature": "none: x402 v2 SettlementResponse is unsigned",
    "settlement_onchain": "transaction lookup on the accepted network: status, Transfer, AuthorizationUsed",
    "receipt_signature": "x402 offer-receipt EIP-712 signature: payload version 1, or version 2 under #3186 "
                         "or #3140 by member names",
    "receipt_signer_authorized": "x402 offer-receipt 4.5.1 signer authorization under the relying party's policy",
    "delivery_binding": "#3186 responseHash or #3140 contentHash, SHA-256",
}
POLICY_CHECKS = ("payer_trust", "asset_trust")
OBJECT_OF = {
    "payload_form": PAYLOAD, "payer_signature": PAYLOAD, "payer_trust": PAYLOAD, "asset_trust": PAYLOAD,
    "authorization_terms": PAYLOAD, "authorization_window": PAYLOAD, "settle_response_form": SETTLE,
    "settle_response_join": SETTLE, "settle_response_signature": SETTLE, "settlement_onchain": SETTLE,
    "receipt_signature": RECEIPT, "receipt_signer_authorized": RECEIPT, "delivery_binding": RECEIPT,
}


def policy(signer: str) -> dict:
    return {
        "id": f"constructed-policy-{signer}",
        "signer": signer,
        "domains": [{"network": NETWORK, "asset": ASSET, **DOMAIN}],
        "payers": [{"address": PAYER, "party": "constructed payer (development account 0)"}],
        "receipt_signers": [],
        "chain_source": "the case's recorded lookup",
    }


def reports(pol: dict, statuses: dict[str, str]) -> list[dict]:
    """One ``native_check`` report per named check, the name in ``detail`` (x402-v0.md §7)."""
    out = []
    for check, status in statuses.items():
        method = f"relying party policy {pol['id']}" if check in POLICY_CHECKS else METHOD[check]
        out.append({"property": "native_check", "status": status, "method": method,
                    "detail": {"check": check, "object": OBJECT_OF[check]}})
    return out


S_SCOPE = "x402-v0.md §3"
S_OCTETS = "x402-v0.md §4"
S_ISSUERS = "x402-v0.md §5"
S_PAYLOAD = "x402-v0.md §6.1"
S_SETTLE = "x402-v0.md §6.2"
S_LOOKUP = "x402-v0.md §6.4"
S_RESULTS = "x402-v0.md §7"
S_MAPPING = "x402-v0.md §8.1"


def _wrapped(kind: str, octets: bytes) -> dict:
    return {"type": kind, "digest_alg": "SHA-256", "digest": hashlib.sha256(octets).hexdigest()}


def cases() -> tuple[list[dict], dict[str, bytes]]:
    files: dict[str, bytes] = {}
    entries = []

    def add(name: str, description: str, payload_value: dict, signer: str, statuses: dict[str, str],
            requirements: list[dict]) -> None:
        payload_octets = _compact(payload_value)
        settle_octets = _compact(settle_response())
        base = f"cases/{name}/"
        inputs = {
            "payment-payload.octets": payload_octets,
            "payment-signature.header": base64.b64encode(payload_octets),
            "settle-response.octets": settle_octets,
            "payment-response.header": base64.b64encode(settle_octets),
            "lookup.json": (json.dumps(lookup(), indent=2) + "\n").encode("utf-8"),
        }
        for file_name, data in inputs.items():
            files[base + file_name] = data
        pol = policy(signer)
        entries.append({
            "name": name,
            "provenance": PROVENANCE,
            "description": description,
            "inputs": {
                "wrapped": [
                    {**_wrapped(PAYLOAD, payload_octets), "octets": base + "payment-payload.octets"},
                    {**_wrapped(SETTLE, settle_octets), "octets": base + "settle-response.octets"},
                ],
                "informative": {
                    "PAYMENT-SIGNATURE": base + "payment-signature.header",
                    "PAYMENT-RESPONSE": base + "payment-response.header",
                },
                "lookup": base + "lookup.json",
                "online": True,
            },
            "policy": pol,
            "expect": {"reports": reports(pol, statuses), "requirements": requirements},
            "section": [S_SCOPE, S_OCTETS, S_ISSUERS, S_PAYLOAD, S_SETTLE, S_LOOKUP, S_RESULTS, S_MAPPING],
        })

    no_receipt = {"receipt_signature": "NOT_PRESENT", "receipt_signer_authorized": "NOT_PRESENT",
                  "delivery_binding": "NOT_PRESENT"}

    signed = authorization()
    add("positive",
        "A constructed exact/eip3009 payment on Base Sepolia, signed by development account 0, settled in "
        "a recorded (constructed) transaction. Default signer policy eoa-or-contract. Every check that has "
        "an input passes; the settlement response has no signature, and there is no receipt.",
        payment_payload(signed, signed), "eoa-or-contract",
        {"payload_form": "PASS", "payer_signature": "PASS", "payer_trust": "PASS", "asset_trust": "PASS",
         "authorization_terms": "PASS", "authorization_window": "PASS", "settle_response_form": "PASS",
         "settle_response_join": "PASS", "settle_response_signature": "NOT_PRESENT",
         "settlement_onchain": "PASS", **no_receipt},
        [])

    mutated = authorization(value=str(int(AMOUNT) + 1))
    add("native-check-fails",
        "The positive payment with authorization.value changed from 10000 to 10001 after signing. value is "
        "inside the signed EIP-712 message, so recovery yields another address; under signer policy eoa "
        "that is FAIL. The value no longer equals accepted.amount, and the recorded Transfer no longer "
        "matches the authorization.",
        payment_payload(signed, mutated), "eoa",
        {"payload_form": "PASS", "payer_signature": "FAIL", "payer_trust": "PASS", "asset_trust": "PASS",
         "authorization_terms": "FAIL", "authorization_window": "PASS", "settle_response_form": "PASS",
         "settle_response_join": "PASS", "settle_response_signature": "NOT_PRESENT",
         "settlement_onchain": "FAIL", **no_receipt},
        [
            {"requirement": "the payer signed this transfer authorization", "relation": "is the check",
             "row": 5, "status": "SATISFIED", "sufficiency": "SATISFIED", "verdict": "not_met"},
            {"requirement": "the resource was paid for", "relation": "supported by the check",
             "row": 6, "status": "INSUFFICIENT", "sufficiency": "INSUFFICIENT", "verdict": "not_evaluable"},
        ])
    return entries, files


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------


def _dump(value: Any) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def build() -> dict[str, bytes]:
    entries, files = cases()
    files["cases.json"] = _dump({
        "document": DOCUMENT,
        "provenance": PROVENANCE,
        "description": "x402 adapter v0: the wrapped objects' octets, the relying party's policy and recorded "
                       "lookup, and the expected native_check reports.",
        "development_key": {
            "private_key": hex(DEV_KEY),
            "address": PAYER,
            "source": "first default development account of Hardhat Network and Foundry anvil (mnemonic "
                      "'test test test test test test test test test test test junk'); foundry-rs/foundry "
                      "crates/script/src/lib.rs at 131bd9d03941a79836653296d84921e2ab4d9fbb",
        },
        "count": len(entries),
        "cases": entries,
    })
    files["manifest.json"] = _dump({
        "document": DOCUMENT,
        "provenance": PROVENANCE,
        "generator": "python/scripts/generate_adapter_x402_vectors.py",
        "files": [{"path": name, "sha256": hashlib.sha256(data).hexdigest()} for name, data in sorted(files.items())],
    })
    return files


def write(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for name, data in build().items():
        path = out / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    files = sorted((p.relative_to(out).as_posix(), p) for p in out.rglob("*") if p.is_file())
    lines = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {rel}" for rel, p in files if p.name != "SHA256SUMS"]
    (out / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    write(parser.parse_args().out)


if __name__ == "__main__":
    main()
