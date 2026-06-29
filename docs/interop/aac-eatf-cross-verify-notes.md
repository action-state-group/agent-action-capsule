# AAC ↔ EATF Cross-Verify Notes

**Date:** 2026-06-29  
**Corpus:** `tyche-institute/eatf` (MIT License), `test-vectors/valid/` — 4 vectors

These notes record what was independently verified against the public EATF corpus
BEFORE the live hackathon cross-verify (scheduled IETF 126, Vienna, 18–19 Jul 2026).

---

## EATF test vectors inspected

| Vector | policy_decision | Notable fields |
|---|---|---|
| `minimal-roundtrip` | (not in metadata) | schema: urn:eatf:spec:aep:metadata:1.0; minimal metadata |
| `valid-overt-profile` | (not in metadata) | overt_receipt.json with content_hash |
| `mcp-tools-call-valid` | `allow` | action_type: mcp.tools/call:github.create_issue; privacy_mode: true; MCP metadata |
| `mcp-tools-call-denied-policy` | `deny` | action_type: mcp.tools/call:payment.transfer; policy enforcement |

---

## What we verified

### 1. Canonicalization and hash

In all 4 valid test vectors:

```
canonical.bin == response.txt   (byte-identical)
sha256(canonical.bin) == hash.sha256   ✓
```

**Finding:** EATF v0.1 test corpus uses `canonical.bin = response.txt` only.
The AEP spec v1 document describes `canonical.bin = response.txt + 0x0A + JCS(metadata.json)`,
but the current test vectors predate this — they were generated at v0.1 where the
canonical form was response text only. **The full v1 canonicalization (including JCS
metadata) is specified but not yet reflected in the v0.1 test corpus.** Cross-verify
at the hackathon should confirm which canonicalization Anton's live pipeline uses.

### 2. RSA-SHA256 signature (minimal-roundtrip)

```python
# Verified independently:
pubkey.verify(sig, canonical_bin, padding.PKCS1v15(), hashes.SHA256())
# → VALID ✓
```

The bundle's `signature.sig` (Base64-encoded PKCS#1 v1.5 RSA-SHA256) over `canonical.bin`
verifies against `public_key.pem` (RSA-4096 dev key from `test-vectors/keys/`). This
confirms the AEP bundle format is cryptographically consistent and independently verifiable.

### 3. OVERT receipt binding (valid-overt-profile)

The `overt_receipt.json` carries:
```json
"content_hash": "sha256:<64-char hex>"
```
This matches `hash.sha256` byte-for-byte. The OVERT receipt is a machine-readable
link from the receipt to the content, enabling the receipt to serve as verifiable
evidence of what was attested. Structure inspected:

```json
{
  "overt": "1.0.0",
  "profile": "urn:eatf:spec:aep:1.0",
  "scope": "foundational:aep-response",
  "content_hash": "sha256:99388830...",
  "policy": { "id": "atap-basic", "version": "1.0", "coverage": 1.0, "decision": "allow" },
  "witness": { "iap": "EATF.eu", "signature_refs": ["signature.sig"], "timestamp_refs": ["timestamp.tsr"] }
}
```

### 4. Policy enforcement vector (mcp-tools-call-denied-policy)

The `policy_decision: "deny"` vector confirms that AEP records both `allow` and `deny`
outcomes — the same action type (`mcp.tools/call:payment.transfer`) appears as denied.
This is structurally parallel to AAC's `verdict_class: "blocked"` / `disposition.decision:
"reject"` — the capsule records the denial as an equally valid outcome.

### 5. MCP integration metadata (mcp-tools-call-valid)

The vector carries:
```json
"mcp": {
  "tool_name": "github.create_issue",
  "method": "tools/call",
  "gateway_mode": "server",
  "request_id": "fixture-att_mcp_01J0000000000000000000001"
}
```
This shows EATF records MCP tool calls with explicit tool/method/request binding.
AAC's equivalent is `action_id: "write_order/<uuid>"` + `compute_attestation.agent_input_digest`
(the request is committed by digest rather than by name in the capsule body).

---

## Format comparison (corpus-level)

| Property | AAC (our minted capsule) | EATF v0.1 corpus |
|---|---|---|
| Content representation | Digest-only (`agent_input_digest`, `response_digest`) — content stays local | `response.txt` in cleartext in the ZIP bundle |
| Canonicalization | JCS (RFC 8785) over the full capsule JSON | `canonical.bin` = `response.txt` (v0.1); spec adds `+ LF + JCS(metadata.json)` in v1 |
| Integrity hash | `capsule_id = SHA-256(JCS(capsule))` — self-addressing | `hash.sha256 = SHA-256(canonical.bin)` — separate from content address |
| Signature | No embedded signature in the JSON (SCITT receipt is the externally verifiable proof) | RSA-4096-SHA256 (+ optionally ML-DSA-65) over `canonical.bin` embedded in bundle |
| Timestamp | `timestamp` field in JSON (self-reported) | RFC 3161 TSA token in `timestamp.tsr` |
| Transparency log | SCITT (neutral, RFC 9162 CT structure); receipt in `receipt_b64` | Per-tenant hash-chained ledger (operator-hosted); OVERT receipt optionally references it |
| Policy record | `disposition.verdict_class`, `effect.type`, `assurance.effect_mode` | `policy_id`, `policy_version`, `policy_coverage`, `policy_decision` |
| Privacy | Content never in bundle — digests only | `response.txt` present in bundle in v0.1; `privacy_mode: true` flag exists but response is still plaintext in these vectors |

---

## What remains for live cross-verify (hackathon)

1. **Confirm v1 canonicalization in Anton's live system.** The test corpus uses `canonical.bin = response.txt`;
   the spec says `canonical.bin = response.txt + LF + JCS(metadata)`. We need to confirm which form
   his live signer uses before constructing the AEP binding of our capsule.

2. **AEP bundle containing our capsule_id.** Anton produces a bundle where `response.txt` includes
   our `capsule_id` + `response_digest` fields. We verify the `hash.sha256` covers that content.

3. **swtpm → Veraison pipeline.** Anton's quote nonce = raw bytes of our `capsule_id`.
   We confirm: `bytes.fromhex("c52a66d0…")` (32 bytes) appears in the quote structure.

4. **SCITT receipt verification by Anton's toolchain.** He decodes our `receipt_b64` (COSE Receipt)
   and checks the RFC 9162 inclusion proof against the anchor's Ed25519 public key.
   The anchor public key is at `https://anchor.agentactioncapsule.org/attest/pubkey`.

---

## Corpus conclusion

The EATF public test corpus is independently verifiable and the format is correct by inspection.
The AEP bundle is a standard ZIP archive; the canonicalization and signature are straightforward
to implement in any language with ZIP + SHA-256 + RSA-SHA256 support. The OVERT receipt provides
a machine-readable chain of custody reference. Cross-verification of the cryptographic layer
(hash + signature) against the public corpus succeeded without needing the Java reference verifier.

The key structural difference confirmed by the corpus: AEP records agent responses in cleartext
(`response.txt`); AAC commits them by digest. These are not competing choices — they reflect
different threat models (AEP prioritizes repudiation-resistance; AAC prioritizes content-privacy).
Both can coexist in the same evidence chain, which is the compose point.
