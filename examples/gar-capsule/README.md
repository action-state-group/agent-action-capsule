# GAR Capsule Example — draft-sato-soos-gar-03 §6.2

This directory contains a self-contained example of a
[draft-sato-soos-gar-03](https://datatracker.ietf.org/doc/draft-sato-soos-gar/)
Governance Audit Record (GAR) block wrapped in an Agent Action Capsule (AAC) envelope.

## Files

| File | Description |
|------|-------------|
| `sample-gar-block.json` | Sample GAR block (SAR) with -03 §6.2 fields |
| `demo.py` | Computes SAR digest, builds and verifies the AAC capsule |

## -03 field set (§6.2)

Base fields:

| Field | Notes |
|-------|-------|
| `so_id` | SOOS Operator identifier |
| `kernel_signature` | Kernel-level attestation signature (renamed from `kernel_attestation`/`kia_signed` in earlier drafts) |
| `session_id` | Session identifier |
| `agent_id` | Agent URI |
| `timestamp` | ISO 8601 timestamp |

-03 additions:

| Field | Notes |
|-------|-------|
| `cap_profile_id` | Capability profile identifier (e.g. `aac-01`) |
| `cap_profile_hash` | `sha256:`-prefixed hash of the capability profile document |
| `acd_session_id` | ACD session identifier; **null** when no ACD session is active (dropped by normalization — see below) |
| `soos.gar.block_id` | Block identifier within the GAR audit trail |
| `hem_events` | List of HEM events; empty array when none (dropped by normalization) |
| `cap_violations` | List of capability violations; empty array when none (dropped by normalization) |

## SAR digest computation

```
digest = SHA-256( JCS( normalize(sar) ) )
```

**Canonicalization rule (load-bearing for interoperability):**

Absent-field normalization (AAC §2) is applied to the SAR **before** JCS
serialization. Normalization **drops**:

- Members whose value is `null` — e.g. `acd_session_id` when no ACD session is active
- Members whose value is an empty array — e.g. `hem_events: []`, `cap_violations: []`
- Members whose value is an empty object (recursively, bottom-up)

SOOS-side implementations **must apply normalization first, then JCS**.
Tom's sorted-key-stringify produces byte-for-byte identical output **after**
normalization — i.e., normalize first, then JCS-serialize.

### Pinned values for this sample

| Value | Hex |
|-------|-----|
| SAR digest | `6128a6953eef64c6c5117322ab34a76e36d0c77d95505830f3bdb06e220a9b88` |
| `capsule_id` | `14c4877c56f648b3c5ca41466527e9cdad3369ee4201b227565a627c8f4965b8` |

The `capsule_id` is the JSON-DIGEST (SHA-256 over JCS(normalize(capsule))) of
the AAC envelope minus the `capsule_id` and `chain` fields.

### Normalized SAR (JCS input)

After normalization, the digest input is (keys sorted by UTF-16 code units per RFC 8785 §3.2.3):

```json
{"agent_id":"agent://acme-corp/order-processor/v1","cap_profile_hash":"sha256:315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3","cap_profile_id":"aac-01","kernel_signature":"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","session_id":"sess-2026-07-28-demo","so_id":"soos-operator-01","soos.gar.block_id":"gar-blk-2026-07-28-0001","timestamp":"2026-07-28T00:00:00Z"}
```

## Running the demo

```sh
cd python && pip install -e .
python ../examples/gar-capsule/demo.py
```

Expected output:

```
SAR digest:  6128a6953eef64c6c5117322ab34a76e36d0c77d95505830f3bdb06e220a9b88
Normalization dropped (null/empty): ['acd_session_id', 'hem_events', 'cap_violations']
capsule_id:  14c4877c56f648b3c5ca41466527e9cdad3369ee4201b227565a627c8f4965b8
verify ok:   True
GAR capsule demo complete.
```
