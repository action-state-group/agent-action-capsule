# agent-action-capsule

[![CI](https://github.com/action-state-group/agent-action-capsule/actions/workflows/python.yml/badge.svg)](https://github.com/action-state-group/agent-action-capsule/actions/workflows/python.yml)
[![Conformance](https://github.com/action-state-group/agent-action-capsule/actions/workflows/conformance.yml/badge.svg)](https://github.com/action-state-group/agent-action-capsule/actions/workflows/conformance.yml)

An **open specification** for recording and independently verifying what an
AI agent actually did. An Agent Action Capsule is a digest-committed JSON record
with a signer-independent identity. New Capsules declare plain RFC 8785 JCS,
commit `chain` to `capsule_id`, and use format version 4.

A Capsule is recorded on every verdict. One or more independent COSE_Sign1
Producer Envelopes may authenticate the raw 32-byte Capsule ID. Signing never
changes the Capsule or its identity. Refusals are Capsules too, so a blocked or
denied Capsule is affirmative evidence that a gate worked.

> **Status / standards honesty.** This is an **individual** IETF Internet-Draft,
> not a Working Group document, and not an RFC. The substrate it builds on is
> now published: the SCITT architecture is [RFC 9943](https://www.rfc-editor.org/rfc/rfc9943)
> and COSE Receipts are [RFC 9942](https://www.rfc-editor.org/rfc/rfc9942)
> (both June 2026). No RFC number is claimed for this profile; no WG adoption
> is claimed.

## The draft

- **Datatracker:** https://datatracker.ietf.org/doc/draft-mih-scitt-agent-action-capsule/
- **Editor's source (this repo):** [`spec/draft-mih-scitt-agent-action-capsule-04.md`](spec/draft-mih-scitt-agent-action-capsule-04.md)
  (kramdown-rfc source).
- **Registry of record:** [`spec/REGISTRY.md`](spec/REGISTRY.md) — the interim
  registry for the six profile vocabularies until IANA registries are
  established on RFC publication.
- **Reader's guide:** [`spec/section-map.md`](spec/section-map.md).

The authoritative version of the draft is the one on the Datatracker; the `.md`
here is the editor's source from which it is built. `-04` is the current posted
revision; `-05` is in preparation.

## Quickstart — try the reference verifier

Verify a capsule in under a minute. Class-1 verification is reproducible from the
capsule bytes alone — no keys, no network, no clock.

```bash
git clone https://github.com/action-state-group/agent-action-capsule
cd agent-action-capsule
pip install -e python            # or, once published: pip install agent-action-capsule

# a known-good conformance vector  ->  ok: True, findings: none
agent-action-capsule verify test-vectors/pos-v4-jcs-chain-committed/input.json

# a tampered capsule               ->  ok: False, capsule_id_mismatch
agent-action-capsule verify test-vectors/neg-v4-chain-tampered/input.json
```

The good capsule recomputes its content-address and passes; the tampered one is
rejected because the recomputed `capsule_id` no longer matches the carried value.
Every directory under `test-vectors/` is one case — `input.json` is the capsule,
`expected.json` is the verifier's expected result — so you can check the reference
implementation against the frozen bytes the spec is conformance-tested on.

```bash
agent-action-capsule verify --help     # also: verify a store, or a full SCITT Signed Statement
agent-action-capsule anchor --help     # submit a capsule_id digest to a SCITT Transparency Service
```

For the SCITT receipt + anchor paths: `pip install -e "python[transparent,anchor]"`. Full
reference-library detail — the producer/emit side, `--transparent` Signed-Statement verification, and
every option — is in [`python/README.md`](python/README.md).

## Repository layout

```
spec/            the Internet-Draft (.md source + built .xml/.txt), REGISTRY.md,
                 section-map.md, Makefile
python/          reference library (capsule parse + verify) -> PyPI agent-action-capsule
go/              independent Go canonicalization and verification runtime
test-vectors/    conformance vectors (frozen bytes; the scitt-cose pattern)
producer-envelope-vectors/  shared binary COSE Producer Envelope vectors
LICENSE          BCP 78/79 for the specification; Revised BSD for code components
NOTICE           attribution + neutrality intent
CONTRIBUTING.md  IETF process (BCP 78/79), DCO, scope gates
SECURITY.md      private vulnerability reporting
```

## Relationship to scitt-cose

This profile builds **on top of** the neutral substrate in
[`action-state-group/scitt-cose`](https://github.com/action-state-group/scitt-cose):
that package verifies *anyone's* SCITT Signed Statements and COSE Receipts and
treats the statement payload as **opaque bytes**, with no profile baked in. The
AAC registration statement uses those opaque bytes for the raw 32-byte Capsule
ID. A Producer Envelope is a separate, narrower COSE_Sign1 profile and is not
itself an RFC 9943 Signed Statement. This repository adds both exact profiles,
the Capsule-ID match, and Capsule-domain checks. Generic SCITT registration,
Receipt, and inclusion-proof verification remain substrate concerns.

## Relationship to the producer (`capsule-emit`)

This repository owns the public protocol contract: specification, registries,
canonicalization, verification helpers, and shared conformance vectors. The
producer layer — the one-call `seal()` on-ramp that mints Capsules from a live
agent, plus its framework adapters — lives in
[`action-state-group/capsule-emit`](https://github.com/action-state-group/capsule-emit).
The producer consumes this repository's contract; this repository does not depend
on the producer. (This repo also ships a `go/` directory — an independent Go
canonicalization and verification runtime — used to cross-check the contract, not
a producer.)

## Canonical Payload Binding (CPB)

Agent Action Capsule is the first payload profile registered under the
**Canonical Payload Binding** (CPB) profile — a payload-neutral SCITT binding
(canonicalize → derive an identifier → bind a receipt → cite externals). CPB and
its provisional registries have a dedicated repository:
**[action-state-group/scitt-payload-binding](https://github.com/action-state-group/scitt-payload-binding)**.

The CPB `-00`, as posted, references this repository as its source; the `-01`
revision updates that pointer to the dedicated repository.

## Transparency-layer design — VDS-agnostic

The Capsule is signer-independent. A Producer Envelope authenticates the raw
32-byte Capsule ID. A distinct RFC 9943 Signed Statement registers that same ID
with SCITT because RFC 9943 requires protected CWT claims that the intentionally
minimal Producer Envelope does not contain.

Verification is split into Capsule Class 1, per-envelope cryptographic
verification, caller-defined signer authorization, and optional Receipt
verification. Merkle trees, Merkle mountains, and other VDS choices live only
behind the SCITT registration boundary. They do not participate in Capsule
construction or identity.

```
┌──────────────────────────────────────────────────┐
│  Producer Envelope (COSE_Sign1, tag 18)          │  ← independent signer
│   protected: { alg=-8, content_type, kid=raw key }│
│   payload:   raw 32-byte Capsule ID              │
└──────────────────────────────────────────────────┘
         │  verifies independently
         │
┌──────────────────────────────────────────────────┐
│  SCITT Signed Statement (RFC 9943)               │  ← separate registrar
│   protected: { alg, content_type, kid, CWT claims }│
│   payload:   same raw 32-byte Capsule ID         │
└──────────────────────────────────────────────────┘
         │  (submitted to a Transparency Service)
         ▼
┌──────────────────────────────────────────────────┐
│  SCITT Receipt  (COSE_Sign1, TS-minted)          │  ← what the TS adds
│   protected: { alg, vds=1 (RFC9162_SHA256) }     │
│   unprotected: { vdp: { inclusion_proof } }      │
│   payload:   Merkle root (detached)              │
└──────────────────────────────────────────────────┘
         │
         ▼
  Transparent Statement = SCITT Signed Statement + Receipt(s)
```

The producer (`capsule-emit`) creates Capsules and Producer Envelopes. It has no
opinion on VDS selection. Registration tooling creates the RFC 9943 statement. The
Receipt's `vds` header is the Transparency Service's choice.

**RFC9162_SHA256 (vds=1)** is the current default — the only VDS registered under
draft-ietf-cose-merkle-tree-proofs today, and the profile implemented in
`scitt-cose` (both `build_receipt` and `verify_receipt`).

**CCF (Microsoft Confidential Consortium Framework)** — tested against
`scitt-ccf-ledger v7.0.6` (2026-06-26): CCF emits receipts with **`vds=2`**
(`ccf.v1` Merkle format), not `vds=1` (RFC9162_SHA256). Our `scitt-cose`
`verify_receipt` currently implements **`vds=1` only**; `vds=2` support is
in progress and tracked in `scitt-cose`. Once landed, `verify_receipt` will
accept real CCF receipts without any change to the capsule or Signed Statement
format. See `scitt-cose/tests/test_ccf_interop.py` for the integration test.

Adding support for a new VDS is a new `if vds == N` branch in `scitt-cose`'s
verifier — the capsule format does not change.

**What we are NOT saying:**
- We are not claiming the capsule format requires CCF.
- We are not claiming CCF's VDS is the same as ours — CCF 7.0.6 uses `vds=2`
  (its own Merkle format); our verifier uses `vds=1` (RFC9162_SHA256). Different
  proof formats, same statement layer — the expected outcome during standardisation.
- We are not claiming `capsule-anchor`'s local TS provides the same trust
  guarantees as CCF. The SCITT protocol is the same; the trust model is not.

## Interop & independent implementations

[`INTEROP.md`](INTEROP.md) is the registry of record for cross-implementation
runs and third-party verification events as of IETF 126 (Vienna, Jul 2026). It
covers roughly a dozen rows across two tiers:

**Independent implementations** (different organization, independently written
codebase): EMILIA Protocol (Schrock), Tyche Institute (Sokolov), Microsoft/CCF
(Chamayou), Songbo Bu, NANDA/MIT, GlyphZero, APS, COSA, GAR, and VeritasChain —
each row links a public artifact (PR, release tag, or datatracker entry) as its
evidence. "Ran and verified" means the result is on the public record; a link to
a digest or PR is the evidence, not a name.

**Same-team ports** (ASG's own dual runtime — Python reference library plus Go
clean-room verifier): both track the same frozen conformance vectors and are
cross-checked in CI; they are listed separately in `scitt-cose` rather than
claimed as third-party implementations.

The INTEROP.md table includes additional rows marked `agreed — scheduled` (runs
coordinated, artifact exchange pending) and one row marked `HOLD` (PermitReceipt
— wording fixed by agreement with the owner). Scheduled and HOLD rows are not
counted as completed runs.

## Building the draft

```bash
# one-time toolchain
gem install kramdown-rfc
python3 -m venv ~/.venvs/x2r && ~/.venvs/x2r/bin/pip install xml2rfc

# build (from spec/)
cd spec && make            # md -> v2 xml -> v3 xml -> txt
make idnits                # expected residuals only (RFC 8785 downref, BCP14, UTF-8)
```

kramdown-rfc emits RFCXML **v2**; the committed `.xml` is RFCXML **v3** (RFC 7991).
The Makefile converts with `xml2rfc --v2v3` — see `spec/Makefile`.

## Provenance, neutrality & governance

This specification was developed by **Action State Group, Inc.** and is published
as an **open specification, intended for contribution to an appropriate standards
body as the ecosystem matures.** The content here is standard-only: the draft,
its registry of record, a reference implementation, and conformance vectors —
nothing product-specific or tenant-specific.

The specification text is an IETF contribution under **BCP 78 / BCP 79**; the
intended venue for discussion is the IETF **SCITT** Working Group
(`scitt@ietf.org`). The change controller for the interim registry is Action
State Group, Inc., transferring to the IETF on RFC publication. No primacy is
claimed; the value is an interoperable, independently-verifiable record format
and a clean transfer path to a neutral home (Working Group adoption or a
foundation donation) whenever that moment arrives.

## License

See [LICENSE](LICENSE): the specification text is governed by BCP 78 and the
IETF Trust's Legal Provisions; code and reference-implementation material are
under the Revised BSD License. Contributions follow [CONTRIBUTING.md](CONTRIBUTING.md)
(DCO sign-off; no CLA).

**Patent posture:** All six provisional patent applications related to this specification were expressly abandoned on July 6, 2026. No license is required. See [agentactioncapsule.org/ip](https://agentactioncapsule.org/ip) for details.
