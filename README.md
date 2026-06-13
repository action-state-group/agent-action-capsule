# agent-action-capsule

An **open specification** for recording — and independently verifying — what an
AI agent actually did. The **Agent Action Capsule** is a SCITT statement profile:
a digest-committed, signed record of one agent action carrying its verdict-level
disposition (executed, blocked, denied, errored, timed out), the deterministic
constraints that were evaluated, the effect that was committed together with a
confirmed-effect binding that distinguishes a *dispatched attempt* from an
*observed result*, and an honest human-in-the-loop flag.

Capsules are expressed as SCITT Signed Statements (COSE_Sign1) and made
transparent by registration in a SCITT Transparency Service. A Capsule is
recorded on **every** verdict, including refusals — a blocked or denied Capsule
is the auditor-grade evidence that a gate worked.

> **Status / standards honesty.** This is an **individual** IETF Internet-Draft,
> not a Working Group document, and not an RFC. The substrate it builds on (the
> SCITT architecture and COSE Receipts) are themselves Internet-Drafts in the
> RFC Editor Queue, not published RFCs. No RFC number is claimed; no WG adoption
> is claimed.

## The draft

- **Datatracker:** https://datatracker.ietf.org/doc/draft-mih-scitt-agent-action-capsule/
- **Editor's source (this repo):** [`spec/draft-mih-scitt-agent-action-capsule-00.md`](spec/draft-mih-scitt-agent-action-capsule-00.md)
  (kramdown-rfc source), with built [`.xml`](spec/draft-mih-scitt-agent-action-capsule-00.xml)
  (RFCXML v3) and [`.txt`](spec/draft-mih-scitt-agent-action-capsule-00.txt).
- **Registry of record:** [`spec/REGISTRY.md`](spec/REGISTRY.md) — the interim
  registry for the six profile vocabularies until IANA registries are
  established on RFC publication.
- **Reader's guide:** [`spec/section-map.md`](spec/section-map.md).

The authoritative version of the draft is the one on the Datatracker; the `.md`
here is the editor's source from which it is built.

## Repository layout

```
spec/            the Internet-Draft (.md source + built .xml/.txt), REGISTRY.md,
                 section-map.md, Makefile
python/          reference library (capsule parse + verify) -> PyPI agent-action-capsule
test-vectors/    conformance vectors (frozen bytes; the scitt-cose pattern)
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
Agent Action Capsule is one example consumer that defines the
statement/claim semantics carried *inside* that payload. Substrate verification
(the COSE_Sign1 signature, registration, the Receipt's inclusion proof) is
SCITT's and is verified by reference; the agent-domain checks defined in this
draft are the part that is specific here.

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
