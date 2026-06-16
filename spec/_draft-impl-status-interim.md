# DRAFT: Implementation Status section — interim (-01 submission, 2026-06-15)
#
# Per RFC 7942.  Insert immediately before Security Considerations in -01.
# Note to self: swap this out for _draft-impl-status-post-go.md once
# Session 2 confirms cross-verifier differential-fuzz results.
# Do NOT commit this file into a filed I-D; copy the section below.
# -----------------------------------------------------------------------

## Implementation Status

{:aside}
Note to the RFC Editor: Please remove this section and the reference to
{{RFC7942}} before publication.

This section records the status of known implementations of the protocol
defined by this specification at the time of posting of this Internet-Draft,
and is based on a proposal described in {{RFC7942}}.  The description of
implementations in this section is intended to assist the IETF in its decision
processes in progressing drafts to RFCs.  Please note that the listing of any
individual implementation here does not imply endorsement by the IETF.
Furthermore, no effort has been spent to verify the information presented here
that was supplied by IETF contributors.  This is not intended as, and must not
be construed to be, a catalog of available implementations or their features.
Readers are advised to note that other implementations may exist.

### agent-action-capsule reference implementation

Organization:
: Action State Group, Inc.

Implementation URL:
: https://github.com/action-state-group/agent-action-capsule
  (Python package on PyPI: `agent-action-capsule`)

Description:
: A BSD-3-Clause Python library providing a Class 1 (payload-only) verifier
  for the Agent Action Capsule profile, together with typed builders, a
  command-line verifier (`agent-action-capsule verify`), and an optional
  two-layer composition path that calls the substrate verifier by reference
  per {{I-D.ietf-scitt-architecture}}.

  The implementation covers: the complete §5 envelope schema (all REQUIRED
  and OPTIONAL fields, absent-field normalization); the `capsule_id`
  content-address computation (JCS canonical form per {{RFC8785}} followed by
  SHA-256); the confirmed-effect binding (check 3); verdict/effect
  orthogonality (check 4); the effect-attestation matrix (check 5); and
  chain semantics (check 6).  The structured result contract (never-raise,
  `ok` boolean, ordered findings) is implemented per Section 8
  ({{verification}}).

  A set of frozen conformance test vectors (positive and negative, covering
  all Class 1 check paths) is included in the repository.  The two-layer
  transparent path (Class 1 payload check + substrate COSE_Sign1 and Receipt
  verification) is available as an optional extra (`agent-action-capsule
  [transparent]`) and is covered by the test suite when the optional
  dependency is present.

Level of maturity:
: Prototype / alpha (version 0.0.1).  Implemented against
  draft-mih-scitt-agent-action-capsule-00.  The implementation is complete
  for Class 1.  A second-runtime cross-check against an independently written
  verifier is in preparation.

Coverage:
: Class 1 verification — complete.  Class 2 verification (manifest-dependent
  material, Section 9 ({{class2}})) — not implemented (manifest discovery is
  out of scope for this release).

Licensing:
: BSD-3-Clause

Contact:
: See the GitHub issue tracker at the implementation URL above.
