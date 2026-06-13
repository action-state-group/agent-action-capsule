# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities **privately**:

- **GitHub:** use *Security → Report a vulnerability* on this repository
  (GitHub private vulnerability reporting), or
- **Email:** security@actionstate.ai with `[agent-action-capsule security]` in
  the subject.

Please do not open a public issue for a suspected vulnerability. We aim to
acknowledge reports within 72 hours.

## Scope

- The reference implementation under `python/` (capsule parse + verification).
- The conformance vectors under `test-vectors/` (a vector that should fail
  verification but passes, or vice versa, is in scope).

A *cryptographic or verification bypass* — a capsule that verifies but should
not, a confirmed-effect binding that can be forged, or a parser memory-safety /
resource-exhaustion issue — is the highest-priority class.

## Specification issues

Ambiguities, under-specifications, or honest-but-misleading prose about
standards status in the Internet-Draft are not security vulnerabilities — raise
those as public issues, or on the SCITT mailing list. This project treats
standards honesty as a correctness property.

## Supported versions

The latest revision of the draft and the latest released reference
implementation receive fixes.
