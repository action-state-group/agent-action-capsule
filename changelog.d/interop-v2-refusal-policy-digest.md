- Spec: `evidence-interop/2` (`spec/interop-profile-v2.md`, AAC#438), written as the difference from
  `evidence-interop/1`, which is frozen at commit `5c2d42bc`. A refusal MAY carry `policy_digest`,
  the SHA-256 of the policy its responder declares, and under `evidence-interop/2` the refusal's
  signature covers it when present (§6.3, P-69). Without one the signing input is the ERV A7
  bytes. A refusal is checked under the identifier its request asks for, so `evidence-interop/0`
  and `/1` refusals, and every `/1` verifier, are unchanged: a `policy_digest` beside an A7 refusal
  binds nothing. 72 vectors in `vectors/interop-profile-v2/` (ten new: signed, absent, tampered,
  stripped, unsigned and malformed `policy_digest`, a `/1` refusal that still verifies, with and
  without an unsigned `policy_digest`, the v2 signing input answering a `/1` request, and a signed
  `policy_digest` checked by a `/1`-only verifier) and 2 in
  `vectors/interop-profile-v2-requirement-facts/`.
- Python: the interop verifier implements `evidence-interop/2` (`PROFILE_V2`); `sign_refusal` takes
  `policy_digest` and `profile`, and `check_refusal`, `check_refusal_cbor`,
  `verify_refusal_offline` and `Refusal.signing_body` take the `profile` the request asked for
  (`refusal_signed_members`). `parse_reply` keeps a refusal's `policy_digest`. Defaults are
  unchanged.
