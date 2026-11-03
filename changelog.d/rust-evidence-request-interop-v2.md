<!-- changelog: rust/evidence-request/CHANGELOG.md -->
- **`evidence-interop/2`** (`spec/interop-profile-v2.md`, AAC#438): `envelope::PROFILE_V2`, now in
  `envelope::PROFILES` and `acceptance::PROFILE_IDS`, with `/1`'s envelope, acceptance records,
  CLL material and ten §9.1 tokens. A refusal MAY carry `policy_digest`, signed under `/2` (v2
  §6.3, P-69): `refusal::sign_with_profile` takes the identifier the request asked for, an optional
  `detail` and an optional `policy_digest`, and refuses a `policy_digest` under any other
  identifier (`SignError::PolicyDigestProfile`) or one that is not 64 lowercase hex
  (`SignError::PolicyDigest`). `refusal::check_for_profile`, `check_cbor_for_profile`,
  `verify_for_profile` and `verify_for_profile_cbor` check a refusal under the identifier its
  request asked for: under `/2` a `policy_digest` present is signed and must be a digest; under
  `/0` and `/1` it is outside the signature; under an identifier the crate does not implement, the
  signature passes over either signing input. `refusal::signed_members`, `SIGNED_MEMBERS_V2` and
  `signing_body_for_profile` give the signing input per identifier. `sign`, `sign_with_detail`,
  `check`, `check_cbor`, `verify_for` and `verify_for_cbor` keep the A7 signing input.
  `envelope::parse_reply` keeps a refusal's `policy_digest` and refuses a byte string there.
  Breaking: `Refusal` gains the public field `policy_digest`, `SignError` two variants, and
  `envelope::PROFILES` and `acceptance::PROFILE_IDS` become `[&str; 3]`. The tests run
  `vectors/interop-profile-v2/` (envelopes, acceptance, `anchor_inclusion`, and the
  `refusal_signature` verdict of its ten refusal cases).
