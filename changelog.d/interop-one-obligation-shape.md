- Spec: `evidence-interop/2` gives the Evidence Contract's obligation profile one shape, the native,
  pack-declared one (`spec/interop-profile-v2.md` §11.3.2, P-71, AAC#568). EC is re-pinned to
  `schemas/evidence-contract-v0.json` (SHA-256
  `bf9a1cdee27c8cf6d35b2371fe3b778cf5e1db671dd9c4bce9f503e8842cb78b`), which drops
  `requirementObligationGeneric`, so an obligation cited only by `clause_ref` is refused. The
  outcome profile keeps both shapes. `evidence-interop/0` and `/1` keep the capsule-engine pin.
  The two v2 corpora record the new pin (their contracts are unchanged), and
  `vectors/evidence-contract-obligation/` adds three cases: native obligation accepted, abstract
  obligation refused, abstract outcome accepted.
