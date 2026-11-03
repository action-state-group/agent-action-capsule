- Spec: `evidence-interop/2` fixes the HTTP location of the evidence manifest at
  `/.well-known/evidence-manifest` (§11.4.2, P-70), an additive rule that changes no signing input:
  a `GET` returns the JCS serialization of the same manifest that the A2A `params` and the
  `evidence_manifest` result carry. `evidence-interop/1` stays frozen. The v2 vector
  `carriage-invariance` gains the HTTP copy, and `carriage-manifest-http-differs` and
  `carriage-manifest-http-not-jcs` are new. The IANA well-known registration stays open. Closes #554.
