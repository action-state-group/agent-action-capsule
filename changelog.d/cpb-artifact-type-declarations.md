- Spec: draft-06 no longer cites a CPB Artifact Type registry, which CPB does not define (#412). It
  declares one artifact type, `agent-action-capsule` (`digest_alg` `"SHA-256"`, `digest` the cited
  Capsule ID), and accepts every other `references[].type` only through a declaration a citing
  profile names by stable normative reference, of which a deployment may accept a subset. The
  verifiers accept only `agent-action-capsule`: check 8 reports a well-formed `references` entry of
  any other type as the new informational finding `reference_type_unresolved` (CPB Unresolved, cause
  `context`). It never rejects, and `ok` does not change. Python, Go and TypeScript report it; the
  vectors `reference-unknown-type-algorithm`, `reference-same-hex-other-type`,
  `reference-unregistered-capsule-token` and the two `pos-provenance-mode-witnessed-corroborated`
  vectors now expect it, the new vector `reference-undeclared-type` pins it, and
  `reference-undeclared-type-malformed` pins that a malformed reference is reported by check 1 only.
- Removed: the vendored CPB registry snapshots (`cpb_registry.json` and `cpb_provisional.json` in
  Python, `cpb_provisional.json` in Go and TypeScript), the `vendor_cpb_registry.py` refresh script,
  the Python `load_cpb_provisional_values` and `find_cpb_provisional` functions, the
  `AAC_CPB_PROVISIONAL_PATH` override, the Go `registries.ProvisionalValues` function, the Go check-8
  `registry_snapshot_unavailable` warning and the check-8 `known_provisional_registry_value` finding
  (#418). CPB does not authorize artifact-type discovery from a registry snapshot. The bundled
  snapshot listed no capsule field values since #602, so it produced that finding for no input; in
  Python, a caller-supplied snapshot through `AAC_CPB_PROVISIONAL_PATH` still could, and no longer
  does.
