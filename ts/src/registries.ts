/** Seed registries from draft-04. Unknown values remain informational. */
export const registries = Object.freeze({
  verdict_class: new Set([
    "executed",
    "blocked",
    "hitl_dispatched",
    "denied",
    "timeout",
    "errored",
    "engine_failure",
    "deferred",
    "needs_decision",
    "expired",
    "escalated",
    "resolved",
    "epoch_boundary",
  ]),
  "disposition.decision": new Set([
    "accept",
    "reject",
    "needs_input",
    "deferred",
  ]),
  "effect.type": new Set(["write_order", "send_payment"]),
  irreversibility_class: new Set([
    "two_way",
    "one_way_recoverable",
    "one_way_consequential",
    "one_way_terminal",
  ]),
  effect_attestation: new Set(["gate_executed", "runtime_claimed"]),
  "chain.relation": new Set(["confirms", "supersedes", "epoch_opens"]),
  citation_purpose: new Set(["acted_on", "responds_to"]),
});

/** Disclosure Envelope member to committed Capsule field path. */
export const disclosureEligibleFields = Object.freeze({
  agent_input: "model_attestation.compute_attestation.agent_input_digest",
  agent_output: "model_attestation.compute_attestation.agent_output_digest",
});

export type RegistryName = keyof typeof registries;
