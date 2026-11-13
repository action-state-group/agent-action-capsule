# draft-mih-scitt-agent-action-capsule-04: edits made after posting

This note is non-normative. It records text that was edited into the repository
copy of `-04` after that revision was posted, and that has since been removed so
the repository again holds the posted bytes.

## What is in `spec/` now

`spec/draft-mih-scitt-agent-action-capsule-04.{md,xml,txt}` are the bytes of
commit `7e112c8b877ad79d4d2a53be7b522a63470a2b1d` (2026-08-28), the as-posted
source. The `.xml` and `.txt` are byte-identical to the Datatracker copies:

| File | sha256 (repository and Datatracker) |
|---|---|
| `draft-mih-scitt-agent-action-capsule-04.txt` | `4684a1d7f9331a421ec821b72e4b127d055a121af66c5092becead7d45ac7db6` |
| `draft-mih-scitt-agent-action-capsule-04.xml` | `3f6a785bda995fab7040f4d68fe90c860ed33a96528e2cb653c0ba9d1b838ea7` |

Datatracker sources: <https://www.ietf.org/archive/id/draft-mih-scitt-agent-action-capsule-04.txt>
and <https://www.ietf.org/archive/id/draft-mih-scitt-agent-action-capsule-04.xml>
(submitted 2026-08-28 as `.xml`).

Posted `-04` keeps the vintage format-2 / `jcs-n` Capsule-ID verification path.
The "Changes from draft-mih-scitt-agent-action-capsule-04" appendix of `-05`
describes that path as removed in `-05`, which is correct against the posted
text.

## The two post-posting edits

| Commit | Date | Change to `-04` |
|---|---|---|
| `f71c12bafb7997557a9687ef38af42d60148d759` | 2026-09-12 | Added the "Why the digest is the identity" rationale to Cross-record references; the rebuild also refreshed the cited I-D.sato-soos-gar reference. |
| `9b3b075ec4bda9e83e4fb8c8a9e606d631756dd2` (#99) | 2026-09-15 | Made format 4 the only format and removed the vintage format-2 / `jcs-n` path; scoped committed payload digests to `UTF8(JCS(value))` with no key filtering at any depth; removed local-only `signature` and `key_id` before computing `capsule_id`; typed `log_coordinates.leaf_index` as a zero-based JSON integer. |

Neither change was posted as `-04`. Both were carried forward into `-05`, which
is where the text now lives:

| Text | `-05` section |
|---|---|
| Format 4 is the sole supported format; payload digest over the whole JCS value | Conventions and Definitions (`{#conventions}`) |
| `capsule_id` after removing local-only `signature` and `key_id` | Identity and parties (`{#identity}`) |
| Why the digest is the identity | Cross-record references (`{#xref}`) |
| `leaf_index` is a zero-based JSON integer | Retention declarations (`{#retentiondecl}`) |

## The removed `-04.md` text

The diff below runs from the as-posted source to the repository `-04.md` as it
stood before this restore (the result of both commits above). Lines marked `+`
were never in posted `-04`.

```diff
diff --git a/spec/draft-mih-scitt-agent-action-capsule-04.md b/spec/draft-mih-scitt-agent-action-capsule-04.md
index e9a7247..f3885d4 100644
--- a/spec/draft-mih-scitt-agent-action-capsule-04.md
+++ b/spec/draft-mih-scitt-agent-action-capsule-04.md
@@ -200,18 +200,28 @@ Verifier:
   Producer. Verifier conformance is split into two classes
   ({{conformance}}).
 
-New Capsules compute JSON digests with plain JSON Canonicalization Scheme
-(JCS) {{RFC8785}} and declare `canonicalization_id: "jcs"`. No absent-field
-normalization is applied: `null`, empty arrays, and empty objects participate
-when present. JSON floating-point values are forbidden in digest-bearing
-material, and integers outside the IEEE-754 safe range MUST be represented as
-decimal strings.
-
-The withdrawn `jcs-n` construction of
-{{I-D.mih-sokolov-scitt-payload-binding}} remains only as a vintage
-Capsule-ID verification path. It is selected by a format-2 Capsule in which
-`canonicalization_id` is absent. A producer MUST NOT emit `jcs-n`, and a
-verifier MUST reject any explicit `canonicalization_id: "jcs-n"` declaration.
+Format 4 is the sole supported format for producers and verifiers. A
+conforming Capsule MUST declare `format_version: "4"` and
+`canonicalization_id: "jcs"`. A producer or verifier MUST check both
+declarations before computing any digest. Capsules compute JSON digests with
+plain JSON Canonicalization Scheme (JCS) {{RFC8785}}. `null`, empty arrays,
+and empty objects participate when present. JSON floating-point values are
+forbidden in digest-bearing material, and integers outside the IEEE-754 safe
+range MUST be represented as decimal strings.
+
+A committed payload digest, including `agent_input_digest`,
+`agent_output_digest`, `response_digest`, and `evidence_digest`, is the
+lowercase-hex SHA-256 digest of `UTF8(JCS(value))` for the entire JSON value
+being committed. JCS property sorting applies recursively to every object in
+that value. A producer or verifier MUST NOT apply an object-member allow-list,
+replacer array, or other key-filtering operation at any depth before JCS; all
+members of every nested object participate in the digest.
+
+Any other `format_version`, or an absent, null, non-string, empty, unknown, or
+`"jcs-n"` `canonicalization_id`, MUST fail closed for producers and verifiers.
+Pre-format-4 Capsules and the withdrawn `jcs-n` construction of
+{{I-D.mih-sokolov-scitt-payload-binding}} are out of scope for this document
+and are not verifiable under it.
 
 # Producer Envelopes and SCITT registration {#projection}
 
@@ -318,9 +328,9 @@ detail is specified in {{constraints}}.
 | Field | Type | Req | Meaning |
 |---|---|---|---|
 | spec_version | string | REQUIRED | The profile prose version the Capsule conforms to. The value defined by this profile version is "draft-mih-scitt-agent-action-capsule-04". |
-| format_version | string | REQUIRED | The serialization-suite version. New Capsules use "4". Vintage format-2 Capsules remain verifiable only under the compatibility rule below. |
-| canonicalization_id | string | REQUIRED for format 4; MUST be absent for format 2 | New Capsules MUST carry exactly "jcs". Explicit "jcs-n", empty, null, non-string, and unknown declarations are invalid. |
-| capsule_id | string (64 lowercase hex) | REQUIRED | The derived identifier. For format 4, compute SHA-256 over plain JCS of the Capsule with only `capsule_id` removed. The `canonicalization_id` declaration and `chain` block participate. Verifiers MUST recompute; carried values MUST NOT be trusted. |
+| format_version | string | REQUIRED | The serialization-suite version. The value MUST be exactly "4". |
+| canonicalization_id | string | REQUIRED | The value MUST be exactly "jcs". Absent, null, non-string, empty, unknown, and `"jcs-n"` declarations are invalid. |
+| capsule_id | string (64 lowercase hex) | REQUIRED | The derived identifier. Remove local-only `signature` and `key_id` envelope fields, if present in a local composite representation, then compute SHA-256 over plain JCS of the Capsule after removing only `capsule_id`. The `canonicalization_id` declaration, `chain` block, and `references` array participate. Verifiers MUST recompute; carried values MUST NOT be trusted. |
 | action_id | string | REQUIRED | Stable identifier of the action; unique within one producer ledger. |
 | action_type | string | REQUIRED | "fyi" (informational) or "decide" (a disposition was required). |
 | operator | string | REQUIRED | The accountable tenant the action was performed for. |
@@ -328,11 +338,6 @@ detail is specified in {{constraints}}.
 | timestamp | string | REQUIRED | {{RFC3339}} UTC with "Z" suffix. |
 | epoch_id | string | OPTIONAL | An operator-assigned epoch identifier, stable within one operational configuration of the agent system. Producers SHOULD populate this field and rotate its value — together with an epoch-boundary Capsule ({{epochs}}) — when a configuration change that materially alters agent behavior occurs (for example, a model-version swap, a policy-manifest revision, or a significant constraint-schema change). A verifier or ledger consumer scopes a history window to a specific operational configuration by filtering on operator and epoch_id. Absent epoch_id implies a single, unnamed epoch; a producer MUST NOT back-fill epoch_id on Capsules already sealed. |
 
-For a vintage format-2 Capsule, `canonicalization_id` MUST be absent. Its
-Capsule ID is verified by removing `capsule_id` and `chain`, applying the
-legacy absent-field normalization, then applying JCS and SHA-256. This path is
-verification-only. A producer MUST NOT emit a new format-2 Capsule.
-
 Monetary and quantity values are subject to the exact-decimal-string
 requirement in {{conventions}}.
 
@@ -396,10 +401,9 @@ verification failure (an epoch change mid-stream is not structurally
 non-conforming), but it is evidence that a configuration boundary occurred
 without a corresponding epoch-boundary Capsule.
 
-For format 4, the `chain` block participates in `capsule_id`. Changing a
-parent identifier or relation after sealing therefore changes the recomputed
-identity and invalidates every Producer Envelope over the prior Capsule ID.
-Only vintage format-2 verification excludes `chain`.
+The `chain` block participates in `capsule_id`. Changing a parent identifier
+or relation after sealing therefore changes the recomputed identity and
+invalidates every Producer Envelope over the prior Capsule ID.
 
 ## Effect Record and the confirmed-effect binding {#effect}
 
@@ -774,13 +778,41 @@ external-authorization references of the Effect Record ({{effect}}).
 document defines the `references` entry shape, not an exhaustive list
 of what may be cited.
 
+**Why the digest is the identity.** A reference whose identity is a
+name — a URI, a record identifier, a position in some other party's
+system — can be resolved tomorrow to bytes that differ from the bytes
+the citing producer saw. The name survives; the content moves beneath
+it. A citation that can drift is worse than no citation, because it
+presents as evidence while guaranteeing nothing about what it points
+to. Resolvability and unchangedness are two different promises, and
+only a digest can make the second one. This profile therefore makes
+the digest the identity and treats every locator as a route to it
+rather than as the reference itself.
+
+This rule is this profile's own and predates its generalization.
+{{I-D.mih-sokolov-scitt-payload-binding}} supplies the typed reference
+mechanism that CPB profiles share; the requirement that a cited
+artifact be identified by content rather than by name originates here.
+
+This profile states no availability or retention obligation for a
+cited artifact. Content-derived addressing establishes that bytes,
+once obtained, are the bytes cited; it cannot establish that any party
+will serve them. An availability undertaking is a separate claim with
+a named obligated party and an expiry, and belongs to whatever profile
+carries the locator.
+
 A reference MAY additionally carry `log_coordinates`, an object
 `{log_id, leaf_index, inclusion_proof}`, present as a unit when the
 cited record has been registered to an append-only log a verifier can
-consult. `log_coordinates` is an upgrade, not a second identity: it
-proves the exact referenced bytes were found at the stated log
-position, and its presence or absence never changes what `type` +
-`digest_alg` + `digest` already identify. Producer-local log
+consult. `leaf_index` MUST be a JSON integer, not a string. It is the
+zero-based MMR leaf index for which `inclusion_proof` was computed, not the
+one-based CLL log-entry sequence number. When a log exposes a one-based
+sequence number `seq`, the producer MUST encode `leaf_index` as `seq - 1`.
+The outer `leaf_index` MUST agree with the index used by the enclosed
+`inclusion_proof`; a proof for any other index is non-conforming.
+`log_coordinates` is an upgrade, not a second identity: it proves the exact
+referenced bytes were found at the stated log position, and its presence or
+absence never changes what `type` + `digest_alg` + `digest` already identify. Producer-local log
 checkpointing is future scope at the CPB binding layer, not this
 document ({{future}}); until that mechanism is specified, a Class 1
 verifier treats a present `log_coordinates` member as structurally
@@ -852,13 +884,13 @@ Capsules; no other input is needed. A verifier MUST return a structured
 result, never throw; a single `ok` boolean gates trust in every other
 reported field; findings are reported in a fixed order.
 
-1. Structural: REQUIRED fields present and typed; no floating-point
-   values in digest-bearing fields; format 4 requires exactly
-   `canonicalization_id: "jcs"`; format 2 requires the field to be absent;
-   unknown formats and all other declarations fail closed.
-2. Identity: for format 4, remove only `capsule_id` and compute SHA-256 over
-   plain JCS. For vintage format 2, remove `capsule_id` and `chain`, apply
-   absent-field normalization, then JCS and SHA-256. Compare the result with
+1. Structural: REQUIRED fields present and typed; `format_version` is exactly
+   the string `"4"`; `canonicalization_id` is exactly the string `"jcs"`; and
+   no floating-point values occur in digest-bearing fields. Any other format
+   or canonicalization declaration fails closed.
+2. Identity: remove local-only `signature` and `key_id` envelope fields, if
+   present in a local composite representation, and remove only `capsule_id`
+   from the Capsule. Compute SHA-256 over plain JCS and compare the result with
    the carried `capsule_id`.
 3. Confirmed-effect binding: `effect.status: "confirmed"` without a
    well-formed `response_digest` is a failure ({{effect}}).
```
