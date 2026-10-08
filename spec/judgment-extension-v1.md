# Judgment extension v1 (`x-judgment-v1`)

**Status: PROVISIONAL.** Held for ratification and not registered. The digest rules for
`rubric_digest` and `judge_parameters_digest` are proposed and unratified, and so is
everything this document adds.

**Companion schema.** `schemas/judgment/judgment-extension-v1.json`.
**Vectors.** `vectors/judgment/` (members, digest rules, and cases in `vectors/judgment/README.md`).
Where this document and the schema disagree, this document governs and the schema is corrected
to match.

A Capsule that records a judgment, by a model judge or a human expert, carries one member at
`/model_attestation/compute_attestation/x-judgment-v1`: `rubric_digest`, `rubric_version`,
`judge_parameters_digest`, and, for a model judge, `model_hosting`. Base fields keep their
meaning: `developer` is the judge, `agent_output_digest` binds the judge's answer
`{verdict, rationale}`, and `references[]` carries exactly one `judged_from` entry.

JSON-DIGEST is the base profile's rule: lowercase-hex SHA-256 of `UTF8(JCS(value))` (RFC 8785),
with no member filtering at any depth. RAW-DIGEST, in this document, is lowercase-hex SHA-256 of
a published file's raw bytes.

The key words MUST, MUST NOT, SHOULD and MAY are to be interpreted as described in BCP 14
(RFC 2119, RFC 8174) when, and only when, they appear in all capitals.

## 1. Model hosting

`model_hosting` states where the model named by `developer` ran. Its values are the closed set
a pack's judge declaration uses:

| Value | Meaning |
|---|---|
| `hosted` | The model was reached through another party's endpoint. The producer holds neither its weights nor any guarantee that the model behind the name stays the same. |
| `self_hosted` | The producer runs the weights. Whether the weights are published, so that a stranger could run them, is not stated by this value. |

- A model-judge record (one whose published judge-parameters preimage is a `JudgeParameters`
  object) MUST carry `model_hosting`. A human-expert record MUST NOT.
- A verifier that finds `model_hosting` absent on a model-judge record MUST treat the judgment
  as `hosted`. An unstated hosting claim is read as the weaker one.
- `model_hosting` sits in the member, **outside** `judge_parameters_digest`. That digest
  excludes the judge's identity so that the same parameters can be compared across judges.
  Hosting describes the judge, not how the judge was asked. It is committed by `capsule_id`
  like every other member.

**Hosted means attributable, not re-derivable.** A `hosted` judgment is attributable: a
verifier can check that the record names the declared judge and that every published preimage
recomputes. It is not re-derivable: nobody outside the endpoint's operator can run the same
model again, and the name can stay fixed while the model changes. Therefore:

- A consumer MUST NOT treat a `hosted` judgment's verdict as sufficient on its own to refuse an
  action. It MAY treat that verdict as grounds to ask for review.
- `self_hosted` does not by itself make a judgment re-derivable by a stranger. A judgment is
  re-runnable by whoever holds the weights. As with every judgment, it is never reproducible
  (vectors README: "re-runnable, not reproducible").

**Relation to existing vocabulary, which this document does not redefine.** A claim whose
evidence is a judgment record has Result v0 `tier: judged` whatever its hosting
(`evidence-result-v0.md` §1). `model_hosting` refines what `judged` can mean for re-derivation;
it never changes a claim's `tier`. The claim's `grade` (`self-attested | witnessed |
countersigned`) attests the bundle that carries the record. A `witnessed` or `countersigned`
grade does not make a `hosted` verdict re-derivable.

## 2. Model identity (`developer`)

For a model judge, `developer` MUST be `model_id` or `model_id "@" version`, where:

- `model_id` is the model identifier exactly as a pack's judge declaration names it, byte-equal
  with no case folding or other normalization, and contains no `@`;
- `version` is the producer's version label for the model as called, when it has one.

For a human expert, `developer` is a role or pseudonymous rater label, never a personal name or
contact identifier.

`judge_parameters_digest` deliberately excludes the judge's identity. The join on the model is
therefore **value-level (a string match), not digest-level**: `developer` equals the declared
`model_id`, or begins with the declared `model_id` followed by `@`. A pack's judge declaration
does not pin a version, so a `hosted` model can change behind a matching `model_id` (§1).

## 3. Answer schema

The answer schema of every `x-judgment-v1` record is `$defs/JudgeAnswer` in the companion
schema: `{verdict, rationale}`, with `verdict` in `met | not_met | not_evaluable`. It is fixed by
the member name, so the record carries no answer-schema field. The **answer schema digest** is
the JSON-DIGEST of the `$defs/JudgeAnswer` value as published in
`schemas/judgment/judgment-extension-v1.json` at the member's version.

The axes file (`axes_digest`, a RAW-DIGEST inside `judge_parameters_digest`) is not the answer
schema. It names what the judge is asked to assess, which is part of how the judge was asked.

## 4. Correspondence with a pack's judge declaration

A pack obligation that a judge answers carries a **judge declaration**. It is forward-looking:
"this obligation is answered by a judge named thus". An `x-judgment-v1` record is
backward-looking: "this judge, with these parameters, produced this verdict". The two are kept
separate and are never merged. This section states how a third party joins them, to answer one
question: **was this recorded judgment produced by the judge the pack declared?**

The judge declaration's members are `model_id`, `prompt_template_hash`, `schema_hash`,
`input_refs` and `model_hosting` (`hosted | self_hosted`).

### 4.1 Join table

| Pack judge declaration | Pack method | Record member | Record method | Join |
|---|---|---|---|---|
| `model_id` | string, verbatim | `developer` (base) | string: `model_id` or `model_id@version` (§2) | **value-level**. Outside any digest except `capsule_id`. |
| `model_hosting` | closed set `hosted \| self_hosted` | `x-judgment-v1.model_hosting` | same closed set; absent on a model-judge record reads as `hosted` (§1) | **value-level, exact**. |
| `prompt_template_hash` | JSON-DIGEST of the instruction template object, as published, before interpolation | `JudgeParameters.instruction_template_digest`, reached by recomputing `judge_parameters_digest` from the published `JudgeParameters` | JSON-DIGEST of the same object | **digest-level, equal**. |
| *(no member)* | | `JudgeParameters.prompt_digest` | RAW-DIGEST of the published judge prompt file | **No pack counterpart.** MUST NOT be compared with `prompt_template_hash`. |
| `schema_hash` | JSON-DIGEST of the answer schema | *(no member)*: the answer schema digest (§3), fixed by the member name | JSON-DIGEST of `$defs/JudgeAnswer` | **digest-level, against a constant**. |
| *(no member)* | | `JudgeParameters.axes_digest` | RAW-DIGEST of the published axes file | **No pack counterpart.** |
| `input_refs` | list of action field names | *(no member)* | | **Not joinable.** `judged_from` names the evidence by digest, not which of its fields the template read. |
| *(no member)* | | `JudgeParameters.sampling_params`, `min_confidence_micros`, `judge_batch` | inside `judge_parameters_digest` | **Not declared by the pack**, so any value is consistent with the declaration. |
| *(no member)* | | `rubric_digest`, `rubric_version` | JSON-DIGEST of the rubric document; label | **No pack counterpart.** The declaring obligation is identified by the pack's own digest, not by `rubric_digest`. |

The template object is whatever object the judge publishes as its instruction template. Its
shape is producer-defined. The pack's `prompt_template_hash` and the record's
`instruction_template_digest` MUST be JSON-DIGESTs of the same published object. An
implementation that calls its own template-object digest `prompt_digest` computes the value
that joins with `instruction_template_digest`, not with this extension's `prompt_digest`.

Neither digest preimage carries the action's content. `instruction_template_digest` and
`prompt_template_hash` cover the template before interpolation. `prompt_digest` and
`axes_digest` cover published files. An interpolated prompt never enters either side.

### 4.2 Procedure

Given a judge declaration `D`, a judgment Capsule `C` whose member is `M`, and the published
`JudgeParameters` `P` behind `C`, a verifier reports **"produced by the declared judge"** if and
only if all five checks hold:

1. `JSON-DIGEST(P)` equals `M.judge_parameters_digest`.
2. `P.instruction_template_digest` equals `D.prompt_template_hash`.
3. `D.schema_hash` equals the answer schema digest (§3).
4. `C.developer` equals `D.model_id`, or begins with `D.model_id` followed by `@`.
5. `M.model_hosting` (or `hosted`, if absent) equals `D.model_hosting`.

Checks 1 to 3 are digest-level. Checks 4 and 5 are value-level. A pass establishes
**attribution**, not re-derivation (§1). It says nothing about the rubric, the sampling
parameters or the fields read, which the declaration does not pin (§4.1). A human-expert record
never joins a judge declaration: check 1 fails on shape, because its preimage is
`ExpertProtocolParameters`.
