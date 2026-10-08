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
`judge_parameters_digest`, and, for a model judge, `model_hosting` with the optional
`model_reference` and `model_digest` (§2). Base fields keep their
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

**`model_hosting` is checkable through the identity ladder (§2).** A `hosted` record cannot
carry `model_digest`. A `self_hosted` record without `model_digest` sits at rung 1 or 2, and
is visibly weaker than one that carries it. A reader can see the difference from the record
alone, without trusting the producer's hosting claim.

## 2. Model identity

### 2.1 The identity ladder

A judgment record can identify the model that produced it at one of four rungs. Each rung
proves strictly more than the one below it.

| Rung | Carried by | What it proves |
|---|---|---|
| 1. Name | `developer` (`model_id`, §2.2) | Nothing about bytes. A name is not proof of the bytes served: a proxy or a mis-deployed host can serve a different model under the same name. |
| 2. Reference | `model_reference` (optional) | Which artifact was **named**, for example a repository, a revision and a file. It does not prove which bytes were loaded. |
| 3. Loaded bytes | `model_digest` (optional) | Which bytes the producer **says** it loaded: lowercase-hex SHA-256 over the raw bytes of the model file actually loaded. Anyone holding a file can check it against this digest. |
| 4. Above self-report | outside this member | That the reported bytes are the bytes that ran: a trusted execution environment with a load hook, or an independent referee. |

**Rung 3 is still self-reported.** A producer can report a digest for a file it did not load.
`model_digest` therefore makes a judgment **re-derivable in principle**, not proven. Text,
renderings and verifiers MUST NOT describe a rung 3 record as proven, verified or attested
model identity. Only rung 4 is above self-report, and this member does not carry rung 4.

**Absent is absent.** A producer that did not compute, or could not compute, a digest of the
loaded bytes omits `model_digest`. It never writes a zero, an empty string or any other
placeholder. The same applies to `model_reference`. The schema rejects an empty value, an
all-zero digest and an empty or blank reference. A renderer shows an absent field as absent,
never as a zero or an empty value. This is the same discipline as `not_evaluable`: an honest
absent fact, never a fabricated one.

**Rules.**

- `model_digest` requires `model_hosting`. A record with `model_hosting: hosted` MUST NOT carry
  `model_digest`, because nobody outside a hosted endpoint holds the loaded bytes. A hosted
  judgment is therefore at rung 1 or 2. That is why it is attributable and not re-derivable
  (§1), and it follows from the data, not from an assertion.
- A model judgment at rung 1 or 2 is `judged` (Result v0 `tier`) at best. It never supports
  `recomputed`.
- `recomputed` REQUIRES rung 3. Rung 3 is necessary, not sufficient: sampling, batching and the
  other `judge_parameters_digest` inputs still bear on whether a verdict re-derives. This
  document does not say when a judged verdict becomes `recomputed`. It says only that, below
  rung 3, it cannot.
- The model file is a single file. A model loaded from several files is out of scope for v1.

**Relation to existing vocabulary, which this document does not redefine.** `tier`
(`recomputed | judged`) keeps its meaning from `evidence-result-v0.md` §1. The ladder only
constrains which `tier` a model judgment's evidence can support. A claim's `grade`
(`self-attested | witnessed | countersigned`) attests the bundle that carries the record. A
`witnessed` or `countersigned` grade moves no record up the ladder, and does not make a
`hosted` verdict re-derivable.

### 2.2 Model identifier (`developer`)

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
| `model_id` | string, verbatim | `developer` (base) | string: `model_id` or `model_id@version` (§2.2) | **value-level**. Outside any digest except `capsule_id`. |
| `model_hosting` | closed set `hosted \| self_hosted` | `x-judgment-v1.model_hosting` | same closed set; absent on a model-judge record reads as `hosted` (§1) | **value-level, exact**. |
| `model_digest` (optional) | lowercase-hex SHA-256 over the raw bytes of the model file | `x-judgment-v1.model_digest` (optional) | same method, over the file actually loaded (§2.1) | **digest-level, equal, when both carry it.** If the declaration carries it and the record does not, the join fails: the record does not show the declared bytes. If only the record carries it, it is not part of the join. A hosted declaration or record never carries it. |
| *(no member)* | | `x-judgment-v1.model_reference` (optional) | reference string (§2.1, rung 2) | **No pack counterpart.** |
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
only if all six checks hold:

1. `JSON-DIGEST(P)` equals `M.judge_parameters_digest`.
2. `P.instruction_template_digest` equals `D.prompt_template_hash`.
3. `D.schema_hash` equals the answer schema digest (§3).
4. `C.developer` equals `D.model_id`, or begins with `D.model_id` followed by `@`.
5. `M.model_hosting` (or `hosted`, if absent) equals `D.model_hosting`.
6. If `D.model_digest` is present, `M.model_digest` is present and equal to it.

Checks 1 to 3 and 6 are digest-level. Checks 4 and 5 are value-level. When check 6 applies,
the join reaches rung 3, which is still self-reported (§2.1). A pass establishes
**attribution**, not re-derivation (§1). It says nothing about the rubric, the sampling
parameters or the fields read, which the declaration does not pin (§4.1). A human-expert record
never joins a judge declaration: check 1 fails on shape, because its preimage is
`ExpertProtocolParameters`.
