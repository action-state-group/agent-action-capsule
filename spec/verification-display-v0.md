# Verification Display — v0

**Status.** Design specification, pre-Internet-Draft, beside `spec/evidence-result-v0.md`. This
document defines what a viewer's page states about verification: what "verified" means for a
page, the verification page's check lists and their words, the verification banner, the refusal's
text, and how words a page shows as evidence are bound to the records (evidentiary words and the
`sha256-jcs-nonce256` commitment). It is normative for any viewer that claims to follow it. It
does not define how a page is assembled or which presentation draws it.

Its text was part of `spec/presentation-contract-v0.md`, which is now an informative pointer. The
sections keep that document's numbers, so a citation of its §1 ("Verified"), §6.1, §6.2, §7.1,
§7.2, I1 or I3 reads the same section here. The numbers in between have no section here.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in
BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all capitals.

## 1. Terms

Every term below is used with this meaning throughout this document.

- **Bundle**: an Evidence Bundle (`draft-mih-zhang-agent-disclosure-bundle`): the records, their
  disclosures, a checkpoint, witness receipts, countersignatures and extensions.
- **Record**: one Capsule in a bundle's `records`, identified by its `capsule_id`.
- **Payload**: a record's content, such as its `agent_input` or `agent_output`.
- **Extension**: a member of a bundle's `extensions` object.
- **Disclosure**: a record member's state as the verifier resolved it: `disclosed`, `withheld` or
  `disclosure_mismatch`. A disclosure **match** is a member whose supplied value recomputes to the
  committed digest.
- **Checkpoint**, **witness receipt**, **countersignature**, **graph closure**, **interval
  coverage**, **per-record membership**: as the bundle draft defines them.
- **Producer**: whoever built a bundle or a record.
- **Verifier**: an implementation of the bundle draft's verification. Its **verification result**
  is what it found, and its **strict verdict** is the draft's `valid`, `incomplete` or `invalid`.
- **Viewer**: software that shows a bundle to a person.
- **Runtime** (the rendering runtime): the part of a viewer that verifies a bundle and draws its
  page. "This runtime" is the one that drew the page being read.
- **Core**: the runtime's own code and fixed text, as distinct from a module's: it verifies the
  bundle and draws the banner, the refusal and the verification page.
- **Page**: what a viewer draws for one bundle.
- **Header chrome**: the page's header (a title, the producer's name, a logo), drawn before the
  banner.
- **Banner**: the line at the top of a page that states its verification state (section 6.2).
- **Verification state**: one of the states in section 6.2's table.
- **Details line**: the line under the banner that names the checks behind an incomplete or
  failed verdict (section 6.2).
- **Verification page**: the core's part of a page that lists the checks this runtime ran
  (section 6.1).
- **Check**: one verification step a runtime runs. A **check list** is one of the verification
  page's lists of checks (section 6.1).
- **Full verifier**: a verifier that runs every check a bundle calls for.
- **Module**: a presentation a viewer runs to draw a bundle's content (its records, rows and
  payloads) on a page. A **module region** is the part of the page a module fills.
- **Row**: one line of a table a module draws. A **row model** is a payload shape a module draws
  as rows.
- **Host**: the page or program a viewer runs inside.
- **Refusal**: the core's fixed statement, drawn after the banner, that a bundle's records, rows
  and payloads are not shown (section 8, I1).
- **Verified**: the bundle passed the viewer's verification gate (graph closure, interval
  coverage, per-record membership proven or unbound, every record's identity, every disclosure
  a match or withheld). Today this is `bundleVerified` in `ts/src/verification-page.ts`
  (Go: `bundle.Verified`).
- **Wording pack**: the presentation words a module draws with, identified by the SHA-256 of its
  bytes (`wording_sha256`).
- **Presentation words**: labels, headings, column names, explanations, notices and button text.
- **Evidentiary words**: words a relying party may rely on as what someone said or was shown
  (section 7.1).
- **Relying party**: whoever reads a page to rely on the evidence it shows.
- **Commitment**: a digest a record carries in place of a text. The **opening** is what a
  holder supplies to recompute it.
- **JCS**: the JSON Canonicalization Scheme (RFC 8785).
- **Digest-committed**: covered by a record's digest, so that a change to it changes the record's
  identifier.
- **Theme**, **locale**, **depth**: a viewer's choice of styling, of language, and of how much of
  a page is open.

## 6. What a page states about verification

### 6.1 The verification page's check lists

The core's verification page, drawn after every module and on every page including a refusal,
states which checks the rendering runtime ran. It does so in up to three lists, each derived
from that runtime's own results (its verification result, its countersignature
classification, and what its own page module checked) and never from a claim, status or
summary carried in the bundle:

- **Checked on this page.** Each check this runtime ran that passed.
- **Failed on this page.** Each check this runtime ran that did not pass. A check that fails is
  never listed as checked on this page: editing a record, a disclosed value, a membership entry
  or a countersignature moves its check from the first list to this one.
- **Not checked on this page.** Each check the bundle calls for, by what it carries (a signed
  checkpoint, a signature on a record, a witness receipt, a countersignature of a type the
  runtime does not check, a receipt with a countersignature), that this runtime does not run
  or could not complete. When the runtime passed the bundle without checking the checkpoint's
  signature (the verifier recorded `checkpoint_unverified`), the line says so. The list ends
  with a pointer to verify the bundle with a full verifier, which names no product or command.

A check the bundle does not call for is in no list. An empty list is not drawn. Each line names
what was checked, never its outcome, so it reads true under any of the three headings.

The words are the core's own fixed text. A host MAY supply its own text for running a full
verifier (for example a command line); it is presentation only, shown as text after the
pointer, and it changes no list. Nothing from the bundle reaches the lists' words.

Every extension block the bundle carries, whether or not a presentation reads it, is
reported on the verification page with its integrity and interpretation status.

Two word rules hold for all of the verification page's own text: the lists, the lines around
them and every other row (check names, receipt and countersignature lines). Values the page
shows from the bundle, such as a witness name or a countersigner's statement, are data, not the
page's words.

- **"Verified" is used only for a check the page ran.** A line for a check that is not run
  here never calls it verified. A witness receipt this runtime does not check shows its grade
  as claimed and not checked here (for example "consistency claimed (not checked here)"); the
  grade value itself is unchanged.
- **No line says "identity" or "freshness".** None of these checks establishes who produced the
  records or that the file is the most recent copy, and the page says so in those plain words.

### 6.2 The verification banner

The banner is the first thing a page draws after the header chrome, before any
record. It states exactly one verification state at a time, taken from the rendering
runtime's own result and never from the bundle. Its `data-verify` attribute names the state.
Once the checks have finished, `data-verdict` names the strict verdict of
`draft-mih-zhang-agent-disclosure-bundle` they reached. The state follows that verdict, so it
covers the bundle's own checks: records, signatures, graph closure, the checkpoint, interval
coverage, per-record membership and disclosures. A countersignature or a top-level witness
receipt is not one of them; its line appears in the lists of section 6.1 and never changes the
state, so a countersignature anyone appends cannot turn a verified page into a failed one.

| State | `data-verify` | `data-verdict` | Records shown |
|---|---|---|---|
| checking | `checking` | (absent) | no |
| verified | `verified` | `valid` | yes |
| incomplete | `incomplete` | `incomplete` | yes |
| failed | `failed` | `invalid` | yes, unless the page's own checks refuse them (then the refusal of section 8 follows the banner) |
| unable to verify | `unable` | (absent) | no |

- **checking** is drawn as soon as rendering starts and stays until the checks finish. No
  record, module region or verdict is drawn while it is shown.
- **verified** is drawn only for a `valid` verdict: every one of the bundle's own checks ran on
  this page and passed. A runtime that cannot run one of them (for example, one that cannot
  authenticate the checkpoint) draws **incomplete** instead.
- **failed** is drawn whenever one of the bundle's own checks failed, whether or not the
  records are still shown.
- **unable to verify** means the runtime could not run the checks at all. It is never drawn
  as failed.
- "Records shown" is what the checks allow.
- A presentation failure never changes the banner or its state.

The banner's line for each state, and the details line under it naming the checks behind an
incomplete or failed verdict, are the core's own fixed text, like the lists of section 6.1.
No module, wording pack or bundle supplies, selects or alters them. The banner line names no
internal token. The details line carries the labels the bundle draft requires, such as
`checkpoint_unverified`. `vectors/viewer-core-text/core-text.json` holds the exact
fixed words of each state and of each check-list line, and a viewer's words MUST equal it.

## 7. Words shown as evidence

### 7.1 Evidentiary words

Evidentiary words are words a relying party may rely on as what someone said, saw, approved,
was shown or was told: a user's request, the wording of an authority or mandate, a proposal, an
approval sentence, terms displayed to a party, a representation made by a counterparty.
**Evidentiary words MUST be bound by one of three registered mechanisms**, and a module MUST
display them only after the core has checked the binding:

1. **Digest with an out-of-band opening.** A record commits the digest of the exact text (or
   of the JCS form of the object carrying it); the text, the opening, travels separately, for
   example as a disclosure. The text is shown only when its recomputed digest equals the
   committed one, exactly as a disclosed `agent_input` is shown only on a disclosure match.
2. **Nonce-salted commitment, `commit_alg: "sha256-jcs-nonce256"`** (section 7.2). The record
   carries the commitment and declares the construction; the opening `{nonce, text}` travels
   separately. The text is shown only when the commitment recomputes. Without an opening, the
   page says the text is committed and not opened; it never shows a placeholder as the text.
3. **A separately sealed text record.** The text is the disclosed payload of its own record in
   the bundle, cited by `capsule_id`, and is shown only when that record verified and the
   member is `disclosed`.

**Forbidden: clear text in a digest-committed UI field.** Placing words meant for display
inside a sealed payload, as a label, status or reason field, binds the wrong thing. It seals
presentation words, so changing a heading changes the evidence's identifier (against I3), and it
gives producer-asserted prose the look of a checked result. The cited counter-example is the
`report/v1` row model (`ts/src/report-rows.ts`): each row's `label`, `status` and `reason` are
clear text inside the root's digest-committed `agent_input`, nothing recomputes `status`, and a
change of wording is a change of record. A new row model MUST NOT repeat this; it carries
enumerated states and references, and takes its words from a wording pack. Equally forbidden is
the opposite failure: evidentiary words displayed from a bundle extension no record seals.

### 7.2 `sha256-jcs-nonce256`

This section defines the construction. It is the construction already declared under the same
identifier by an existing public producer profile (capsule-cli's `record-common-v0` schema),
and this definition is intended to be identical to it.

```
commitment = lowercase_hex( SHA-256( JCS( { "nonce": N, "text": T } ) ) )
```

- `N` is 64 lowercase hexadecimal characters encoding 32 bytes from a cryptographically secure
  random source, drawn fresh for each committed text. Uppercase hex is not a valid `N`.
- `T` is the exact text as a JSON string: no Unicode normalization, trimming or case folding
  is applied before committing. JCS serializes it as UTF-8.
- The object has exactly the two members `nonce` and `text`; JCS (RFC 8785) orders them.
- There is no key. The commitment is recomputable only by a holder of the opening `{N, T}`, and
  a guess at `T` cannot be tested without `N`.
- A record declares the construction as `commit_alg: "sha256-jcs-nonce256"` and names its
  commitment members `<name>_commitment`. A verifier recomputes from an opening and compares
  the lowercase hex strings for equality.
- Reusing one nonce for two texts is permitted only where a profile deliberately states that
  equal commitments mean equal text; otherwise it is a producer defect.

## 8. Invariants

- **I1. Failure collapses to the refusal.** A page whose bundle is not Verified draws the
  banner, the refusal and the verification page, and no module content. The refusal's text is
  the core's:
  "This bundle did not verify. Its records, rows and payloads are not shown; the verification
  page below lists which checks failed."
- **I3. Theme, wording, locale and depth never change evidence identifiers.** The bundle
  digest, every `capsule_id`, every disclosure digest, `composed_digest` and every identifier
  inside a payload are the same whatever theme, wording pack, locale or depth renders them.
  None of those four is ever inside a digest-committed payload of the evidence.

## 10. Conformance

- A viewer conforms when its words equal `vectors/viewer-core-text/`, and it satisfies sections
  6.1, 6.2, 7.1 and 8.
- A producer or verifier that uses `sha256-jcs-nonce256` conforms when it computes and compares
  the commitment as section 7.2 states.
