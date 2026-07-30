# Agent Action Capsule — Regulatory Property Crosswalk

> **Informative only. Not legal advice.**
> This document identifies regulatory instruments and framework controls
> that reference record properties of the kind an Agent Action Capsule
> carries. It does **not** assert that deploying the Agent Action Capsule
> satisfies, complies with, certifies conformance to, or meets the
> requirements of any regulation or framework. Whether a capsule-based
> record meets a specific obligation is a determination to be made by
> deployers, their counsel, and relevant supervisory authorities on the
> facts of each deployment. No row in this document constitutes a legal
> conclusion. This document is not a substitute for legal or regulatory
> advice.

## Purpose and consumers

This crosswalk is produced by the Agent Action Capsule project and maintained
in the public repository. It feeds two artefacts:

- **Verify-surface governance panel** — the collapsible "Regulatory context"
  panel on the capsule permalink page. The panel is property-driven: rows
  appear only for properties detected in the rendered capsule (anchor receipt
  present → tamper-evident rows; HITL disposition present → human-oversight
  rows; withheld-commitment block present → disclosure-control rows). No
  scores, no checkmarks against regulations. The panel header repeats the
  disclaimer above verbatim.
- **An internal capability-list artefact** — the capability list that describes
  what properties a conforming capsule carries. That artefact borrows this document's
  language discipline and property vocabulary directly.

## How to read each row

| Column | Meaning |
|--------|---------|
| **Regulation / Article** | The instrument, version, and specific provision |
| **Property** | The record-property type (from the controlled vocabulary below) referenced by the provision |
| **AAC Constructs** | The capsule field(s) or mechanism, with section references to `draft-mih-scitt-agent-action-capsule-02` |
| **Instrument text** | Verbatim or near-verbatim excerpt from the instrument (English; official translation where applicable). Bracketed `[...]` indicates a near-verbatim condensation; the full text of the instrument controls. |
| **Limits** | What the capsule does not address that a reader might assume it does |

Citations to `draft-mih-scitt-agent-action-capsule-02` use `§N.N` notation
(e.g., §5.1 = "Identity and parties"). All section references are to the
published -02 text unless noted. Instruments marked **⚠ Verify** were
published after the crosswalk author's knowledge cutoff (August 2025); the
cited text is a best-effort placeholder and must be verified against the
current published instrument before relying on it.

## Controlled property vocabulary

Five properties appear as a controlled vocabulary across all rows. The verify
surface uses these identifiers to drive panel rendering.

| ID | Meaning |
|----|---------|
| `tamper-evident-log` | The record is immutable after sealing and third-party verifiable without producer involvement |
| `per-action-attribution` | Each action is attributed to a specific operator, developer/agent, and timestamp |
| `human-oversight-record` | The record captures whether a human acted in the decision loop, and if so who |
| `disclosure-transparency-record` | The record carries or commits to information about what was disclosed vs. withheld |
| `retention` | The record is structurally preserved and chain-linked for a bounded history window |

---

## EU AI Act (Regulation (EU) 2024/1689)

Applies to providers and deployers of AI systems in the EU. High-risk
AI system categories are enumerated in Annexes I and III. Obligations vary
by role (provider vs. deployer) and risk tier.

| Regulation / Article | Property | AAC Constructs | Instrument text | Limits |
|---|---|---|---|---|
| EU AI Act Art 12(1) — Logging capabilities | `tamper-evident-log` | `capsule_id` (§5.1, content-addresses the envelope); SCITT anchor receipt / inclusion proof (§3.2); `chain.parent_capsule_id` (§5.5.4, chain linkage); `timestamp` RFC3339 UTC (§5.1) | "High-risk AI systems shall be designed and developed with capabilities enabling the automatic recording of events ('logs') over the lifetime of the system." — Reg (EU) 2024/1689, Art 12(1) | Art 12 addresses *providers* who design the system. Whether a capsule produced by a deployer addresses the provider's obligation depends on the system's architecture and supply-chain configuration. The capsule records one event per sealed envelope; log-completeness (Art 12(2) level of traceability) requires chain-completeness verification via the ledger-grade API. |
| EU AI Act Art 12(2) — Level of traceability | `tamper-evident-log`, `retention` | `chain.parent_capsule_id` + `chain.relation` (§5.5.4, gap-detectable linkage); `epoch_id` (§5.2.1, operational configuration scope); epoch-scoped verification (§5.2.3) | "The logging capabilities referred to in paragraph 1 shall ensure a level of traceability of the AI system's functioning throughout its lifetime that is appropriate to the intended purpose of the system." — Reg (EU) 2024/1689, Art 12(2) | "Appropriate level of traceability" is a context-dependent standard. The capsule provides a structural mechanism for gap detection; whether the gap-detection granularity and field depth satisfy the intended-purpose traceability standard is a deployer-level determination. |
| EU AI Act Art 26(6) — Deployer log retention | `retention` | `epoch_id` (§5.2.1, configuration scope); `chain.parent_capsule_id` (§5.5.4); export-verifiable bundle (`docs/ledger-grade.md`, `export_verifiable_bundle()`) | "Deployers of high-risk AI systems shall keep the logs automatically generated by the high-risk AI system to the extent such logs are under their control, for a period of at least six months, unless provided otherwise in applicable Union or national law." — Reg (EU) 2024/1689, Art 26(6) | The capsule provides a structured, verifiable record unit; the retention policy (duration, storage location, access controls, deletion procedures) must be implemented at the deployment layer. The capsule itself does not enforce retention schedules or deletion windows. The phrase "to the extent such logs are under their control" is a scoping question for each deployment. |
| EU AI Act Art 50(1) — Machine-readable AI-content marking | `disclosure-transparency-record` | `action_type` ("fyi" / "decide", §5.1); `disposition.decision` (§5.5); `withheld_commitments` selective-disclosure manifest (§9.2 + companion I-D) | "Providers of AI systems, including general-purpose AI systems, generating synthetic audio, image, video and text content, shall ensure that the outputs of the AI system are marked in a machine-readable format and detectable as artificially generated or manipulated." — Reg (EU) 2024/1689, Art 50(1) | Art 50(1) addresses content-level marking (e.g., watermarking, C2PA provenance manifests) applied to the output artifact itself. The capsule records the *action disposition* and *effect binding*, not the content-level marking of the output. Capsule presence does not substitute for Art 50(1) content marking; the two operate at different layers. See also `I-D.dawkins-scitt-ai-article50`, which profiles SCITT receipts for Art 50 obligations. |
| EU AI Act Art 50(2) / (3) — Notice to persons subject to AI interaction | `human-oversight-record`, `disclosure-transparency-record` | `human_disposed` flag (§5.5, true only if human actually acted); `disposition.approver` (§5.5, "human" / "policy"); `verdict_class` (§5.5.1) | "[Deployers ... shall inform the natural persons exposed to them of the existence of such systems...]" — Reg (EU) 2024/1689, Art 50(2)-(3) [condensed] | The capsule records *whether* human disposition occurred and by what class of approver; it does not constitute notice to the affected person. Notice is a separate process-layer obligation. `human_disposed: true` is an honest flag constrained by the profile (§5.5: producer MUST NOT claim human disposed when policy did); it can serve as evidence toward demonstrating the oversight posture, not as the notice mechanism itself. |

---

## DORA (Regulation (EU) 2022/2554)

Digital Operational Resilience Act. Applies to financial entities in the EU.
Relevant obligations cover ICT risk management, incident detection and
recording, and third-party ICT risk. Agentic AI actions that form part of
a financial entity's ICT operations are within scope.

| Regulation / Article | Property | AAC Constructs | Instrument text | Limits |
|---|---|---|---|---|
| DORA Art 9(4) — ICT security policies (logging and monitoring) | `tamper-evident-log`, `per-action-attribution` | SCITT anchor receipt (§3.2); `capsule_id` (§5.1); `operator` + `developer` (§5.1, attribution); `timestamp` (§5.1); Constraint Records (§8.1) | "[Financial entities shall implement ... policies, procedures, protocols and tools, as appropriate to their needs, to ... ensure the security of the ICT systems and data ... and detect and prevent anomalous activities ...]" — Reg (EU) 2022/2554, Art 9(4) [condensed; verify against official text] | Art 9(4) sets general principles; the specific logging controls required will depend on the financial entity's ICT risk management framework. The capsule records an agentic AI action; whether it constitutes a qualifying event for ICT logging purposes depends on the entity's operational risk categorization of AI agent actions. |
| DORA Art 10(1)-(2) — Detection of anomalous activity | `tamper-evident-log` | Constraint Records (§8.1, deterministic checks with `blocking` flag); `verdict_class` (§5.5.1, including `blocked`/`denied`); SCITT anchor receipt (§3.2) | "[Financial entities shall have in place mechanisms to promptly detect anomalous activities ... The detection mechanisms shall define alert thresholds and criteria to trigger and initiate ICT-related incident response processes ...]" — Reg (EU) 2022/2554, Art 10(1)-(2) [condensed; verify against official text] | The capsule records the outcome of deterministic checks (Constraint Records, §8.1) and carries a `verdict_class: blocked` or `denied` disposition when a check gates the action. It is a record of the check outcome, not the detection infrastructure itself. Detection pipelines feeding into the capsule are operator-layer concerns. |
| DORA Art 17(3)(b) — ICT incident records | `tamper-evident-log`, `per-action-attribution` | `action_id` (§5.1, stable identifier); `timestamp` (§5.1); `operator` + `developer` (§5.1); SCITT anchor receipt (§3.2); `disposition.decision` + `verdict_class` (§5.5, §5.5.1) | "[When financial entities detect ... ICT-related incidents, they shall ... document all ICT-related incidents and ICT threats ...]" — Reg (EU) 2022/2554, Art 17(3)(b) [condensed; verify against official text] | DORA Art 17 incident records are framed around ICT-related incidents meeting classification thresholds (Art 18). Not every agentic AI action constitutes a DORA Art 17 incident; the capsule can serve as evidence toward the required incident record when an AI agent action is classified as an ICT-related incident by the financial entity. |

---

## MAS SAFR (Monetary Authority of Singapore, Jul 2026) ⚠ Verify

MAS Supervisory Assessment Framework for Responsible AI (or the applicable
July 2026 MAS AI governance publication). Applies to MAS-regulated financial
institutions operating AI systems. **The July 2026 publication post-dates
the crosswalk author's knowledge cutoff. Row content below is a best-effort
placeholder; the instrument title, article references, and cited text must
be verified against the current MAS publication before relying on this row.**

| Regulation / Article | Property | AAC Constructs | Instrument text | Limits |
|---|---|---|---|---|
| MAS SAFR (Jul 2026) — Accountability and auditability | `tamper-evident-log`, `per-action-attribution` | `operator` + `developer` (§5.1); `capsule_id` (§5.1); SCITT anchor receipt (§3.2); `timestamp` (§5.1) | ⚠ **Verify**: MAS AI governance instruments consistently reference requirements for firms to maintain audit trails of AI-driven decisions attributable to accountable parties. Cite the specific MAS SAFR article and verbatim text on verification. | MAS regulatory scope, definitions, and specific obligations must be confirmed from the published instrument. |
| MAS SAFR (Jul 2026) — Human oversight and decision review | `human-oversight-record` | `human_disposed` (§5.5); `disposition.approver: "human"` (§5.5); HITL chain (`chain.relation: "supersedes"`, §5.5.4) | ⚠ **Verify**: MAS guidance on model risk management and responsible AI consistently references requirements for human oversight of automated decisions. Cite the specific SAFR article on verification. | Capsule records whether human disposition occurred; the governance obligations around escalation thresholds, reviewer qualifications, and documentation of human review outcomes are deployment-layer obligations. |

---

## FCA AI Live Testing / AI Lab Expectations (UK FCA)

The UK Financial Conduct Authority has articulated expectations for AI
transparency, accountability, and audit trails through its AI Lab, AI
Sandbox, and published feedback statements (including FS23/5). The
"AI Live Testing" scheme places additional documentary obligations on
participating firms.

| Regulation / Article | Property | AAC Constructs | Instrument text | Limits |
|---|---|---|---|---|
| FCA AI accountability expectations (FS23/5 and successor publications) | `per-action-attribution`, `tamper-evident-log` | `operator` + `developer` (§5.1); `capsule_id` (§5.1); SCITT anchor receipt (§3.2); `timestamp` (§5.1); Constraint Records (§8.1, policy-check evidence) | "[Firms should be able to demonstrate accountability for AI-driven outcomes and maintain adequate records to allow supervisory scrutiny of how AI systems operate and make decisions.]" — FCA FS23/5 and AI Strategy documentation [condensed; verify against current FCA publication] | FCA expectations evolve through guidance, Dear CEO letters, and supervisory engagement rather than prescriptive rules. Specific obligations depend on the regulated activity, the AI system's role in that activity, and the applicable FCA rulebook (SYSC, MAR, etc.). |
| FCA AI Live Testing — transparency of AI decision-making | `human-oversight-record`, `disclosure-transparency-record` | `human_disposed` (§5.5); `disposition.approver` (§5.5); `verdict_class` (§5.5.1); selective-disclosure manifest (§9.2) | "[Participants in the AI Live Testing scheme are expected to demonstrate robust governance, including audit trails of AI decisions and records of human review where required.]" — FCA AI Lab / ALTS framework documentation [condensed; ⚠ verify against current published scheme terms] | The FCA AI Live Testing scheme's precise obligations are set by the terms of the specific sandbox engagement. "Adequate" audit trails and governance standards are assessed contextually. |

---

## SEC Rule 17a-4 / FINRA Rule 4511

U.S. broker-dealer books-and-records requirements under the Securities
Exchange Act of 1934 and FINRA rules. These instruments prescribe the format,
accessibility, and retention period for required books and records.

| Regulation / Article | Property | AAC Constructs | Instrument text | Limits |
|---|---|---|---|---|
| SEC Rule 17a-4(f)(2)(ii)(A) — Non-rewriteable, non-erasable electronic records | `tamper-evident-log` | SCITT anchor receipt (§3.2, inclusion proof from a Transparency Service; registration is append-only and the receipt makes the capsule third-party verifiable without producer involvement); `capsule_id` (§5.1, content-addresses the envelope) | "The electronic storage media must preserve the records exclusively in a non-rewriteable, non-erasable format." — 17 C.F.R. § 240.17a-4(f)(2)(ii)(A) | The non-rewriteable property of 17a-4(f)(2)(ii)(A) applies to the *storage medium*, not only the record format. Whether a SCITT-anchored capsule stored on a given medium addresses the storage requirement depends on the medium, the audit system, and the regulatory interpretation in effect. 17a-4 requires an audit system that monitors the integrity of the electronic records (§240.17a-4(f)(3)(i)), which is a separate deployment obligation. |
| SEC Rule 17a-4(b)(1)-(2) — Retention periods | `retention` | `epoch_id` (§5.2.1, configuration epoch as a retention-window boundary); `timestamp` (§5.1); export-verifiable bundle (`docs/ledger-grade.md`) | "Every ... member ... shall preserve for a period of not less than three years ... [and for specified record types, not less than six years] ..." — 17 C.F.R. § 240.17a-4(b)(1)-(2) [condensed] | The capsule provides a structured record unit; the retention period, deletion schedule, and storage accessibility requirements (17a-4(b)(1): first two years in an accessible place) are deployment-layer obligations. The capsule does not enforce retention windows. |
| FINRA Rule 4511(a) — General books-and-records obligation | `tamper-evident-log`, `per-action-attribution` | `operator` + `developer` (§5.1); `timestamp` (§5.1); SCITT anchor receipt (§3.2); `action_id` (§5.1, unique within producer ledger) | "Each member shall make and preserve books and records as required under the FINRA rules, the Exchange Act and the applicable Exchange Act rules." — FINRA Rule 4511(a) | FINRA Rule 4511 incorporates SEC Rule 17a-4 by reference (FINRA Rule 4511(c)). The same storage-medium and retention-period limits noted above apply. Whether a capsule constitutes a required "book or record" depends on the regulated activity and FINRA rule set that governs it. |
| FINRA Rule 4511(c) — 17a-4 format compliance | `tamper-evident-log` | SCITT anchor receipt (§3.2); `capsule_id` (§5.1) | "All books and records required to be made pursuant to the FINRA rules shall be preserved in a format and media that complies with Rule 17a-4 under the Exchange Act." — FINRA Rule 4511(c) | See limits for SEC Rule 17a-4(f)(2)(ii)(A) above. |

---

## NIST AI Risk Management Framework (NIST AI RMF 1.0, NIST AI 100-1, January 2023)

Voluntary U.S. framework for managing AI risk. Organized around four
functions: GOVERN, MAP, MEASURE, MANAGE. Subcategory IDs are per the
published RMF Core (Table 1 of NIST AI 100-1).

| Regulation / Article | Property | AAC Constructs | Instrument text | Limits |
|---|---|---|---|---|
| NIST AI RMF GOVERN 1.1 — Risk management policies and practices | `per-action-attribution` | `operator` (§5.1); `developer` (§5.1); `spec_version` (§5.1, profile version); Constraint Records (§8.1, policy-check verdicts) | "Policies, processes, procedures, and practices across the organization related to the mapping, measuring, and managing of AI risks are in place, transparent, and implemented effectively." — NIST AI 100-1, GOVERN 1.1 | NIST AI RMF is a voluntary framework; its subcategories are organizational practices, not prescriptive technical requirements. The capsule can serve as evidence toward demonstrating that per-action attribution practices are in place and implemented; it does not itself constitute a risk management policy. |
| NIST AI RMF GOVERN 6.1 — Third-party and supply-chain risk policies | `per-action-attribution`, `tamper-evident-log` | `developer` (§5.1, agent identity and version); `operator` (§5.1, accountable tenant); `capsule_id` (§5.1); SCITT anchor receipt (§3.2) | "Policies and procedures are in place to address AI risks and benefits arising from third-party software and data and other supply chain issues, which are reviewed and updated regularly." — NIST AI 100-1, GOVERN 6.1 | Third-party risk policies are organizational-layer obligations. The capsule's `developer` field records the agent identity and version (§5.1: "The agent identity and version that performed the action"), which references supply-chain provenance; whether this addresses a GOVERN 6.1 practice depends on the organization's risk framework. |
| NIST AI RMF MEASURE 2.6 — AI risk and performance tracking | `tamper-evident-log`, `per-action-attribution` | `verdict_class` (§5.5.1); `effect_attestation` (§5.3); Constraint Records (§8.1); SCITT anchor receipt (§3.2) | "[The organization tracks key observations about AI risk and performance ... risks are documented and regularly reviewed ...]" — NIST AI 100-1, MEASURE 2.6 [condensed; verify subcategory text] | MEASURE subcategories describe organizational practices for risk tracking. The capsule's per-action verdict record can serve as evidence toward demonstrating that AI risk observations are tracked; the organizational risk-tracking practice and documentation are separate obligations. |
| NIST AI RMF MEASURE 2.8 — Transparency and accountability risks | `disclosure-transparency-record` | `disclosure` field / selective-disclosure manifest (§9.2); `withheld_commitments`; `action_type` (§5.1) | "Risks associated with transparency and accountability – as identified in the MAP function – are examined and documented." — NIST AI 100-1, MEASURE 2.8 | MEASURE 2.8 addresses documentation of *risks*; the capsule carries a record of what was disclosed vs. withheld per action. Whether documenting disclosure posture addresses the MEASURE 2.8 transparency-risk examination is an organizational-layer determination. |
| NIST AI RMF MANAGE 1.3 — High-priority risk response planning and documentation | `human-oversight-record` | `human_disposed` (§5.5); `disposition.approver` (§5.5); HITL chain + `chain.relation: "supersedes"` (§5.5.4) | "Responses to the AI risks deemed high priority, as identified by the MAP function, are developed, planned, and documented." — NIST AI 100-1, MANAGE 1.3 | MANAGE 1.3 addresses organizational response-planning documentation. The HITL chain (§5.5.4) records that a human acted in the decision loop and, via `chain.relation: "supersedes"`, captures the resolution; it can serve as evidence toward demonstrating planned human-review responses for high-priority risks. |

---

## prEN 18229-1 (CEN/TC AI — Artificial Intelligence: Transparency) ⚠ Verify

Draft European Standard on AI transparency, produced by CEN/CENELEC JTC 21.
The public enquiry window was open as of the date of this document
(July 2026). **The draft standard post-dates the crosswalk author's knowledge
cutoff. Row content below is a best-effort placeholder; the part number,
article references, and cited text must be verified against the current
CEN enquiry document. Note the open enquiry window: comments on the draft
are currently accepted.**

| Regulation / Article | Property | AAC Constructs | Instrument text | Limits |
|---|---|---|---|---|
| prEN 18229-1 — Transparency documentation requirements for AI systems | `disclosure-transparency-record`, `per-action-attribution` | `action_type` (§5.1); `operator` + `developer` (§5.1); `disposition.decision` (§5.5); selective-disclosure manifest (§9.2) | ⚠ **Verify**: CEN transparency standards for AI typically reference requirements for documentation of AI system operation, decision attribution, and disclosure of AI involvement to affected parties. Cite the specific prEN 18229-1 clause and verbatim text on verification against the current enquiry draft. | The standard's precise scope (whether it covers agentic AI action logs or is focused on system-level transparency declarations) must be confirmed from the draft. Enquiry-stage text may change before final publication. |
| prEN 18229-1 — Tamper-evidence and integrity of AI transparency records | `tamper-evident-log` | SCITT anchor receipt (§3.2); `capsule_id` (§5.1, content-addresses the envelope); `chain.parent_capsule_id` (§5.5.4) | ⚠ **Verify**: AI transparency standards typically reference requirements for integrity and auditability of transparency records. Cite the specific clause on verification. | Same enquiry-stage caveat applies. |

---

## OWASP Agentic AI Security (ASI08, ASI09, ASI10)

From the OWASP Agentic AI Security project (OWASP AISC), which publishes
security considerations and mitigations for agentic AI systems. ASI08,
ASI09, and ASI10 address audit, accountability, and transparency mitigations.
**Row content below reflects the best available mapping as of July 2026;
verify against the current OWASP AISC publication for exact control numbering
and text, as the project's numbering may have changed.**

| Regulation / Article | Property | AAC Constructs | Instrument text | Limits |
|---|---|---|---|---|
| OWASP Agentic ASI08 — Logging and monitoring failures (mitigation) | `tamper-evident-log`, `per-action-attribution` | SCITT anchor receipt (§3.2); `capsule_id` (§5.1); `action_id` (§5.1); `timestamp` (§5.1); `operator` + `developer` (§5.1); Constraint Records (§8.1) | ⚠ **Verify**: OWASP Agentic ASI08 (or the current corresponding control) addresses failures to log and monitor agentic AI actions with sufficient attribution. Mitigations reference maintaining tamper-evident audit trails of agent actions attributable to specific agents and operators. Cite current OWASP AISC text on verification. | The OWASP control addresses the *absence* of logging as a security risk; the capsule provides a structured record format. Whether the capsule's deployment is sufficient to address ASI08 depends on completeness of emission (every action sealed), chain integrity, and anchor configuration. Partial emission undermines the mitigation. |
| OWASP Agentic ASI09 — Insufficient authorization audit trail (mitigation) | `per-action-attribution`, `human-oversight-record` | `disposition.approver` (§5.5, "human" / "policy"); `human_disposed` (§5.5); `verdict_class` (§5.5.1, `denied` / `blocked`); Constraint Records (`blocking` flag, §8.1) | ⚠ **Verify**: OWASP Agentic ASI09 (or current control) addresses the failure to record authorization decisions for agentic AI actions, enabling unauthorized actions to be undetectable post-hoc. Mitigations reference per-action authorization records attributing approvals to specific approver types. | The capsule records the approver type (`human` / `policy`) and the `human_disposed` flag; it does not record the identity of individual human approvers beyond the `approver` field (§5.5: `authority` OPTIONAL, opaque reference). More granular human-approver identity is a deployment-layer configuration. |
| OWASP Agentic ASI10 — Transparency and disclosure failures (mitigation) | `disclosure-transparency-record`, `human-oversight-record` | `action_type` (§5.1, "fyi" / "decide"); `disposition.decision` (§5.5); selective-disclosure manifest (§9.2); `withheld_commitments`; `human_disposed` (§5.5) | ⚠ **Verify**: OWASP Agentic ASI10 (or current control) addresses failures to disclose AI agent involvement and disposition in interactions with users and third parties. Mitigations reference per-action disclosure records. | Disclosure to an end user or affected party is a separate process-layer obligation; the capsule carries a machine-verifiable record of the disclosure posture (what was withheld vs. disclosed) rather than the disclosure act itself. |

---

## AIUC-1 Accountability Domain ⚠ Verify

AI Underwriter's Criteria (or the applicable accountability-domain instrument).
**AIUC-1 was published after the crosswalk author's knowledge cutoff (August 2025).
Row content below is a best-effort placeholder; the instrument title, domain
references, and cited text must be verified against the current published
document before relying on this row.**

| Regulation / Article | Property | AAC Constructs | Instrument text | Limits |
|---|---|---|---|---|
| AIUC-1 Accountability Domain — Per-action attribution requirements | `per-action-attribution`, `tamper-evident-log` | `operator` (§5.1); `developer` (§5.1); `capsule_id` (§5.1); SCITT anchor receipt (§3.2); `timestamp` (§5.1) | ⚠ **Verify**: AIUC-1 accountability-domain controls reference requirements for attributing AI-generated actions to accountable parties with tamper-evident records. Cite specific domain/control and verbatim text on verification. | Must be confirmed from the published instrument. |
| AIUC-1 Accountability Domain — Human oversight records | `human-oversight-record` | `human_disposed` (§5.5); `disposition.approver` (§5.5); HITL chain (§5.5.4) | ⚠ **Verify**: AIUC-1 accountability-domain controls reference requirements for recording human oversight of AI decisions. Cite specific domain/control and verbatim text on verification. | Same caveat applies. |

---

## What the capsule does NOT address — honesty section

This section states explicitly what a reader might assume the capsule addresses
but does not. The verify-surface panel omits rows for these properties.

**Content-level AI marking.** The capsule is an action-disposition record; it
is not a content watermark or C2PA provenance manifest. It does not embed
AI-generated-content markers in the output artifact itself. EU AI Act Art 50(1)
content-marking obligations require separate implementation at the content-
production layer.

**Retention enforcement.** The capsule does not enforce retention periods,
deletion schedules, or storage medium requirements. These are deployment-layer
obligations. The capsule provides a structured record unit that a retention
system can preserve; it does not constitute the retention system.

**Notice to affected persons.** The capsule records whether human oversight
occurred and what disposition was taken; it does not constitute or deliver
notice to natural persons subject to an AI system's decision (EU AI Act Art 50(2)-(3),
MAS fairness obligations). Notice is a process-layer obligation separate from
the audit record.

**Human approver identity.** The `disposition.approver` field (§5.5) records
the approver *class* ("human" / "policy"). The `authority` field (OPTIONAL) is
an opaque reference under non-human disposition. The capsule does not record
granular human approver identity (e.g., employee ID, reviewer name). Deployers
requiring this must carry it in a non-public operator-side record and, where
permitted, bind it to the capsule via a digest commitment.

**Completeness guarantee.** The capsule provides structural mechanisms for
gap detection (chain-completeness verification via `chain.parent_capsule_id`,
§5.5.4) but does not guarantee complete emission. A deployment that does not
emit a capsule for every action has a gap in its record. Log-completeness is
an operational obligation, not a structural invariant of the format.

**Semantic accuracy of the disposition.** The `human_disposed: true` flag is
constrained by the profile (§5.5: "MUST NOT claim human disposed when policy
did"), but the capsule cannot verify that a human who approved an action did
so attentively or with adequate information. The capsule records the structural
fact of human disposition; the quality and governance of that disposition are
supervisor- and auditor-layer concerns.

**Storage medium non-rewriteability.** SCITT anchor registration makes the
capsule third-party verifiable and the inclusion proof tamper-evident, but
the non-rewriteable storage medium requirements of SEC Rule 17a-4(f)(2)(ii)(A)
and equivalent instruments apply to the *storage medium* used by the deployer,
not to the capsule format. The deployer must use qualifying storage to meet
those requirements.

**Personal data and privacy.** The capsule is designed to carry sanitized
categories only (§8.1: Constraint Records carry "only sanitized categories";
content a check evaluated MUST NOT appear in the public record). However,
deployers must independently assess whether capsule fields (e.g., `action_id`,
`operator`, `developer`, agent output digests) constitute or reference
personal data under applicable law (GDPR, etc.) and apply appropriate
controls. The profile's selective-disclosure mechanism (§9.2) enables
per-field concealment; its eligibility list is defined in the companion I-D.

---

## Notes on comparable approaches

`I-D.emirdag-scitt-ai-agent-execution` (AgentInteractionRecords) also carries
regulatory mappings for EU AI Act, DORA, NIST AI RMF, MAS, and PCI DSS. The
crosswalk above is produced from first-principles instrument text (not from
the emirdag I-D) and makes the following differences explicit:

1. **Language discipline.** The emirdag I-D uses "satisfy" / "comply" in its
   mapping claims. This crosswalk does not; every row is framed as "references
   properties of this kind" or "can serve as evidence toward."
2. **Limits column.** This crosswalk includes explicit "Limits" entries stating
   what the capsule does not address. The honesty section above is additional.
3. **Instrument text column.** Each row cites verbatim or near-verbatim
   instrument text; the emirdag I-D's regulatory language should be compared
   against the primary instruments on a row-by-row basis.

`I-D.dawkins-scitt-ai-article50` profiles SCITT receipts specifically for EU
AI Act Art 50 obligations and is directly relevant to the Art 50 rows above.

---

*Maintained in `agent-action-capsule/docs/regulatory-crosswalk.md`.
Crosswalk version: 2026-07-27. Row count by framework:
EU AI Act (5), DORA (3), MAS SAFR (2⚠), FCA (2⚠), SEA 17a-4/FINRA 4511 (4),
NIST AI RMF (5), prEN 18229-1 (2⚠), OWASP Agentic (3⚠), AIUC-1 (2⚠).
Total: 28 rows. ⚠ = citation requires verification against current instrument.*
