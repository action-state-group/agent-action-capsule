- Spec: `spec/bilateral-attestation-mapping-v0.md` (informational, pre-Internet-Draft) maps the
  records two producers seal for a two-party exchange onto
  `draft-mih-agent-bilateral-attestation-03`: a compute-exchange plugin's settlement legs, its
  session agreement and its payment lifecycle records, and every record type of both versions of
  a marketplace plugin's deal record profile (v0 and v1), with the countersign and cadence of the core it builds on.
  Each row is a `draft-mih-agent-settlement-records-01` leg, an interop-profile acceptance record,
  plugin-local or not emitted, and names its nearest BA object and what it lacks to be one. Findings: no record
  either producer seals today is a BA object; countersign and cadence do not fit BA without loss; the cadence chain matches the Evidence
  Bundle `-03` `parent-log-witness/v1` kind link for link, and the mapping lists every member
  cadence lacks or adds against it; BA
  has no slot for intent, and an optional digest reference carries it with no new member; the
  negotiation trail is plugin-local in both versions, though v1 signs each party's own moves; the
  agreed terms verify without the trail only as an SR terms leg cited by the other side, which v1
  carries on an offer with one payment row; the v1 agreement pair is not a BA exchange; and v1 seals
  no delivered leg, so the core is complete at neither version of the deal profile. It changes no draft and
  registers nothing.
