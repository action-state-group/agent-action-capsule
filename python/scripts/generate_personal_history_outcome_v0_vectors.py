#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate the conformance vectors of the Personal-Agent History Profile v0, Outcome level.

The level is ``spec/personal-agent-history-outcome-v0.md`` (``personal_history_outcome/1``); its §12
lists these cases. They are built from the Basic level run in
``vectors/personal-history-basic-v0/responder-run.json``, which this script reads and never
rewrites:

- one positive per outcome source (§5): the holder's own record, the other party's half, a native
  object read through the x402 adapter declaration, and a judge's verdict given under the holder's
  consent;
- one ``not_evaluable`` case: a deal whose payment is established and whose delivery is asked for;
- the deal commitment of §7, opened, not opened and opened with other text;
- a mutant for every level property that can be ``FAIL`` except ``native_check`` (§12 says why),
  each re-signed by the holder key where it changes a reply.

The native object is the x402 adapter corpus's ``positive`` case: its payment payload and settlement
response octets, unchanged, and its recorded lookup with ``final`` set to true. Those two object
files are the same under the released adapter text and under its pending revision, and the lookup
is the one the pending revision gives, so the case holds under both (§12).

It states each claim's properties and each History property by hand from the level text, and
derives from them, by the level's rules, whether each claim counts, its deal binding, the
requirement results (§8.4), the openings (§7) and the failing properties. Each case cites the
sections it comes from. Nothing here imports or runs a verifier. Every reply is the run's, asked again under the
Outcome level definition and re-signed by the holder key, so every case is ``derived``. The added
records' digests are label digests, not record identifiers: ``anchor_inclusion`` is ``NOT_CHECKED``
at this level as at the Basic level.

Output: ``vectors/personal-history-outcome-v0/`` (or ``--out DIR``). Deterministic: no clock, no
randomness. ``README.md`` is never rewritten; every file in the directory is listed in
``SHA256SUMS``. Dependencies: the standard library, ``cryptography`` (Ed25519 only) and the
generators beside this script, for their encodings, keys and statuses.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import generate_personal_history_basic_v0_vectors as history_vectors
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from generate_interop_profile_v0_vectors import EC_SCHEMA, KINDS, PROFILE, jcs, json_digest, sha, shx
from generate_personal_history_basic_v0_vectors import (
    RUN,
    answered,
    artifact_of,
    carried,
    decode,
    load_run,
    resign,
)

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "vectors" / "personal-history-outcome-v0"
X402 = ROOT / "vectors" / "adapters" / "x402"
SET = "aac-personal-history-outcome-v0"
SPEC = "spec/personal-agent-history-outcome-v0.md"
STATUS = ("Conformance vectors for the informational Personal-Agent History Profile v0, Outcome level, "
          "over evidence-interop/0. Every key is a test key derived from a public seed; never use one "
          "for anything else.")
HISTORY = "personal_history_outcome/1"
J = "application/json"
OCTETS = "application/octet-stream"

SEED_LABELS = {
    "counterparty": "personal-agent-history-outcome-v0 conformance vectors: the other party's key",
    "judge": "personal-agent-history-outcome-v0 conformance vectors: judge key",
    "not-the-judge": "personal-agent-history-outcome-v0 conformance vectors: key that is not the judge",
}
PRIV = {name: Ed25519PrivateKey.from_private_bytes(sha(label.encode())) for name, label in SEED_LABELS.items()}
PUB = {name: k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex() for name, k in PRIV.items()}
ALL_PRIV = {**history_vectors.PRIV, **PRIV}
ALL_PUB = {**history_vectors.PUB, **PUB}

# §6: the shared predicate table. Its digest is every definition's `predicates` member.
PREDICATES = {
    "name": "outcome_predicates/1",
    "predicates": [
        {"id": "cancelled", "sources": ["counterparty_half", "holder_record", "judge_verdict"]},
        {"id": "completed", "sources": ["counterparty_half", "holder_record", "judge_verdict", "native_object"],
         "native": [{"adapter": "ucp-v0", "predicate": "checkout-completed"}]},
        {"id": "delivered", "sources": ["counterparty_half", "holder_record", "judge_verdict"]},
        {"id": "disputed", "sources": [], "lifecycle": "disputes"},
        {"id": "paid", "sources": ["counterparty_half", "holder_record", "judge_verdict", "native_object"],
         "native": [{"adapter": "x402-v0", "predicate": "X3"}, {"adapter": "x402-v0", "predicate": "X4"}]},
    ],
}
PREDICATES_DIGEST = json_digest(PREDICATES)
SOURCES = ["counterparty_half", "holder_record", "judge_verdict", "native_object"]
READS = ["commit_alg", "committed_at", "consent", "deal_commitment", "epistemic_type", "event_time_claim",
         "outcome", "record_type"]

# §8.2: the level's History properties, in report order.
HISTORY_PROPS = ["definition_form", "definition_binding", "predicate_binding", "coverage_declaration_form",
                 "selection_coverage", "single_signer", "single_anchor", "artifact_form", "record_kinds"]

# §8.3: the claim properties of each source, in report order.
CLAIM_PROPS = {
    "holder_record": ["outcome_form", "outcome_source_allowed"],
    "counterparty_half": ["outcome_form", "outcome_source_allowed", "outcome_evidence", "half_signature",
                          "half_signer_trust", "half_subject", "half_states", "issuer_independence"],
    "native_object": ["outcome_form", "outcome_source_allowed", "outcome_evidence", "adapter_predicate_maps",
                      "native_check"],
    "judge_verdict": ["outcome_form", "outcome_source_allowed", "outcome_evidence", "judge_signature",
                      "judge_signer_trust", "judge_subject", "judge_grounds", "consent_precedes_judgment",
                      "judge_verdict_allowed"],
}

# The IP requirement every envelope maps (as at the Basic level, §6.1 there), and the recipient's
# outcome requirements of §8.4, in the form fixed for these vectors only.
CONTRACT = {
    "id": "O",
    "version": "1",
    "requirements": [
        {"id": "r-deal-steps", "profile": "outcome",
         "statement": "The recorded steps of each selected deal are served under a verified envelope.",
         "evidence_requirements": {"accepted_epistemic_types": ["producer_claim"]}},
    ],
}
CONTRACT_REF = f"{CONTRACT['id']}@{CONTRACT['version']}"
CONTRACT_DIGEST = json_digest(CONTRACT)
OUTCOME_REQUIREMENTS = [
    {"id": "r-completed", "predicate": "completed", "sources": SOURCES},
    {"id": "r-delivered", "predicate": "delivered", "sources": ["counterparty_half", "judge_verdict", "native_object"]},
    {"id": "r-paid", "predicate": "paid", "sources": ["counterparty_half", "judge_verdict", "native_object"]},
]
EVAL = "2026-10-19T01:00:00Z"

# The judge's question: the contract its verdict is given under (§5.4).
JUDGE_CONTRACT_REF = "ec:personal-history-outcome-example:2026-10-19@1"
COMMIT_ALG = "sha256-jcs-nonce256"


def label(text: str) -> str:
    return shx(f"personal-agent-history-outcome-v0 conformance vectors: {text}".encode())


# ---------------------------------------------------------------------------
# Held objects: halves, judge records, native objects, openings
# ---------------------------------------------------------------------------


def signed(body: dict, member: str, signer: str, named: str | None = None) -> dict:
    """``body`` with ``member`` set to the key ``named`` (by default the signer's), and Ed25519 ``sig`` by
    ``signer`` over UTF-8 of JCS of the rest."""
    body = dict(body, **{member: ALL_PUB[named or signer]})
    return {"media_type": J, "octets_text": jcs(dict(body, sig=ALL_PRIV[signer].sign(jcs(body).encode()).hex()))}


def half(claim: str, deal: str, signer: str = "counterparty", named: str | None = None) -> dict:
    """§5.2's half, in the form fixed for these vectors: IP §11.5's producer record with ``subject_ref``."""
    return signed({"claim": claim, "issued_at": "2026-10-15T00:00:30Z", "subject_ref": deal}, "producer", signer,
                  named)


def judge_record(deal: str, acts: list[str], verdict: str, signer: str = "judge", named: str = "judge") -> dict:
    """§5.4's judge record, in the form fixed for these vectors: an ``evaluation-report/v1`` record
    with the judge's key and the deal it answers for, signed by the judge."""
    report = {
        "record_version": "evaluation-report/v1",
        "record_id": f"er-{deal}",
        "epistemic_type": "semantic_judgment",
        "generated_at": "2026-10-15T00:00:40Z",
        "contract_ref": JUDGE_CONTRACT_REF,
        "judge_pin": {"model_id": "example-judge-v1",
                      "prompt_digest": {"digest_alg": "SHA-256", "digest": label("judge prompt")},
                      "axes_digest": {"digest_alg": "SHA-256", "digest": label("judge axes")},
                      "sampling": {"seed": 1, "temperature_micros": 0}},
        "cases": [{"case_id": "completed", "verdict": verdict,
                   "acts": [{"type": "personal-history-record", "digest_alg": "SHA-256", "digest": d,
                             "citation_purpose": "grounds"} for d in acts],
                   "method": {"type": "rubric", "digest_alg": "SHA-256", "digest": label("judge rubric"),
                              "citation_purpose": "method"}}],
    }
    return signed({"record": report, "subject_ref": deal}, "judge", signer, named=named)


def x402_positive() -> tuple[list[dict], dict, list[str]]:
    """The x402 adapter corpus's positive case: its two wrapped objects, held as their octets, and its
    recorded lookup with ``final`` true (the pending adapter revision's lookup)."""
    case = next(c for c in json.loads((X402 / "cases.json").read_text())["cases"] if c["name"] == "positive")
    objects, digests = [], []
    for w in case["inputs"]["wrapped"]:
        raw = (X402 / w["octets"]).read_bytes()
        assert shx(raw) == w["digest"], w["octets"]
        objects.append({"media_type": OCTETS, "octets_hex": raw.hex()})
        digests.append(w["digest"])
    lookup = json.loads((X402 / case["inputs"]["lookup"]).read_text())
    lookup["final"] = True
    return objects, lookup, sorted(digests)


def opening(deal: str, *, text: str | None = None) -> dict:
    return {"nonce": label(f"opening nonce of {deal}"), "text": text if text is not None else f"terms of {deal}"}


def commitment(o: dict) -> str:
    """Presentation contract §7.2: SHA-256 of JCS of {nonce, text}."""
    return json_digest({"nonce": o["nonce"], "text": o["text"]})


# ---------------------------------------------------------------------------
# Definitions and answers
# ---------------------------------------------------------------------------


def definition(basic: dict, **over: Any) -> dict:
    d = {k: v for k, v in basic.items() if k != "completeness"}
    d.update(name=HISTORY, reads=READS, coverage_declaration={"kind": "holder_selected"}, holder_role="seller",
             sources=SOURCES, predicates=PREDICATES_DIGEST)
    d.update(over)
    return d


def record(seq: int, record_type: str, **members: Any) -> dict:
    """A record the case adds to a deal: a label digest and a leaf index past the run's stream."""
    t = f"2026-10-15T00:01:{seq:02d}Z"
    return {"digest": label(f"added record {seq}"), "leaf_index": 100 + seq, "committed_at": t,
            "epistemic_type": "producer_claim", "event_time_claim": t, "record_type": record_type, **members}


def reanswer(exchange: dict, env: dict, derivation: str, tag: str, extra: list[dict]) -> tuple[dict, dict]:
    """One exchange of the run asked again under ``derivation``, with the deal commitment on the
    deal's first record and ``extra`` records after the run's, re-signed by the holder key."""
    request = json.loads(exchange["request"]["octets_text"])
    request["derivation"] = derivation
    request["nonce"] = request["nonce"].replace("/history-", f"/{tag}-")
    req = {"media_type": J, "octets_text": jcs(request)}
    a = artifact_of(env)
    a["derivation"] = derivation
    deal = a["subject"]["correlation"]
    recs = [dict(r) for r in a["records"]]
    recs[0].update(commit_alg=COMMIT_ALG, deal_commitment=commitment(opening(deal)))
    a["records"] = recs + extra
    reply = resign(env, "holder", artifact=a, derivation=derivation, request_digest=shx(req["octets_text"].encode()))
    return req, carried(reply)


# ---------------------------------------------------------------------------
# Expected values
# ---------------------------------------------------------------------------


def history_props(**over: str) -> dict:
    props = dict.fromkeys(HISTORY_PROPS, "PASS")
    props.update(over)
    return props


def claim_props(source: str, **over: str) -> dict:
    props = dict.fromkeys(CLAIM_PROPS[source], "PASS")
    if source == "counterparty_half":
        props["issuer_independence"] = "NOT_CHECKED"
    props.update(over)
    return props


def counts(props: dict) -> bool:
    """§8.3: a claim counts when every property passes; issuer_independence may be NOT_CHECKED."""
    return all(s == "PASS" or (p == "issuer_independence" and s == "NOT_CHECKED") for p, s in props.items())


def claim_result(deal: str, rec: dict, props: dict, *, verdict: str = "met") -> dict:
    o = rec["outcome"]
    # §5: carried only when the evidence itself names the deal.
    subject = {"counterparty_half": "half_subject", "judge_verdict": "judge_subject"}.get(o["source"])
    binding = "carried" if subject is not None and props.get(subject) == "PASS" else "holder_only"
    return {"deal": deal, "record": rec["digest"], "predicate": o["predicate"], "source": o["source"],
            "properties": props, "counts": counts(props), "deal_binding": binding,
            "verdict": verdict if counts(props) and binding == "carried" else None}


def requirement_results(deals: list[str], claims: list[dict]) -> dict:
    """§8.4, per requirement and deal."""
    out: dict[str, dict] = {}
    for req in OUTCOME_REQUIREMENTS:
        per: dict[str, dict] = {}
        for deal in deals:
            mine = [c for c in claims if c["deal"] == deal and c["predicate"] == req["predicate"]
                    and c["source"] in req["sources"]]
            verdicts = {c["verdict"] for c in mine if c["counts"] and c["deal_binding"] == "carried"}
            if not mine:
                status = "GAP"
            elif verdicts == {"met"} or verdicts == {"not_met"}:
                status = "SATISFIED"
            elif verdicts or any(c["counts"] for c in mine) or any(
                    set(c["properties"].values()) <= {"PASS", "NOT_CHECKED", "INCONCLUSIVE"} for c in mine):
                status = "UNKNOWN"
            else:
                status = "INSUFFICIENT"
            verdict = verdicts.pop() if status == "SATISFIED" else "not_evaluable"
            per[deal] = {"status": status, "sufficiency": status, "verdict": verdict}
        out[req["id"]] = per
    return out


def openings_result(deals: list[str], openings: dict) -> dict:
    out = {}
    for deal in deals:
        o = openings.get(deal)
        out[deal] = ("NOT_PRESENT" if o is None else
                     "PASS" if commitment(o) == commitment(opening(deal)) else "FAIL")
    return out


ROLES = {"counterparty": [PUB["counterparty"]], "judge": [PUB["judge"]]}


def pins(run: dict, native: dict | None = None, roles: dict | None = None) -> dict:
    trust = {"responder_keys": [history_vectors.PUB["holder"]],
             "log_keys": [cp["log_key"] for cp in run["checkpoints"]],
             "foreign_keys": [PUB["counterparty"], PUB["judge"]], "parties": {}, "successions": [],
             "require_action_time_from_other_party": False}
    out: dict[str, Any] = {"trust_policy": trust,
                           "verification_policy": {"online": False, "profiles_implemented": [PROFILE],
                                                   "kinds_implemented": KINDS},
                           "contract_ref": CONTRACT_REF, "contract_digest": CONTRACT_DIGEST,
                           "outcome_roles": roles or ROLES, "outcome_requirements": OUTCOME_REQUIREMENTS,
                           "evaluation_time": EVAL}
    if native is not None:
        out["native_observations"] = native
    return out


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------


def cases(run: dict) -> list[dict]:
    ex = {e["name"]: e for e in run["exchanges"]}
    basic = json.loads(run["definitions"]["basic"])
    history = [ex[f"history-{i}"] for i in (1, 2, 3)]
    envs = [decode(e["reply"]) for e in history]
    deals = [e["subject"]["correlation"] for e in envs]
    d1, d2 = deals[0], deals[1]
    d1_records = [r["digest"] for r in artifact_of(envs[0])["records"]]
    d2_records = [r["digest"] for r in artifact_of(envs[1])["records"]]
    x402_objects, x402_lookup, x402_digests = x402_positive()
    native_obs = {"x402-v0": {"lookup": x402_lookup}}
    all_openings = {d: opening(d) for d in deals}

    def case(cid: str, title: str, cites: list[str], source: str, extra: list[dict], claims: list[dict], *,
             evidence: list[dict] | None = None, openings: dict | None = None, defn: dict | None = None,
             hprops: dict | None = None, native: bool = False, roles: dict | None = None) -> dict:
        d = defn if defn is not None else definition(basic)
        digest = shx(jcs(d).encode())
        exchanges = [reanswer(x, env, digest, cid, extra if i == 0 else []) for i, (x, env) in
                     enumerate(zip(history, envs))]
        results = [answered(decode(rep)) for _, rep in exchanges]
        hp = hprops or history_props()
        opened = all_openings if openings is None else openings
        accepted = all(x["accepted"] for x in results) and all(v == "PASS" for v in hp.values())
        # §8.1: claims are evaluated only in an accepted History.
        expected_claims = claims if accepted else None
        fails = sorted({p for c in expected_claims or [] for p, s in c["properties"].items() if s == "FAIL"}
                       | {p for p, s in hp.items() if s == "FAIL"}
                       | ({"deal_commitment_opening"} if "FAIL" in openings_result(deals, opened).values() else set()))
        inputs: dict[str, Any] = {"history": HISTORY, "definition": d,
                                  "exchanges": [{"request": q, "reply": r} for q, r in exchanges],
                                  "evidence": evidence or [], "openings": opened}
        return {"id": cid, "title": title, "cites": cites, "source": source, "mode": "asked",
                "pins": pins(run, native_obs if native else None, roles), "inputs": inputs,
                "expected": {"exchanges": results, "history_properties": hp, "accepted": accepted,
                             "claims": expected_claims,
                             "requirements": requirement_results(deals, expected_claims) if accepted else None,
                             "deal_commitment_opening": openings_result(deals, opened), "fails": fails}}

    def outcome(predicate: str, src: str, ev: list[str] | None = None, **more: Any) -> dict:
        o: dict[str, Any] = {"predicate": predicate, "source": src}
        if ev is not None:
            o["evidence"] = sorted(ev)
        o.update(more)
        return o

    derived = "derived: history-1 to history-3 asked under the Outcome level definition, the deal commitment " \
              "added to each deal's first record"
    out = []

    # §5.1: the holder's own record.
    r = record(1, "outcome_recorded", outcome=outcome("completed", "holder_record"))
    out.append(case("holder-record", "The holder's agent records the first deal as completed",
                    ["§5.1", "§6", "§8.3", "§8.4"], f"{derived}; one outcome record added, re-signed by the holder key",
                    [r], [claim_result(d1, r, claim_props("holder_record"))]))

    # §5.2: the other party's half.
    h = half("delivered", d1)
    hd = shx(h["octets_text"].encode())
    r = record(1, "outcome_recorded", outcome=outcome("delivered", "counterparty_half", [hd]))
    out.append(case("counterparty-half", "The other party's half states the first deal delivered",
                    ["§5.2", "§6", "§8.3", "§8.4", "IP §6.7.4"],
                    f"{derived}; one outcome record citing the half, re-signed by the holder key; the half "
                    "signed by the other party's key", [r], [claim_result(d1, r, claim_props("counterparty_half"))],
                    evidence=[h]))

    # §5.3: a native object, read through the x402 adapter declaration (predicate X3).
    r = record(1, "outcome_recorded", outcome=outcome("paid", "native_object", x402_digests, adapter="x402-v0",
                                                       adapter_predicate="X3"))
    out.append(case("native-object", "An x402 payment, executed on chain, attached by the holder to the first deal",
                    ["§5.3", "§6", "§8.3", "§8.4", "spec/adapters/x402-v0.md §8"],
                    f"{derived}; one outcome record citing the x402 adapter corpus's positive objects, re-signed by "
                    "the holder key", [r], [claim_result(d1, r, claim_props("native_object"))],
                    evidence=x402_objects, native=True))

    # §5.4: a judge's verdict, after the holder's consent.
    def judged(cid: str, title: str, *, acts: list[str] = d1_records, signer: str = "judge", named: str = "judge",
               subject: str = d1, consent_seq: int = 1, defn: dict | None = None, verdict: str = "met",
               **props: str) -> dict:
        jr = judge_record(subject, acts, verdict, signer, named)
        jd = shx(jr["octets_text"].encode())
        c = record(consent_seq, "judge_consent", consent={"judge": PUB["judge"], "contract_ref": JUDGE_CONTRACT_REF})
        r = record(2, "outcome_recorded", outcome=outcome("completed", "judge_verdict", [jd]))
        recs = sorted([c, r], key=lambda x: x["leaf_index"])
        return case(cid, title, ["§5.4", "§6", "§8.3", "§8.4"],
                    f"{derived}; a consent record and an outcome record citing the judge record, re-signed by the "
                    f"holder key; the judge record signed by the {signer} key",
                    recs, [claim_result(d1, r, claim_props("judge_verdict", **props))], evidence=[jr], defn=defn)

    out.append(judged("judge-verdict", "A judge, consented to first, finds the first deal completed from its records"))

    # The not_evaluable case: payment established two ways, delivery asked for.
    ph = half("paid", d1)
    r1 = record(1, "outcome_recorded", outcome=outcome("paid", "native_object", x402_digests, adapter="x402-v0",
                                                        adapter_predicate="X3"))
    r2 = record(2, "outcome_recorded", outcome=outcome("paid", "counterparty_half", [shx(ph["octets_text"].encode())]))
    out.append(case("not-evaluable-delivered-from-payment-evidence",
                    "Payment shown by the payment and by the other party's half; delivery is not established",
                    ["§6", "§6.3", "§8.4"],
                    f"{derived}; two outcome records, re-signed by the holder key", [r1, r2],
                    [claim_result(d1, r1, claim_props("native_object")),
                     claim_result(d1, r2, claim_props("counterparty_half"))],
                    evidence=[*x402_objects, ph], native=True))

    # §7: the deal commitment.
    r = record(1, "outcome_recorded", outcome=outcome("completed", "holder_record"))
    hr = [claim_result(d1, r, claim_props("holder_record"))]
    out.append(case("deal-commitment-unopened", "The second deal's commitment, with no opening carried",
                    ["§7"], f"{derived}; the second deal's opening left out", [r], hr,
                    openings={d: o for d, o in all_openings.items() if d != d2}))
    out.append(case("deal-commitment-wrong-opening", "The second deal's commitment, opened with other text",
                    ["§7"], f"{derived}; the second deal's opening text changed", [r], hr,
                    openings={**all_openings, d2: opening(d2, text=f"other terms of {d2}")}))

    # Mutants of the level's properties.
    out.append(judged("source-not-allowed", "A judge verdict under a definition that does not name that source",
                      defn=definition(basic, sources=["counterparty_half", "holder_record", "native_object"]),
                      outcome_source_allowed="FAIL"))
    out.append(judged("judgment-before-consent", "The consent record is committed after the judgment's outcome record",
                      consent_seq=3, consent_precedes_judgment="FAIL"))
    out.append(judged("judge-acts-outside-deal", "The judge's verdict grounds on a record of another deal",
                      acts=[d1_records[0], d2_records[0]], judge_grounds="FAIL"))
    out.append(judged("judge-signature-forged", "The judge record names the judge and is signed by another key",
                      signer="not-the-judge", judge_signature="FAIL"))
    out.append(judged("judge-not-a-judge", "A judge record signed by the other party's key, naming itself as the judge",
                      signer="counterparty", named="counterparty", judge_signer_trust="FAIL",
                      consent_precedes_judgment="FAIL"))
    out.append(judged("judge-for-another-deal", "A judge record naming the second deal, cited for the first",
                      subject=d2, judge_subject="FAIL"))
    out.append(judged("judge-verdict-out-of-scope",
                      "The judge's case for the predicate answers out_of_scope, which no requirement here allows",
                      verdict="out_of_scope", judge_verdict_allowed="FAIL"))

    def halved(cid: str, title: str, h: dict, predicate: str = "delivered", roles: dict | None = None,
               **props: str) -> dict:
        r = record(1, "outcome_recorded", outcome=outcome(predicate, "counterparty_half", [shx(h["octets_text"].encode())]))
        return case(cid, title, ["§5.2", "§8.3"], f"{derived}; one outcome record citing the half, re-signed by the "
                    "holder key", [r], [claim_result(d1, r, claim_props("counterparty_half", **props))], evidence=[h],
                    roles=roles)

    out.append(halved("half-states-other-predicate", "A half stating payment, cited for delivery",
                      half("paid", d1), half_states="FAIL"))
    out.append(halved("half-for-another-deal", "A half naming the second deal, cited for the first",
                      half("delivered", d2), half_subject="FAIL"))
    hk = half("delivered", d1, "holder")
    out.append(halved("half-under-holder-key", "A half signed by the holder key",
                      hk, half_signer_trust="FAIL", issuer_independence="FAIL"))
    out.append(halved("half-under-holder-key-trusted",
                      "A half signed by the holder key, under a policy that accepts that key as the other party's",
                      hk, roles={**ROLES, "counterparty": [PUB["counterparty"], history_vectors.PUB["holder"]]},
                      issuer_independence="FAIL"))
    out.append(halved("half-signature-forged", "A half naming the other party's key, signed by another key",
                      half("delivered", d1, "not-the-judge", named="counterparty"), half_signature="FAIL"))

    # §5.3 and FR-20a's rule as §6.3 states it: payment evidence cited for delivery.
    r = record(1, "outcome_recorded", outcome=outcome("delivered", "native_object", x402_digests, adapter="x402-v0",
                                                       adapter_predicate="X3"))
    out.append(case("payment-evidence-claimed-as-delivered", "An x402 payment cited as evidence of delivery",
                    ["§5.3", "§6.3", "§8.3"], f"{derived}; one outcome record, re-signed by the holder key", [r],
                    [claim_result(d1, r, claim_props("native_object", outcome_form="FAIL",
                                                     adapter_predicate_maps="FAIL"))],
                    evidence=x402_objects, native=True))

    r = record(1, "outcome_recorded", outcome=outcome("paid", "native_object", x402_digests, adapter="x402-v0",
                                                       adapter_predicate="X3"))
    out.append(case("native-object-not-held", "An x402 payment cited, its octets not carried",
                    ["§5.3", "§8.3"], f"{derived}; one outcome record, re-signed by the holder key", [r],
                    [claim_result(d1, r, claim_props("native_object", outcome_evidence="NOT_PRESENT",
                                                     native_check="NOT_CHECKED"))], native=True))

    r = record(1, "outcome_recorded", outcome=outcome("disputed", "holder_record"))
    out.append(case("disputed-as-outcome-claim", "A holder record claiming the deal disputed",
                    ["§6.4", "§8.3"], f"{derived}; one outcome record, re-signed by the holder key", [r],
                    [claim_result(d1, r, claim_props("holder_record", outcome_form="FAIL"))]))

    r = record(1, "outcome_recorded", outcome=outcome("completed", "holder_record"))
    out.append(case("predicates-digest-altered", "A definition whose predicates member is not the table's digest",
                    ["§3", "§6.1", "§8.2"], f"{derived}; the definition's predicates member changed", [r],
                    [], defn=definition(basic, predicates=label("another predicate table")),
                    hprops=history_props(predicate_binding="FAIL")))

    r = record(1, "step_completed", outcome=outcome("completed", "holder_record"))
    out.append(case("outcome-on-a-step-record", "An outcome member on a step record",
                    ["§4", "§8.2"], f"{derived}; one step record carrying an outcome, re-signed by the holder key", [r],
                    [], hprops=history_props(record_kinds="FAIL")))

    r = record(1, "outcome_recorded", outcome=outcome("completed", "holder_record"))
    other_rule = {"kind": "stream_interval", "rule": "records_of_completed_deals",
                  "interval": {"from": None, "to": label("an anchor")},
                  "live_set": [{"stream": "holder-stream-1", "checkpoint": label("a checkpoint"), "start": 0,
                                "count": 1}]}
    out.append(case("coverage-rule-not-all-records", "A stream_interval declaration under a rule other than all_records",
                    ["§3", "§8.2"], f"{derived}; the definition's coverage declaration changed", [r],
                    [], defn=definition(basic, coverage_declaration=other_rule),
                    hprops=history_props(coverage_declaration_form="FAIL")))
    return out


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def _dump(value: Any) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def build(run: dict, run_sha256: str) -> dict[str, bytes]:
    all_cases = cases(run)
    ids = [c["id"] for c in all_cases]
    assert len(ids) == len(set(ids)), "duplicate case id"
    run_ref = {"path": "personal-history-basic-v0/responder-run.json", "sha256": run_sha256}
    labels = {**history_vectors.SEED_LABELS, **SEED_LABELS}
    corpus = {
        "set": SET,
        "status": STATUS,
        "profile": PROFILE,
        "history": HISTORY,
        "spec": SPEC,
        "run": run_ref,
        "test_keys": {
            "note": "TEST-ONLY. Each private key is the 32-byte Ed25519 seed SHA-256(seed_label).",
            "keys": {name: {"seed_label": labels[name], "public": ALL_PUB[name]}
                     for name in ("holder", "counterparty", "judge", "not-the-judge")},
        },
        "predicates": {"document": PREDICATES, "document_jcs": jcs(PREDICATES), "digest": PREDICATES_DIGEST},
        "contract": {"document": CONTRACT, "document_jcs": jcs(CONTRACT), "contract_ref": CONTRACT_REF,
                     "contract_digest": CONTRACT_DIGEST, "schema": EC_SCHEMA},
        "history_properties": HISTORY_PROPS,
        "claim_properties": CLAIM_PROPS,
        "count": len(all_cases),
        "cases": all_cases,
    }
    files = {"vectors.json": _dump(corpus)}
    files["manifest.json"] = _dump({
        "set": SET,
        "status": STATUS,
        "spec": SPEC,
        "generator": "python/scripts/generate_personal_history_outcome_v0_vectors.py",
        "run": run_ref,
        "native_objects": {"corpus": "adapters/x402/cases.json", "case": "positive",
                           "note": "the payment payload and settlement response octets unchanged; the lookup with "
                                   "final set to true"},
        "files": [{"path": name, "sha256": shx(data), "count": json.loads(data).get("count")}
                  for name, data in sorted(files.items())],
    })
    return files


def write(out: Path, run_path: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    raw = run_path.read_bytes()
    for name, data in build(load_run(run_path), shx(raw)).items():
        (out / name).write_bytes(data)
    files = sorted((p.relative_to(out).as_posix(), p) for p in out.rglob("*") if p.is_file())
    lines = [f"{shx(p.read_bytes())}  {rel}" for rel, p in files if rel != "SHA256SUMS"]
    (out / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--run", type=Path, default=RUN, help="the History run to build from")
    args = parser.parse_args()
    write(args.out, args.run)


if __name__ == "__main__":
    main()
