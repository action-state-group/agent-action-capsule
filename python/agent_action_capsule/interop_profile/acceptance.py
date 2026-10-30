# SPDX-License-Identifier: BSD-3-Clause
"""Acceptance records, receipts and the acceptance finding (profile §11.1).

Given the contract version evaluated, the transaction, the two parties' keys and every acceptance
record, acceptance receipt and execution record the verifier holds, this module reports the
§11.1.7 properties of each candidate and each receipt and the §11.1.8 finding.

Trust in a key is "as of evaluation" (§11.1.7): the caller's evaluation time, never the clock. A
record's own ``issued_at`` is the signer's claim and never shows when it was signed (§11.1.5).

Records and receipts are read as JSON. A record that asserts ``authority`` is labelled
``agent_origin_assertion`` (§11.1.6): this module checks no cited authorization. The optional
acceptance of a key retired after an earlier ordering point (§11.1.7, a MAY) is not implemented.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Callable

from ._common import (
    FAIL,
    INCONCLUSIVE,
    NOT_CHECKED,
    NOT_PRESENT,
    PASS,
    PROFILE_ID,
    PropertyReport,
    TrustPolicy,
    ceil_seconds,
    ed25519_verify_hex,
    floor_seconds,
    is_digest,
    is_key_id,
    is_profile_time,
    is_signature,
    is_text,
    json_value_digest,
    member_of,
    numbers_in_domain,
    parse_json,
    parse_time,
    unsigned_jcs,
)
from .exchange import contract_ref_of

__all__ = [
    "ExecutionRecord",
    "read_fixture_execution_record",
    "Candidate",
    "ReceiptResult",
    "AcceptanceResult",
    "evaluate_acceptance",
    "CANDIDATE_PROPERTIES",
]

STATES = ("proposed", "accepted", "declined", "countered")
CANDIDATE_PROPERTIES = (
    "acceptance_form", "acceptance_signature", "acceptance_signer_trust", "acceptance_binding",
    "proposal_binding", "acceptance_unique", "execution_cites_acceptance", "acceptance_ordering",
)
_RANK = ("accepted_before_action", "accepted_execution_cites", "accepted_not_cited", "not_accepted")
_DECIDING = ("acceptance_form", "acceptance_signature", "acceptance_signer_trust", "acceptance_binding",
             "proposal_binding")


@dataclass(frozen=True)
class ExecutionRecord:
    """What the verifier reads from one execution record: its verified issuer (None when its
    signature does not verify), the time it claims for the action, the digests it cites, the
    transaction it names, and the method used to read it."""

    issuer: str | None
    action_at: str | None
    cites: frozenset
    transaction: Any
    method: str


def read_fixture_execution_record(octets: bytes) -> ExecutionRecord | None:
    """The execution record format §11.5 fixes for the conformance vectors only (not registered):
    ``action_at``, ``issuer``, ``links`` (EL link shape, type ``cites``), ``transaction``, ``sig``;
    ``sig`` is Ed25519 by ``issuer`` over UTF-8 of JCS of the other members. A record JCS cannot
    represent (for example one holding an unpaired surrogate) is unreadable, as an acceptance record
    or receipt is."""
    parsed = parse_json(octets)
    if parsed is None or not parsed.well_formed or not isinstance(parsed.value, dict):
        return None
    rec = parsed.value
    body = unsigned_jcs(rec)
    if body is None or json_value_digest(rec) is None:  # sig included
        return None
    verified = ed25519_verify_hex(rec.get("issuer"), rec.get("sig"), body)
    links = rec.get("links") if isinstance(rec.get("links"), list) else []
    cites = frozenset(link["target"] for link in links if isinstance(link, dict) and link.get("type") == "cites"
                      and is_digest(link.get("target")))
    return ExecutionRecord(rec.get("issuer") if verified else None, rec.get("action_at"), cites,
                           rec.get("transaction"), "§11.5 fixture execution record: Ed25519 over JCS; EL cites link")


@dataclass
class ReceiptResult:
    receipt_digest: str
    acceptance_digest: Any
    properties: list = field(default_factory=list)

    def status(self, prop: str) -> str | None:
        return next((r.status for r in self.properties if r.property == prop), None)


@dataclass
class Candidate:
    record_digest: str
    record: dict
    properties: list = field(default_factory=list)
    finding: str = "not_accepted"
    relied_receipts: list = field(default_factory=list)

    def status(self, prop: str) -> str | None:
        return next((r.status for r in self.properties if r.property == prop), None)


@dataclass
class AcceptanceResult:
    finding: str
    candidates: list
    receipts: list
    contract_ref: str | None = None
    evidence: list = field(default_factory=list)
    unreadable: list = field(default_factory=list)

    @property
    def claim_fields(self) -> dict | None:
        """§11.1.8: where the finding is not ``not_accepted``, each claim's ``contract_ref`` is the
        accepted record's and its ``evidence[]`` lists the record and every receipt relied on."""
        if self.finding == "not_accepted":
            return None
        return {"contract_ref": self.contract_ref, "evidence_includes": list(self.evidence)}


def _signer(record: Mapping[str, Any]) -> Any:
    return record.get("proposer") if record.get("state") == "proposed" else record.get("acceptor")


def _form_problems(r: Mapping[str, Any]) -> list[str]:
    """§11.1.2 and §11.1.3, as ``acceptance_form`` checks them."""
    out = []
    state = r.get("state")
    if r.get("profile") != PROFILE_ID:
        out.append("profile is not evidence-interop/0")
    if state not in STATES:
        out.append("state is not one of the four tokens, exact case")
    for name in ("contract_ref",):
        if not is_text(r.get(name)):
            out.append(f"{name} is not text")
    for name in ("contract_digest",):
        if not is_digest(r.get(name)):
            out.append(f"{name} is not a digest")
    for name in ("proposer", "acceptor"):
        if not is_key_id(r.get(name)):
            out.append(f"{name} is not a key identifier")
    t = r.get("transaction")
    if not (isinstance(t, dict) and set(t) == {"scheme", "id"} and all(is_text(v) for v in t.values())):
        out.append("transaction is not {scheme, id} of text")
    if not is_profile_time(r.get("issued_at")):
        out.append("issued_at is not in the §5.2 form")
    if not is_signature(r.get("sig")):
        out.append("sig is not an Ed25519 signature")
    if state == "proposed" and "proposal_digest" in r:
        out.append("proposal_digest is present in a proposed record")
    if state in ("accepted", "declined", "countered") and not is_digest(r.get("proposal_digest")):
        out.append("proposal_digest is absent or not a digest")
    if state == "countered" and not is_digest(r.get("counter_contract_digest")):
        out.append("counter_contract_digest is absent or not a digest")
    if state != "countered" and "counter_contract_digest" in r:
        out.append("counter_contract_digest is present outside countered")
    if "session" in r:
        s = r["session"]
        ok = isinstance(s, dict) and {"not_before", "not_after"} <= set(s) <= \
            {"not_before", "not_after", "policy", "terms"} and is_profile_time(s["not_before"]) and \
            is_profile_time(s["not_after"]) and s["not_after"] >= s["not_before"] and \
            all(is_digest(s[k]) for k in ("policy", "terms") if k in s)
        if not ok:
            out.append("session is not a valid window (§11.1.3)")
    if "authority" in r and not (isinstance(r["authority"], list) and all(is_digest(a) for a in r["authority"])):
        out.append("authority is not an array of digests")
    return out


def evaluate_acceptance(
    contract: Mapping[str, Any],
    transaction: Mapping[str, Any],
    proposer: str,
    acceptor: str,
    records: Sequence[bytes],
    execution_records: Sequence[bytes],
    receipts: Sequence[bytes],
    trust: TrustPolicy,
    evaluation_time: str,
    *,
    session: bool = False,
    form_ii_objects: Sequence[Any] = (),
    profiles_implemented: frozenset = frozenset({PROFILE_ID}),
    read_execution_record: Callable[[bytes], ExecutionRecord | None] = read_fixture_execution_record,
) -> AcceptanceResult:
    """The §11.1.8 finding for one contract version and one transaction.

    With ``session`` true, ``transaction`` names the session and the candidates are session
    acceptances whose window covers every time held for the exchange (§11.1.3, §11.1.8).
    ``form_ii_objects`` are transparency-service or witness receipts (§11.1.5 form ii); this
    revision names no mechanism for them, so they are held but never checked (``NOT_CHECKED``).
    """
    if parse_time(evaluation_time) is None:
        raise ValueError("evaluation_time must be an RFC 3339 time; the verifier never reads the clock")
    contract_digest = json_value_digest(contract) if numbers_in_domain(contract) else None
    if contract_digest is None:
        raise ValueError("the contract carries a value JCS cannot represent, or a number outside 0 to 2^53 - 1; "
                         "no contract_digest (§11.3.7)")
    if not (isinstance(contract.get("id"), str) and isinstance(contract.get("version"), str)
            and isinstance(contract.get("requirements", []), list)):
        raise ValueError("the contract's id or version is not text, or its requirements are not an array "
                         "(§11.3.7)")
    ids = [q.get("id") if isinstance(q, dict) else None for q in contract.get("requirements", [])]
    if len({json_value_digest(i) for i in ids}) != len(ids):
        raise ValueError("two requirements share one id; the contract version is not evaluated (§11.3.7)")
    contract_ref = contract_ref_of(contract)
    implemented = profiles_implemented & {PROFILE_ID}

    held: dict[str, dict] = {}  # by record digest: two copies of one record are one record
    unreadable: list = []
    for octets in records:
        parsed = parse_json(octets)
        digest = json_value_digest(parsed.value) if parsed is not None and parsed.well_formed else None
        if digest is None or not isinstance(parsed.value, dict):
            unreadable.append(octets)
            continue
        held.setdefault(digest, parsed.value)
    receipt_objs: list = []
    for octets in receipts:
        parsed = parse_json(octets)
        digest = json_value_digest(parsed.value) if parsed is not None and parsed.well_formed else None
        if digest is None or not isinstance(parsed.value, dict):
            unreadable.append(octets)
            continue
        receipt_objs.append((digest, parsed.value))
    execs = [read_execution_record(o) for o in execution_records]
    unreadable += [o for o, e in zip(execution_records, execs) if e is None]
    execs = [e for e in execs if e is not None]

    def sig_ok(r: Mapping[str, Any]) -> bool:
        body = unsigned_jcs(r)
        return body is not None and ed25519_verify_hex(_signer(r), r.get("sig"), body)

    def role_trust(r: Mapping[str, Any]) -> str:
        counterpart = r.get("acceptor") if r.get("state") == "proposed" else r.get("proposer")
        return trust.accepts_in_role(_signer(r), counterpart, evaluation_time)

    def in_window(r: Mapping[str, Any], times: Sequence[str]) -> bool:
        s = r.get("session")
        return isinstance(s, dict) and all(
            parse_time(s.get("not_before")) is not None and parse_time(s.get("not_after")) is not None
            and parse_time(s["not_before"]) <= parse_time(t) <= parse_time(s["not_after"])
            for t in times if parse_time(t) is not None)

    # Sort what is held (§11.1.5, §11.1.7). A record whose signature verifies under the acceptor
    # key, or under a key the trust policy maps to the acceptor's party, is the acceptor's own
    # execution record. One verified under a trusted key of another party is that party's
    # attestation of the action: a time for it, never an execution record. Anything else is held
    # as an execution record that is not attributed to the acceptor.
    acceptor_party = trust.parties.get(acceptor)

    def party_now(key: Any) -> Any:
        status, party = trust.party_of(key, evaluation_time)
        return party if status == PASS else None

    own_records, attestations = [], []
    for e in execs:
        party = party_now(e.issuer) if e.issuer is not None else None
        if e.issuer == acceptor or (party is not None and party == acceptor_party):
            own_records.append(e)
        elif party is not None:
            attestations.append(e)
        else:
            own_records.append(e)

    def times(records_: Sequence[ExecutionRecord]) -> list:
        """Each time the records give for the action, rounded down to the second (§11.1.5)."""
        out = []
        for e in records_:
            moment = parse_time(e.action_at)
            if e.issuer is None or moment is None or (not session and e.transaction != transaction):
                continue
            out.append(floor_seconds(moment))
        return out

    own_times = times([e for e in own_records if e.issuer is not None and
                       (e.issuer == acceptor or party_now(e.issuer) == acceptor_party)])
    other_times = times(attestations)
    action_times = own_times + other_times

    candidates: list[Candidate] = []
    out_receipts: list[ReceiptResult] = []
    for digest, r in held.items():
        if not (r.get("state") == "accepted" and r.get("contract_digest") == contract_digest
                and r.get("proposer") == proposer and r.get("acceptor") == acceptor
                and r.get("transaction") == transaction and ("session" in r) == session):
            continue
        if session and not in_window(r, [e.action_at for e in own_records + attestations]):
            continue
        cand = Candidate(digest, r)
        candidates.append(cand)
        if not member_of(r.get("profile"), implemented):
            cand.properties = [PropertyReport(p, NOT_CHECKED, "not run (§11.1.7, §3.3 step 5)",
                                              f"profile {r.get('profile')!r} is not implemented")
                               for p in CANDIDATE_PROPERTIES]
            continue
        p: dict[str, PropertyReport] = {}
        problems = _form_problems(r)
        p["acceptance_form"] = PropertyReport("acceptance_form", FAIL if problems else PASS,
                                              "§11.1.2 members and forms", "; ".join(problems) or None)
        p["acceptance_signature"] = PropertyReport(
            "acceptance_signature", PASS if sig_ok(r) else FAIL,
            "Ed25519 by the key the state names, over JCS of every member but sig (§11.1.2)")
        p["acceptance_signer_trust"] = PropertyReport(
            "acceptance_signer_trust", role_trust(r), f"trust policy, as the acceptor, as of {evaluation_time}")
        binding_ok = r.get("contract_digest") == contract_digest and r.get("contract_ref") == contract_ref
        p["acceptance_binding"] = PropertyReport(
            "acceptance_binding", PASS if binding_ok else FAIL,
            "contract_digest against the contract evaluated; contract_ref against its id@version (§11.1.2)",
            # §11.1.6: no cited authorization is checked by this verifier, so asserted authority
            # is labelled as the agent's own assertion.
            "agent_origin_assertion" if "authority" in r else None)
        p["proposal_binding"] = _proposal_binding(r, held, sig_ok, role_trust)
        # Answers are held by record digest, so each is a distinct answer: two of them is the
        # equivocation of §11.1.1.
        answers = [d for d, a in held.items() if a.get("state") in ("accepted", "declined", "countered")
                   and a.get("proposal_digest") == r.get("proposal_digest") and a.get("acceptor") == r.get("acceptor")
                   and sig_ok(a) and role_trust(a) == PASS]
        method = "one record digest among verified answers to one proposal (§11.1.1)"
        if len(answers) < 2:
            p["acceptance_unique"] = PropertyReport("acceptance_unique", NOT_CHECKED, method,
                                                    "fewer than two verified answers are held")
        else:
            p["acceptance_unique"] = PropertyReport("acceptance_unique", FAIL, method,
                                                    f"{len(answers)} different answers to one proposal")
        p["execution_cites_acceptance"] = _execution_cites(r, digest, own_records, session, in_window,
                                                           lambda key: key == acceptor or party_now(key) == acceptor_party)
        # Receipts for this record (§11.1.4) and the ordering (§11.1.5).
        rps = []
        for rdigest, rc in receipt_objs:
            if rc.get("acceptance_digest") != digest:
                continue
            rr = ReceiptResult(rdigest, digest, _receipt_properties(rc, r, trust, evaluation_time, implemented))
            out_receipts.append(rr)
            rps.append((rc, rr))
        order, relied = _ordering(r, rps, action_times, other_times, trust, form_ii_objects)
        p["acceptance_ordering"] = order
        cand.properties = [p[k] for k in CANDIDATE_PROPERTIES]
        if any(p[k].status != PASS for k in _DECIDING) or p["acceptance_unique"].status == FAIL:
            cand.finding = "not_accepted"
        elif order.status == FAIL:
            cand.finding = "accepted_after_action"
        elif p["execution_cites_acceptance"].status != PASS:
            cand.finding = "accepted_not_cited"
        elif order.status == PASS:
            cand.finding = "accepted_before_action"
            cand.relied_receipts = relied
        else:
            cand.finding = "accepted_execution_cites"

    findings = [c.finding for c in candidates]
    if not candidates or any(c.status("acceptance_unique") == FAIL for c in candidates):
        finding = "not_accepted"
    elif "accepted_after_action" in findings:
        finding = "accepted_after_action"
    else:
        finding = min(findings, key=_RANK.index)
    result = AcceptanceResult(finding, candidates, out_receipts, unreadable=unreadable)
    if finding != "not_accepted":
        best = next(c for c in candidates if c.finding == finding)
        result.contract_ref = best.record.get("contract_ref")
        result.evidence = [{"digest_alg": "SHA-256", "digest": d} for d in [best.record_digest] + best.relied_receipts]
    return result


def _proposal_binding(r, held, sig_ok, role_trust) -> PropertyReport:
    method = "the proposed record answered: signature, proposer trust, and the §11.1.2 equality rule"
    prop = held.get(r.get("proposal_digest")) if is_digest(r.get("proposal_digest")) else None
    if prop is None:
        return PropertyReport("proposal_binding", NOT_PRESENT, method, "the proposed record is not held")
    problems = []
    if prop.get("state") != "proposed":
        problems.append("the record named is not a proposed record")
    if not sig_ok(prop):
        problems.append("its signature does not verify")
    trust_status = role_trust(prop)
    if trust_status != PASS:
        problems.append("the policy does not accept its signer as the proposer")
    for k in ("contract_ref", "contract_digest", "transaction", "proposer", "acceptor", "session"):
        if (k in prop) != (k in r) or prop.get(k) != r.get(k):
            problems.append(f"{k} differs from the proposal")
    if not problems:
        return PropertyReport("proposal_binding", PASS, method)
    status = INCONCLUSIVE if problems == ["the policy does not accept its signer as the proposer"] and \
        trust_status == INCONCLUSIVE else FAIL
    return PropertyReport("proposal_binding", status, method, "; ".join(problems))


def _execution_cites(r, digest, execs, session, in_window, attributed) -> PropertyReport:
    method = "each execution record: verified under the acceptor key or a key the policy maps to its party, " \
             "an EL cites link to the record digest, " \
             + ("within the session window" if session else "naming the record's transaction")
    if not execs:
        return PropertyReport("execution_cites_acceptance", NOT_PRESENT, method, "no execution record is held")
    problems = []
    for e in execs:
        if e.issuer is None or not attributed(e.issuer):
            problems.append("an execution record is not attributed to the acceptor")
        elif digest not in e.cites:
            problems.append("an execution record does not cite the accepted record")
        elif not session and e.transaction != r.get("transaction"):
            problems.append("an execution record names another transaction")
        elif session and not in_window(r, [e.action_at]):
            problems.append("an execution record lies outside the session window")
    method = f"{method}; read by {execs[0].method}"
    return PropertyReport("execution_cites_acceptance", FAIL if problems else PASS, method,
                          "; ".join(problems) or None)


def _receipt_properties(rc, record, trust: TrustPolicy, evaluation_time: str, implemented) -> list:
    if not member_of(rc.get("profile"), implemented):
        return [PropertyReport(p, NOT_CHECKED, "not run (§11.1.7)", f"profile {rc.get('profile')!r} is not implemented")
                for p in ("receipt_signature", "receipt_signer")]
    members_ok = set(rc) == {"profile", "acceptance_digest", "received_at", "receiver", "sig"}
    body = unsigned_jcs(rc)
    sig = members_ok and body is not None and ed25519_verify_hex(rc.get("receiver"), rc.get("sig"), body)
    receiver = rc.get("receiver")
    if receiver != record.get("proposer") or receiver == record.get("acceptor"):
        signer = FAIL
    else:
        signer = trust.accepts_in_role(receiver, record.get("acceptor"), evaluation_time)
    return [PropertyReport("receipt_signature", PASS if sig else FAIL,
                           "Ed25519 by receiver over JCS of the other four members (§11.1.4)",
                           None if members_ok else "members are not exactly those of §11.1.4"),
            PropertyReport("receipt_signer", signer,
                           f"receiver is the proposer, not the acceptor, and accepted as the proposer as of "
                           f"{evaluation_time} (§11.1.7)")]


def _ordering(r, rps, action_times, other_times, trust, form_ii) -> tuple[PropertyReport, list]:
    """``acceptance_ordering`` (§11.1.5): the first rule that applies decides."""
    method = "§11.1.5: form (i) receipts against the earliest time held for the action"
    if not action_times:
        return PropertyReport("acceptance_ordering", NOT_PRESENT, method, "rule 1: no time for the action"), []
    issued = parse_time(r.get("issued_at"))
    # Strictly later only: an equal time, at the precision held (a producer may hold times to the
    # minute), does not order the acceptance after the action.
    if issued is not None and any(issued > t for t in action_times):
        return PropertyReport("acceptance_ordering", FAIL, method,
                              "rule 2: the record's own issued_at is later than a time held for the action"), []
    if trust.require_action_time_from_other_party and not other_times:
        return PropertyReport("acceptance_ordering", NOT_PRESENT, method,
                              "rule 3: the policy requires a time for the action from another party; none held"), []
    reference = min(action_times)  # already rounded down
    counted, unresolved = [], False
    for rc, rr in rps:
        statuses = (rr.status("receipt_signature"), rr.status("receipt_signer"))
        point = parse_time(rc.get("received_at"))
        if statuses == (PASS, PASS) and point is not None:
            counted.append((ceil_seconds(point), rr.receipt_digest))  # an ordering point rounds up
        elif statuses[0] == PASS and statuses[1] == INCONCLUSIVE:
            unresolved = True
    earlier = [d for point, d in counted if point < reference]
    if earlier:
        return PropertyReport("acceptance_ordering", PASS, method,
                              "rule 4: a counterparty receipt is earlier than the action reference point"), earlier
    if counted or unresolved:
        why = "no counted receipt is earlier than the action" if counted else "a receipt signer is unresolved"
        return PropertyReport("acceptance_ordering", INCONCLUSIVE, method, f"rule 5: {why}"), []
    if form_ii:
        return PropertyReport("acceptance_ordering", NOT_CHECKED, method,
                              "rule 6: only form (ii) objects are held, and no mechanism is implemented (P-13)"), []
    return PropertyReport("acceptance_ordering", NOT_PRESENT, method, "rule 7: no ordering evidence counts"), []
