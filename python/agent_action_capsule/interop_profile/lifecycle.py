# SPDX-License-Identifier: BSD-3-Clause
"""Lifecycle statements: their properties, findings, and what a verifier shows (profile §11.2).

The verifier is given every record it holds, each with its kind, because the issuer of a record
and whether it may be amended depend on the kind (§11.2.3, §11.2.4). The chain of a record is
built from links alone; ``issued_at`` and the order of receipt never change it (§11.2.6).

Not implemented: a ``supersedes`` or ``rebuts`` link in an Evidence Layer record's ``links``
header, which §11.2.2 evaluates as a statement issued by that record's issuer. Only lifecycle
statements are evaluated here.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from ._cbor import CborError, decode
from ._common import (
    FAIL,
    MEDIA_CBOR,
    MEDIA_JSON,
    NOT_CHECKED,
    NOT_PRESENT,
    PASS,
    PROFILE_ID,
    PropertyReport,
    TrustPolicy,
    ed25519_verify_hex,
    is_digest,
    is_key_id,
    is_profile_time,
    is_text,
    jcs_or_none,
    json_value_digest,
    member_of,
    parse_json,
    parse_time,
    sha256_hex,
    unsigned_jcs,
)

__all__ = ["HeldRecord", "StatementResult", "Display", "LifecycleResult", "evaluate_lifecycle", "RECORD_KINDS"]

TOKENS = ("supersedes", "amends", "rebuts", "disputes", "resolves")
_CORRECTIVE = ("amends", "supersedes")
# §11.2.3: the record kinds this verifier can establish an issuer for. "other" has none.
RECORD_KINDS = ("lifecycle_statement", "producer_record", "acceptance_record", "acceptance_receipt",
                "envelope", "refusal", "absence_record", "other")
# §11.2.4: kinds an amends or supersedes statement must not target.
_EXCLUDED = frozenset({"acceptance_record", "acceptance_receipt", "envelope", "refusal", "absence_record"})
_ENVELOPE_SIGNED = ("profile", "request_digest", "subject", "derivation", "anchor", "artifact_digest",
                    "verification", "responder", "issued_at")


@dataclass(frozen=True)
class HeldRecord:
    """A record as held: its octets, its kind (one of ``RECORD_KINDS``) and its media type.

    ``producer_record`` is the format §11.5 fixes for the conformance vectors only: ``claim``,
    ``issued_at``, ``producer``, ``sig``, its issuer ``producer``.
    """

    octets: bytes
    kind: str
    media_type: str = MEDIA_JSON


@dataclass
class StatementResult:
    statement_digest: str
    statement: dict
    properties: dict = field(default_factory=dict)  # property name -> PropertyReport
    finding: str = "lifecycle_not_effective"

    @property
    def token(self) -> str | None:
        link = self.statement.get("link")
        t = link.get("type") if isinstance(link, dict) else None
        return t if member_of(t, TOKENS) else None

    @property
    def target(self) -> Any:
        link = self.statement.get("link")
        target = link.get("target") if isinstance(link, dict) else None
        return target if is_digest(target) else None


@dataclass
class Display:
    """What a verifier shows for one record (§11.2.6)."""

    historical_claim: str
    latest_supported_state: dict | None  # {"element": digest, "contents": [digest, ...]} or None
    forked_at: str | None
    branches: list
    challenges: list


@dataclass
class LifecycleResult:
    statements: list
    records: dict  # digest -> (kind, value, issuer or None)

    def display(self, root: str) -> Display:
        """The chain of ``root``, its latest supported state, forks and challenges (§11.2.6)."""
        if root not in self.records:
            raise ValueError("the root record is not held")
        by_target: dict[Any, list] = {}
        for s in self.statements:
            by_target.setdefault(s.target, []).append(s)
        if any(s.statement_digest == root and s.token in _CORRECTIVE for s in self.statements):
            raise ValueError("a chain starts at a record that is not an amends or supersedes statement")

        def extend(start: str) -> tuple[list, list, str | None, list]:
            chain, contents = [start], []
            while True:
                nxt = [s for s in by_target.get(chain[-1], []) if s.token in _CORRECTIVE]
                forked = [s for s in nxt if s.finding == "lifecycle_forked"]
                if forked:
                    branches = []
                    for s in sorted(forked, key=lambda x: x.statement_digest):
                        sub_chain, _, _, sub_branches = extend(s.statement_digest)
                        branches.append(sub_chain)
                        branches.extend(sub_branches)
                    return chain, contents, chain[-1], branches
                effective = [s for s in nxt if s.finding == "lifecycle_effective"]
                if not effective:
                    return chain, contents, None, []
                chain.append(effective[0].statement_digest)
                contents.append(effective[0].statement.get("content"))

        chain, contents, forked_at, branches = extend(root)
        elements = set(chain) | {d for b in branches for d in b}
        challenges = []
        for s in self.statements:
            if s.token in ("disputes", "rebuts") and s.finding == "lifecycle_effective" and s.target in elements:
                c = {"statement_digest": s.statement_digest, "type": s.token, "issuer": s.statement.get("issuer"),
                     "on": s.target, "lifecycle_signer_trust": s.properties["lifecycle_signer_trust"].status,
                     "scope": s.statement.get("scope"), "content": s.statement.get("content")}
                if s.token == "disputes":
                    c["status"] = self._dispute_status(s.statement_digest, by_target)
                challenges.append(c)
        latest = None if forked_at else {"element": chain[-1], "contents": contents}
        return Display(root, latest, forked_at, branches, challenges)

    @staticmethod
    def _dispute_status(digest: str, by_target: Mapping[Any, list]) -> str:
        outcomes = [s.statement.get("outcome") for s in by_target.get(digest, [])
                    if s.token == "resolves" and s.finding == "lifecycle_effective"]
        if not outcomes:
            return "open"
        return outcomes[0] if len(set(outcomes)) == 1 else "conflicting"


def _decode(record: HeldRecord) -> dict | None:
    if record.media_type == MEDIA_JSON:
        parsed = parse_json(record.octets)
        ok = parsed is not None and parsed.well_formed and isinstance(parsed.value, dict)
        return parsed.value if ok else None
    if record.media_type == MEDIA_CBOR:
        try:
            d = decode(record.octets)
        except CborError:
            return None
        return d.value if d.well_formed and isinstance(d.value, dict) else None
    return None


def _digest(record: HeldRecord, value: dict | None) -> str:
    """§5.1: a JSON record by JCS; an envelope or refusal, and anything unreadable, by its octets."""
    if value is not None and record.kind not in ("envelope", "refusal", "other"):
        digest = json_value_digest(value)
        if digest is not None:
            return digest
    return sha256_hex(record.octets)


def _issuer(kind: str, v: dict | None) -> str | None:
    """§11.2.3: the key whose verified signature makes the record its own statement."""
    if v is None:
        return None
    if kind in ("lifecycle_statement", "producer_record", "acceptance_record", "acceptance_receipt",
                "absence_record"):
        key = {"lifecycle_statement": v.get("issuer"), "producer_record": v.get("producer"),
               "acceptance_receipt": v.get("receiver"), "absence_record": v.get("key_id"),
               "acceptance_record": v.get("proposer") if v.get("state") == "proposed" else v.get("acceptor")}[kind]
        body = unsigned_jcs(v)
        return key if body is not None and ed25519_verify_hex(key, v.get("sig"), body) else None
    if kind == "refusal":
        body = jcs_or_none({k: v.get(k) for k in ("issued_at", "reason", "request_digest")})
        return v.get("key_id") if body is not None and ed25519_verify_hex(v.get("key_id"), v.get("sig"), body) else None
    if kind == "envelope":
        body = jcs_or_none({k: v[k] for k in _ENVELOPE_SIGNED if k in v})
        key = v.get("responder")
        return key if body is not None and ed25519_verify_hex(key, v.get("sig"), body) else None
    return None


def _form_problems(s: Mapping[str, Any]) -> list[str]:
    """§11.2.2, as ``lifecycle_form`` checks it."""
    out = []
    link = s.get("link")
    token = link.get("type") if isinstance(link, dict) else None
    if s.get("profile") != PROFILE_ID:
        out.append("profile is not evidence-interop/0")
    if not is_key_id(s.get("issuer")):
        out.append("issuer is not a key identifier")
    if not (isinstance(link, dict) and set(link) == {"type", "target"}):
        out.append("link is not {type, target}")
    if not member_of(token, TOKENS):
        out.append("link.type is not one of the five tokens, exact case")
    if isinstance(link, dict) and not is_digest(link.get("target")):
        out.append("link.target is not a digest")
    if "basis" in s and not (isinstance(s["basis"], list) and all(is_digest(b) for b in s["basis"])):
        out.append("basis is not an array of digests")
    if "content" in s and not is_digest(s["content"]):
        out.append("content is not a digest")
    if "scope" in s and not (isinstance(s["scope"], list) and all(is_text(x) for x in s["scope"])):
        out.append("scope is not an array of text strings")
    if "process" in s:
        p = s["process"]
        if not (isinstance(p, dict) and set(p) == {"scheme", "id"} and all(is_text(x) for x in p.values())):
            out.append("process is not exactly {scheme, id} of text")
    if "outcome" in s and s["outcome"] not in ("upheld", "dismissed"):
        out.append("outcome is not upheld or dismissed")
    if not is_profile_time(s.get("issued_at")):
        out.append("issued_at is not in the §5.2 form")
    required = {"profile", "issuer", "link", "issued_at", "sig"}
    allowed = required | {"basis", "content", "scope", "process", "outcome"}
    if token in _CORRECTIVE:
        required |= {"content"}
    if token in ("disputes", "resolves"):
        required |= {"process"}
    if token == "resolves":
        required |= {"outcome"}
    if token == "supersedes":
        allowed -= {"scope"}
    if token not in ("disputes", "resolves"):
        allowed -= {"process"}
    if token != "resolves":
        allowed -= {"outcome"}
    missing, extra = required - set(s), set(s) - allowed
    if missing:
        out.append(f"members required for {token} are absent: {sorted(missing)}")
    if extra:
        out.append(f"members not allowed for {token}: {sorted(extra)}")
    return out


def evaluate_lifecycle(records: Sequence[HeldRecord], trust: TrustPolicy, evaluation_time: str,
                       profiles_implemented: frozenset = frozenset({PROFILE_ID})) -> LifecycleResult:
    """Report the §11.2.5 properties and finding of every lifecycle statement held."""
    if parse_time(evaluation_time) is None:
        raise ValueError("evaluation_time must be an RFC 3339 time; the verifier never reads the clock")
    implemented = profiles_implemented & {PROFILE_ID}
    held: dict[str, tuple] = {}
    statements: list[StatementResult] = []
    for rec in records:
        if rec.kind not in RECORD_KINDS:
            raise ValueError(f"unknown record kind {rec.kind!r}")
        value = _decode(rec)
        digest = _digest(rec, value)
        if digest in held:
            continue  # the same record received twice is one record
        held[digest] = (rec.kind, value, _issuer(rec.kind, value))
        if rec.kind == "lifecycle_statement" and value is not None:
            statements.append(StatementResult(digest, value))

    def report(s: StatementResult, name: str, status: str, method: str, detail: str | None = None) -> None:
        s.properties[name] = PropertyReport(name, status, method, detail)

    def applies(s: StatementResult) -> list:
        names = ["lifecycle_form", "lifecycle_signature", "lifecycle_target"]
        if s.token in _CORRECTIVE:
            names.append("lifecycle_issuer")
        names.append("lifecycle_signer_trust")
        if s.token in _CORRECTIVE:
            names.append("lifecycle_unique")
        return names

    for s in statements:
        if not member_of(s.statement.get("profile"), implemented):
            for name in applies(s):
                report(s, name, NOT_CHECKED, "not run (§11.2.5)",
                       f"profile {s.statement.get('profile')!r} is not implemented")
            continue
        problems = _form_problems(s.statement)
        report(s, "lifecycle_form", FAIL if problems else PASS, "§11.2.2 members and forms",
               "; ".join(problems) or None)
        body = unsigned_jcs(s.statement)
        ok = body is not None and ed25519_verify_hex(s.statement.get("issuer"), s.statement.get("sig"), body)
        report(s, "lifecycle_signature", PASS if ok else FAIL, "Ed25519 by issuer over JCS of every member but sig")

    def target_status(s: StatementResult) -> None:
        method = "§11.2.5 lifecycle_target"
        target = held.get(s.target)
        if target is None:
            report(s, "lifecycle_target", NOT_PRESENT, method, "no record with that digest is held")
        elif s.token in _CORRECTIVE and target[0] in _EXCLUDED:
            report(s, "lifecycle_target", FAIL, method, f"a {target[0]} cannot be amended or superseded (§11.2.4)")
        elif s.token == "resolves":
            disputed = next((x for x in statements if x.statement_digest == s.target), None)
            ok = disputed is not None and disputed.token == "disputes" and \
                disputed.finding == "lifecycle_effective" and disputed.statement.get("process") == s.statement.get("process")
            report(s, "lifecycle_target", PASS if ok else FAIL, method,
                   None if ok else "not an effective disputes statement with the same process")
        else:
            report(s, "lifecycle_target", PASS, method)

    def issuer_and_trust(s: StatementResult) -> None:
        issuer = s.statement.get("issuer")
        if s.properties["lifecycle_signature"].status != PASS:
            for name in ("lifecycle_issuer", "lifecycle_signer_trust", "lifecycle_unique"):
                if name in applies(s):
                    report(s, name, NOT_CHECKED, f"§11.2.5 {name}",
                           "lifecycle_signature is not PASS, so the statement's issuer is not established")
            return
        if s.token in _CORRECTIVE:
            target = held.get(s.target)
            target_issuer = target[2] if target is not None else None
            method = "§11.2.3: the target's established issuer, or a successor the trust policy states"
            if target_issuer is None:
                report(s, "lifecycle_issuer", FAIL, method, "the target has no established issuer")
            elif issuer == target_issuer or trust.succeeds(issuer, target_issuer):
                report(s, "lifecycle_issuer", PASS, method)
            else:
                report(s, "lifecycle_issuer", FAIL, method, "the signer is neither the target's issuer nor its successor")
        if s.token == "resolves":
            process = s.statement.get("process") if isinstance(s.statement.get("process"), dict) else {}
            status = trust.accepts_resolver(issuer, process, evaluation_time)
            detail = _same_party_note(s, held, statements, trust)
            report(s, "lifecycle_signer_trust", status,
                   f"trust policy: resolver for the process named, as of {evaluation_time}", detail)
        else:
            status, _ = trust.party_of(issuer, evaluation_time)
            report(s, "lifecycle_signer_trust", status, f"trust policy, as of {evaluation_time}")

    def qualifies(s: StatementResult) -> bool:
        return all(s.properties.get(k) is not None and s.properties[k].status == PASS for k in
                   ("lifecycle_form", "lifecycle_signature", "lifecycle_target", "lifecycle_issuer",
                    "lifecycle_signer_trust"))

    def unique(s: StatementResult) -> None:
        if s.token not in _CORRECTIVE or "lifecycle_unique" in s.properties:
            return
        method = "§11.2.5 lifecycle_unique: one qualifying correction per target"
        others = [o for o in statements if o is not s and o.token in _CORRECTIVE and o.target == s.target
                  and o.statement_digest != s.statement_digest]
        if not qualifies(s) or not others:
            report(s, "lifecycle_unique", NOT_CHECKED, method,
                   "the statement does not qualify" if others else "no other correction of the target is held")
        elif any(qualifies(o) for o in others):
            report(s, "lifecycle_unique", FAIL, method, "another qualifying correction targets the same record")
        else:
            report(s, "lifecycle_unique", PASS, method)

    def finding(s: StatementResult) -> str:
        st = {k: v.status for k, v in s.properties.items()}
        if any(st.get(k) != PASS for k in ("lifecycle_form", "lifecycle_signature", "lifecycle_target")):
            return "lifecycle_not_effective"
        if s.token in _CORRECTIVE and st.get("lifecycle_issuer") == FAIL:
            return "lifecycle_not_issuer"
        if (s.token in _CORRECTIVE and st.get("lifecycle_issuer") != PASS) or \
                (s.token in ("amends", "supersedes", "resolves") and st.get("lifecycle_signer_trust") != PASS):
            return "lifecycle_not_effective"
        if st.get("lifecycle_unique") == FAIL:
            return "lifecycle_forked"
        return "lifecycle_effective"

    checked = [s for s in statements if "lifecycle_form" in s.properties and
               s.properties["lifecycle_form"].status != NOT_CHECKED]
    # A resolves statement's target check needs the finding of the disputes statement it names.
    first, last = [s for s in checked if s.token != "resolves"], [s for s in checked if s.token == "resolves"]
    for group in (first, last):
        for s in group:
            target_status(s)
            issuer_and_trust(s)
        for s in group:
            unique(s)
        for s in group:
            s.finding = finding(s)
    return LifecycleResult(statements, held)


def _same_party_note(s: StatementResult, held: Mapping[str, tuple], statements: Sequence[StatementResult],
                     trust: TrustPolicy) -> str | None:
    """§11.2.4: say so when the resolver maps to the same party as the target's issuer or the
    disputant."""
    party = trust.parties.get(s.statement.get("issuer"))
    if party is None:
        return None
    disputed = next((x for x in statements if x.statement_digest == s.target), None)
    if disputed is None:
        return None
    notes = []
    if trust.parties.get(disputed.statement.get("issuer")) == party:
        notes.append("the resolver is the same party as the disputant")
    target = held.get(disputed.target)
    if target is not None and target[2] is not None and trust.parties.get(target[2]) == party:
        notes.append("the resolver is the same party as the disputed record's issuer")
    return "; ".join(notes) or None
