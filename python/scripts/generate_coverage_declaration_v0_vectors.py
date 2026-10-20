#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate the coverage declaration vectors of the Minimum Evidence Interoperability Profile.

The profile is ``spec/interop-profile-v0.md``; its §6.7 defines the coverage declaration and §6.7.6
lists these cases. They are built from the personal-agent History run in
``vectors/personal-history-basic-v0/responder-run.json``, which this script reads and never
rewrites:

- one positive per coverage kind: the Basic level History as it was answered (``holder_selected``),
  the holder's four deals in four streams at one tick (``stream_interval``), and three deals listed
  by a source's population object (``source_authoritative``);
- the negatives of §6.7.6: a cherry-picked selection declared ``stream_interval``, a record left
  out, an interval ending at another anchor, an undefined rule, an aggregate declaring more than its
  evidence, a source that lists fewer deals, a source's list for another holder, a forged
  population object;
- two pairs of agreeing halves for issuer independence (§6.7.4).

It states every expected status by hand from the profile text. Each case cites the sections it
comes from. Nothing here imports or runs a verifier.

The definition ``coverage_declaration_example/0`` and the population object are fixed for these
vectors only and are not registered (§6.7.6). A case whose replies are not the run's own says so
in ``source``; those replies are re-signed by the holder key.

Output: ``vectors/coverage-declaration-v0/`` (or ``--out DIR``). Deterministic: no clock, no
randomness. ``README.md`` is never rewritten; every file in the directory is listed in
``SHA256SUMS``. Dependencies: the standard library, ``cryptography`` (Ed25519 only) and the two
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
    HISTORY,
    RUN,
    answered,
    artifact_of,
    carried,
    decode,
    history_props,
    load_run,
    resign,
)

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "vectors" / "coverage-declaration-v0"
SET = "aac-coverage-declaration-v0"
SPEC = "spec/interop-profile-v0.md"
STATUS = ("Conformance vectors for the coverage declaration of the informational Minimum Evidence "
          "Interoperability Profile v0 (evidence-interop/0, §6.7). Every key is a test key derived from a "
          "public seed; never use one for anything else.")
EXAMPLE = "coverage_declaration_example/0"
J = "application/json"

SEED_LABELS = {
    "source": "interop-profile-v0 coverage declaration vectors: population source key",
    "other-source": "interop-profile-v0 coverage declaration vectors: key that is not the source",
    "producer-a": "interop-profile-v0 coverage declaration vectors: first producer key",
    "producer-b": "interop-profile-v0 coverage declaration vectors: second producer key",
}
PRIV = {name: Ed25519PrivateKey.from_private_bytes(sha(label.encode())) for name, label in SEED_LABELS.items()}
PUB = {name: k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex() for name, k in PRIV.items()}

COVERAGE_PROPS = ["coverage_declaration_form", "coverage_declaration_anchor", "coverage_declaration_population",
                  "coverage_declaration_commitment", "coverage_declaration_source", "coverage_declaration_aggregate"]

# §6.7.1, last column: what completeness is relative to, per kind.
RELATIVE_TO = {
    "holder_selected": "not asserted",
    "stream_interval": "the live set the holder opened, under the rule and in the interval; "
                       "not checked against the anchor",
    "source_authoritative": "the source's list",
}

# The recipient's requirements: the History one (as in the History corpus), one that relies on
# completeness (§6.7.3 item 4) and one that relies on corroboration (§6.7.4). The last two are
# read by their member's presence only (P-48).
CONTRACT = {
    "id": "C",
    "version": "1",
    "requirements": [
        {"id": "r-deal-steps", "profile": "outcome",
         "statement": "The recorded steps of each selected deal are served under a verified envelope.",
         "evidence_requirements": {"accepted_epistemic_types": ["producer_claim"]}},
        {"id": "r-complete", "profile": "outcome",
         "statement": "The deals shown are every deal of the holder's in the period.",
         "evidence_requirements": {"coverage": "every deal in the period"}},
        {"id": "r-corroborated", "profile": "outcome",
         "statement": "The step is stated by two parties.",
         "evidence_requirements": {"independence": "two distinct issuers"}},
    ],
}
CONTRACT_REF = f"{CONTRACT['id']}@{CONTRACT['version']}"
CONTRACT_DIGEST = json_digest(CONTRACT)
EVAL = "2026-10-19T01:00:00Z"

# §6.7.1: the tick a stream_interval History over several streams is answered at, and each stream's
# checkpoint it commits to. Label digests, not real checkpoints: coverage_declaration_commitment is
# NOT_CHECKED in this revision.
TICK = shx(b"interop-profile-v0 coverage declaration vectors: witnessed checkpoint tick")


def stream_checkpoint(stream: str) -> str:
    return shx(f"interop-profile-v0 coverage declaration vectors: checkpoint of {stream} at the tick".encode())


SOURCE_METHOD = "Ed25519 over UTF-8 of JCS of the population object's other members (IP §6.7.6, vectors only)"
POPULATION_ISSUED_AT = "2026-10-18T00:00:00Z"


# ---------------------------------------------------------------------------
# Definitions and answers
# ---------------------------------------------------------------------------


def example_definition(basic: dict, selection: list[str], declaration: dict) -> dict:
    """§6.7.6: the Basic level definition with ``coverage_declaration`` in place of ``completeness``."""
    d = {k: v for k, v in basic.items() if k != "completeness"}
    d.update(name=EXAMPLE, selection=sorted(selection), coverage_declaration=declaration)
    return d


def reanswer(exchange: dict, env: dict, derivation: str, tag: str, *, anchor: str | None = None,
             own_stream: bool = False, drop: int | None = None) -> tuple[dict, dict]:
    """One exchange of the run asked again under ``derivation`` and re-signed by the holder key. With
    ``anchor`` the request and reply name it; with ``own_stream`` the deal's records move to a stream
    of their own, keeping their order; ``drop`` leaves out the record at that position."""
    request = json.loads(exchange["request"]["octets_text"])
    request["derivation"] = derivation
    request["nonce"] = request["nonce"].replace("/history-", f"/{tag}-").replace("/not-selected", f"/{tag}-4")
    if anchor is not None:
        request["coverage"] = {"expected_pin": anchor}
    req = {"media_type": J, "octets_text": jcs(request)}
    a = artifact_of(env)
    a["derivation"] = derivation
    members: dict[str, Any] = {"derivation": derivation, "request_digest": shx(req["octets_text"].encode())}
    if anchor is not None:
        a["anchor"] = anchor
        members["anchor"] = {"digest": anchor}
    if own_stream:
        a["evidence_stream"] = f"deal/{a['subject']['correlation']}"
        a["records"] = [dict(r, leaf_index=i) for i, r in enumerate(a["records"])]
    if drop is not None:
        a["records"] = [r for i, r in enumerate(a["records"]) if i != drop]
    return req, carried(resign(env, "holder", artifact=a, **members))


def population_object(holder: str, items: list[str], signer: str) -> dict:
    """§6.7.6's population object, issued by the source key and signed by ``signer``."""
    body = {"issued_at": POPULATION_ISSUED_AT, "issuer": PUB["source"], "items": sorted(items), "subject": holder}
    return {"media_type": J, "octets_text": jcs(dict(body, sig=PRIV[signer].sign(jcs(body).encode()).hex()))}


def half(claim: str, issued_at: str, signer: str) -> dict:
    """A half: the producer record of IP §11.5, signed by ``producer``."""
    body = {"claim": claim, "issued_at": issued_at, "producer": PUB[signer]}
    return {"media_type": J, "octets_text": jcs(dict(body, sig=PRIV[signer].sign(jcs(body).encode()).hex()))}


# ---------------------------------------------------------------------------
# Expected values
# ---------------------------------------------------------------------------


def coverage(kind: str, by: str, props: dict, *, aggregate: tuple[str, str] | None = None) -> dict:
    """The §6.7.3 report: the declared kind, its properties, what completeness is relative to, whether
    the set is accepted as its kind, and what §6.7.3 item 4 makes of a SATISFIED completeness
    requirement."""
    statuses = set(props.values())
    if kind == "holder_selected" or statuses & {"FAIL", "NOT_PRESENT"}:
        becomes = "INSUFFICIENT"
    elif statuses & {"NOT_CHECKED", "INCONCLUSIVE"}:
        becomes = "UNKNOWN"
    else:
        becomes = None
    out: dict[str, Any] = {"declared_kind": kind, "declared_by": by, "properties": dict(props),
                           "relative_to": RELATIVE_TO[kind], "accepted_as_declared": "FAIL" not in statuses,
                           "satisfied_becomes": {"r-complete": becomes}}
    if aggregate is not None:
        declared, derived = aggregate
        out["aggregate"] = {"declared": declared, "derived": derived,
                            "coverage_declaration_aggregate": "PASS" if declared == derived else "FAIL"}
    return out


def holder_selected_props() -> dict:
    return {"coverage_declaration_form": "PASS"}


def stream_props(population: str = "PASS") -> dict:
    return {"coverage_declaration_form": "PASS", "coverage_declaration_anchor": "PASS",
            "coverage_declaration_population": population, "coverage_declaration_commitment": "NOT_CHECKED"}


def source_props(population: str = "PASS", source: str = "PASS") -> dict:
    return {"coverage_declaration_form": "PASS", "coverage_declaration_population": population,
            "coverage_declaration_source": source}


def pins(run: dict) -> dict:
    trust = {"responder_keys": [history_vectors.PUB["holder"]], "log_keys": [cp["log_key"] for cp in run["checkpoints"]],
             "foreign_keys": [PUB["source"], PUB["producer-a"], PUB["producer-b"]], "parties": {},
             "successions": [], "require_action_time_from_other_party": False}
    return {"trust_policy": trust,
            "verification_policy": {"online": False, "profiles_implemented": [PROFILE], "kinds_implemented": KINDS},
            "contract_ref": CONTRACT_REF, "contract_digest": CONTRACT_DIGEST, "evaluation_time": EVAL}


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------


def cases(run: dict) -> list[dict]:
    ex = {e["name"]: e for e in run["exchanges"]}
    basic = json.loads(run["definitions"]["basic"])
    history = [ex[f"history-{i}"] for i in (1, 2, 3)]
    envs = [decode(e["reply"]) for e in history]
    four = [*history, ex["not-selected"]]
    four_envs = [decode(e["reply"]) for e in four]
    deals = sorted(e["subject"]["correlation"] for e in four_envs)
    assert deals == sorted(run["deals"]), deals
    holder = run["holder_key"]

    def set_case(cid: str, title: str, cites: list[str], source: str, definition: dict,
                 exchanges: list[tuple[dict, dict]], hprops: dict, cov: dict, fails: list[str], *,
                 population: dict | None = None, aggregate: str | None = None) -> dict:
        results = [answered(decode(rep)) for _, rep in exchanges]
        accepted = (all(x["accepted"] for x in results) and all(v == "PASS" for v in hprops.values())
                    and cov["accepted_as_declared"]
                    and cov.get("aggregate", {}).get("coverage_declaration_aggregate") != "FAIL")
        assert accepted is (not fails), cid
        inputs: dict[str, Any] = {"history": definition["name"], "definition": definition,
                                  "exchanges": [{"request": q, "reply": r} for q, r in exchanges]}
        if population is not None:
            inputs["population"] = population
        if aggregate is not None:
            inputs["aggregate"] = {"coverage_declaration": {"kind": aggregate}}
        return {"id": cid, "title": title, "cites": cites, "source": source, "mode": "asked", "pins": pins(run),
                "inputs": inputs,
                "expected": {"exchanges": results, "history_properties": hprops, "coverage": cov,
                             "accepted": accepted, "fails": fails}}

    out = []

    # holder_selected: the Basic level History as the responder answered it. Its completeness
    # not_asserted is the declaration (history profile §2, PA-15), so the bytes are the run's own.
    pairs = [(e["request"], e["reply"]) for e in history]
    assert basic["name"] == HISTORY
    out.append(set_case(
        "holder-selected", "The Basic level History: three deals the holder chose, read as holder_selected",
        ["§6.7.1", "§6.7.3", "§6.7.5"], "responder", basic, pairs, history_props(),
        coverage("holder_selected", "completeness", holder_selected_props(),
                 aggregate=("holder_selected", "holder_selected")), [], aggregate="holder_selected"))

    # stream_interval: all four of the holder's deals, each in its own stream, at one tick, with the
    # holder opening the tick's live set: every record of every stream from its start.
    def live_entry(env: dict) -> dict:
        stream = f"deal/{env['subject']['correlation']}"
        return {"stream": stream, "checkpoint": stream_checkpoint(stream), "start": 0,
                "count": len(artifact_of(env)["records"])}

    live_set = sorted((live_entry(env) for env in four_envs), key=lambda e: e["stream"])
    interval = {"rule": "all_records", "interval": {"from": None, "to": TICK}, "live_set": live_set}

    def stream_set(selection_envs: list[dict], selection_exchanges: list[dict], tag: str, *,
                   drop: tuple[int, int] | None = None, **over: Any) -> tuple[dict, list[tuple[dict, dict]]]:
        d = example_definition(basic, [e["subject"]["correlation"] for e in selection_envs],
                               {"kind": "stream_interval", **interval, **over})
        digest = shx(jcs(d).encode())
        answers = [reanswer(x, env, digest, tag, anchor=TICK, own_stream=True,
                            drop=drop[1] if drop is not None and drop[0] == i else None)
                   for i, (x, env) in enumerate(zip(selection_exchanges, selection_envs))]
        return d, answers

    d, answers = stream_set(four_envs, four, "stream-interval")
    out.append(set_case(
        "stream-interval", "Four deals in four streams at one tick, every record of the live set answered",
        ["§6.7.1", "§6.7.2", "§6.7.3", "§6.7.5"],
        "derived: each of the holder's four deals moved to a stream of its own, asked under the example "
        "definition at the tick and re-signed by the holder key",
        d, answers, history_props(),
        coverage("stream_interval", "coverage_declaration", stream_props(),
                 aggregate=("stream_interval", "stream_interval")), [], aggregate="stream_interval"))

    # The cherry-picked History: the holder's own three-deal selection, declared stream_interval over
    # the same honest live set of four streams. The fourth deal's records are in the live set and no
    # answer carries them. Its aggregate can only say holder_selected (§6.7.5).
    d, answers = stream_set(envs, history, "cherry-picked")
    out.append(set_case(
        "cherry-picked", "Holder-selected deals declared stream_interval: three of the live set's four streams",
        ["§6.7.2", "§6.7.3 item 2", "§6.7.5"],
        "derived: the stream-interval case with the not-selected deal left out of the selection and the answers",
        d, answers, history_props(),
        coverage("stream_interval", "coverage_declaration", stream_props("FAIL"),
                 aggregate=("holder_selected", "holder_selected")),
        ["coverage_declaration_population"], aggregate="holder_selected"))

    # One record of an answered stream left out of its artifact: the deal with the most records.
    i = max(range(4), key=lambda k: len(artifact_of(four_envs[k])["records"]))
    assert len(artifact_of(four_envs[i])["records"]) >= 2
    d, answers = stream_set(four_envs, four, "record-missing", drop=(i, 1))
    out.append(set_case(
        "stream-interval-record-missing", "Four deals at one tick, one record of one stream left out",
        ["§6.7.2", "§6.7.3 item 2"],
        f"derived: the stream-interval case with the second record of {live_entry(four_envs[i])['stream']} "
        "left out of its artifact, re-signed by the holder key",
        d, answers, history_props(),
        coverage("stream_interval", "coverage_declaration", stream_props("FAIL")),
        ["coverage_declaration_population"]))

    # The declaration's interval ends at another anchor than the one every answer is given at.
    other = shx(b"interop-profile-v0 coverage declaration vectors: an anchor no answer is given at")
    d, answers = stream_set(four_envs, four, "anchor-mismatch", interval={"from": None, "to": other})
    out.append(set_case(
        "stream-interval-anchor-mismatch", "Four deals answered at the tick, under a declaration ending at another anchor",
        ["§6.7.2", "§6.7.3 item 2"],
        "derived: the stream-interval case with interval.to set to another anchor, re-signed by the holder key",
        d, answers, history_props(),
        coverage("stream_interval", "coverage_declaration", stream_props() | {"coverage_declaration_anchor": "FAIL"}),
        ["coverage_declaration_anchor"]))

    # A rule this revision does not define (§6.7.1, P-59): the declaration's form fails, and no other
    # coverage property is reported.
    d, answers = stream_set(four_envs, four, "unknown-rule", rule="records_of_completed_deals")
    out.append(set_case(
        "stream-interval-unknown-rule", "Four deals at the tick, under a stream_interval rule this revision does not define",
        ["§6.7.1", "§6.7.2"],
        "derived: the stream-interval case with an undefined rule, re-signed by the holder key",
        d, answers, history_props(),
        coverage("stream_interval", "coverage_declaration", {"coverage_declaration_form": "FAIL"}),
        ["coverage_declaration_form"]))

    # The Basic level History under an aggregate that declares stream_interval.
    out.append(set_case(
        "aggregate-stronger-than-evidence", "The Basic level History under an aggregate declaring stream_interval",
        ["§6.7.5", "RES §7.2"], "responder", basic, pairs, history_props(),
        coverage("holder_selected", "completeness", holder_selected_props(),
                 aggregate=("stream_interval", "holder_selected")),
        ["coverage_declaration_aggregate"], aggregate="stream_interval"))

    # source_authoritative: the holder's three selected deals, at the run's anchor in its one stream,
    # listed by a source's population object.
    selected = [e["subject"]["correlation"] for e in envs]

    def source_set(items: list[str], signer: str, tag: str, *,
                   subject: str = holder) -> tuple[dict, list[tuple[dict, dict]], dict]:
        population = population_object(subject, items, signer)
        d = example_definition(basic, selected, {
            "kind": "source_authoritative", "source": PUB["source"], "method": SOURCE_METHOD,
            "population": shx(population["octets_text"].encode())})
        digest = shx(jcs(d).encode())
        return d, [reanswer(x, env, digest, tag) for x, env in zip(history, envs)], population

    d, answers, population = source_set(selected, "source", "source-authoritative")
    out.append(set_case(
        "source-authoritative", "Three deals listed by a source's population object, all answered",
        ["§6.7.1", "§6.7.2", "§6.7.3"],
        "derived: history-1 to history-3 asked under the example definition and re-signed by the holder key; "
        "the population object signed by the source key",
        d, answers, history_props(), coverage("source_authoritative", "coverage_declaration", source_props()), [],
        population=population))

    d, answers, population = source_set(selected[:2], "source", "source-unlisted")
    out.append(set_case(
        "source-authoritative-deal-unlisted", "Three deals answered, two listed by the source",
        ["§6.7.2", "§6.7.3 item 2"],
        "derived: the source-authoritative case with one deal left out of the population object, re-signed by "
        "the source key",
        d, answers, history_props(),
        coverage("source_authoritative", "coverage_declaration", source_props(population="FAIL")),
        ["coverage_declaration_population"], population=population))

    d, answers, population = source_set(selected, "source", "source-other-subject",
                                        subject=history_vectors.PUB["second-holder"])
    out.append(set_case(
        "source-authoritative-other-subject", "The three deals listed by the source, for another holder key",
        ["§6.7.2", "§6.7.3 item 2"],
        "derived: the source-authoritative case with the population object's subject set to the second holder "
        "key, re-signed by the source key",
        d, answers, history_props(),
        coverage("source_authoritative", "coverage_declaration", source_props(population="FAIL")),
        ["coverage_declaration_population"], population=population))

    d, answers, population = source_set(selected, "other-source", "source-forged")
    out.append(set_case(
        "source-authoritative-forged-population", "A population object naming the source, signed by another key",
        ["§6.7.2", "§6.7.3 item 2"],
        "derived: the source-authoritative case with the population object signed by a key that is not the "
        "source's",
        d, answers, history_props(),
        coverage("source_authoritative", "coverage_declaration", source_props(source="FAIL")),
        ["coverage_declaration_source"], population=population))

    # §6.7.4: two agreeing halves.
    claim = "the deal's step was completed"

    def halves_case(cid: str, title: str, second: str, status: str, shown: str, becomes: str) -> dict:
        halves = [half(claim, "2026-10-15T00:00:20Z", "producer-a"), half(claim, "2026-10-15T00:00:21Z", second)]
        return {"id": cid, "title": title, "cites": ["§6.7.4"], "source": "derived: two producer records (IP §11.5)",
                "mode": "asked", "pins": pins(run), "inputs": {"halves": halves},
                "expected": {"halves": {"signatures": ["PASS", "PASS"], "agree": True, "issuer_independence": status,
                                        "shown_as": shown, "satisfied_becomes": {"r-corroborated": becomes}},
                             "fails": ["issuer_independence"] if status == "FAIL" else []}}

    out.append(halves_case("same-controller-halves-same-key", "Two agreeing halves signed by one key",
                           "producer-a", "FAIL", "redundant, not corroborating", "INSUFFICIENT"))
    out.append(halves_case("same-controller-halves-unbound-keys",
                           "Two agreeing halves under two keys, no evidence about their controllers",
                           "producer-b", "NOT_CHECKED", "not corroborating", "UNKNOWN"))
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
    keys = {**history_vectors.PUB, **PUB}
    corpus = {
        "set": SET,
        "status": STATUS,
        "profile": PROFILE,
        "spec": SPEC,
        "example_definition": EXAMPLE,
        "run": run_ref,
        "test_keys": {
            "note": "TEST-ONLY. Each private key is the 32-byte Ed25519 seed SHA-256(seed_label).",
            "keys": {name: {"seed_label": labels[name], "public": keys[name]}
                     for name in ("holder", "second-holder", "source", "other-source", "producer-a", "producer-b")},
        },
        "contract": {"document": CONTRACT, "document_jcs": jcs(CONTRACT), "contract_ref": CONTRACT_REF,
                     "contract_digest": CONTRACT_DIGEST, "schema": EC_SCHEMA},
        "tick": TICK,
        "coverage_properties": COVERAGE_PROPS,
        "count": len(all_cases),
        "cases": all_cases,
    }
    files = {"vectors.json": _dump(corpus)}
    files["manifest.json"] = _dump({
        "set": SET,
        "status": STATUS,
        "spec": SPEC,
        "generator": "python/scripts/generate_coverage_declaration_v0_vectors.py",
        "run": run_ref,
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
