#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate the conformance vectors of the Personal-Agent History Profile v0, Basic level.

The profile is ``spec/personal-agent-history-profile-v0.md``; its §6.4 describes the acceptance
run these vectors publish (PA-11). The positive run is ``responder-run.json`` in the output
directory: requests and replies exchanged with an IP responder, produced by ``producer/main.go``
there (see the corpus README). This script reads that run and builds from it one History, the nine
§6.4 mutants, a second reading of the other-anchor mutant, a History over several streams at one
anchor (§2) with its mixed-anchor mutant, and a refusal to another requester. It
states every expected status by hand from the profile text. Each case cites the
sections it comes from. Nothing here imports or runs a verifier.

A mutant the responder can produce is taken from the run as it is. A mutant no conforming
responder sends is derived from the run's octets here: the reply is changed and, where the case
says so, re-signed with the holder key (or a second test key). Each case says which.

Output: ``vectors/personal-history-basic-v0/`` (or ``--out DIR``). Deterministic: no clock, no
randomness. ``README.md``, ``responder-run.json`` and ``producer/`` are never rewritten; every file
in the directory is listed in ``SHA256SUMS``. Dependencies: the standard library, ``cryptography``
(Ed25519 only) and the interop profile generator beside this script, for its encodings and
statuses.
"""
from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path
from typing import Any

import history_frame
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from generate_interop_profile_v0_vectors import (
    KINDS,
    PROFILE,
    REFUSAL_PROPS,
    b64u,
    env_props,
    jcs,
    json_digest,
    mapped,
    ref,
    ref_props,
    sha,
    shx,
)

# The Basic level is frozen at its release (tests/test_personal_history_outcome_v0_vectors.py
# test_basic_vectors_unchanged), so it keeps the EC pin it was released under, not the profile's
# current one.
RELEASED_EC_SCHEMA = {
    "name": "evidence-contract-v0.json",
    "sha256": "6d10d5eb97e15421db0ab922b5f6d1f0a2e9f453fb64e52fb45306ba029ad480",
}

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "vectors" / "personal-history-basic-v0"
RUN = DEFAULT_OUT / "responder-run.json"
SET = "aac-personal-history-basic-v0"
SPEC = "spec/personal-agent-history-profile-v0.md"
STATUS = ("Conformance vectors for the informational Personal-Agent History Profile v0, Basic level, "
          "over evidence-interop/0. Every key is a test key derived from a public seed; never use one "
          "for anything else.")
HISTORY = "personal_history_basic/1"
J = "application/json"

# The responder that produced responder-run.json, and the commit it ran at.
RESPONDER = {
    "repository": "https://github.com/action-state-group/evidencebook",
    "commit": "43f3cb1b955d647bc92cb4da0d823973d1981cad",
    "entry_point": "Book.Respond, driven by producer/main.go from the repository's test/interop/ directory",
}

SEED_LABELS = {
    "holder": "personal-agent-history-profile-v0 conformance vectors: holder key",
    "holder-log": "personal-agent-history-profile-v0 conformance vectors: holder log key",
    "second-holder": "personal-agent-history-profile-v0 conformance vectors: second holder key",
}
PRIV = {name: Ed25519PrivateKey.from_private_bytes(sha(label.encode())) for name, label in SEED_LABELS.items()}
PUB = {name: k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex() for name, k in PRIV.items()}

# §6.2: the envelope members its signature covers, when present (IP §6.2).
SIGNED = ("profile", "request_digest", "subject", "derivation", "anchor", "artifact_digest", "verification",
          "responder", "issued_at")

HISTORY_PROPS = ["definition_form", "definition_binding", "selection_coverage", "single_signer",
                 "single_anchor", "artifact_form", "record_kinds"]

# The recipient requirement a Basic level answer is the only evidence for (§6.1).
CONTRACT = {
    "id": "H",
    "version": "1",
    "requirements": [
        {"id": "r-deal-steps", "profile": "outcome",
         "statement": "The recorded steps of each selected deal are served under a verified envelope.",
         "evidence_requirements": {"accepted_epistemic_types": ["producer_claim"]}},
    ],
}
CONTRACT_REF = f"{CONTRACT['id']}@{CONTRACT['version']}"
CONTRACT_DIGEST = json_digest(CONTRACT)
REQUIREMENT = "r-deal-steps"
EVAL = "2026-10-15T01:00:00Z"

# §2's anchors for a History over several streams. Each is a label digest, not a real checkpoint: at
# the Basic level a verifier checks only that every envelope names the same anchor (PA-14).
TICK = shx(b"personal-agent-history-profile-v0 conformance vectors: witnessed checkpoint tick")
STREAM_CHECKPOINT = shx(b"personal-agent-history-profile-v0 conformance vectors: one deal stream's checkpoint")


def load_run(path: Path) -> dict:
    run = json.loads(path.read_text(encoding="utf-8"))
    if run["holder_key"] != PUB["holder"] or run["checkpoints"][0]["log_key"]["kid"] != PUB["holder-log"]:
        raise SystemExit(f"{path}: the run's keys are not this corpus's test keys")
    return run


# ---------------------------------------------------------------------------
# Envelopes
# ---------------------------------------------------------------------------


def decode(reply: dict) -> dict:
    return json.loads(reply["octets_text"])


def artifact_of(env: dict) -> dict:
    a = env["artifact"]
    return json.loads(base64.urlsafe_b64decode(a + "=" * (-len(a) % 4)))


def resign(env: dict, key: str, *, artifact: dict | None = None, **members: Any) -> dict:
    """The envelope with ``members`` replaced (and ``artifact``, as JCS octets), signed by ``key``."""
    out = {k: v for k, v in env.items() if k != "sig"}
    out.update(members)
    out["responder"] = PUB[key]
    if artifact is not None:
        data = jcs(artifact).encode()
        out["artifact"], out["artifact_digest"] = b64u(data), shx(data)
    body = {k: out[k] for k in SIGNED if k in out}
    out["sig"] = PRIV[key].sign(jcs(body).encode()).hex()
    return out


def multi_stream(exchange: dict, env: dict, anchor: str) -> tuple[dict, dict]:
    """One deal of the run moved to a stream of its own (§2) and answered at ``anchor``: the request
    names ``anchor``, and the reply is re-signed by the holder key over that request."""
    request = json.loads(exchange["request"]["octets_text"])
    request["coverage"] = {"expected_pin": anchor}
    request["nonce"] = request["nonce"].replace("/history-", "/multi-stream-")
    req = {"media_type": J, "octets_text": jcs(request)}
    a = artifact_of(env)
    a["anchor"] = anchor
    a["evidence_stream"] = f"deal/{a['subject']['correlation']}"
    a["records"] = [dict(r, leaf_index=i) for i, r in enumerate(a["records"])]
    reply = resign(env, "holder", artifact=a, anchor={"digest": anchor},
                   request_digest=shx(req["octets_text"].encode()))
    return req, carried(reply)


def carried(env: dict) -> dict:
    return {"media_type": J, "octets_text": jcs(env)}


def request_digest(exchange: dict) -> str:
    return shx(exchange["request"]["octets_text"].encode())


# ---------------------------------------------------------------------------
# Expected values
# ---------------------------------------------------------------------------

ACCEPTED_PROPS = env_props(verification_binding="NOT_PRESENT", anchor_inclusion="NOT_CHECKED")


def answered(env: dict, **over: str) -> dict:
    """One envelope's IP result (§6.1): its properties, its §6.1 acceptance and its IP §8 row."""
    props = dict(ACCEPTED_PROPS, **over)
    accepted = not over
    return {"message_type": "envelope", "subject": env["subject"], "properties": props, "accepted": accepted,
            "requirements": {REQUIREMENT: mapped("envelope-4" if accepted else "envelope-2")},
            "claim": {"evidence": [ref(env["artifact_digest"])], "proofs": []}}


def history_props(**over: str) -> dict:
    props = dict.fromkeys(HISTORY_PROPS, "PASS")
    props.update(over)
    return props


FAILED, COMPLETED, NO_STEP = ("with a recorded failed step", "with recorded completed steps only",
                              "with no recorded step")


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------


def trust_policy(run: dict, *keys: str) -> dict:
    return {"responder_keys": [PUB[k] for k in keys or ("holder",)],
            "log_keys": [cp["log_key"] for cp in run["checkpoints"]], "foreign_keys": [], "parties": {},
            "successions": [], "require_action_time_from_other_party": False}


def pins(run: dict, *keys: str) -> dict:
    return {"trust_policy": trust_policy(run, *keys),
            "verification_policy": {"online": False, "profiles_implemented": [PROFILE], "kinds_implemented": KINDS},
            "contract_ref": CONTRACT_REF, "contract_digest": CONTRACT_DIGEST, "evaluation_time": EVAL}


def swap(items: list, i: int, item: Any) -> list:
    """``items`` with item ``i`` replaced."""
    return [item if k == i else x for k, x in enumerate(items)]


def container(definition: dict, exchanges: list[tuple[dict, dict]]) -> dict:
    """§8.2's one-file History, holding the requests the recipient made (§8.1)."""
    return {"history": HISTORY, "definition": definition,
            "exchanges": [{"request": req, "reply": rep} for req, rep in exchanges]}


def cases(run: dict) -> list[dict]:
    ex = {e["name"]: e for e in run["exchanges"]}
    basic = json.loads(run["definitions"]["basic"])
    wide = json.loads(run["definitions"]["wide_reads"])
    history = [ex[f"history-{i}"] for i in (1, 2, 3)]
    envs = [decode(e["reply"]) for e in history]
    for env, e in zip(envs, history):  # the run's replies are JCS: re-encoding one leaves its octets as they are
        assert carried(env) == e["reply"]
    pairs = [(e["request"], e["reply"]) for e in history]
    positive = [answered(env) for env in envs]

    def case(cid: str, title: str, cites: list[str], source: str, inputs: dict, exchanges: list[dict],
             hprops: dict, fails: list[str], *, keys: tuple[str, ...] = (), states: dict | None = None) -> dict:
        accepted = all(e["accepted"] for e in exchanges) and all(v == "PASS" for v in hprops.values())
        assert accepted is (states is not None), cid
        expected: dict[str, Any] = {"exchanges": exchanges, "history_properties": hprops, "accepted": accepted,
                                    "fails": fails}
        if states is not None:
            expected["deal_states"] = states
        return {"id": cid, "title": title, "cites": cites, "source": source, "mode": "asked",
                "pins": pins(run, *keys), "inputs": inputs, "expected": expected}

    # §5, as producer/main.go seeds the stream: deal 1 records two completed steps, deal 2 a completed
    # and a failed one, deal 3 one completed step. Deal 4 is not selected.
    d = run["deals"]
    states = {"selected_deals": 3, "per_deal": dict(sorted({d[0]: COMPLETED, d[1]: FAILED, d[2]: COMPLETED}.items())),
              "counts": {FAILED: 1, COMPLETED: 2, NO_STEP: 0}}
    out = []
    out.append(case(
        "history-basic", "A History at the Basic level: three of four deals, one holder key, one anchor",
        ["§4", "§5", "§6.1", "§6.2", "§6.4"], "responder",
        container(basic, pairs), positive, history_props(), [], states=states))

    # 1. One step's kind changed in an artifact in transit: the signed artifact_digest no longer matches.
    # The changed step is the deal's failed one, so the change would turn its §5 state.
    (f,) = [i for i, env in enumerate(envs) if "step_failed" in {r["record_type"] for r in artifact_of(env)["records"]}]
    changed = artifact_of(envs[f])
    for r in changed["records"]:
        if r["record_type"] == "step_failed":
            r["record_type"] = "step_completed"
    tampered = dict(envs[f], artifact=b64u(jcs(changed).encode()))
    out.append(case(
        "mutant-step-kind-in-transit", "One step's kind changed in an artifact in transit",
        ["§6.1", "§6.2", "§6.4", "IP §7.2"],
        f"derived: history-{f + 1}'s failed step made completed in its artifact after signing, not re-signed",
        container(basic, swap(pairs, f, (pairs[f][0], carried(tampered)))),
        swap(positive, f, answered(tampered, artifact_digest="FAIL")),
        # The tampered envelope is not accepted under §6.1, so no accepted envelope answers its deal.
        history_props(selection_coverage="FAIL"), ["artifact_digest"]))

    # 2. A deal added to the definition the recipient holds: no envelope signed its digest.
    added = dict(basic, selection=sorted([*basic["selection"], run["deals"][3]]))
    out.append(case(
        "mutant-deal-added-to-definition", "A deal added to the definition the recipient holds",
        ["§4.2", "§6.2", "§6.4"], "derived: the run's replies, under a definition with one more deal",
        container(added, pairs), positive,
        # The added deal is in the held selection and no envelope answers it.
        history_props(definition_binding="FAIL", selection_coverage="FAIL"), ["definition_binding"]))

    # 3. An envelope, signed by the holder key, for a deal not selected. The responder answers any
    # deal under a registered derivation, so this is its own reply.
    extra = ex["not-selected"]
    out.append(case(
        "mutant-envelope-for-deal-not-selected", "An envelope, signed by the holder key, for a deal not selected",
        ["§6.2", "§6.4"], "responder",
        container(basic, [*pairs, (extra["request"], extra["reply"])]),
        [*positive, answered(decode(extra["reply"]))],
        history_props(selection_coverage="FAIL"), ["selection_coverage"]))

    # 4. A selected deal not answered.
    out.append(case(
        "mutant-selected-deal-not-answered", "A selected deal not answered",
        ["§6.2", "§6.4"], "derived: the run's replies for deals 1 and 2 only",
        container(basic, pairs[:2]), positive[:2],
        history_props(selection_coverage="FAIL"), ["selection_coverage"]))

    # 5. One deal answered under a second key the relying party also trusts.
    second = resign(envs[1], "second-holder")
    out.append(case(
        "mutant-second-trusted-key", "One deal answered under a second key the relying party also trusts",
        ["§2", "§6.2", "§6.4"], "derived: history-2's envelope re-signed by the second holder key",
        container(basic, [pairs[0], (pairs[1][0], carried(second)), pairs[2]]),
        [positive[0], answered(second), positive[2]],
        history_props(single_signer="FAIL"), ["single_signer"], keys=("holder", "second-holder")))

    # 6. One deal answered at another anchor. The responder answered the deal at the first checkpoint
    # because the request named it, so anchor_match passes and §6.1 accepts the envelope.
    other = ex["other-anchor"]
    o = [env["subject"] for env in envs].index(decode(other["reply"])["subject"])
    out.append(case(
        "mutant-deal-at-another-anchor", "One deal answered at another anchor, as its request named",
        ["§4.3", "§6.2", "§6.4"], "responder",
        container(basic, swap(pairs, o, (other["request"], other["reply"]))),
        swap(positive, o, answered(decode(other["reply"]))),
        history_props(single_anchor="FAIL"), ["single_anchor"]))

    # 6, as §6.4's parenthesis reads it: the request names the History's anchor and the envelope
    # answers at another. IP anchor_match fails, so §6.2 does not see the envelope at all.
    moved = resign(decode(other["reply"]), "holder", request_digest=request_digest(history[o]))
    out.append(case(
        "mutant-deal-at-another-anchor-request-at-history-anchor",
        "One deal answered at another anchor, against a request naming the History's anchor",
        ["§4.3", "§6.1", "§6.2", "§6.4", "IP §7.2"],
        f"derived: the other-anchor envelope re-signed by the holder key over history-{o + 1}'s request digest",
        container(basic, swap(pairs, o, (pairs[o][0], carried(moved)))),
        swap(positive, o, answered(moved, anchor_match="FAIL")),
        history_props(selection_coverage="FAIL"), ["anchor_match"]))

    # 7. A record kind outside §3, re-signed by the holder key.
    a1 = artifact_of(envs[0])
    a1["records"][1]["record_type"] = "step_skipped"
    kind = resign(envs[0], "holder", artifact=a1)
    out.append(case(
        "mutant-record-kind-outside-list", "A record kind outside §3, re-signed by the holder key",
        ["§3", "§6.2", "§6.4"], "derived: history-1's second record_type changed, re-signed by the holder key",
        container(basic, [(pairs[0][0], carried(kind)), pairs[1], pairs[2]]),
        [answered(kind), positive[1], positive[2]],
        history_props(record_kinds="FAIL"), ["record_kinds"]))

    # 8. A record carrying a member outside reads, re-signed by the holder key.
    a1 = artifact_of(envs[0])
    a1["records"][0]["counterparty_ref"] = "counterparty-1"
    member = resign(envs[0], "holder", artifact=a1)
    out.append(case(
        "mutant-member-outside-reads", "A record carrying a member outside reads, re-signed by the holder key",
        ["§4.3", "§6.2", "§6.4"],
        "derived: counterparty_ref added to history-1's first record, re-signed by the holder key",
        container(basic, [(pairs[0][0], carried(member)), pairs[1], pairs[2]]),
        [answered(member), positive[1], positive[2]],
        history_props(artifact_form="FAIL"), ["artifact_form"]))

    # 9. A definition whose reads adds statement and counterparty_ref. The responder serves it as
    # registered; the records carry neither member, so only the definition's form fails.
    wides = [ex[f"wide-reads-{i}"] for i in (1, 2, 3)]
    out.append(case(
        "mutant-definition-reads-widened", "A definition whose reads adds statement and counterparty_ref",
        ["§4.1", "§6.2", "§6.4"], "responder",
        container(wide, [(e["request"], e["reply"]) for e in wides]),
        [answered(decode(e["reply"])) for e in wides],
        history_props(definition_form="FAIL"), ["definition_form"]))

    # §2: the same three deals, each held in its own stream and answered at one witnessed checkpoint
    # tick. The responder of the run serves one stream, so these are derived: each deal's records
    # move to a stream of their own, keeping their order, and each request and reply names the tick.
    multi = [multi_stream(e, env, TICK) for e, env in zip(history, envs)]
    streams = sorted({artifact_of(decode(rep))["evidence_stream"] for _, rep in multi})
    assert len(streams) == 3, streams
    out.append(case(
        "multi-stream-one-tick", "Three deals in three streams, one holder key, one witnessed checkpoint tick",
        ["§2", "§4.3", "§6.1", "§6.2"],
        "derived: each of history-1 to history-3 moved to a stream of its own deal, requested at the tick and "
        "re-signed by the holder key",
        container(basic, multi), [answered(decode(rep)) for _, rep in multi], history_props(), [], states=states))

    # §2, §6.2: the same, with one deal answered at its own stream's checkpoint, as its request named.
    alone = multi_stream(history[o], envs[o], STREAM_CHECKPOINT)
    out.append(case(
        "mutant-multi-stream-mixed-anchor", "Three deals in three streams, one answered at its stream's own checkpoint",
        ["§2", "§6.2"],
        f"derived: multi-stream-one-tick with history-{o + 1} requested and answered at its stream's checkpoint, "
        "re-signed by the holder key",
        container(basic, swap(multi, o, alone)),
        swap([answered(decode(rep)) for _, rep in multi], o, answered(decode(alone[1]))),
        history_props(single_anchor="FAIL"), ["single_anchor"]))

    # A request under the definition from a requester other than its recipient (§8.1, ER §4.2).
    refused = ex["other-requester"]
    out.append({
        "id": "refused-other-requester", "title": "A request under the definition from another requester",
        "cites": ["§6.4", "§8.1", "IP §6.3", "IP §8.1"], "source": "responder", "mode": "asked",
        "pins": pins(run), "inputs": {"requester": refused["requester"], "request": refused["request"],
                                      "reply": refused["reply"]},
        "expected": {"message_type": "refusal", "reason": "not_authorized", "properties": ref_props(),
                     "requirements": {REQUIREMENT: mapped("refusal-withheld")},
                     "claim": {"evidence": [ref(shx(refused["reply"]["octets_text"].encode()))], "proofs": []}},
    })
    return out


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def _dump(value: Any) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def check_frame(run: dict, all_cases: list[dict]) -> None:
    """HF §6.3: the instance's counting table and wording pack (``spec/history-frame/``) match the
    run's definition and what these vectors emit, and every case's acceptance is HF §4.5's rule."""
    table, pack = history_frame.load(HISTORY)
    assert table["properties"] == HISTORY_PROPS, "counting table: properties"
    basic = json.loads(run["definitions"]["basic"])
    assert sorted(basic) == sorted(table["definition_members"]), "counting table: definition members"
    assert all(basic[k] == v for k, v in table["definition_fixed"].items()), "counting table: definition values"
    s = pack["strings"]
    assert (s["deal_state.failed_step"], s["deal_state.completed_only"], s["deal_state.no_step"]) == (
        FAILED, COMPLETED, NO_STEP), "wording pack: deal states"
    positive = next(c for c in all_cases if c["id"] == "history-basic")
    for e in positive["inputs"]["exchanges"]:
        a = artifact_of(decode(e["reply"]))
        assert sorted(a) == sorted(table["artifact_members"]), "counting table: artifact members"
        assert {r["record_type"] for r in a["records"]} <= set(table["record_kinds"]), "counting table: kinds"
    for c in all_cases:
        e = c["expected"]
        if "history_properties" in e:
            ok = all(x["accepted"] for x in e["exchanges"]) and history_frame.accepted(
                e["history_properties"], table["may_be_not_checked"])
            assert e["accepted"] is ok, c["id"]
            if ok:
                assert set(e["deal_states"]["counts"]) == {FAILED, COMPLETED, NO_STEP}, c["id"]
    refused = next(c for c in all_cases if c["id"] == "refused-other-requester")
    assert refused["expected"]["reason"] == "not_authorized", "HF §4.9: the instance's non-recipient refusal"


def build(run: dict, run_sha256: str) -> dict[str, bytes]:
    all_cases = cases(run)
    ids = [c["id"] for c in all_cases]
    assert len(ids) == len(set(ids)), "duplicate case id"
    check_frame(run, all_cases)
    corpus = {
        "set": SET,
        "status": STATUS,
        "provenance": "responder-run",
        "profile": PROFILE,
        "history": HISTORY,
        "spec": SPEC,
        "responder": dict(RESPONDER, run="responder-run.json", run_sha256=run_sha256),
        "test_keys": {
            "note": "TEST-ONLY. Each private key is the 32-byte Ed25519 seed SHA-256(seed_label).",
            "keys": {name: {"seed_label": SEED_LABELS[name], "public": PUB[name]} for name in SEED_LABELS},
        },
        "contract": {"document": CONTRACT, "document_jcs": jcs(CONTRACT), "contract_ref": CONTRACT_REF,
                     "contract_digest": CONTRACT_DIGEST, "schema": RELEASED_EC_SCHEMA},
        "holder_stream": {"deals": run["deals"], "selection": run["selection"], "records": run["records"],
                          "checkpoints": run["checkpoints"]},
        "history_properties": HISTORY_PROPS,
        "refusal_properties": REFUSAL_PROPS,
        "count": len(all_cases),
        "cases": all_cases,
    }
    files = {"vectors.json": _dump(corpus)}
    files["manifest.json"] = _dump({
        "set": SET,
        "status": STATUS,
        "provenance": "responder-run",
        "spec": SPEC,
        "generator": "python/scripts/generate_personal_history_basic_v0_vectors.py",
        "responder": dict(RESPONDER, run="responder-run.json", run_sha256=run_sha256),
        "files": [{"path": name, "sha256": shx(data), "count": json.loads(data).get("count")}
                  for name, data in sorted(files.items())],
    })
    return files


def write(out: Path, run_path: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    raw = run_path.read_bytes()
    for name, data in build(load_run(run_path), shx(raw)).items():
        (out / name).write_bytes(data)
    if run_path.resolve() != (out / "responder-run.json").resolve():
        (out / "responder-run.json").write_bytes(raw)
    files = sorted((p.relative_to(out).as_posix(), p) for p in out.rglob("*") if p.is_file())
    lines = [f"{shx(p.read_bytes())}  {rel}" for rel, p in files if rel != "SHA256SUMS"]
    (out / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--run", type=Path, default=RUN, help="the responder run to build from")
    args = parser.parse_args()
    write(args.out, args.run)


if __name__ == "__main__":
    main()
