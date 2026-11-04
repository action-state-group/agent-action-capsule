#!/usr/bin/env python3
"""Generate the AAC <-> refusal-digest gate-boundary vector.

Deterministic: every output is derived from two pinned inputs and two published
test constants, so a third party can regenerate the directory byte for byte.

  inputs/issued-digest.json  the refusal digest exactly as its issuer emitted it
  inputs/test-key.pub    the public half of the test signing key
  TEST_KEY_SEED_LABEL        the published label the test key derives from
  RUN_SEED_LABEL             the published label the digest's run.seed derives from

The test key is a test constant. It secures nothing; it is published so that the
re-signed tamper cases (a lying issuer) can be expressed and reproduced.

Usage:  python generate.py            write every case beside this file
        python generate.py --check    regenerate in memory and diff (exit 1 on drift)

Requires the AAC Python reference (python/, installed with the dev extra) for
json_digest/compute_capsule_id, and `cryptography` for Ed25519 signing.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
import uuid
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_action_capsule.canonical import compute_capsule_id, json_digest

HERE = Path(__file__).resolve().parent
TEST_KEY_SEED_LABEL = b"aac-refusal-digest-gate-boundary/test-signing-key"
RUN_SEED_LABEL = b"aac-refusal-digest-gate-boundary"
KEY_ID = "gate-boundary-test"
PROBE_ID = "clock-overreach"
CONSTRAINT_ID = "org.example.operator_role_gate"

# ── the refusal digest's own byte rules (refusal-transparency §3, AHR §3) ──────
# Go's encoding/json: \b \f \n \r \t short; other C0 \u00xx; U+2028/9 escaped;
# keys sorted by code point (UTF-8 bytes). Not JCS: the digest is not an AAC
# artifact and does not use AAC canonicalization.
_SHORT = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _go_str(s: str, html: bool) -> str:
    out = ['"']
    for ch in s:
        cp = ord(ch)
        if ch in _SHORT:
            out.append(_SHORT[ch])
        elif cp < 0x20 or (html and ch in "<>&"):
            out.append(f"\\u{cp:04x}")
        elif cp in (0x2028, 0x2029):
            out.append(f"\\u{cp:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def go_json(v, *, sort_keys: bool, html: bool) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        return _go_str(v, html)
    if isinstance(v, list):
        return "[" + ",".join(go_json(x, sort_keys=sort_keys, html=html) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v) if sort_keys else list(v)
        return "{" + ",".join(_go_str(k, html) + ":" + go_json(v[k], sort_keys=sort_keys, html=html) for k in keys) + "}"
    raise TypeError(f"value outside the integer-only domain: {v!r}")


def event_hash(evt: dict) -> str:
    """The platform event-hash rule (ledger-export §2, refusal-transparency §2.1)."""
    pre = (
        evt["event_id"] + evt["event_type"] + evt["aggregate_type"] + evt["aggregate_id"]
        + evt["timestamp"] + str(evt["event_version"])
        + go_json(evt.get("payload"), sort_keys=False, html=True)
        + (evt.get("previous_event_id") or "")
    )
    return hashlib.sha256(pre.encode()).hexdigest()


def digest_hash(doc: dict) -> str:
    body = {k: v for k, v in doc.items() if k != "proof"}
    return hashlib.sha256(go_json(body, sort_keys=True, html=False).encode()).hexdigest()


KEY = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(TEST_KEY_SEED_LABEL).digest())
OTHER_KEY = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"not-the-issuer").digest())


def sig(message: str, key=KEY, key_id=KEY_ID) -> str:
    raw = key.sign(message.encode())
    return f"ed25519:{key_id}:" + base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def resign(doc: dict, key=KEY, key_id=KEY_ID) -> dict:
    doc = copy.deepcopy(doc)
    h = digest_hash(doc)
    doc["proof"]["digest_hash"] = h
    doc["proof"]["verification_method"] = key_id
    doc["proof"]["signature"] = sig(h, key, key_id)
    return doc


def probe(doc: dict) -> dict:
    return next(p for p in doc["probes"] if p["id"] == PROBE_ID)


# ── refusal-digest cases ───────────────────────────────────────────────────────
def digest_cases(issued: dict) -> list:
    # Self-check: this generator's byte rules reproduce the issuer's own hashes.
    assert digest_hash(issued) == issued["proof"]["digest_hash"], "digest_hash rule drifted"
    for p in issued["probes"]:
        for e in p["events"]:
            assert event_hash(e) == e["event_hash"], f"event-hash rule drifted at {e['event_id']}"

    cases = [("d-golden", issued, "pass", None,
              "the digest exactly as issued: every probe refused, every event hashed and signed")]

    t = copy.deepcopy(issued)
    probe(t)["refusal_ground"] = "allowed: operator approved the succession"
    cases.append(("d-ground-reworded", t, "fail", "proof", "refusal ground edited, digest not re-signed"))

    t = copy.deepcopy(issued)
    evts = probe(t)["events"]
    last = evts[-1]
    # A well-formed SuccessionApproved for the probe's own succession, so the only
    # thing wrong with it is that the refused transition is now on the record.
    legitimacy = next(e for e in evts if e["event_type"] == "LegitimacyDetermined")["payload"]["legitimacy_id"]
    forged = copy.deepcopy(last)
    forged["event_id"] = str(uuid.uuid5(uuid.NAMESPACE_URL, "aac-refusal-digest-gate-boundary/forged-approval"))
    forged["event_type"] = "SuccessionApproved"
    forged["payload"] = {"succession_id": last["payload"]["succession_id"], "legitimacy_id": legitimacy}
    forged["previous_event_id"] = last["event_id"]
    forged.pop("signature", None)
    forged["event_hash"] = event_hash(forged)
    forged["signature"] = sig(forged["event_hash"])
    evts.append(forged)
    cases.append(("d-forbidden-event-injected-resigned", resign(t), "fail", "forbidden_event",
                  "the refused transition appended to the probe ledger, hashed, signed and re-signed with the issuer key"))

    t = copy.deepcopy(issued)
    e = probe(t)["events"][0]
    e["payload"]["classification"] = "O2" if e["payload"]["classification"] != "O2" else "O3"
    cases.append(("d-event-payload-altered-resigned", resign(t), "fail", "event_hash",
                  "one probe event's payload value edited without recomputing its hash"))

    t = copy.deepcopy(issued)
    e = probe(t)["events"][0]
    s = e["signature"]
    e["signature"] = s[:-2] + ("AA" if s[-2:] != "AA" else "BB")
    cases.append(("d-event-signature-bitflip-resigned", resign(t), "fail", "event_signature",
                  "one probe event's signature corrupted"))

    t = copy.deepcopy(issued)
    t["summary"]["refused"] = t["summary"]["refused"] - 1
    cases.append(("d-summary-miscount-resigned", resign(t), "fail", "summary", "summary.refused restated wrongly"))

    t = copy.deepcopy(issued)
    seed = t["run"]["seed"]
    t["run"]["seed"] = ("0" if seed[0] != "0" else "1") + seed[1:]
    cases.append(("d-seed-flipped-resigned", resign(t), "fail", "seed_derivation",
                  "run.seed changed: the staged identities no longer derive from it"))

    t = copy.deepcopy(issued)
    t["spec_version"] = "9.9"
    cases.append(("d-spec-version-unknown-resigned", resign(t), "fail", "structure", "unimplemented spec_version"))

    cases.append(("d-lying-issuer-untrusted", resign(issued, OTHER_KEY, KEY_ID), "fail", "proof",
                  "re-signed under the issuer's key_id by a key the relying party does not trust"))

    # Boundary rows: these VERIFY. They are here to state what the digest cannot see.
    t = copy.deepcopy(issued)
    probe(t)["refusal_ground"] = "allowed: operator approved the succession"
    cases.append(("d-boundary-ground-rewritten-by-issuer", resign(t), "pass", None,
                  "BOUNDARY: the issuer re-signs a different ground. The ground is the issuer's statement; "
                  "nothing in the digest can contradict its own signer"))

    t = copy.deepcopy(issued)
    probe(t)["events"] = probe(t)["events"][:-1]
    cases.append(("d-boundary-tail-truncated-by-issuer", resign(t), "pass", None,
                  "BOUNDARY: the issuer drops the last ledger event and re-signs. Absence is checked over the "
                  "supplied ledger only; completeness of that ledger is the issuer's attestation"))
    return cases


# ── AAC cases ──────────────────────────────────────────────────────────────────
def evidence(issued: dict, digest_hash_value: str | None = None) -> dict:
    p = probe(issued)
    return {
        "evidence_version": "1",
        "refusal_digest": {
            "spec": issued["spec"],
            "spec_version": issued["spec_version"],
            "issuer": issued["issuer"]["id"],
            "key_id": KEY_ID,
            "digest_hash": digest_hash_value or issued["proof"]["digest_hash"],
        },
        "probe_id": p["id"],
        "run_seed": issued["run"]["seed"],
        "refusal_ground": p["refusal_ground"],
        "forbidden_event_types": p["forbidden_event_types"],
    }


MANIFEST = {
    "manifest_version": "1",
    "constraints": {
        CONSTRAINT_ID: {
            "description": "The gate refuses an operator-role caller on approve/complete routes.",
            "evidence_schema": {
                "required": ["evidence_version", "refusal_digest", "probe_id", "run_seed",
                             "refusal_ground", "forbidden_event_types"],
                "refusal_digest.required": ["spec", "spec_version", "issuer", "key_id", "digest_hash"],
            },
        }
    },
}


def seal(capsule: dict) -> dict:
    capsule = copy.deepcopy(capsule)
    capsule.pop("capsule_id", None)
    capsule["capsule_id"] = compute_capsule_id(capsule)
    return capsule


def control_capsule(issued: dict, ev: dict) -> dict:
    return seal({
        "spec_version": "draft-mih-scitt-agent-action-capsule-05",
        "format_version": "4",
        "canonicalization_id": "jcs",
        "action_id": f"{PROBE_ID}@{issued['run']['seed']}",
        "action_type": "decide",
        "operator": "org.example.operator",
        "developer": "agent@v1",
        "timestamp": issued["run"]["started_at"][:19] + "Z",
        "disposition": {"approver": "policy", "decision": "reject", "human_disposed": False,
                        "verdict_class": "blocked"},
        "constraints": [{
            "id": CONSTRAINT_ID,
            "check_type": "org.example.role_gate",
            "method": "org.example.router_refusal",
            "result": "fail",
            "severity": "high",
            "blocking": True,
            "evidence_digest": json_digest(ev),
        }],
        "assurance": {"attestation_mode": "self_attested", "effect_mode": "not_applicable",
                      "ledger_mode": "standalone"},
    })


def capsule_cases(issued: dict) -> list:
    ev = evidence(issued)
    ctl = control_capsule(issued, ev)
    out = [("c-blocked-control", ctl, ev, "pass", [], "pass", "pass",
            "valid blocked Capsule: policy rejected it pre-dispatch; no Effect Record")]

    t = copy.deepcopy(ctl)
    t["effect"] = {"status": "planned", "effect_attestation": "gate_executed"}
    out.append(("c-gate-executed-resealed", seal(t), ev, "fail", [5], "pass", "pass",
                "Imran's check-5 case: the blocked Capsule carries effect_attestation gate_executed and is "
                "resealed. effect_mode stays not_applicable, so the matrix requires the attestation absent"))

    t = copy.deepcopy(ctl)
    t["effect"] = {"effect_attestation": "gate_executed"}
    out.append(("c-gate-executed-no-status-resealed", seal(t), ev, "fail", [4], "pass", "pass",
                "the same claim without effect.status: a missing status derives dispatched_unconfirmed, for "
                "which the matrix REQUIRES an attestation, so check 5 is satisfied and check 4 (never-dispatch "
                "conflict) alone rejects it. Which check catches gate_executed depends on effect.status"))

    t = copy.deepcopy(ctl)
    t["effect"] = {"status": "planned", "effect_attestation": "gate_executed"}
    out.append(("c-gate-executed-not-resealed", t, ev, "fail", [2, 5], "pass", "pass",
                "gate_executed added without recomputing capsule_id"))

    t = copy.deepcopy(ctl)
    t["effect"] = {"status": "dispatched", "effect_attestation": "gate_executed"}
    out.append(("c-dispatched-under-blocked-resealed", seal(t), ev, "fail", [4], "pass", "pass",
                "a dispatched effect recorded under a blocked verdict"))

    t = copy.deepcopy(ctl)
    t["capsule_id"] = ("0" if t["capsule_id"][0] != "0" else "1") + t["capsule_id"][1:]
    out.append(("c-capsule-id-mutated", t, ev, "fail", [2], "pass", "pass", "capsule_id no longer recomputes"))

    t = copy.deepcopy(ctl)
    d = t["constraints"][0]["evidence_digest"]
    t["constraints"][0]["evidence_digest"] = ("0" if d[0] != "0" else "1") + d[1:]
    out.append(("c-evidence-digest-mutated-resealed", seal(t), ev, "pass", [], "fail:evidence_digest", "n/a",
                "Class 1 cannot see it: the constraint's evidence_digest no longer matches the evidence. "
                "Only the manifest-dependent check catches it"))

    ev_other = evidence(issued, "f" * 64)
    out.append(("c-evidence-binds-other-digest-resealed", control_capsule(issued, ev_other), ev_other,
                "pass", [], "pass", "fail:digest_binding",
                "the evidence is self-consistent and its digest matches, but it names a refusal digest other "
                "than the one supplied"))

    t = copy.deepcopy(ctl)
    t["action_id"] = f"illegal-amendment@{issued['run']['seed']}"
    out.append(("c-action-id-other-probe-resealed", seal(t), ev, "pass", [], "pass", "fail:attempt_join",
                "the Capsule names a different attempt than its evidence and the digest probe"))
    return out


def build() -> dict[str, bytes]:
    issued = json.loads((HERE / "inputs" / "issued-digest.json").read_text())
    assert issued["run"]["seed"] == hashlib.sha256(RUN_SEED_LABEL).hexdigest(), "run.seed is not the published one"
    files: dict[str, bytes] = {}

    def put(name, obj):
        files[name] = (json.dumps(obj, indent=2, ensure_ascii=False) + "\n").encode()

    rows_d = []
    for name, doc, expect, check, note in digest_cases(issued):
        put(f"digest/{name}.json", doc)
        rows_d.append({"case": name, "file": f"digest/{name}.json", "expect": expect,
                       "failing_check": check, "note": note})

    rows_c = []
    for name, cap, ev, c1, c1_checks, c2, cross, note in capsule_cases(issued):
        put(f"capsule/{name}.json", cap)
        ev_name = "capsule/evidence.json" if ev == evidence(issued) else f"capsule/{name}.evidence.json"
        put(ev_name, ev)
        rows_c.append({"case": name, "file": f"capsule/{name}.json", "evidence": ev_name,
                       "class1": c1, "class1_failing_checks": c1_checks,
                       "manifest_dependent": c2, "cross_format": cross, "note": note})
    put("capsule/manifest.json", MANIFEST)

    vector = {
        "profile_label": "urn:action-state:aac-refusal-digest:gate-boundary:2026-11-04",
        "status": "compatibility experiment; no commitment to adoption, integration or specification change",
        "pins": {
            "aac_spec": "draft-mih-scitt-agent-action-capsule-06 (Capsule spec_version draft-mih-scitt-agent-action-capsule-05)",
            "aac_reference": {"repo": "action-state-group/agent-action-capsule", "python_at": ["518303c", "33aa732"]},
            "refusal_digest_spec": {"repo": "jsabes24/css-succession-receipts", "commit": "edc254b",
                                    "spec": "spec/refusal-transparency.md (css-refusal-digest v0.2)",
                                    "draft": "draft-sabey-refusal-transparency-03"},
            "refusal_digest_verifier": {
                "kind": "public browser verifier (Go compiled to WebAssembly), run under Node by check_digest.mjs",
                "url": "https://continuitylaboratories.com/verifier/sr-verify.wasm",
                "runtime": "https://continuitylaboratories.com/verifier/wasm_exec.js",
                "sha256": "5c3acb19da62f99c454b19a271e2eaf008722968ca58732f827593bda77690db",
                "note": "the binary is published and pinned; its source is not. The format, its specification and "
                        "conformance corpus are public, so any implementation of refusal-transparency section 4 "
                        "can be substituted",
            },
        },
        "derivation_inputs": {
            "run_seed": {"label": RUN_SEED_LABEL.decode(), "rule": "sha256(label), lowercase hex",
                         "value": issued["run"]["seed"]},
            "test_signing_key": {"label": TEST_KEY_SEED_LABEL.decode(),
                                 "rule": "Ed25519 private key = sha256(label) (RFC 8032 seed)",
                                 "key_id": KEY_ID, "public_key": "inputs/test-key.pub",
                                 "note": "test constant; secures nothing"},
            "issued_digest": {"file": "inputs/issued-digest.json",
                              "digest_hash": issued["proof"]["digest_hash"]},
            "joined_probe": PROBE_ID,
            "capsule_action_id_rule": "<probe id>@<digest run.seed>",
            "evidence_digest_rule": "AAC json_digest(evidence) = HEX(SHA-256(JCS(evidence)))",
            "capsule_id_rule": "AAC compute_capsule_id (format 4, JCS)",
        },
        "cross_format_checks": {
            "attempt_join": "capsule.action_id == evidence.probe_id + '@' + evidence.run_seed, and that probe is "
                            "a refused probe of the supplied digest whose run.seed matches (no manifest needed for "
                            "the action_id half)",
            "digest_binding": "evidence.refusal_digest.digest_hash == the supplied digest's verified "
                              "proof.digest_hash, and evidence.refusal_ground / forbidden_event_types equal the "
                              "probe's verbatim (needs the evidence, so manifest-dependent)",
        },
        "digest_cases": rows_d,
        "capsule_cases": rows_c,
    }
    put("vector.json", vector)
    pinned = {f"inputs/{n}": (HERE / "inputs" / n).read_bytes() for n in ("issued-digest.json", "test-key.pub")}
    every = {**files, **pinned}
    sums = "".join(f"{hashlib.sha256(every[k]).hexdigest()}  {k}\n" for k in sorted(every))
    files["SHA256SUMS"] = sums.encode()
    return files


def main() -> int:
    files = build()
    if "--check" in sys.argv:
        drift = [k for k, v in files.items() if not (HERE / k).is_file() or (HERE / k).read_bytes() != v]
        for k in drift:
            print(f"drift: {k}")
        return 1 if drift else 0
    for k, v in files.items():
        (HERE / k).parent.mkdir(parents=True, exist_ok=True)
        (HERE / k).write_bytes(v)
    print(f"wrote {len(files)} files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
