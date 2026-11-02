# SPDX-License-Identifier: BSD-3-Clause
"""The evidence-interop/0 conformance vectors (``vectors/interop-profile-v0/`` and
``vectors/interop-profile-v0-requirement-facts/``), checked from their inputs alone.

``test_interop_profile_v1_vectors.py`` runs this module again with ``_PROFILE_VERSION`` 1, for the
evidence-interop/1 corpora and ``spec/interop-profile-v1.md``; every version-dependent name below
derives from that one value.

Nothing here imports the generator. Every digest, signature and encoding is recomputed from the
octets each case carries: JSON through this library's RFC 8785 ``jcs``, CBOR through a strict
decoder written here (definite lengths, shortest heads, sorted keys, no duplicates), MMR proofs
through functions written here from the pinned MMR -02 algorithms, and Ed25519 through
``cryptography``. Each expected status is then derived by an evaluator written here from
``spec/interop-profile-v0.md`` (§3.3, §6.2.1, §7, §8, §11.1, §11.2, §11.4) and compared with the
status the generator states by hand. The two derivations are independent; a disagreement fails.

The evaluator also runs with named defects switched on (``MUTANTS``); the corpus must catch each.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from agent_action_capsule._ed25519_strict import strict_encoding
from agent_action_capsule.canonical import jcs

ROOT = Path(__file__).resolve().parents[2]
VERSION = globals().get("_PROFILE_VERSION", 0)
V = f"v{VERSION}"
VECTORS = ROOT / "vectors" / f"interop-profile-{V}"
SPEC = ROOT / "spec" / f"interop-profile-{V}.md"
# Each set the generator writes, by its --set name: its directory and its root manifest key.
SETS = {"interop-profile-v0": (VECTORS, f"interop_profile_{V}"),
        "requirement-facts": (ROOT / "vectors" / f"interop-profile-{V}-requirement-facts",
                              f"interop_profile_{V}_requirement_facts")}
GENERATOR = ROOT / "python" / "scripts" / "generate_interop_profile_v0_vectors.py"
HAND_WRITTEN = ("README.md",)
DATA = json.loads((VECTORS / "vectors.json").read_text(encoding="utf-8"))
CASES = DATA["cases"]
PROFILE = f"evidence-interop/{VERSION}"
# §3.3 step 2: a request with no profile asks for evidence-interop/0, in both revisions.
DEFAULT_PROFILE = "evidence-interop/0"
EXT_URI = "https://datatracker.ietf.org/doc/draft-mih-agent-evidence-request/"
TIME = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
REASONS = {"not_authorized", "no_such_subject", "coverage_unsatisfiable", "derivation_unsupported",
           "policy_declined", "deadline_unmet", "request_malformed", "retention_expired"}
# §9.1 of each revision: v0 pins ER -01's eight tokens, v1 ER -02's ten.
REASONS_BY_PROFILE = {"evidence-interop/0": frozenset(REASONS),
                      "evidence-interop/1": frozenset(REASONS | {"capacity_exceeded", "request_unauthenticated"})}
KINDS = ("cll-checkpoint", "cll-inclusion-proof", "cll-consistency-proof")
# The Evidence Contract projection [EC contractResult] and §8.1.
PROJECTION = {"SATISFIED": "SATISFIED", "NOT_FOUND": "GAP", "NOT_COMMITTED": "GAP", "WITHHELD": "GAP",
              "CONTRADICTED": "GAP", "INSUFFICIENT": "INSUFFICIENT", "UNKNOWN": "UNKNOWN"}


def sha(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def shx(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def jdigest(value: Any) -> str:
    return shx(jcs(value))


def d64u(text: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]*", text):
        raise ValueError("not base64url without padding")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def d64(text: str) -> bytes:
    return base64.b64decode(text, validate=True)


def verifies(key_hex: str, sig_hex: str, message: bytes, *, strict: bool = True) -> bool:
    """Ed25519; at /1 strict (§5.2) unless ``strict`` is False, for a foreign object's own check (§5.1)."""
    if strict and VERSION >= 1 and not strict_encoding(bytes.fromhex(key_hex), bytes.fromhex(sig_hex)):
        return False  # §5.2: strict Ed25519, P-68
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex)).verify(bytes.fromhex(sig_hex), message)
        return True
    except (InvalidSignature, ValueError):
        return False


def strict_json(text: str) -> Any:
    def no_dup(pairs):
        keys = [k for k, _ in pairs]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate member")
        return dict(pairs)
    return json.loads(text, object_pairs_hook=no_dup)


# ---------------------------------------------------------------------------
# Strict deterministic CBOR decoder
# ---------------------------------------------------------------------------


class Bad(Exception):
    pass


def _dec(b: bytes, i: int):
    if i >= len(b):
        raise Bad("truncated")
    ib = b[i]
    mt, ai = ib >> 5, ib & 31
    i += 1
    if ai < 24:
        n = ai
    elif ai in (24, 25, 26, 27):
        k = 1 << (ai - 24)
        if len(b) < i + k:
            raise Bad("truncated")
        n = int.from_bytes(b[i:i + k], "big")
        if n < (24 if k == 1 else 1 << (8 * k // 2)):
            raise Bad("non-shortest head")
        i += k
    else:
        raise Bad("indefinite or reserved")
    if mt == 0:
        return n, i
    if mt == 1:
        return -1 - n, i
    if mt in (2, 3):
        if len(b) < i + n:
            raise Bad("truncated")
        v = b[i:i + n]
        return (v if mt == 2 else v.decode("utf-8")), i + n
    if mt == 4:
        out = []
        for _ in range(n):
            v, i = _dec(b, i)
            out.append(v)
        return out, i
    if mt == 5:
        out, raw = {}, []
        for _ in range(n):
            s = i
            k, i = _dec(b, i)
            raw.append(b[s:i])
            v, i = _dec(b, i)
            if isinstance(k, (list, dict, tuple)) or k in out:
                raise Bad("bad or duplicate key")
            out[k] = v
        if raw != sorted(raw):
            raise Bad("keys not in deterministic order")
        return out, i
    if mt == 6:
        v, i = _dec(b, i)
        return ("tag", n, v), i
    if ib == 0xF6:
        return None, i
    if ib in (0xF4, 0xF5):
        return ib == 0xF5, i
    raise Bad("unsupported item")


def dec1(b: bytes):
    v, i = _dec(b, 0)
    if i != len(b):
        raise Bad("trailing octets")
    return v


def _head(mt: int, n: int) -> bytes:
    if n < 24:
        return bytes([mt << 5 | n])
    for ai, k in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * k):
            return bytes([mt << 5 | ai]) + n.to_bytes(k, "big")
    raise ValueError


def sig_structure(protected: bytes, payload: bytes) -> bytes:
    """COSE Sig_structure for Signature1 with empty external AAD (RFC 9052 §4.4)."""
    parts = [b"Signature1", protected, b"", payload]
    out = _head(4, 4) + _head(3, 10) + parts[0]
    for p in parts[1:]:
        out += _head(2, len(p)) + p
    return out


# ---------------------------------------------------------------------------
# MMR, from the pinned MMR -02 algorithms
# ---------------------------------------------------------------------------


def index_height(i: int) -> int:
    pos = i + 1
    while pos & (pos + 1):
        pos = pos - (1 << (pos.bit_length() - 1)) + 1
    return pos.bit_length() - 1


def hp(pos: int, a: bytes, b: bytes) -> bytes:
    return sha(pos.to_bytes(8, "big") + a + b)


def peaks(i: int) -> list[int]:
    pk, out, s = 0, [], i + 1
    while s:
        hi = (1 << ((s + 1).bit_length() - 1)) - 1
        pk += hi
        out.append(pk - 1)
        s -= hi
    return out


def included_root(i: int, node: bytes, proof: list[bytes]) -> bytes:
    r, g = node, index_height(i)
    for s in proof:
        if index_height(i + 1) > g:
            i += 1
            r = hp(i + 1, s, r)
        else:
            i += 2 << g
            r = hp(i + 1, r, s)
        g += 1
    return r


def consistent_roots(ifrom: int, acc: list[bytes], proofs: list[list[bytes]]) -> list[bytes]:
    roots = []
    for p, a, path in zip(peaks(ifrom), acc, proofs):
        r = included_root(p, a, path)
        if not roots or roots[-1] != r:
            roots.append(r)
    return roots


def peak_list(raw: bytes) -> list[bytes]:
    v = dec1(raw)
    if not isinstance(v, list) or not v or not all(isinstance(x, bytes) and len(x) == 32 for x in v):
        raise Bad("peak list")
    return v


# ---------------------------------------------------------------------------
# The evaluator
# ---------------------------------------------------------------------------

ENVELOPE_SIGNED = ("profile", "request_digest", "subject", "derivation", "anchor", "artifact_digest",
                   "verification", "responder", "issued_at")


class Verifier:
    """Derives every status of a case from its inputs, per the profile. ``mutant`` switches on one defect."""

    def __init__(self, case: dict, mutant: str | None = None):
        self.case, self.m = case, mutant
        p = case["pins"]
        self.policy, self.vpolicy = p["trust_policy"], p["verification_policy"]
        self.contract = DATA["contract"]["document"]

    # ---- inputs ----
    @staticmethod
    def octets(o: dict) -> bytes:
        return o["octets_text"].encode("utf-8") if "octets_text" in o else bytes.fromhex(o["octets_hex"])

    @staticmethod
    def decode(media_type: str, data: bytes) -> dict:
        if media_type == "application/json":
            obj = strict_json(data.decode("utf-8"))
            if jcs(obj) != data:
                raise Bad("JSON octets are not the JCS form")
            if "artifact" in obj:
                obj["artifact"] = d64u(obj["artifact"])
            if "verification_content" in obj:
                obj["verification_content"] = [d64u(t) for t in obj["verification_content"]]
            return obj
        return dec1(data)

    # ---- §6.2.1 ----
    def log_key(self, iss: str, sub: str, kid: bytes) -> str | None:
        for e in self.policy["log_keys"]:
            if (e["iss"], e["sub"], e["kid"]) == (iss, sub, kid.hex()):
                return e["kid"]
        return None

    def anchor_inclusion(self, env: dict, pre_ok: bool) -> str:
        if list(env["subject"]) != ["record"] or "derivation" in env:
            return "NOT_CHECKED"
        ver = env.get("verification")
        if not ver:
            return "NOT_PRESENT"
        kinds = [e["kind"] for e in ver]
        if any(k not in self.vpolicy["kinds_implemented"] or k not in KINDS for k in kinds):
            return "NOT_CHECKED"
        if any(kinds.count(k) > 1 for k in KINDS):
            return "FAIL"
        if "cll-checkpoint" not in kinds or "cll-inclusion-proof" not in kinds:
            return "NOT_PRESENT"
        if not pre_ok:
            return "NOT_CHECKED"
        if env["subject"]["record"] != env["artifact_digest"]:
            return "NOT_CHECKED"
        items = dict(zip(kinds, env["verification_content"]))
        if ver[kinds.index("cll-checkpoint")]["digest"] != env["anchor"]["digest"]:
            return "FAIL"
        try:
            c = dec1(items["cll-checkpoint"])
            if not (isinstance(c, tuple) and c[1] == 18):
                raise Bad("tag")
            c = c[2]
            if not (isinstance(c, list) and len(c) == 4 and c[1] == {} and all(
                    isinstance(c[j], bytes) for j in (0, 2, 3))):
                raise Bad("COSE_Sign1")
            prot, claims = dec1(c[0]), dec1(c[2])
            kid, cwt = prot.get(4), prot.get(15)
            if 1 not in prot or not isinstance(kid, bytes) or not isinstance(cwt, dict) or not {1, 2} <= set(cwt):
                raise Bad("header")
            ls, ps = claims["log_size"], claims["prev_size"]
            if claims["kind"] != "cll-checkpoint" or not (isinstance(ls, int) and isinstance(ps, int) and 0 <= ps <= ls):
                raise Bad("claims")
            commit = peak_list(claims["commitment"])
            prev = peak_list(claims["prev_commitment"]) if ps else []
            if not ps and claims["prev_commitment"] != b"":
                raise Bad("prev_commitment")
        except (Bad, KeyError, TypeError, ValueError):
            return "FAIL"
        if prot[1] != -8 or 2 in prot:
            return "NOT_CHECKED"
        key = self.log_key(cwt[1], cwt[2], kid)
        if key is None:
            return "FAIL"
        if not verifies(key, c[3].hex(), sig_structure(c[0], c[2])):
            return "FAIL"
        try:
            idx, path = dec1(items["cll-inclusion-proof"])
        except (Bad, ValueError, TypeError):
            return "FAIL"
        if index_height(idx) != 0:
            return "FAIL"
        if included_root(idx, sha(b"\x00" + bytes.fromhex(env["artifact_digest"])), path) not in commit:
            return "FAIL"
        if "cll-consistency-proof" in items:
            try:
                ts1, ts2, paths, right = dec1(items["cll-consistency-proof"])
                if ts1 > ts2 or not ps or not (len(peaks(ts1 - 1)) == len(paths) == len(prev)):
                    raise Bad("shape")
                roots = consistent_roots(ts1 - 1, prev, paths)
                if len(right) != len(peaks(ts2 - 1)) - len(roots) or roots + right != commit:
                    raise Bad("accumulator")
            except (Bad, ValueError, TypeError):
                return "FAIL"
        return "PASS"

    # ---- §7.2, §7.3: envelope ----
    def envelope_props(self, env: dict, req_octets: bytes, req: dict) -> dict:
        props: dict[str, str] = {}
        others = ("envelope_signature", "responder_trust", "responder_key_current", "issued_at_form",
                  "request_binding", "subject_binding", "artifact_digest", "verification_binding",
                  "anchor_match", "anchor_inclusion")
        asked = req.get("profile", DEFAULT_PROFILE)
        if "profile" not in env:
            props["profile_version"] = "NOT_PRESENT"
        elif env["profile"] != asked:
            props["profile_version"] = "FAIL"
        elif env["profile"] not in self.vpolicy["profiles_implemented"]:
            props["profile_version"] = "NOT_CHECKED"
        else:
            props["profile_version"] = "PASS"
        if props["profile_version"] != "PASS" and self.m != "version-ignored":
            return {**props, **dict.fromkeys(others, "NOT_CHECKED")}
        body = {k: env[k] for k in ENVELOPE_SIGNED if k in env}
        st = lambda ok: "PASS" if ok else "FAIL"  # noqa: E731
        props["envelope_signature"] = st(verifies(env["responder"], env["sig"], jcs(body)))
        props["responder_trust"] = st(env["responder"] in self.policy["responder_keys"])
        assert not self.vpolicy["online"], "the vectors pin an offline verifier"
        props["responder_key_current"] = "NOT_CHECKED"  # an online check, made offline (§7.1)
        props["issued_at_form"] = st(isinstance(env.get("issued_at"), str) and TIME.match(env["issued_at"]))
        props["request_binding"] = st(env["request_digest"] == shx(req_octets) or self.m == "binding-skipped")
        props["subject_binding"] = st(env["subject"] == req["subject"] and env.get("derivation") == req.get("derivation"))
        props["artifact_digest"] = st(shx(env["artifact"]) == env["artifact_digest"])
        ver, items = env.get("verification", []), env.get("verification_content", [])
        props["verification_binding"] = st(len(ver) == len(items) and all(
            shx(x) == e["digest"] for x, e in zip(items, ver)))
        cov = req["coverage"]
        if "expected_pin" in cov:
            props["anchor_match"] = st(env["anchor"]["digest"] == cov["expected_pin"])
        else:
            floor, got = cov["min_freshness"], env["anchor"].get("freshness")
            props["anchor_match"] = st(got is not None and type(got) is type(floor) and got >= floor)
        pre_ok = all(props[k] == "PASS" for k in ("envelope_signature", "artifact_digest", "verification_binding"))
        props["anchor_inclusion"] = self.anchor_inclusion(env, pre_ok)
        return props

    @staticmethod
    def required_ok(props: dict) -> dict:
        return {k: v for k, v in props.items() if k != "responder_key_current"}

    def native_check(self, artifact: bytes, spec: dict) -> str:
        obj = strict_json(artifact.decode("utf-8"))
        for part in spec["path"].split("."):
            obj = obj[part]
        h, p, s = obj.split(".")
        header = strict_json(d64u(h).decode("utf-8"))
        if header.get("alg") != "EdDSA" or header.get("kid") not in self.policy["foreign_keys"]:
            return "FAIL"
        ok = verifies(header["kid"], d64u(s).hex(), f"{h}.{p}".encode("ascii"), strict=False)
        return "PASS" if ok else "FAIL"

    def envelope_rows(self, props: dict, invariance_fail: bool, native: str | None) -> dict:
        req = self.required_ok(props)
        relations = self.case["inputs"].get("requirement_relations", {"r-record": None})
        rows = {}
        for r, relation in relations.items():
            if invariance_fail and self.m != "invariance-ignored":
                row = "envelope-1"
            elif "FAIL" in req.values():
                row = "envelope-2"
            elif "NOT_PRESENT" in req.values():
                row = "envelope-3"
            elif {"NOT_CHECKED", "INCONCLUSIVE"} & set(req.values()):
                row = "envelope-4"
            elif native == "FAIL" and relation == "is_check":
                row = "envelope-6" if self.m == "is-check-as-supports" else "envelope-5"
            elif native == "FAIL" and relation == "supports":
                row = "envelope-5" if self.m == "supports-as-is-check" else "envelope-6"
            else:
                row = "envelope-7"
            rows[r] = row
        return rows

    # ---- §6.3, §7.3: refusal ----
    def reasons(self, req: dict) -> frozenset:
        """§6.3, §9.1: a refusal is checked against the tokens of the identifier its request asks
        for, or of every identifier implemented when that one is not."""
        implemented = [p for p in self.vpolicy["profiles_implemented"] if p in REASONS_BY_PROFILE]
        if self.m == "reasons-of-the-latest":
            return REASONS_BY_PROFILE[max(implemented)]
        asked = req.get("profile", DEFAULT_PROFILE)
        if asked in implemented:
            return REASONS_BY_PROFILE[asked]
        return frozenset().union(*(REASONS_BY_PROFILE[p] for p in implemented))

    def refusal_props(self, ref: dict, req_octets: bytes, req: dict) -> dict:
        st = lambda ok: "PASS" if ok else "FAIL"  # noqa: E731
        body = {k: ref[k] for k in ("issued_at", "reason", "request_digest")}
        return {
            "refusal_signature": st(verifies(ref["key_id"], ref["sig"], jcs(body))),
            "responder_trust": st(ref["key_id"] in self.policy["responder_keys"] or self.m == "refusal-trust-skipped"),
            "responder_key_current": "NOT_CHECKED",
            "request_binding": st(ref["request_digest"] == shx(req_octets)),
            "reason_registered": st(ref["reason"] in self.reasons(req)),
            "issued_at_form": st(isinstance(ref.get("issued_at"), str) and TIME.match(ref["issued_at"])),
        }

    @staticmethod
    def refusal_row(props: dict, reason: str) -> str:
        if any(v != "PASS" for k, v in props.items() if k != "responder_key_current"):
            return "refusal-failed"
        if reason in ("not_authorized", "policy_declined", "derivation_unsupported"):
            return "refusal-withheld"
        if reason in ("deadline_unmet", "request_malformed"):
            return "refusal-deadline_or_malformed"
        return f"refusal-{reason}"

    # ---- one reply ----
    def reply(self, media_type: str, data: bytes, req_octets: bytes, req: dict) -> dict:
        obj = self.decode(media_type, data)
        if "artifact_digest" in obj and "reason" not in obj:
            props = self.envelope_props(obj, req_octets, req)
            out = {"message_type": "envelope", "properties": props, "_env": obj}
            out["claim"] = {"evidence": [{"digest_alg": "SHA-256", "digest": obj["artifact_digest"]}],
                            "proofs": []}
            if props["anchor_inclusion"] == "PASS":
                inc = [e for e in obj["verification"] if e["kind"] == "cll-inclusion-proof"][0]
                out["claim"]["proofs"] = [{"kind": "inclusion_proof", "digest_alg": "SHA-256",
                                           "digest": inc["digest"]}]
            return out
        if "reason" in obj and "artifact_digest" not in obj:
            props = self.refusal_props(obj, req_octets, req)
            return {"message_type": "refusal", "properties": props,
                    "_row": self.refusal_row(props, obj["reason"]),
                    "claim": {"evidence": [{"digest_alg": "SHA-256", "digest": shx(data)}], "proofs": []}}
        raise Bad("not a reply")

    def finish(self, replies: list[dict]) -> tuple[list[dict], dict]:
        """Set-level caller_invariance (§7.2) and the §8.1 mapping of each reply."""
        envs = [r for r in replies if r["message_type"] == "envelope"]
        group = [r for r in envs if all(r["properties"].get(k) == "PASS"
                                        for k in ("envelope_signature", "responder_trust", "artifact_digest"))]
        keys = {(r["_env"]["responder"], jcs(r["_env"]["subject"]), r["_env"].get("derivation"),
                 r["_env"]["anchor"]["digest"]) for r in group}
        assert len(keys) <= 1, "vectors compare one question per case"
        if len(group) < 2:
            inv = "NOT_CHECKED"
        else:
            inv = "PASS" if len({r["_env"]["artifact_digest"] for r in group}) == 1 else "FAIL"
        out = []
        for r in replies:
            r = dict(r)
            if r["message_type"] == "envelope":
                env = r.pop("_env")
                contradicted = inv == "FAIL" and any(g["_env"] is env for g in group)
                native = None
                spec = self.case["inputs"].get("foreign_object")
                rq = self.required_ok(r["properties"])
                if spec and all(v == "PASS" for v in rq.values()) and not contradicted:
                    native = self.native_check(env["artifact"], spec)
                if spec:
                    r["native_check"] = native
                rows = self.envelope_rows(r["properties"], contradicted, native)
            else:
                rows = {"r-record": r.pop("_row")}
            r["requirements"] = {req: {"row": row} for req, row in rows.items()}
            out.append(r)
        return out, {"caller_invariance": inv}

    # ---- an absence record (§6.4, §7.3) ----
    def absence(self, data: bytes, req_octets: bytes) -> dict:
        rec = strict_json(data.decode("utf-8"))
        unsigned = ("sig", "key_id") if self.m == "absence-key-id-unsigned" else ("sig",)
        ok = (rec.get("outcome") == "recorded_absence" and rec["request_digest"] == shx(req_octets)
              and TIME.match(rec["recorded_at"]) and rec["recorded_at"] >= rec["window"]["closed"]
              and "reason" not in rec and ("key_id" in rec) == ("sig" in rec)
              and ("sig" not in rec or verifies(rec["key_id"], rec["sig"], jcs(
                  {k: v for k, v in rec.items() if k not in unsigned}))))
        if not ok:  # not an absence, so no claim (§6.4, §8.2 invariant 3)
            return {"form": "not_conforming", "requirements": {}}
        return {"form": "conforming",
                "requirements": {"r-record": {"row": "absence"}},
                "claim": {"evidence": [{"digest_alg": "SHA-256", "digest": shx(data)}], "proofs": []}}

    # ---- §11.1 ----
    def party(self, key: str) -> str | None:
        return self.policy["parties"].get(key)

    def accepted_as(self, key: str, other: str) -> bool:
        return self.party(key) is not None and self.party(key) != self.party(other)

    def acceptance(self) -> dict:
        inp = self.case["inputs"]
        records = [strict_json(t) for t in inp["acceptance_records"]]
        by_digest = {jdigest(r): r for r in records}
        execs = [strict_json(t) for t in inp["execution_records"]]
        receipts = [strict_json(t) for t in inp["acceptance_receipts"]]
        contract_digest = jdigest(self.contract)
        contract_ref = f"{self.contract['id']}@{self.contract['version']}"
        st = lambda ok: "PASS" if ok else "FAIL"  # noqa: E731
        unsigned = lambda r: jcs({k: v for k, v in r.items() if k != "sig"})  # noqa: E731

        def signer(r: dict) -> str:
            return r["proposer"] if r["state"] == "proposed" else r["acceptor"]

        def form(r: dict) -> bool:
            need = {"profile", "state", "contract_ref", "contract_digest", "transaction", "proposer", "acceptor",
                    "issued_at", "sig"}
            if r["state"] != "proposed":
                need.add("proposal_digest")
            if r["state"] == "countered":
                need.add("counter_contract_digest")
            allowed = need | {"session", "authority"}
            return (r.get("profile") == PROFILE and r.get("state") in ("proposed", "accepted", "declined", "countered")
                    and need <= set(r) <= allowed and bool(TIME.match(r["issued_at"])))

        def sig_ok(r: dict) -> bool:
            return verifies(signer(r), r["sig"], unsigned(r))

        def receipt_props(rc: dict, rec: dict) -> dict:
            return {"receipt_signature": st(verifies(rc["receiver"], rc["sig"], unsigned(rc))),
                    "receipt_signer": st(rc["receiver"] == rec["proposer"] and rc["receiver"] != rec["acceptor"]
                                         and self.accepted_as(rc["receiver"], rec["acceptor"]))}

        action_times = [e["action_at"] for e in execs if verifies(e["issuer"], e["sig"], unsigned(e))
                        and e["issuer"] == inp["acceptor"]]
        candidates, out_receipts = [], []
        for d, r in by_digest.items():
            if not (r["state"] == "accepted" and r["contract_digest"] == contract_digest
                    and r["proposer"] == inp["proposer"] and r["acceptor"] == inp["acceptor"]
                    and r["transaction"] == inp["transaction"] and "session" not in r):
                continue
            p: dict[str, str] = {}
            p["acceptance_form"] = st(form(r))
            p["acceptance_signature"] = st(sig_ok(r))
            p["acceptance_signer_trust"] = st(self.accepted_as(r["acceptor"], r["proposer"]))
            p["acceptance_binding"] = st(r["contract_digest"] == contract_digest and r["contract_ref"] == contract_ref)
            prop = by_digest.get(r["proposal_digest"])
            if prop is None or prop["state"] != "proposed":
                p["proposal_binding"] = "NOT_PRESENT"
            else:
                same = all(prop.get(k) == r.get(k) for k in ("contract_ref", "contract_digest", "transaction",
                                                              "proposer", "acceptor", "session"))
                p["proposal_binding"] = st(sig_ok(prop) and self.accepted_as(prop["proposer"], prop["acceptor"]) and same)
            answers = [jdigest(a) for a in records if a["state"] != "proposed"
                       and a.get("proposal_digest") == r["proposal_digest"] and a["acceptor"] == r["acceptor"]
                       and sig_ok(a) and self.accepted_as(a["acceptor"], a["proposer"])]
            p["acceptance_unique"] = "NOT_CHECKED" if len(answers) < 2 else st(len(set(answers)) == 1)
            if not execs:
                p["execution_cites_acceptance"] = "NOT_PRESENT"
            else:
                p["execution_cites_acceptance"] = st(all(
                    verifies(e["issuer"], e["sig"], unsigned(e)) and e["issuer"] == r["acceptor"]
                    and {"type": "cites", "target": d} in e["links"] and e["transaction"] == r["transaction"]
                    for e in execs))
            rps = [(rc, receipt_props(rc, r)) for rc in receipts if rc["acceptance_digest"] == d]
            out_receipts += [{"receipt_digest": jdigest(rc), "properties": rp} for rc, rp in rps]
            counted = [rc for rc, rp in rps if all(v == "PASS" for v in rp.values())]
            arp = min(action_times) if action_times else None
            relied: list[str] = []
            if arp is None:
                order = "NOT_PRESENT"
            elif any(r["issued_at"] > t for t in action_times):
                order = "FAIL"
            elif self.policy["require_action_time_from_other_party"]:
                order = "NOT_PRESENT"
            elif self.m == "ordering-trusts-issued_at" and r["issued_at"] < arp:
                order = "PASS"
            elif any(rc["received_at"] < arp for rc in counted):
                order = "PASS"
                relied = [jdigest(rc) for rc in counted if rc["received_at"] < arp]
            elif counted:
                order = "INCONCLUSIVE"
            else:
                order = "NOT_PRESENT"
            p["acceptance_ordering"] = order
            if any(p[k] != "PASS" for k in ("acceptance_form", "acceptance_signature", "acceptance_signer_trust",
                                            "acceptance_binding", "proposal_binding")) or p["acceptance_unique"] == "FAIL":
                finding = "not_accepted"
            elif order == "FAIL":
                finding = "accepted_after_action"
            elif p["execution_cites_acceptance"] != "PASS":
                finding = "accepted_not_cited"
            elif order == "PASS":
                finding = "accepted_before_action"
            else:
                finding = "accepted_execution_cites"
            candidates.append({"record_digest": d, "properties": p, "_finding": finding, "_relied": [d] + relied})
        rank = ["accepted_before_action", "accepted_execution_cites", "accepted_not_cited", "not_accepted"]
        findings = [c["_finding"] for c in candidates]
        if not candidates or any(c["properties"]["acceptance_unique"] == "FAIL" for c in candidates):
            finding = "not_accepted"
        elif "accepted_after_action" in findings:
            finding = "accepted_after_action"
        else:
            finding = min(findings, key=rank.index)
        out = {"finding": finding,
               "candidates": [{"record_digest": c["record_digest"], "properties": c["properties"]} for c in candidates],
               "receipts": out_receipts}
        if finding != "not_accepted":
            best = [c for c in candidates if c["_finding"] == finding][0]
            out["claim"] = {"contract_ref": contract_ref,
                            "evidence_includes": [{"digest_alg": "SHA-256", "digest": x} for x in best["_relied"]]}
        return out

    # ---- §11.2 ----
    def lifecycle(self) -> dict:
        inp = self.case["inputs"]
        r0 = strict_json(inp["target_record"])
        d0 = jdigest(r0)
        stmts = [strict_json(t) for t in inp["statements"]]
        held = {d0: r0, **{jdigest(s): s for s in stmts}}
        unsigned = lambda r: jcs({k: v for k, v in r.items() if k != "sig"})  # noqa: E731
        st = lambda ok: "PASS" if ok else "FAIL"  # noqa: E731
        r0_issuer = r0["producer"] if verifies(r0["producer"], r0["sig"], unsigned(r0)) else None
        succ = {(e["key"], e["succeeds"]) for e in self.policy["successions"]}

        def successor(key: str, of: str) -> bool:
            seen, frontier = set(), {of}
            while frontier:
                nxt = {k for k, s in succ if s in frontier and k not in seen}
                if key in nxt:
                    return True
                seen |= nxt
                frontier = nxt
            return False

        def form(s: dict) -> bool:
            t = s["link"]["type"]
            need = {"profile", "issuer", "link", "issued_at", "sig"}
            if t in ("amends", "supersedes"):
                need.add("content")
            if t in ("disputes", "resolves"):
                need.add("process")
            if t == "resolves":
                need.add("outcome")
            allowed = need | {"basis", "content"} | ({"scope"} if t != "supersedes" else set())
            return (s["profile"] == PROFILE and bool(HEX64.match(s["issuer"]))
                    and t in ("supersedes", "amends", "rebuts", "disputes", "resolves")
                    and bool(HEX64.match(s["link"]["target"])) and need <= set(s) <= allowed
                    and ("content" not in s or bool(HEX64.match(s["content"]))) and bool(TIME.match(s["issued_at"])))

        def target_status(s: dict) -> str:
            """§11.2.5 lifecycle_target. No vector holds an excluded kind or a resolves statement."""
            tgt = held.get(s["link"]["target"])
            if tgt is None:
                return "NOT_PRESENT"
            if s["link"]["type"] == "resolves":
                return st(tgt.get("link", {}).get("type") == "disputes" and tgt.get("process") == s.get("process"))
            return "PASS"

        res = {}
        for s in stmts:
            d, t = jdigest(s), s["link"]["type"]
            p: dict[str, str] = {"lifecycle_form": st(form(s)),
                                 "lifecycle_signature": st(verifies(s["issuer"], s["sig"], unsigned(s))),
                                 "lifecycle_target": target_status(s)}
            corrective = t in ("amends", "supersedes")
            if p["lifecycle_signature"] != "PASS":
                if corrective:
                    p["lifecycle_issuer"] = "NOT_CHECKED"
                p["lifecycle_signer_trust"] = "NOT_CHECKED"
                if corrective:
                    p["lifecycle_unique"] = "NOT_CHECKED"
            else:
                if corrective:
                    tgt_issuer = r0_issuer if s["link"]["target"] == d0 else None
                    same_party = self.m == "issuer-by-party" and tgt_issuer and \
                        self.party(s["issuer"]) == self.party(tgt_issuer)
                    p["lifecycle_issuer"] = st(tgt_issuer is not None and (
                        s["issuer"] == tgt_issuer or successor(s["issuer"], tgt_issuer) or bool(same_party)))
                p["lifecycle_signer_trust"] = st(self.party(s["issuer"]) is not None)
            res[d] = {"s": s, "p": p}
        for d, e in res.items():
            s, p = e["s"], e["p"]
            if s["link"]["type"] not in ("amends", "supersedes") or "lifecycle_unique" in p:
                continue
            q = lambda x: all(x["p"].get(k) == "PASS" for k in  # noqa: E731
                              ("lifecycle_form", "lifecycle_signature", "lifecycle_target", "lifecycle_issuer",
                               "lifecycle_signer_trust"))
            others = [o for od, o in res.items() if od != d and o["s"]["link"]["type"] in ("amends", "supersedes")
                      and o["s"]["link"]["target"] == s["link"]["target"]]
            if not q(e) or not others:
                p["lifecycle_unique"] = "NOT_CHECKED"
            elif any(q(o) for o in others):
                p["lifecycle_unique"] = "FAIL"
            else:
                p["lifecycle_unique"] = "PASS"
        for e in res.values():
            p, t = e["p"], e["s"]["link"]["type"]
            corrective = t in ("amends", "supersedes")
            if any(p[k] != "PASS" for k in ("lifecycle_form", "lifecycle_signature", "lifecycle_target")):
                f = "lifecycle_not_effective"
            elif corrective and p["lifecycle_issuer"] == "FAIL":
                f = "lifecycle_not_issuer"
            elif (corrective and p["lifecycle_issuer"] != "PASS") or (
                    t in ("amends", "supersedes", "resolves") and p["lifecycle_signer_trust"] != "PASS"):
                f = "lifecycle_not_effective"
            elif p.get("lifecycle_unique") == "FAIL":
                f = "lifecycle_forked"
            else:
                f = "lifecycle_effective"
            e["f"] = f
        chain, contents, forked, branches = [d0], [], None, []
        while True:
            nxt = [(d, e) for d, e in res.items() if e["s"]["link"]["target"] == chain[-1]
                   and e["s"]["link"]["type"] in ("amends", "supersedes")]
            fk = [d for d, e in nxt if e["f"] == "lifecycle_forked"]
            eff = [(d, e) for d, e in nxt if e["f"] == "lifecycle_effective"]
            if fk:
                forked, branches = chain[-1], sorted([[d] for d in fk])
                break
            if not eff:
                break
            chain.append(eff[0][0])
            contents.append(eff[0][1]["s"]["content"])
        def dispute_status(d: str) -> str:
            outcomes = {e["s"]["outcome"] for e in res.values() if e["s"]["link"]["type"] == "resolves"
                        and e["s"]["link"]["target"] == d and e["f"] == "lifecycle_effective"}
            return "open" if not outcomes else outcomes.pop() if len(outcomes) == 1 else "conflicting"

        challenges = []
        for d, e in res.items():
            s = e["s"]
            if s["link"]["type"] in ("disputes", "rebuts") and e["f"] == "lifecycle_effective" \
                    and s["link"]["target"] in chain:
                c = {"statement_digest": d, "type": s["link"]["type"], "issuer": s["issuer"],
                     "on": s["link"]["target"], "lifecycle_signer_trust": e["p"]["lifecycle_signer_trust"],
                     "scope": s.get("scope"), "content": s.get("content")}
                if s["link"]["type"] == "disputes":
                    c["status"] = dispute_status(d)
                challenges.append(c)
        display = {"historical_claim": d0,
                   "latest_supported_state": None if forked else {"element": chain[-1], "contents": contents},
                   "forked_at": forked, "branches": branches, "challenges": challenges}
        return {"target_digest": d0,
                "statements": [{"statement_digest": d, "properties": res[d]["p"], "finding": res[d]["f"]}
                               for d in (jdigest(s) for s in stmts)],
                "display": display}

    # ---- §11.4 ----
    def manifest_form(self, m: Any) -> str:
        allowed = {"profiles", "drafts", "subject_forms", "derivations", "bindings", "refusal_policy", "retention"}
        if not isinstance(m, dict) or not {"profiles", "drafts", "subject_forms", "bindings"} <= set(m):
            return "FAIL"
        for v in m.values():
            if isinstance(v, str):
                continue
            if not (isinstance(v, list) and v and all(isinstance(x, str) for x in v) and v == sorted(set(v))):
                return "FAIL"
        if set(m) - allowed:
            return "FAIL" if set(m["profiles"]) <= set(self.vpolicy["profiles_implemented"]) else "NOT_CHECKED"
        return "PASS"

    def carriage(self) -> dict:
        inp = self.case["inputs"]
        req_octets = self.octets(inp["request"])
        req = self.decode(inp["request"]["media_type"], req_octets)
        mt = inp["request"]["media_type"]
        digests, classes, raw_replies = {}, {}, []
        if "native" in inp:
            sent = bytes.fromhex(inp["native"]["request_frame_hex"])
            digests["native"] = shx(sent)
            frame = bytes.fromhex(inp["native"]["response_frame_hex"])
            try:
                self.reply(mt, frame, req_octets, req)
                classes["native"] = "reply"
                raw_replies.append(frame)
            except (Bad, KeyError, ValueError):
                classes["native"] = "transport_condition"
        if "a2a" in inp:
            msg, task = inp["a2a"]["message"], inp["a2a"]["task"]
            parts = msg["parts"]
            if EXT_URI in msg.get("extensions", []) and len(parts) == 1 and parts[0].get("mediaType") == mt \
                    and "raw" in parts[0] and "taskId" not in msg:  # a request under §11.4.4
                digests["a2a"] = shx(d64(parts[0]["raw"]))
            found = {}
            for a in task.get("artifacts", []):
                if EXT_URI in a.get("extensions", []) and len(a["parts"]) == 1 and \
                        a["parts"][0].get("mediaType") == mt and "raw" in a["parts"][0]:
                    found.setdefault(a["artifactId"], d64(a["parts"][0]["raw"]))
            if found:
                classes["a2a"] = "reply"
                raw_replies += list(found.values())
            elif task["status"]["state"] in ("TASK_STATE_SUBMITTED", "TASK_STATE_WORKING", "TASK_STATE_INPUT_REQUIRED",
                                             "TASK_STATE_AUTH_REQUIRED", "TASK_STATE_UNSPECIFIED"):
                classes["a2a"] = "pending"
            else:
                classes["a2a"] = "refusal" if self.m == "rejected-task-is-refusal" else "transport_condition"
        if "mcp" in inp:
            call, result = inp["mcp"]["call"], inp["mcp"]["result"]
            if call["name"] == "evidence_request" and call["arguments"].get("media_type") == mt:
                digests["mcp"] = shx(d64u(call["arguments"]["request"]))
            sc = result.get("structuredContent") or {}
            if self.m == "is-error-is-transport" and result.get("isError"):
                classes["mcp"] = "transport_condition"
            elif isinstance(sc.get("reply"), str) and sc.get("media_type") == mt:
                classes["mcp"] = "reply"
                raw_replies.append(d64u(sc["reply"]))
            else:
                classes["mcp"] = "transport_condition"
        replies, set_props = self.finish([self.reply(mt, r, req_octets, req) for r in raw_replies])
        out = {"request_digest": shx(req_octets), "carriage_request_digests": digests,
               "classification": classes, "replies": replies}
        if replies:
            out["set_properties"] = set_props
        if "absence_record" in inp:
            out["absence"] = self.absence(self.octets(inp["absence_record"]), req_octets)
        if "manifests" in inp:
            ms = inp["manifests"]
            a2a_m, mcp_m = ms["a2a_extension"]["params"], ms["mcp_evidence_manifest"]["structuredContent"]
            copies = [a2a_m, mcp_m]
            out["manifest_properties"] = {
                "a2a_extension": {"manifest_form": self.manifest_form(a2a_m)},
                "mcp_evidence_manifest": {"manifest_form": self.manifest_form(mcp_m)}}
            if "http_well_known" in ms:
                h = ms["http_well_known"]
                body = self.octets(h["body"])
                http_m = json.loads(body)
                copies.append(http_m)
                form = self.manifest_form(http_m)
                if h["media_type"] != "application/json" or body != jcs(http_m):
                    form = "FAIL"
                out["manifest_properties"]["http_well_known"] = {"manifest_form": form}
            out["manifest_properties"]["manifest_consistency"] = (
                "PASS" if len({jcs(m) for m in copies}) == 1 else "FAIL")
        return out

    # ---- a whole case ----
    def run(self) -> dict:
        cid, inp = self.case["id"], self.case["inputs"]
        if cid.startswith("acceptance-"):
            return self.acceptance()
        if cid.startswith("lifecycle-"):
            return self.lifecycle()
        if cid.startswith("carriage-"):
            return self.carriage()
        reqs = [inp["request"]] if "request" in inp else inp["requests"]
        decoded = [(self.octets(r), self.decode(r["media_type"], self.octets(r))) for r in reqs]
        replies = []
        for i, rep in enumerate(inp["replies"]):
            k = min(i, len(decoded) - 1)
            r = self.reply(rep["media_type"], self.octets(rep), *decoded[k])
            if "requests" in inp:
                r["request_index"] = k
            replies.append(r)
        replies, set_props = self.finish(replies)
        out: dict[str, Any] = {"replies": replies}
        if any(r["message_type"] == "envelope" for r in replies):
            out["set_properties"] = set_props
        if "request" in inp:
            out["request_digest"] = shx(decoded[0][0])
        else:
            out["request_digests"] = [shx(o) for o, _ in decoded]
        if "absence_record" in inp:
            out["absence"] = self.absence(self.octets(inp["absence_record"]), decoded[0][0])
        return out


def project(expected: dict) -> dict:
    """Reduce an expected block to what the evaluator derives: rows, not the row's status triple."""
    e = copy.deepcopy(expected)

    def strip_reqs(block: dict) -> None:
        if "requirements" in block:
            block["requirements"] = {k: {"row": v["row"]} for k, v in block["requirements"].items()}
        block.pop("presentation_kinds_allowed", None)
        block.pop("presentation_kind_recommended", None)

    for r in e.get("replies", []):
        strip_reqs(r)
    if "absence" in e:
        strip_reqs(e["absence"])
    for s in e.get("statements", []):
        s.pop("name", None)
    for k in ("artifact_digest", "artifact_octets_identical"):
        e.pop(k, None)
    return e


def derived(case: dict, mutant: str | None = None) -> dict:
    return Verifier(case, mutant).run()


# ---------------------------------------------------------------------------
# The statuses
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["id"])
def test_expected_statuses_are_derived_from_the_inputs(case):
    assert derived(case) == project(case["expected"])


# Each mutant is a plausible verifier defect; at least one case must expose it.
MUTANTS = {
    "version-ignored": f"checks an envelope under {V} rules whatever profile it names (§3.3 step 5)",
    "binding-skipped": "never compares request_digest with the retained request octets (§7.2)",
    "invariance-ignored": "does not apply §8.1 row 1 when caller_invariance FAILs",
    "is-check-as-supports": "maps a failed native check under the requirement that IS it to row 6",
    "supports-as-is-check": "maps a failed native check under a requirement it SUPPORTS to row 5 (met/not_met)",
    "refusal-trust-skipped": "accepts a refusal under any key that signs it (§7.2 responder_trust)",
    "ordering-trusts-issued_at": "grants acceptance ordering from the acceptor's own issued_at (§11.1.5)",
    "issuer-by-party": "treats a key mapped to the issuer's party as the issuer (§11.2.3)",
    "rejected-task-is-refusal": "reads TASK_STATE_REJECTED as a refusal (§11.4.4)",
    "is-error-is-transport": "classifies by MCP isError instead of the reply octets (§11.4.5)",
    "absence-key-id-unsigned": "checks an absence record's sig over the refusal's signing input, key_id left out (§6.4)",
}
if VERSION >= 1:
    MUTANTS["reasons-of-the-latest"] = ("checks every refusal against the newest identifier's tokens, whatever "
                                        "its request asks for (§6.3, §9.1)")


@pytest.mark.parametrize("mutant", sorted(MUTANTS))
def test_corpus_catches_mutant_verifier(mutant):
    caught = [case["id"] for case in CASES if derived(case, mutant) != project(case["expected"])]
    assert caught, f"mutant {mutant!r} ({MUTANTS[mutant]}) survived every vector"


# ---------------------------------------------------------------------------
# The §8.2 invariants: the verdict pairs with the sufficiency (invariant 1), and the rest
# ---------------------------------------------------------------------------


def requirement_blocks(corpus: dict):
    for case in corpus["cases"]:
        exp = case["expected"]
        for r in exp.get("replies", []):
            for name, block in r.get("requirements", {}).items():
                yield case["id"], name, block, r
        if "absence" in exp:
            for name, block in exp["absence"]["requirements"].items():
                yield case["id"], name, block, exp["absence"]


VERDICTS = ("met", "not_met", "out_of_scope", "not_evaluable")


def invariant_violations(corpus: dict) -> list[str]:
    bad = []
    for cid, name, b, holder in requirement_blocks(corpus):
        where = f"{cid}/{name}"
        verdict, sufficiency = b["verdict"], b["sufficiency"]
        if verdict not in VERDICTS:
            bad.append(f"{where}: {verdict!r} is not a verdict")
        elif sufficiency == "SATISFIED" and verdict == "not_evaluable":
            bad.append(f"{where}: not_evaluable with sufficiency SATISFIED")
        elif sufficiency != "SATISFIED" and verdict != "not_evaluable":
            bad.append(f"{where}: {verdict} with sufficiency {sufficiency}")
        if verdict == "out_of_scope" and b.get("out_of_scope_allowed") is not True:
            bad.append(f"{where}: out_of_scope on a requirement without the switch")
        if "out_of_scope_allowed" in b and b["out_of_scope_allowed"] is not True:
            bad.append(f"{where}: out_of_scope_allowed is true or absent")
        if b["status"] is not None and PROJECTION.get(b["status"]) != sufficiency:
            bad.append(f"{where}: status {b['status']} does not project to {sufficiency}")
        if None in (b["status"], b["sufficiency"], b["verdict"]):
            bad.append(f"{where}: an empty result; a requirement the verifier cannot apply is UNKNOWN (§11.3.7)")
        if b["status"] in ("WITHHELD", "NOT_COMMITTED") and "disclosure" in holder.get(
                "presentation_kinds_allowed", ["disclosure"]):
            bad.append(f"{where}: {b['status']} may be shown as disclosure")
    return bad


ROW_TRIPLES = {
    "envelope-1": ("CONTRADICTED", "GAP", "not_evaluable"),
    "envelope-2": ("INSUFFICIENT", "INSUFFICIENT", "not_evaluable"),
    "envelope-3": ("INSUFFICIENT", "INSUFFICIENT", "not_evaluable"),
    "envelope-4": ("UNKNOWN", "UNKNOWN", "not_evaluable"),
    "envelope-5": ("SATISFIED", "SATISFIED", "not_met"),
    "envelope-6": ("INSUFFICIENT", "INSUFFICIENT", "not_evaluable"),
    "envelope-7": ("UNKNOWN", "UNKNOWN", "not_evaluable"),  # no content evaluator (§11.3.7)
    "refusal-no_such_subject": ("NOT_FOUND", "GAP", "not_evaluable"),
    "refusal-withheld": ("WITHHELD", "GAP", "not_evaluable"),
    "refusal-deadline_or_malformed": ("UNKNOWN", "UNKNOWN", "not_evaluable"),
    "refusal-capacity_exceeded": ("UNKNOWN", "UNKNOWN", "not_evaluable"),  # v1
    "refusal-request_unauthenticated": ("UNKNOWN", "UNKNOWN", "not_evaluable"),  # v1
    "refusal-failed": ("UNKNOWN", "UNKNOWN", "not_evaluable"),
    "absence": ("UNKNOWN", "UNKNOWN", "not_evaluable"),
}


def test_every_vector_verdict_pairs_with_its_sufficiency():
    assert invariant_violations(DATA) == []
    blocks = list(requirement_blocks(DATA))
    assert any(b["verdict"] == "not_met" for _, _, b, _ in blocks), "row 5 is exercised"
    for cid, name, b, _ in blocks:
        assert (b["status"], b["sufficiency"], b["verdict"]) == ROW_TRIPLES[b["row"]], f"{cid}/{name}"


@pytest.mark.parametrize("mutation", ["row-6-not-met", "row-2-met", "withheld-as-disclosure", "row-7-met",
                                      "row-7-null", "row-5-not-evaluable", "row-5-unknown-verdict",
                                      "row-5-out-of-scope-without-switch", "gap-out-of-scope",
                                      "switch-false"])
def test_invariant_check_catches_its_mutant(mutation):
    corpus = copy.deepcopy(DATA)
    for _, _, b, holder in requirement_blocks(corpus):
        if mutation == "row-6-not-met" and b["row"] == "envelope-6":
            b["verdict"] = "not_met"
        elif mutation == "row-2-met" and b["row"] == "envelope-2":
            b["verdict"] = "met"
        elif mutation == "withheld-as-disclosure" and b["status"] == "WITHHELD":
            holder["presentation_kinds_allowed"] = ["analysis", "disclosure", "story"]
        elif mutation == "row-7-met" and b["row"] == "envelope-7":
            b["verdict"] = "met"
        elif mutation == "row-7-null" and b["row"] == "envelope-7":
            b["status"] = b["sufficiency"] = b["verdict"] = None
        elif mutation == "row-5-not-evaluable" and b["row"] == "envelope-5":
            b["verdict"] = "not_evaluable"
        elif mutation == "row-5-unknown-verdict" and b["row"] == "envelope-5":
            b["verdict"] = "passed"
        elif mutation == "row-5-out-of-scope-without-switch" and b["row"] == "envelope-5":
            b["verdict"] = "out_of_scope"
        elif mutation == "gap-out-of-scope" and b["sufficiency"] == "GAP":
            b["verdict"] = "out_of_scope"
            b["out_of_scope_allowed"] = True
        elif mutation == "switch-false" and b["row"] == "envelope-5":
            b["out_of_scope_allowed"] = False
    assert invariant_violations(corpus), f"invariant check missed {mutation}"


# ---------------------------------------------------------------------------
# Pins and encodings
# ---------------------------------------------------------------------------


def test_test_keys_derive_from_their_stated_seeds():
    for name, k in DATA["test_keys"]["keys"].items():
        if name == "small-order":  # the identity point: a public key with no private key (§5.2)
            assert k["public"] == "01" + "00" * 31
            continue
        priv = Ed25519PrivateKey.from_private_bytes(sha(k["seed_label"].encode()))
        assert priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex() == k["public"], name
    assert "TEST-ONLY" in DATA["test_keys"]["note"]


def test_contract_pin_shape():
    """The contract's digest, reference and requirement shape, and that the recorded schema SHA-256
    is the profile's EC pin. Validation against the schema itself needs the schema file, which
    this repository does not carry."""
    c = DATA["contract"]
    assert jcs(c["document"]).decode() == c["document_jcs"]
    assert shx(c["document_jcs"].encode()) == c["contract_digest"]
    assert c["contract_ref"] == f"{c['document']['id']}@{c['document']['version']}"
    assert HEX64.match(c["schema"]["sha256"]) and c["schema"]["name"] == "evidence-contract-v0.json"
    ec_row = next(line for line in SPEC.read_text(encoding="utf-8")
                  .splitlines() if line.startswith("| EC |"))
    assert c["schema"]["sha256"] in ec_row, "the recorded schema is the one the profile pins as EC"
    for r in c["document"]["requirements"]:
        assert {"id", "profile", "statement"} <= set(r) and "status" not in r and "result" not in r


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["id"])
def test_every_case_pins_policy_contract_time_and_cites(case):
    p = case["pins"]
    assert set(p) == {"trust_policy", "verification_policy", "contract_ref", "contract_digest", "evaluation_time"}
    assert p["contract_digest"] == DATA["contract"]["contract_digest"]
    assert p["contract_ref"] == DATA["contract"]["contract_ref"]
    assert TIME.match(p["evaluation_time"])
    assert case["cites"] and all(c.startswith(("§", "P-")) for c in case["cites"])
    known = {k["public"] for k in DATA["test_keys"]["keys"].values()}
    pol = p["trust_policy"]
    keys = set(pol["responder_keys"]) | set(pol["foreign_keys"]) | set(pol["parties"]) | {
        e["kid"] for e in pol["log_keys"]} | {k for e in pol["successions"] for k in (e["key"], e["succeeds"])}
    assert keys <= known, "every trusted key is a stated test key"


def test_section_10_1_bytes_are_reused():
    profile = SPEC.read_text(encoding="utf-8")
    valid = next(c for c in CASES if c["id"] == "valid-exchange")
    assert valid["inputs"]["request"]["octets_text"] in profile
    env = strict_json(valid["inputs"]["replies"][0]["octets_text"])
    assert env["sig"] in profile
    assert all(t in profile for t in env["verification_content"])
    assert DATA["logs"]["log-1"]["checkpoint_hex"] in profile


def test_invariance_case_shape():
    case = next(c for c in CASES if c["id"] == "invariance-two-nonces-two-transports")
    reqs = [Verifier.octets(r) for r in case["inputs"]["requests"]]
    assert {r["media_type"] for r in case["inputs"]["requests"]} == {"application/json", "application/cbor"}
    envs = [Verifier.decode(r["media_type"], Verifier.octets(r)) for r in case["inputs"]["replies"]]
    assert {r["carriage"] for r in case["inputs"]["replies"]} == {"http", "evidence-request/1"}
    assert envs[0]["artifact"] == envs[1]["artifact"]
    assert shx(envs[0]["artifact"]) == case["expected"]["artifact_digest"] == envs[1]["artifact_digest"]
    assert envs[0]["request_digest"] != envs[1]["request_digest"] and envs[0]["sig"] != envs[1]["sig"]
    assert [shx(r) for r in reqs] == case["expected"]["request_digests"]
    assert Verifier.decode("application/json", reqs[0])["nonce"] != dec1(reqs[1])["nonce"]


def test_carriage_moves_one_octet_string():
    case = next(c for c in CASES if c["id"] == "carriage-invariance")
    r = Verifier.octets(case["inputs"]["request"])
    assert dec1(r)["subject"] == {"record": DATA["logs"]["log-1"]["entries"][2]}
    raw = case["inputs"]["a2a"]["message"]["parts"][0]["raw"]
    assert d64(raw) == r and d64u(case["inputs"]["mcp"]["call"]["arguments"]["request"]) == r
    assert bytes.fromhex(case["inputs"]["native"]["request_frame_hex"]) == r


# ---------------------------------------------------------------------------
# Reproducibility and registration
# ---------------------------------------------------------------------------


def _generate(out: Path, set_name: str) -> None:
    for name in HAND_WRITTEN:
        shutil.copyfile(SETS[set_name][0] / name, out / name)
    subprocess.run([sys.executable, str(GENERATOR), "--set", set_name, "--profile", str(VERSION), "--out", str(out)],
                   check=True)


@pytest.mark.parametrize("set_name", sorted(SETS))
def test_generator_is_deterministic_and_reproduces_every_file(tmp_path, set_name):
    vectors = SETS[set_name][0]
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    _generate(a, set_name)
    _generate(b, set_name)
    committed = sorted(p.name for p in vectors.iterdir() if p.is_file())
    assert committed == sorted(p.name for p in a.iterdir()) == sorted(p.name for p in b.iterdir())
    for name in committed:
        assert (a / name).read_bytes() == (b / name).read_bytes() == (vectors / name).read_bytes(), name


@pytest.mark.parametrize("set_name", sorted(SETS))
def test_sha256sums_and_registration(set_name):
    vectors, key = SETS[set_name]
    listed = dict(reversed(line.split("  ", 1)) for line in (vectors / "SHA256SUMS").read_text().splitlines())
    on_disk = {p.name for p in vectors.iterdir() if p.is_file() and p.name != "SHA256SUMS"}
    assert set(listed) == on_disk
    for name, digest in listed.items():
        assert shx((vectors / name).read_bytes()) == digest, name
    top = dict(reversed(line.split("  ", 1)) for line in (ROOT / "vectors" / "SHA256SUMS").read_text().splitlines())
    for name in on_disk:
        assert top.get(f"{vectors.name}/{name}") == listed[name], name
    corpora = json.loads((ROOT / "vectors" / "manifest.json").read_text(encoding="utf-8"))["corpora"]
    assert corpora[key] == f"{vectors.name}/manifest.json"
    data = json.loads((vectors / "vectors.json").read_text(encoding="utf-8"))
    assert data["count"] == len(data["cases"])
    manifest = json.loads((vectors / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["files"] == [{"path": "vectors.json", "sha256": listed["vectors.json"],
                                  "count": len(data["cases"])}]
