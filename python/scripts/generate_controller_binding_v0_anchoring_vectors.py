#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate the controller binding vectors for revocation against an attested time
(``spec/controller-binding-v0.md`` §5.2 and §10.1, cited as CB).

Each case is a pair of agreeing halves under two bound keys, as in ``vectors/controller-binding-v0/``,
with one binding of the two keys, a revocation statement by a bound key, **stamps** (time
attestations over the halves) and **anchors** (time attestations over the statement). CB §10.1
lists the cases:

- a statement dated before the halves and anchored after their stamps (it does not count), before
  them (it counts) and at their time (it counts: anchor <= the stamp);
- a statement dated after the halves were signed but before they were stamped, and anchored before
  the stamps: it does not count, as CB §5 alone would not count it;
- a statement with no anchor, against stamped halves (it counts at no attested T), against
  unstamped halves (CB §5 applies unchanged) and against one stamped half and one not;
- a statement anchored before the stamps but dated after them;
- two anchors, of which the earliest counts, and two stamps per half, of which the earliest counts;
- attestations that are not anchors or stamps: by a bound key, by a key the using profile does not
  accept, forged, over another statement, and stamps dated after the evaluation time;
- a list declared complete (CB §5.1) holding the statement, unanchored and anchored, against
  stamped halves.

It states every expected status by hand from CB §5.2, §6 and §7. Nothing here imports or runs a
verifier. The time attestation and its method are fixed for these vectors only and are not
registered (CB §10.1, CB-10).

Output: ``vectors/controller-binding-v0-anchoring/`` (or ``--out DIR``). Deterministic: no clock,
no randomness. ``README.md`` is never rewritten; every file in the directory is listed in
``SHA256SUMS``. Dependencies: the standard library, ``cryptography`` (Ed25519) and the generators
beside this script, for their encodings, keys, halves, binding records and revocation statements.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import generate_controller_binding_v0_vectors as base
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from generate_coverage_declaration_v0_vectors import half
from generate_interop_profile_v0_vectors import jcs, sha, shx

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "vectors" / "controller-binding-v0-anchoring"
SET = "aac-controller-binding-v0-anchoring"
SPEC = "spec/controller-binding-v0.md"
STATUS = ("Conformance vectors for revocation against a time a third party attests in the informational "
          "Controller Binding v0 (spec/controller-binding-v0.md §5.2, §10.1). Every key is a test key derived "
          "from a public seed; never use one for anything else.")

TIME_ATTESTER_LABEL = "controller-binding-v0 anchoring vectors: time attester key"
PRIV = dict(base.PRIV)
PRIV["time-attester"] = Ed25519PrivateKey.from_private_bytes(sha(TIME_ATTESTER_LABEL.encode()))
PUB = dict(base.PUB)
PUB["time-attester"] = PRIV["time-attester"].public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

ATTESTATION_METHOD = ("Ed25519 by attester over UTF-8 of JCS of the time attestation's other members "
                      "(controller-binding-v0 §10.1, vectors only)")
TIMES_ASKED = ("each half's T is its issued_at (CB §6.1); its attested time is the attested_at of its earliest "
               "stamp that counts (CB §5.2), or none")

# The halves are signed at base.HALF_TIMES (2026-10-15T00:00:20Z and :21Z), inside the window.
STAMP_AT = "2026-10-15T00:05:00Z"      # the stamps over the halves: each half's attested T
REVOKED_EARLY = "2026-10-12T00:00:00Z"  # revoked_at, before both halves
ANCHOR_BEFORE = "2026-10-13T00:00:00Z"  # an anchor before the stamps
ANCHOR_AFTER = "2026-10-16T00:00:00Z"   # an anchor after the stamps
REVOKED_LATE = "2026-10-15T01:00:00Z"   # revoked_at, after the stamps
REVOKED_BETWEEN = "2026-10-15T00:01:00Z"  # revoked_at, after the halves were signed, before the stamps
ANCHOR_BETWEEN = "2026-10-15T00:02:00Z"  # an anchor after the halves were signed, before the stamps
STAMP_LATER = "2026-10-17T00:00:00Z"    # a second, later stamp over each half
STAMP_FUTURE = "2026-10-20T00:00:00Z"   # a stamp dated after the evaluation time


def halves() -> list[dict]:
    return [half(base.CLAIM, base.HALF_TIMES[0], "producer-a"), half(base.CLAIM, base.HALF_TIMES[1], "producer-b")]


def attestation(subject_octets: str, attested_at: str, *, attester: str = "time-attester",
                signer: str | None = None, subject: str | None = None) -> dict:
    """CB §10.1's time attestation over ``subject_octets``, naming ``attester`` and signed by
    ``signer`` (default: the attester). ``subject`` replaces the digest."""
    body = {"attested_at": attested_at, "attester": PUB[attester],
            "subject": subject or shx(subject_octets.encode())}
    return base.octets(dict(body, sig=PRIV[signer or attester].sign(jcs(body).encode()).hex()))


def pins(also_accepted: str | None = None) -> dict:
    """The pins of ``vectors/controller-binding-v0/``, plus the time attesters the using profile
    accepts: the time attester key, and ``also_accepted`` where a case needs a bound key accepted
    too, so that only the bound-key rule of CB §5.2 refuses its attestation."""
    p = base.pins()
    p["trust_policy"]["time_attesters"] = sorted([PUB["time-attester"]] + ([PUB[also_accepted]] if also_accepted else []))
    p["verification_policy"]["attestation_methods_implemented"] = [ATTESTATION_METHOD]
    p["times_asked"] = TIMES_ASKED
    return p


def case(cid: str, title: str, cites: list[str], *, counts: bool, counted_from: str | None,
         times: list[tuple[str, str | None]], revocations: list[dict] | None = None,
         stamps: list[dict] | None = None, anchors: list[dict] | None = None,
         revocation_list: dict | None = None, list_counts: bool | None = None, record: dict,
         also_accepted: str | None = None) -> dict:
    """A case over the binding ``record`` of the two halves' keys. ``counts`` is whether a statement
    counts at some T (CB §5.2), so that revocation is ``FAIL``; ``times`` is each half's attested
    time and its attester, or (None, None)."""
    if counts:
        status = "FAIL"
    elif revocation_list is not None and list_counts:
        status = "PASS"
    else:
        status = "NOT_CHECKED"
    applies = not counts
    c = base.case(cid, title, cites, record, base.ok(controller_binding_revocation=status), binds_pair=True,
                  applies=applies, independence="FAIL" if applies else "NOT_CHECKED",
                  reason=base.by_binding(record) if applies else None, revocations=revocations,
                  revocation_list=revocation_list, list_counts=list_counts,
                  fails=[] if applies else ["controller_binding_revocation"])
    c["source"] = ("derived: two producer records (IP §11.5), a binding record (CB §3), a revocation statement "
                   "(CB §5) and time attestations (CB §10.1)")
    c["pins"] = pins(also_accepted)
    if stamps is not None:
        c["inputs"]["stamps"] = stamps
    if anchors is not None:
        c["inputs"]["anchors"] = anchors
    c["expected"]["binding"]["times"] = [{"t": t, "attested_at": at, "attested_by": by}
                                         for t, (at, by) in zip(base.HALF_TIMES, times)]
    c["expected"]["binding"]["revocation_counted_from"] = counted_from
    return c


def cases() -> list[dict]:
    ab = ("producer-a", "producer-b")
    r = base.binding("same_controller_asserted", ab)
    hs = halves()
    early = base.revocation(r, "producer-b", REVOKED_EARLY)
    early_text = jcs(early)
    attester = PUB["time-attester"]
    stamped = [attestation(h["octets_text"], STAMP_AT) for h in hs]
    at_stamp = [(STAMP_AT, attester), (STAMP_AT, attester)]
    at_issued = [(None, None), (None, None)]
    cites = ["CB §5", "CB §5.2", "CB §6.1", "CB §6.2", "CB §7", "IP §6.7.4"]
    out = []

    def add(cid: str, title: str, **kw: Any) -> None:
        kw.setdefault("revocations", [early])
        out.append(case(cid, title, kw.pop("cites", cites), record=r, **kw))

    add("anchored-after-the-stamp",
        "A revocation dated before the halves, first anchored after their stamps: it does not count",
        counts=False, counted_from=None, times=at_stamp, stamps=stamped,
        anchors=[attestation(early_text, ANCHOR_AFTER)])

    add("anchored-before-the-stamp",
        "A revocation dated before the halves and anchored before their stamps: it counts",
        counts=True, counted_from=ANCHOR_BEFORE, times=at_stamp, stamps=stamped,
        anchors=[attestation(early_text, ANCHOR_BEFORE)])

    add("anchored-at-the-stamp", "A revocation anchored at the stamps' own time: anchored time <= T, it counts",
        counts=True, counted_from=STAMP_AT, times=at_stamp, stamps=stamped,
        anchors=[attestation(early_text, STAMP_AT)])

    add("not-anchored-stamped", "A revocation dated before the halves with no anchor, against stamped halves",
        counts=False, counted_from=None, times=at_stamp, stamps=stamped)

    add("not-anchored-not-stamped",
        "The same revocation with no anchor and no stamps: no T is attested, and CB §5 applies unchanged",
        counts=True, counted_from=REVOKED_EARLY, times=at_issued)

    add("one-half-stamped",
        "No anchor, the first half stamped and the second not: the statement counts at the second half's issued_at",
        counts=True, counted_from=REVOKED_EARLY, times=[(STAMP_AT, attester), (None, None)],
        stamps=stamped[:1])

    late = base.revocation(r, "producer-b", REVOKED_LATE)
    add("revoked-at-after-the-stamp",
        "A revocation anchored before the stamps but dated after them: the anchored time is its revoked_at",
        counts=False, counted_from=None, times=at_stamp, stamps=stamped, revocations=[late],
        anchors=[attestation(jcs(late), ANCHOR_BEFORE)])

    between = base.revocation(r, "producer-b", REVOKED_BETWEEN)
    add("revoked-between-signing-and-stamp",
        "A revocation dated after the halves were signed and before they were stamped, anchored before the stamps",
        counts=False, counted_from=None, times=at_stamp, stamps=stamped, revocations=[between],
        anchors=[attestation(jcs(between), ANCHOR_BETWEEN)])

    add("earliest-anchor-counts", "Two anchors, one after the stamps and one before: the earliest counts",
        counts=True, counted_from=ANCHOR_BEFORE, times=at_stamp, stamps=stamped,
        anchors=[attestation(early_text, ANCHOR_AFTER), attestation(early_text, ANCHOR_BEFORE)])

    add("anchor-by-bound-key",
        "An anchor before the stamps, attested by a bound key the using profile also accepts: not an anchor",
        counts=False, counted_from=None, times=at_stamp, stamps=stamped, also_accepted="producer-a",
        anchors=[attestation(early_text, ANCHOR_BEFORE, attester="producer-a")])

    add("anchor-attester-not-accepted",
        "An anchor before the stamps, attested by a key the using profile does not accept: not an anchor",
        counts=False, counted_from=None, times=at_stamp, stamps=stamped,
        anchors=[attestation(early_text, ANCHOR_BEFORE, attester="other-issuer")])

    add("anchor-forged",
        "An anchor before the stamps that names the accepted attester and is signed by another key: not an anchor",
        counts=False, counted_from=None, times=at_stamp, stamps=stamped,
        anchors=[attestation(early_text, ANCHOR_BEFORE, signer="other-issuer")])

    other = base.revocation(r, "producer-a", REVOKED_EARLY)
    add("anchor-other-statement",
        "An anchor before the stamps over another statement's octets: not an anchor for this one",
        counts=False, counted_from=None, times=at_stamp, stamps=stamped,
        anchors=[attestation(jcs(other), ANCHOR_BEFORE)])

    add("stamp-by-bound-key",
        "The halves' stamps are attested by a bound key the using profile also accepts: no T is attested",
        counts=True, counted_from=REVOKED_EARLY, times=at_issued, also_accepted="producer-b",
        stamps=[attestation(h["octets_text"], STAMP_AT, attester="producer-b") for h in hs])

    add("earliest-stamp-counts",
        "Two stamps over each half, before and after the statement's only anchor: the earliest stamp counts",
        counts=False, counted_from=None, times=at_stamp,
        stamps=stamped + [attestation(h["octets_text"], STAMP_LATER) for h in hs],
        anchors=[attestation(early_text, ANCHOR_AFTER)])

    add("stamp-after-evaluation-time",
        "The halves' stamps are dated after the evaluation time: no T is attested, and CB §5 applies unchanged",
        counts=True, counted_from=REVOKED_EARLY, times=at_issued,
        stamps=[attestation(h["octets_text"], STAMP_FUTURE) for h in hs])

    add("complete-list-entry-anchored",
        "Stamped halves and a list declared complete that holds the statement, anchored before the stamps",
        cites=["CB §5.1", *cites], counts=True, counted_from=ANCHOR_BEFORE, times=at_stamp, stamps=stamped,
        revocations=None, revocation_list=base.declared(r, [early]), list_counts=True,
        anchors=[attestation(early_text, ANCHOR_BEFORE)])

    add("complete-list-entry-not-anchored",
        "Stamped halves and a list declared complete that holds the unanchored statement: it does not count",
        cites=["CB §5.1", *cites], counts=False, counted_from=None, times=at_stamp, stamps=stamped,
        revocations=None, revocation_list=base.declared(r, [early]), list_counts=True)
    return out


def _dump(value: Any) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def build() -> dict[str, bytes]:
    all_cases = cases()
    ids = [c["id"] for c in all_cases]
    assert len(ids) == len(set(ids)), "duplicate case id"
    labels = {**base.coverage_vectors.SEED_LABELS, **base.SEED_LABELS, "time-attester": TIME_ATTESTER_LABEL}
    names = ("producer-a", "producer-b", "other-issuer", "time-attester")
    corpus = {
        "set": SET,
        "status": STATUS,
        "profile": base.PROFILE,
        "spec": SPEC,
        "test_keys": {
            "note": "TEST-ONLY. Each private key is the 32-byte Ed25519 seed SHA-256(seed_label).",
            "keys": {name: {"seed_label": labels[name], "public": PUB[name]} for name in names},
        },
        "contract": {"document": base.CONTRACT, "document_jcs": jcs(base.CONTRACT),
                     "contract_ref": base.CONTRACT_REF, "contract_digest": base.CONTRACT_DIGEST,
                     "schema": base.EC_SCHEMA},
        "attestation_method": ATTESTATION_METHOD,
        "binding_properties": base.BINDING_PROPS,
        "count": len(all_cases),
        "cases": all_cases,
    }
    files = {"vectors.json": _dump(corpus)}
    files["manifest.json"] = _dump({
        "set": SET,
        "status": STATUS,
        "spec": SPEC,
        "generator": "python/scripts/generate_controller_binding_v0_anchoring_vectors.py",
        "files": [{"path": name, "sha256": shx(data), "count": json.loads(data).get("count")}
                  for name, data in sorted(files.items())],
    })
    return files


def write(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for name, data in build().items():
        (out / name).write_bytes(data)
    files = sorted((p.relative_to(out).as_posix(), p) for p in out.rglob("*") if p.is_file())
    lines = [f"{shx(p.read_bytes())}  {rel}" for rel, p in files if rel != "SHA256SUMS"]
    (out / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    write(args.out)


if __name__ == "__main__":
    main()
