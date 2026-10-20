#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate the Evidence Bundle -02 certificate vectors.

Two directories, both read by strict ``verify_bundle`` exactly as
``vectors/bundle/strict/`` is:

- ``vectors/bundle/non-record-leaves/``: a range over a log whose leaves include
  padding records, carried in ``completeness_certificate.non_record_leaves``;
- ``vectors/bundle/certificate-mode/``: the producer-selected certificate in the
  shape producers already emit, and ``completeness.selection`` values that name
  a certificate mode the verifier does not implement.

Every expected result below is written by hand, per case, from the rules in
each directory's README; nothing here runs a verifier. The literal Bundles are
built with the strict generator's records, keys and checkpoint signer, so the
output is a pure function of the two scripts. The READMEs are hand-written and
never rewritten here.

Dependencies: ``agent-action-capsule[bundle,envelope]`` and ``cryptography``.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import sys
from pathlib import Path
from typing import Any

from cll.checkpoint import (
    CheckpointRecord,
    MemoryNodeStore,
    add_leaf,
    checkpoint_to_cose,
    core,
    leaf_hash,
    peaks,
    root_from_peaks,
)

sys.path.insert(0, str(Path(__file__).resolve().parent))
import generate_bundle_strict_vectors as strict  # noqa: E402

from agent_action_capsule.canonical import jcs  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "vectors" / "bundle"
LOG_ID = "log:bundle-02-vectors"

# The layout checked on a real padded log (pad bucket 32): 5 records, 27
# padding, 3 records, 29 padding. The checkpoint tip, seq 64, is padding.
LAYOUT = [("record", 5), ("padding", 27), ("record", 3), ("padding", 29)]

claims, claim, case, records_expect, ABSENT, UNANCHORED = (
    strict.claims, strict.claim, strict.case, strict.records_expect, strict.ABSENT, strict.UNANCHORED,
)


def digest(value: Any) -> str:
    return hashlib.sha256(jcs(value)).hexdigest()


def padding(label: str) -> dict:
    """A padding record in the four-member serialization. The nonce is a
    fixed value derived from ``label`` so the run is reproducible."""
    body = {
        "record_type": "padding",
        "epistemic_type": "producer_claim",
        "store_nonce": hashlib.sha256(f"bundle-02 padding {label}".encode()).hexdigest(),
    }
    return {"capsule_id": digest(body), **body}


def padded_log() -> list[tuple[str, dict]]:
    leaves: list[tuple[str, dict]] = []
    for kind, count in LAYOUT:
        for _ in range(count):
            seq = len(leaves) + 1
            if kind == "record":
                leaves.append((kind, strict.signed(strict.capsule(f"padded-{seq}"))))
            else:
                leaves.append((kind, padding(str(seq))))
    return leaves


def bundle_over_log(leaves: list[tuple[str, dict]], first_seq: int | None) -> dict:
    """A Bundle over the whole log ``leaves`` with a signed COSE checkpoint at
    its tip. ``first_seq`` starts a range ending at the tip, carrying every
    record of it and every padding leaf in ``non_record_leaves``; ``None``
    builds the producer-selected Bundle of every record, in the shape a
    producer already emits (``payloads_mode`` ``none``, no range)."""
    store = MemoryNodeStore()
    for _, item in leaves:
        add_leaf(store, leaf_hash(bytes.fromhex(item["capsule_id"])))
    size = store.size()
    peak_hashes = [store.node(p) for p in peaks(size)]
    root = root_from_peaks(peak_hashes).hex()
    signer = strict._StatementSigner(strict.LOG_KEY)
    cp = CheckpointRecord(
        v=1, kind="mmr_checkpoint", log_id=LOG_ID, mmr_size=size, root=root, prev_size=0, prev_root="",
        key_id=signer.key_id, timestamp=strict.TIMESTAMP, signature="",
    )
    checkpoint = {
        "log_id": LOG_ID, "mmr_size": size, "root": root, "prev_size": 0, "prev_root": "",
        "key_id": signer.key_id, "timestamp": strict.TIMESTAMP,
        "cose": strict.b64u(checkpoint_to_cose(cp, signer, peak_hashes)),
    }
    tip = len(leaves)
    start = first_seq or 1
    carried = [(seq, item) for seq, (kind, item) in enumerate(leaves, 1) if kind == "record" and seq >= start]
    certificate: dict[str, Any] = {"log_id": LOG_ID, "range_root": root}
    if first_seq is not None:
        rp = core.range_proof(store, first_seq - 1, tip - 1, size)
        certificate.update({
            "first_seq": first_seq,
            "last_seq": tip,
            "body_digests": [item["capsule_id"] for _, item in leaves[first_seq - 1:]],
            "range_proof": {
                "from_seq": first_seq, "to_seq": tip, "size": rp.size, "from_index": rp.from_index,
                "to_index": rp.to_index, "witness": list(rp.witness),
            },
        })
    certificate["memberships"] = {
        item["capsule_id"]: {
            "log_coordinates": {"log_id": LOG_ID, "seq": seq, "leaf_index": seq - 1},
            "inclusion_proof": strict.proof_dict(core.inclusion_proof(store, seq - 1, size)),
        }
        for seq, item in carried
    }
    if first_seq is not None:
        certificate["non_record_leaves"] = [
            {"seq": seq, "content": copy.deepcopy(item)}
            for seq, (kind, item) in enumerate(leaves, 1)
            if kind == "padding" and seq >= first_seq
        ]
    completeness = {
        "closure_depth": 0, "records_mode": "complete", "payloads_mode": "selected", "suppressed_fields": [],
        "missing": [],
    }
    if first_seq is None:
        completeness.update(selection="producer-selected", payloads_mode="none")
    return {
        "bundle_version": "2",
        "bundle_kind": "evidence-bundle/v2",
        "root": carried[-1][1]["capsule_id"],
        "records": [item for _, item in carried],
        "completeness": completeness,
        "completeness_certificate": certificate,
        "checkpoint": checkpoint,
    }


def expect(bundle: dict, verdict: str, **overrides: Any) -> dict:
    return {
        "verdict": verdict, "claims": claims(**overrides), "witnesses": ABSENT, "records": records_expect(bundle),
        "checkpoint_authenticated": True, "signer_matches_checkpoint": False,
    }


def leaf_cases() -> list[dict]:
    log = padded_log()
    whole = bundle_over_log(log, 1)
    suffix = bundle_over_log(log, 6)
    cases = [
        case("pos-padded-whole-log",
             "The whole 64-leaf log (5 records, 27 padding, 3 records, 29 padding): every padding leaf is carried in "
             "full and recomputes to its body digest.", whole, expect(whole, "VALID")),
        case("pos-padded-suffix",
             "The suffix [6, 64]: it starts on a padding leaf and ends on the padding tip.", suffix,
             expect(suffix, "VALID")),
    ]
    leaves = whole["completeness_certificate"]["non_record_leaves"]
    index_of = {element["seq"]: i for i, element in enumerate(leaves)}

    def edited(edit: Any) -> dict:
        bundle = copy.deepcopy(whole)
        edit(bundle["completeness_certificate"]["non_record_leaves"])
        return bundle

    def neg(case_id: str, description: str, edit: Any, *findings: str) -> None:
        bundle = edited(edit)
        cases.append(case(case_id, description, bundle,
                          expect(bundle, "INVALID", per_record_membership=claim("fail", *findings))))

    def content(seq: int) -> Any:
        return lambda leaves: leaves[index_of[seq]]["content"]

    neg("neg-padding-nonce-edited", "The padding at seq 6 has its store_nonce changed and its capsule_id left as it was.",
        lambda ls: content(6)(ls).update(store_nonce="00" * 32), "non_record_leaf_mismatch:6")

    def recomputed_other(ls: list) -> None:
        other = padding("not in this log")
        ls[index_of[7]]["content"] = other

    neg("neg-padding-other-leaf", "The padding at seq 7 is a well-formed padding record that recomputes to its own "
        "capsule_id, but not to body_digests for seq 7.", recomputed_other, "non_record_leaf_mismatch:7")

    def swapped(ls: list) -> None:
        a, b = index_of[6], index_of[7]
        ls[a]["content"], ls[b]["content"] = ls[b]["content"], ls[a]["content"]

    neg("neg-padding-swapped", "The contents of seq 6 and seq 7 are swapped.", swapped,
        "non_record_leaf_mismatch:6", "non_record_leaf_mismatch:7")

    def digest_only(ls: list) -> None:
        element = ls[index_of[8]]
        ls[index_of[8]] = {"seq": 8, "digest": element["content"]["capsule_id"]}

    neg("neg-padding-digest-only", "Seq 8 is carried as its digest, with no content.", digest_only,
        "non_record_leaf_malformed:8")
    neg("neg-padding-extra-member", "The padding at seq 9 also carries links: [].",
        lambda ls: content(9)(ls).update(links=[]), "non_record_leaf_malformed:9")

    def envelope_left(ls: list) -> None:
        c = content(10)(ls)
        c["signature"] = strict.envelope(c["capsule_id"], strict.PRODUCER)
        c["key_id"] = strict.raw_public(strict.PRODUCER).hex()

    neg("neg-padding-envelope-left", "The padding at seq 10 still carries a producer envelope (signature, key_id).",
        envelope_left, "non_record_leaf_malformed:10")
    neg("neg-padding-epistemic-type", "The padding at seq 11 has epistemic_type observed_event.",
        lambda ls: content(11)(ls).update(epistemic_type="observed_event"), "non_record_leaf_malformed:11")

    def nonce_upper(ls: list) -> None:
        c = content(12)(ls)
        c["store_nonce"] = c["store_nonce"].upper()

    neg("neg-padding-nonce-uppercase", "The padding at seq 12 has an uppercase store_nonce.", nonce_upper,
        "non_record_leaf_malformed:12")
    neg("neg-padding-content-not-object", "The content of seq 13 is a string.",
        lambda ls: ls[index_of[13]].update(content="padding"), "non_record_leaf_malformed:13")
    neg("neg-padding-seq-out-of-range", "The element for seq 14 says seq 65, past the tip.",
        lambda ls: ls[index_of[14]].update(seq=65),
        f"non_record_leaf_seq_invalid:{index_of[14]}", "membership_record_missing:14")
    # Elements are read in order: the first to claim seq 16 holds it (and does
    # not recompute to it), the next one is the repeat.
    neg("neg-padding-seq-repeated", "The element for seq 15 says seq 16, which the next element also claims.",
        lambda ls: ls[index_of[15]].update(seq=16),
        "non_record_leaf_mismatch:16", f"non_record_leaf_seq_invalid:{index_of[16]}", "membership_record_missing:15")
    neg("neg-padding-seq-on-record", "The element for seq 17 says seq 3, a record's seq.",
        lambda ls: ls[index_of[17]].update(seq=3),
        f"non_record_leaf_seq_invalid:{index_of[17]}", "membership_record_missing:17")
    neg("neg-padding-seq-not-integer", "The element for seq 18 says seq \"18\".",
        lambda ls: ls[index_of[18]].update(seq="18"),
        f"non_record_leaf_seq_invalid:{index_of[18]}", "membership_record_missing:18")
    neg("neg-padding-omitted", "The element for the tip, seq 64, is left out.",
        lambda ls: ls.pop(index_of[64]), "membership_record_missing:64")

    bundle = copy.deepcopy(whole)
    bundle["completeness_certificate"]["non_record_leaves"] = {}
    padding_seqs = [e["seq"] for e in leaves]
    cases.append(case(
        "neg-non-record-leaves-not-array", "non_record_leaves is an object, not an array: no padding seq is accounted for.",
        bundle, expect(bundle, "INVALID", per_record_membership=claim(
            "fail", "non_record_leaves_malformed", *[f"membership_record_missing:{s}" for s in padding_seqs]))))
    neg("neg-non-record-leaf-element-not-object", "The element for seq 19 is the number 19.",
        lambda ls: ls.__setitem__(index_of[19], 19),
        f"non_record_leaf_element_invalid:{index_of[19]}", "membership_record_missing:19")

    stamp = {"record_type": "checkpoint_stamp", "epistemic_type": "producer_claim", "note": "an unknown type"}
    unknown = edited(lambda ls: ls[index_of[20]].update(content=stamp))
    cases.append(case(
        "incomplete-unknown-leaf-type", "Seq 20 is carried as a leaf of a record_type this document does not define: "
        "everything else passes, the claim is withheld.", unknown,
        expect(unknown, "INCOMPLETE", per_record_membership=claim("withheld", "non_record_leaf_type_unsupported:20"))))

    def unknown_and(edit: Any) -> Any:
        def both(ls: list) -> None:
            ls[index_of[20]]["content"] = copy.deepcopy(stamp)
            edit(ls)
        return both

    neg("neg-unknown-type-and-mismatch", "Seq 20 is of an unknown type and seq 21's nonce is edited: the mismatch fails.",
        unknown_and(lambda ls: content(21)(ls).update(store_nonce="11" * 32)),
        "non_record_leaf_type_unsupported:20", "non_record_leaf_mismatch:21")
    neg("neg-unknown-type-and-missing", "Seq 20 is of an unknown type and the element for seq 22 is left out.",
        unknown_and(lambda ls: ls.pop(index_of[22])),
        "non_record_leaf_type_unsupported:20", "membership_record_missing:22")

    no_cose = copy.deepcopy(unknown)
    del no_cose["checkpoint"]["cose"]
    cases.append(case(
        "incomplete-unknown-leaf-type-unsigned-checkpoint", "The unknown-type Bundle without checkpoint.cose: "
        "withheld, with checkpoint_unverified added.", no_cose,
        {**expect(no_cose, "INCOMPLETE",
                  checkpoint=claim("withheld", "checkpoint_signature_absent"),
                  interval_coverage=UNANCHORED,
                  per_record_membership=claim("withheld", "non_record_leaf_type_unsupported:20", "checkpoint_unverified")),
         "checkpoint_authenticated": False, "signer_matches_checkpoint": None}))

    selected = bundle_over_log(log, None)
    selected["completeness_certificate"]["non_record_leaves"] = []
    cases.append(case(
        "neg-non-record-leaves-on-producer-selected", "A producer-selected Bundle (no range) carrying an empty "
        "non_record_leaves member.", selected,
        expect(selected, "INVALID", interval_coverage=claim("withheld", "selection_not_checkable"),
               per_record_membership=claim("fail", "completeness_certificate_invalid"))))
    return cases


def mode_cases() -> list[dict]:
    log = padded_log()
    selected = bundle_over_log(log, None)
    cases = [case(
        "incomplete-producer-selected-padded-log", "The eight records of the padded log, producer-selected, in the "
        "shape producers emit (payloads_mode none, no range): each record's proof checks, the interval is not shown.",
        selected, expect(selected, "INCOMPLETE", interval_coverage=claim("withheld", "selection_not_checkable")))]
    tampered = copy.deepcopy(selected)
    tampered["completeness_certificate"]["memberships"][tampered["root"]]["inclusion_proof"]["witness"][0] = "00" * 32
    cases.append(case(
        "neg-producer-selected-padded-log-tampered", "The same with the root record's inclusion proof edited.", tampered,
        expect(tampered, "INVALID", interval_coverage=claim("withheld", "selection_not_checkable"),
               per_record_membership=claim("fail", f"membership_proof_invalid:{tampered['root']}"))))
    unsupported = claim("withheld", "certificate_mode_unsupported")
    for case_id, value, what in (
        ("incomplete-certificate-mode-unknown", "x-sampled", "a selection value this document does not define"),
        ("incomplete-certificate-mode-not-a-string", 7, "a selection value that is not a string"),
    ):
        bundle = copy.deepcopy(selected)
        bundle["completeness"]["selection"] = value
        cases.append(case(case_id, f"The producer-selected Bundle with {what}: interval coverage and per-record "
                          "membership are withheld, never failed.", bundle,
                          expect(bundle, "INCOMPLETE", interval_coverage=unsupported, per_record_membership=unsupported)))
    ranged = bundle_over_log(log, 33)
    ranged["completeness"]["selection"] = "x-sampled"
    cases.append(case(
        "incomplete-certificate-mode-unknown-on-range", "A valid range certificate [33, 64] under an unknown selection "
        "value: the verifier does not read the certificate under a mode it does not implement.", ranged,
        expect(ranged, "INCOMPLETE", interval_coverage=unsupported, per_record_membership=unsupported)))
    return cases


def write(out: Path, description: str, cases: list[dict]) -> None:
    out.mkdir(parents=True, exist_ok=True)
    vectors = {
        "format_version": "1",
        "description": description,
        "keys": {
            "producer_public_key": strict.raw_public(strict.PRODUCER).hex(),
            "log_public_key": strict.raw_public(strict.LOG_KEY).hex(),
        },
        "cases": cases,
    }
    files = {"vectors.json": strict.dump(vectors)}
    files["manifest.json"] = strict.dump({
        "format_version": "1",
        "files": {name: {"sha256": hashlib.sha256(data).hexdigest()} for name, data in files.items()},
        "case_count": len(cases),
    })
    for name, data in files.items():
        (out / name).write_bytes(data)
    names = sorted(p.name for p in out.iterdir() if p.is_file() and p.name != "SHA256SUMS")
    (out / "SHA256SUMS").write_text("".join(f"{hashlib.sha256((out / n).read_bytes()).hexdigest()}  {n}\n" for n in names))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="the parent of the two vector directories")
    out = parser.parse_args().out
    write(out / "non-record-leaves", "Strict verify_bundle over ranges that carry padding leaves in "
          "completeness_certificate.non_record_leaves (Evidence Bundle -02). See README.md.", leaf_cases())
    write(out / "certificate-mode", "Strict verify_bundle on the producer-selected certificate and on certificate "
          "modes a verifier does not implement (Evidence Bundle -02). See README.md.", mode_cases())


if __name__ == "__main__":
    main()
