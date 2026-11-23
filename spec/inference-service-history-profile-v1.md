# Inference-Service History Profile — `inference-service-history/1`

**Status.** Informational host profile, pre-Internet-Draft, kept in this repository. It is the
revision `inference-service-history/1` (cited here as ISH1) of the Inference-Service History
Profile v0 (`spec/inference-service-history-profile-v0.md`, `inference-service-history/0`, cited
as ISH). ISH and its documents, vectors and definitions are frozen: a definition that names
`inference-service-history/0` conforms to ISH as it stands, and nothing here changes it. ISH1
changes no Internet-Draft and no part of the Minimum Evidence Interoperability Profile
(`spec/interop-profile-v1.md`, cited here as IP).

ISH1 is ISH with one rule added to complementary suppression in `period_counts`: a published total
that fixes two or more cells withheld under the floor is withheld with them (§6.2 item 3.2,
closing SH-8 for this case). This document states only what differs from ISH. Each numbered
section below replaces or extends the ISH section of the same number, as it says; "Identifier and
pinning", "Interop profile revision" and the open points replace ISH's counterparts. Every other
part of ISH applies as it stands, with `inference-service-history/1` read for
`inference-service-history/0` wherever ISH names its own identifier.

## Dependency boundary

**Owns:** the identifier `inference-service-history/1`, its counting table and wording pack
("Identifier and pinning"), the added rule (§6.2 item 3.2), the rule that keeps `/0` and `/1`
Standard Histories apart under one node key (§6.1 item 9), and the cases of §9.4.

**Uses unchanged:**

| Tag | Document | What ISH1 takes from it |
|---|---|---|
| ISH | `spec/inference-service-history-profile-v0.md` | every section as it stands, except ISH's identifier and pinning, its "Interop profile revision" paragraph, §6.1 (extended), §6.2 item 3 (replaced), §6.3 (as read here), §9.4 (extended), §12 (extended) and §13 (amended), which this document states |
| IP | `spec/interop-profile-v1.md` (`evidence-interop/1`) | as ISH takes it |
| HF | `spec/history-frame-v0.md` | the History frame; ISH1 takes the ISH columns of HF §6.1 and pins its own documents |

**Interop profile revision.** ISH1 is written against `evidence-interop/1`, and its vectors are
under it only. ISH's "Interop profile revision" paragraph, which also lets a `/0` History be served
under the frozen `evidence-interop/0`, is not taken over.

## Identifier and pinning

- **Identifier.** A definition under ISH1 carries `"profile": "inference-service-history/1"`. It is
  otherwise ISH §4.1's frame, member for member. Its digest differs from any `/0` definition's.
- **Counting table:** `spec/history-frame/inference-service-history-1-table.json`, digest
  `591090aab054e05bec51d823c2d36645c637cd09baf81366af9bdb02ea9f5e7f`. It is the `/0` table with its
  `instance` and its fixed `profile` naming `/1`: ISH1 adds no member, unit, label, policy member,
  suppression reason or property, and changes what one property checks (§6.3).
- **Wording pack:** `spec/history-frame/inference-service-history-1-pack.json`, digest
  `d5f5c2f807335fdc8d003ae04fecc87bcdcbaad1ed54cb30f1c496901826718b`, the `/0` pack with its
  `instance` naming `/1`.
- **Pinning.** As ISH's (HF §5.4): any change to either document is a new identifier,
  `inference-service-history/2`.

## 6. Period counts

### 6.1 Periods

ISH §6.1 items 1 to 8 apply, and one more:

9. **No `/0` Standard History beside it.** A node that serves Standard Histories under ISH1 MUST
   NOT serve a Standard History under `inference-service-history/0` under the same node key, and
   MUST NOT serve ISH1 Standard Histories under a node key that has served `/0` ones. Its periods
   are the same (item 6), a `/0` History publishes the totals ISH1 withholds under §6.2 item 3.2,
   and a period once answered keeps its cells (item 4), so a `/0` answer under the key would give
   away the cells ISH1 protects.

### 6.2 Floor and complementary suppression

ISH §6.2 items 1, 2 and 4 apply unchanged. Item 3 reads:

3. **Complementary suppression.** A cell whose value could be derived from published cells and
   totals is suppressed with them, with the reason `complementary`. At the least:
   1. where a unit's total for a period is published and exactly one of its dimension cells is
      suppressed, the smallest other dimension cell is suppressed too (ISH §6.2 item 3, unchanged);
      and
   2. in `period_counts`, where a unit's total for a period is at least the floor, two or more of
      its dimension cells are suppressed, every one of them with the reason `below_floor`, and the
      **rest** (the total less the published dimension cells) is 0, one for each suppressed cell,
      or `floor` − 1 for each suppressed cell, the total is suppressed too, with the reason
      `complementary`.

   A dimension cell is listed only when it counts at least one record, so a cell suppressed below
   the floor holds 1 to `floor` − 1. A rest of one each or of `floor` − 1 each therefore fixes
   every suppressed cell, and a rest of 0 can only come from a table that lists a cell it did not
   count. Any other rest that such cells can hold leaves at least two values for each of them,
   and the total stays published. With a floor of 5: two cells of 4 and a total of 8 fix both, so
   the 8 is withheld; five cells of 1 and a total of 5 fix all five, so the 5 is withheld; two
   cells of 4 and 3 and a total of 7 fix neither, so the 7 stays.

   Item 3.2 adds no reason and no member: a total withheld under it is published with no value
   and the reason `complementary`, as any suppressed cell is (item 1). A total below the floor is
   suppressed `below_floor` under item 1, and item 3.2 does not apply to it. ISH1 states no rule
   of its own for the tables of `verdict_counts` (ISH §5.3), which stay as ISH has them (SH-8).

### 6.3 Period properties

ISH §6.3 applies. `period_floor`'s check, "§6.2 item 3 holds", reads §6.2 item 3 above, both
parts: a published total in a `period_counts` table that item 3.2 describes is `period_floor`
`FAIL`.

## 9. Acceptance vectors (informative)

`vectors/inference-service-history-v1/` holds ISH's cases (ISH §9.4) with every definition naming
`inference-service-history/1`, each expected as ISH states it (no period of theirs has two or more
cells suppressed `below_floor`), and the cases below, under `evidence-interop/1`.
`python/scripts/generate_inference_service_history_v0_vectors.py --profile 1 --history 1` writes
them; `python/tests/test_inference_service_history_v1_vectors.py` and the Go package
`go/inferencehistory` check every case, and the Rust test `inference_history_vectors` checks the
Standard-level History cases and the pairs.

### 9.4 The cases

Each is the served-only History (ISH §9.1) with 2 October's cells changed, under a floor of 5.

| Case | Expected |
|---|---|
| `standard-total-withheld-two-pinned` | accepted; two models of 4 suppressed `below_floor`, the total 8 suppressed `complementary` (§6.2 item 3.2) |
| `standard-total-withheld-ones-pinned` | accepted; five models of 1 suppressed `below_floor`, the total 5 suppressed `complementary` |
| `standard-total-published-not-pinned` | accepted; models of 4 and 3 suppressed `below_floor`, the total 7 published: 7 is neither 2 nor 8 |
| `mutant-total-two-pinned-published` | `period_floor` `FAIL`: two models of 4 suppressed and their total 8 published |
| `mutant-total-ones-pinned-published` | `period_floor` `FAIL`: five models of 1 suppressed and their total 5 published |

## 12. Security and privacy considerations

ISH §12 applies. §6.2 item 3.2 removes one exact disclosure, a total that fixes the cells it sits
beside; it does not remove bounds. Beside a published total, two suppressed cells whose rest is 7
under a floor of 5 are each 3 or 4; a requester learns that much, as it learns from ISH §6.2
item 1 that a suppressed cell is below the floor. The floor limits, and does not remove, what a
requester learns from a small count.

Item 3.2 reads only tables whose suppressed cells are all `below_floor`. A table where item 3.1
has suppressed a cell `complementary` beside one `below_floor` cell can still be fixed by its
total: with a floor of 5, models of 1, 5 and 9 publish the 9 and a total of 15, and the rest of 6
is a cell of 1 to 4 and a cell of at least 5, so 1 and 5 (SH-8).

## 13. Open points

ISH's open points apply, except:

| # | Point |
|---|---|
| SH-8 | Closed for a `period_counts` total that fixes two or more cells suppressed below the floor (§6.2 item 3.2), the narrow rule. Still open: a total that fixes cells when item 3.1 has suppressed one `complementary` beside one `below_floor` (§12); the bounds a published total gives the cells it sits beside (§12); tables of more than one dimension; and the tables of `verdict_counts`, for which ISH1 states no rule beyond ISH's. |
| SH-14 | As ISH's, except that §9.4 now has cases for two or more models withheld under the floor beside a published total in `period_counts`. Still no vectors for: a `/0` Standard History beside an ISH1 one under one key (§6.1 item 9), which a verifier sees only when it holds answers of both; item 3.2 in `verdict_counts`; a table of item 3.1's mixed kind (§12). |
