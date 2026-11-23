- Spec: `inference-service-history/1` (`spec/inference-service-history-profile-v1.md`, ISH1), the
  Inference-Service History Profile with one rule added to complementary suppression, closing SH-8
  for `period_counts` with the narrow rule (agent-action-capsule#616). Where two or more of a unit's
  cells in a period are suppressed `below_floor` and the total less the published cells is 0, one
  for each or `floor` − 1 for each, the total fixes every one of them, so it is withheld too, as
  `complementary` (ISH1 §6.2 item 3.2). Any other total stays published. A node that serves ISH1
  Standard Histories serves no `/0` Standard History under the same key, and a key that has served
  `/0` ones serves no ISH1 ones (ISH1 §6.1 item 9). SH-8 stays open for a table where one cell is
  suppressed `complementary` beside one `below_floor`, for bounds, and for `verdict_counts`. New
  counting table and wording pack (`spec/history-frame/inference-service-history-1-*.json`),
  listed in the History frame (HF §6.1), and vectors `vectors/inference-service-history-v1/` (33
  cases: ISH's cases under `/1` plus five for the rule). `inference-service-history/0`, its text,
  documents and both vector sets are unchanged and frozen.
- Go: `inferencehistory.ProfileV1`; `definition_form` accepts a `/1` definition, and
  `period_floor` fails a `/1` History that publishes a total ISH1 §6.2 item 3.2 withholds.
