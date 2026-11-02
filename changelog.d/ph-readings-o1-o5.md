- Spec: the Personal-Agent History Profile v0 (`spec/personal-agent-history-profile-v0.md`) settles
  five readings of its Basic level (action-state-group/agent-action-capsule#328). An anchor tick may
  commit to a stream through an earlier tick of the same tick log when the History carries that
  stream's tick path, a new optional `tick_paths` member of the §8.2 file with its own check (§2,
  §8.3, PA-16); the check is not a History property and never changes acceptance. The host states
  its correlation rule, which may hold only a deal's steps and need not use `subject_ref`, and a
  History never borrows a completeness proof built for another set (§3.1, PA-17). PA-6 is the
  choosing party's obligation, and a holder never selects a deal reference of unknown source (§4.5).
  Read members are the values sealed in the record's header, never mapped at answer time (§3,
  PA-18). `artifact_form` now requires an Artifact that is exactly JCS and each entry value in its
  §4.3 form: IP §5.2 times for `committed_at` and `event_time_claim`, and EL §4.1's vocabulary for
  `epistemic_type`. The Outcome level applies the same entry forms through its references to PH.
  Nine new cases in `vectors/personal-history-basic-v0/` (23 in all). `personal_history_basic/1`
  keeps its name and its counting table and wording pack bytes.
- Go: `personalhistory` reads and writes `tick_paths` in the one-file History (`File.TickPaths`,
  `ParseTickPaths`) and runs the tick path check (`CheckTickPaths`); its `artifact_form`, and
  `personalhistoryoutcome`'s, hold the §4.3 entry forms. `evidencerequest.CLLCheckpoint` gains
  `Iss` and `Sub`, `TrustPolicy.AcceptsLogKey` is exported, and `DecodeCLLCheckpoint` marks a
  checkpoint whose signature is not checked with `ErrCheckpointNotChecked`.
