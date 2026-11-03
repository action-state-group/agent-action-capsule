- Spec: the Outcome level of the Personal-Agent History Profile
  (`spec/personal-agent-history-outcome-v0.md`) carries tick paths. Its one-file History (§11) gains
  the `tick_paths` member, as PH §8.2 defines it, so a History whose anchor tick commits to a stream
  through an earlier tick has a carriage at this level; a file with any other member, or a
  `tick_paths` value not of PH §8.3's form, is not a History at this level. As at the Basic level,
  the tick path check is not a History property and never changes acceptance or a claim (§8.2), and
  a verifier shows each path's status (§9) (action-state-group/agent-action-capsule#580). Two new
  cases in `vectors/personal-history-outcome-v0/` (27 in all): `multi-stream-earlier-tick` and
  `mutant-tick-path-consistency-changed`.
- Go: `personalhistoryoutcome.Inputs.TickPaths` takes the tick paths a History carries, and
  `Result.TickPaths` reports each path's check (`personalhistory.CheckTickPaths`).
