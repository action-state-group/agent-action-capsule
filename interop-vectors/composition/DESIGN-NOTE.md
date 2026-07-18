# Design note — the third attestor is a composition-level slot, not a spec role

A physically-measured meter reading (did the curtailment actually reduce load?)
is a **third attestor's separate signed claim over the same `subject_digest`**,
composed at the same digest join as WHO and WHAT. It answers a different question
("what was observed") than the capsule ("what the agent did") or the receipt
("who authorized it").

It is deliberately **not** modeled as a role inside the Agent Action Capsule and
**not** added to `draft-mih-agent-bilateral-attestation` — adding a meter role
would reopen the -01 freeze for no gain, since composition already carries it: a
meter attestation is just another record over the shared `subject_digest`, joined
the same way. `pos-composition-third-attestor-STUB/` reserves the slot; fill it
when a third-attestor sample is supplied.

This keeps the boundary the whole set is built on: **compose by shared digest,
do not grow any one profile to swallow the others.**
