# Presentation Builder — v0 (moved)

**Status.** Informative pointer. This document is not normative. The presentation builder
specification that was here (`buildPresentation`, its four packagings, `availablePackagings` and
its reasons, the fragment payload `aac.presentation-fragment/v0`, the static page and the
share-side scoping step) moved whole, with its section numbers, to
`spec/presentation-builder-v0.md` in the `action-state-group/capsule-viewer` repository. The last
revision here with the whole text is `60a5b11`.

What stays in this repository: the Evidence Bundle permalink codec it packages with (the
"Fragment Codec" section of `draft-mih-zhang-agent-disclosure-bundle`, implemented by
`encodeFragment` in `ts/src/bundle.ts` and `bundle.EncodeFragment` in Go), and its shared vectors,
`vectors/bundle/fragment/`.
