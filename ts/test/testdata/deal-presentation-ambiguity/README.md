# Two deal pages, one unilateral x-deal-v0 bundle

Read by `test/deal-presentation-ambiguity.test.ts`.

- `capsulectl.deal-view.manifest.json`: byte copy of
  `internal/cli/assets/deal-view.manifest.json` in capsule-cli at
  `46420af559fde0036a9a234b4a4afee061025ad4`.
- `capsuleviewer.receipt.unilateral.manifest.json`: byte copy of
  `src/capsule_viewer/receipt/manifest-unilateral.json` in capsule-viewer at
  `7fec78c94211cfaa63beb47a262e37423dce1d5a`.
- `unilateral-deal-bundle.json`: synthetic, sealed at test time. Shaped like a
  unilateral deal bundle: the root's `agent_input` carries `body` and
  `x-deal-v0` and no `spec_version`, so the descriptor has no profile token.
- `resolution.json`: what registration and resolution do today, pinned.
