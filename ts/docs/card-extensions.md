# Card extensions: which view draws a verified Result

A card is a view of a verified Result v0 bundle drawn in place of the
generic Result page: `outcome-report/v1` (the outcome report) and
`eu-ai-act-compliance/v1` (the EU AI Act obligations report) are the two
built in. This note is the contract every card follows. Modules:
`src/card-registry.ts` (registry and dispatch, no DOM), `src/card-view.ts`
(built-in cards, notices, view guards), `src/evidence-graph-view.ts` (the
page shell). Tests: `test/card-registry.test.ts`.

The key words MUST, MUST NOT, SHOULD and MAY are used as in BCP 14
(RFC 2119, RFC 8174) when, and only when, they appear in all capitals.

## Declaring a card

A bundle declares a card with an Evidence Bundle extension: a member of the
bundle's `extensions` object whose value is a JSON object with
`"enabled": true`. The member name is the card's kind, `<name>/v<N>`, or
`x-<name>/v<N>` for a private card. A block that is absent, not an object,
or not `"enabled": true` declares nothing. `presentation/v1` and the data
extension kinds (`producer-key/v1`, `composed/v1`,
`disclosure-policy-decisions/v1`, `sd-jwt-issuers/v1`,
`evidencebook/payloads`) are never cards.

Like every extension, a card block is covered by the bundle digest and sits
outside the signed records. It is display input, not evidence, and a card
labels what it read from it as such.

A bundle names a card; it never supplies one. The code that draws a card is
registered by the page that hosts the viewer.

## The registry

```ts
const cards = defaultCardRegistry(); // outcome-report/v1, eu-ai-act-compliance/v1
cards.registerCard("x-month-view/v1", {
  label: "month view",
  readSettings: (block) =>
    typeof block.month === "string" ? { month: block.month } : undefined,
  render: (result, bundle, chrome, settings) => monthView(result, settings),
});
await renderEvidenceGraph(bundle, root, countersigners, cards);
```

- `registerCard(kind, definition)` adds one card. A duplicate kind, a kind
  not shaped `name/vN`, or a non-card kind throws. Adding a card MUST NOT
  need an edit to the page shell or to the report build.
- `resolveCard(bundle)` returns the card to draw (if any) and the notices
  the page shows.
- `defaultCardRegistry()` returns a fresh registry holding the built-in
  cards; each call is independent, so one host's card never appears in
  another's.
- `readSettings(block)` receives a frozen copy of the card's own block and
  nothing else, and returns typed values or `undefined` to reject it.

## Dispatch

The shell resolves a card only after the bundle verified and its root built
as a Result v0. Then:

1. **No card declared.** The generic Result page, with no notice. This is
   every bundle that predates cards.
2. **One registered kind declared, and its reader accepts the block.** That
   card is drawn in place of the generic Result page.
3. **Several declared.** The first kind in the registry's registration order
   that the bundle declares and whose reader accepts its block is drawn. The
   bundle's member order is not used: a JCS-canonical bundle sorts its
   members, so it carries no producer intent, and the registry's order is
   the one order that is the same on every run. Each other declared kind
   gets a `not-selected` notice naming the card drawn instead.
4. **A declared kind the registry does not know.** The generic Result page,
   plus an `unrecognized-kind` notice that names the kind. Not a failure,
   and never another card's view.
5. **A known kind whose reader rejects its block.** An `unreadable-block`
   notice; dispatch continues with the next declared kind, else the generic
   Result page.
6. **The card fails.** If the card throws (including on a write to the
   frozen data it was given), returns no element, or changes the shell's
   banner, the shell clears the page, redraws the chrome from the verifier's
   result, shows a `card-failed` notice and the generic Result page.

A bundle that did not verify draws no card and no notice: the banner says it
failed and the verification page says why, as before. A verified bundle
whose root is not a Result v0 gets a `not-a-result-root` notice for each
declared kind.

Notices are drawn by the shell after the banner, as plain text
(`[data-card-notice]`, with the kind on `data-card-kind`, capped at 120
characters). They are not verification findings and never change the
banner.

## The boundary

The rule a card MUST NOT break, and how the code holds it:

- **A card draws verified data only.** `render` receives the Result root
  model built from the verified bundle; a `VerifiedBundle` holding the
  bundle verification result and the bundle document with `extensions`
  removed; the `presentation/v1` chrome (`producerDisplayName`,
  `logoDataUrl`, `title`, read by `readPresentationBlock` and nothing else);
  and the settings its own reader returned. It never receives the raw
  bundle, any other extension, or any other member of its own block.
- **A card never takes markup from the bundle.** Strings from the settings
  are display text; a renderer writes them with `textContent`. The shell
  then seals the returned view (`sealCardView`): script, frame, object,
  embed, base, meta, link and template elements are removed, as are event
  handler and `srcdoc` attributes and any URL attribute other than a
  `#fragment` or a `data:image/` URL. The count is recorded on
  `data-card-sealed`.
- **A card never alters a verification result.** Every input is a deep,
  frozen copy (`frozenCopy`): a write throws, and even a bypass reaches only
  the copy, never the objects the shell draws from. The banner
  (`[data-verify]`) and the verification page are drawn by the shell from
  the verifier's result, outside the card. A card view's own `data-verify`,
  `data-refusal`, `data-page="verification"` or notice marker is removed,
  and after mounting the shell checks that its banner is unchanged and is
  the only verdict marker on the page, or drops the card (rule 6).

Cards are trusted code chosen by the host page. The boundary is against the
bundle: whatever a bundle carries, it can only pick among registered cards,
and what reaches the page is verified data, escaped.

## Registration status

None of these kinds is in `spec/REGISTRY.md` §14 (Evidence Bundle extension
kind), and this note registers none. Candidates, held as PROVISIONAL:
`presentation/v1`, `outcome-report/v1`, `eu-ai-act-compliance/v1`, and the
card-declaration rule above (`"enabled": true`) as the shared shape of a
card block.
