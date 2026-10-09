import type {
  PresentationFormat,
  PresentationResolver,
} from "./presentation-registry.js";
import { renderEvidenceGraph } from "./evidence-graph-view.js";
import {
  decodePresentationFragment,
  FRAGMENT_TOKEN_MAX_LENGTH,
  type PresentationDepth,
  type WordingPackInput,
} from "./presentation-fragment.js";

/** What a host element is given: an already scoped bundle and its settings. */
export interface MountPresentationInput {
  readonly bundle: unknown;
  readonly audience: string;
  readonly format: PresentationFormat;
  readonly depth?: PresentationDepth;
  readonly wording?: WordingPackInput;
  /** The host's registry; the default registry when omitted. */
  readonly registry?: PresentationResolver;
}

/**
 * Render a scoped bundle into a host element (the `embedded` packaging, and
 * the body of the fragment viewer). Verification, resolution and the
 * refusal are renderEvidenceGraph's; this only forwards the settings. It
 * never scopes: what the element shows is the bundle it was given.
 */
export function mountPresentation(
  element: HTMLElement,
  input: MountPresentationInput,
): Promise<void> {
  return renderEvidenceGraph(input.bundle, element, undefined, {
    audience: input.audience,
    format: input.format,
    ...(input.depth === undefined ? {} : { depth: input.depth }),
    ...(input.wording === undefined ? {} : { wording: input.wording }),
    ...(input.registry === undefined ? {} : { registry: input.registry }),
  });
}

/**
 * The fragment viewer: read a presentation fragment (`location.hash`) and
 * render it into `element` as the `fragment` format. A fragment that cannot
 * be read shows a fixed statement and nothing else. The fragment is never
 * sent anywhere: this reads it in the page.
 */
export async function mountPresentationFragment(
  hash: string,
  element: HTMLElement,
  maxLength: number = FRAGMENT_TOKEN_MAX_LENGTH,
): Promise<void> {
  let payload;
  try {
    payload = decodePresentationFragment(hash, maxLength);
  } catch (err) {
    const note = document.createElement("p");
    note.dataset.refusal = "fragment-unreadable";
    note.textContent =
      `This link's fragment could not be read, so nothing is shown. ${err instanceof Error ? err.message : ""}`.trim();
    element.replaceChildren(note);
    return;
  }
  await mountPresentation(element, {
    bundle: payload.bundle,
    audience: payload.audience,
    format: "fragment",
    ...(payload.depth === undefined ? {} : { depth: payload.depth }),
    ...(payload.wording === undefined ? {} : { wording: payload.wording }),
  });
}
