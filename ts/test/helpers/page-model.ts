// The verification a page states, built from the DOM-free model alone: the
// banner, the countersignature stamps and the verification page model, read
// from one verification run exactly as a viewer reads them. capsule-viewer
// draws the page (action-state-group/capsule-viewer); these tests hold the
// verification it draws from.
import {
  buildVerifiedBundleContext,
  isVerifiedBundleContext,
  withCountersigners,
  type VerifiedBundleContext,
} from "../../src/bundle.js";
import {
  classifyCountersignatures,
  declaredProducerKeys,
  type CountersignatureStamp,
  type CountersignerSource,
} from "../../src/countersignature-stamp.js";
import type { ExtensionInterpreterId } from "../../src/extension-interpreters.js";
import type { PresentationRefusal } from "../../src/presentation-registry.js";
import {
  buildVerificationPageModel,
  verificationBanner,
  type VerificationBanner,
  type VerificationPageModel,
} from "../../src/verification-page.js";

export interface PageModelOptions {
  readonly countersigners?: CountersignerSource;
  /** The interpreters the drawn page ran; omitted, the verifier's status stands. */
  readonly applied?: ReadonlySet<ExtensionInterpreterId>;
  readonly refused?: readonly PresentationRefusal[];
  /** True when the drawn page module checked the signers it cites. */
  readonly citedSigners?: boolean;
}

export interface PageModel {
  readonly context: VerifiedBundleContext;
  readonly stamps: readonly CountersignatureStamp[];
  readonly banner: VerificationBanner;
  readonly page: VerificationPageModel;
}

/** Verify `input` once (or reuse a context) and read what its page states. */
export async function pageModel(
  input: unknown,
  options: PageModelOptions = {},
): Promise<PageModel> {
  const context = isVerifiedBundleContext(input)
    ? options.countersigners === undefined
      ? input
      : withCountersigners(input, options.countersigners)
    : await buildVerifiedBundleContext(
        input,
        options.countersigners === undefined
          ? {}
          : { countersigners: options.countersigners },
      );
  const stamps = await classifyCountersignatures(
    context.countersignatures.map((entry) => entry.value),
    context.verification.bundleDigest,
    declaredProducerKeys(context.bundle),
    context.countersigners,
  );
  return {
    context,
    stamps,
    banner: verificationBanner(context, stamps),
    page: buildVerificationPageModel(
      context.bundle,
      context.verification,
      options.applied,
      options.refused ?? [],
      {
        stamps,
        ...(options.citedSigners === undefined
          ? {}
          : { citedSigners: options.citedSigners }),
        ...(context.strict === undefined ? {} : { strict: context.strict }),
      },
    ),
  };
}
