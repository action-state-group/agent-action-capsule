import { readFileSync } from "node:fs";
import { sign as edSign } from "node:crypto";
import { resolve } from "node:path";
// Imported by module (not via src/index.js) so this helper also loads under
// the jsdom test environment, where the emitter's node:fs shell read cannot.
import { bundleDigest } from "../../src/bundle.js";
import { createEd25519Identity } from "../../src/producer-envelope.js";
import {
  encodeProducerEnvelope,
  hexToBytes,
  producerEnvelopeSigningBytes,
  protectedHeadersFor,
} from "../../src/producer-envelope-wire.js";

/**
 * Derived countersignature-stamp and presentation/v1 fixtures, built at test
 * time from the committed seed `test/testdata/week-bundle.json`.
 *
 * Each derived bundle is the seed plus a small edit (an empty
 * `countersignatures[]`, one COSE_Sign1 countersignature over the seed's
 * bundle digest, or a `presentation/v1` block). Committing them would
 * re-check-in the ~50k-line seed five times over, so they are derived here
 * instead, memoised per test worker, and never written to disk.
 *
 * Keys are fixed, clearly test-only seeds (never a production key). The
 * committed `test/testdata/countersigner-directory.json` names the
 * directory signer's public key; `countersignerDirectory()` derives the same
 * entry so a test can assert the two never drift.
 */

type Obj = Record<string, unknown>;

export type DerivedFixtureName =
  | "week-bundle-empty-countersignatures.json"
  | "week-bundle-producer-countersigned.json"
  | "week-bundle-directory-countersigned.json"
  | "week-bundle-unresolved-countersigned.json"
  | "week-bundle-presentation.json";

export interface CountersignerDirectoryEntry {
  readonly publicKey: string;
  readonly name: string;
  readonly logoDataUrl: string;
  readonly checksRecomputed: number;
}

const BUNDLE_DIGEST_CONTENT_TYPE =
  "application/agent-action-capsule-bundle-digest";

// 1x1 transparent PNG.
const TEST_PNG_DATA_URL =
  "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=";

const producerIdentity = createEd25519Identity(new Uint8Array(32).fill(11));
const directorySignerIdentity = createEd25519Identity(
  new Uint8Array(32).fill(22),
);
const strangerIdentity = createEd25519Identity(new Uint8Array(32).fill(33));

function toBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString("base64")
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}

function signDigest(
  digestHex: string,
  identity: ReturnType<typeof createEd25519Identity>,
): string {
  const payload = hexToBytes(digestHex);
  const protectedBytes = protectedHeadersFor(
    BUNDLE_DIGEST_CONTENT_TYPE,
    identity.publicKey,
  );
  const signature = edSign(
    null,
    producerEnvelopeSigningBytes(protectedBytes, payload),
    identity.privateKey,
  );
  return toBase64Url(
    encodeProducerEnvelope(protectedBytes, payload, signature),
  );
}

/** A fresh parse of the committed seed bundle. */
export function seedBundle(): Obj {
  return JSON.parse(
    readFileSync(
      resolve(process.cwd(), "test", "testdata", "week-bundle.json"),
      "utf8",
    ),
  ) as Obj;
}

/** The directory entry for the test-only directory signer. */
export function countersignerDirectory(): CountersignerDirectoryEntry[] {
  return [
    {
      publicKey: toHex(directorySignerIdentity.publicKey),
      name: "Example Countersigners Ltd",
      logoDataUrl: TEST_PNG_DATA_URL,
      checksRecomputed: 7,
    },
  ];
}

async function countersigned(
  bundle: Obj,
  identity: ReturnType<typeof createEd25519Identity>,
  signedAt: string,
): Promise<Obj> {
  const digest = await bundleDigest(bundle);
  return {
    ...bundle,
    countersignatures: [
      {
        type: "cose-sign1",
        signature: signDigest(digest, identity),
        signed_at: signedAt,
      },
    ],
  };
}

const builders: Record<DerivedFixtureName, () => Promise<Obj>> = {
  // Empty countersignatures[] -> hollow stamp (an *absent* field already
  // hollows via the seed; this exercises the empty-array form explicitly).
  "week-bundle-empty-countersignatures.json": async () => ({
    ...seedBundle(),
    countersignatures: [],
  }),

  // The producer's own key countersigns -> "not independent".
  "week-bundle-producer-countersigned.json": () =>
    countersigned(
      {
        ...seedBundle(),
        extensions: {
          "producer-key/v1": { public_key: toHex(producerIdentity.publicKey) },
        },
      },
      producerIdentity,
      "2026-09-10T00:00:00Z",
    ),

  // A directory-resolved signer (see countersignerDirectory()).
  "week-bundle-directory-countersigned.json": () =>
    countersigned(
      seedBundle(),
      directorySignerIdentity,
      "2026-09-12T00:00:00Z",
    ),

  // A verified signature from neither the producer nor the directory -- the
  // "unresolved" stamp state (shown plainly, not hidden).
  "week-bundle-unresolved-countersigned.json": () =>
    countersigned(seedBundle(), strangerIdentity, "2026-09-13T00:00:00Z"),

  // presentation/v1 with a "VERIFIED" badge image -- the chrome rule test:
  // this must render in the header only, never near the checks.
  "week-bundle-presentation.json": async () => ({
    ...seedBundle(),
    extensions: {
      "presentation/v1": {
        producer_display_name: "Acme Evals",
        logo_data_url: TEST_PNG_DATA_URL,
        title: "VERIFIED",
      },
    },
  }),
};

const cache = new Map<DerivedFixtureName, Promise<Obj>>();

/**
 * The named derived fixture, built once per test worker and reused. The
 * returned object is shared: treat it as read-only, or spread it before
 * editing.
 */
export function derivedFixture(name: DerivedFixtureName): Promise<Obj> {
  let pending = cache.get(name);
  if (pending === undefined) {
    pending = builders[name]();
    cache.set(name, pending);
  }
  return pending;
}
