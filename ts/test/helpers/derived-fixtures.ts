import { readFileSync } from "node:fs";
import { sign as edSign } from "node:crypto";
import { resolve } from "node:path";
// Imported by module (not via src/index.js) so this helper also loads under
// the jsdom test environment, where the emitter's node:fs shell read cannot.
import { bundleDigest } from "../../src/bundle.js";
import { countersignV1SigningInput } from "../../src/countersignature-stamp.js";
import { createEd25519Identity } from "../../src/producer-envelope.js";

/**
 * Derived countersignature-stamp and presentation/v1 fixtures, built at test
 * time from the committed seed `test/testdata/week-bundle.json`.
 *
 * Each derived bundle is the seed plus a small edit (an empty
 * `countersignatures[]`, one countersign/v1 entry over the seed's bundle
 * digest, or a `presentation/v1` block). Committing them would re-check-in
 * the ~50k-line seed five times over, so they are derived here instead,
 * memoised per test worker, and never written to disk.
 *
 * Keys are fixed, clearly test-only seeds (never a production key). The
 * committed `test/testdata/countersigner-directory.json` is a `witnesses.json`
 * in capsule-emit's directory shape naming the directory signer's key;
 * `countersignerDirectory()` derives the same document so a test can assert
 * the two never drift.
 */

type Obj = Record<string, unknown>;

export type DerivedFixtureName =
  | "week-bundle-empty-countersignatures.json"
  | "week-bundle-producer-countersigned.json"
  | "week-bundle-directory-countersigned.json"
  | "week-bundle-unresolved-countersigned.json"
  | "week-bundle-presentation.json";

// 1x1 transparent PNG.
const TEST_PNG_DATA_URL =
  "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=";

const producerIdentity = createEd25519Identity(new Uint8Array(32).fill(11));
const directorySignerIdentity = createEd25519Identity(
  new Uint8Array(32).fill(22),
);
const strangerIdentity = createEd25519Identity(new Uint8Array(32).fill(33));

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}

/** The test directory signer's public key, 64 hex. */
export const DIRECTORY_SIGNER_KEY_ID = toHex(directorySignerIdentity.publicKey);

/** A countersign/v1 statement with one check per result kind the stamp shows. */
export function testStatement(recomputedAt: string): Obj {
  return {
    checks: [
      { name: "chain consistency", result: "established" },
      { name: "range membership", result: "failed" },
      { name: "key hygiene", result: "not present" },
    ],
    recomputed_at: recomputedAt,
    scope: { ledger_id: "ledger:test", closure_depth: 2 },
  };
}

/** Sign a countersign/v1 entry over `over` with a test identity. */
export function countersignV1Entry(
  over: string,
  statement: Obj,
  identity: ReturnType<typeof createEd25519Identity>,
): Obj {
  const signature = edSign(
    null,
    countersignV1SigningInput({ over, statement, type: "countersign/v1" }),
    identity.privateKey,
  );
  return {
    type: "countersign/v1",
    signer: {
      id: "did:web:countersign.example",
      key_id: toHex(identity.publicKey),
    },
    over,
    statement,
    signature: toHex(signature),
  };
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

/** The `witnesses.json` directory naming the test-only directory signer. */
export function countersignerDirectory(): Obj {
  return {
    directory_version: "1",
    witnesses: [],
    countersigners: [
      {
        name: "Example Countersigners Ltd",
        endpoint: "https://countersign.example",
        key_ids: [DIRECTORY_SIGNER_KEY_ID],
        statement_types_issued: ["countersign/v1"],
        since: "2026-09-12",
        independent_of: [],
      },
    ],
  };
}

async function countersigned(
  bundle: Obj,
  identity: ReturnType<typeof createEd25519Identity>,
  recomputedAt: string,
): Promise<Obj> {
  const digest = await bundleDigest(bundle);
  return {
    ...bundle,
    countersignatures: [
      countersignV1Entry(digest, testStatement(recomputedAt), identity),
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
