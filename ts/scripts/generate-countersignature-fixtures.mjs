#!/usr/bin/env node
// Generates the countersignature-stamp test fixtures from week-bundle.json.
// Run after `npm run build` (uses the compiled dist output for the exact
// bundle-digest and COSE_Sign1 wire logic the library ships).
import { readFileSync, writeFileSync } from "node:fs";
import { sign as edSign } from "node:crypto";
import { resolve } from "node:path";
import { bundleDigest, createEd25519Identity } from "../dist/index.js";
import {
  encodeProducerEnvelope,
  hexToBytes,
  producerEnvelopeSigningBytes,
  protectedHeadersFor,
} from "../dist/producer-envelope-wire.js";

const BUNDLE_DIGEST_CONTENT_TYPE =
  "application/agent-action-capsule-bundle-digest";

function toBase64Url(bytes) {
  return Buffer.from(bytes)
    .toString("base64")
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
}

function toHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}

function signDigest(digestHex, identity) {
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

const testdata = resolve(import.meta.dirname, "..", "test", "testdata");
const base = JSON.parse(
  readFileSync(resolve(testdata, "week-bundle.json"), "utf8"),
);

// Fixed, clearly test-only seeds (never a production key).
const producerIdentity = createEd25519Identity(new Uint8Array(32).fill(11));
const directorySignerIdentity = createEd25519Identity(
  new Uint8Array(32).fill(22),
);
const strangerIdentity = createEd25519Identity(new Uint8Array(32).fill(33));

// --- Fixture: empty countersignatures[] -> hollow stamp (the gap the
// review found: an *absent* field already hollows via week-bundle.json;
// this exercises the empty-array form explicitly). ---
writeFileSync(
  resolve(testdata, "week-bundle-empty-countersignatures.json"),
  `${JSON.stringify({ ...base, countersignatures: [] }, null, 2)}\n`,
);

// --- Fixture: producer's own key countersigns -> "not independent". ---
{
  const bundle = {
    ...base,
    extensions: {
      "producer-key/v1": {
        public_key: toHex(producerIdentity.publicKey),
      },
    },
  };
  const digest = await bundleDigest(bundle);
  const countersignatures = [
    {
      type: "cose-sign1",
      signature: signDigest(digest, producerIdentity),
      signed_at: "2026-09-10T00:00:00Z",
    },
  ];
  writeFileSync(
    resolve(testdata, "week-bundle-producer-countersigned.json"),
    `${JSON.stringify({ ...bundle, countersignatures }, null, 2)}\n`,
  );
}

// --- Fixture: a directory-resolved signer, plus a stub directory file. ---
{
  const digest = await bundleDigest(base);
  const countersignatures = [
    {
      type: "cose-sign1",
      signature: signDigest(digest, directorySignerIdentity),
      signed_at: "2026-09-12T00:00:00Z",
    },
  ];
  writeFileSync(
    resolve(testdata, "week-bundle-directory-countersigned.json"),
    `${JSON.stringify({ ...base, countersignatures }, null, 2)}\n`,
  );
  const directory = [
    {
      publicKey: toHex(directorySignerIdentity.publicKey),
      name: "Example Countersigners Ltd",
      logoDataUrl:
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=",
      checksRecomputed: 7,
    },
  ];
  writeFileSync(
    resolve(testdata, "countersigner-directory.json"),
    `${JSON.stringify(directory, null, 2)}\n`,
  );
}

// --- Fixture: a verified signature from neither the producer nor the
// directory -- the "unresolved" stamp state (shown plainly, not hidden). ---
{
  const digest = await bundleDigest(base);
  const countersignatures = [
    {
      type: "cose-sign1",
      signature: signDigest(digest, strangerIdentity),
      signed_at: "2026-09-13T00:00:00Z",
    },
  ];
  writeFileSync(
    resolve(testdata, "week-bundle-unresolved-countersigned.json"),
    `${JSON.stringify({ ...base, countersignatures }, null, 2)}\n`,
  );
}

// --- Fixture: presentation/v1 with a "VERIFIED" badge image -- the chrome
// rule test: this must render in the header only, never near the checks. ---
{
  const bundle = {
    ...base,
    extensions: {
      "presentation/v1": {
        producer_display_name: "Acme Evals",
        logo_data_url:
          "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=",
        title: "VERIFIED",
      },
    },
  };
  writeFileSync(
    resolve(testdata, "week-bundle-presentation.json"),
    `${JSON.stringify(bundle, null, 2)}\n`,
  );
}

console.log("wrote countersignature-stamp and presentation/v1 fixtures");
