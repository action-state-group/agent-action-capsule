import {
  createPrivateKey,
  createPublicKey,
  sign as edSign,
  type KeyObject,
} from "node:crypto";
import {
  concat,
  encodeProducerEnvelope,
  equalBytes,
  hex64,
  hexToBytes,
  producerEnvelopeSigningBytes,
  producerProtectedHeaders,
} from "./producer-envelope-wire.js";
import type { SigningIdentity } from "./types.js";

export { verifyProducerEnvelope } from "./producer-envelope-verification.js";

const pkcs8Prefix = hexToBytes("302e020100300506032b657004220420");

/** Construct an immutable Ed25519 identity from a 32-byte seed or PKCS#8 key. */
export function createEd25519Identity(
  privateKey: Uint8Array | KeyObject,
): SigningIdentity {
  const key =
    privateKey instanceof Uint8Array
      ? createPrivateKey({
          key: Buffer.from(concat(pkcs8Prefix, privateKey)),
          format: "der",
          type: "pkcs8",
        })
      : privateKey;
  if (key.asymmetricKeyType !== "ed25519")
    throw new TypeError("Producer Envelope signer must use Ed25519");
  const der = createPublicKey(key).export({ format: "der", type: "spki" });
  const publicKey = new Uint8Array(der.subarray(der.length - 32));
  return Object.freeze({ privateKey: key, publicKey });
}

export function createSigningIdentity(
  privateKey: KeyObject,
  rawPublicKey: Uint8Array,
): SigningIdentity {
  if (privateKey.asymmetricKeyType !== "ed25519" || rawPublicKey.length !== 32)
    throw new TypeError("valid Ed25519 key pair required");
  const derived = createEd25519Identity(privateKey);
  if (!equalBytes(derived.publicKey, rawPublicKey))
    throw new TypeError("signer does not match public key");
  return Object.freeze({
    privateKey,
    publicKey: Uint8Array.from(rawPublicKey),
  });
}

export function signCapsuleId(
  capsuleId: string,
  identity: SigningIdentity,
): Uint8Array {
  if (!hex64.test(capsuleId))
    throw new TypeError(
      "Capsule ID must be 64 lowercase hexadecimal characters",
    );
  if (
    identity.publicKey.length !== 32 ||
    identity.privateKey.asymmetricKeyType !== "ed25519"
  )
    throw new TypeError("valid Ed25519 signing identity is required");
  const payload = hexToBytes(capsuleId);
  const protectedBytes = producerProtectedHeaders(identity.publicKey);
  const signature = edSign(
    null,
    producerEnvelopeSigningBytes(protectedBytes, payload),
    identity.privateKey,
  );
  return encodeProducerEnvelope(protectedBytes, payload, signature);
}
