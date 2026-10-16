// Which DER SubjectPublicKeyInfo values a witness directory counts as keys:
// an Ed25519 key, or an ECDSA P-256 key whose point is on the curve, the
// only keys a receipt verifies under. Checked without WebCrypto, so the
// answer does not depend on the runtime. This mirrors the Python reference's
// check in python/agent_action_capsule/witness.py and
// vectors/bundle/strict/README.md.

const hex = (value: string): Uint8Array =>
  Uint8Array.from(value.match(/../gu)!, (byte) => Number.parseInt(byte, 16));
const equal = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((byte, i) => byte === b[i]);
const big = (bytes: Uint8Array): bigint =>
  bytes.reduce((value, byte) => (value << 8n) | BigInt(byte), 0n);

// AlgorithmIdentifier contents: id-Ed25519 with no parameters, and
// id-ecPublicKey with the named curve prime256v1.
const ED25519_ALGORITHM = hex("06032b6570");
const P256_ALGORITHM = hex("06072a8648ce3d020106082a8648ce3d030107");

// P-256: y^2 = x^3 - 3x + b over GF(p).
const P = 2n ** 256n - 2n ** 224n + 2n ** 192n + 2n ** 96n - 1n;
const B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;

function modPow(base: bigint, exponent: bigint): bigint {
  let result = 1n;
  base %= P;
  while (exponent > 0n) {
    if (exponent & 1n) result = (result * base) % P;
    base = (base * base) % P;
    exponent >>= 1n;
  }
  return result;
}

/** Whether a SEC 1 point (uncompressed or compressed) is on P-256. */
function onP256(point: Uint8Array): boolean {
  const rhs = (x: bigint) => (((x * x * x - 3n * x + B) % P) + P) % P;
  if (point[0] === 0x04 && point.length === 65) {
    const x = big(point.subarray(1, 33)),
      y = big(point.subarray(33));
    return x < P && y < P && (y * y) % P === rhs(x);
  }
  if ((point[0] === 0x02 || point[0] === 0x03) && point.length === 33) {
    const x = big(point.subarray(1));
    if (x >= P) return false;
    // Some y exists when the right-hand side is zero or a quadratic residue
    // (Euler's criterion).
    const value = rhs(x);
    return value === 0n || modPow(value, (P - 1n) / 2n) === 1n;
  }
  return false;
}

/** One DER TLV at `at`: its tag, contents and end, or undefined. */
function element(
  der: Uint8Array,
  at: number,
): { tag: number; body: Uint8Array; end: number } | undefined {
  const tag = der[at],
    first = der[at + 1];
  if (tag === undefined || first === undefined) return undefined;
  let length = first,
    start = at + 2;
  if (first & 0x80) {
    const width = first & 0x7f;
    // DER: the long form only for 128 or more, with no leading zero byte.
    if (width === 0 || width > 3 || der[start] === 0) return undefined;
    length = 0;
    for (let i = 0; i < width; i += 1)
      length = length * 256 + (der[start + i] ?? 0);
    if (length < 128) return undefined;
    start += width;
  }
  const end = start + length;
  return end <= der.length
    ? { tag, body: der.subarray(start, end), end }
    : undefined;
}

/**
 * Whether a witness directory counts `der` as a key: a DER
 * SubjectPublicKeyInfo of an Ed25519 key (any 32 bytes), or of an ECDSA
 * P-256 key whose point is on the curve. Any other key (RSA, secp256k1,
 * P-384, an unknown algorithm) or malformed bytes do not count.
 */
export function directoryKeyCounts(der: Uint8Array): boolean {
  const outer = element(der, 0);
  if (outer?.tag !== 0x30 || outer.end !== der.length) return false;
  const algorithm = element(outer.body, 0);
  if (algorithm?.tag !== 0x30) return false;
  const key = element(outer.body, algorithm.end);
  if (key?.tag !== 0x03 || key.end !== outer.body.length || key.body[0] !== 0)
    return false;
  const bits = key.body.subarray(1);
  if (equal(algorithm.body, ED25519_ALGORITHM)) return bits.length === 32;
  return equal(algorithm.body, P256_ALGORITHM) && onP256(bits);
}
