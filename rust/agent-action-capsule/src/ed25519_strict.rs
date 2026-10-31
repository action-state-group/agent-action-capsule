//! The strict Ed25519 conditions shared by every path that verifies an
//! Ed25519 signature under a stated or pinned key (the witness receipts and
//! the Bundle -02 `category_coverage` signature), so one rule covers both.

/// Whether a 32-byte point encoding has y < p (RFC 8032 section 5.1.3).
fn canonical_point(encoded: &[u8; 32]) -> bool {
    !(encoded[0] >= 0xed && encoded[1..31].iter().all(|&b| b == 0xff) && encoded[31] & 0x7f == 0x7f)
}

/// Whether a point encoding decodes to a point of small order.
fn small_order(encoded: &[u8; 32]) -> bool {
    ed25519_dalek::VerifyingKey::from_bytes(encoded).is_ok_and(|point| point.is_weak())
}

/// The Ed25519 group order L, little-endian.
const ED25519_L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

/// The strict Ed25519 conditions of checkpointed-local-log's
/// `ed25519-vectors.json` that do not need the message: A and R canonical
/// (y < p) and not of small order, and S < L. scitt-cose-receipt 0.1.1
/// verifies with dalek's `verify`, which checks the same cofactorless
/// equation as `verify_strict` but accepts a small-order A, and a small-order
/// A verifies a forged signature over any message. Refusing these first makes
/// that check strict.
pub(crate) fn strict_ed25519(public_key: &[u8; 32], signature: &[u8]) -> bool {
    let Ok(signature) = <&[u8; 64]>::try_from(signature) else {
        return false;
    };
    let r: &[u8; 32] = signature[..32].try_into().expect("32 bytes");
    let s_below_l = signature[32..]
        .iter()
        .rev()
        .zip(ED25519_L.iter().rev())
        .find(|(s, l)| s != l)
        .is_some_and(|(s, l)| s < l);
    canonical_point(public_key)
        && canonical_point(r)
        && !small_order(public_key)
        && !small_order(r)
        && s_below_l
}
