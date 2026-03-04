//! # Tombstone Constant
//!
//! `TOMBSTONE_CONSTANT: [u8; 32] = SHA-256("MKTD_TOMBSTONE_V1")`
//!
//! This is the value written to each PII field during tombstoning.
//! It is a well-known, deterministic value that any verifier can
//! independently recompute from the published seed string.
//!
//! **This is NOT a domain separation tag.** It is the actual bytes
//! that replace PII data in storage. Do not confuse with
//! `MKTD02_TOMBSTONE_HASH_V1` (the domain tag for the receipt's
//! `tombstone_hash` field).

use crate::hashing::{sha256, TOMBSTONE_SEED};

/// The tombstone constant: the exact 32 bytes written to every PII
/// field when a canister is tombstoned.
///
/// Computed as `SHA-256("MKTD_TOMBSTONE_V1")`. Any verifier can
/// independently derive this value to confirm a field has been
/// tombstoned.
pub static TOMBSTONE_CONSTANT: std::sync::LazyLock<[u8; 32]> =
    std::sync::LazyLock::new(|| sha256(TOMBSTONE_SEED));

/// Returns a reference to the tombstone constant bytes.
pub fn tombstone_constant() -> &'static [u8; 32] {
    &TOMBSTONE_CONSTANT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tombstone_constant_is_32_bytes() {
        assert_eq!(tombstone_constant().len(), 32);
    }

    #[test]
    fn tombstone_constant_is_deterministic() {
        let a = *tombstone_constant();
        let b = sha256(b"MKTD_TOMBSTONE_V1");
        assert_eq!(a, b);
    }

    #[test]
    fn tombstone_constant_is_not_zero() {
        assert_ne!(*tombstone_constant(), [0u8; 32]);
    }

    #[test]
    fn tombstone_constant_not_confused_with_domain_tag() {
        let seed_hash = sha256(b"MKTD_TOMBSTONE_V1");
        let tag_hash = sha256(b"MKTD02_TOMBSTONE_HASH_V1");
        assert_ne!(seed_hash, tag_hash, "constant and domain tag must differ");
    }
}
