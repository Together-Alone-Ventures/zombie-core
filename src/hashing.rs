//! # Hashing Primitives & Domain Separation
//!
//! SHA-256 wrapper, domain separation tags, and byte concatenation helpers.
//!
//! ## Naming Convention Table
//!
//! | Name                       | Kind           | Purpose                                      | Used in          |
//! |----------------------------|----------------|----------------------------------------------|------------------|
//! | MKTD_TOMBSTONE_V1          | Constant seed  | Seed for TOMBSTONE_CONSTANT (bytes written)   | tombstone.rs     |
//! | MKTD02_TOMBSTONE_HASH_V1   | Domain tag     | Tag for tombstone_hash in receipt             | engine.rs        |
//! | MKTD02_EVENT_V1            | Domain tag     | Tag for deletion_event_hash                   | engine.rs        |
//! | MKTD02_CERTIFIED_V1        | Domain tag     | Tag for certified_commitment                  | certified.rs     |
//! | MKTD02_RECEIPT_V1          | Domain tag     | Tag for receipt_id derivation                 | receipt.rs       |
//! | MKTD02_SALT_V1             | Domain tag     | Tag for per-canister salt derivation          | state.rs         |
//! | MKTD02_MANIFEST_V1         | Domain tag     | Tag for manifest_hash computation             | manifest.rs      |
//!
//! **Key distinction:** The tombstone constant is a *value written to storage*;
//! domain tags are *prefixes for hash computations*. They must never be confused.

use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Constant seed (used to derive a stored value, NOT a hash prefix)
// ---------------------------------------------------------------------------

/// Seed string for the tombstone constant. The actual constant is
/// SHA-256(TOMBSTONE_SEED) -- see tombstone module.
pub const TOMBSTONE_SEED: &[u8] = b"MKTD_TOMBSTONE_V1";

// ---------------------------------------------------------------------------
// Domain separation tags (used as prefixes in hash computations)
// ---------------------------------------------------------------------------

/// A domain separation tag. Wraps a static byte slice to enforce
/// tag-first ordering in hash computations via [`hash_with_tag`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainTag(pub &'static [u8]);

/// Domain tag for tombstone_hash field in the deletion receipt.
pub const TAG_TOMBSTONE_HASH: DomainTag = DomainTag(b"MKTD02_TOMBSTONE_HASH_V1");

/// Domain tag for deletion_event_hash.
pub const TAG_EVENT: DomainTag = DomainTag(b"MKTD02_EVENT_V1");

/// Domain tag for certified_commitment.
pub const TAG_CERTIFIED: DomainTag = DomainTag(b"MKTD02_CERTIFIED_V1");

/// Domain tag for receipt_id derivation.
pub const TAG_RECEIPT: DomainTag = DomainTag(b"MKTD02_RECEIPT_V1");

/// Domain tag for per-canister salt derivation.
pub const TAG_SALT: DomainTag = DomainTag(b"MKTD02_SALT_V1");

/// Domain tag for manifest_hash computation.
pub const TAG_MANIFEST: DomainTag = DomainTag(b"MKTD02_MANIFEST_V1");

// ---------------------------------------------------------------------------
// SHA-256 wrapper
// ---------------------------------------------------------------------------

/// Compute SHA-256 of a single byte slice.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute a domain-separated hash: `SHA-256(tag || part_0 || part_1 || ...)`.
///
/// The [`DomainTag`] newtype enforces that the tag is always the first
/// element in the hash preimage, preventing accidental misordering.
pub fn hash_with_tag(tag: DomainTag, parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(tag.0);
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// Compute SHA-256 of multiple byte slices concatenated in order
///
/// **Prefer [`hash_with_tag`] for domain-separated hashes.** This
/// function is for cases without a domain tag (e.g., salt || state_bytes).
pub fn sha256_concat(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// A zero-filled 32-byte hash, used as the initial value for
/// deletion_event_hash before any deletion has occurred.
pub const ZERO_HASH: [u8; 32] = [0u8; 32];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_deterministic() {
        let a = sha256(b"hello");
        let b = sha256(b"hello");
        assert_eq!(a, b);
    }

    #[test]
    fn sha256_different_inputs_differ() {
        let a = sha256(b"hello");
        let b = sha256(b"world");
        assert_ne!(a, b);
    }

    #[test]
    fn sha256_known_vector() {
        let empty = sha256(b"");
        assert_eq!(
            hex::encode(empty),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn hash_with_tag_matches_concat() {
        let via_tag = hash_with_tag(TAG_EVENT, &[b"data"]);
        let via_concat = sha256_concat(&[TAG_EVENT.0, b"data"]);
        assert_eq!(via_tag, via_concat);
    }

    #[test]
    fn hash_with_tag_order_matters() {
        let ab = hash_with_tag(TAG_EVENT, &[b"a", b"b"]);
        let ba = hash_with_tag(TAG_EVENT, &[b"b", b"a"]);
        assert_ne!(ab, ba);
    }

    #[test]
    fn domain_tags_are_distinct() {
        let tags: &[DomainTag] = &[
            TAG_TOMBSTONE_HASH,
            TAG_EVENT,
            TAG_CERTIFIED,
            TAG_RECEIPT,
            TAG_SALT,
            TAG_MANIFEST,
        ];
        for (i, a) in tags.iter().enumerate() {
            for (j, b) in tags.iter().enumerate() {
                if i != j {
                    assert_ne!(a.0, b.0, "tags at index {} and {} collide", i, j);
                }
            }
        }
    }

    #[test]
    fn tombstone_seed_differs_from_all_tags() {
        let tags: &[DomainTag] = &[
            TAG_TOMBSTONE_HASH,
            TAG_EVENT,
            TAG_CERTIFIED,
            TAG_RECEIPT,
            TAG_SALT,
            TAG_MANIFEST,
        ];
        for tag in tags {
            assert_ne!(TOMBSTONE_SEED, tag.0);
        }
    }

    #[test]
    fn zero_hash_is_zero() {
        assert_eq!(ZERO_HASH, [0u8; 32]);
    }
    // ---------------------------------------------------------------
    // Golden vectors — lock down exact hash outputs.
    // Computed independently via Python hashlib. Any change here
    // means the protocol has changed and all existing CVDRs break.
    // ---------------------------------------------------------------

    #[test]
    fn golden_tombstone_seed() {
        let tombstone = sha256(TOMBSTONE_SEED);
        assert_eq!(
            hex::encode(tombstone),
            "485a0cf91d7feb0f97f428df6328feca93788456a5b614b1bcedf6c4dc0e8d2a",
            "tombstone constant changed — this breaks all existing tombstones"
        );
    }

    #[test]
    fn golden_tag_tombstone_hash() {
        assert_eq!(
            hex::encode(hash_with_tag(TAG_TOMBSTONE_HASH, &[b"test"])),
            "1d458fe278607fd548c30148ffd8eb9fba8c132cc9b1ec5039b7c973ef3bd322"
        );
    }

    #[test]
    fn golden_tag_event() {
        assert_eq!(
            hex::encode(hash_with_tag(TAG_EVENT, &[b"test"])),
            "6393c15cb2820d70e84c82c0928fccf15792cb3f79bb0783a78eb050260a977f"
        );
    }

    #[test]
    fn golden_tag_certified() {
        assert_eq!(
            hex::encode(hash_with_tag(TAG_CERTIFIED, &[b"test"])),
            "b2a533ef0b75007545bda617076df5a8694db1e3f6ae0c3050b45b81d0cfcf5c"
        );
    }

    #[test]
    fn golden_tag_receipt() {
        assert_eq!(
            hex::encode(hash_with_tag(TAG_RECEIPT, &[b"test"])),
            "b5acde122055eed7a27d1af0e0d6cf510b8afa1532c4383193587e3c57001b15"
        );
    }

    #[test]
    fn golden_tag_salt() {
        assert_eq!(
            hex::encode(hash_with_tag(TAG_SALT, &[b"test"])),
            "59c364395836b540971fcc4021eaf977deaf174d6eb87b2da68b30e46df66b4a"
        );
    }

    #[test]
    fn golden_tag_manifest() {
        assert_eq!(
            hex::encode(hash_with_tag(TAG_MANIFEST, &[b"test"])),
            "158e49fbae2d7356adccead6973a51722c587a935fdbda455592a1dbb8bc31f2"
        );
    }
    /// Golden vector for v0.2.0 deletion_event_hash formula.
    /// Inputs: pre_state=[1;32], post_state=[2;32], timestamp=1_000_000,
    /// module_hash=[3;32], nonce=1. Note: NO manifest_hash in preimage.
    /// Computed independently via Python hashlib.
    #[test]
    fn golden_deletion_event_hash_v2() {
        let pre_state = [1u8; 32];
        let post_state = [2u8; 32];
        let timestamp = 1_000_000u64.to_be_bytes();
        let module_hash = [3u8; 32];
        let nonce = 1u64.to_be_bytes();

        let result = hash_with_tag(
            TAG_EVENT,
            &[&pre_state, &post_state, &timestamp, &module_hash, &nonce],
        );

        assert_eq!(
            hex::encode(result),
            "9078d9a080606b46298bd9d66d3dd4a75389b04f7531b53a3a0e7c8f25955023",
            "v0.2.0 deletion_event_hash formula changed — manifest_hash must NOT be in preimage"
        );
    }
}
