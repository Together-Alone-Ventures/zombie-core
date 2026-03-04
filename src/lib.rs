//! # zombie-core
//!
//! Shared types, hashing primitives, and receipt structures for the
//! Zombie Delete CVDR (Cryptographically Verifiable Deletion Receipt) system.
//!
//! This crate is **pure Rust** with zero ICP dependencies. It compiles and
//! tests on native targets (`cargo test -p zombie-core`).

pub mod hashing;
pub mod manifest;
pub mod receipt;
pub mod serialisation;
pub mod tombstone;

pub use hashing::{sha256, sha256_concat, ZERO_HASH};
pub use manifest::{compute_manifest_hash, FieldDescriptor};
pub use receipt::{compute_receipt_id, DeletionReceipt, ProtocolVersion, ReceiptSummary};
pub use serialisation::{decode_pii_state, encode_pii_state, SerialisationError};
pub use tombstone::{tombstone_constant, TOMBSTONE_CONSTANT};
