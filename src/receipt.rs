//! # CVDR (Cryptographically Verifiable Deletion Receipt)
//!
//! Receipt struct definition and `receipt_id` computation.
//! Domain tag: `MKTD02_RECEIPT_V1`
//!
//! The receipt is an **unsigned artifact**. Verification relies on
//! the certified commitment obtained via ICP's certified query
//! mechanism, not a signature on the receipt itself.
//!
//! ## v0.2.0 Changes
//!
//! - Added `protocol_version` (constrained enum → String on wire)
//! - Added `bls_certificate` (Option<Vec<u8>>, populated on finalization)
//! - Added `trust_root_key` (Vec<u8>, NNS root key for offline V2)
//! - Removed `commit_mode` (redundant — MKTd02 is Leaf by definition)
//! - Removed `manifest_hash` (replaced by module_hash → source code path)

use crate::hashing::{hash_with_tag, TAG_RECEIPT};
use candid::{CandidType, Principal};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Protocol Version
// ---------------------------------------------------------------------------

/// Constrained protocol version enum.
///
/// Provides compile-time safety for version strings. The receipt stores
/// the serialised string on the wire (Candid and CBOR), not the enum
/// variant, so verification tooling can parse it without importing
/// this crate.
///
/// **Naming convention:** `mktd02-v{N}` — no "leaf" suffix because
/// MKTd02 is Leaf mode by definition. Tree mode is MKTd03.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolVersion {
    /// v0.2.0 format: manifest_hash removed from deletion_event_hash,
    /// BLS certificate and trust_root_key embedded.
    V2,
}

impl ProtocolVersion {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProtocolVersion::V2 => "mktd02-v2",
        }
    }
}

impl From<ProtocolVersion> for String {
    fn from(v: ProtocolVersion) -> String {
        v.as_str().to_string()
    }
}

impl std::fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Deletion Receipt
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, CandidType)]
pub struct DeletionReceipt {
    /// Protocol version string (e.g. "mktd02-v2"). Tells the verifier
    /// which hash formulas to use.
    pub protocol_version: String,
    pub receipt_id: [u8; 32],
    pub canister_id: Principal,
    pub subnet_id: Principal,
    pub pre_state_hash: [u8; 32],
    pub post_state_hash: [u8; 32],
    pub tombstone_hash: [u8; 32],
    pub deletion_event_hash: [u8; 32],
    pub certified_commitment: [u8; 32],
    pub module_hash: [u8; 32],
    pub timestamp: u64,
    pub nonce: u64,
    /// Raw BLS certificate blob from ic0.data_certificate().
    /// None while receipt is pending finalization; Some after finalization.
    pub bls_certificate: Option<Vec<u8>>,
    /// NNS root public key (96 bytes, BLS12-381). Included so the CVDR
    /// is fully self-contained for offline V2 verification.
    pub trust_root_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, CandidType)]
pub struct ReceiptSummary {
    pub receipt_id: [u8; 32],
    pub canister_id: Principal,
    pub protocol_version: String,
    pub timestamp: u64,
    pub nonce: u64,
    pub state_changed: bool,
}

impl From<&DeletionReceipt> for ReceiptSummary {
    fn from(r: &DeletionReceipt) -> Self {
        Self {
            receipt_id: r.receipt_id,
            canister_id: r.canister_id,
            protocol_version: r.protocol_version.clone(),
            timestamp: r.timestamp,
            nonce: r.nonce,
            state_changed: r.pre_state_hash != r.post_state_hash,
        }
    }
}

/// Compute a receipt ID.
///
/// `receipt_id = SHA-256(MKTD02_RECEIPT_V1 || canister_id_bytes || nonce_be_bytes)`
pub fn compute_receipt_id(canister_id: &Principal, nonce: u64) -> [u8; 32] {
    hash_with_tag(TAG_RECEIPT, &[canister_id.as_slice(), &nonce.to_be_bytes()])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_id_deterministic() {
        let c = Principal::from_text("aaaaa-aa").unwrap();
        assert_eq!(compute_receipt_id(&c, 1), compute_receipt_id(&c, 1));
    }

    #[test]
    fn receipt_id_different_nonces_differ() {
        let c = Principal::from_text("aaaaa-aa").unwrap();
        assert_ne!(compute_receipt_id(&c, 1), compute_receipt_id(&c, 2));
    }

    #[test]
    fn receipt_id_different_canisters_differ() {
        let c1 = Principal::from_text("aaaaa-aa").unwrap();
        let c2 = Principal::from_text("2vxsx-fae").unwrap();
        assert_ne!(compute_receipt_id(&c1, 1), compute_receipt_id(&c2, 1));
    }

    #[test]
    fn receipt_summary_from_receipt() {
        let c = Principal::from_text("aaaaa-aa").unwrap();
        let r = DeletionReceipt {
            protocol_version: ProtocolVersion::V2.into(),
            receipt_id: [1u8; 32], canister_id: c,
            subnet_id: Principal::from_text("2vxsx-fae").unwrap(),
            pre_state_hash: [2u8; 32], post_state_hash: [3u8; 32],
            tombstone_hash: [4u8; 32], deletion_event_hash: [5u8; 32],
            certified_commitment: [6u8; 32],
            module_hash: [8u8; 32], timestamp: 1_000_000, nonce: 1,
            bls_certificate: None,
            trust_root_key: vec![],
        };
        let s = ReceiptSummary::from(&r);
        assert!(s.state_changed);
        assert_eq!(s.protocol_version, "mktd02-v2");
    }

    #[test]
    fn receipt_summary_state_unchanged_when_equal() {
        let c = Principal::from_text("aaaaa-aa").unwrap();
        let r = DeletionReceipt {
            protocol_version: ProtocolVersion::V2.into(),
            receipt_id: [1u8; 32], canister_id: c,
            subnet_id: Principal::from_text("2vxsx-fae").unwrap(),
            pre_state_hash: [2u8; 32], post_state_hash: [2u8; 32],
            tombstone_hash: [4u8; 32], deletion_event_hash: [5u8; 32],
            certified_commitment: [6u8; 32],
            module_hash: [8u8; 32], timestamp: 1_000_000, nonce: 1,
            bls_certificate: None,
            trust_root_key: vec![],
        };
        let s = ReceiptSummary::from(&r);
        assert!(!s.state_changed);
    }

    #[test]
    fn golden_receipt_id() {
        // aaaaa-aa (management canister), nonce = 1
        // Formula unchanged from v0.1.x — receipt_id does not depend on
        // manifest_hash or commit_mode.
        let c = Principal::from_text("aaaaa-aa").unwrap();
        let id = compute_receipt_id(&c, 1);
        assert_eq!(
            hex::encode(id),
            "1f213a0f2bf4992071a7f23e72d1942e564a4e871e3decce8ac8ee27d08f534b",
            "receipt_id derivation changed — this breaks all existing receipts"
        );
    }

    #[test]
    fn protocol_version_serialises_correctly() {
        assert_eq!(ProtocolVersion::V2.as_str(), "mktd02-v2");
        let s: String = ProtocolVersion::V2.into();
        assert_eq!(s, "mktd02-v2");
        assert_eq!(format!("{}", ProtocolVersion::V2), "mktd02-v2");
    }
}
