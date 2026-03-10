//! # CVDR (Cryptographically Verifiable Deletion Receipt)
//!
//! Receipt struct definition and `receipt_id` computation.
//! Domain tags:
//! - v2: `MKTD02_RECEIPT_V1`
//! - v3: `MKTD02_RECEIPT_V3`
//!
//! The receipt is an **unsigned artifact**. Verification relies on
//! the certified commitment obtained via ICP's certified query
//! mechanism, not a signature on the receipt itself.
//!
//! ## v0.2.0 Changes
//!
//! - Added `protocol_version` (constrained enum -> String on wire)
//! - Added `bls_certificate` (Option<Vec<u8>>, populated on finalization)
//! - Added `trust_root_key_id` (String, identifies NNS key from zombie-core allowlist)
//! - Removed `commit_mode` (redundant - MKTd02 is Leaf by definition)
//! - Removed `manifest_hash` (replaced by module_hash -> source code path)
//! - Removed `trust_root_key: Vec<u8>` (replaced by `trust_root_key_id`)
//!
//! ## trust_root_key_id Design
//!
//! Instead of embedding 96 raw key bytes in every receipt, the receipt stores
//! a compact identifier (e.g. `"mainnet"`) that references a key in
//! `zombie_core::nns_keys`. Verifiers look up the actual bytes there.
//! This keeps the receipt compact while ensuring verifiers always use the
//! key that was current when the receipt was issued -- critical for
//! historical verification after any future NNS key rotation.

use crate::hashing::{hash_with_tag, TAG_RECEIPT, TAG_RECEIPT_V3};
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
/// **Naming convention:** `mktd02-v{N}` - no "leaf" suffix because
/// MKTd02 is Leaf mode by definition. Tree mode is MKTd03.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolVersion {
    /// v0.2.0 format: manifest_hash removed from deletion_event_hash,
    /// BLS certificate embedded, trust_root_key_id references allowlist.
    V2,
    /// v0.3.0 format: adds `record_id`, removes `subnet_id`, renames
    /// `nonce` to `deletion_seq`, and uses length-delimited v3 receipt_id.
    V3,
}

impl ProtocolVersion {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProtocolVersion::V2 => "mktd02-v2",
            ProtocolVersion::V3 => "mktd02-v3",
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
#[serde(from = "DeletionReceiptWire")]
pub struct DeletionReceipt {
    /// Protocol version string (e.g. "mktd02-v3"). Tells the verifier
    /// which hash formulas to use.
    pub protocol_version: String,
    pub receipt_id: [u8; 32],
    pub canister_id: Principal,
    /// In MKTd02 leaf mode this is the deleted subject principal bytes.
    /// For legacy v2 receipts, this decodes as an empty vector.
    pub record_id: Vec<u8>,
    pub pre_state_hash: [u8; 32],
    pub post_state_hash: [u8; 32],
    pub tombstone_hash: [u8; 32],
    pub deletion_event_hash: [u8; 32],
    pub certified_commitment: [u8; 32],
    pub module_hash: [u8; 32],
    pub timestamp: u64,
    pub deletion_seq: u64,
    /// Raw BLS certificate blob from ic0.data_certificate().
    /// None while receipt is pending finalization; Some after finalization.
    pub bls_certificate: Option<Vec<u8>>,
    /// Identifies the NNS root key used to sign the BLS certificate.
    /// Look up the actual key bytes via `zombie_core::nns_keys::lookup_key(id)`.
    ///
    /// Empty string for pending receipts (populated during finalization).
    /// For all mainnet receipts: `"mainnet"`.
    /// For local-dev receipts: `"local-dev"` (requires `local-replica` feature).
    pub trust_root_key_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, CandidType)]
pub struct ReceiptSummary {
    pub receipt_id: [u8; 32],
    pub canister_id: Principal,
    pub protocol_version: String,
    pub timestamp: u64,
    pub deletion_seq: u64,
    pub state_changed: bool,
}

impl From<&DeletionReceipt> for ReceiptSummary {
    fn from(r: &DeletionReceipt) -> Self {
        Self {
            receipt_id: r.receipt_id,
            canister_id: r.canister_id,
            protocol_version: r.protocol_version.clone(),
            timestamp: r.timestamp,
            deletion_seq: r.deletion_seq,
            state_changed: r.pre_state_hash != r.post_state_hash,
        }
    }
}

/// Compute a v3 receipt ID.
///
/// `receipt_id = SHA-256(
///   MKTD02_RECEIPT_V3 ||
///   u32_be(len(canister_id_bytes)) || canister_id_bytes ||
///   u32_be(len(record_id_bytes))   || record_id_bytes   ||
///   u64_be(deletion_seq)
/// )`
pub fn compute_receipt_id(
    canister_id: &Principal,
    record_id: &[u8],
    deletion_seq: u64,
) -> [u8; 32] {
    let canister_bytes = canister_id.as_slice();
    let canister_len = (canister_bytes.len() as u32).to_be_bytes();
    let record_len = (record_id.len() as u32).to_be_bytes();
    let deletion_seq_be = deletion_seq.to_be_bytes();

    hash_with_tag(
        TAG_RECEIPT_V3,
        &[
            &canister_len,
            canister_bytes,
            &record_len,
            record_id,
            &deletion_seq_be,
        ],
    )
}

/// Compute a legacy v2 receipt ID for backward-compatible verification.
///
/// `receipt_id = SHA-256(MKTD02_RECEIPT_V1 || canister_id_bytes || nonce_be_bytes)`
pub fn compute_receipt_id_v2(canister_id: &Principal, nonce: u64) -> [u8; 32] {
    hash_with_tag(TAG_RECEIPT, &[canister_id.as_slice(), &nonce.to_be_bytes()])
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
enum DeletionReceiptWire {
    V3(DeletionReceiptV3Wire),
    V2(DeletionReceiptV2Wire),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DeletionReceiptV3Wire {
    protocol_version: String,
    receipt_id: [u8; 32],
    canister_id: Principal,
    record_id: Vec<u8>,
    pre_state_hash: [u8; 32],
    post_state_hash: [u8; 32],
    tombstone_hash: [u8; 32],
    deletion_event_hash: [u8; 32],
    certified_commitment: [u8; 32],
    module_hash: [u8; 32],
    timestamp: u64,
    deletion_seq: u64,
    #[serde(default)]
    bls_certificate: Option<Vec<u8>>,
    #[serde(default)]
    trust_root_key_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DeletionReceiptV2Wire {
    protocol_version: String,
    receipt_id: [u8; 32],
    canister_id: Principal,
    subnet_id: Principal,
    pre_state_hash: [u8; 32],
    post_state_hash: [u8; 32],
    tombstone_hash: [u8; 32],
    deletion_event_hash: [u8; 32],
    certified_commitment: [u8; 32],
    module_hash: [u8; 32],
    timestamp: u64,
    nonce: u64,
    #[serde(default)]
    bls_certificate: Option<Vec<u8>>,
    #[serde(default)]
    trust_root_key_id: String,
}

impl From<DeletionReceiptWire> for DeletionReceipt {
    fn from(value: DeletionReceiptWire) -> Self {
        match value {
            DeletionReceiptWire::V3(v3) => Self {
                protocol_version: v3.protocol_version,
                receipt_id: v3.receipt_id,
                canister_id: v3.canister_id,
                record_id: v3.record_id,
                pre_state_hash: v3.pre_state_hash,
                post_state_hash: v3.post_state_hash,
                tombstone_hash: v3.tombstone_hash,
                deletion_event_hash: v3.deletion_event_hash,
                certified_commitment: v3.certified_commitment,
                module_hash: v3.module_hash,
                timestamp: v3.timestamp,
                deletion_seq: v3.deletion_seq,
                bls_certificate: v3.bls_certificate,
                trust_root_key_id: v3.trust_root_key_id,
            },
            DeletionReceiptWire::V2(v2) => Self {
                protocol_version: v2.protocol_version,
                receipt_id: v2.receipt_id,
                canister_id: v2.canister_id,
                record_id: Vec::new(),
                pre_state_hash: v2.pre_state_hash,
                post_state_hash: v2.post_state_hash,
                tombstone_hash: v2.tombstone_hash,
                deletion_event_hash: v2.deletion_event_hash,
                certified_commitment: v2.certified_commitment,
                module_hash: v2.module_hash,
                timestamp: v2.timestamp,
                deletion_seq: v2.nonce,
                bls_certificate: v2.bls_certificate,
                trust_root_key_id: v2.trust_root_key_id,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_receipt() -> DeletionReceipt {
        DeletionReceipt {
            protocol_version: ProtocolVersion::V3.into(),
            receipt_id: [1u8; 32],
            canister_id: Principal::from_text("aaaaa-aa").unwrap(),
            record_id: vec![7u8, 8u8, 9u8],
            pre_state_hash: [2u8; 32],
            post_state_hash: [3u8; 32],
            tombstone_hash: [4u8; 32],
            deletion_event_hash: [5u8; 32],
            certified_commitment: [6u8; 32],
            module_hash: [8u8; 32],
            timestamp: 1_000_000,
            deletion_seq: 1,
            bls_certificate: None,
            // Finalized receipt: bls_certificate = None here only for test brevity,
            // but trust_root_key_id reflects a finalized state.
            trust_root_key_id: String::from("mainnet"),
        }
    }

    #[test]
    fn receipt_id_deterministic() {
        let c = Principal::from_text("aaaaa-aa").unwrap();
        let record_id = vec![1, 2, 3];
        assert_eq!(
            compute_receipt_id(&c, &record_id, 1),
            compute_receipt_id(&c, &record_id, 1)
        );
    }

    #[test]
    fn receipt_id_different_deletion_seq_values_differ() {
        let c = Principal::from_text("aaaaa-aa").unwrap();
        let record_id = vec![1, 2, 3];
        assert_ne!(
            compute_receipt_id(&c, &record_id, 1),
            compute_receipt_id(&c, &record_id, 2)
        );
    }

    #[test]
    fn receipt_id_different_canister_bytes_differ() {
        let c1 = Principal::from_text("aaaaa-aa").unwrap();
        let c2 = Principal::from_text("2vxsx-fae").unwrap();
        let record_id = vec![1, 2, 3];
        assert_ne!(
            compute_receipt_id(&c1, &record_id, 1),
            compute_receipt_id(&c2, &record_id, 1)
        );
    }

    #[test]
    fn receipt_id_different_record_ids_differ() {
        let c = Principal::from_text("aaaaa-aa").unwrap();
        assert_ne!(
            compute_receipt_id(&c, &[1, 2, 3], 1),
            compute_receipt_id(&c, &[1, 2, 4], 1)
        );
    }

    #[test]
    fn receipt_summary_from_receipt() {
        let r = test_receipt();
        let s = ReceiptSummary::from(&r);
        assert!(s.state_changed);
        assert_eq!(s.protocol_version, "mktd02-v3");
        assert_eq!(s.deletion_seq, 1);
    }

    #[test]
    fn receipt_summary_state_unchanged_when_equal() {
        let mut r = test_receipt();
        r.post_state_hash = r.pre_state_hash;
        let s = ReceiptSummary::from(&r);
        assert!(!s.state_changed);
    }

    #[test]
    fn golden_receipt_id_v3_with_u32_length_prefixes() {
        // canister bytes = [1,2,3,4], record_id bytes = [10,11,12], deletion_seq = 7
        // Preimage bytes:
        // 00000004 || 01020304 || 00000003 || 0a0b0c || 0000000000000007
        let c = Principal::from_slice(&[1, 2, 3, 4]);
        let id = compute_receipt_id(&c, &[10, 11, 12], 7);
        assert_eq!(
            hex::encode(id),
            "231bca0d2351bb588bae612eab8ea46810097294dcd98cfbc4ae3045fdced09d",
            "v3 receipt_id derivation changed - this breaks v0.3 receipts"
        );
    }

    #[test]
    fn golden_receipt_id_v2_still_stable() {
        let c = Principal::from_text("aaaaa-aa").unwrap();
        let id = compute_receipt_id_v2(&c, 1);
        assert_eq!(
            hex::encode(id),
            "1f213a0f2bf4992071a7f23e72d1942e564a4e871e3decce8ac8ee27d08f534b",
            "v2 receipt_id derivation changed - this breaks existing v2 receipts"
        );
    }

    #[test]
    fn protocol_version_serialises_correctly() {
        assert_eq!(ProtocolVersion::V2.as_str(), "mktd02-v2");
        assert_eq!(ProtocolVersion::V3.as_str(), "mktd02-v3");
        let s: String = ProtocolVersion::V2.into();
        let s3: String = ProtocolVersion::V3.into();
        assert_eq!(s, "mktd02-v2");
        assert_eq!(s3, "mktd02-v3");
        assert_eq!(format!("{}", ProtocolVersion::V2), "mktd02-v2");
        assert_eq!(format!("{}", ProtocolVersion::V3), "mktd02-v3");
    }

    #[test]
    fn trust_root_key_id_default_is_mainnet_for_finalized_receipt() {
        // A finalized mainnet receipt must carry "mainnet" as the key ID.
        // This test documents the expected value.
        let r = test_receipt();
        assert_eq!(r.trust_root_key_id, "mainnet");
    }

    #[test]
    fn pending_receipt_has_empty_trust_root_key_id() {
        // Invariant: pending receipts (not yet finalized) have empty trust_root_key_id.
        // This is enforced by convention and tested here.
        let r = DeletionReceipt {
            trust_root_key_id: String::new(),
            bls_certificate: None,
            ..test_receipt()
        };
        assert!(r.trust_root_key_id.is_empty());
        assert!(r.bls_certificate.is_none());
    }

    #[test]
    fn legacy_v2_cbor_decodes_safely_to_v3_shape() {
        let legacy_wire = DeletionReceiptV2Wire {
            protocol_version: "mktd02-v2".into(),
            receipt_id: [1u8; 32],
            canister_id: Principal::from_text("aaaaa-aa").unwrap(),
            subnet_id: Principal::from_text("2vxsx-fae").unwrap(),
            pre_state_hash: [2u8; 32],
            post_state_hash: [3u8; 32],
            tombstone_hash: [4u8; 32],
            deletion_event_hash: [5u8; 32],
            certified_commitment: [6u8; 32],
            module_hash: [8u8; 32],
            timestamp: 1_000_000u64,
            nonce: 42u64,
            bls_certificate: None,
            trust_root_key_id: "mainnet".into(),
        };

        let mut buf = Vec::new();
        ciborium::into_writer(&legacy_wire, &mut buf).unwrap();
        let decoded: DeletionReceipt = ciborium::from_reader(buf.as_slice()).unwrap();

        assert_eq!(decoded.protocol_version, "mktd02-v2");
        assert_eq!(decoded.record_id, Vec::<u8>::new());
        assert_eq!(decoded.deletion_seq, 42);
        assert_eq!(decoded.trust_root_key_id, "mainnet");
    }

    #[test]
    fn legacy_v2_receipt_summary_uses_deletion_seq_from_nonce() {
        let legacy_wire = DeletionReceiptV2Wire {
            protocol_version: "mktd02-v2".into(),
            receipt_id: [1u8; 32],
            canister_id: Principal::from_text("aaaaa-aa").unwrap(),
            subnet_id: Principal::from_text("2vxsx-fae").unwrap(),
            pre_state_hash: [2u8; 32],
            post_state_hash: [3u8; 32],
            tombstone_hash: [4u8; 32],
            deletion_event_hash: [5u8; 32],
            certified_commitment: [6u8; 32],
            module_hash: [8u8; 32],
            timestamp: 1_000_000u64,
            nonce: 77u64,
            bls_certificate: None,
            trust_root_key_id: "mainnet".into(),
        };

        let mut buf = Vec::new();
        ciborium::into_writer(&legacy_wire, &mut buf).unwrap();
        let decoded: DeletionReceipt = ciborium::from_reader(buf.as_slice()).unwrap();

        let summary = ReceiptSummary::from(&decoded);
        assert_eq!(summary.protocol_version, "mktd02-v2");
        assert_eq!(summary.deletion_seq, 77);
    }
}
