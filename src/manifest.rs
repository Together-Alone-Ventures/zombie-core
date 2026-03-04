//! # PII Field Manifest
//!
//! The manifest defines the PII boundary -- which fields are covered
//! by MKTd02. Changes to the manifest during upgrade trigger a full
//! recomputation cascade (state_hash -> certified_commitment -> publish).
//!
//! Domain tag: `MKTD02_MANIFEST_V1`

use crate::hashing::{hash_with_tag, TAG_MANIFEST};
use candid::CandidType;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, CandidType)]
pub struct FieldDescriptor {
    pub field_name: String,
    pub field_type: String,
    pub field_order: u32,
}

/// Compute the manifest hash from a list of field descriptors.
///
/// `manifest_hash = SHA-256(MKTD02_MANIFEST_V1 || field_count || field_0 || field_1 || ...)`
///
/// **The input must be sorted by `field_order`.** Panics if unsorted or duplicated.
pub fn compute_manifest_hash(fields: &[FieldDescriptor]) -> [u8; 32] {
    for window in fields.windows(2) {
        assert!(
            window[0].field_order < window[1].field_order,
            "FieldDescriptors must be sorted by field_order with no duplicates. \
             Found field_order {} followed by {}",
            window[0].field_order,
            window[1].field_order,
        );
    }

    let field_count = (fields.len() as u32).to_be_bytes();

    let mut field_bytes = Vec::new();
    for f in fields {
        field_bytes.extend_from_slice(&f.field_order.to_be_bytes());
        field_bytes.extend_from_slice(&(f.field_name.len() as u32).to_be_bytes());
        field_bytes.extend_from_slice(f.field_name.as_bytes());
        field_bytes.extend_from_slice(&(f.field_type.len() as u32).to_be_bytes());
        field_bytes.extend_from_slice(f.field_type.as_bytes());
    }

    hash_with_tag(TAG_MANIFEST, &[&field_count, &field_bytes])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_manifest() -> Vec<FieldDescriptor> {
        vec![
            FieldDescriptor {
                field_name: "email".into(),
                field_type: "String".into(),
                field_order: 0,
            },
            FieldDescriptor {
                field_name: "birthdate".into(),
                field_type: "Option<String>".into(),
                field_order: 1,
            },
            FieldDescriptor {
                field_name: "gender".into(),
                field_type: "Option<String>".into(),
                field_order: 2,
            },
            FieldDescriptor {
                field_name: "display_name".into(),
                field_type: "Option<String>".into(),
                field_order: 3,
            },
        ]
    }

    #[test]
    fn manifest_hash_deterministic() {
        let a = compute_manifest_hash(&sample_manifest());
        let b = compute_manifest_hash(&sample_manifest());
        assert_eq!(a, b);
    }

    #[test]
    fn manifest_hash_changes_with_field_added() {
        let base = sample_manifest();
        let mut extended = base.clone();
        extended.push(FieldDescriptor {
            field_name: "phone".into(),
            field_type: "Option<String>".into(),
            field_order: 4,
        });
        assert_ne!(
            compute_manifest_hash(&base),
            compute_manifest_hash(&extended)
        );
    }

    #[test]
    fn manifest_hash_changes_with_type_change() {
        let base = sample_manifest();
        let mut modified = base.clone();
        modified[0].field_type = "Option<String>".into();
        assert_ne!(
            compute_manifest_hash(&base),
            compute_manifest_hash(&modified)
        );
    }

    #[test]
    fn manifest_hash_changes_with_name_change() {
        let base = sample_manifest();
        let mut modified = base.clone();
        modified[0].field_name = "email_address".into();
        assert_ne!(
            compute_manifest_hash(&base),
            compute_manifest_hash(&modified)
        );
    }

    #[test]
    #[should_panic(expected = "must be sorted by field_order")]
    fn manifest_hash_rejects_unsorted() {
        let mut fields = sample_manifest();
        fields.swap(0, 1);
        compute_manifest_hash(&fields);
    }

    #[test]
    #[should_panic(expected = "must be sorted by field_order")]
    fn manifest_hash_rejects_duplicates() {
        let mut fields = sample_manifest();
        fields[1].field_order = 0;
        compute_manifest_hash(&fields);
    }

    #[test]
    fn empty_manifest_is_valid() {
        let hash = compute_manifest_hash(&[]);
        assert_ne!(hash, [0u8; 32]);
    }
}
