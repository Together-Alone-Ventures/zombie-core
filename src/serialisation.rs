//! # Deterministic CBOR Serialisation
//!
//! `encode_pii_state()` -- the single safe encoding entry point for
//! producing `get_state_bytes()` output.
//!
//! ## Important: "Deterministic", not "Canonical"
//!
//! This module produces **deterministic CBOR under this library's encoder**
//! (ciborium + serde). The same Rust struct with the same field values
//! will always produce identical bytes. However, this is NOT canonical
//! CBOR in the RFC 8949 sense (which requires sorted map keys, etc.).
//!
//! Determinism is guaranteed because:
//! - ciborium + serde serialises struct fields in declaration order
//! - We reject floats (which have non-deterministic representations)
//! - Adapters must use `encode_pii_state()` as the only encoding path
//!
//! **Future direction:** Consider encoding PII state as a CBOR array
//! (tuple of values in manifest order) rather than a map, which would
//! give byte-level determinism independent of the CBOR library.
//!
//! ## Adapter Rules
//!
//! - All PII fields listed in manifest, in `field_order`
//! - No `f32`/`f64` fields -- rejected at encode time
//! - No `HashMap`/`BTreeMap` in PII structs (enforced by convention;
//!   use structs with named fields)
//! - `encode_pii_state()` is the ONLY path to produce hashable state bytes

use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SerialisationError {
    FloatDetected,
    EncodingFailed(String),
    DecodingFailed(String),
    ValidationFailed(String),
}

impl fmt::Display for SerialisationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FloatDetected => write!(
                f,
                "CBOR contains floating-point value; floats are forbidden in PII state encoding"
            ),
            Self::EncodingFailed(e) => write!(f, "CBOR encoding failed: {e}"),
            Self::DecodingFailed(e) => write!(f, "CBOR decoding failed: {e}"),
            Self::ValidationFailed(e) => write!(f, "CBOR validation failed: {e}"),
        }
    }
}

impl std::error::Error for SerialisationError {}

/// Encode a PII state struct to deterministic CBOR bytes.
///
/// This is the **only** function adapters should use to produce bytes
/// for `get_state_bytes()`. It serialises via ciborium then validates
/// the output contains no floats.
///
/// Determinism depends on ciborium's serde implementation serialising
/// struct fields in declaration order. Adapters must use structs (not
/// HashMap/BTreeMap) to ensure consistent field ordering.
pub fn encode_pii_state<T: Serialize>(value: &T) -> Result<Vec<u8>, SerialisationError> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf)
        .map_err(|e| SerialisationError::EncodingFailed(e.to_string()))?;
    validate_cbor_bytes(&buf)?;
    Ok(buf)
}

/// Decode deterministic CBOR bytes back to a PII state struct.
pub fn decode_pii_state<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
) -> Result<T, SerialisationError> {
    validate_cbor_bytes(bytes)?;
    ciborium::from_reader(bytes).map_err(|e| SerialisationError::DecodingFailed(e.to_string()))
}

/// Validate that CBOR bytes contain no floats.
///
/// Walks the CBOR value tree recursively. Rejects any floating-point
/// values (f16/f32/f64) because IEEE 754 has non-deterministic
/// representations (NaN bit patterns, +/-0).
///
/// Maps are allowed because ciborium serialises Rust structs as CBOR
/// maps with deterministic field ordering.
pub fn validate_cbor_bytes(bytes: &[u8]) -> Result<(), SerialisationError> {
    let value: ciborium::Value = ciborium::from_reader(bytes)
        .map_err(|e| SerialisationError::ValidationFailed(e.to_string()))?;
    validate_cbor_value(&value)
}

fn validate_cbor_value(value: &ciborium::Value) -> Result<(), SerialisationError> {
    match value {
        ciborium::Value::Float(_) => Err(SerialisationError::FloatDetected),
        ciborium::Value::Array(items) => {
            for item in items {
                validate_cbor_value(item)?;
            }
            Ok(())
        }
        ciborium::Value::Map(entries) => {
            for (k, v) in entries {
                validate_cbor_value(k)?;
                validate_cbor_value(v)?;
            }
            Ok(())
        }
        ciborium::Value::Tag(_, inner) => validate_cbor_value(inner),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct SimpleProfile {
        email: String,
        age: u32,
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct ProfileWithOption {
        email: String,
        birthdate: Option<String>,
        gender: Option<String>,
        display_name: Option<String>,
    }

    #[test]
    fn round_trip_simple() {
        let p = SimpleProfile {
            email: "test@example.com".into(),
            age: 30,
        };
        let bytes = encode_pii_state(&p).unwrap();
        let decoded: SimpleProfile = decode_pii_state(&bytes).unwrap();
        assert_eq!(p, decoded);
    }

    #[test]
    fn round_trip_with_options() {
        let p = ProfileWithOption {
            email: "test@example.com".into(),
            birthdate: Some("1990-01-01".into()),
            gender: None,
            display_name: Some("Test User".into()),
        };
        let bytes = encode_pii_state(&p).unwrap();
        let decoded: ProfileWithOption = decode_pii_state(&bytes).unwrap();
        assert_eq!(p, decoded);
    }

    #[test]
    fn deterministic_encoding() {
        let p = ProfileWithOption {
            email: "test@example.com".into(),
            birthdate: Some("1990-01-01".into()),
            gender: None,
            display_name: Some("Test User".into()),
        };
        let a = encode_pii_state(&p).unwrap();
        let b = encode_pii_state(&p).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn rejects_float() {
        let val = ciborium::Value::Float(3.14);
        let mut buf = Vec::new();
        ciborium::into_writer(&val, &mut buf).unwrap();
        assert!(matches!(
            validate_cbor_bytes(&buf),
            Err(SerialisationError::FloatDetected)
        ));
    }

    #[test]
    fn rejects_nested_float() {
        let val = ciborium::Value::Array(vec![
            ciborium::Value::Integer(1.into()),
            ciborium::Value::Array(vec![ciborium::Value::Float(2.5)]),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&val, &mut buf).unwrap();
        assert!(matches!(
            validate_cbor_bytes(&buf),
            Err(SerialisationError::FloatDetected)
        ));
    }

    #[test]
    fn rejects_float_inside_map() {
        let val = ciborium::Value::Map(vec![(
            ciborium::Value::Text("temp".into()),
            ciborium::Value::Float(98.6),
        )]);
        let mut buf = Vec::new();
        ciborium::into_writer(&val, &mut buf).unwrap();
        assert!(matches!(
            validate_cbor_bytes(&buf),
            Err(SerialisationError::FloatDetected)
        ));
    }

    #[test]
    fn allows_bool_and_null() {
        let val = ciborium::Value::Array(vec![
            ciborium::Value::Bool(true),
            ciborium::Value::Null,
            ciborium::Value::Integer(42.into()),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&val, &mut buf).unwrap();
        assert!(validate_cbor_bytes(&buf).is_ok());
    }

    #[test]
    fn struct_encodes_successfully() {
        let p = SimpleProfile {
            email: "test@example.com".into(),
            age: 30,
        };
        let bytes = encode_pii_state(&p).unwrap();
        assert!(!bytes.is_empty());
    }
}
