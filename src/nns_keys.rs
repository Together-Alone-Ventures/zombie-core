//! # NNS Root Key Registry
//!
//! Compile-time allowlist of known NNS root keys for V2 offline verification.
//!
//! ## Design
//!
//! Instead of embedding 96 raw key bytes in every receipt, receipts carry a
//! compact `trust_root_key_id` string (e.g. `"mainnet"`). Verifiers look up
//! the actual DER-encoded key bytes here.
//!
//! ## Key Identifiers
//!
//! | ID            | Used when                                           |
//! |---------------|-----------------------------------------------------|
//! | `"mainnet"`   | ICP mainnet (all production receipts)               |
//! | `"local-dev"` | dfx local replica (`local-replica` feature only)  |
//!
//! ## Fail-Closed Behaviour
//!
//! The `local-replica` feature must be **explicitly enabled** to include the
//! development key. It is disabled in CI and in all mainnet builds.
//! Attempting to verify or issue a receipt with `trust_root_key_id = "local-dev"`
//! without the feature enabled returns `None` from `lookup_key()`, causing V2
//! to fail with a clear message. This is intentional.
//!
//! ## Key Rotation
//!
//! If the NNS root key is ever rotated, add the new key to `MAINNET_KEYS` with
//! a new ID (e.g. `"mainnet-2"`) and keep the old entry. Historical receipts
//! referencing the old key ID must remain verifiable indefinitely.

// ---------------------------------------------------------------------------
// Struct
// ---------------------------------------------------------------------------

/// A known NNS root key with a compact identifier.
#[derive(Debug, Clone, Copy)]
pub struct NnsRootKey {
    /// Short identifier stored in the receipt's `trust_root_key_id` field.
    pub id: &'static str,
    /// DER-encoded BLS12-381 G2 public key (133 bytes for all current ICP keys).
    pub der_bytes: &'static [u8],
}

impl NnsRootKey {
    /// Return the raw 96-byte BLS12-381 key, stripping the 37-byte DER header.
    ///
    /// ## DER structure for ICP BLS12-381 public keys
    ///
    /// Offset | Bytes         | Meaning
    /// -------|---------------|----------------------------------
    ///  0-2   | 30 81 82      | SEQUENCE, long-form length 130
    ///  3-4   | 30 1d         | AlgorithmIdentifier SEQUENCE (29 bytes)
    ///  5-35  | (OIDs)        | BLS12-381 G2 algorithm OIDs
    /// 34-36  | 03 61 00      | BIT STRING, 97 bytes, 0 unused bits
    /// 37-132 | (96 bytes)    | Raw BLS12-381 G2 public key
    ///
    /// Total DER = 133 bytes; prefix = 37 bytes; raw key = 96 bytes.
    ///
    /// ## Errors
    ///
    /// Returns `Err` if the DER bytes are too short or if the expected
    /// SEQUENCE header or BIT STRING marker is not found at the known offsets.
    /// This guards against silent corruption and future DER format changes.
    pub fn raw_bytes(&self) -> Result<&[u8], &'static str> {
        const DER_PREFIX_LEN: usize = 37;
        const RAW_KEY_LEN: usize = 96;
        const EXPECTED_TOTAL: usize = DER_PREFIX_LEN + RAW_KEY_LEN; // 133

        if self.der_bytes.len() < EXPECTED_TOTAL {
            return Err("DER key too short: expected at least 133 bytes");
        }
        // Validate outer SEQUENCE header: 30 81 82
        if self.der_bytes[0] != 0x30
            || self.der_bytes[1] != 0x81
            || self.der_bytes[2] != 0x82
        {
            return Err("DER header mismatch: expected SEQUENCE 30 81 82 at offset 0");
        }
        // Validate BIT STRING header: 03 61 00 at offset 34
        // (offset 34 = 3-byte outer SEQUENCE header + 31-byte AlgorithmIdentifier)
        if self.der_bytes[34] != 0x03
            || self.der_bytes[35] != 0x61
            || self.der_bytes[36] != 0x00
        {
            return Err("DER BIT STRING header mismatch: expected 03 61 00 at offset 34");
        }
        Ok(&self.der_bytes[DER_PREFIX_LEN..DER_PREFIX_LEN + RAW_KEY_LEN])
    }
}

// ---------------------------------------------------------------------------
// Mainnet key
// ---------------------------------------------------------------------------

/// ICP mainnet NNS root key.
///
/// Active since ICP genesis (May 2021). Has never been rotated.
/// Source: `dfx ping --network ic | grep root_key`
/// Matches the constant in ic-agent and verified against on-chain status.
pub const MAINNET_KEY_DER: &[u8] = &[
    0x30, 0x81, 0x82, 0x30, 0x1d, 0x06, 0x0d, 0x2b, 0x06, 0x01, 0x04, 0x01,
    0x82, 0xdc, 0x7c, 0x05, 0x03, 0x01, 0x02, 0x01, 0x06, 0x0c, 0x2b, 0x06,
    0x01, 0x04, 0x01, 0x82, 0xdc, 0x7c, 0x05, 0x03, 0x02, 0x01, 0x03, 0x61,
    0x00, 0x81, 0x4c, 0x0e, 0x6e, 0xc7, 0x1f, 0xab, 0x58, 0x3b, 0x08, 0xbd,
    0x81, 0x37, 0x3c, 0x25, 0x5c, 0x3c, 0x37, 0x1b, 0x2e, 0x84, 0x86, 0x3c,
    0x98, 0xa4, 0xf1, 0xe0, 0x8b, 0x74, 0x23, 0x5d, 0x14, 0xfb, 0x5d, 0x9c,
    0x0c, 0xd5, 0x46, 0xd9, 0x68, 0x5f, 0x91, 0x3a, 0x0c, 0x0b, 0x2c, 0xc5,
    0x34, 0x15, 0x83, 0xbf, 0x4b, 0x43, 0x92, 0xe4, 0x67, 0xdb, 0x96, 0xd6,
    0x5b, 0x9b, 0xb4, 0xcb, 0x71, 0x71, 0x12, 0xf8, 0x47, 0x2e, 0x0d, 0x5a,
    0x4d, 0x14, 0x50, 0x5f, 0xfd, 0x74, 0x84, 0xb0, 0x12, 0x91, 0x09, 0x1c,
    0x5f, 0x87, 0xb9, 0x88, 0x83, 0x46, 0x3f, 0x98, 0x09, 0x1a, 0x0b, 0xaa,
    0xae,
];

pub const MAINNET_KEY: NnsRootKey = NnsRootKey {
    id: "mainnet",
    der_bytes: MAINNET_KEY_DER,
};

// ---------------------------------------------------------------------------
// Local development key (feature-gated)
// ---------------------------------------------------------------------------

/// dfx local replica root key (development only).
///
/// To fill in this constant:
///   1. Run `dfx start --background`
///   2. Run `dfx ping --network local`
///   3. Copy the `root_key` array from the JSON output
///   4. Convert from decimal array to hex bytes and paste below
///
/// The local key changes between dfx versions. If local-dev verification
/// fails, update these bytes to match the current dfx version's output.
///
/// **Never enable `local-replica` in mainnet or CI builds.**
#[cfg(feature = "local-replica")]
const LOCAL_DEV_KEY_DER: &[u8] = &[
    // TODO: paste bytes from `dfx ping --network local | grep -A1 root_key`
    // Placeholder — compilation will succeed but verification will fail until filled in
    0x00,
];

#[cfg(feature = "local-replica")]
pub const LOCAL_DEV_KEY: NnsRootKey = NnsRootKey {
    id: "local-dev",
    der_bytes: LOCAL_DEV_KEY_DER,
};

// ---------------------------------------------------------------------------
// Allowlist and lookup
// ---------------------------------------------------------------------------

/// All known mainnet NNS root keys.
///
/// Old entries must be kept here forever — historical receipts referencing
/// them must remain verifiable after any future key rotation.
pub const MAINNET_KEYS: &[NnsRootKey] = &[MAINNET_KEY];

/// Look up a known NNS root key by ID.
///
/// Returns `None` for unknown IDs, including `"local-dev"` when the
/// `local-replica` feature is not compiled in (fail-closed behaviour).
pub fn lookup_key(id: &str) -> Option<&'static NnsRootKey> {
    match id {
        "mainnet" => Some(&MAINNET_KEY),
        #[cfg(feature = "local-replica")]
        "local-dev" => Some(&LOCAL_DEV_KEY),
        _ => None,
    }
}

/// Return the key ID appropriate for the current build environment.
///
/// - Without `local-replica` feature: always `"mainnet"`
/// - With `local-replica` feature: `"local-dev"`
///
/// Used by `mktd02::finalize_receipt()` to stamp the receipt automatically.
pub fn active_key_id() -> &'static str {
    #[cfg(feature = "local-replica")]
    {
        return "local-dev";
    }
    "mainnet"
}

/// Return the active NNS root key for the current build environment.
///
/// Panics if `active_key_id()` is not in the allowlist — this is a
/// compile-time invariant that must always hold.
pub fn active_key() -> &'static NnsRootKey {
    lookup_key(active_key_id())
        .expect("active_key_id() returned an ID not in the allowlist — this is a bug in zombie-core")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_key_is_133_bytes() {
        assert_eq!(
            MAINNET_KEY.der_bytes.len(),
            133,
            "mainnet DER key must be 133 bytes"
        );
    }

    #[test]
    fn mainnet_raw_bytes_is_96_bytes() {
        assert_eq!(
            MAINNET_KEY.raw_bytes().unwrap().len(),
            96,
            "raw BLS12-381 key must be 96 bytes after stripping DER prefix"
        );
    }

    #[test]
    fn mainnet_raw_bytes_starts_with_known_prefix() {
        // The first byte of the mainnet raw key is 0x81 — known from the
        // published key. This golden check catches accidental key changes.
        assert_eq!(
            MAINNET_KEY.raw_bytes().unwrap()[0],
            0x81,
            "mainnet raw key first byte changed — verify the key constant"
        );
    }

    #[test]
    fn raw_bytes_validates_der_header() {
        // A key with a wrong SEQUENCE header must return Err.
        let bad_key = NnsRootKey {
            id: "bad",
            der_bytes: &[0xFF; 133], // wrong header
        };
        assert!(bad_key.raw_bytes().is_err(), "wrong DER header should return Err");
    }

    #[test]
    fn raw_bytes_rejects_short_input() {
        // A key shorter than 133 bytes must return Err rather than panic.
        let short_key = NnsRootKey {
            id: "short",
            der_bytes: &[0x30, 0x81, 0x82], // only 3 bytes
        };
        assert!(short_key.raw_bytes().is_err(), "short DER should return Err");
    }

    #[test]
    fn lookup_mainnet_succeeds() {
        let k = lookup_key("mainnet").expect("mainnet key must always be found");
        assert_eq!(k.id, "mainnet");
    }

    #[test]
    fn lookup_unknown_returns_none() {
        assert!(lookup_key("unknown-key-id").is_none());
        assert!(lookup_key("").is_none());
    }

    #[test]
    fn active_key_id_without_feature_is_mainnet() {
        #[cfg(not(feature = "local-replica"))]
        assert_eq!(active_key_id(), "mainnet");
    }

    #[test]
    fn active_key_is_callable_without_panic() {
        let _ = active_key();
    }

    #[test]
    fn mainnet_key_der_starts_with_expected_sequence_header() {
        assert_eq!(&MAINNET_KEY.der_bytes[..3], &[0x30, 0x81, 0x82]);
    }
}
