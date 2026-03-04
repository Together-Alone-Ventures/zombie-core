# zombie-core

Shared protocol types for the Zombie suite — cryptographic deletion receipts,
hashing primitives, and serialisation for GDPR Right to Erasure on ICP.

## What this is

`zombie-core` is the canonical definition of the **CVDR (Cryptographically
Verifiable Deletion Receipt)** data structures and the hash primitives that
produce them. Every Zombie suite product (`MKTd02`, `MKTd03`, future variants)
depends on this crate so that receipts, verification tooling, and protocol
changes all share a single source of truth.

This crate is **pure Rust with zero ICP dependencies**. It compiles and tests
on native targets:

```
cargo test
```

## Crate contents

| Module | Purpose |
|---|---|
| `receipt` | `DeletionReceipt`, `ProtocolVersion`, `ReceiptSummary`, `compute_receipt_id` |
| `hashing` | `hash_with_tag`, `sha256`, domain separation tags, golden test vectors |
| `tombstone` | `TOMBSTONE_CONSTANT` and derivation |
| `serialisation` | CBOR encode/decode helpers for PII state |
| `manifest` | `compute_manifest_hash`, `FieldDescriptor` |

## Protocol versioning

Each receipt contains a `protocol_version` string (e.g. `"mktd02-v2"`) that
tells verification tooling which hash formulas to use. Domain tags are stable
across versions; the version field gates formula selection. Golden test vectors
in `hashing.rs` act as tripwires — any accidental protocol change breaks them
immediately.

## Versioning and pinning

Consumer crates (`MKTd02`, `CVDR-Verify`) pin `zombie-core` by **commit hash
(rev)** during active development, and by **version tag** for releases. Tags
follow the convention `zombie-core-vX.Y.Z` to avoid confusion with consumer
repo version tags.

**Always prefix version strings with the repo name** when both repos are in
scope: write `zombie-core v0.1.0` and `MKTd02 v0.2.0`, never just `v0.1.0`.

## Part of the Zombie suite

```
Together-Alone-Ventures/zombie-core   ← you are here (shared types)
Together-Alone-Ventures/MKTd02        ← Leaf-mode ICP canister library
Together-Alone-Ventures/CVDR-Verify   ← standalone verification tooling
```

Future products (`MKTd03` Tree mode, `ZKPd` family) will add their own repos
and depend on this crate.

## Licence

Apache-2.0 — see [LICENSE](LICENSE).
