# `handshake` (Rust)

The **canonical** Handshake AI SDK implementation. The Python and TypeScript SDKs are FFI shims over this crate (see [ADR-0006](../../docs/decisions/0006-rust-core-authoritative.md)); the Go SDK is a parallel native implementation continuously checked for byte-equality with this one.

## Surface (Phase 1)

| Module | What it does | Backing crate |
| --- | --- | --- |
| [`jcs`](src/jcs.rs)       | RFC 8785 canonical JSON (incl. IEEE-754 ECMAScript Number→String) | [`serde_jcs`](https://crates.io/crates/serde_jcs) |
| [`hash`](src/hash.rs)     | SHA-256 over canonical bytes                                       | [`sha2`](https://crates.io/crates/sha2) |
| [`sign`](src/sign.rs)     | Ed25519 sign/verify (RFC 8032)                                     | [`ed25519-dalek`](https://crates.io/crates/ed25519-dalek) v2 |
| [`mldsa`](src/mldsa.rs)   | ML-DSA-65 deterministic sign/verify (FIPS 204)                     | [`ml-dsa`](https://crates.io/crates/ml-dsa) v0.0.4 |
| [`models`](src/models.rs) | Schema-native `DelegationToken`, `HandshakeRequest`, `Receipt`     | `serde` derives |

The crate has **no provider, network, or KMS dependencies** (ADR-0002). It is entirely synchronous and `no_std`-friendly aspirationally (current version uses `std`).

## Usage

```rust
use handshake::{jcs, sign, hash, mldsa};
use serde_json::json;

let payload = json!({"b": 2, "a": 1});
let canonical: Vec<u8> = jcs::canonicalize(&payload)?;  // {"a":1,"b":2}
let digest: [u8; 32]   = hash::sha256(&canonical);

// Ed25519
let kp_ed = sign::Keypair::from_seed(&[0x11; 32]);
let sig_ed = kp_ed.sign(&canonical);
sign::verify(&kp_ed.public_key(), &sig_ed, &canonical)?;

// ML-DSA-65 (post-quantum, FIPS 204)
let (vk_pq, sk_pq) = mldsa::keygen_from_seed(&[0x2a; 32]);
let sig_pq = mldsa::sign(&sk_pq, &canonical);
mldsa::verify(&vk_pq, &sig_pq, &canonical)?;
```

## Run

```bash
cargo test --release
cargo run --release --example conformance
```

`cargo run --example conformance` emits the per-implementation conformance JSON consumed by the Phase 1 dashboard at <http://localhost:5000/>. The full cross-language demo (Rust + handshake-py + handshake-ts + handshake-go) is `bash examples/phase1_demo.sh` from the repo root.

## How the FFI shims consume this crate

`packages/handshake-py/Cargo.toml` and `packages/handshake-ts/Cargo.toml` both declare:

```toml
[dependencies]
handshake = { path = "../handshake-rs" }
```

…and re-export `canonicalize`, `sha256`, Ed25519 sign/verify, and ML-DSA-65 sign/verify across the FFI boundary (PyO3 in Python, NAPI-RS in Node.js). The pure-language façades (`packages/handshake-py/python/handshake/`, `packages/handshake-ts/ts/`) wrap the native module to provide schema-native models in Pydantic v2 and Zod respectively.
