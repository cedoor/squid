# 🦑 SquidFHE
 
**An ergonomic Rust wrapper for [Poulpy](https://github.com/phantomzone-org/poulpy), making Fully Homomorphic Encryption accessible without sacrificing control.**
 
[![Crates.io](https://img.shields.io/crates/v/squid-fhe.svg)](https://crates.io/crates/squid-fhe) [![docs.rs](https://img.shields.io/docsrs/squid-fhe)](https://docs.rs/squid-fhe) [![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) [![CI](https://github.com/cedoor/squid/actions/workflows/ci.yml/badge.svg)](https://github.com/cedoor/squid/actions) ![Status](https://img.shields.io/badge/status-early%20development-orange)

Poulpy is a low-level, modular toolkit exposing the full machinery of lattice-based homomorphic encryption. That power comes with sharp edges: manual scratch arenas, explicit lifecycle transitions, trait-heavy APIs. `squid-fhe` wraps Poulpy with a smaller, opinionated surface so you can write FHE programs without managing every byte of workspace memory or tracking which representation a ciphertext currently lives in.

**Current scope:** `squid` wraps Poulpy's `bin_fhe::bdd_arithmetic` layer: gate-level FHE on encrypted unsigned integers (`u8`, `u16`, `u32`). This is the only fully exposed end-to-end capability in `poulpy-schemes` today. The API will expand as Poulpy adds more scheme-level implementations.

## Usage

```rust
use squid_fhe::{Context, Params};

fn main() {
    // Demo preset — not a vetted security level (see Params::unsecure docs)
    let mut ctx = Context::new(Params::unsecure());

    // Generate keys (secret key + evaluation key)
    let (sk, ek) = ctx.keygen();

    // Encrypt two 32-bit integers
    let a = ctx.encrypt::<u32>(255, &sk);
    let b = ctx.encrypt::<u32>(30, &sk);

    // Homomorphic addition: computes (a + b) under encryption
    let c = ctx.add(&a, &b, &ek);

    // Decrypt the result
    let result: u32 = ctx.decrypt(&c, &sk);
    assert_eq!(result, 255_u32.wrapping_add(30));
    println!("255 + 30 = {result}");
}
```

## Operations

All operations work on `Ciphertext<T>` where `T` is `u8`, `u16`, or `u32`:

| Method | Description |
|---|---|
| `ctx.add(a, b, ek)` | Wrapping addition |
| `ctx.sub(a, b, ek)` | Wrapping subtraction |
| `ctx.and(a, b, ek)` | Bitwise AND |
| `ctx.or(a, b, ek)` | Bitwise OR |
| `ctx.xor(a, b, ek)` | Bitwise XOR |
| `ctx.sll(a, b, ek)` | Logical left shift |
| `ctx.srl(a, b, ek)` | Logical right shift |
| `ctx.sra(a, b, ek)` | Arithmetic right shift |
| `ctx.slt(a, b, ek)` | Signed less-than |
| `ctx.sltu(a, b, ek)` | Unsigned less-than |

## Backends

Squid defaults to a portable scalar CPU backend. On x86-64 machines with AVX2 and FMA, you can opt into a faster backend:

| Feature flag  | Backend    | Requirements              | Typical speedup |
|---------------|------------|---------------------------|-----------------|
| *(default)*   | `FFT64Ref` | Any CPU                   | baseline        |
| `backend-avx` | `FFT64Avx` | x86-64 with AVX2 + FMA    | ~3–5×           |

```sh
RUSTFLAGS="-C target-cpu=native" cargo build --release --features backend-avx
```

The public API is identical regardless of which backend is selected.

## Design goals

- **Hide scratch management.** Callers never allocate or thread scratch buffers.
- **Hide lifecycle transitions.** The Standard → Prepared → BDD-eval pipeline is handled internally; users see one coherent `Ciphertext<T>` type.
- **Explicitly non-production defaults.** `Params::unsecure()` matches Poulpy's `bdd_arithmetic` example for demos; treat it as unaudited unless you analyse parameters yourself.
- **No magic.** Every abstraction is traceable to the underlying Poulpy call. No hidden global state, no surprising allocations beyond the initial `Context::new`.
