# 🦑 Squid
 
**An ergonomic Rust wrapper for [Poulpy](https://github.com/phantomzone-org/poulpy), making Fully Homomorphic Encryption accessible without sacrificing control.**
 
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) [![CI](https://github.com/cedoor/squid/actions/workflows/ci.yml/badge.svg)](https://github.com/cedoor/squid/actions) ![Status](https://img.shields.io/badge/status-early%20development-orange)

Poulpy is a low-level, modular toolkit exposing the full machinery of lattice-based homomorphic encryption. That power comes with sharp edges: manual scratch arenas, explicit lifecycle transitions, trait-heavy APIs. `squid` wraps Poulpy with a smaller, opinionated surface so you can write FHE programs without managing every byte of workspace memory or tracking which representation a ciphertext currently lives in.

**Current scope:** `squid` wraps Poulpy's `bin_fhe::bdd_arithmetic` layer: gate-level FHE on encrypted unsigned integers (`u8`, `u16`, `u32`). This is the only fully exposed end-to-end capability in `poulpy-schemes` today. The API will expand as Poulpy adds more scheme-level implementations.

## Usage

```rust
use squid::{Context, Params};

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

All operations currently require `T = u32` (the only width with compiled BDD circuits in Poulpy). Encrypt and decrypt work for `u8`, `u16`, and `u32`.

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

## Roadmap

### Milestone 1 — Working Foundation: [#1](https://github.com/cedoor/squid/milestone/1)

- [x] Write README with installation, quick start example: [#2](https://github.com/cedoor/squid/issues/2)
- [x] Set up GitHub Actions (cargo test, cargo clippy, cargo fmt check): [#3](https://github.com/cedoor/squid/issues/3)
- [x] Release first alpha version: [#5](https://github.com/cedoor/squid/issues/5)
- [x] Add at least one runnable example in examples/: [#7](https://github.com/cedoor/squid/issues/7)
- [ ] Add tests for all existing ops: [#4](https://github.com/cedoor/squid/issues/4)
- [ ] Add rustdoc comments to all public items: [#6](https://github.com/cedoor/squid/issues/6)
- [ ] Faster tests via fixtures or deterministic keygen: [#19](https://github.com/cedoor/squid/issues/19)

### Milestone 2 — Full bin_fhe Coverage: [#2](https://github.com/cedoor/squid/milestone/2)

- [ ] Wrap Poulpy's blind selection / retrieval primitives: [#8](https://github.com/cedoor/squid/issues/8)
- [x] Multi-threaded evaluation: [#9](https://github.com/cedoor/squid/issues/9)
- [ ] Sub-word operations: [#10](https://github.com/cedoor/squid/issues/10)
- [ ] Identity / noise refresh: [#11](https://github.com/cedoor/squid/issues/11)
- [ ] NTT backend: [#12](https://github.com/cedoor/squid/issues/12)
- [x] Key serialization: [#13](https://github.com/cedoor/squid/issues/13)

### Milestone 3 — Developer Experience & Optimization: [#3](https://github.com/cedoor/squid/milestone/3)

- [ ] WASM crate: [#14](https://github.com/cedoor/squid/issues/14)
- [ ] Params validation with clear error messages: [#15](https://github.com/cedoor/squid/issues/15)
- [ ] Realistic examples: [#16](https://github.com/cedoor/squid/issues/16)
- [ ] Benchmarks: [#17](https://github.com/cedoor/squid/issues/17)
- [ ] Vetted Params presets: [#18](https://github.com/cedoor/squid/issues/18)
- [ ] Refactor `context.rs`: [#20](https://github.com/cedoor/squid/issues/20)
- [ ] Split keygen scratch from runtime arena to reduce persistent memory: [#22](https://github.com/cedoor/squid/issues/22)

## Design goals

- **Hide scratch management.** Callers never allocate or thread scratch buffers.
- **Hide lifecycle transitions.** The Standard → Prepared → BDD-eval pipeline is handled internally; users see one coherent `Ciphertext<T>` type.
- **Explicitly non-production defaults.** `Params::unsecure()` matches Poulpy's `bdd_arithmetic` example for demos; treat it as unaudited unless you analyse parameters yourself.
- **No magic.** Every abstraction is traceable to the underlying Poulpy call. No hidden global state, no surprising allocations beyond the initial `Context::new`.
- **Safe defaults.** Every user-facing choice has a default that works without configuration. Alternatives are documented with their trade-offs and the conditions under which they should be preferred.
