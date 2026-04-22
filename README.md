# 🦑 Squid

**An ergonomic Rust wrapper ([`squid`](crates/squid)) for [Poulpy](https://github.com/poulpy-fhe/poulpy) and the [`squid-js`](packages/squid-js) library for browser and Node (WebAssembly + napi-rs), making Fully Homomorphic Encryption accessible without sacrificing control.**

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) [![CI](https://github.com/cedoor/squid/actions/workflows/ci.yml/badge.svg)](https://github.com/cedoor/squid/actions) [![Live demo](https://img.shields.io/badge/demo-squid.cedoor.dev-blueviolet)](https://squid.cedoor.dev/) ![Status](https://img.shields.io/badge/status-early%20development-orange)

Poulpy is a low-level, modular toolkit exposing the full machinery of lattice-based homomorphic encryption. That power comes with sharp edges: manual scratch arenas, explicit lifecycle transitions, trait-heavy APIs. [`squid`](crates/squid) wraps Poulpy with a smaller, opinionated surface so you can write FHE programs without managing every byte of workspace memory or tracking which representation a ciphertext currently lives in.

For JavaScript and TypeScript, **[`squid-js`](packages/squid-js)** exposes the same stack: **`squid-js/client`** runs keygen, encrypt, and decrypt in the browser over WebAssembly (typically inside a dedicated worker so crypto stays off the UI thread), while **`squid-js/server`** runs homomorphic evaluation in Node via a native addon (napi-rs). In the usual setup the secret key stays on the client; the server only receives the evaluation key and ciphertexts.

**Current scope:** [`squid`](crates/squid) wraps Poulpy's `bin_fhe::bdd_arithmetic` layer: gate-level FHE on encrypted unsigned integers (`u8`, `u16`, `u32`). This is the only fully exposed end-to-end capability in `poulpy-schemes` today. The API will expand as Poulpy adds more scheme-level implementations.

## Monorepo structure

| Path                                     | Description                                                      |
| ---------------------------------------- | ---------------------------------------------------------------- |
| [`crates/squid`](crates/squid)           | Rust library — ergonomic Poulpy wrapper (this is the main crate) |
| [`crates/squid-wasm`](crates/squid-wasm) | WebAssembly bindings via `wasm-bindgen` (browser)                |
| [`crates/squid-napi`](crates/squid-napi) | Node.js native bindings via `napi-rs` (server)                   |
| [`packages/squid-js`](packages/squid-js) | npm package — browser client + Node evaluator                    |
| [`demo`](demo)                           | Next.js demo: keygen in browser, homomorphic eval on server — **[live at squid.cedoor.dev](https://squid.cedoor.dev/)** |
| [`tests`](tests)                         | Playwright end-to-end tests for the demo                         |

The Cargo workspace ties the three Rust crates together. The pnpm workspace ties [`squid-js`](packages/squid-js), the demo, and the E2E tests together.

## Usage (Rust)

### Quick start

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

### Preset name (config / CLI)

Built-in bundles can be selected by string: `Params::by_name("unsecure")` and `Params::by_name("test")` each return `Some(Params)`, and any other input returns `None`. Prefer `Params::unsecure()` / `Params::test()` when the choice is fixed in code.

### Serialize / deserialize an evaluation key

The evaluation key is public material needed for every homomorphic op. Persist
it once and reload it on the server that runs the circuits. The blob is
versioned and tied to the [`Params`](crates/squid/src/context.rs) used at keygen — loading
under different parameters returns an `io::Error`.

```rust
use squid::{Context, EvaluationKey, Params};

let mut ctx = Context::new(Params::unsecure());
let (_sk, ek) = ctx.keygen();

// Serialize to a versioned little-endian blob.
let blob: Vec<u8> = ctx.serialize_evaluation_key(&ek).unwrap();
std::fs::write("ek.bin", &blob).unwrap();

// Reload later, under the same Params, into a fresh Context.
let mut ctx = Context::new(Params::unsecure());
let bytes = std::fs::read("ek.bin").unwrap();
let ek: EvaluationKey = ctx.deserialize_evaluation_key(&bytes).unwrap();
```

Secret keys do not expose binary I/O — persist
[`KeygenSeeds`](#deterministic-key-generation-from-seeds) instead.

### Serialize / deserialize a ciphertext

Ciphertexts are the wire format for sending encrypted values between parties.
The blob records the plaintext bit width and GLWE layout, so mismatched
parameters or a wrong `T` are rejected before any ciphertext bytes are read.

```rust
use squid::{Ciphertext, Context, Params};

let mut ctx = Context::new(Params::unsecure());
let (sk, _ek) = ctx.keygen();

let ct = ctx.encrypt::<u32>(42, &sk);
let blob: Vec<u8> = ctx.serialize_ciphertext(&ct).unwrap();

// Reload with the same T and the same Params.
let ct: Ciphertext<u32> = ctx.deserialize_ciphertext(&blob).unwrap();
assert_eq!(ctx.decrypt::<u32>(&ct, &sk), 42);
```

### Deterministic key generation from seeds

Poulpy does not expose a stable wire format for secret keys. To reproduce the
same `(SecretKey, EvaluationKey)` pair across runs or machines, persist the
three 32-byte ChaCha8 seeds returned by `keygen_with_seeds` and rebuild with
`keygen_from_seeds`. Same `Params`, same backend, same keys.

```rust
use squid::{Context, KeygenSeeds, Params};

let mut ctx = Context::new(Params::unsecure());

// OS-random seeds (kept so we can replay keygen).
let (sk, ek, seeds) = ctx.keygen_with_seeds();

// Persist the seeds at the app level — `KeygenSeeds` redacts its Debug output.
let KeygenSeeds { lattice, bdd_mask, bdd_noise } = seeds;
// std::fs::write("seeds.bin", [lattice, bdd_mask, bdd_noise].concat()).unwrap();

// Later: regenerate the same keys deterministically.
let mut ctx = Context::new(Params::unsecure());
let (sk2, ek2) = ctx.keygen_from_seeds(seeds);

// If you only need encrypt/decrypt (no homomorphic ops), the lattice seed alone
// is enough to rebuild the SecretKey — no EvaluationKey produced.
let sk_only = ctx.secret_key_from_lattice_seed(seeds.lattice);
```

Treat the seeds as secret: anyone holding them can reconstruct `sk`.

## Operations

All operations currently require `T = u32` (the only width with compiled BDD circuits in Poulpy). Encrypt and decrypt work for `u8`, `u16`, and `u32`.

| Method               | Description            |
| -------------------- | ---------------------- |
| `ctx.add(a, b, ek)`  | Wrapping addition      |
| `ctx.sub(a, b, ek)`  | Wrapping subtraction   |
| `ctx.and(a, b, ek)`  | Bitwise AND            |
| `ctx.or(a, b, ek)`   | Bitwise OR             |
| `ctx.xor(a, b, ek)`  | Bitwise XOR            |
| `ctx.sll(a, b, ek)`  | Logical left shift     |
| `ctx.srl(a, b, ek)`  | Logical right shift    |
| `ctx.sra(a, b, ek)`  | Arithmetic right shift |
| `ctx.slt(a, b, ek)`  | Signed less-than       |
| `ctx.sltu(a, b, ek)` | Unsigned less-than     |

## Backends

| Feature       | Backend    | Notes                           |
| ------------- | ---------- | ------------------------------- |
| _(default)_   | `FFT64Ref` | Portable                        |
| `backend-avx` | `FFT64Avx` | x86-64, AVX2+FMA (~3–5× vs ref) |

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
- [x] Faster tests via fixtures or deterministic keygen: [#19](https://github.com/cedoor/squid/issues/19)

### Milestone 2 — Full bin_fhe Coverage: [#2](https://github.com/cedoor/squid/milestone/2)

- [ ] Wrap Poulpy's blind selection / retrieval primitives: [#8](https://github.com/cedoor/squid/issues/8)
- [x] Multi-threaded evaluation: [#9](https://github.com/cedoor/squid/issues/9)
- [ ] Sub-word operations: [#10](https://github.com/cedoor/squid/issues/10)
- [ ] Identity / noise refresh: [#11](https://github.com/cedoor/squid/issues/11)
- [ ] NTT backend: [#12](https://github.com/cedoor/squid/issues/12)
- [x] Key serialization: [#13](https://github.com/cedoor/squid/issues/13)
- [x] Revert `encrypt` workaround once upstream poulpy bug is fixed: [#24](https://github.com/cedoor/squid/issues/24)

### Milestone 3 — Developer Experience & Optimization: [#3](https://github.com/cedoor/squid/milestone/3)

- [x] WASM crate: [#14](https://github.com/cedoor/squid/issues/14)
- [ ] Params validation with clear error messages: [#15](https://github.com/cedoor/squid/issues/15)
- [ ] Realistic examples: [#16](https://github.com/cedoor/squid/issues/16)
- [ ] Benchmarks: [#17](https://github.com/cedoor/squid/issues/17)
- [ ] Vetted Params presets: [#18](https://github.com/cedoor/squid/issues/18)
- [ ] Refactor `context.rs`: [#20](https://github.com/cedoor/squid/issues/20)
- [ ] Add CHANGELOG file: [#26](https://github.com/cedoor/squid/issues/26)
- [x] [#22](https://github.com/cedoor/squid/issues/22) — closed: `Context` no longer keeps a persistent max-sized arena; scratch is allocated per operation from Poulpy's `*_tmp_bytes` (supersedes the issue's "split keygen vs runtime" split).

## Design goals

- **Hide scratch management.** Callers never allocate or thread scratch buffers.
- **Hide lifecycle transitions.** The Standard → Prepared → BDD-eval pipeline is handled internally; users see one coherent `Ciphertext<T>` type.
- **Explicitly non-production defaults.** `Params::unsecure()` matches Poulpy's `bdd_arithmetic` example for demos; treat it as unaudited unless you analyse parameters yourself.
- **No magic.** Every abstraction is traceable to the underlying Poulpy call. No hidden global state; scratch is sized with Poulpy's `*_tmp_bytes` at each operation.
- **Safe defaults.** Every user-facing choice has a default that works without configuration. Alternatives are documented with their trade-offs and the conditions under which they should be preferred.
