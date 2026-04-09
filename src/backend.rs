//! Compile-time backend selection.
//!
//! Defines [`BE`], the concrete Poulpy backend used throughout squid.
//! All internal modules import this alias instead of hard-coding a specific type.
//!
//! ## Choosing a backend
//!
//! | Feature flag    | Backend      | Requirements                  | Typical speedup |
//! |-----------------|--------------|-------------------------------|-----------------|
//! | *(default)*     | `FFT64Ref`   | Any CPU                       | baseline        |
//! | `backend-avx`   | `FFT64Avx`   | x86-64 with AVX2 + FMA        | ~3–5×           |
//!
//! Enable the AVX backend by passing `--features backend-avx` to Cargo, or adding
//! it to the `[features]` section of your `Cargo.toml`.  You must also compile
//! with the required target features:
//!
//! ```text
//! RUSTFLAGS="-C target-cpu=native" cargo build --release --features backend-avx
//! ```

#[cfg(all(feature = "backend-avx", not(target_arch = "x86_64")))]
compile_error!("feature `backend-avx` requires target_arch = \"x86_64\".");

// ── Default: portable scalar f64 FFT backend ────────────────────────────────

#[cfg(not(feature = "backend-avx"))]
pub(crate) use poulpy_cpu_ref::FFT64Ref as BE;

// ── Optional: AVX2/FMA-accelerated backend ───────────────────────────────────

#[cfg(feature = "backend-avx")]
pub(crate) use poulpy_cpu_avx::FFT64Avx as BE;
