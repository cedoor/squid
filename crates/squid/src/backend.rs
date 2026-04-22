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
//! With `backend-avx` on a non-x86_64 host, the optional AVX crate may still be
//! linked for feature resolution, but [`BE`] stays `FFT64Ref` (e.g. `cargo clippy --all-features`).
//!
//! Poulpy’s AVX code must be compiled with AVX2+FMA available to rustc (`cfg(target_feature)`).
//! Example (matches README / typical CI):
//!
//! ```text
//! RUSTFLAGS="-C target-cpu=native" cargo build --release --features backend-avx
//! ```
//!
//! Alternatively: `RUSTFLAGS="-C target-feature=+avx2,+fma"`. Runtime CPU checks are still
//! inside Poulpy.

// ── AVX2/FMA-accelerated backend (x86_64 only) ─────────────────────────────

#[cfg(all(feature = "backend-avx", target_arch = "x86_64"))]
pub(crate) use poulpy_cpu_avx::FFT64Avx as BE;

// ── Portable scalar f64 FFT backend (default and non-x86 with `backend-avx`) ─

#[cfg(not(all(feature = "backend-avx", target_arch = "x86_64")))]
pub(crate) use poulpy_cpu_ref::FFT64Ref as BE;
