//! The user-facing ciphertext type.
//!
//! [`Ciphertext<T>`] wraps Poulpy's packed `FheUint<Vec<u8>, T>` (the wire
//! format) and additionally caches the prepared (DFT-domain) `FheUintPrepared`
//! produced at encryption time.  Homomorphic ops consume the prepared cache;
//! [`Context::decrypt`](crate::context::Context::decrypt) and
//! [`Ciphertext::serialize`] use the packed form only.
//!
//! ## Chaining limitation
//!
//! In the currently pinned Poulpy revision, the `FheUint -> FheUintPrepared`
//! re-prepare path produces incorrect results, so a ciphertext that has lost
//! its prepared cache (an op result, or a freshly deserialized blob) cannot be
//! used as input to another homomorphic op. Doing so panics with a descriptive
//! message. This restriction will lift as upstream Poulpy stabilizes that
//! pipeline.
//!
//! Standard-form wire encoding is [`Ciphertext::serialize`] /
//! [`Ciphertext::deserialize`] / [`crate::context::Context::serialize_ciphertext`] /
//! [`crate::context::Context::deserialize_ciphertext`] (versioned little-endian blob;
//! must be loaded with the same [`crate::context::Params`] as encryption).

use std::io;

use poulpy_core::layouts::GLWEToRef;
use poulpy_hal::layouts::{DeviceBuf, WriterTo};
use poulpy_schemes::bin_fhe::bdd_arithmetic::{FheUint, FheUintPrepared, UnsignedInteger};

use crate::context::Context;

/// Leading byte of [`Ciphertext::serialize`] / [`crate::context::Context::serialize_ciphertext`] blobs.
pub(crate) const CIPHERTEXT_BLOB_VERSION: u8 = 1;

/// An encrypted unsigned integer of type `T`.
///
/// `T` must implement [`UnsignedInteger`], which is satisfied by `u8`, `u16`,
/// `u32`, `u64`, and `u128`.  All homomorphic operations on this type are
/// performed through [`crate::Context`].
///
/// ## Lifecycle
///
/// 1. Create with [`crate::Context::encrypt`] (caches the prepared form for ops).
/// 2. Pass to homomorphic operations (`ctx.add`, `ctx.xor`, …).
/// 3. Recover the plaintext with [`crate::Context::decrypt`].
pub struct Ciphertext<T: UnsignedInteger> {
    pub(crate) inner: FheUint<Vec<u8>, T>,
    pub(crate) prepared:
        Option<FheUintPrepared<DeviceBuf<crate::backend::BE>, T, crate::backend::BE>>,
}

impl<T: UnsignedInteger> Ciphertext<T> {
    /// Serializes the packed GLWE ciphertext (little-endian, versioned). The plaintext type `T`
    /// is recorded in the blob; use the same `T` with [`Ciphertext::deserialize`].
    ///
    /// The prepared cache is **not** serialized; deserialized ciphertexts can only be
    /// decrypted (see module-level note about chaining).
    ///
    /// Same as [`crate::context::Context::serialize_ciphertext`] with this value.
    pub fn serialize(&self) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        out.push(CIPHERTEXT_BLOB_VERSION);
        out.extend_from_slice(&T::BITS.to_le_bytes());
        self.inner.to_ref().write_to(&mut out)?;
        Ok(out)
    }

    /// Restores a [`Ciphertext<T>`] from [`Ciphertext::serialize`] output for the same [`Context`]
    /// [`Params`](crate::context::Params).
    ///
    /// Same as [`crate::context::Context::deserialize_ciphertext`].
    ///
    /// # Errors
    ///
    /// Returns [`std::io::Error`] with kind [`InvalidData`](io::ErrorKind::InvalidData) if the
    /// blob does not match `T` or this context's [`GLWE`](poulpy_core::layouts::GLWE) layout.
    pub fn deserialize(ctx: &mut Context, bytes: &[u8]) -> io::Result<Self> {
        ctx.deserialize_ciphertext(bytes)
    }
}
