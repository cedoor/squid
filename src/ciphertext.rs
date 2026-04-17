//! The user-facing ciphertext type.
//!
//! [`Ciphertext<T>`] is a thin newtype over Poulpy's `FheUint<Vec<u8>, T>`.
//! It is the only ciphertext form users ever see.  The prepared (DFT-domain)
//! form `FheUintPrepared` is an implementation detail that lives temporarily
//! inside [`crate::context::Context`] during operation evaluation.
//!
//! Standard-form wire encoding is [`Ciphertext::serialize`] /
//! [`Ciphertext::deserialize`] / [`crate::context::Context::serialize_ciphertext`] /
//! [`crate::context::Context::deserialize_ciphertext`] (versioned little-endian blob;
//! must be loaded with the same [`crate::context::Params`] as encryption).

use std::io;

use poulpy_core::layouts::GLWEToRef;
use poulpy_hal::layouts::WriterTo;
use poulpy_schemes::bin_fhe::bdd_arithmetic::{FheUint, UnsignedInteger};

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
/// 1. Create with [`crate::Context::encrypt`].
/// 2. Pass to homomorphic operations (`ctx.add`, `ctx.xor`, …).
/// 3. Recover the plaintext with [`crate::Context::decrypt`].
///
/// The ciphertext is in standard (serializable) form at all times from the
/// caller's perspective.  Conversion to the prepared DFT-domain form happens
/// internally inside each operation call and is not visible here.
pub struct Ciphertext<T: UnsignedInteger> {
    pub(crate) inner: FheUint<Vec<u8>, T>,
}

impl<T: UnsignedInteger> Ciphertext<T> {
    /// Serializes the packed GLWE ciphertext (little-endian, versioned). The plaintext type `T`
    /// is recorded in the blob; use the same `T` with [`Ciphertext::deserialize`].
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
