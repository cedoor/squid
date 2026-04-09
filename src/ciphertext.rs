//! The user-facing ciphertext type.
//!
//! [`Ciphertext<T>`] is a thin newtype over Poulpy's `FheUint<Vec<u8>, T>`.
//! It is the only ciphertext form users ever see.  The prepared (DFT-domain)
//! form `FheUintPrepared` is an implementation detail that lives temporarily
//! inside [`crate::context::Context`] during operation evaluation.

use poulpy_schemes::bin_fhe::bdd_arithmetic::{FheUint, UnsignedInteger};

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
