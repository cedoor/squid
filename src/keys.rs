//! Key generation and lifecycle management.
//!
//! Exposes two types that are **opaque to dependents**: their fields are
//! `pub(crate)` only, so other crates see the type plus public methods, not a
//! public field layout.
//!
//! - [`SecretKey`] — the private GLWE + LWE secret pair plus the prepared
//!   (DFT-domain) GLWE secret needed for encryption and decryption.
//!   Keep this secret; this crate does not offer binary serialization for it.
//! - [`EvaluationKey`] — the public evaluation key bundle needed for all
//!   homomorphic operations.  Wraps Poulpy's `BDDKey` in standard and prepared
//!   forms.
//!
//! Persist [`KeygenSeeds`] using [`crate::context::Context::keygen_with_seeds`], then rebuild
//! with [`crate::context::Context::keygen_from_seeds`] instead of serializing raw polynomials.
//! [`crate::context::Context::keygen`] returns keys only (no seeds). Standard-form serialization
//! for the evaluation key only is exposed
//! via [`EvaluationKey::serialize`] / [`crate::context::Context::serialize_evaluation_key`] and
//! [`EvaluationKey::deserialize`] / [`crate::context::Context::deserialize_evaluation_key`].
//!
//! For application-level use of the standard-form GLWE/LWE polynomials (not
//! supported as a stable wire format by Poulpy), see [`SecretKey::glwe_standard`]
//! and [`SecretKey::lwe_standard`]. For the standard-form BDD key material (same
//! blob as [`EvaluationKey::serialize`]), see [`EvaluationKey::bdd_standard`],
//! [`EvaluationKey::serialize`], and [`EvaluationKey::deserialize`].

use std::io;

use poulpy_core::layouts::{prepared::GLWESecretPrepared, GLWESecret, LWESecret};
use poulpy_hal::layouts::{DeviceBuf, WriterTo};
use poulpy_schemes::bin_fhe::{
    bdd_arithmetic::{BDDKey, BDDKeyPrepared},
    blind_rotation::CGGI,
};

use crate::context::Context;

/// Leading byte of [`EvaluationKey::serialize`] / [`crate::context::Context::serialize_evaluation_key`] blobs.
pub(crate) const EVALUATION_KEY_BLOB_VERSION: u8 = 1;

/// Three 32-byte ChaCha8 seeds used by [`crate::context::Context::keygen_from_seeds`].
///
/// These match the three independent [`poulpy_hal::source::Source`] streams in
/// Poulpy key generation: lattice secrets (GLWE + LWE), BDD public-mask
/// randomness, and BDD error randomness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeygenSeeds {
    pub lattice: [u8; 32],
    pub bdd_mask: [u8; 32],
    pub bdd_noise: [u8; 32],
}

/// The private key material.
///
/// Holds the GLWE and LWE secrets in standard form (same values produced during
/// [`crate::Context::keygen`]) plus the prepared GLWE secret used on the
/// encrypt/decrypt path.
///
/// Created by [`crate::context::Context::keygen`], [`crate::context::Context::keygen_with_seeds`],
/// [`crate::context::Context::keygen_from_seeds`], or [`SecretKey::from_lattice_seed`] /
/// [`crate::context::Context::secret_key_from_lattice_seed`] (lattice seed only).
pub struct SecretKey {
    pub(crate) sk_glwe: GLWESecret<Vec<u8>>,
    pub(crate) sk_glwe_prepared: GLWESecretPrepared<DeviceBuf<crate::backend::BE>, crate::backend::BE>,
    pub(crate) sk_lwe: LWESecret<Vec<u8>>,
}

impl SecretKey {
    /// GLWE + LWE + prepared GLWE from the lattice ChaCha seed only ([`KeygenSeeds::lattice`]).
    /// Same as [`crate::context::Context::secret_key_from_lattice_seed`]. No [`EvaluationKey`] is produced.
    pub fn from_lattice_seed(ctx: &mut Context, lattice_seed: [u8; 32]) -> Self {
        ctx.secret_key_from_lattice_seed(lattice_seed)
    }

    /// Standard-form GLWE secret (polynomial masks). Encrypt/decrypt uses the
    /// prepared copy; this is the raw material from key generation.
    pub fn glwe_standard(&self) -> &GLWESecret<Vec<u8>> {
        &self.sk_glwe
    }

    /// Standard-form LWE secret used when building the BDD evaluation key.
    pub fn lwe_standard(&self) -> &LWESecret<Vec<u8>> {
        &self.sk_lwe
    }
}

/// The public evaluation key bundle.
///
/// Wraps a [`BDDKey`] in both standard (serializable) and prepared
/// (DFT-domain) forms.  Passed to every homomorphic operation on
/// [`crate::Ciphertext`].
///
/// Created by [`crate::context::Context::keygen`], [`crate::context::Context::keygen_with_seeds`],
/// [`crate::context::Context::keygen_from_seeds`], or [`EvaluationKey::deserialize`] /
/// [`crate::context::Context::deserialize_evaluation_key`].
pub struct EvaluationKey {
    /// Standard-form BDD key (circuit bootstrapping + switching keys).
    pub(crate) bdd_key: BDDKey<Vec<u8>, CGGI>,
    /// Prepared (DFT-domain) copy used on the hot path.
    pub(crate) bdd_key_prepared: BDDKeyPrepared<DeviceBuf<crate::backend::BE>, CGGI, crate::backend::BE>,
}

impl EvaluationKey {
    /// Serializes the standard-form BDD key (little-endian, versioned). The prepared key is not stored;
    /// reload with [`EvaluationKey::deserialize`].
    ///
    /// Same as [`crate::context::Context::serialize_evaluation_key`] with this key as argument.
    pub fn serialize(&self) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        out.push(EVALUATION_KEY_BLOB_VERSION);
        self.bdd_key.write_to(&mut out)?;
        Ok(out)
    }

    /// Restores an [`EvaluationKey`] from [`EvaluationKey::serialize`] output for the same [`Context`]
    /// [`Params`](crate::context::Params).
    ///
    /// Same as [`crate::context::Context::deserialize_evaluation_key`].
    ///
    /// # Errors
    ///
    /// Returns [`std::io::Error`] with kind [`InvalidData`](io::ErrorKind::InvalidData) if the
    /// blob does not match this context's layouts.
    pub fn deserialize(ctx: &mut Context, bytes: &[u8]) -> io::Result<Self> {
        ctx.deserialize_evaluation_key(bytes)
    }

    /// Standard-form BDD key (circuit bootstrapping + switching keys). This is
    /// what [`EvaluationKey::serialize`] writes; the prepared copy is used only on the
    /// homomorphic path inside [`crate::context::Context`].
    pub fn bdd_standard(&self) -> &BDDKey<Vec<u8>, CGGI> {
        &self.bdd_key
    }
}
