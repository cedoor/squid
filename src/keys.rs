//! Key generation and lifecycle management.
//!
//! Exposes two opaque types:
//!
//! - [`SecretKey`] — the private GLWE + LWE secret pair plus the prepared
//!   (DFT-domain) GLWE secret needed for encryption and decryption.
//!   Keep this secret; treat serialized blobs like raw key material.
//! - [`EvaluationKey`] — the public evaluation key bundle needed for all
//!   homomorphic operations.  Wraps Poulpy's `BDDKey` in standard and prepared
//!   forms.
//!
//! Both types are created by [`crate::context::Context::keygen`] and are
//! opaque: no fields are public. Standard-form serialization is exposed via
//! [`crate::Context::serialize_secret_key`], [`crate::Context::serialize_evaluation_key`],
//! and the matching `deserialize_*` methods.

use poulpy_core::layouts::{GLWESecret, GLWESecretPrepared, LWESecret};
use poulpy_schemes::bin_fhe::{
    bdd_arithmetic::{BDDKey, BDDKeyPrepared},
    blind_rotation::CGGI,
};

/// The private key material.
///
/// Contains the GLWE and LWE secret keys (standard form for storage) plus the
/// prepared GLWE secret (DFT-domain, needed by encrypt/decrypt).
///
/// Created by [`crate::Context::keygen`].
pub struct SecretKey {
    pub(crate) sk_glwe: GLWESecret<Vec<u8>>,
    pub(crate) sk_glwe_prepared: GLWESecretPrepared<Vec<u8>, crate::backend::BE>,
    pub(crate) sk_lwe: LWESecret<Vec<u8>>,
}

/// The public evaluation key bundle.
///
/// Wraps a [`BDDKey`] in both standard (serializable) and prepared
/// (DFT-domain) forms.  Passed to every homomorphic operation on
/// [`crate::Ciphertext`].
///
/// Created by [`crate::Context::keygen`].
pub struct EvaluationKey {
    /// Standard-form BDD key (circuit bootstrapping + switching keys).
    pub(crate) bdd_key: BDDKey<Vec<u8>, CGGI>,
    /// Prepared (DFT-domain) copy used on the hot path.
    pub(crate) bdd_key_prepared: BDDKeyPrepared<Vec<u8>, CGGI, crate::backend::BE>,
}
