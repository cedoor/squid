//! Key generation and lifecycle management.
//!
//! Exposes two opaque types:
//!
//! - [`SecretKey`] — the private GLWE + LWE secret pair plus the prepared
//!   (DFT-domain) GLWE secret needed for encryption and decryption.
//!   Keep this secret; never serialize it in production.
//! - [`EvaluationKey`] — the public evaluation key bundle needed for all
//!   homomorphic operations.  Wraps Poulpy's `BDDKey` in standard and prepared
//!   forms.
//!
//! Both types are created by [`crate::context::Context::keygen`] and are
//! opaque: no fields are public.

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
    // TODO: read when adding load/serialize, key rotation, or re-prepare-from-standard APIs.
    #[allow(dead_code)]
    pub(crate) sk_glwe: GLWESecret<Vec<u8>>,
    pub(crate) sk_glwe_prepared: GLWESecretPrepared<Vec<u8>, crate::backend::BE>,
    // TODO: same as `sk_glwe` — needed for any path that reconstructs or exports the full secret.
    #[allow(dead_code)]
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
    // TODO: read when adding serialization, portable storage, or re-prepare after load (hot path uses `bdd_key_prepared` only).
    #[allow(dead_code)]
    pub(crate) bdd_key: BDDKey<Vec<u8>, CGGI>,
    /// Prepared (DFT-domain) copy used on the hot path.
    pub(crate) bdd_key_prepared: BDDKeyPrepared<Vec<u8>, CGGI, crate::backend::BE>,
}
