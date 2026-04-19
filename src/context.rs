//! Top-level user entry point: [`Context`] and [`Params`].
//!
//! All public API operations flow through [`Context`].  Users should never
//! need to import anything from the other squid modules directly.
//!
//! ## Typical workflow
//!
//! ```rust,no_run
//! use squid::{Context, ContextOptions, Params};
//!
//! let mut ctx = Context::new(Params::unsecure()).with_options(ContextOptions::default());
//! let (sk, ek) = ctx.keygen();
//!
//! let a = ctx.encrypt::<u32>(42, &sk, &ek);
//! let b = ctx.encrypt::<u32>(7, &sk, &ek);
//! let c = ctx.add(&a, &b, &ek);
//! let result: u32 = ctx.decrypt(&c, &sk);
//! ```

use std::io::{self, Cursor};

use poulpy_core::{
    layouts::{
        prepared::GLWESecretPreparedFactory, Base2K, Degree, Dnum, Dsize, GGLWEToGGSWKeyLayout,
        GGSWLayout, GLWEAutomorphismKeyLayout, GLWEInfos, GLWELayout, GLWESecret,
        GLWESwitchingKeyLayout, GLWEToLWEKeyLayout, GLWEToMut, LWEInfos, LWESecret, Rank,
        TorusPrecision,
    },
    EncryptionLayout,
};
use poulpy_hal::{
    api::ModuleNew,
    layouts::{DeviceBuf, Module, ReaderFrom},
    source::Source,
};
use poulpy_schemes::bin_fhe::{
    bdd_arithmetic::{
        Add, And, BDDEncryptionInfos, BDDKey, BDDKeyEncryptSk, BDDKeyLayout, BDDKeyPrepared,
        BDDKeyPreparedFactory, FheUint, FheUintPrepared, FromBits, Or, Sll, Slt, Sltu, Sra, Srl,
        Sub, ToBits, UnsignedInteger, Xor,
    },
    blind_rotation::{BlindRotationKeyLayout, CGGI},
    circuit_bootstrapping::CircuitBootstrappingKeyLayout,
};

use crate::{
    ciphertext::CIPHERTEXT_BLOB_VERSION,
    keys::{EvaluationKey, KeygenSeeds, SecretKey, EVALUATION_KEY_BLOB_VERSION},
    scratch, Ciphertext,
};

// ── Module alias ────────────────────────────────────────────────────────────

/// The concrete Poulpy backend used by squid.
///
/// Resolved at compile time via `crate::backend::BE` (see `src/backend.rs`).
/// Defaults to `crate::backend::BE`; use `--features backend-avx` for the AVX2/FMA backend.
/// No generic backend parameter surfaces in squid's public API.
type Mod = Module<crate::backend::BE>;

#[inline]
fn assert_eval_threads(n: usize) {
    assert!(n >= 1, "eval_threads must be >= 1, got {n}");
}

// ── ContextOptions ───────────────────────────────────────────────────────────

/// Runtime options for a [`Context`], separate from cryptographic [`Params`].
///
/// Pass to [`Context::with_options`] after [`Context::new`], or use
/// [`ContextOptions::default`] for single-threaded BDD evaluation.  Invalid
/// `eval_threads` (0) is rejected when options are applied ([`Context::with_options`],
/// [`Context::set_options`]).
#[derive(Debug, Clone)]
pub struct ContextOptions {
    /// OS threads used for BDD circuit evaluation (CMux phase) on homomorphic
    /// binary ops.  **Default 1.**
    pub eval_threads: usize,
}

impl Default for ContextOptions {
    /// Single-threaded BDD evaluation: no extra OS threads, minimal scratch, and
    /// the same behavior on any machine.  Higher `eval_threads` can improve
    /// throughput on multi-core hosts but adds coordination cost and is opt-in.
    fn default() -> Self {
        Self { eval_threads: 1 }
    }
}

// ── Params ───────────────────────────────────────────────────────────────────

/// Parameter set for a [`Context`].
///
/// Wraps all layout descriptors needed for key generation, encryption, and
/// evaluation.  [`Params::unsecure`] matches Poulpy's `bdd_arithmetic` example
/// (n = 1024); [`Params::test`] matches Poulpy's `bdd_arithmetic`
/// `test_suite` layouts (smaller ring, faster tests).  Neither is a vetted
/// security level.
///
/// Advanced users may construct custom `Params` directly (often with struct
/// update syntax, e.g. `Params { n_glwe: 2048, ..Params::unsecure() }`), but
/// must ensure consistency across all layout fields — concretely, `n_glwe`,
/// `base2k`, and `rank` must agree everywhere they appear.
#[derive(Debug, Clone)]
pub struct Params {
    /// GLWE ring degree (must be a power of two; determines the ring Z_q[X]/(X^n+1)).
    pub n_glwe: u32,
    /// Block size for the binary LWE secret key distribution.
    pub binary_block_size: u32,
    /// Layout for GLWE ciphertexts and the GLWE secret key.
    pub glwe_layout: GLWELayout,
    /// Layout for GGSW ciphertexts produced by `FheUintPrepared`.
    pub ggsw_layout: GGSWLayout,
    /// Full BDD evaluation key layout.
    pub bdd_layout: BDDKeyLayout,
}

impl Params {
    /// **Not a production security target** — same bundle as Poulpy's `bdd_arithmetic` example
    /// (`poulpy-schemes/examples/bdd_arithmetic.rs`).
    ///
    /// - GLWE ring degree n = 1024, rank = 1
    /// - LWE dimension n_lwe = 567 (block-binary secret, block size 7)
    /// - base2k = 17, torus precision = 2×base2k
    ///
    /// For demos and tests only unless you have your own parameter analysis.
    pub fn unsecure() -> Self {
        const N_GLWE: u32 = 1024;
        const N_LWE: u32 = 567;
        const BINARY_BLOCK_SIZE: u32 = 7;
        const BASE2K: u32 = 17;
        const RANK: u32 = 1;

        let glwe_layout = GLWELayout {
            n: Degree(N_GLWE),
            base2k: Base2K(BASE2K),
            k: TorusPrecision(2 * BASE2K),
            rank: Rank(RANK),
        };

        let ggsw_layout = GGSWLayout {
            n: Degree(N_GLWE),
            base2k: Base2K(BASE2K),
            k: TorusPrecision(3 * BASE2K),
            rank: Rank(RANK),
            dnum: Dnum(3),
            dsize: Dsize(1),
        };

        let bdd_layout = BDDKeyLayout {
            cbt_layout: CircuitBootstrappingKeyLayout {
                brk_layout: BlindRotationKeyLayout {
                    n_glwe: Degree(N_GLWE),
                    n_lwe: Degree(N_LWE),
                    base2k: Base2K(BASE2K),
                    k: TorusPrecision(4 * BASE2K),
                    dnum: Dnum(4),
                    rank: Rank(RANK),
                },
                atk_layout: GLWEAutomorphismKeyLayout {
                    n: Degree(N_GLWE),
                    base2k: Base2K(BASE2K),
                    k: TorusPrecision(4 * BASE2K),
                    dnum: Dnum(4),
                    dsize: Dsize(1),
                    rank: Rank(RANK),
                },
                tsk_layout: GGLWEToGGSWKeyLayout {
                    n: Degree(N_GLWE),
                    base2k: Base2K(BASE2K),
                    k: TorusPrecision(4 * BASE2K),
                    dnum: Dnum(4),
                    dsize: Dsize(1),
                    rank: Rank(RANK),
                },
            },
            ks_glwe_layout: Some(GLWESwitchingKeyLayout {
                n: Degree(N_GLWE),
                base2k: Base2K(BASE2K),
                k: TorusPrecision(4 * BASE2K),
                dnum: Dnum(4),
                dsize: Dsize(1),
                rank_in: Rank(RANK),
                rank_out: Rank(1),
            }),
            ks_lwe_layout: GLWEToLWEKeyLayout {
                n: Degree(N_GLWE),
                base2k: Base2K(BASE2K),
                k: TorusPrecision(4 * BASE2K),
                rank_in: Rank(1),
                dnum: Dnum(4),
            },
        };

        Params {
            n_glwe: N_GLWE,
            binary_block_size: BINARY_BLOCK_SIZE,
            glwe_layout,
            ggsw_layout,
            bdd_layout,
        }
    }

    /// Same layout bundle as Poulpy's `bdd_arithmetic` **`test_suite`** module
    /// (`poulpy-schemes/src/bin_fhe/bdd_arithmetic/tests/test_suite/mod.rs`):
    /// ring degree 256, rank 2, smaller keys than [`Params::unsecure`].
    ///
    /// Use in tests or local dev when you want parity with Poulpy's BDD tests and
    /// faster runs than the `bdd_arithmetic` example parameters.  **Not** a
    /// production security target.  If Poulpy changes its test layouts, update
    /// this constructor to match.
    pub fn test() -> Self {
        // Keep in sync with poulpy-schemes `bdd_arithmetic::tests::test_suite` constants.
        const N_GLWE: u32 = 256;
        const N_LWE: u32 = 77;
        const FHEUINT_BASE2K: u32 = 13;
        const BRK_BASE2K: u32 = 12;
        const ATK_BASE2K: u32 = 11;
        const TSK_BASE2K: u32 = 10;
        const LWE_KS_BASE2K: u32 = 4;
        const K_GLWE: u32 = 26;
        const K_GGSW: u32 = 39;
        const BINARY_BLOCK_SIZE: u32 = 7;
        const RANK: u32 = 2;

        let glwe_layout = GLWELayout {
            n: Degree(N_GLWE),
            base2k: Base2K(FHEUINT_BASE2K),
            k: TorusPrecision(K_GLWE),
            rank: Rank(RANK),
        };

        let ggsw_layout = GGSWLayout {
            n: Degree(N_GLWE),
            base2k: Base2K(FHEUINT_BASE2K),
            k: TorusPrecision(K_GGSW),
            rank: Rank(RANK),
            dnum: Dnum(2),
            dsize: Dsize(1),
        };

        let bdd_layout = BDDKeyLayout {
            cbt_layout: CircuitBootstrappingKeyLayout {
                brk_layout: BlindRotationKeyLayout {
                    n_glwe: Degree(N_GLWE),
                    n_lwe: Degree(N_LWE),
                    base2k: Base2K(BRK_BASE2K),
                    k: TorusPrecision(52),
                    dnum: Dnum(4),
                    rank: Rank(RANK),
                },
                atk_layout: GLWEAutomorphismKeyLayout {
                    n: Degree(N_GLWE),
                    base2k: Base2K(ATK_BASE2K),
                    k: TorusPrecision(52),
                    rank: Rank(RANK),
                    dnum: Dnum(4),
                    dsize: Dsize(1),
                },
                tsk_layout: GGLWEToGGSWKeyLayout {
                    n: Degree(N_GLWE),
                    base2k: Base2K(TSK_BASE2K),
                    k: TorusPrecision(52),
                    rank: Rank(RANK),
                    dnum: Dnum(4),
                    dsize: Dsize(1),
                },
            },
            ks_glwe_layout: Some(GLWESwitchingKeyLayout {
                n: Degree(N_GLWE),
                base2k: Base2K(LWE_KS_BASE2K),
                k: TorusPrecision(20),
                rank_in: Rank(RANK),
                rank_out: Rank(1),
                dnum: Dnum(3),
                dsize: Dsize(1),
            }),
            ks_lwe_layout: GLWEToLWEKeyLayout {
                n: Degree(N_GLWE),
                base2k: Base2K(LWE_KS_BASE2K),
                k: TorusPrecision(16),
                rank_in: Rank(1),
                dnum: Dnum(3),
            },
        };

        Params {
            n_glwe: N_GLWE,
            binary_block_size: BINARY_BLOCK_SIZE,
            glwe_layout,
            ggsw_layout,
            bdd_layout,
        }
    }
}

// ── Context ──────────────────────────────────────────────────────────────────

/// The main entry point for all FHE operations.
///
/// `Context` owns the Poulpy [`Module`] (precomputed FFT tables) and the chosen
/// [`Params`].  Scratch space is allocated per operation using Poulpy’s
/// `*_tmp_bytes` helpers (same pattern as Poulpy’s examples and tests).  It does
/// **not** own any key material;
/// keys are returned from [`Context::keygen`] and passed back into each
/// operation so callers control their lifecycle.
///
/// ## Thread safety
///
/// `Context` is not `Sync`.  Create one context per thread, or wrap in a
/// `Mutex`.  Key material (`SecretKey`, `EvaluationKey`) is `Send + Sync`.
pub struct Context {
    params: Params,
    module: Mod,
    options: ContextOptions,
}

impl Context {
    /// Create a new context with the given parameter set.
    ///
    /// Uses [`ContextOptions::default`] (single-threaded BDD evaluation).  Chain
    /// [`Context::with_options`] to change that, e.g.
    /// `Context::new(params).with_options(ContextOptions { eval_threads: 4 })`.
    ///
    /// Allocates the FFT tables.  Scratch is allocated per-operation on the
    /// encrypt/decrypt/keygen/eval paths; see Poulpy’s `*_tmp_bytes` sizing.
    pub fn new(params: Params) -> Self {
        let options = ContextOptions::default();
        assert_eval_threads(options.eval_threads);
        let module = Mod::new(params.n_glwe as u64);
        Context {
            params,
            module,
            options,
        }
    }

    /// Applies runtime options, replacing any previous [`ContextOptions`].
    ///
    /// # Panics
    ///
    /// If `options.eval_threads` is zero.
    pub fn with_options(mut self, options: ContextOptions) -> Self {
        assert_eval_threads(options.eval_threads);
        self.options = options;
        self
    }

    /// Returns a copy of the current [`ContextOptions`].
    pub fn options(&self) -> ContextOptions {
        self.options.clone()
    }

    /// BDD evaluation thread count from the active [`ContextOptions`].
    pub fn eval_threads(&self) -> usize {
        self.options.eval_threads
    }

    /// Updates runtime options in place (same rules as [`Context::with_options`]).
    ///
    /// # Panics
    ///
    /// If `options.eval_threads` is zero.
    pub fn set_options(&mut self, options: ContextOptions) {
        assert_eval_threads(options.eval_threads);
        self.options = options;
    }

    /// Sets only [`ContextOptions::eval_threads`] (same rules as [`Context::with_options`]).
    ///
    /// # Panics
    ///
    /// If `eval_threads` is zero.
    pub fn with_eval_threads(self, eval_threads: usize) -> Self {
        let mut opts = self.options();
        opts.eval_threads = eval_threads;
        self.with_options(opts)
    }

    /// Same as [`Context::with_eval_threads`], in-place (`&mut self`).
    ///
    /// # Panics
    ///
    /// If `eval_threads` is zero.
    pub fn set_eval_threads(&mut self, eval_threads: usize) {
        let mut opts = self.options();
        opts.eval_threads = eval_threads;
        self.set_options(opts);
    }

    /// Generate a fresh secret key and the corresponding evaluation key.
    ///
    /// Uses OS randomness to seed the three ChaCha8 streams required by Poulpy
    /// (lattice secrets, BDD public masks, BDD noise). Does not return the seeds;
    /// use [`Context::keygen_with_seeds`] if you need [`KeygenSeeds`] for persistence.
    ///
    /// # Panics
    ///
    /// Panics if the OS cannot supply enough random bytes (extremely unlikely).
    pub fn keygen(&mut self) -> (SecretKey, EvaluationKey) {
        let (sk, ek, _) = self.keygen_with_seeds();
        (sk, ek)
    }

    /// Like [`Context::keygen`], but also returns the [`KeygenSeeds`] for replay via
    /// [`Context::keygen_from_seeds`].
    ///
    /// # Panics
    ///
    /// Panics if the OS cannot supply enough random bytes (extremely unlikely).
    pub fn keygen_with_seeds(&mut self) -> (SecretKey, EvaluationKey, KeygenSeeds) {
        let mut lattice = [0u8; 32];
        let mut bdd_mask = [0u8; 32];
        let mut bdd_noise = [0u8; 32];

        getrandom::fill(&mut lattice).expect("OS random number generator unavailable");
        getrandom::fill(&mut bdd_mask).expect("OS random number generator unavailable");
        getrandom::fill(&mut bdd_noise).expect("OS random number generator unavailable");

        let seeds = KeygenSeeds {
            lattice,
            bdd_mask,
            bdd_noise,
        };
        let (sk, ek) = self.keygen_from_seeds(seeds);

        (sk, ek, seeds)
    }

    /// Deterministic key generation from stored [`KeygenSeeds`] for the same [`Params`] and backend.
    pub fn keygen_from_seeds(&mut self, seeds: KeygenSeeds) -> (SecretKey, EvaluationKey) {
        let mut source_xs = Source::new(seeds.lattice);
        let sk = self.secret_key_material_from_lattice_source(&mut source_xs);
        let mut source_xa = Source::new(seeds.bdd_mask);
        let mut source_xe = Source::new(seeds.bdd_noise);

        // BDD evaluation key (standard form)
        let bdd_enc_infos = BDDEncryptionInfos::from_default_sigma(&self.params.bdd_layout)
            .expect("default BDD encryption sigma");
        let mut bdd_key: BDDKey<Vec<u8>, CGGI> = BDDKey::alloc_from_infos(&self.params.bdd_layout);
        let keygen_bytes = self
            .module
            .bdd_key_encrypt_sk_tmp_bytes(&self.params.bdd_layout)
            .max(
                self.module
                    .prepare_bdd_key_tmp_bytes(&self.params.bdd_layout),
            );
        let mut keygen_arena = scratch::new_arena(keygen_bytes);
        let scratch = scratch::borrow(&mut keygen_arena);
        bdd_key.encrypt_sk(
            &self.module,
            &sk.sk_lwe,
            &sk.sk_glwe,
            &bdd_enc_infos,
            &mut source_xe,
            &mut source_xa,
            scratch,
        );

        // BDD evaluation key (prepared / DFT form)
        let mut bdd_key_prepared: BDDKeyPrepared<
            DeviceBuf<crate::backend::BE>,
            CGGI,
            crate::backend::BE,
        > = BDDKeyPrepared::alloc_from_infos(&self.module, &self.params.bdd_layout);
        bdd_key_prepared.prepare(&self.module, &bdd_key, scratch);

        let ek = EvaluationKey {
            bdd_key,
            bdd_key_prepared,
        };
        (sk, ek)
    }

    /// Secret key material (encrypt/decrypt) from the **lattice** ChaCha seed only — the same
    /// [`KeygenSeeds::lattice`] field used in [`Context::keygen_from_seeds`].
    ///
    /// Does not use [`KeygenSeeds::bdd_mask`] or [`KeygenSeeds::bdd_noise`]; you must obtain an
    /// [`EvaluationKey`] separately (e.g. full [`Context::keygen_from_seeds`] or
    /// [`Context::deserialize_evaluation_key`]).
    pub fn secret_key_from_lattice_seed(&mut self, lattice_seed: [u8; 32]) -> SecretKey {
        let mut source_xs = Source::new(lattice_seed);
        self.secret_key_material_from_lattice_source(&mut source_xs)
    }

    fn secret_key_material_from_lattice_source(&mut self, source_xs: &mut Source) -> SecretKey {
        let mut sk_glwe = GLWESecret::alloc_from_infos(&self.params.glwe_layout);
        sk_glwe.fill_ternary_prob(0.5, source_xs);

        let mut sk_lwe = LWESecret::alloc(self.params.bdd_layout.cbt_layout.brk_layout.n_lwe);
        sk_lwe.fill_binary_block(self.params.binary_block_size as usize, source_xs);

        let mut sk_glwe_prepared = self
            .module
            .glwe_secret_prepared_alloc_from_infos(&self.params.glwe_layout);
        self.module
            .glwe_secret_prepare(&mut sk_glwe_prepared, &sk_glwe);

        SecretKey {
            sk_glwe,
            sk_glwe_prepared,
            sk_lwe,
        }
    }

    /// Serializes the standard-form BDD evaluation key (little-endian, versioned).
    /// The prepared key is not stored; use [`Context::deserialize_evaluation_key`].
    ///
    /// Same as [`EvaluationKey::serialize`].
    pub fn serialize_evaluation_key(&self, ek: &EvaluationKey) -> io::Result<Vec<u8>> {
        ek.serialize()
    }

    /// Restores an [`EvaluationKey`] from [`EvaluationKey::serialize`] / [`Context::serialize_evaluation_key`] for the same [`Params`].
    ///
    /// # Errors
    ///
    /// Returns [`std::io::Error`] with kind [`InvalidData`](io::ErrorKind::InvalidData) if the
    /// blob does not match this context's [`Params`] layouts.
    pub fn deserialize_evaluation_key(&mut self, bytes: &[u8]) -> io::Result<EvaluationKey> {
        let Some((&ver, rest)) = bytes.split_first() else {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "empty evaluation key blob",
            ));
        };
        if ver != EVALUATION_KEY_BLOB_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported evaluation key blob version {ver}"),
            ));
        }
        let mut r = Cursor::new(rest);
        let mut bdd_key = BDDKey::alloc_from_infos(&self.params.bdd_layout);
        bdd_key.read_from(&mut r)?;
        if (r.position() as usize) != rest.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "trailing bytes in evaluation key blob",
            ));
        }
        let mut bdd_key_prepared: BDDKeyPrepared<
            DeviceBuf<crate::backend::BE>,
            CGGI,
            crate::backend::BE,
        > = BDDKeyPrepared::alloc_from_infos(&self.module, &self.params.bdd_layout);
        let mut scratch_p = scratch::new_arena(
            self.module
                .prepare_bdd_key_tmp_bytes(&self.params.bdd_layout),
        );
        bdd_key_prepared.prepare(&self.module, &bdd_key, scratch::borrow(&mut scratch_p));
        Ok(EvaluationKey {
            bdd_key,
            bdd_key_prepared,
        })
    }

    /// Serializes a [`Ciphertext<T>`] (little-endian, versioned).
    ///
    /// Same as [`Ciphertext::serialize`].
    pub fn serialize_ciphertext<T: UnsignedInteger>(
        &self,
        ct: &Ciphertext<T>,
    ) -> io::Result<Vec<u8>> {
        ct.serialize()
    }

    /// Restores a [`Ciphertext<T>`] from [`Ciphertext::serialize`] / [`Context::serialize_ciphertext`]
    /// for the same [`Params`].
    ///
    /// # Errors
    ///
    /// Returns [`std::io::Error`] with kind [`InvalidData`](io::ErrorKind::InvalidData) if the
    /// blob does not match `T` or this context's [`GLWELayout`].
    pub fn deserialize_ciphertext<T>(&mut self, bytes: &[u8]) -> io::Result<Ciphertext<T>>
    where
        T: UnsignedInteger,
    {
        let Some((&ver, rest)) = bytes.split_first() else {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "empty ciphertext blob",
            ));
        };
        if ver != CIPHERTEXT_BLOB_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported ciphertext blob version {ver}"),
            ));
        }
        if rest.len() < 4 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "ciphertext blob truncated (bit width)",
            ));
        }
        let bits = u32::from_le_bytes(rest[..4].try_into().unwrap());
        if bits != T::BITS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "ciphertext blob declares {bits} bit plaintext width but {} was requested",
                    T::BITS
                ),
            ));
        }
        let payload = &rest[4..];
        let mut r = Cursor::new(payload);
        let mut fhe_uint = FheUint::alloc_from_infos(&self.params.glwe_layout);
        fhe_uint.to_mut().read_from(&mut r)?;
        let gl = &self.params.glwe_layout;
        if fhe_uint.n() != gl.n
            || fhe_uint.base2k() != gl.base2k
            || fhe_uint.max_k() != gl.k
            || fhe_uint.rank() != gl.rank
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ciphertext GLWE parameters do not match context Params",
            ));
        }
        if (r.position() as usize) != payload.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "trailing bytes in ciphertext blob",
            ));
        }
        Ok(Ciphertext {
            inner: fhe_uint,
            prepared: None,
        })
    }

    // ── Encrypt / Decrypt ────────────────────────────────────────────────────

    /// Encrypt a plaintext value under the given secret key.
    ///
    /// Internally encrypts directly to the prepared (DFT-domain) form via
    /// `FheUintPrepared::encrypt_sk`, then packs to a standard `FheUint` via
    /// `from_fhe_uint_prepared` (which is why an [`EvaluationKey`] is required).
    /// This matches the path validated by Poulpy's `test_bdd_add` and avoids the
    /// `FheUint::encrypt_sk -> FheUintPrepared::prepare` pipeline, which is
    /// currently broken upstream (`b598566`).
    ///
    /// The cached prepared form is consumed by homomorphic ops; the packed
    /// inner form is used for [`Context::decrypt`] and serialization.
    ///
    /// `T` must be one of `u8`, `u16`, `u32`, `u64`, `u128`.  Note that
    /// homomorphic arithmetic operations are currently only implemented for
    /// `u32` (the only type with compiled BDD circuits in `poulpy-schemes`).
    pub fn encrypt<T>(&mut self, value: T, sk: &SecretKey, ek: &EvaluationKey) -> Ciphertext<T>
    where
        T: UnsignedInteger + ToBits + FromBits,
    {
        let mut source_xa = random_source();
        let mut source_xe = random_source();
        let ggsw_enc_infos = EncryptionLayout::new_from_default_sigma(self.params.ggsw_layout)
            .expect("default GGSW encryption sigma");

        // TODO(poulpy-bug): switch to dynamic sizing once poulpy fixes the
        // upstream `FheUint::encrypt_sk -> FheUintPrepared::prepare` bug
        // (see `crate::ciphertext` module docs).  Once fixed, encrypt should
        // route through that path and use `FheUint::encrypt_sk_tmp_bytes` +
        // `Module::fhe_uint_prepare_tmp_bytes` for exact scratch sizing.
        //
        // Until then we work around the bug via `FheUintPrepared::encrypt_sk`
        // followed by `FheUint::from_fhe_uint_prepared`.  Poulpy exposes no
        // wrapper-level `*_tmp_bytes` helpers for either, and hand-composing
        // from primitives is fragile (both wrappers call into deeper helpers
        // like `glwe_pack -> glwe_trace` whose runtime scratch checks don't
        // match a naive sum of public `_tmp_bytes`).  Poulpy's own
        // `bdd_arithmetic` example/tests use a single 4 MiB arena for the
        // whole pipeline; we do the same here for these two sequential ops.
        const ENCRYPT_SCRATCH_BYTES: usize = 1 << 22;
        let mut scratch_arena = scratch::new_arena(ENCRYPT_SCRATCH_BYTES);

        let mut prepared: FheUintPrepared<DeviceBuf<crate::backend::BE>, T, crate::backend::BE> =
            FheUintPrepared::alloc_from_infos(&self.module, &self.params.ggsw_layout);
        prepared.encrypt_sk(
            &self.module,
            value,
            &sk.sk_glwe_prepared,
            &ggsw_enc_infos,
            &mut source_xe,
            &mut source_xa,
            scratch::borrow(&mut scratch_arena),
        );

        let mut packed: FheUint<Vec<u8>, T> = FheUint::alloc_from_infos(&self.params.glwe_layout);
        packed.from_fhe_uint_prepared(
            &self.module,
            &prepared,
            &ek.bdd_key_prepared,
            scratch::borrow(&mut scratch_arena),
        );

        Ciphertext {
            inner: packed,
            prepared: Some(prepared),
        }
    }

    /// Decrypt a ciphertext and return the plaintext value.
    pub fn decrypt<T>(&mut self, ct: &Ciphertext<T>, sk: &SecretKey) -> T
    where
        T: UnsignedInteger + FromBits,
    {
        let dec_bytes = ct.inner.decrypt_tmp_bytes(&self.module);
        let mut scratch_d = scratch::new_arena(dec_bytes);
        ct.inner.decrypt(
            &self.module,
            &sk.sk_glwe_prepared,
            scratch::borrow(&mut scratch_d),
        )
    }

    // ── Internal helper ───────────────────────────────────────────────────────

    /// Run a binary op on the prepared form of `a` and `b`.
    ///
    /// Both inputs must carry their prepared cache (i.e. come straight from
    /// [`Context::encrypt`]). Op outputs and deserialized ciphertexts have
    /// no cache and panic with a clear message — see the [`crate::ciphertext`]
    /// module docs for the upstream limitation.
    fn eval_binary<T, F>(
        &mut self,
        a: &Ciphertext<T>,
        b: &Ciphertext<T>,
        ek: &EvaluationKey,
        eval_scratch_bytes: usize,
        op: F,
    ) -> Ciphertext<T>
    where
        T: UnsignedInteger,
        F: FnOnce(
            &Mod,
            usize,
            &mut FheUint<Vec<u8>, T>,
            &FheUintPrepared<DeviceBuf<crate::backend::BE>, T, crate::backend::BE>,
            &FheUintPrepared<DeviceBuf<crate::backend::BE>, T, crate::backend::BE>,
            &BDDKeyPrepared<DeviceBuf<crate::backend::BE>, CGGI, crate::backend::BE>,
            &mut poulpy_hal::layouts::Scratch<crate::backend::BE>,
        ),
    {
        const NO_PREPARED_CACHE: &str =
            "ciphertext lacks prepared cache; only freshly encrypted ciphertexts can be operated \
             on in this Poulpy revision (see ciphertext module docs)";
        let a_prep = a.prepared.as_ref().expect(NO_PREPARED_CACHE);
        let b_prep = b.prepared.as_ref().expect(NO_PREPARED_CACHE);

        let mut out: FheUint<Vec<u8>, T> = FheUint::alloc_from_infos(&self.params.glwe_layout);
        let mut scratch_eval = scratch::new_arena(eval_scratch_bytes);
        op(
            &self.module,
            self.options.eval_threads,
            &mut out,
            a_prep,
            b_prep,
            &ek.bdd_key_prepared,
            scratch::borrow(&mut scratch_eval),
        );
        Ciphertext {
            inner: out,
            prepared: None,
        }
    }

    // ── Arithmetic and logical operations ────────────────────────────────────

    /// Homomorphic wrapping addition: `a + b`.
    pub fn add<T>(
        &mut self,
        a: &Ciphertext<T>,
        b: &Ciphertext<T>,
        ek: &EvaluationKey,
    ) -> Ciphertext<T>
    where
        T: UnsignedInteger,
        FheUint<Vec<u8>, T>: Add<T, crate::backend::BE>,
    {
        let eval_threads = self.options.eval_threads;
        let eval_bytes = if eval_threads == 1 {
            a.inner.add_tmp_bytes(
                &self.module,
                &self.params.glwe_layout,
                &self.params.ggsw_layout,
                &ek.bdd_key_prepared,
            )
        } else {
            a.inner.add_multi_thread_tmp_bytes(
                &self.module,
                eval_threads,
                &self.params.glwe_layout,
                &self.params.ggsw_layout,
                &ek.bdd_key_prepared,
            )
        };
        self.eval_binary(
            a,
            b,
            ek,
            eval_bytes,
            |module, _threads, out, ap, bp, key, scratch| {
                if eval_threads == 1 {
                    out.add(module, ap, bp, key, scratch);
                } else {
                    out.add_multi_thread(eval_threads, module, ap, bp, key, scratch);
                }
            },
        )
    }

    /// Homomorphic wrapping subtraction: `a - b`.
    pub fn sub<T>(
        &mut self,
        a: &Ciphertext<T>,
        b: &Ciphertext<T>,
        ek: &EvaluationKey,
    ) -> Ciphertext<T>
    where
        T: UnsignedInteger,
        FheUint<Vec<u8>, T>: Sub<T, crate::backend::BE>,
    {
        let eval_bytes = a.inner.sub_multi_thread_tmp_bytes(
            &self.module,
            self.options.eval_threads,
            &self.params.glwe_layout,
            &self.params.ggsw_layout,
            &ek.bdd_key_prepared,
        );
        self.eval_binary(
            a,
            b,
            ek,
            eval_bytes,
            |module, threads, out, ap, bp, key, scratch| {
                out.sub_multi_thread(threads, module, ap, bp, key, scratch);
            },
        )
    }

    /// Homomorphic bitwise AND: `a & b`.
    pub fn and<T>(
        &mut self,
        a: &Ciphertext<T>,
        b: &Ciphertext<T>,
        ek: &EvaluationKey,
    ) -> Ciphertext<T>
    where
        T: UnsignedInteger,
        FheUint<Vec<u8>, T>: And<T, crate::backend::BE>,
    {
        let eval_bytes = a.inner.and_multi_thread_tmp_bytes(
            &self.module,
            self.options.eval_threads,
            &self.params.glwe_layout,
            &self.params.ggsw_layout,
            &ek.bdd_key_prepared,
        );
        self.eval_binary(
            a,
            b,
            ek,
            eval_bytes,
            |module, threads, out, ap, bp, key, scratch| {
                out.and_multi_thread(threads, module, ap, bp, key, scratch);
            },
        )
    }

    /// Homomorphic bitwise OR: `a | b`.
    pub fn or<T>(
        &mut self,
        a: &Ciphertext<T>,
        b: &Ciphertext<T>,
        ek: &EvaluationKey,
    ) -> Ciphertext<T>
    where
        T: UnsignedInteger,
        FheUint<Vec<u8>, T>: Or<T, crate::backend::BE>,
    {
        let eval_bytes = a.inner.or_multi_thread_tmp_bytes(
            &self.module,
            self.options.eval_threads,
            &self.params.glwe_layout,
            &self.params.ggsw_layout,
            &ek.bdd_key_prepared,
        );
        self.eval_binary(
            a,
            b,
            ek,
            eval_bytes,
            |module, threads, out, ap, bp, key, scratch| {
                out.or_multi_thread(threads, module, ap, bp, key, scratch);
            },
        )
    }

    /// Homomorphic bitwise XOR: `a ^ b`.
    pub fn xor<T>(
        &mut self,
        a: &Ciphertext<T>,
        b: &Ciphertext<T>,
        ek: &EvaluationKey,
    ) -> Ciphertext<T>
    where
        T: UnsignedInteger,
        FheUint<Vec<u8>, T>: Xor<T, crate::backend::BE>,
    {
        let eval_bytes = a.inner.xor_multi_thread_tmp_bytes(
            &self.module,
            self.options.eval_threads,
            &self.params.glwe_layout,
            &self.params.ggsw_layout,
            &ek.bdd_key_prepared,
        );
        self.eval_binary(
            a,
            b,
            ek,
            eval_bytes,
            |module, threads, out, ap, bp, key, scratch| {
                out.xor_multi_thread(threads, module, ap, bp, key, scratch);
            },
        )
    }

    /// Homomorphic logical left shift: `a << b`.
    pub fn sll<T>(
        &mut self,
        a: &Ciphertext<T>,
        b: &Ciphertext<T>,
        ek: &EvaluationKey,
    ) -> Ciphertext<T>
    where
        T: UnsignedInteger,
        FheUint<Vec<u8>, T>: Sll<T, crate::backend::BE>,
    {
        let eval_bytes = a.inner.sll_multi_thread_tmp_bytes(
            &self.module,
            self.options.eval_threads,
            &self.params.glwe_layout,
            &self.params.ggsw_layout,
            &ek.bdd_key_prepared,
        );
        self.eval_binary(
            a,
            b,
            ek,
            eval_bytes,
            |module, threads, out, ap, bp, key, scratch| {
                out.sll_multi_thread(threads, module, ap, bp, key, scratch);
            },
        )
    }

    /// Homomorphic logical right shift: `a >> b` (zero-extending).
    pub fn srl<T>(
        &mut self,
        a: &Ciphertext<T>,
        b: &Ciphertext<T>,
        ek: &EvaluationKey,
    ) -> Ciphertext<T>
    where
        T: UnsignedInteger,
        FheUint<Vec<u8>, T>: Srl<T, crate::backend::BE>,
    {
        let eval_bytes = a.inner.srl_multi_thread_tmp_bytes(
            &self.module,
            self.options.eval_threads,
            &self.params.glwe_layout,
            &self.params.ggsw_layout,
            &ek.bdd_key_prepared,
        );
        self.eval_binary(
            a,
            b,
            ek,
            eval_bytes,
            |module, threads, out, ap, bp, key, scratch| {
                out.srl_multi_thread(threads, module, ap, bp, key, scratch);
            },
        )
    }

    /// Homomorphic arithmetic right shift: `a >> b` (sign-extending).
    pub fn sra<T>(
        &mut self,
        a: &Ciphertext<T>,
        b: &Ciphertext<T>,
        ek: &EvaluationKey,
    ) -> Ciphertext<T>
    where
        T: UnsignedInteger,
        FheUint<Vec<u8>, T>: Sra<T, crate::backend::BE>,
    {
        let eval_bytes = a.inner.sra_multi_thread_tmp_bytes(
            &self.module,
            self.options.eval_threads,
            &self.params.glwe_layout,
            &self.params.ggsw_layout,
            &ek.bdd_key_prepared,
        );
        self.eval_binary(
            a,
            b,
            ek,
            eval_bytes,
            |module, threads, out, ap, bp, key, scratch| {
                out.sra_multi_thread(threads, module, ap, bp, key, scratch);
            },
        )
    }

    /// Homomorphic signed less-than: result is `1` if `(a as signed) < (b as signed)`, else `0`.
    pub fn slt<T>(
        &mut self,
        a: &Ciphertext<T>,
        b: &Ciphertext<T>,
        ek: &EvaluationKey,
    ) -> Ciphertext<T>
    where
        T: UnsignedInteger,
        FheUint<Vec<u8>, T>: Slt<T, crate::backend::BE>,
    {
        let eval_bytes = a.inner.slt_multi_thread_tmp_bytes(
            &self.module,
            self.options.eval_threads,
            &self.params.glwe_layout,
            &self.params.ggsw_layout,
            &ek.bdd_key_prepared,
        );
        self.eval_binary(
            a,
            b,
            ek,
            eval_bytes,
            |module, threads, out, ap, bp, key, scratch| {
                out.slt_multi_thread(threads, module, ap, bp, key, scratch);
            },
        )
    }

    /// Homomorphic unsigned less-than: result is `1` if `a < b`, else `0`.
    pub fn sltu<T>(
        &mut self,
        a: &Ciphertext<T>,
        b: &Ciphertext<T>,
        ek: &EvaluationKey,
    ) -> Ciphertext<T>
    where
        T: UnsignedInteger,
        FheUint<Vec<u8>, T>: Sltu<T, crate::backend::BE>,
    {
        let eval_bytes = a.inner.sltu_multi_thread_tmp_bytes(
            &self.module,
            self.options.eval_threads,
            &self.params.glwe_layout,
            &self.params.ggsw_layout,
            &ek.bdd_key_prepared,
        );
        self.eval_binary(
            a,
            b,
            ek,
            eval_bytes,
            |module, threads, out, ap, bp, key, scratch| {
                out.sltu_multi_thread(threads, module, ap, bp, key, scratch);
            },
        )
    }
}

// ── Internal utilities ────────────────────────────────────────────────────────

/// Construct a [`Source`] seeded from OS randomness.
fn random_source() -> Source {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("OS random number generator unavailable");
    Source::new(seed)
}
