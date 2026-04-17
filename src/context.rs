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
//! let a = ctx.encrypt::<u32>(42, &sk);
//! let b = ctx.encrypt::<u32>(7, &sk);
//! let c = ctx.add(&a, &b, &ek);
//! let result: u32 = ctx.decrypt(&c, &sk);
//! ```

use std::io::{self, Cursor};

use poulpy_core::layouts::{
    Base2K, Degree, Dnum, Dsize, GGLWEToGGSWKeyLayout, GGSWLayout, GLWEAutomorphismKeyLayout,
    GLWELayout, GLWESecret, GLWESecretPrepared, GLWESwitchingKeyLayout, GLWEToLWEKeyLayout,
    LWESecret, Rank, TorusPrecision,
};
use poulpy_hal::{
    api::ModuleNew,
    layouts::{Module, ReaderFrom},
    source::Source,
};
use poulpy_schemes::bin_fhe::{
    bdd_arithmetic::{
        Add, And, BDDKey, BDDKeyEncryptSk, BDDKeyLayout, BDDKeyPrepared, BDDKeyPreparedFactory,
        FheUint, FheUintPrepare, FheUintPrepared, FromBits, Or, Sll, Slt, Sltu, Sra, Srl, Sub,
        ToBits, UnsignedInteger, Xor,
    },
    blind_rotation::{BlindRotationKeyLayout, CGGI},
    circuit_bootstrapping::CircuitBootstrappingKeyLayout,
};

use crate::{
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
/// `Context` owns the Poulpy [`Module`] (precomputed FFT tables), the scratch
/// arena, and the chosen [`Params`].  It does **not** own any key material;
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
    arena: scratch::Arena,
    options: ContextOptions,
}

impl Context {
    /// Create a new context with the given parameter set.
    ///
    /// Uses [`ContextOptions::default`] (single-threaded BDD evaluation).  Chain
    /// [`Context::with_options`] to change that, e.g.
    /// `Context::new(params).with_options(ContextOptions { eval_threads: 4 })`.
    ///
    /// Allocates the FFT tables and scratch arena.  This is the most expensive
    /// one-time setup cost; key generation and evaluation are the runtime costs.
    pub fn new(params: Params) -> Self {
        let options = ContextOptions::default();
        assert_eval_threads(options.eval_threads);
        let module = Mod::new(params.n_glwe as u64);
        let bytes = compute_arena_bytes(&module, &params, options.eval_threads);
        let arena = scratch::new_arena(bytes);
        Context {
            params,
            module,
            arena,
            options,
        }
    }

    /// Applies runtime options, replacing any previous [`ContextOptions`].
    ///
    /// Reallocates the scratch arena for this [`Params`] and the new
    /// [`ContextOptions::eval_threads`] (worst-case size from Poulpy’s scratch helpers).
    ///
    /// # Panics
    ///
    /// If `options.eval_threads` is zero.
    pub fn with_options(mut self, options: ContextOptions) -> Self {
        assert_eval_threads(options.eval_threads);
        self.options = options;
        let bytes = compute_arena_bytes(&self.module, &self.params, self.options.eval_threads);
        self.arena = scratch::new_arena(bytes);
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
        let bytes = compute_arena_bytes(&self.module, &self.params, self.options.eval_threads);
        self.arena = scratch::new_arena(bytes);
    }

    /// Sets only [`ContextOptions::eval_threads`].  Reallocates the scratch arena
    /// like [`Context::with_options`].
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
        let mut bdd_key: BDDKey<Vec<u8>, CGGI> = BDDKey::alloc_from_infos(&self.params.bdd_layout);
        bdd_key.encrypt_sk(
            &self.module,
            &sk.sk_lwe,
            &sk.sk_glwe,
            &mut source_xa,
            &mut source_xe,
            scratch::borrow(&mut self.arena),
        );

        // BDD evaluation key (prepared / DFT form)
        let mut bdd_key_prepared: BDDKeyPrepared<Vec<u8>, CGGI, crate::backend::BE> =
            BDDKeyPrepared::alloc_from_infos(&self.module, &self.params.bdd_layout);
        bdd_key_prepared.prepare(&self.module, &bdd_key, scratch::borrow(&mut self.arena));

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

        let mut sk_glwe_prepared =
            GLWESecretPrepared::alloc_from_infos(&self.module, &self.params.glwe_layout);
        sk_glwe_prepared.prepare(&self.module, &sk_glwe);

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
        let mut bdd_key_prepared =
            BDDKeyPrepared::alloc_from_infos(&self.module, &self.params.bdd_layout);
        bdd_key_prepared.prepare(&self.module, &bdd_key, scratch::borrow(&mut self.arena));
        Ok(EvaluationKey {
            bdd_key,
            bdd_key_prepared,
        })
    }

    // ── Encrypt / Decrypt ────────────────────────────────────────────────────

    /// Encrypt a plaintext value under the given secret key.
    ///
    /// `T` must be one of `u8`, `u16`, `u32`, `u64`, `u128`.  Note that
    /// homomorphic arithmetic operations are currently only implemented for
    /// `u32` (the only type with compiled BDD circuits in `poulpy-schemes`).
    pub fn encrypt<T>(&mut self, value: T, sk: &SecretKey) -> Ciphertext<T>
    where
        T: UnsignedInteger + ToBits,
    {
        let mut source_xa = random_source();
        let mut source_xe = random_source();
        let mut fhe_uint = FheUint::alloc_from_infos(&self.params.glwe_layout);
        fhe_uint.encrypt_sk(
            &self.module,
            value,
            &sk.sk_glwe_prepared,
            &mut source_xa,
            &mut source_xe,
            scratch::borrow(&mut self.arena),
        );
        Ciphertext { inner: fhe_uint }
    }

    /// Decrypt a ciphertext and return the plaintext value.
    pub fn decrypt<T>(&mut self, ct: &Ciphertext<T>, sk: &SecretKey) -> T
    where
        T: UnsignedInteger + FromBits,
    {
        ct.inner.decrypt(
            &self.module,
            &sk.sk_glwe_prepared,
            scratch::borrow(&mut self.arena),
        )
    }

    // ── Internal helper ───────────────────────────────────────────────────────

    /// Prepare two ciphertexts, run `op`, and return the result.
    ///
    /// All arithmetic operations share this pattern:
    /// 1. Allocate and populate `FheUintPrepared` for `a` and `b`.
    /// 2. Allocate output `FheUint`.
    /// 3. Invoke `op` on it.
    ///
    /// Uses [`ContextOptions::eval_threads`] for Poulpy's `*_multi_thread` BDD evaluators.
    fn eval_binary<T, F>(
        &mut self,
        a: &Ciphertext<T>,
        b: &Ciphertext<T>,
        ek: &EvaluationKey,
        op: F,
    ) -> Ciphertext<T>
    where
        T: UnsignedInteger,
        F: FnOnce(
            &Mod,
            usize,
            &mut FheUint<Vec<u8>, T>,
            &FheUintPrepared<Vec<u8>, T, crate::backend::BE>,
            &FheUintPrepared<Vec<u8>, T, crate::backend::BE>,
            &BDDKeyPrepared<Vec<u8>, CGGI, crate::backend::BE>,
            &mut poulpy_hal::layouts::Scratch<crate::backend::BE>,
        ),
    {
        let eval_threads = self.options.eval_threads;
        let mut a_prep: FheUintPrepared<Vec<u8>, T, crate::backend::BE> =
            FheUintPrepared::alloc_from_infos(&self.module, &self.params.ggsw_layout);
        a_prep.prepare::<CGGI, _, _, _, _>(
            &self.module,
            &a.inner,
            &ek.bdd_key_prepared,
            scratch::borrow(&mut self.arena),
        );

        let mut b_prep: FheUintPrepared<Vec<u8>, T, crate::backend::BE> =
            FheUintPrepared::alloc_from_infos(&self.module, &self.params.ggsw_layout);
        b_prep.prepare::<CGGI, _, _, _, _>(
            &self.module,
            &b.inner,
            &ek.bdd_key_prepared,
            scratch::borrow(&mut self.arena),
        );

        let mut out: FheUint<Vec<u8>, T> = FheUint::alloc_from_infos(&self.params.glwe_layout);
        op(
            &self.module,
            eval_threads,
            &mut out,
            &a_prep,
            &b_prep,
            &ek.bdd_key_prepared,
            scratch::borrow(&mut self.arena),
        );
        Ciphertext { inner: out }
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
        self.eval_binary(a, b, ek, |module, threads, out, ap, bp, key, scratch| {
            out.add_multi_thread(threads, module, ap, bp, key, scratch);
        })
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
        self.eval_binary(a, b, ek, |module, threads, out, ap, bp, key, scratch| {
            out.sub_multi_thread(threads, module, ap, bp, key, scratch);
        })
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
        self.eval_binary(a, b, ek, |module, threads, out, ap, bp, key, scratch| {
            out.and_multi_thread(threads, module, ap, bp, key, scratch);
        })
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
        self.eval_binary(a, b, ek, |module, threads, out, ap, bp, key, scratch| {
            out.or_multi_thread(threads, module, ap, bp, key, scratch);
        })
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
        self.eval_binary(a, b, ek, |module, threads, out, ap, bp, key, scratch| {
            out.xor_multi_thread(threads, module, ap, bp, key, scratch);
        })
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
        self.eval_binary(a, b, ek, |module, threads, out, ap, bp, key, scratch| {
            out.sll_multi_thread(threads, module, ap, bp, key, scratch);
        })
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
        self.eval_binary(a, b, ek, |module, threads, out, ap, bp, key, scratch| {
            out.srl_multi_thread(threads, module, ap, bp, key, scratch);
        })
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
        self.eval_binary(a, b, ek, |module, threads, out, ap, bp, key, scratch| {
            out.sra_multi_thread(threads, module, ap, bp, key, scratch);
        })
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
        self.eval_binary(a, b, ek, |module, threads, out, ap, bp, key, scratch| {
            out.slt_multi_thread(threads, module, ap, bp, key, scratch);
        })
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
        self.eval_binary(a, b, ek, |module, threads, out, ap, bp, key, scratch| {
            out.sltu_multi_thread(threads, module, ap, bp, key, scratch);
        })
    }
}

// ── Internal utilities ────────────────────────────────────────────────────────

/// Compute the exact scratch arena size required for all operations in the
/// pipeline by taking the `max` across every scratch-taking category.
/// The arena is reused sequentially, so the worst-case single operation
/// determines the required size.
fn compute_arena_bytes(module: &Mod, params: &Params, eval_threads: usize) -> usize {
    let keygen_encrypt = module.bdd_key_encrypt_sk_tmp_bytes(&params.bdd_layout);
    let keygen_prepare = module.prepare_bdd_key_tmp_bytes(&params.bdd_layout);
    let fhe_prepare = module.fhe_uint_prepare_tmp_bytes(
        params.binary_block_size as usize,
        1usize,
        &params.ggsw_layout,
        &params.glwe_layout,
        &params.bdd_layout,
    );

    // encrypt_sk_tmp_bytes / decrypt_tmp_bytes are &self instance methods on
    // FheUint — a dummy is needed for dispatch. It's a one-time ~32 KB
    // allocation freed immediately after sizing.
    let dummy: FheUint<Vec<u8>, u32> = FheUint::alloc_from_infos(&params.glwe_layout);
    let encrypt = dummy.encrypt_sk_tmp_bytes(module);
    let decrypt = dummy.decrypt_tmp_bytes(module);

    // Each BDD circuit has a different max_state_size, so all 10 ops are
    // queried and the max is taken. Poulpy's `*_tmp_bytes` helpers require a
    // prepared evaluation key (`GLWEAutomorphismKeyHelper`), not raw layouts.
    let bdd_key_prepared: BDDKeyPrepared<Vec<u8>, CGGI, crate::backend::BE> =
        BDDKeyPrepared::alloc_from_infos(module, &params.bdd_layout);
    let g = &params.ggsw_layout;
    let r = &params.glwe_layout;
    let t = eval_threads;
    let eval = [
        dummy.add_multi_thread_tmp_bytes(module, t, r, g, &bdd_key_prepared),
        dummy.sub_multi_thread_tmp_bytes(module, t, r, g, &bdd_key_prepared),
        dummy.and_multi_thread_tmp_bytes(module, t, r, g, &bdd_key_prepared),
        dummy.or_multi_thread_tmp_bytes(module, t, r, g, &bdd_key_prepared),
        dummy.xor_multi_thread_tmp_bytes(module, t, r, g, &bdd_key_prepared),
        dummy.sll_multi_thread_tmp_bytes(module, t, r, g, &bdd_key_prepared),
        dummy.srl_multi_thread_tmp_bytes(module, t, r, g, &bdd_key_prepared),
        dummy.sra_multi_thread_tmp_bytes(module, t, r, g, &bdd_key_prepared),
        dummy.slt_multi_thread_tmp_bytes(module, t, r, g, &bdd_key_prepared),
        dummy.sltu_multi_thread_tmp_bytes(module, t, r, g, &bdd_key_prepared),
    ]
    .into_iter()
    .max()
    .unwrap_or(0);

    [
        keygen_encrypt,
        keygen_prepare,
        fhe_prepare,
        encrypt,
        decrypt,
        eval,
    ]
    .into_iter()
    .max()
    .unwrap_or(0)
}

/// Construct a [`Source`] seeded from OS randomness.
fn random_source() -> Source {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("OS random number generator unavailable");
    Source::new(seed)
}
