//! Top-level user entry point: [`Context`] and [`Params`].
//!
//! All public API operations flow through [`Context`].  Users should never
//! need to import anything from the other squid modules directly.
//!
//! ## Typical workflow
//!
//! ```rust,no_run
//! use squid::{Context, Params};
//!
//! let mut ctx = Context::new(Params::unsecure());
//! let (sk, ek) = ctx.keygen();
//!
//! let a = ctx.encrypt::<u32>(42, &sk);
//! let b = ctx.encrypt::<u32>(7, &sk);
//! let c = ctx.add(&a, &b, &ek);
//! let result: u32 = ctx.decrypt(&c, &sk);
//! ```

use poulpy_core::layouts::{
    Base2K, Degree, Dnum, Dsize, GGLWEToGGSWKeyLayout, GGSWLayout, GLWEAutomorphismKeyLayout,
    GLWELayout, GLWESecret, GLWESecretPrepared, GLWESwitchingKeyLayout, GLWEToLWEKeyLayout,
    LWESecret, Rank, TorusPrecision,
};
use poulpy_hal::{api::ModuleNew, layouts::Module, source::Source};
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
    keys::{EvaluationKey, SecretKey},
    scratch, Ciphertext,
};

// ── Module alias ────────────────────────────────────────────────────────────

/// The concrete Poulpy backend used by squid.
///
/// Resolved at compile time via `crate::backend::BE` (see `src/backend.rs`).
/// Defaults to `crate::backend::BE`; use `--features backend-avx` for the AVX2/FMA backend.
/// No generic backend parameter surfaces in squid's public API.
type Mod = Module<crate::backend::BE>;

// ── Params ───────────────────────────────────────────────────────────────────

/// Parameter set for a [`Context`].
///
/// Wraps all layout descriptors needed for key generation, encryption, and
/// evaluation.  [`Params::unsecure`] matches Poulpy's `bdd_arithmetic` example
/// (n = 1024) and is **not** presented as a vetted security level.
///
/// Advanced users may construct custom `Params` directly, but must ensure
/// consistency across all layout fields — concretely, `n_glwe`, `base2k`, and
/// `rank` must agree everywhere they appear.
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
    /// Scratch arena size in bytes.  If `None`, computed exactly from the
    /// parameter set via the Poulpy `*_tmp_bytes` methods.
    pub scratch_bytes: Option<usize>,
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
            scratch_bytes: None,
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
}

impl Context {
    /// Create a new context with the given parameter set.
    ///
    /// Allocates the FFT tables and scratch arena.  This is the most expensive
    /// one-time setup cost; key generation and evaluation are the runtime costs.
    pub fn new(params: Params) -> Self {
        let module = Mod::new(params.n_glwe as u64);
        let bytes = params
            .scratch_bytes
            .unwrap_or_else(|| compute_arena_bytes(&module, &params));
        let arena = scratch::new_arena(bytes);
        Context {
            params,
            module,
            arena,
        }
    }

    /// Generate a fresh secret key and the corresponding evaluation key.
    ///
    /// Uses OS randomness to seed the three CSPRNG streams required by Poulpy
    /// (secret key, public mask, and error noise).
    ///
    /// # Panics
    ///
    /// Panics if the OS cannot supply enough random bytes (extremely unlikely).
    pub fn keygen(&mut self) -> (SecretKey, EvaluationKey) {
        let mut source_xs = random_source();
        let mut source_xa = random_source();
        let mut source_xe = random_source();

        // GLWE secret key
        let mut sk_glwe = GLWESecret::alloc_from_infos(&self.params.glwe_layout);
        sk_glwe.fill_ternary_prob(0.5, &mut source_xs);

        // LWE secret key (block-binary)
        let mut sk_lwe = LWESecret::alloc(self.params.bdd_layout.cbt_layout.brk_layout.n_lwe);
        sk_lwe.fill_binary_block(self.params.binary_block_size as usize, &mut source_xs);

        // Prepared GLWE secret (DFT domain) — needed for encryption/decryption
        let mut sk_glwe_prepared =
            GLWESecretPrepared::alloc_from_infos(&self.module, &self.params.glwe_layout);
        sk_glwe_prepared.prepare(&self.module, &sk_glwe);

        // BDD evaluation key (standard form)
        let mut bdd_key: BDDKey<Vec<u8>, CGGI> = BDDKey::alloc_from_infos(&self.params.bdd_layout);
        bdd_key.encrypt_sk(
            &self.module,
            &sk_lwe,
            &sk_glwe,
            &mut source_xa,
            &mut source_xe,
            scratch::borrow(&mut self.arena),
        );

        // BDD evaluation key (prepared / DFT form)
        let mut bdd_key_prepared: BDDKeyPrepared<Vec<u8>, CGGI, crate::backend::BE> =
            BDDKeyPrepared::alloc_from_infos(&self.module, &self.params.bdd_layout);
        bdd_key_prepared.prepare(&self.module, &bdd_key, scratch::borrow(&mut self.arena));

        let sk = SecretKey {
            sk_glwe,
            sk_glwe_prepared,
            sk_lwe,
        };
        let ek = EvaluationKey {
            bdd_key,
            bdd_key_prepared,
        };
        (sk, ek)
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
            &mut FheUint<Vec<u8>, T>,
            &FheUintPrepared<Vec<u8>, T, crate::backend::BE>,
            &FheUintPrepared<Vec<u8>, T, crate::backend::BE>,
            &BDDKeyPrepared<Vec<u8>, CGGI, crate::backend::BE>,
            &mut poulpy_hal::layouts::Scratch<crate::backend::BE>,
        ),
    {
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
        self.eval_binary(a, b, ek, |module, out, ap, bp, key, scratch| {
            out.add(module, ap, bp, key, scratch);
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
        self.eval_binary(a, b, ek, |module, out, ap, bp, key, scratch| {
            out.sub(module, ap, bp, key, scratch);
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
        self.eval_binary(a, b, ek, |module, out, ap, bp, key, scratch| {
            out.and(module, ap, bp, key, scratch);
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
        self.eval_binary(a, b, ek, |module, out, ap, bp, key, scratch| {
            out.or(module, ap, bp, key, scratch);
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
        self.eval_binary(a, b, ek, |module, out, ap, bp, key, scratch| {
            out.xor(module, ap, bp, key, scratch);
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
        self.eval_binary(a, b, ek, |module, out, ap, bp, key, scratch| {
            out.sll(module, ap, bp, key, scratch);
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
        self.eval_binary(a, b, ek, |module, out, ap, bp, key, scratch| {
            out.srl(module, ap, bp, key, scratch);
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
        self.eval_binary(a, b, ek, |module, out, ap, bp, key, scratch| {
            out.sra(module, ap, bp, key, scratch);
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
        self.eval_binary(a, b, ek, |module, out, ap, bp, key, scratch| {
            out.slt(module, ap, bp, key, scratch);
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
        self.eval_binary(a, b, ek, |module, out, ap, bp, key, scratch| {
            out.sltu(module, ap, bp, key, scratch);
        })
    }
}

// ── Internal utilities ────────────────────────────────────────────────────────

/// Compute the exact scratch arena size required for all operations in the
/// pipeline by taking the `max` across every scratch-taking category.
/// The arena is reused sequentially, so the worst-case single operation
/// determines the required size.
fn compute_arena_bytes(module: &Mod, params: &Params) -> usize {
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
    let eval = [
        dummy.add_tmp_bytes(module, r, g, &bdd_key_prepared),
        dummy.sub_tmp_bytes(module, r, g, &bdd_key_prepared),
        dummy.and_tmp_bytes(module, r, g, &bdd_key_prepared),
        dummy.or_tmp_bytes(module, r, g, &bdd_key_prepared),
        dummy.xor_tmp_bytes(module, r, g, &bdd_key_prepared),
        dummy.sll_tmp_bytes(module, r, g, &bdd_key_prepared),
        dummy.srl_tmp_bytes(module, r, g, &bdd_key_prepared),
        dummy.sra_tmp_bytes(module, r, g, &bdd_key_prepared),
        dummy.slt_tmp_bytes(module, r, g, &bdd_key_prepared),
        dummy.sltu_tmp_bytes(module, r, g, &bdd_key_prepared),
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
