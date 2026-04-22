//! wasm-bindgen bindings over `squid` for browser use.
//!
//! Public surface mirrors the plan: `Session` owns a `Context` + `(sk, ek)`
//! and exposes byte-oriented helpers. Secret key material never leaves memory
//! — only `KeygenSeeds` (96 bytes) and serialized `ek`/ciphertexts do.

use squid::{Context, EvaluationKey, KeygenSeeds, Params, SecretKey};
use wasm_bindgen::prelude::*;

const SEEDS_LEN: usize = 96;

fn params_from_name(name: &str) -> Result<Params, JsError> {
    Params::by_name(name).ok_or_else(|| {
        JsError::new(&format!(
            "unknown parameter set {name:?}; expected \"test\" or \"unsecure\""
        ))
    })
}

#[wasm_bindgen(start)]
pub fn __start() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub struct Session {
    ctx: Context,
    sk: SecretKey,
    ek: EvaluationKey,
    seeds: KeygenSeeds,
}

#[wasm_bindgen]
impl Session {
    /// Fresh keys from OS randomness. Returns a session whose seeds can be
    /// exported via [`Session::seeds`] for later restoration.
    #[wasm_bindgen(js_name = newRandom)]
    pub fn new_random(params_name: &str) -> Result<Session, JsError> {
        let params = params_from_name(params_name)?;
        let mut ctx = Context::new(params);
        let (sk, ek, seeds) = ctx.keygen_with_seeds();
        Ok(Session { ctx, sk, ek, seeds })
    }

    /// Deterministic rebuild from a 96-byte seed blob produced by
    /// [`Session::seeds`].
    #[wasm_bindgen(js_name = fromSeeds)]
    pub fn from_seeds(seeds: &[u8], params_name: &str) -> Result<Session, JsError> {
        if seeds.len() != SEEDS_LEN {
            return Err(JsError::new(&format!(
                "expected {SEEDS_LEN}-byte seeds blob, got {}",
                seeds.len()
            )));
        }
        let mut lattice = [0u8; 32];
        let mut bdd_mask = [0u8; 32];
        let mut bdd_noise = [0u8; 32];
        lattice.copy_from_slice(&seeds[0..32]);
        bdd_mask.copy_from_slice(&seeds[32..64]);
        bdd_noise.copy_from_slice(&seeds[64..96]);
        let ks = KeygenSeeds {
            lattice,
            bdd_mask,
            bdd_noise,
        };
        let params = params_from_name(params_name)?;
        let mut ctx = Context::new(params);
        let (sk, ek) = ctx.keygen_from_seeds(ks);
        Ok(Session {
            ctx,
            sk,
            ek,
            seeds: ks,
        })
    }

    /// 96-byte seed blob: `lattice || bdd_mask || bdd_noise`.
    #[wasm_bindgen(js_name = seeds)]
    pub fn seeds(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SEEDS_LEN);
        out.extend_from_slice(&self.seeds.lattice);
        out.extend_from_slice(&self.seeds.bdd_mask);
        out.extend_from_slice(&self.seeds.bdd_noise);
        out
    }

    /// Versioned little-endian evaluation key blob to ship to the server.
    #[wasm_bindgen(js_name = evaluationKeyBytes)]
    pub fn evaluation_key_bytes(&self) -> Result<Vec<u8>, JsError> {
        self.ek.serialize().map_err(io_err)
    }

    /// Encrypt a `u32` value and return the serialized ciphertext.
    #[wasm_bindgen(js_name = encryptU32)]
    pub fn encrypt_u32(&mut self, value: u32) -> Result<Vec<u8>, JsError> {
        let ct = self.ctx.encrypt::<u32>(value, &self.sk);
        ct.serialize().map_err(io_err)
    }

    /// Deserialize + decrypt a `u32` ciphertext.
    #[wasm_bindgen(js_name = decryptU32)]
    pub fn decrypt_u32(&mut self, bytes: &[u8]) -> Result<u32, JsError> {
        let ct = self
            .ctx
            .deserialize_ciphertext::<u32>(bytes)
            .map_err(io_err)?;
        Ok(self.ctx.decrypt::<u32>(&ct, &self.sk))
    }
}

fn io_err(e: std::io::Error) -> JsError {
    JsError::new(&e.to_string())
}
