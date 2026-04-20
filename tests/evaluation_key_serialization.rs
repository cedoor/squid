mod common;

use squid::{Context, EvaluationKey, Params};

use common::TEST_SEEDS;

/// Evaluation key serialize → deserialize; same in-memory secret key for encrypt/decrypt.
#[test]
fn evaluation_key_serialize_roundtrip() {
    let mut ctx = Context::new(Params::test());
    let (sk, ek) = ctx.keygen_from_seeds(TEST_SEEDS);

    let ek_blob = ek.serialize().expect("serialize ek");
    let ek2 = EvaluationKey::deserialize(&mut ctx, &ek_blob).expect("deserialize ek");

    let a = ctx.encrypt::<u32>(11, &sk);
    let b = ctx.encrypt::<u32>(22, &sk);
    let c = ctx.add(&a, &b, &ek2);
    assert_eq!(ctx.decrypt(&c, &sk), 33);
}
