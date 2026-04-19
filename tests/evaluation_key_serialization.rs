use squid::{Context, EvaluationKey, Params};

/// Evaluation key serialize → deserialize; same in-memory secret key for encrypt/decrypt.
#[test]
fn evaluation_key_serialize_roundtrip_from_os_random() {
    let mut ctx = Context::new(Params::test());
    let (sk, ek) = ctx.keygen();

    let ek_blob = ek.serialize().expect("serialize ek");
    let ek2 = EvaluationKey::deserialize(&mut ctx, &ek_blob).expect("deserialize ek");

    let a = ctx.encrypt::<u32>(11, &sk, &ek);
    let b = ctx.encrypt::<u32>(22, &sk, &ek);
    let c = ctx.add(&a, &b, &ek2);
    assert_eq!(ctx.decrypt(&c, &sk), 33);
}
