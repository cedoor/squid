use squid::{Context, Params};

/// Full `keygen` → serialize → deserialize round-trip using OS randomness.
#[test]
fn keygen_serialize_roundtrip_from_os_random() {
    let mut ctx = Context::new(Params::test());
    let (sk, ek) = ctx.keygen();

    let sk_blob = ctx.serialize_secret_key(&sk).expect("serialize sk");
    let ek_blob = ctx.serialize_evaluation_key(&ek).expect("serialize ek");

    let sk2 = ctx
        .deserialize_secret_key(&sk_blob)
        .expect("deserialize sk");
    let ek2 = ctx
        .deserialize_evaluation_key(&ek_blob)
        .expect("deserialize ek");

    let a = ctx.encrypt::<u32>(11, &sk2);
    let b = ctx.encrypt::<u32>(22, &sk2);
    let c = ctx.add(&a, &b, &ek2);
    assert_eq!(ctx.decrypt(&c, &sk2), 33);
}
