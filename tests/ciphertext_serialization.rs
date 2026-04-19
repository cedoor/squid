use squid::{Ciphertext, Context, Params};

#[test]
fn ciphertext_serialize_roundtrip_decrypts() {
    let mut ctx = Context::new(Params::test());
    let (sk, ek) = ctx.keygen();

    let ct = ctx.encrypt::<u32>(0xdead_beef, &sk, &ek);
    let blob = ct.serialize().expect("serialize ciphertext");
    let ct2 = Ciphertext::<u32>::deserialize(&mut ctx, &blob).expect("deserialize ciphertext");

    assert_eq!(ctx.decrypt(&ct2, &sk), 0xdead_beef);
}

#[test]
fn ciphertext_wrong_type_parameter_is_rejected() {
    let mut ctx = Context::new(Params::test());
    let (sk, ek) = ctx.keygen();

    let ct = ctx.encrypt::<u32>(1, &sk, &ek);
    let blob = ct.serialize().expect("serialize");

    match Ciphertext::<u16>::deserialize(&mut ctx, &blob) {
        Ok(_) => panic!("expected InvalidData for wrong bit width"),
        Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::InvalidData),
    }
}

#[test]
fn ciphertext_rejects_mismatched_params_glwe_layout() {
    let mut ctx_encrypt = Context::new(Params::test());
    let mut ctx_other = Context::new(Params::unsecure());
    let (sk, ek) = ctx_encrypt.keygen();

    let ct = ctx_encrypt.encrypt::<u32>(1, &sk, &ek);
    let blob = ct.serialize().expect("serialize");

    match Ciphertext::<u32>::deserialize(&mut ctx_other, &blob) {
        Ok(_) => panic!("expected InvalidData for mismatched GLWE layout"),
        Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::InvalidData),
    }
}
