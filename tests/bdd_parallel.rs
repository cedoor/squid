use squid::{Context, Params};

#[test]
fn eval_threads_two_matches_one() {
    let params = Params::test();

    let mut ctx1 = Context::new(params.clone());
    let mut ctx2 = Context::new(params).with_eval_threads(2);

    let (sk1, ek1) = ctx1.keygen();
    let (sk2, ek2) = ctx2.keygen();

    let ct_a1 = ctx1.encrypt(7u32, &sk1);
    let ct_b1 = ctx1.encrypt(5u32, &sk1);
    let c1 = ctx1.add(&ct_a1, &ct_b1, &ek1);

    let ct_a2 = ctx2.encrypt(7u32, &sk2);
    let ct_b2 = ctx2.encrypt(5u32, &sk2);
    let c2 = ctx2.add(&ct_a2, &ct_b2, &ek2);

    assert_eq!(ctx1.decrypt(&c1, &sk1), ctx2.decrypt(&c2, &sk2));
}
