use squid::{Context, Params};

#[test]
fn eval_threads_two_matches_one() {
    let params = Params::unsecure();

    let mut ctx1 = Context::new(params.clone());
    let mut ctx2 = Context::new(params).with_eval_threads(2);

    let (sk, ek) = ctx1.keygen();

    let ct_a = ctx1.encrypt(7u32, &sk);
    let ct_b = ctx1.encrypt(5u32, &sk);

    let c1 = ctx1.add(&ct_a, &ct_b, &ek);
    let c2 = ctx2.add(&ct_a, &ct_b, &ek);

    assert_eq!(ctx1.decrypt(&c1, &sk), ctx2.decrypt(&c2, &sk));
}
