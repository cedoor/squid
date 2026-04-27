mod common;

use squid::{Context, Params};

use common::TEST_SEEDS;

#[test]
fn bdd_homomorphic_ops_match_u32_plaintext() {
    let mut ctx = Context::new(Params::test());
    let (sk, ek) = ctx.keygen_from_seeds(TEST_SEEDS);

    let a: u32 = 0xcafe_babe;
    let b: u32 = 5;
    let ct_a = ctx.encrypt(a, &sk);
    let ct_b = ctx.encrypt(b, &sk);

    let c_add = ctx.add(&ct_a, &ct_b, &ek);
    assert_eq!(ctx.decrypt(&c_add, &sk), a.wrapping_add(b));

    let c_sub = ctx.sub(&ct_a, &ct_b, &ek);
    assert_eq!(ctx.decrypt(&c_sub, &sk), a.wrapping_sub(b));

    let c_and = ctx.and(&ct_a, &ct_b, &ek);
    assert_eq!(ctx.decrypt(&c_and, &sk), a & b);

    let c_or = ctx.or(&ct_a, &ct_b, &ek);
    assert_eq!(ctx.decrypt(&c_or, &sk), a | b);

    let c_xor = ctx.xor(&ct_a, &ct_b, &ek);
    assert_eq!(ctx.decrypt(&c_xor, &sk), a ^ b);

    let c_sll = ctx.sll(&ct_a, &ct_b, &ek);
    assert_eq!(ctx.decrypt(&c_sll, &sk), a.wrapping_shl(b));

    let c_srl = ctx.srl(&ct_a, &ct_b, &ek);
    assert_eq!(ctx.decrypt(&c_srl, &sk), a.wrapping_shr(b));

    let c_sra = ctx.sra(&ct_a, &ct_b, &ek);
    assert_eq!(
        ctx.decrypt(&c_sra, &sk),
        ((a as i32).wrapping_shr(b)) as u32
    );

    let c_slt = ctx.slt(&ct_a, &ct_b, &ek);
    let exp_slt = u32::from((a as i32) < (b as i32));
    assert_eq!(ctx.decrypt(&c_slt, &sk), exp_slt);

    let c_sltu = ctx.sltu(&ct_a, &ct_b, &ek);
    let exp_sltu = u32::from(a < b);
    assert_eq!(ctx.decrypt(&c_sltu, &sk), exp_sltu);
}
