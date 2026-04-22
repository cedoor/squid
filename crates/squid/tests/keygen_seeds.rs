mod common;

use squid::{Context, Params, SecretKey};

use common::TEST_SEEDS;

#[test]
fn keygen_from_seeds_is_deterministic_across_contexts() {
    let mut a = Context::new(Params::test());
    let mut b = Context::new(Params::test());
    let (sk_a, _) = a.keygen_from_seeds(TEST_SEEDS);
    let (sk_b, _) = b.keygen_from_seeds(TEST_SEEDS);

    assert!(sk_a.glwe_standard() == sk_b.glwe_standard());
    assert_eq!(sk_a.lwe_standard().raw(), sk_b.lwe_standard().raw());
}

#[test]
fn secret_key_from_lattice_seed_matches_full_keygen_lattice_part() {
    let mut ctx = Context::new(Params::test());
    let (sk_full, _) = ctx.keygen_from_seeds(TEST_SEEDS);
    let sk_lattice = SecretKey::from_lattice_seed(&mut ctx, TEST_SEEDS.lattice);
    assert!(sk_full.glwe_standard() == sk_lattice.glwe_standard());
    assert_eq!(
        sk_full.lwe_standard().raw(),
        sk_lattice.lwe_standard().raw()
    );
}

#[test]
fn keygen_from_seeds_homomorphic_smoke() {
    let mut ctx = Context::new(Params::test());
    let (sk, ek) = ctx.keygen_from_seeds(TEST_SEEDS);
    let x = ctx.encrypt::<u32>(10, &sk);
    let y = ctx.encrypt::<u32>(20, &sk);
    let z = ctx.add(&x, &y, &ek);
    assert_eq!(ctx.decrypt(&z, &sk), 30);
}
