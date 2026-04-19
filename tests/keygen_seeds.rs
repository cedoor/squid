use squid::{Context, KeygenSeeds, Params, SecretKey};

const SEEDS: KeygenSeeds = KeygenSeeds {
    lattice: [7u8; 32],
    bdd_mask: [11u8; 32],
    bdd_noise: [13u8; 32],
};

#[test]
fn keygen_from_seeds_is_deterministic_across_contexts() {
    let mut a = Context::new(Params::test());
    let mut b = Context::new(Params::test());
    let (sk_a, _) = a.keygen_from_seeds(SEEDS);
    let (sk_b, _) = b.keygen_from_seeds(SEEDS);

    assert!(sk_a.glwe_standard() == sk_b.glwe_standard());
    assert_eq!(sk_a.lwe_standard().raw(), sk_b.lwe_standard().raw());
}

#[test]
fn keygen_seeds_roundtrip_through_keygen_from_seeds() {
    let mut gen = Context::new(Params::test());
    let (sk_w, _, seeds) = gen.keygen_with_seeds();

    let mut replay = Context::new(Params::test());
    let (sk_r, _) = replay.keygen_from_seeds(seeds);

    assert!(sk_w.glwe_standard() == sk_r.glwe_standard());
    assert_eq!(sk_w.lwe_standard().raw(), sk_r.lwe_standard().raw());
}

#[test]
fn secret_key_from_lattice_seed_matches_full_keygen_lattice_part() {
    let mut ctx = Context::new(Params::test());
    let (sk_full, _, seeds) = ctx.keygen_with_seeds();
    let sk_lattice = SecretKey::from_lattice_seed(&mut ctx, seeds.lattice);
    assert!(sk_full.glwe_standard() == sk_lattice.glwe_standard());
    assert_eq!(
        sk_full.lwe_standard().raw(),
        sk_lattice.lwe_standard().raw()
    );
}

#[test]
fn keygen_from_seeds_homomorphic_smoke() {
    let mut ctx = Context::new(Params::test());
    let (sk, ek) = ctx.keygen_from_seeds(SEEDS);
    let x = ctx.encrypt::<u32>(10, &sk, &ek);
    let y = ctx.encrypt::<u32>(20, &sk, &ek);
    let z = ctx.add(&x, &y, &ek);
    assert_eq!(ctx.decrypt(&z, &sk), 30);
}
