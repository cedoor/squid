use squid::KeygenSeeds;

/// Fixed seeds for integration tests so runs are reproducible (no OS RNG in keygen paths).
pub const TEST_SEEDS: KeygenSeeds = KeygenSeeds {
    lattice: [7u8; 32],
    bdd_mask: [11u8; 32],
    bdd_noise: [13u8; 32],
};
