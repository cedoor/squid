//! End-to-end example: homomorphic addition on encrypted u32 values.
//!
//! Run with:
//!
//!   cargo run --example add_u32
//!
//! Key generation takes most of the time (~seconds on typical hardware).
//! The addition itself runs the BDD circuit bootstrapping pipeline.

use squid::{Context, Params};

fn main() {
    println!("Creating context (Params::unsecure — demo / non-production)...");
    let mut ctx = Context::new(Params::unsecure());

    println!("Generating keys...");
    let (sk, ek) = ctx.keygen();

    let a: u32 = 255;
    let b: u32 = 30;

    println!("Encrypting {a} and {b}...");
    let ct_a = ctx.encrypt::<u32>(a, &sk, &ek);
    let ct_b = ctx.encrypt::<u32>(b, &sk, &ek);

    println!("Computing homomorphic addition...");
    let ct_c = ctx.add(&ct_a, &ct_b, &ek);

    let result: u32 = ctx.decrypt(&ct_c, &sk);
    let expected = a.wrapping_add(b);

    println!("Result:   {result}");
    println!("Expected: {expected}");
    assert_eq!(
        result, expected,
        "decrypted result does not match plaintext computation"
    );
    println!("OK");
}
