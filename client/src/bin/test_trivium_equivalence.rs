// Correctness test: TriviumFhe (homomorphic) vs plaintext Trivium.
//
// For N random (key, iv, message) trials, this reproduces the exact
// register/verify data flow used in production:
//   1. Client encrypts a random 512-bit message with plaintext Trivium.
//   2. Server homomorphically decrypts the ciphertext via TriviumFhe
//      (decrypt_homomorphic), given only the FHE-encrypted key/iv.
//   3. The client decrypts the FHE result and checks it matches the
//      original plaintext message bit-for-bit.
//
// idea.md §1.3 asks for this equivalence to be verified over N randomized
// trials. N=1000 full-circuit trials is not feasible here: TriviumFhe's
// 1152-cycle warmup alone costs ~4.6 minutes regardless of message length
// (see progress.md bench_fhe results), so N is kept small by design.

use shared::{decrypt_homomorphic, u64_to_bits_80, Trivium};

use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};

use rand::Rng;
use std::time::Instant;

const N: usize = 3;
const MESSAGE_BITS: usize = 512;

fn random_bits(rng: &mut impl Rng, n: usize) -> Vec<bool> {
    (0..n).map(|_| rng.gen()).collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("TriviumFhe <-> plaintext Trivium equivalence test (N={})", N);
    println!("{}", "=".repeat(70));

    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);
    set_server_key(server_key.clone());
    let encrypted_true = FheBool::encrypt(true, &client_key);

    let mut rng = rand::thread_rng();
    let mut failures = 0;
    let suite_start = Instant::now();

    for trial in 1..=N {
        println!("\n-- Trial {}/{} --", trial, N);
        let trial_start = Instant::now();

        let key_bits = u64_to_bits_80(rng.gen());
        let iv_bits = u64_to_bits_80(rng.gen());
        let message = random_bits(&mut rng, MESSAGE_BITS);

        let mut trivium = Trivium::new(&key_bits, &iv_bits);
        let ciphertext = trivium.process(&message);

        let enc_key: Vec<FheBool> = key_bits.iter().map(|&b| FheBool::encrypt(b, &client_key)).collect();
        let enc_iv: Vec<FheBool> = iv_bits.iter().map(|&b| FheBool::encrypt(b, &client_key)).collect();

        let decrypted_fhe = decrypt_homomorphic(&ciphertext, &enc_key, &enc_iv, &encrypted_true, &server_key);
        let decrypted: Vec<bool> = decrypted_fhe.iter().map(|b| b.decrypt(&client_key)).collect();

        let mismatches: usize = decrypted
            .iter()
            .zip(message.iter())
            .filter(|(a, b)| a != b)
            .count();

        if mismatches == 0 {
            println!(
                "   PASS ({} bits, {:.1}s)",
                MESSAGE_BITS,
                trial_start.elapsed().as_secs_f64()
            );
        } else {
            failures += 1;
            println!(
                "   FAIL: {} / {} bits mismatched ({:.1}s)",
                mismatches,
                MESSAGE_BITS,
                trial_start.elapsed().as_secs_f64()
            );
        }
    }

    println!("\n{}", "=".repeat(70));
    println!(
        "SUMMARY: {}/{} trials passed ({:.1}s total)",
        N - failures,
        N,
        suite_start.elapsed().as_secs_f64()
    );

    if failures > 0 {
        std::process::exit(1);
    }
    Ok(())
}
