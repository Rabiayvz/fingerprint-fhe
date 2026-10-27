// Research stress test (non-spec): verifies TriviumFhe's per-round
// state-update/keystream logic across many random trials by using a
// reduced, non-standard warm-up round count (cheap), instead of the
// spec-mandated 1152 rounds used by the real protocol (see Section 4.3
// of the paper for the N=3 full-spec 1152-round correctness trials).
//
// This does NOT replace those trials; it only exercises clock()'s
// XOR/AND gate logic over more random state configurations for less
// total compute.

use shared::trivium_fhe::TriviumFhe;

use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};

use rand::Rng;
use std::time::Instant;

const N_TRIALS: usize = 20;
const WARMUP_ROUNDS: usize = 128;
const MESSAGE_BITS: usize = 64;

/// Plaintext Trivium with a configurable warm-up round count (self-contained,
/// mirrors shared::Trivium's clock() logic exactly; used only for this test).
fn plaintext_keystream(key: &[bool], iv: &[bool], warmup_rounds: usize, n_out: usize) -> Vec<bool> {
    let mut state = vec![false; 288];
    state[0..80].copy_from_slice(key);
    state[93..173].copy_from_slice(iv);
    state[285] = true;
    state[286] = true;
    state[287] = true;

    let mut clock = move |state: &mut Vec<bool>| -> bool {
        let t1 = state[65] ^ state[92];
        let t2 = state[161] ^ state[176];
        let t3 = state[242] ^ state[287];
        let output = t1 ^ t2 ^ t3;
        let s1 = t1 ^ (state[90] & state[91]) ^ state[170];
        let s2 = t2 ^ (state[174] & state[175]) ^ state[263];
        let s3 = t3 ^ (state[285] & state[286]) ^ state[68];
        state.rotate_right(1);
        state[0] = s3;
        state[93] = s1;
        state[177] = s2;
        output
    };

    for _ in 0..warmup_rounds {
        clock(&mut state);
    }
    (0..n_out).map(|_| clock(&mut state)).collect()
}

fn random_bits(rng: &mut impl Rng, n: usize) -> Vec<bool> {
    (0..n).map(|_| rng.gen::<bool>()).collect()
}

fn main() {
    println!("STRESS TEST: TriviumFhe state-update logic, {} trials, {}-round (non-spec) warm-up", N_TRIALS, WARMUP_ROUNDS);
    println!("{}", "=".repeat(70));

    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);
    set_server_key(server_key.clone());
    let encrypted_true = FheBool::encrypt(true, &client_key);

    let mut rng = rand::thread_rng();
    let mut passed = 0usize;
    let mut total_bit_mismatches = 0usize;
    let t_start = Instant::now();

    for trial in 0..N_TRIALS {
        let key = random_bits(&mut rng, 80);
        let iv = random_bits(&mut rng, 80);
        let message = random_bits(&mut rng, MESSAGE_BITS);

        let plain_keystream = plaintext_keystream(&key, &iv, WARMUP_ROUNDS, MESSAGE_BITS);
        let ciphertext: Vec<bool> = message.iter().zip(plain_keystream.iter()).map(|(&m, &k)| m ^ k).collect();

        let t0 = Instant::now();
        let enc_key: Vec<FheBool> = key.iter().map(|&b| FheBool::encrypt(b, &client_key)).collect();
        let enc_iv: Vec<FheBool> = iv.iter().map(|&b| FheBool::encrypt(b, &client_key)).collect();

        let mut trivium_fhe = TriviumFhe::new_with_warmup_rounds(&enc_key, &enc_iv, &encrypted_true, &server_key, WARMUP_ROUNDS);
        let fhe_keystream = trivium_fhe.keystream(MESSAGE_BITS);

        let decrypted_plaintext: Vec<bool> = ciphertext
            .iter()
            .zip(fhe_keystream.iter())
            .map(|(&c, k)| {
                let p_fhe = if c { k ^ &encrypted_true } else { k.clone() };
                p_fhe.decrypt(&client_key)
            })
            .collect();
        let elapsed = t0.elapsed();

        let mismatches = decrypted_plaintext.iter().zip(message.iter()).filter(|(a, b)| a != b).count();
        total_bit_mismatches += mismatches;
        let ok = mismatches == 0;
        if ok {
            passed += 1;
        }
        println!(
            "[trial {:>2}/{}] {} ({:.1}s) mismatches={}",
            trial + 1,
            N_TRIALS,
            if ok { "PASS" } else { "FAIL" },
            elapsed.as_secs_f64(),
            mismatches
        );
    }

    let total_elapsed = t_start.elapsed();
    println!("{}", "=".repeat(70));
    println!(
        "RESULT: {}/{} trials passed, {} total bit mismatches across {} bits, total time {:.1}s ({:.1} min)",
        passed,
        N_TRIALS,
        total_bit_mismatches,
        N_TRIALS * MESSAGE_BITS,
        total_elapsed.as_secs_f64(),
        total_elapsed.as_secs_f64() / 60.0
    );
}
