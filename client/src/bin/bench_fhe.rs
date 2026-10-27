// Performance benchmark for the FHE / transciphering pipeline.
// Runs one full register+verify cycle in-process (no file IPC) and times
// every stage, plus compares against a naive "encrypt the whole template
// directly under FHE" baseline (no transciphering).

use client::feature_extraction::extract_fingerprint_128bit;
use client::matching::hamming_distance;

use shared::{
    decrypt_homomorphic, diff_bits, leq_constant, popcount_512, u64_to_bits_80, Trivium,
};

use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool};

use rand::Rng;
use std::time::{Duration, Instant};

const ENROLLED_IMAGE: &str = "../data/fingerprints/101_1.tif";
const PROBE_IMAGE: &str = "../data/fingerprints/101_2.tif";
const BITS: usize = 512;
const THRESHOLD: usize = (BITS as f64 * 0.2) as usize; // <=20% diff => match

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("FHE / TRANSCIPHERING PERFORMANCE BENCHMARK");
    println!("{}", "=".repeat(70));
    println!("Enrolled image: {}", ENROLLED_IMAGE);
    println!("Probe image:    {}", PROBE_IMAGE);
    println!();

    // ---------------------------------------------------------------
    // 0. Feature extraction (not FHE, but part of end-to-end timing)
    // ---------------------------------------------------------------
    let t0 = Instant::now();
    let enrolled_bits = extract_fingerprint_128bit(ENROLLED_IMAGE)?;
    let t_extract_enrolled = t0.elapsed();

    let t0 = Instant::now();
    let probe_bits = extract_fingerprint_128bit(PROBE_IMAGE)?;
    let t_extract_probe = t0.elapsed();

    assert_eq!(enrolled_bits.len(), BITS);
    assert_eq!(probe_bits.len(), BITS);

    // ---------------------------------------------------------------
    // 1. FHE key generation (client, one-time cost)
    // ---------------------------------------------------------------
    let t0 = Instant::now();
    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);
    let t_keygen = t0.elapsed();
    println!("[1] FHE key generation:            {:>10.1} ms", ms(t_keygen));

    set_server_key(server_key.clone());

    // ---------------------------------------------------------------
    // 2. Client-side Trivium key/IV generation + symmetric encryption
    //    (this is the "cheap" part transciphering relies on)
    // ---------------------------------------------------------------
    let mut rng = rand::thread_rng();

    let enroll_key_bits = u64_to_bits_80(rng.gen());
    let enroll_iv_bits = u64_to_bits_80(rng.gen());
    let probe_key_bits = u64_to_bits_80(rng.gen());
    let probe_iv_bits = u64_to_bits_80(rng.gen());

    let t0 = Instant::now();
    let mut trivium_enroll = Trivium::new(&enroll_key_bits, &enroll_iv_bits);
    let enroll_ciphertext = trivium_enroll.process(&enrolled_bits);
    let t_trivium_enc_enrolled = t0.elapsed();

    let t0 = Instant::now();
    let mut trivium_probe = Trivium::new(&probe_key_bits, &probe_iv_bits);
    let probe_ciphertext = trivium_probe.process(&probe_bits);
    let t_trivium_enc_probe = t0.elapsed();

    println!(
        "[2] Trivium symmetric encryption:  {:>10.3} ms (enrolled) / {:>7.3} ms (probe)",
        ms(t_trivium_enc_enrolled),
        ms(t_trivium_enc_probe)
    );

    // ---------------------------------------------------------------
    // 3a. TRANSCIPHERING baseline: client only FHE-encrypts key+iv+true
    //     (80 + 80 + 1 = 161 bits) per template.
    // ---------------------------------------------------------------
    let encrypted_true = FheBool::encrypt(true, &client_key);

    let t0 = Instant::now();
    let enc_key_enrolled: Vec<FheBool> = enroll_key_bits
        .iter()
        .map(|&b| FheBool::encrypt(b, &client_key))
        .collect();
    let enc_iv_enrolled: Vec<FheBool> = enroll_iv_bits
        .iter()
        .map(|&b| FheBool::encrypt(b, &client_key))
        .collect();
    let t_fhe_enc_transcipher_enrolled = t0.elapsed();

    let t0 = Instant::now();
    let enc_key_probe: Vec<FheBool> = probe_key_bits
        .iter()
        .map(|&b| FheBool::encrypt(b, &client_key))
        .collect();
    let enc_iv_probe: Vec<FheBool> = probe_iv_bits
        .iter()
        .map(|&b| FheBool::encrypt(b, &client_key))
        .collect();
    let t_fhe_enc_transcipher_probe = t0.elapsed();

    println!(
        "[3] FHE-encrypt key+iv (161 bits): {:>10.1} ms (enrolled) / {:>7.1} ms (probe)  [transciphering]",
        ms(t_fhe_enc_transcipher_enrolled),
        ms(t_fhe_enc_transcipher_probe)
    );

    // ---------------------------------------------------------------
    // 3b. NAIVE full-FHE baseline: client FHE-encrypts the entire
    //     512-bit template directly, no Trivium/transciphering at all.
    // ---------------------------------------------------------------
    let t0 = Instant::now();
    let naive_enrolled_fhe: Vec<FheBool> = enrolled_bits
        .iter()
        .map(|&b| FheBool::encrypt(b, &client_key))
        .collect();
    let t_fhe_enc_naive_enrolled = t0.elapsed();

    let t0 = Instant::now();
    let naive_probe_fhe: Vec<FheBool> = probe_bits
        .iter()
        .map(|&b| FheBool::encrypt(b, &client_key))
        .collect();
    let t_fhe_enc_naive_probe = t0.elapsed();

    println!(
        "[3] FHE-encrypt full template (512 bits): {:>5.1} ms (enrolled) / {:>7.1} ms (probe)  [naive baseline]",
        ms(t_fhe_enc_naive_enrolled),
        ms(t_fhe_enc_naive_probe)
    );
    println!();

    // ---------------------------------------------------------------
    // 4. Payload size comparison (what actually goes over the wire)
    // ---------------------------------------------------------------
    let transcipher_payload = bincode::serialize(&enroll_ciphertext)?.len()
        + bincode::serialize(&enc_key_enrolled)?.len()
        + bincode::serialize(&enc_iv_enrolled)?.len()
        + bincode::serialize(&encrypted_true)?.len();
    let naive_payload = bincode::serialize(&naive_enrolled_fhe)?.len();

    println!("[4] Network payload per template (register request):");
    println!(
        "      transciphering: {:>10} bytes ({:.1} KB)",
        transcipher_payload,
        transcipher_payload as f64 / 1024.0
    );
    println!(
        "      naive full-FHE: {:>10} bytes ({:.1} KB)",
        naive_payload,
        naive_payload as f64 / 1024.0
    );
    println!(
        "      reduction:      {:.1}x smaller\n",
        naive_payload as f64 / transcipher_payload as f64
    );

    // ---------------------------------------------------------------
    // 5. Server-side: homomorphic Trivium decryption (transciphering
    //    cost that the naive baseline does NOT pay)
    // ---------------------------------------------------------------
    let t0 = Instant::now();
    let enrolled_template_fhe = decrypt_homomorphic(
        &enroll_ciphertext,
        &enc_key_enrolled,
        &enc_iv_enrolled,
        &encrypted_true,
        &server_key,
    );
    let t_decrypt_enrolled = t0.elapsed();
    println!(
        "[5] Server: decrypt_homomorphic (enrolled, register-time): {:>8.1} ms",
        ms(t_decrypt_enrolled)
    );

    let t0 = Instant::now();
    let probe_template_fhe = decrypt_homomorphic(
        &probe_ciphertext,
        &enc_key_probe,
        &enc_iv_probe,
        &encrypted_true,
        &server_key,
    );
    let t_decrypt_probe = t0.elapsed();
    println!(
        "[5] Server: decrypt_homomorphic (probe, verify-time):      {:>8.1} ms",
        ms(t_decrypt_probe)
    );

    // ---------------------------------------------------------------
    // 6. Server-side matching circuit (shared by both approaches)
    // ---------------------------------------------------------------
    let t0 = Instant::now();
    let diff = diff_bits(&enrolled_template_fhe, &probe_template_fhe);
    let t_diff = t0.elapsed();

    let t0 = Instant::now();
    let distance_fhe = popcount_512(&diff, &encrypted_true);
    let t_popcount = t0.elapsed();

    let t0 = Instant::now();
    let match_fhe = leq_constant(&distance_fhe, THRESHOLD, &encrypted_true);
    let t_leq = t0.elapsed();

    println!("[6] Server: diff_bits:                                      {:>8.3} ms", ms(t_diff));
    println!("[6] Server: popcount_512:                                   {:>8.1} ms", ms(t_popcount));
    println!("[6] Server: leq_constant (threshold={}):                   {:>8.1} ms", THRESHOLD, ms(t_leq));
    println!();

    // ---------------------------------------------------------------
    // 6b. NAIVE full-FHE matching: same circuit, but run directly on the
    //     client-encrypted templates (no decrypt_homomorphic step at all,
    //     since there's no transciphering to undo).
    // ---------------------------------------------------------------
    let t0 = Instant::now();
    let naive_diff = diff_bits(&naive_enrolled_fhe, &naive_probe_fhe);
    let t_naive_diff = t0.elapsed();

    let t0 = Instant::now();
    let naive_distance_fhe = popcount_512(&naive_diff, &encrypted_true);
    let t_naive_popcount = t0.elapsed();

    let t0 = Instant::now();
    let naive_match_fhe = leq_constant(&naive_distance_fhe, THRESHOLD, &encrypted_true);
    let t_naive_leq = t0.elapsed();

    println!("[6b] Server (naive): diff_bits:                             {:>8.3} ms", ms(t_naive_diff));
    println!("[6b] Server (naive): popcount_512:                          {:>8.1} ms", ms(t_naive_popcount));
    println!("[6b] Server (naive): leq_constant (threshold={}):          {:>8.1} ms", THRESHOLD, ms(t_naive_leq));
    println!();

    let naive_match_result: bool = naive_match_fhe.decrypt(&client_key);
    let naive_distance_bits: Vec<bool> = naive_distance_fhe.iter().map(|b| b.decrypt(&client_key)).collect();
    let mut naive_distance = 0usize;
    for (i, &b) in naive_distance_bits.iter().enumerate() {
        if b {
            naive_distance += 1 << i;
        }
    }
    println!(
        "Correctness check (naive): FHE distance = {}, plaintext distance = {} -> {}",
        naive_distance,
        hamming_distance(&enrolled_bits, &probe_bits),
        if naive_distance == hamming_distance(&enrolled_bits, &probe_bits) { "MATCH (circuit correct)" } else { "MISMATCH! bug" }
    );
    println!("Match result (naive, decrypted): {}", naive_match_result);
    println!();

    // ---------------------------------------------------------------
    // 7. Client-side decrypt of the result + correctness sanity check
    // ---------------------------------------------------------------
    let t0 = Instant::now();
    let match_result: bool = match_fhe.decrypt(&client_key);
    let distance_bits: Vec<bool> = distance_fhe.iter().map(|b| b.decrypt(&client_key)).collect();
    let t_client_decrypt = t0.elapsed();

    let mut distance = 0usize;
    for (i, &b) in distance_bits.iter().enumerate() {
        if b {
            distance += 1 << i;
        }
    }

    let plaintext_distance = hamming_distance(&enrolled_bits, &probe_bits);

    println!(
        "[7] Client: decrypt match+distance:                         {:>8.3} ms",
        ms(t_client_decrypt)
    );
    println!();
    println!("Correctness check: FHE distance = {}, plaintext distance = {} -> {}",
        distance, plaintext_distance,
        if distance == plaintext_distance { "MATCH (circuit correct)" } else { "MISMATCH! bug" }
    );
    println!("Match result (FHE, decrypted): {}", match_result);
    println!();

    // ---------------------------------------------------------------
    // Summary table
    // ---------------------------------------------------------------
    let t_end_to_end_register = t_extract_enrolled
        + t_trivium_enc_enrolled
        + t_fhe_enc_transcipher_enrolled
        + t_decrypt_enrolled;
    let t_end_to_end_verify = t_extract_probe
        + t_trivium_enc_probe
        + t_fhe_enc_transcipher_probe
        + t_decrypt_probe
        + t_diff
        + t_popcount
        + t_leq
        + t_client_decrypt;

    // Naive baseline has no transciphering step at all: register is just
    // "client FHE-encrypts template, server stores ciphertext as-is."
    let t_naive_end_to_end_register = t_extract_enrolled + t_fhe_enc_naive_enrolled;
    let t_naive_end_to_end_verify = t_extract_probe
        + t_fhe_enc_naive_probe
        + t_naive_diff
        + t_naive_popcount
        + t_naive_leq
        + t_client_decrypt;

    println!("{}", "=".repeat(70));
    println!("SUMMARY");
    println!("{}", "=".repeat(70));
    println!("{:<50}{:>15.1} ms", "Feature extraction (per image)", ms(t_extract_enrolled));
    println!("{:<50}{:>15.1} ms", "FHE key generation (one-time)", ms(t_keygen));
    println!("{:<50}{:>15.1} ms", "End-to-end REGISTER (client+server)", ms(t_end_to_end_register));
    println!("{:<50}{:>15.1} ms", "End-to-end VERIFY (client+server)", ms(t_end_to_end_verify));
    println!();
    println!("NAIVE full-FHE baseline (no transciphering at all):");
    println!("{:<50}{:>15.1} ms", "  End-to-end REGISTER (client+server)", ms(t_naive_end_to_end_register));
    println!("{:<50}{:>15.1} ms", "  End-to-end VERIFY (client+server)", ms(t_naive_end_to_end_verify));
    println!();
    println!("Transciphering vs naive full-FHE (client-side encrypt time, per template):");
    println!(
        "{:<50}{:>15.1} ms",
        "  transciphering (161 bits)",
        ms(t_fhe_enc_transcipher_enrolled)
    );
    println!(
        "{:<50}{:>15.1} ms",
        "  naive full-FHE (512 bits)",
        ms(t_fhe_enc_naive_enrolled)
    );
    println!(
        "{:<50}{:>15.1} ms",
        "  extra server cost transciphering pays (decrypt_homomorphic)",
        ms(t_decrypt_enrolled)
    );
    println!(
        "{:<50}{:>14.1}x",
        "  network payload reduction",
        naive_payload as f64 / transcipher_payload as f64
    );
    println!(
        "{:<50}{:>14.1}x",
        "  REGISTER speedup (naive / transciphering)",
        ms(t_naive_end_to_end_register) / ms(t_end_to_end_register)
    );
    println!(
        "{:<50}{:>14.1}x",
        "  VERIFY speedup (naive / transciphering)",
        ms(t_naive_end_to_end_verify) / ms(t_end_to_end_verify)
    );

    Ok(())
}
