// client/src/main.rs

mod feature_extraction;
mod matching;

use feature_extraction::extract_fingerprint_128bit;
use matching::{hamming_distance, match_fingerprints};

use shared::{AuthRequest, AuthResponse, Trivium, u64_to_bits_80};

use tfhe::prelude::*;
use tfhe::{generate_keys, ConfigBuilder, FheBool};

use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 FINGERPRINT AUTHENTICATION CLIENT");
    println!("{}", "=".repeat(70));

    // ----------------------------
    // Paths (keep your folder layout)
    // ----------------------------
    let exchange_dir = Path::new("../exchange");
    let data_dir = Path::new("../data");
    fs::create_dir_all(exchange_dir)?;
    fs::create_dir_all(data_dir)?;

    let req_path = exchange_dir.join("auth_request.json");
    let resp_path = exchange_dir.join("auth_response.json");
    let server_key_path = exchange_dir.join("server_key.bin");

    // ----------------------------
    // CLI args
    // Usage:
    //   cargo run --release -- auth user_101 ../data/fingerprints/101_1.tif ../data/fingerprints/101_2.tif
    //
    // Modes:
    //   enroll -> only extracts and saves enrolled template locally
    //   auth   -> runs full pipeline, writes request, reads response, decrypts and verifies
    // ----------------------------
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("auth");
    let user_id = args.get(2).cloned().unwrap_or_else(|| "user_101".to_string());

    let enrolled_path = args.get(3).cloned().unwrap_or_else(|| "../data/fingerprints/101_1.tif".to_string());
    let probe_path    = args.get(4).cloned().unwrap_or_else(|| "../data/fingerprints/101_2.tif".to_string());

    let enrolled_template_path = data_dir.join(format!("{}_enrolled.bin", user_id));

    // ----------------------------
    // 1) Enrollment (local save)
    // ----------------------------
    println!("\n📝 ENROLLMENT PHASE (local save):");
    println!("{}", "─".repeat(70));

    println!("📷 Extracting enrolled fingerprint ({})...", enrolled_path);
    let enrolled_bits = extract_fingerprint_128bit(&enrolled_path)?;
    println!("✅ Enrolled: {} bits extracted", enrolled_bits.len());
    if enrolled_bits.len() != 128 {
        return Err(format!("Expected 128-bit feature, got {}", enrolled_bits.len()).into());
    }

    save_bool_vec(&enrolled_template_path, &enrolled_bits)?;
    println!("💾 Saved enrolled template: {}", enrolled_template_path.display());

    if mode == "enroll" {
        println!("\nℹ️ Mode=enroll => only local template saved.");
        return Ok(());
    }

    // ----------------------------
    // 2) Auth - extract probe
    // ----------------------------
    println!("\n🔎 AUTH PHASE:");
    println!("{}", "─".repeat(70));

    println!("📷 Extracting probe fingerprint ({})...", probe_path);
    let probe_bits = extract_fingerprint_128bit(&probe_path)?;
    println!("✅ Probe: {} bits extracted", probe_bits.len());
    if probe_bits.len() != 128 {
        return Err(format!("Expected 128-bit feature, got {}", probe_bits.len()).into());
    }

    // ----------------------------
    // 3) Generate TFHE keys
    // ----------------------------
    println!("\n🧠 TFHE KEY GENERATION:");
    println!("{}", "─".repeat(70));

    let config = ConfigBuilder::default()
        .build();

    let (client_key, server_key) = generate_keys(config);

    // Export server_key for server side usage
    let server_key_bytes = bincode::serialize(&server_key)?;
    fs::write(&server_key_path, server_key_bytes)?;
    println!("✅ server_key written to: {}", server_key_path.display());
    println!("🔒 client_key stays in client memory (NOT written).");

    // ----------------------------
    // 4) Trivium key/IV (80-bit)
    // ----------------------------
    println!("\n🔧 TRIVIUM PARAMS:");
    println!("{}", "─".repeat(70));

    // NOTE: Ensure your shared::u64_to_bits_80 matches server bit ordering expectations.
    let key_bits_80 = u64_to_bits_80(0x0123_4567_89AB_CDEF);
    let iv_bits_80  = u64_to_bits_80(0x0F1E_2D3C_4B5A_6978);

    println!("✅ Key bits: {}", key_bits_80.len());
    println!("✅ IV  bits: {}", iv_bits_80.len());

    // ----------------------------
    // 5) Plain Trivium encrypt probe -> ciphertext
    // ----------------------------
    println!("\n🔐 PLAIN TRIVIUM ENCRYPT:");
    println!("{}", "─".repeat(70));

    let mut triv = Trivium::new(&key_bits_80, &iv_bits_80);
    let ciphertext_bits = triv.process(&probe_bits);
    println!("✅ Ciphertext produced: {} bits", ciphertext_bits.len());

    // Sanity check: decrypt locally to ensure plain Trivium is consistent
    let mut triv2 = Trivium::new(&key_bits_80, &iv_bits_80);
    let decrypted_local = triv2.process(&ciphertext_bits);
    let local_err = hamming_distance(&decrypted_local, &probe_bits);
    println!("🧪 Local Trivium sanity check errors: {}/{}", local_err, probe_bits.len());
    if local_err != 0 {
        return Err("Local Trivium sanity check failed (plain encrypt/decrypt mismatch)".into());
    }

    // ----------------------------
    // 6) FHE-encrypt key/iv bits + encrypted_true
    // ----------------------------
    println!("\n🔐 FHE-ENCRYPT KEY/IV:");
    println!("{}", "─".repeat(70));

    let encrypted_key: Vec<FheBool> = key_bits_80
        .iter()
        .map(|&b| FheBool::encrypt(b, &client_key))
        .collect();

    let encrypted_iv: Vec<FheBool> = iv_bits_80
        .iter()
        .map(|&b| FheBool::encrypt(b, &client_key))
        .collect();

    let encrypted_true = FheBool::encrypt(true, &client_key);

    // Serialize for protocol
    let encrypted_key_bytes = bincode::serialize(&encrypted_key)?;
    let encrypted_iv_bytes = bincode::serialize(&encrypted_iv)?;
    let encrypted_true_bytes = bincode::serialize(&encrypted_true)?;

    println!("✅ encrypted_key_bytes size: {}", encrypted_key_bytes.len());
    println!("✅ encrypted_iv_bytes  size: {}", encrypted_iv_bytes.len());
    println!("✅ encrypted_true_bytes size: {}", encrypted_true_bytes.len());

    // ----------------------------
    // 7) Build & write AuthRequest (JSON)
    // ----------------------------
    println!("\n📤 Sending to server (file-based demo)...");
    println!("{}", "─".repeat(70));

    let req = AuthRequest::new(
        ciphertext_bits.clone(),
        encrypted_key_bytes,
        encrypted_iv_bytes,
        encrypted_true_bytes,
        user_id.clone(),
    );

    write_json(&req_path, &req)?;
    println!("✅ Request sent! -> {}", req_path.display());

    // ----------------------------
    // 8) Read AuthResponse
    // ----------------------------
    println!("\n⏳ Waiting for server response...");
    let resp: AuthResponse = wait_and_read_json(&resp_path, Duration::from_secs(15000))?;
    println!("✅ Response received!");

    if let Some(m) = resp.server_match {
        println!("🧾 Server match: {}", m);
    }
    if let Some(d) = resp.distance {
        println!("📏 Server distance: {}", d);
    }

    // ----------------------------
    // 9) Decrypt result and verify against original probe bits
    // ----------------------------
    println!("\n🔓 Decrypting result...");
    println!("{}", "─".repeat(70));

    // Server returns encrypted_result: Vec<u8> representing bincode(Vec<FheBool>)
    let encrypted_plaintext_bits: Vec<FheBool> = bincode::deserialize(&resp.encrypted_result)?;
    if encrypted_plaintext_bits.len() != probe_bits.len() {
        return Err(format!(
            "Server returned {} bits, expected {}",
            encrypted_plaintext_bits.len(),
            probe_bits.len()
        ).into());
    }

    let plaintext_from_server: Vec<bool> = encrypted_plaintext_bits
        .iter()
        .map(|b| b.decrypt(&client_key))
        .collect();

    let errors = hamming_distance(&plaintext_from_server, &probe_bits);

    println!("✅ VERIFICATION:");
    println!("{}", "─".repeat(70));
    println!("Decryption errors: {}/{} bits", errors, probe_bits.len());

    if errors == 0 {
        println!("✅ Decryption successful!");
    } else {
        println!("❌ Decryption failed!");
    }

    // Optional local match demo with enrolled template (plaintext on client)
    println!("\n🧾 OPTIONAL LOCAL MATCH (demo):");
    println!("{}", "─".repeat(70));
    if enrolled_template_path.exists() {
        let enrolled_loaded = load_bool_vec(&enrolled_template_path)?;
        let dist = hamming_distance(&plaintext_from_server, &enrolled_loaded);
        let ok = match_fingerprints(&plaintext_from_server, &enrolled_loaded, 0.7);
        println!("Hamming distance (server-plaintext vs enrolled): {}", dist);
        println!("Match decision (client-local demo): {}", ok);
    } else {
        println!("(No enrolled template found at {})", enrolled_template_path.display());
    }

    Ok(())
}

// ----------------------------
// Helpers
// ----------------------------

fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), Box<dyn std::error::Error>> {
    let json = serde_json::to_vec_pretty(value)?;
    fs::write(path, json)?;
    Ok(())
}

fn wait_and_read_json<T: for<'de> serde::Deserialize<'de>>(
    path: &Path,
    timeout: Duration,
) -> Result<T, Box<dyn std::error::Error>> {
    let start = Instant::now();
    loop {
        if path.exists() {
            let data = fs::read(path)?;
            // Retry once if parse fails (server may be writing)
            match serde_json::from_slice::<T>(&data) {
                Ok(v) => return Ok(v),
                Err(_) => {
                    std::thread::sleep(Duration::from_millis(150));
                    let data2 = fs::read(path)?;
                    let v2 = serde_json::from_slice::<T>(&data2)?;
                    return Ok(v2);
                }
            }
        }

        if start.elapsed() > timeout {
            return Err(format!("Timeout waiting for {}", path.display()).into());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn save_bool_vec(path: &Path, v: &[bool]) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = bincode::serialize(v)?;
    fs::write(path, bytes)?;
    Ok(())
}

fn load_bool_vec(path: &Path) -> Result<Vec<bool>, Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    Ok(bincode::deserialize(&bytes)?)
}
