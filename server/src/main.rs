mod database;

use database::{Database, TemplateEntry};
use shared::{
    RegisterRequest, RegisterResponse,
    VerifyRequest, VerifyResponse,
    decrypt_homomorphic,
    diff_bits, popcount_512, leq_constant,
};

use tfhe::{set_server_key, ServerKey, FheBool};
use std::fs;
use std::path::Path;
use std::time::Duration;

const EXCHANGE_DIR: &str = "../exchange";
const SERVER_KEY_PATH: &str = "../database/server_key.bin";

// Request/Response paths
const REGISTER_REQ_PATH: &str = "../exchange/register_request.json";
const REGISTER_RESP_PATH: &str = "../exchange/register_response.json";
const VERIFY_REQ_PATH: &str = "../exchange/verify_request.json";
const VERIFY_RESP_PATH: &str = "../exchange/verify_response.json";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🖥️  FINGERPRINT AUTHENTICATION SERVER");
    println!("{}", "=".repeat(70));

    fs::create_dir_all(EXCHANGE_DIR)?;
    fs::create_dir_all("../database")?;

    println!("\n⏳ Waiting for requests...\n");

    loop {
        // REGISTER
        if Path::new(REGISTER_REQ_PATH).exists() {
            println!("\n📥 REGISTER REQUEST DETECTED");
            println!("{}", "─".repeat(70));

            if let Err(e) = handle_register() {
                eprintln!("❌ Register failed: {}", e);
            } else {
                println!("✅ Register completed successfully!");
            }

            println!("\n⏳ Waiting for next request...\n");
        }

        // VERIFY
        if Path::new(VERIFY_REQ_PATH).exists() {
            println!("\n📥 VERIFY REQUEST DETECTED");
            println!("{}", "─".repeat(70));

            if let Err(e) = handle_verify() {
                eprintln!("❌ Verify failed: {}", e);
            } else {
                println!("✅ Verify completed successfully!");
            }

            println!("\n⏳ Waiting for next request...\n");
        }

        std::thread::sleep(Duration::from_millis(500));
    }
}

// ==================== INTERNAL HELPERS ====================

fn load_or_init_db_with_recovery() -> Result<Database, Box<dyn std::error::Error>> {
    match Database::load() {
        Ok(db) => Ok(db),
        Err(e) => {
            eprintln!("❌ Database load failed: {}", e);
            eprintln!("🔧 Creating fresh database...");

            if Path::new("../database/templates.json").exists() {
                let backup_path = format!(
                    "../database/templates.json.backup.{}",
                    chrono::Utc::now().timestamp()
                );
                let _ = fs::rename("../database/templates.json", &backup_path);
                println!("📦 Corrupt database backed up to: {}", backup_path);
            }

            let fresh_db = Database::new();
            fresh_db.save()?;
            Ok(fresh_db)
        }
    }
}

fn load_server_key_from_disk() -> Result<ServerKey, Box<dyn std::error::Error>> {
    if !Path::new(SERVER_KEY_PATH).exists() {
        return Err("Server key not found! Register a user first.".into());
    }
    let server_key_bytes = fs::read(SERVER_KEY_PATH)?;
    let server_key: ServerKey = bincode::deserialize(&server_key_bytes)?;
    Ok(server_key)
}

// ==================== REGISTER HANDLER ====================
// NEW:
// - Transcipher once at register
// - Store encrypted plaintext template in DB
fn handle_register() -> Result<(), Box<dyn std::error::Error>> {
    // Always cleanup request file at end (best effort)
    let cleanup = || {
        let _ = fs::remove_file(REGISTER_REQ_PATH);
    };

    // 1) Read request JSON
    let req_json = match fs::read_to_string(REGISTER_REQ_PATH) {
        Ok(s) => s,
        Err(e) => {
            cleanup();
            return Err(format!("Failed to read register request: {}", e).into());
        }
    };

    let req: RegisterRequest = match serde_json::from_str(&req_json) {
        Ok(r) => r,
        Err(e) => {
            cleanup();
            return Err(format!("Failed to parse register request JSON: {}", e).into());
        }
    };

    println!("👤 User ID: {}", req.user_id);
    println!("📊 Ciphertext: {} bits", req.ciphertext.len());

    // 2) Save server key if provided (first registration)
    if let Some(ref server_key_bytes) = req.server_key_bytes {
        println!("🔑 Saving server key (first registration)...");
        fs::write(SERVER_KEY_PATH, server_key_bytes)?;
        println!("✅ Server key saved to: {}", SERVER_KEY_PATH);
    } else {
        if !Path::new(SERVER_KEY_PATH).exists() {
            // write response too, if possible
            let resp = RegisterResponse::error(
                req.user_id.clone(),
                "Server key not found and not provided in request!".to_string(),
            );
            let _ = fs::write(REGISTER_RESP_PATH, serde_json::to_string_pretty(&resp).unwrap_or_default());
            cleanup();
            return Err("Server key not found and not provided in request!".into());
        }
        println!("✅ Server key already exists");
    }

    // 3) Load server key and set global
    let server_key = load_server_key_from_disk()?;
    set_server_key(server_key.clone());
    println!("✅ Server key loaded");

    // 4) Load DB (with recovery)
    let mut db = load_or_init_db_with_recovery()?;

    // 5) Check if user exists
    if db.exists(&req.user_id) {
        println!("⚠️  User already exists, updating...");
    }

    // 6) Deserialize FHE key/iv/true
    println!("\n🔓 Deserializing FHE data (register)...");
    let encrypted_key: Vec<FheBool> = bincode::deserialize(&req.encrypted_key_bytes)?;
    let encrypted_iv: Vec<FheBool> = bincode::deserialize(&req.encrypted_iv_bytes)?;
    let encrypted_true: FheBool = bincode::deserialize(&req.encrypted_true_bytes)?;

    println!("✅ FHE data deserialized:");
    println!("   Key bits: {}", encrypted_key.len());
    println!("   IV  bits: {}", encrypted_iv.len());

    // 7) Transcipher once (enrolled)
    println!("\n🔐 FHE-Trivium decrypting ENROLLED fingerprint (one-time at register)...");
    println!("⚠️  This may take time, but happens ONLY once per enrolled template.");

    let plaintext_enrolled_fhe: Vec<FheBool> = decrypt_homomorphic(
        &req.ciphertext,
        &encrypted_key,
        &encrypted_iv,
        &encrypted_true,
        &server_key,
    );

    println!("✅ Enrolled decrypted under FHE (plaintext bits encrypted)!");
    println!("   Template bits: {}", plaintext_enrolled_fhe.len());

    // 8) Serialize and store in DB
    let encrypted_template_bytes = bincode::serialize(&plaintext_enrolled_fhe)?;
    let entry = TemplateEntry::new(req.user_id.clone(), encrypted_template_bytes);
    db.insert(entry);

    db.save()?;
    println!("💾 Encrypted plaintext template saved to database");
    println!("📈 Total templates: {}", db.templates.len());

    // 9) Send response
    let resp = RegisterResponse::success(req.user_id);
    fs::write(REGISTER_RESP_PATH, serde_json::to_string_pretty(&resp)?)?;
    println!("📤 Response sent!");

    // 10) Cleanup
    cleanup();
    Ok(())
}

// ==================== VERIFY HANDLER ====================
// NEW:
// - Enrolled template is already encrypted plaintext in DB
// - Only decrypt probe, then match
fn handle_verify() -> Result<(), Box<dyn std::error::Error>> {
    // Always cleanup request file at end (best effort)
    let cleanup = || {
        let _ = fs::remove_file(VERIFY_REQ_PATH);
    };

    // 1) Read request JSON
    let req_json = match fs::read_to_string(VERIFY_REQ_PATH) {
        Ok(s) => s,
        Err(e) => {
            cleanup();
            return Err(format!("Failed to read verify request: {}", e).into());
        }
    };

    let req: VerifyRequest = match serde_json::from_str(&req_json) {
        Ok(r) => r,
        Err(e) => {
            cleanup();
            return Err(format!("Failed to parse verify request JSON: {}", e).into());
        }
    };

    println!("👤 User ID: {}", req.user_id);
    println!("📊 Probe ciphertext: {} bits", req.ciphertext.len());

    // 2) Load server key and set global
    let server_key = match load_server_key_from_disk() {
        Ok(k) => k,
        Err(e) => {
            // write error response if possible
            let resp = VerifyResponse::error(format!("{}", e));
            let _ = fs::write(VERIFY_RESP_PATH, serde_json::to_string_pretty(&resp).unwrap_or_default());
            cleanup();
            return Err(e);
        }
    };

    set_server_key(server_key.clone());
    println!("✅ Server key loaded");

    // 3) Load DB & find enrolled template
    let db = Database::load()?;
    let enrolled = match db.get(&req.user_id) {
        Some(e) => e,
        None => {
            let resp = VerifyResponse::error(format!("User '{}' not found in database", req.user_id));
            fs::write(VERIFY_RESP_PATH, serde_json::to_string_pretty(&resp)?)?;
            cleanup();
            return Err(format!("User '{}' not registered", req.user_id).into());
        }
    };

    println!("✅ Enrolled template found");
    println!("   Created: {}", enrolled.created_at);

    // 4) Deserialize enrolled encrypted plaintext template
    println!("\n🔓 Deserializing enrolled encrypted plaintext template...");
    let plaintext_enrolled_fhe: Vec<FheBool> = bincode::deserialize(&enrolled.encrypted_template_bytes)?;
    println!("✅ Enrolled template loaded (still encrypted!)");
    println!("   Bits: {}", plaintext_enrolled_fhe.len());

    // 5) Deserialize probe FHE data
    println!("\n🔓 Deserializing probe FHE data...");
    let encrypted_key_probe: Vec<FheBool> = bincode::deserialize(&req.encrypted_key_bytes)?;
    let encrypted_iv_probe: Vec<FheBool> = bincode::deserialize(&req.encrypted_iv_bytes)?;
    let encrypted_true: FheBool = bincode::deserialize(&req.encrypted_true_bytes)?;

    println!("✅ Probe FHE data deserialized:");
    println!("   Probe key: {} bits", encrypted_key_probe.len());
    println!("   Probe IV:  {} bits", encrypted_iv_probe.len());

    // 6) Decrypt probe only
    println!("\n🔐 FHE-Trivium decrypting PROBE fingerprint...");
    println!("⚠️  This is the only decrypt done during verify now.");

    let plaintext_probe_fhe: Vec<FheBool> = decrypt_homomorphic(
        &req.ciphertext,
        &encrypted_key_probe,
        &encrypted_iv_probe,
        &encrypted_true,
        &server_key,
    );

    println!("✅ Probe fingerprint decrypted (still encrypted!)");

    // 7) FHE Matching
    println!("\n🧬 FHE Matching (computing Hamming distance)...");

    let diff = diff_bits(&plaintext_enrolled_fhe, &plaintext_probe_fhe);
    println!("   ✅ Difference bits computed");

    let distance_fhe = popcount_512(&diff, &encrypted_true);
    println!("   ✅ Hamming distance computed (encrypted counter)");

    let threshold = (512.0 * 0.2) as usize;
    let match_result_fhe = leq_constant(&distance_fhe, threshold, &encrypted_true);
    println!("   ✅ Threshold comparison done (threshold: {} bits)", threshold);

    // 8) Serialize response payload
    println!("\n📦 Serializing results...");

    let encrypted_match_bytes = bincode::serialize(&match_result_fhe)?;
    let encrypted_distance_bytes = bincode::serialize(&distance_fhe)?;

    println!("✅ Results serialized:");
    println!("   Match bytes:    {} bytes", encrypted_match_bytes.len());
    println!("   Distance bytes: {} bytes", encrypted_distance_bytes.len());

    // 9) Write response
    let resp = VerifyResponse::success(encrypted_match_bytes, encrypted_distance_bytes);
    fs::write(VERIFY_RESP_PATH, serde_json::to_string_pretty(&resp)?)?;
    println!("\n📤 Response sent!");

    // 10) Cleanup
    cleanup();
    Ok(())
}
