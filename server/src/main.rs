mod database;

use database::{Database, TemplateEntry};
use shared::{
    RegisterRequest, RegisterResponse,
    VerifyRequest, VerifyResponse,
    decrypt_homomorphic,
    diff_bits, popcount_1024, leq_constant,  // ⬅️ popcount_512 → popcount_1024
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
        // Check for register request
        if Path::new(REGISTER_REQ_PATH).exists() {
            println!("\n📥 REGISTER REQUEST DETECTED");
            println!("{}", "─".repeat(70));
            
            match handle_register() {
                Ok(_) => println!("✅ Register completed successfully!"),
                Err(e) => eprintln!("❌ Register failed: {}", e),
            }
            
            println!("\n⏳ Waiting for next request...\n");
        }

        // Check for verify request
        if Path::new(VERIFY_REQ_PATH).exists() {
            println!("\n📥 VERIFY REQUEST DETECTED");
            println!("{}", "─".repeat(70));
            
            match handle_verify() {
                Ok(_) => println!("✅ Verify completed successfully!"),
                Err(e) => eprintln!("❌ Verify failed: {}", e),
            }
            
            println!("\n⏳ Waiting for next request...\n");
        }

        std::thread::sleep(Duration::from_millis(500));
    }
}

// ==================== REGISTER HANDLER ====================

fn handle_register() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Read request
    let req_json = fs::read_to_string(REGISTER_REQ_PATH)?;
    let req: RegisterRequest = serde_json::from_str(&req_json)?;
    
    println!("👤 User ID: {}", req.user_id);
    println!("📊 Ciphertext: {} bits", req.ciphertext.len());
    
    // 2. Load/Save server key
    if let Some(ref server_key_bytes) = req.server_key_bytes {
        println!("🔑 Saving server key (first registration)...");
        fs::write(SERVER_KEY_PATH, server_key_bytes)?;
        println!("✅ Server key saved to: {}", SERVER_KEY_PATH);
    } else {
        if !Path::new(SERVER_KEY_PATH).exists() {
            // ❌ CLEANUP BEFORE ERROR
            let _ = fs::remove_file(REGISTER_REQ_PATH);
            return Err("Server key not found and not provided in request!".into());
        }
        println!("✅ Server key already exists");
    }
    
    // 3. Load database - ✅ HATA YAKALA
    let mut db = match Database::load() {
        Ok(db) => db,
        Err(e) => {
            eprintln!("❌ Database load failed: {}", e);
            eprintln!("🔧 Creating fresh database...");
            
            // Backup corrupt database
            if Path::new("../database/templates.json").exists() {
                let backup_path = format!("../database/templates.json.backup.{}", 
                    chrono::Utc::now().timestamp());
                let _ = fs::rename("../database/templates.json", &backup_path);
                println!("📦 Corrupt database backed up to: {}", backup_path);
            }
            
            // Create fresh database
            let fresh_db = Database {
                version: "1.0".to_string(),
                templates: std::collections::HashMap::new(),
            };
            fresh_db.save()?;
            fresh_db
        }
    };
    
    // 4. Check if user already exists
    if db.exists(&req.user_id) {
        println!("⚠️  User already exists, updating...");
    }
    
    // 5. Vec<bool> -> Vec<u8> dönüşümü
    let ciphertext_bytes = bools_to_bytes(&req.ciphertext);
    
    // 6. Create template entry
    let entry = TemplateEntry::new(
        req.user_id.clone(),
        ciphertext_bytes,
        req.encrypted_key_bytes,
        req.encrypted_iv_bytes,
    );
    
    // 7. Insert into database
    db.insert(entry);
    
    // ✅ SAVE BEFORE RESPONSE
    match db.save() {
        Ok(_) => {
            println!("💾 Template saved to database");
            println!("📈 Total templates: {}", db.templates.len());
        }
        Err(e) => {
            eprintln!("❌ Failed to save database: {}", e);
            // ❌ CLEANUP AND RETURN ERROR
            let _ = fs::remove_file(REGISTER_REQ_PATH);
            return Err(format!("Database save failed: {}", e).into());
        }
    }
    
    // 8. Send response
    let resp = RegisterResponse::success(req.user_id);
    let resp_json = serde_json::to_string_pretty(&resp)?;
    fs::write(REGISTER_RESP_PATH, resp_json)?;
    
    println!("📤 Response sent!");
    
    // 9. Cleanup - ✅ HER DURUMDA SİL
    let _ = fs::remove_file(REGISTER_REQ_PATH);
    
    Ok(())
}

// ==================== VERIFY HANDLER ====================

fn handle_verify() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Read request
    let req_json = fs::read_to_string(VERIFY_REQ_PATH)?;
    let req: VerifyRequest = serde_json::from_str(&req_json)?;
    
    println!("👤 User ID: {}", req.user_id);
    println!("📊 Probe ciphertext: {} bits", req.ciphertext.len());
    
    // 2. Load server key
    if !Path::new(SERVER_KEY_PATH).exists() {
        return Err("Server key not found! Register a user first.".into());
    }
    
    let server_key_bytes = fs::read(SERVER_KEY_PATH)?;
    let server_key: ServerKey = bincode::deserialize(&server_key_bytes)?;
    set_server_key(server_key.clone());
    
    println!("✅ Server key loaded");
    
    // 3. Load database and find enrolled template
    let db = Database::load()?;
    
    let enrolled = match db.get(&req.user_id) {
        Some(e) => e,
        None => {
            let resp = VerifyResponse::error(format!("User '{}' not found in database", req.user_id));
            let resp_json = serde_json::to_string_pretty(&resp)?;
            fs::write(VERIFY_RESP_PATH, resp_json)?;
            fs::remove_file(VERIFY_REQ_PATH)?;
            return Err(format!("User '{}' not registered", req.user_id).into());
        }
    };
    
    println!("✅ Enrolled template found");
    println!("   Created: {}", enrolled.created_at);
    
    // 4. Deserialize FHE data
    println!("\n🔓 Deserializing FHE data...");
    
    let encrypted_key_enrolled: Vec<FheBool> = bincode::deserialize(&enrolled.encrypted_key_bytes)?;
    let encrypted_iv_enrolled: Vec<FheBool> = bincode::deserialize(&enrolled.encrypted_iv_bytes)?;
    let encrypted_key_probe: Vec<FheBool> = bincode::deserialize(&req.encrypted_key_bytes)?;
    let encrypted_iv_probe: Vec<FheBool> = bincode::deserialize(&req.encrypted_iv_bytes)?;
    let encrypted_true: FheBool = bincode::deserialize(&req.encrypted_true_bytes)?;
    
    println!("✅ FHE data deserialized:");
    println!("   Enrolled key: {} bits", encrypted_key_enrolled.len());
    println!("   Enrolled IV:  {} bits", encrypted_iv_enrolled.len());
    println!("   Probe key:    {} bits", encrypted_key_probe.len());
    println!("   Probe IV:     {} bits", encrypted_iv_probe.len());
    
    // 5. FHE-Trivium decrypt (ENROLLED)
    println!("\n🔐 FHE-Trivium decrypting ENROLLED fingerprint...");
    println!("⚠️  This will take ~15-30 minutes!");
    
    // Vec<u8> -> Vec<bool> dönüşümü
    let enrolled_ciphertext_bools = bytes_to_bools(&enrolled.ciphertext);
    
    let plaintext_enrolled_fhe = decrypt_homomorphic(
        &enrolled_ciphertext_bools,
        &encrypted_key_enrolled,
        &encrypted_iv_enrolled,
        &encrypted_true,
        &server_key,
    );
    
    println!("✅ Enrolled fingerprint decrypted (still encrypted!)");
    
    // 6. FHE-Trivium decrypt (PROBE)
    println!("\n🔐 FHE-Trivium decrypting PROBE fingerprint...");
    println!("⚠️  This will take another ~15-30 minutes!");
    
    let plaintext_probe_fhe = decrypt_homomorphic(
        &req.ciphertext,
        &encrypted_key_probe,
        &encrypted_iv_probe,
        &encrypted_true,
        &server_key,
    );
    
    println!("✅ Probe fingerprint decrypted (still encrypted!)");
    
    // 7. FHE Matching
    println!("\n🧬 FHE Matching (computing Hamming distance)...");
    
    // 7a. XOR difference
    let diff = diff_bits(&plaintext_enrolled_fhe, &plaintext_probe_fhe);
    println!("   ✅ Difference bits computed");
    
    // 7b. Popcount (Hamming distance)
    let distance_fhe = popcount_1024(&diff, &encrypted_true);  // ⬅️
    println!("   ✅ Hamming distance computed (11-bit encrypted counter)");
    
    // 7c. Threshold comparison (80% similarity = max 204 bits difference)
    let threshold = (1024.0 * 0.2) as usize;  // ⬅️ 204 bits
    let match_result_fhe = leq_constant(&distance_fhe, threshold, &encrypted_true);
    println!("   ✅ Threshold comparison done (threshold: {} bits)", threshold);
    
    // 8. Serialize encrypted results
    println!("\n📦 Serializing results...");
    
    let encrypted_match_bytes = bincode::serialize(&match_result_fhe)?;
    let encrypted_distance_bytes = bincode::serialize(&distance_fhe)?;
    
    println!("✅ Results serialized:");
    println!("   Match bytes:    {} bytes", encrypted_match_bytes.len());
    println!("   Distance bytes: {} bytes", encrypted_distance_bytes.len());
    
    // 9. Create response
    let resp = VerifyResponse::success(encrypted_match_bytes, encrypted_distance_bytes);
    
    // 🚫 DEBUG MODE - UNCOMMENT ONLY FOR TESTING
    // WARNING: This reveals plaintext to server!
    /*
    let debug_match = match_result_fhe.decrypt(&server_key);  // ❌ DON'T DO THIS!
    let debug_distance_bits: Vec<bool> = distance_fhe.iter()
        .map(|b| b.decrypt(&server_key))
        .collect();
    let debug_distance = bits_to_usize(&debug_distance_bits);
    let resp = resp.with_debug(debug_match, debug_distance);
    println!("🚨 DEBUG: Match = {}, Distance = {}", debug_match, debug_distance);
    */
    
    // 10. Send response
    let resp_json = serde_json::to_string_pretty(&resp)?;
    fs::write(VERIFY_RESP_PATH, resp_json)?;
    
    println!("\n📤 Response sent!");
    
    // 11. Cleanup
    fs::remove_file(VERIFY_REQ_PATH)?;
    
    Ok(())
}

// Helper: Convert 8-bit binary to usize (for debug)
#[allow(dead_code)]
fn bits_to_usize(bits: &[bool]) -> usize {
    let mut result = 0;
    for (i, &bit) in bits.iter().enumerate() {
        if bit {
            result += 1 << i;
        }
    }
    result
}

// Yardımcı fonksiyonlar: bool ve byte dönüşümleri
fn bools_to_bytes(bools: &[bool]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for chunk in bools.chunks(8) {
        let mut byte = 0u8;
        for (i, &bit) in chunk.iter().enumerate() {
            if bit {
                byte |= 1 << i;
            }
        }
        bytes.push(byte);
    }
    bytes
}

fn bytes_to_bools(bytes: &[u8]) -> Vec<bool> {
    let mut bools = Vec::new();
    for &byte in bytes {
        for i in 0..8 {
            bools.push((byte & (1 << i)) != 0);
        }
    }
    bools
}