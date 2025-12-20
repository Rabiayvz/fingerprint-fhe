// server/src/main.rs

mod fhe_operations; // (ister kullan ister kullanma; şimdilik kalabilir)

use shared::{AuthRequest, AuthResponse, decrypt_homomorphic};

use tfhe::{set_server_key, ServerKey, FheBool};

use std::fs;
use std::path::Path;
use std::time::Duration;

const EXCHANGE_DIR: &str = "../exchange";
const REQ_PATH: &str = "../exchange/auth_request.json";
const RESP_PATH: &str = "../exchange/auth_response.json";
const RESP_TMP_PATH: &str = "../exchange/auth_response.json.tmp";
const SERVER_KEY_PATH: &str = "../exchange/server_key.bin";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🖥️  FINGERPRINT AUTHENTICATION SERVER");
    println!("{}", "=".repeat(70));

    fs::create_dir_all(EXCHANGE_DIR)?;

    println!("\n⏳ Waiting for authentication request...");
    loop {
        match check_for_request() {
            Ok((auth_req, server_key)) => {
                println!("\n📥 Request received from user: {}", auth_req.user_id);

                // Important: set TFHE server key for homomorphic ops
                set_server_key(server_key.clone());

                // --- Deserialize incoming FHE data ---
                println!("🔐 Deserializing FHE data...");
                println!("   ciphertext bits: {}", auth_req.ciphertext.len());
                println!("   encrypted_key_bytes size: {} bytes", auth_req.encrypted_key_bytes.len());
                println!("   encrypted_iv_bytes  size: {} bytes", auth_req.encrypted_iv_bytes.len());
                println!("   encrypted_true_bytes size: {} bytes", auth_req.encrypted_true_bytes.len());

                let encrypted_key: Vec<FheBool> = match bincode::deserialize::<Vec<FheBool>>(&auth_req.encrypted_key_bytes) {
                    Ok(v) => {
                        println!("   ✅ encrypted_key deserialized: {} bits", v.len());
                        v
                    }
                    Err(e) => {
                        eprintln!("❌ Failed to deserialize encrypted_key: {}", e);
                        cleanup_on_error();
                        sleep_tick();
                        continue;
                    }
                };

                let encrypted_iv: Vec<FheBool> = match bincode::deserialize::<Vec<FheBool>>(&auth_req.encrypted_iv_bytes) {
                    Ok(v) => {
                        println!("   ✅ encrypted_iv deserialized: {} bits", v.len());
                        v
                    }
                    Err(e) => {
                        eprintln!("❌ Failed to deserialize encrypted_iv: {}", e);
                        cleanup_on_error();
                        sleep_tick();
                        continue;
                    }
                };

                let encrypted_true: FheBool = match bincode::deserialize::<FheBool>(&auth_req.encrypted_true_bytes) {
                    Ok(v) => {
                        println!("   ✅ encrypted_true deserialized!");
                        v
                    }
                    Err(e) => {
                        eprintln!("❌ Failed to deserialize encrypted_true: {}", e);
                        cleanup_on_error();
                        sleep_tick();
                        continue;
                    }
                };

                // --- Homomorphic decryption ---
                println!("\n🔓 Starting homomorphic decryption...");
                println!("⚠️  Depending on parameters, this can take a while.\n");

                let decrypted_encrypted: Vec<FheBool> = decrypt_homomorphic(
                    &auth_req.ciphertext,
                    &encrypted_key,
                    &encrypted_iv,
                    &encrypted_true,
                    &server_key,
                );

                // Serialize result: Vec<FheBool> -> Vec<u8>
                println!("\n📦 Serializing result...");
                let encrypted_result_bytes = match bincode::serialize(&decrypted_encrypted) {
                    Ok(b) => b,
                    Err(e) => {
                        eprintln!("❌ Failed to serialize decrypted result: {}", e);
                        cleanup_on_error();
                        sleep_tick();
                        continue;
                    }
                };

                // Build response (protocol.rs ile birebir)
                let auth_resp = AuthResponse::new(encrypted_result_bytes);
                // İstersen server-side matching ekleyince:
                // let auth_resp = auth_resp.with_match(matched, distance);

                // Send response atomically (tmp -> rename)
                println!("📤 Sending response...");
                if let Err(e) = send_response_atomic(&auth_resp) {
                    eprintln!("❌ Failed to send response: {}", e);
                    cleanup_on_error();
                    sleep_tick();
                    continue;
                }
                println!("✅ Response sent -> {}", RESP_PATH);

                // Cleanup consumed request artifacts
                cleanup_after_success();

                println!("\n✅ Authentication complete!");
                println!("⏳ Waiting for next request...");
            }
            Err(_) => {
                // No request yet, just wait
                sleep_tick();
            }
        }
    }
}

fn check_for_request() -> Result<(AuthRequest, ServerKey), Box<dyn std::error::Error>> {
    if !Path::new(REQ_PATH).exists() || !Path::new(SERVER_KEY_PATH).exists() {
        return Err("No request".into());
    }

    // Read request JSON
    let req_json = fs::read_to_string(REQ_PATH)?;
    let req: AuthRequest = serde_json::from_str(&req_json)?;

    // Read server key bytes
    let sk_bytes = fs::read(SERVER_KEY_PATH)?;
    let server_key: ServerKey = bincode::deserialize::<ServerKey>(&sk_bytes)?;

    Ok((req, server_key))
}

fn send_response_atomic(resp: &AuthResponse) -> Result<(), Box<dyn std::error::Error>> {
    let resp_json = serde_json::to_string(resp)?;

    // write tmp
    fs::write(RESP_TMP_PATH, resp_json)?;

    // atomic-ish replace
    // On Windows, rename may fail if target exists; remove first.
    if Path::new(RESP_PATH).exists() {
        let _ = fs::remove_file(RESP_PATH);
    }
    fs::rename(RESP_TMP_PATH, RESP_PATH)?;

    Ok(())
}

fn cleanup_after_success() {
    // Request processed; remove request + server key
    let _ = fs::remove_file(REQ_PATH);
    let _ = fs::remove_file(SERVER_KEY_PATH);
    // Leave response for client to read
}

fn cleanup_on_error() {
    // Avoid getting stuck on a corrupt request forever.
    // In demos it's often better to delete and wait for next.
    // If you prefer, comment these out.
    let _ = fs::remove_file(REQ_PATH);
    let _ = fs::remove_file(SERVER_KEY_PATH);
}

fn sleep_tick() {
    std::thread::sleep(Duration::from_millis(400));
}
