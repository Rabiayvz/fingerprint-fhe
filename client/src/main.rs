mod feature_extraction;
mod matching;

use feature_extraction::extract_fingerprint_128bit;
use matching::hamming_distance;

use shared::{
    RegisterRequest, RegisterResponse,
    VerifyRequest, VerifyResponse,
    Trivium, u64_to_bits_80,
};

use tfhe::prelude::*;
use tfhe::{generate_keys, ConfigBuilder, FheBool};

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

// Paths
const EXCHANGE_DIR: &str = "../exchange";
const DATA_DIR: &str = "../data";

// Request/Response paths
const REGISTER_REQ_PATH: &str = "../exchange/register_request.json";
const REGISTER_RESP_PATH: &str = "../exchange/register_response.json";
const VERIFY_REQ_PATH: &str = "../exchange/verify_request.json";
const VERIFY_RESP_PATH: &str = "../exchange/verify_response.json";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 FINGERPRINT AUTHENTICATION CLIENT");
    println!("{}", "=".repeat(70));

    // Parse CLI arguments
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() < 2 {
        print_help();
        return Ok(());
    }

    let mode = args[1].as_str();

    match mode {
        "register" => {
            if args.len() < 4 {
                eprintln!("❌ Usage: cargo run --release -- register <user_id> <image_path>");
                return Ok(());
            }
            let user_id = &args[2];
            let image_path = &args[3];
            handle_register(user_id, image_path)?;
        }
        "verify" => {
            if args.len() < 4 {
                eprintln!("❌ Usage: cargo run --release -- verify <user_id> <image_path>");
                return Ok(());
            }
            let user_id = &args[2];
            let image_path = &args[3];
            handle_verify(user_id, image_path)?;
        }
        "help" | _ => {
            print_help();
        }
    }

    Ok(())
}

// ==================== REGISTER MODE ====================

fn handle_register(user_id: &str, image_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n📝 REGISTER MODE");
    println!("{}", "─".repeat(70));
    println!("👤 User ID: {}", user_id);
    println!("🖼️  Image: {}", image_path);

    let client_key_path = get_client_key_path();
    if client_key_path.exists() {
        println!("🗑️  Removing old client key for testing...");
        fs::remove_file(&client_key_path)?;
    }

    // Setup directories
    fs::create_dir_all(EXCHANGE_DIR)?;
    fs::create_dir_all(DATA_DIR)?;

    // 1. Feature Extraction
    println!("\n🔬 FEATURE EXTRACTION:");
    println!("{}", "─".repeat(70));
    println!("📷 Extracting fingerprint features...");
    
    let fingerprint_bits = extract_fingerprint_128bit(image_path)?;
    
    if fingerprint_bits.len() != 512 {  // ⬅️
        return Err(format!("Expected 512 bits, got {}", fingerprint_bits.len()).into());
    }
    
    println!("✅ Extracted {} bits", fingerprint_bits.len());

    // 2. Generate Random Trivium Key/IV
    println!("\n🔑 TRIVIUM KEY GENERATION:");
    println!("{}", "─".repeat(70));
    
    use rand::Rng;
    let mut rng = rand::thread_rng();
    
    let key_u64: u64 = rng.gen();
    let iv_u64: u64 = rng.gen();
    
    let key_bits = u64_to_bits_80(key_u64);
    let iv_bits = u64_to_bits_80(iv_u64);
    
    println!("✅ Random key generated: 80 bits");
    println!("✅ Random IV generated: 80 bits");

    // 3. Trivium Encryption
    println!("\n🔐 TRIVIUM ENCRYPTION:");
    println!("{}", "─".repeat(70));
    
    let mut trivium = Trivium::new(&key_bits, &iv_bits);
    let ciphertext = trivium.process(&fingerprint_bits);
    
    println!("✅ Fingerprint encrypted: {} bits", ciphertext.len());

    // Sanity check
    let mut trivium2 = Trivium::new(&key_bits, &iv_bits);
    let decrypted_local = trivium2.process(&ciphertext);
    let errors = hamming_distance(&decrypted_local, &fingerprint_bits);
    
    if errors != 0 {
        return Err(format!("Trivium sanity check failed: {} errors", errors).into());
    }
    
    println!("✅ Trivium sanity check passed");

    // 4. FHE Key Management
    println!("\n🔐 FHE KEY MANAGEMENT:");
    println!("{}", "─".repeat(70));
    
    let client_key_path = get_client_key_path();
    let server_key_bytes_opt: Option<Vec<u8>>;

    let client_key = if client_key_path.exists() {
        println!("📂 Loading existing client key...");
        let key_bytes = fs::read(&client_key_path)?;
        let key = bincode::deserialize(&key_bytes)?;
        println!("✅ Client key loaded from: {}", client_key_path.display());
        server_key_bytes_opt = None; // Server key zaten var
        key
    } else {
        println!("🔑 Generating new FHE keys (first time)...");
        println!("⏱️  This may take ~10 seconds...");
        
        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = generate_keys(config);
        
        // Save client key
        fs::create_dir_all(client_key_path.parent().unwrap())?;
        let client_key_bytes = bincode::serialize(&client_key)?;
        fs::write(&client_key_path, client_key_bytes)?;
        println!("✅ Client key saved to: {}", client_key_path.display());
        
        // Prepare server key for sending
        let server_key_bytes = bincode::serialize(&server_key)?;
        server_key_bytes_opt = Some(server_key_bytes);
        println!("✅ Server key will be sent to server: ({} bytes)", 
                     server_key_bytes_opt.as_ref().unwrap().len());

        
        client_key
    };

    // 5. FHE Encryption (Key & IV)
    println!("\n🔒 FHE ENCRYPTION:");
    println!("{}", "─".repeat(70));
    println!("⏱️  Encrypting Trivium key and IV...");
    
    let encrypted_key: Vec<FheBool> = key_bits
        .iter()
        .map(|&b| FheBool::encrypt(b, &client_key))
        .collect();
    
    let encrypted_iv: Vec<FheBool> = iv_bits
        .iter()
        .map(|&b| FheBool::encrypt(b, &client_key))
        .collect();
    
    let encrypted_key_bytes = bincode::serialize(&encrypted_key)?;
    let encrypted_iv_bytes = bincode::serialize(&encrypted_iv)?;
    
    println!("✅ Encrypted key:  {} bytes", encrypted_key_bytes.len());
    println!("✅ Encrypted IV:   {} bytes", encrypted_iv_bytes.len());

    // 6. Build and Send Request
    println!("\n📤 SENDING REQUEST:");
    println!("{}", "─".repeat(70));

    // 🔍 DEBUG
    println!("🔍 Debug info:");
    println!("   user_id: {}", user_id);
    println!("   ciphertext: {} bits", ciphertext.len());
    println!("   encrypted_key_bytes: {} bytes", encrypted_key_bytes.len());
    println!("   encrypted_iv_bytes: {} bytes", encrypted_iv_bytes.len());
    println!("   server_key_bytes: {}", 
            if server_key_bytes_opt.is_some() { "Some(...)" } else { "None" });
    
    let request = RegisterRequest::new(
        user_id.to_string(),
        ciphertext,
        encrypted_key_bytes,
        encrypted_iv_bytes,
        server_key_bytes_opt,
    );
    
    // let req_json = serde_json::to_string_pretty(&request)?;  // ⬅️ YORUM SATIRI YAP
    // println!("\n📄 Request JSON:");
    // println!("{}", req_json);  // ⬅️ YORUM SATIRI YAP

    let req_json = serde_json::to_string_pretty(&request)?;
    fs::write(REGISTER_REQ_PATH, req_json)?;
    
    println!("✅ Request sent to server!");

    // 7. Wait for Response
    println!("\n⏳ WAITING FOR RESPONSE:");
    println!("{}", "─".repeat(70));
    
    let response: RegisterResponse = wait_for_response(REGISTER_RESP_PATH, Duration::from_secs(30))?;
    
    if response.success {
        println!("✅ REGISTRATION SUCCESSFUL!");
        println!("   User ID: {}", response.user_id);
        println!("   Message: {}", response.message);
        println!("   Timestamp: {}", response.timestamp);
    } else {
        println!("❌ REGISTRATION FAILED!");
        println!("   Message: {}", response.message);
    }

    // Cleanup
    let _ = fs::remove_file(REGISTER_RESP_PATH);

    Ok(())
}

// ==================== VERIFY MODE ====================

fn handle_verify(user_id: &str, image_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔍 VERIFY MODE");
    println!("{}", "─".repeat(70));
    println!("👤 User ID: {}", user_id);
    println!("🖼️  Image: {}", image_path);

    // Setup directories
    fs::create_dir_all(EXCHANGE_DIR)?;

    // 1. Feature Extraction
    println!("\n🔬 FEATURE EXTRACTION:");
    println!("{}", "─".repeat(70));
    println!("📷 Extracting probe fingerprint features...");
    
    let probe_bits = extract_fingerprint_128bit(image_path)?;
    
    if probe_bits.len() != 512 {  // ⬅️
        return Err(format!("Expected 512 bits, got {}", probe_bits.len()).into());
    }
    
    println!("✅ Extracted {} bits", probe_bits.len());

    // 2. Generate Random Trivium Key/IV (DIFFERENT from enrolled!)
    println!("\n🔑 TRIVIUM KEY GENERATION:");
    println!("{}", "─".repeat(70));
    
    use rand::Rng;
    let mut rng = rand::thread_rng();
    
    let key_u64: u64 = rng.gen();
    let iv_u64: u64 = rng.gen();
    
    let key_bits = u64_to_bits_80(key_u64);
    let iv_bits = u64_to_bits_80(iv_u64);
    
    println!("✅ Random key generated: 80 bits");
    println!("✅ Random IV generated: 80 bits");

    // 3. Trivium Encryption
    println!("\n🔐 TRIVIUM ENCRYPTION:");
    println!("{}", "─".repeat(70));
    
    let mut trivium = Trivium::new(&key_bits, &iv_bits);
    let ciphertext = trivium.process(&probe_bits);
    
    println!("✅ Probe encrypted: {} bits", ciphertext.len());

    // 4. Load Client Key
    println!("\n🔐 FHE KEY LOADING:");
    println!("{}", "─".repeat(70));
    
    let client_key_path = get_client_key_path();
    
    if !client_key_path.exists() {
        return Err("Client key not found! Please register first.".into());
    }
    
    let key_bytes = fs::read(&client_key_path)?;
    let client_key = bincode::deserialize(&key_bytes)?;
    
    println!("✅ Client key loaded from: {}", client_key_path.display());

    // 5. FHE Encryption
    println!("\n🔒 FHE ENCRYPTION:");
    println!("{}", "─".repeat(70));
    println!("⏱️  Encrypting Trivium key, IV, and constant...");
    
    let encrypted_key: Vec<FheBool> = key_bits
        .iter()
        .map(|&b| FheBool::encrypt(b, &client_key))
        .collect();
    
    let encrypted_iv: Vec<FheBool> = iv_bits
        .iter()
        .map(|&b| FheBool::encrypt(b, &client_key))
        .collect();
    
    let encrypted_true = FheBool::encrypt(true, &client_key);
    
    let encrypted_key_bytes = bincode::serialize(&encrypted_key)?;
    let encrypted_iv_bytes = bincode::serialize(&encrypted_iv)?;
    let encrypted_true_bytes = bincode::serialize(&encrypted_true)?;
    
    println!("✅ Encrypted key:  {} bytes", encrypted_key_bytes.len());
    println!("✅ Encrypted IV:   {} bytes", encrypted_iv_bytes.len());
    println!("✅ Encrypted true: {} bytes", encrypted_true_bytes.len());

    // 6. Build and Send Request
    println!("\n📤 SENDING REQUEST:");
    println!("{}", "─".repeat(70));
    
    let request = VerifyRequest::new(
        user_id.to_string(),
        ciphertext,
        encrypted_key_bytes,
        encrypted_iv_bytes,
        encrypted_true_bytes,
    );
    
    let req_json = serde_json::to_string_pretty(&request)?;
    fs::write(VERIFY_REQ_PATH, req_json)?;
    
    println!("✅ Request sent to server!");
    println!("⚠️  Server will perform FHE operations (~30-60 minutes)");

    // 7. Wait for Response
    println!("\n⏳ WAITING FOR RESPONSE:");
    println!("{}", "─".repeat(70));
    println!("This may take a very long time...");
    
    let response: VerifyResponse = wait_for_response(VERIFY_RESP_PATH, Duration::from_secs(7200))?; // 2 hours timeout
    
    if !response.success {
        println!("❌ VERIFICATION FAILED!");
        return Ok(());
    }

    // 8. Decrypt Results
    println!("\n🔓 DECRYPTING RESULTS:");
    println!("{}", "─".repeat(70));
    
    let encrypted_match: FheBool = bincode::deserialize(&response.encrypted_match_bytes)?;
    let encrypted_distance: Vec<FheBool> = bincode::deserialize(&response.encrypted_distance_bytes)?;
    
    let match_result: bool = encrypted_match.decrypt(&client_key);
    let distance_bits: Vec<bool> = encrypted_distance
        .iter()
        .map(|b| b.decrypt(&client_key))
        .collect();
    
    // Convert 9-bit binary to decimal
    let distance = bits_to_usize(&distance_bits);
    let similarity = 1.0 - (distance as f32 / 512.0);  // ⬅️
    
    // 9. Display Results
    println!("\n{}", "═".repeat(70));
    if match_result {
        println!("✅ AUTHENTICATION SUCCESSFUL!");
    } else {
        println!("❌ AUTHENTICATION FAILED!");
    }
    println!("{}", "═".repeat(70));
    println!("User ID:          {}", user_id);
    println!("Match Result:     {}", match_result);
    println!("Hamming Distance: {}/512 bits", distance);  // ⬅️
    println!("Similarity:       {:.2}%", similarity * 100.0);
    println!("Threshold:        70%");
    println!("Timestamp:        {}", response.timestamp);
    
    // Debug info (if available)
    if let Some(debug_match) = response.debug_server_match {
        println!("\n🚨 DEBUG INFO (Server-side):");
        println!("   Server Match:    {}", debug_match);
        if let Some(debug_dist) = response.debug_server_distance {
            println!("   Server Distance: {}/512", debug_dist);  // ⬅️
        }
    }
    
    println!("{}", "═".repeat(70));

    // Cleanup
    let _ = fs::remove_file(VERIFY_RESP_PATH);

    Ok(())
}

// ==================== HELPERS ====================

fn print_help() {
    println!(r#"
🔐 TRANSCIPHERING FINGERPRINT AUTHENTICATION CLIENT

USAGE:
  cargo run --release -- <MODE> <USER_ID> <IMAGE_PATH>

MODES:
  register   Register a new fingerprint template
  verify     Verify a fingerprint against enrolled template
  help       Show this help message

EXAMPLES:
  # Register a new user
  cargo run --release -- register user_123 ../data/fingerprints/101_1.tif

  # Verify user authentication
  cargo run --release -- verify user_123 ../data/fingerprints/101_2.tif

NOTES:
  - Client key is stored at: ~/.fingerprint_client/client_key.bin
  - Server key is sent only during first registration
  - Verification can take 30-60 minutes due to FHE operations
    "#);
}

fn get_client_key_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        let appdata = std::env::var("APPDATA").unwrap_or_else(|_| ".".to_string());
        Path::new(&appdata).join("fingerprint_client").join("client_key.bin")
    }
    
    #[cfg(not(target_os = "windows"))]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        Path::new(&home).join(".fingerprint_client").join("client_key.bin")
    }
}

fn wait_for_response<T: for<'de> serde::Deserialize<'de>>(
    path: &str,
    timeout: Duration,
) -> Result<T, Box<dyn std::error::Error>> {
    let start = Instant::now();
    let path = Path::new(path);
    
    loop {
        if path.exists() {
            // Wait a bit for file to be fully written
            std::thread::sleep(Duration::from_millis(200));
            
            let data = fs::read_to_string(path)?;
            
            match serde_json::from_str::<T>(&data) {
                Ok(response) => return Ok(response),
                Err(e) => {
                    // Retry once
                    std::thread::sleep(Duration::from_millis(200));
                    let data2 = fs::read_to_string(path)?;
                    let response2 = serde_json::from_str::<T>(&data2)
                        .map_err(|_| format!("Failed to parse response: {}", e))?;
                    return Ok(response2);
                }
            }
        }

        if start.elapsed() > timeout {
            return Err(format!("Timeout waiting for response ({}s)", timeout.as_secs()).into());
        }

        std::thread::sleep(Duration::from_millis(500));
    }
}

fn bits_to_usize(bits: &[bool]) -> usize {
    let mut result = 0;
    for (i, &bit) in bits.iter().enumerate() {
        if bit {
            result += 1 << i;
        }
    }
    result
}