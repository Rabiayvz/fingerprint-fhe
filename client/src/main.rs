use client::feature_extraction::extract_fingerprint_128bit;
use client::matching::hamming_distance;

use shared::{
    RegisterRequest, RegisterResponse,
    VerifyRequest, VerifyResponse,
    Request, Response,
    Trivium, u64_to_bits_80,
    read_message, write_message, SERVER_ADDR,
};

use tfhe::prelude::*;
use tfhe::{generate_keys, ConfigBuilder, FheBool};
use tracing::{error, info, warn};

use std::fs;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

const DATA_DIR: &str = "../data";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

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
                eprintln!("Usage: cargo run --release -- register <user_id> <image_path>");
                return Ok(());
            }
            let user_id = &args[2];
            let image_path = &args[3];
            handle_register(user_id, image_path)?;
        }
        "verify" => {
            if args.len() < 4 {
                eprintln!("Usage: cargo run --release -- verify <user_id> <image_path>");
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
    info!(user_id, image_path, "register mode");

    // Setup directories
    fs::create_dir_all(DATA_DIR)?;

    // 1. Feature Extraction
    info!("extracting fingerprint features");

    let fingerprint_bits = extract_fingerprint_128bit(image_path)?;

    if fingerprint_bits.len() != 512 {
        return Err(format!("Expected 512 bits, got {}", fingerprint_bits.len()).into());
    }

    info!(bits = fingerprint_bits.len(), "features extracted");

    // 2. Generate Random Trivium Key/IV
    use rand::Rng;
    let mut rng = rand::thread_rng();

    let key_u64: u64 = rng.gen();
    let iv_u64: u64 = rng.gen();

    let key_bits = u64_to_bits_80(key_u64);
    let iv_bits = u64_to_bits_80(iv_u64);

    info!("generated random 80-bit Trivium key and IV");

    // 3. Trivium Encryption
    let mut trivium = Trivium::new(&key_bits, &iv_bits);
    let ciphertext = trivium.process(&fingerprint_bits);

    info!(bits = ciphertext.len(), "fingerprint encrypted with Trivium");

    // Sanity check
    let mut trivium2 = Trivium::new(&key_bits, &iv_bits);
    let decrypted_local = trivium2.process(&ciphertext);
    let errors = hamming_distance(&decrypted_local, &fingerprint_bits);

    if errors != 0 {
        return Err(format!("Trivium sanity check failed: {} errors", errors).into());
    }

    info!("Trivium sanity check passed");

    // 4. FHE Key Management
    let client_key_path = get_client_key_path();
    let server_key_bytes_opt: Option<Vec<u8>>;

    let client_key = if client_key_path.exists() {
        info!(path = %client_key_path.display(), "loading existing client key");
        let key_bytes = fs::read(&client_key_path)?;
        let key = bincode::deserialize(&key_bytes)?;
        server_key_bytes_opt = None; // Server key zaten var
        key
    } else {
        info!("generating new FHE keys (first time, may take ~10s)");

        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = generate_keys(config);

        // Save client key
        fs::create_dir_all(client_key_path.parent().unwrap())?;
        let client_key_bytes = bincode::serialize(&client_key)?;
        fs::write(&client_key_path, client_key_bytes)?;
        info!(path = %client_key_path.display(), "client key saved");

        // Prepare server key for sending
        let server_key_bytes = bincode::serialize(&server_key)?;
        server_key_bytes_opt = Some(server_key_bytes);
        info!(
            bytes = server_key_bytes_opt.as_ref().unwrap().len(),
            "server key will be sent to server"
        );

        client_key
    };

    // 5. FHE Encryption (Key & IV + TRUE CONSTANT)
    info!("encrypting Trivium key, IV, and constant under FHE");

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

    info!(
        encrypted_key_bytes = encrypted_key_bytes.len(),
        encrypted_iv_bytes = encrypted_iv_bytes.len(),
        encrypted_true_bytes = encrypted_true_bytes.len(),
        "FHE encryption complete"
    );

    // 6. Build and Send Request
    let request = RegisterRequest::new(
        user_id.to_string(),
        ciphertext,
        encrypted_key_bytes,
        encrypted_iv_bytes,
        encrypted_true_bytes,
        server_key_bytes_opt,
    );

    info!("sending register request to server");

    let response: RegisterResponse = match send_request(
        &Request::Register(request),
        Duration::from_secs(3600),
    )? {
        Response::Register(r) => r,
        Response::Verify(_) => return Err("Unexpected Verify response to Register request".into()),
    };

    if response.success {
        println!("REGISTRATION SUCCESSFUL");
        println!("  User ID:   {}", response.user_id);
        println!("  Message:   {}", response.message);
        println!("  Timestamp: {}", response.timestamp);
    } else {
        error!(message = %response.message, "registration failed");
        println!("REGISTRATION FAILED: {}", response.message);
    }

    Ok(())
}

// ==================== VERIFY MODE ====================

fn handle_verify(user_id: &str, image_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    info!(user_id, image_path, "verify mode");

    // 1. Feature Extraction
    info!("extracting probe fingerprint features");

    let probe_bits = extract_fingerprint_128bit(image_path)?;

    if probe_bits.len() != 512 {
        return Err(format!("Expected 512 bits, got {}", probe_bits.len()).into());
    }

    info!(bits = probe_bits.len(), "features extracted");

    // 2. Generate Random Trivium Key/IV (DIFFERENT from enrolled!)
    use rand::Rng;
    let mut rng = rand::thread_rng();

    let key_u64: u64 = rng.gen();
    let iv_u64: u64 = rng.gen();

    let key_bits = u64_to_bits_80(key_u64);
    let iv_bits = u64_to_bits_80(iv_u64);

    info!("generated random 80-bit Trivium key and IV");

    // 3. Trivium Encryption
    let mut trivium = Trivium::new(&key_bits, &iv_bits);
    let ciphertext = trivium.process(&probe_bits);

    info!(bits = ciphertext.len(), "probe encrypted with Trivium");

    // 4. Load Client Key
    let client_key_path = get_client_key_path();

    if !client_key_path.exists() {
        return Err("Client key not found! Please register first.".into());
    }

    let key_bytes = fs::read(&client_key_path)?;
    let client_key = bincode::deserialize(&key_bytes)?;

    info!(path = %client_key_path.display(), "client key loaded");

    // 5. FHE Encryption
    info!("encrypting Trivium key, IV, and constant under FHE");

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

    info!(
        encrypted_key_bytes = encrypted_key_bytes.len(),
        encrypted_iv_bytes = encrypted_iv_bytes.len(),
        encrypted_true_bytes = encrypted_true_bytes.len(),
        "FHE encryption complete"
    );

    // 6. Build and Send Request
    let request = VerifyRequest::new(
        user_id.to_string(),
        ciphertext,
        encrypted_key_bytes,
        encrypted_iv_bytes,
        encrypted_true_bytes,
    );

    warn!("waiting for server response, this may take a very long time");

    // 7. Send request and wait for response
    let response: VerifyResponse = match send_request(
        &Request::Verify(request),
        Duration::from_secs(7200),
    )? {
        Response::Verify(r) => r,
        Response::Register(_) => return Err("Unexpected Register response to Verify request".into()),
    };

    if !response.success {
        error!(message = %response.message, "verification failed");
        println!("VERIFICATION FAILED: {}", response.message);
        return Ok(());
    }

    // 8. Decrypt Results
    info!("decrypting results with client key");

    let encrypted_match: FheBool = bincode::deserialize(&response.encrypted_match_bytes)?;
    let encrypted_distance: Vec<FheBool> = bincode::deserialize(&response.encrypted_distance_bytes)?;

    let match_result: bool = encrypted_match.decrypt(&client_key);
    let distance_bits: Vec<bool> = encrypted_distance
        .iter()
        .map(|b| b.decrypt(&client_key))
        .collect();

    let distance = bits_to_usize(&distance_bits);
    let similarity = 1.0 - (distance as f32 / 512.0);

    // 9. Display Results
    println!("{}", "=".repeat(70));
    if match_result {
        println!("AUTHENTICATION SUCCESSFUL");
    } else {
        println!("AUTHENTICATION FAILED");
    }
    println!("{}", "=".repeat(70));
    println!("User ID:          {}", user_id);
    println!("Match Result:     {}", match_result);
    println!("Hamming Distance: {}/512 bits", distance);
    println!("Similarity:       {:.2}%", similarity * 100.0);
    println!("Threshold:        62%");
    println!("Timestamp:        {}", response.timestamp);
    println!("{}", "=".repeat(70));

    Ok(())
}

// ==================== HELPERS ====================

fn print_help() {
    println!(r#"
TRANSCIPHERING FINGERPRINT AUTHENTICATION CLIENT

USAGE:
  cargo run --release -- <MODE> <USER_ID> <IMAGE_PATH>

MODES:
  register   Register a new fingerprint template
  verify     Verify a fingerprint against enrolled template
  help       Show this help message

EXAMPLES:
  cargo run --release -- register user_123 ../data/fingerprints/101_1.tif
  cargo run --release -- verify user_123 ../data/fingerprints/101_2.tif

NOTES:
  - Client key is stored at: ~/.fingerprint_client/client_key.bin
  - Server key is sent only during first registration
  - Server must be running (`cargo run --release` in ../server) and
    reachable at {SERVER_ADDR}
  - Set RUST_LOG=info (or debug) to see progress logs
"#, SERVER_ADDR = SERVER_ADDR);
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

fn send_request(request: &Request, timeout: Duration) -> Result<Response, Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect(SERVER_ADDR)
        .map_err(|e| format!("Failed to connect to server at {}: {}", SERVER_ADDR, e))?;
    stream.set_read_timeout(Some(timeout))?;

    write_message(&mut stream, request)?;
    read_message(&mut stream)
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
