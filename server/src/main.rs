mod database;

use database::{Database, TemplateEntry};
use shared::{
    read_message, write_message,
    Request, Response,
    RegisterRequest, RegisterResponse,
    VerifyRequest, VerifyResponse,
    decrypt_homomorphic,
    diff_bits, popcount_512, leq_constant,
    SERVER_ADDR,
};

use tfhe::{set_server_key, ServerKey, FheBool};
use tracing::{error, info, warn};

use std::fs;
use std::net::{TcpListener, TcpStream};
use std::path::Path;

const SERVER_KEY_PATH: &str = "../database/server_key.bin";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    fs::create_dir_all("../database")?;

    let listener = TcpListener::bind(SERVER_ADDR)?;
    info!(addr = SERVER_ADDR, "listening");

    for incoming in listener.incoming() {
        let mut stream = match incoming {
            Ok(s) => s,
            Err(e) => {
                error!(error = %e, "connection failed");
                continue;
            }
        };

        if let Err(e) = handle_connection(&mut stream) {
            error!(error = %e, "connection error");
        }

        info!("waiting for next request");
    }

    Ok(())
}

// ==================== CONNECTION DISPATCH ====================

fn handle_connection(stream: &mut TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let request: Request = read_message(stream)?;

    match request {
        Request::Register(req) => {
            info!("register request received");
            let resp = process_register(req);
            write_message(stream, &Response::Register(resp))?;
            info!("register handled, response sent");
        }
        Request::Verify(req) => {
            info!("verify request received");
            let resp = process_verify(req);
            write_message(stream, &Response::Verify(resp))?;
            info!("verify handled, response sent");
        }
    }

    Ok(())
}

// ==================== INTERNAL HELPERS ====================

fn load_or_init_db_with_recovery() -> Result<Database, Box<dyn std::error::Error>> {
    match Database::load() {
        Ok(db) => Ok(db),
        Err(e) => {
            error!(error = %e, "database load failed, creating fresh database");

            if Path::new("../database/templates.json").exists() {
                let backup_path = format!(
                    "../database/templates.json.backup.{}",
                    chrono::Utc::now().timestamp()
                );
                let _ = fs::rename("../database/templates.json", &backup_path);
                warn!(backup_path, "corrupt database backed up");
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
// - Transcipher once at register
// - Store encrypted plaintext template in DB
fn process_register(req: RegisterRequest) -> RegisterResponse {
    match process_register_inner(&req) {
        Ok(resp) => resp,
        Err(e) => {
            error!(error = %e, "register failed");
            RegisterResponse::error(req.user_id, e.to_string())
        }
    }
}

fn process_register_inner(
    req: &RegisterRequest,
) -> Result<RegisterResponse, Box<dyn std::error::Error>> {
    info!(user_id = %req.user_id, ciphertext_bits = req.ciphertext.len(), "processing register");

    // 1) Save server key if provided (first registration)
    if let Some(ref server_key_bytes) = req.server_key_bytes {
        info!("saving server key (first registration)");
        fs::write(SERVER_KEY_PATH, server_key_bytes)?;
    } else if !Path::new(SERVER_KEY_PATH).exists() {
        return Err("Server key not found and not provided in request!".into());
    }

    // 2) Load server key and set global
    let server_key = load_server_key_from_disk()?;
    set_server_key(server_key.clone());

    // 3) Load DB (with recovery)
    let mut db = load_or_init_db_with_recovery()?;

    // 4) Check if user exists
    if db.exists(&req.user_id) {
        info!(user_id = %req.user_id, "user already exists, updating");
    }

    // 5) Deserialize FHE key/iv/true
    let encrypted_key: Vec<FheBool> = bincode::deserialize(&req.encrypted_key_bytes)?;
    let encrypted_iv: Vec<FheBool> = bincode::deserialize(&req.encrypted_iv_bytes)?;
    let encrypted_true: FheBool = bincode::deserialize(&req.encrypted_true_bytes)?;

    // 6) Transcipher once (enrolled)
    info!("FHE-Trivium decrypting enrolled fingerprint (one-time at register, may take time)");

    let plaintext_enrolled_fhe: Vec<FheBool> = decrypt_homomorphic(
        &req.ciphertext,
        &encrypted_key,
        &encrypted_iv,
        &encrypted_true,
        &server_key,
    );

    info!(bits = plaintext_enrolled_fhe.len(), "enrolled template decrypted under FHE");

    // 7) Serialize and store in DB
    let encrypted_template_bytes = bincode::serialize(&plaintext_enrolled_fhe)?;
    let entry = TemplateEntry::new(req.user_id.clone(), encrypted_template_bytes);
    db.insert(entry);

    db.save()?;
    info!(total_templates = db.templates.len(), "encrypted template saved to database");

    Ok(RegisterResponse::success(req.user_id.clone()))
}

// ==================== VERIFY HANDLER ====================
// - Enrolled template is already encrypted plaintext in DB
// - Only decrypt probe, then match
fn process_verify(req: VerifyRequest) -> VerifyResponse {
    match process_verify_inner(&req) {
        Ok(resp) => resp,
        Err(e) => {
            error!(error = %e, "verify failed");
            VerifyResponse::error(e.to_string())
        }
    }
}

fn process_verify_inner(req: &VerifyRequest) -> Result<VerifyResponse, Box<dyn std::error::Error>> {
    info!(user_id = %req.user_id, probe_bits = req.ciphertext.len(), "processing verify");

    // 1) Load server key and set global
    let server_key = load_server_key_from_disk()?;
    set_server_key(server_key.clone());

    // 2) Load DB & find enrolled template
    let db = Database::load()?;
    let enrolled = db
        .get(&req.user_id)
        .ok_or_else(|| format!("User '{}' not found in database", req.user_id))?;

    info!(created_at = %enrolled.created_at, "enrolled template found");

    // 3) Deserialize enrolled encrypted plaintext template
    let plaintext_enrolled_fhe: Vec<FheBool> = bincode::deserialize(&enrolled.encrypted_template_bytes)?;

    // 4) Deserialize probe FHE data
    let encrypted_key_probe: Vec<FheBool> = bincode::deserialize(&req.encrypted_key_bytes)?;
    let encrypted_iv_probe: Vec<FheBool> = bincode::deserialize(&req.encrypted_iv_bytes)?;
    let encrypted_true: FheBool = bincode::deserialize(&req.encrypted_true_bytes)?;

    // 5) Decrypt probe only
    info!("FHE-Trivium decrypting probe fingerprint (only decrypt done during verify)");

    let plaintext_probe_fhe: Vec<FheBool> = decrypt_homomorphic(
        &req.ciphertext,
        &encrypted_key_probe,
        &encrypted_iv_probe,
        &encrypted_true,
        &server_key,
    );

    // 6) FHE Matching
    info!("computing FHE Hamming distance and threshold comparison");

    let diff = diff_bits(&plaintext_enrolled_fhe, &plaintext_probe_fhe);
    let distance_fhe = popcount_512(&diff, &encrypted_true);

    let threshold = (512.0 * 0.38) as usize;
    let match_result_fhe = leq_constant(&distance_fhe, threshold, &encrypted_true);

    info!(threshold_bits = threshold, "threshold comparison done");

    // 7) Serialize response payload
    let encrypted_match_bytes = bincode::serialize(&match_result_fhe)?;
    let encrypted_distance_bytes = bincode::serialize(&distance_fhe)?;

    info!(
        match_bytes = encrypted_match_bytes.len(),
        distance_bytes = encrypted_distance_bytes.len(),
        "results serialized"
    );

    Ok(VerifyResponse::success(encrypted_match_bytes, encrypted_distance_bytes))
}
