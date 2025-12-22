use serde::{Serialize, Deserialize};

// ==================== REGISTER ENDPOINT ====================

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RegisterRequest {
    pub user_id: String,
    pub ciphertext: Vec<bool>,              // 128 bits - Trivium encrypted
    pub encrypted_key_bytes: Vec<u8>,       // FHE encrypted Trivium key (80 bits)
    pub encrypted_iv_bytes: Vec<u8>,        // FHE encrypted Trivium IV (80 bits)
    pub server_key_bytes: Option<Vec<u8>>,  // İlk kayıtta gönderilir
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RegisterResponse {
    pub success: bool,
    pub message: String,
    pub user_id: String,
    pub timestamp: String,
}

impl RegisterRequest {
    pub fn new(
        user_id: String,
        ciphertext: Vec<bool>,
        encrypted_key_bytes: Vec<u8>,
        encrypted_iv_bytes: Vec<u8>,
        server_key_bytes: Option<Vec<u8>>,
    ) -> Self {
        Self {
            user_id,
            ciphertext,
            encrypted_key_bytes,
            encrypted_iv_bytes,
            server_key_bytes,
        }
    }
}

impl RegisterResponse {
    pub fn success(user_id: String) -> Self {
        Self {
            success: true,
            message: "Fingerprint registered successfully".to_string(),
            user_id,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    pub fn error(user_id: String, message: String) -> Self {
        Self {
            success: false,
            message,
            user_id,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }
}

// ==================== VERIFY ENDPOINT ====================

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VerifyRequest {
    pub user_id: String,
    pub ciphertext: Vec<bool>,              // 128 bits - Trivium encrypted (probe)
    pub encrypted_key_bytes: Vec<u8>,       // FHE encrypted Trivium key (probe)
    pub encrypted_iv_bytes: Vec<u8>,        // FHE encrypted Trivium IV (probe)
    pub encrypted_true_bytes: Vec<u8>,      // FHE encrypted true constant
}

#[derive(Serialize, Deserialize, Debug)]
pub struct VerifyResponse {
    pub success: bool,
    pub encrypted_match_bytes: Vec<u8>,     // FheBool serialized
    pub encrypted_distance_bytes: Vec<u8>,  // Vec<FheBool>[8] serialized
    pub timestamp: String,
    
    // 🚫 DEBUG ONLY - production'da None olacak
    pub debug_server_match: Option<bool>,
    pub debug_server_distance: Option<usize>,
}

impl VerifyRequest {
    pub fn new(
        user_id: String,
        ciphertext: Vec<bool>,
        encrypted_key_bytes: Vec<u8>,
        encrypted_iv_bytes: Vec<u8>,
        encrypted_true_bytes: Vec<u8>,
    ) -> Self {
        Self {
            user_id,
            ciphertext,
            encrypted_key_bytes,
            encrypted_iv_bytes,
            encrypted_true_bytes,
        }
    }
}

impl VerifyResponse {
    pub fn success(
        encrypted_match_bytes: Vec<u8>,
        encrypted_distance_bytes: Vec<u8>,
    ) -> Self {
        Self {
            success: true,
            encrypted_match_bytes,
            encrypted_distance_bytes,
            timestamp: chrono::Utc::now().to_rfc3339(),
            debug_server_match: None,
            debug_server_distance: None,
        }
    }

    pub fn with_debug(mut self, match_result: bool, distance: usize) -> Self {
        self.debug_server_match = Some(match_result);
        self.debug_server_distance = Some(distance);
        self
    }

    pub fn error(message: String) -> Self {
        Self {
            success: false,
            encrypted_match_bytes: vec![],
            encrypted_distance_bytes: vec![],
            timestamp: chrono::Utc::now().to_rfc3339(),
            debug_server_match: None,
            debug_server_distance: None,
        }
    }
}

// ==================== LEGACY (BACKWARD COMPATIBILITY) ====================

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthRequest {
    pub ciphertext: Vec<bool>,
    pub encrypted_key_bytes: Vec<u8>,
    pub encrypted_iv_bytes: Vec<u8>,
    pub encrypted_true_bytes: Vec<u8>,
    pub user_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthResponse {
    pub encrypted_result: Vec<u8>,
    pub server_match: Option<bool>,
    pub distance: Option<usize>,
    pub encrypted_match_bytes: Option<Vec<u8>>,
    pub encrypted_distance_bytes: Option<Vec<u8>>,
}