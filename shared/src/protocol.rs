use serde::{Serialize, Deserialize};

/// Client → Server: Authentication request
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthRequest {
    /// Trivium ciphertext (128 bits)
    pub ciphertext: Vec<bool>,
    
    /// FHE-encrypted Trivium key (80 bits as bytes)
    pub encrypted_key_bytes: Vec<u8>,
    
    /// FHE-encrypted Trivium IV (80 bits as bytes)
    pub encrypted_iv_bytes: Vec<u8>,
    
    /// FHE-encrypted true fingerprint (for comparison, 128 bits as bytes)
    pub encrypted_true_bytes: Vec<u8>,
    
    /// User ID (for enrolled template lookup)
    pub user_id: String,
}

/// Server → Client: Authentication response
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthResponse {
    /// FHE-encrypted decrypted fingerprint (128 bits as bytes) - for debug
    pub encrypted_result: Vec<u8>,
    
    /// Server-side matching result (plaintext) - for debug only
    pub server_match: Option<bool>,
    
    /// Hamming distance (plaintext) - for debug only
    pub distance: Option<usize>,
    
    /// ✅ Best-practice: encrypted matching result (bincode(FheBool))
    pub encrypted_match_bytes: Option<Vec<u8>>,
    
    /// ✅ Best-practice: encrypted hamming distance (bincode(Vec<FheBool>) 8-bit counter)
    pub encrypted_distance_bytes: Option<Vec<u8>>,
}

impl AuthRequest {
    pub fn new(
        ciphertext: Vec<bool>,
        encrypted_key_bytes: Vec<u8>,
        encrypted_iv_bytes: Vec<u8>,
        encrypted_true_bytes: Vec<u8>,
        user_id: String,
    ) -> Self {
        Self {
            ciphertext,
            encrypted_key_bytes,
            encrypted_iv_bytes,
            encrypted_true_bytes,
            user_id,
        }
    }
}

impl AuthResponse {
    pub fn new(encrypted_result: Vec<u8>) -> Self {
        Self {
            encrypted_result,
            server_match: None,
            distance: None,
            encrypted_match_bytes: None,
            encrypted_distance_bytes: None,
        }
    }
    
    pub fn with_encrypted_match(
        mut self,
        encrypted_match_bytes: Vec<u8>,
        encrypted_distance_bytes: Vec<u8>,
    ) -> Self {
        self.encrypted_match_bytes = Some(encrypted_match_bytes);
        self.encrypted_distance_bytes = Some(encrypted_distance_bytes);
        self
    }
    pub fn with_match(mut self, matched: bool, distance: usize) -> Self {
        self.server_match = Some(matched);
        self.distance = Some(distance);
        self
    }
}