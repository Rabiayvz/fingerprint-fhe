pub mod trivium;
pub mod trivium_fhe;
pub mod protocol;
pub mod matching_fhe;

// Re-exports
pub use trivium::{Trivium, u64_to_bits_80};
pub use trivium_fhe::decrypt_homomorphic;
pub use matching_fhe::{diff_bits, popcount_128, leq_constant};
pub use protocol::{
    RegisterRequest, RegisterResponse,
    VerifyRequest, VerifyResponse,
    // Legacy
    AuthRequest, AuthResponse,
};