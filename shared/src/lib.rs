pub mod trivium;
pub mod trivium_fhe;
pub mod protocol;

// Re-exports
pub use trivium::{Trivium, u64_to_bits_80};
pub use trivium_fhe::decrypt_homomorphic;
pub use protocol::{AuthRequest, AuthResponse};
