pub mod trivium;
pub mod trivium_fhe;
pub mod protocol;
pub mod matching_fhe;
pub mod net;

// Re-exports
pub use trivium::{Trivium, u64_to_bits_80};
pub use trivium_fhe::decrypt_homomorphic;
pub use matching_fhe::{
    diff_bits,
    popcount_128,
    popcount_256,
    popcount_512,
    popcount_1024,
    leq_constant,
};
pub use protocol::{
    RegisterRequest, RegisterResponse,
    VerifyRequest, VerifyResponse,
    Request, Response,
};
pub use net::{read_message, write_message, SERVER_ADDR};