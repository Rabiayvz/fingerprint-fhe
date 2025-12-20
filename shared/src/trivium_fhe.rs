// shared/src/trivium_fhe.rs

use tfhe::prelude::*;
use tfhe::{set_server_key, FheBool, ServerKey};

/// Trivium stream cipher state under FHE (288 bits).
///
/// Layout (per Trivium spec):
/// - Register 1: state[0..=92]   (93 bits)
/// - Register 2: state[93..=176] (84 bits)
/// - Register 3: state[177..=287](111 bits)
pub struct TriviumFhe {
    state: Vec<FheBool>, // length 288
}

impl TriviumFhe {
    /// Create a new FHE-Trivium instance with encrypted key/iv.
    ///
    /// `encrypted_true` is required to build homomorphic constants:
    /// - false := true XOR true
    /// - true  := encrypted_true.clone()
    pub fn new(
        encrypted_key: &[FheBool],  // 80 bits
        encrypted_iv: &[FheBool],   // 80 bits
        encrypted_true: &FheBool,
        server_key: &ServerKey,
    ) -> Self {
        assert_eq!(encrypted_key.len(), 80, "Key must be 80 bits");
        assert_eq!(encrypted_iv.len(), 80, "IV must be 80 bits");

        // Ensure server key is set for all homomorphic operations.
        set_server_key(server_key.clone());

        println!("   🔧 Initializing Trivium state (288 bits)...");

        // Homomorphic constants derived from encrypted_true
        let fhe_true = encrypted_true.clone();
        let fhe_false = encrypted_true ^ encrypted_true; // 1 XOR 1 = 0

        let mut state: Vec<FheBool> = Vec::with_capacity(288);

        // state[0..79] = key (80)
        for i in 0..80 {
            state.push(encrypted_key[i].clone());
        }

        // state[80..92] = 13 zeros
        for _ in 0..13 {
            state.push(fhe_false.clone());
        }

        // state[93..172] = iv (80)
        for i in 0..80 {
            state.push(encrypted_iv[i].clone());
        }

        // state[173..176] = 4 zeros
        for _ in 0..4 {
            state.push(fhe_false.clone());
        }

        // state[177..284] = 108 zeros
        for _ in 0..108 {
            state.push(fhe_false.clone());
        }

        // state[285..287] = 1,1,1
        state.push(fhe_true.clone());
        state.push(fhe_true.clone());
        state.push(fhe_true.clone());

        assert_eq!(state.len(), 288, "State must be 288 bits!");

        let mut trivium = TriviumFhe { state };

        // Warmup: 1152 cycles (discard output)
        println!("   ⏳ Warmup phase (1152 cycles)...");
        for i in 0..1152 {
            if i % 192 == 0 && i != 0 {
                println!("      Progress: {}/1152", i);
            }
            let _ = trivium.clock();
        }
        println!("   ✅ Warmup complete!");

        trivium
    }

    /// Shift a register range [start..=end] right by 1 within that range, inserting `new_bit` at `start`.
    ///
    /// Example: for i=end..start+1: state[i] = state[i-1]; state[start] = new_bit.
    fn shift_register(&mut self, start: usize, end: usize, new_bit: FheBool) {
        for i in (start + 1..=end).rev() {
            self.state[i] = self.state[i - 1].clone();
        }
        self.state[start] = new_bit;
    }

    /// One Trivium clock: produces 1 keystream bit (under FHE) and updates internal state.
    ///
    /// Taps per Trivium spec:
    /// t1 = s66  XOR s93
    /// t2 = s162 XOR s177
    /// t3 = s243 XOR s288
    /// z  = t1 XOR t2 XOR t3
    ///
    /// s1 = t1 XOR (s91 AND s92) XOR s171
    /// s2 = t2 XOR (s175 AND s176) XOR s264
    /// s3 = t3 XOR (s286 AND s287) XOR s69
    ///
    /// Then shift:
    /// reg1 in <= s3, reg2 in <= s1, reg3 in <= s2
    fn clock(&mut self) -> FheBool {
        // Compute t1/t2/t3
        let t1 = &self.state[65] ^ &self.state[92];
        let t2 = &self.state[161] ^ &self.state[176];
        let t3 = &self.state[242] ^ &self.state[287];

        // Output bit
        let output = &t1 ^ &t2 ^ &t3;

        // Feedback values
        let s1 = &t1 ^ &(&self.state[90] & &self.state[91]) ^ &self.state[170];
        let s2 = &t2 ^ &(&self.state[174] & &self.state[175]) ^ &self.state[263];
        let s3 = &t3 ^ &(&self.state[285] & &self.state[286]) ^ &self.state[68];

        // IMPORTANT: do NOT rotate the whole 288-bit state.
        // Shift each register separately.
        self.shift_register(0, 92, s3);
        self.shift_register(93, 176, s1);
        self.shift_register(177, 287, s2);

        output
    }

    /// Generate `n` keystream bits under FHE.
    pub fn keystream(&mut self, n: usize) -> Vec<FheBool> {
        println!("   🔑 Generating {} keystream bits...", n);
        (0..n).map(|_| self.clock()).collect()
    }
}

/// Homomorphic Trivium decryption:
/// plaintext = ciphertext XOR keystream
///
/// `ciphertext` is in clear (Vec<bool>), but `keystream` is FHE.
/// So we implement XOR using `encrypted_true` as the only constant input:
/// - if c=0 => p = k
/// - if c=1 => p = k XOR 1 = NOT k
pub fn decrypt_homomorphic(
    ciphertext: &[bool],
    encrypted_key: &[FheBool],
    encrypted_iv: &[FheBool],
    encrypted_true: &FheBool,
    server_key: &ServerKey,
) -> Vec<FheBool> {
    println!("\n🔓 Homomorphic Trivium Decryption:");

    let mut trivium = TriviumFhe::new(encrypted_key, encrypted_iv, encrypted_true, server_key);
    let keystream = trivium.keystream(ciphertext.len());

    println!("   ⚙️  XORing ciphertext with keystream...");
    let plaintext: Vec<FheBool> = ciphertext
        .iter()
        .zip(keystream.iter())
        .map(|(&c_bit, k_bit)| {
            if c_bit {
                // k XOR 1 = NOT k
                k_bit ^ encrypted_true
            } else {
                k_bit.clone()
            }
        })
        .collect();

    println!("   ✅ Decryption complete!");
    plaintext
}
