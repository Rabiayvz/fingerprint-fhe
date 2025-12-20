pub struct Trivium {
    state: Vec<bool>,
}

impl Trivium {
    pub fn new(key: &[bool], iv: &[bool]) -> Self {
        assert_eq!(key.len(), 80);
        assert_eq!(iv.len(), 80);
        
        let mut state = vec![false; 288];
        
        // CORRECT INITIALIZATION:
        
        // Bits 0-79: Key
        state[0..80].copy_from_slice(key);
        
        // Bits 80-92: False (already initialized)
        
        // Bits 93-172: IV
        state[93..173].copy_from_slice(iv);
        
        // Bits 173-284: False (already initialized)
        
        // Bits 285-287: True (per spec!)
        state[285] = true;
        state[286] = true;
        state[287] = true;
        
        let mut trivium = Trivium { state };
        
        // Warmup: 1152 cycles (4 × 288)
        for _ in 0..1152 {
            trivium.clock();
        }
        
        trivium
    }
    
    fn clock(&mut self) -> bool {
    // Extract bits for output
    let t1 = self.state[65] ^ self.state[92];
    let t2 = self.state[161] ^ self.state[176];
    let t3 = self.state[242] ^ self.state[287];
    
    // Output bit (computed BEFORE state update)
    let output = t1 ^ t2 ^ t3;
    
    // Feedback bits (computed from CURRENT state)
    let s1 = t1 ^ (self.state[90] & self.state[91]) ^ self.state[170];
    let s2 = t2 ^ (self.state[174] & self.state[175]) ^ self.state[263];
    let s3 = t3 ^ (self.state[285] & self.state[286]) ^ self.state[68];
    
    // NOW update state (AFTER computing output and feedback)
    self.state.rotate_right(1);
    self.state[0] = s3;
    self.state[93] = s1;
    self.state[177] = s2;
    
    output
    }
    
    pub fn process(&mut self, data: &[bool]) -> Vec<bool> {
        data.iter()
            .map(|&bit| bit ^ self.clock())
            .collect()
    }
}

// Helper function
pub fn u64_to_bits_80(value: u64) -> Vec<bool> {
    let mut bits = vec![false; 80];
    for i in 0..64 {
        bits[i] = ((value >> i) & 1) == 1;
    }
    bits
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_trivium_basic() {
        let key = vec![false; 80];
        let iv = vec![false; 80];
        
        let mut trivium = Trivium::new(&key, &iv);
        
        // Test data
        let plaintext = vec![true, false, true, false];
        let ciphertext = trivium.process(&plaintext);
        
        // Decrypt
        let mut trivium2 = Trivium::new(&key, &iv);
        let decrypted = trivium2.process(&ciphertext);
        
        assert_eq!(plaintext, decrypted, "Trivium encryption/decryption mismatch!");
    }
}