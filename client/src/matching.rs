/// Calculate Hamming distance between two binary vectors
pub fn hamming_distance(bits1: &[bool], bits2: &[bool]) -> usize {
    assert_eq!(bits1.len(), bits2.len());
    
    bits1.iter()
        .zip(bits2.iter())
        .filter(|(a, b)| a != b)
        .count()
}

/// Match fingerprints based on Hamming distance
pub fn match_fingerprints(bits1: &[bool], bits2: &[bool], threshold: f32) -> bool {
    let distance = hamming_distance(bits1, bits2);
    let similarity = 1.0 - (distance as f32 / bits1.len() as f32);
    similarity >= threshold
}