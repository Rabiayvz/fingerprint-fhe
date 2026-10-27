/// Calculate Hamming distance between two binary vectors
pub fn hamming_distance(bits1: &[bool], bits2: &[bool]) -> usize {
    assert_eq!(bits1.len(), bits2.len());
    
    bits1.iter()
        .zip(bits2.iter())
        .filter(|(a, b)| a != b)
        .count()
}
