use image::{GrayImage, ImageError};

/// 128-bit binary grid feature extraction
/// Resize: 16×8 = 128 pixels → 128 bits
pub fn extract_fingerprint_128bit(image_path: &str) -> Result<Vec<bool>, ImageError> {
    // 1. Read grayscale image
    let img = image::open(image_path)?.to_luma8();
    
    // 2. Resize to 16×8 (128 pixels)
    let resized = image::imageops::resize(
        &img,
        16,  // width
        8,   // height
        image::imageops::FilterType::Lanczos3
    );
    
    // 3. Threshold at 128 (middle of 0-255)
    // Dark pixels (ridges) → true, Light pixels (background) → false
    let mut bits = Vec::with_capacity(128);
    for pixel in resized.pixels() {
        let val = pixel[0];
        bits.push(val < 128);  // Invert: dark = 1, light = 0
    }
    
    assert_eq!(bits.len(), 128, "Expected 128 bits");
    
    Ok(bits)
}

// Helper: print binary grid visualization
pub fn print_binary_grid(bits: &[bool]) {
    println!("  Binary grid (16×8):");
    for row in 0..8 {
        print!("  ");
        for col in 0..16 {
            let idx = row * 16 + col;
            print!("{}", if bits[idx] { "█" } else { "·" });
        }
        println!();
    }
}