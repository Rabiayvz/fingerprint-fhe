use image::{GrayImage, ImageError};

/// 256-bit binary grid feature extraction with adaptive thresholding
/// Resize: 16×16 = 256 pixels → 256 bits
pub fn extract_fingerprint_128bit(image_path: &str) -> Result<Vec<bool>, ImageError> {
    // 1. Read grayscale image
    let img = image::open(image_path)?.to_luma8();
    
    // 2. Resize to 16×16 (256 pixels)
    let resized = image::imageops::resize(
        &img,
        16,  // width
        16,  // height
        image::imageops::FilterType::Lanczos3
    );
    
    // 3. Calculate adaptive threshold using Otsu's method
    let pixels: Vec<u8> = resized.pixels().map(|p| p[0]).collect();
    let threshold = calculate_otsu_threshold(&pixels);
    
    println!("📊 Adaptive threshold calculated: {}/255", threshold);
    
    // 4. Binarize with adaptive threshold
    // Dark pixels (ridges) → true, Light pixels (background) → false
    let mut bits = Vec::with_capacity(256);
    for pixel in resized.pixels() {
        let val = pixel[0];
        bits.push(val < threshold);
    }
    
    assert_eq!(bits.len(), 256, "Expected 256 bits");
    
    println!("✅ Extracted 256 bits (16×16 grid with adaptive threshold)");
    
    Ok(bits)
}

/// Calculate optimal threshold using Otsu's method
/// This maximizes inter-class variance for better ridge/valley separation
fn calculate_otsu_threshold(pixels: &[u8]) -> u8 {
    // Build histogram
    let mut histogram = [0u32; 256];
    for &pixel in pixels {
        histogram[pixel as usize] += 1;
    }
    
    let total = pixels.len() as f32;
    
    // Calculate total mean
    let mut sum = 0.0;
    for i in 0..256 {
        sum += (i as f32) * (histogram[i] as f32);
    }
    
    // Find threshold that maximizes between-class variance
    let mut sum_bg = 0.0;
    let mut weight_bg = 0.0;
    let mut max_variance = 0.0;
    let mut threshold = 128u8;  // default fallback
    
    for t in 0..256 {
        weight_bg += histogram[t] as f32;
        if weight_bg == 0.0 {
            continue;
        }
        
        let weight_fg = total - weight_bg;
        if weight_fg == 0.0 {
            break;
        }
        
        sum_bg += (t as f32) * (histogram[t] as f32);
        
        let mean_bg = sum_bg / weight_bg;
        let mean_fg = (sum - sum_bg) / weight_fg;
        
        // Between-class variance
        let variance = weight_bg * weight_fg * (mean_bg - mean_fg).powi(2);
        
        if variance > max_variance {
            max_variance = variance;
            threshold = t as u8;
        }
    }
    
    threshold
}

// Helper: print binary grid visualization (optional, for debugging)
#[allow(dead_code)]
pub fn print_binary_grid(bits: &[bool]) {
    println!("  Binary grid (16×16):");
    for row in 0..16 {
        print!("  ");
        for col in 0..16 {
            let idx = row * 16 + col;
            print!("{}", if bits[idx] { "█" } else { "·" });
        }
        println!();
    }
}