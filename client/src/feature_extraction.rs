use image::{GrayImage, ImageError, imageops};

/// 1024-bit feature extraction using Local Binary Patterns
/// 32×32 grid with LBP texture features
pub fn extract_fingerprint_128bit(image_path: &str) -> Result<Vec<bool>, ImageError> {
    // 1. Read and resize to 64×64
    let img = image::open(image_path)?.to_luma8();
    let resized = imageops::resize(&img, 64, 64, imageops::FilterType::Lanczos3);
    
    // 2. Normalize
    let normalized = normalize_image(&resized);
    
    // 3. Calculate LBP
    let lbp_image = calculate_lbp(&normalized);
    
    // 4. Extract regional histograms (16×16 regions, each with 64-bin histogram)
    let bits = extract_lbp_features(&lbp_image, 8, 8); // 8×8 = 64 regions
    
    assert_eq!(bits.len(), 1024, "Expected 1024 bits");
    
    println!("✅ Extracted 1024 bits (LBP texture features)");
    
    Ok(bits)
}

fn normalize_image(img: &GrayImage) -> GrayImage {
    let (width, height) = img.dimensions();
    let mut normalized = GrayImage::new(width, height);
    
    let mut sum = 0.0;
    let mut sum_sq = 0.0;
    let total = (width * height) as f32;
    
    for pixel in img.pixels() {
        let val = pixel[0] as f32;
        sum += val;
        sum_sq += val * val;
    }
    
    let mean = sum / total;
    let variance = (sum_sq / total) - (mean * mean);
    let std = variance.sqrt().max(1.0);
    
    for (x, y, pixel) in img.enumerate_pixels() {
        let val = pixel[0] as f32;
        let normalized_val = ((val - mean) / std * 50.0 + 128.0).clamp(0.0, 255.0) as u8;
        normalized.put_pixel(x, y, image::Luma([normalized_val]));
    }
    
    normalized
}

/// Calculate Local Binary Pattern for entire image
fn calculate_lbp(img: &GrayImage) -> Vec<u8> {
    let (width, height) = img.dimensions();
    let mut lbp = vec![0u8; (width * height) as usize];
    
    // Process each pixel (excluding borders)
    for y in 1..(height - 1) {
        for x in 1..(width - 1) {
            let center = img.get_pixel(x, y)[0];
            let mut code = 0u8;
            
            // 8 neighbors in clockwise order
            let neighbors = [
                img.get_pixel(x - 1, y - 1)[0], // Top-left
                img.get_pixel(x, y - 1)[0],     // Top
                img.get_pixel(x + 1, y - 1)[0], // Top-right
                img.get_pixel(x + 1, y)[0],     // Right
                img.get_pixel(x + 1, y + 1)[0], // Bottom-right
                img.get_pixel(x, y + 1)[0],     // Bottom
                img.get_pixel(x - 1, y + 1)[0], // Bottom-left
                img.get_pixel(x - 1, y)[0],     // Left
            ];
            
            // Build 8-bit LBP code
            for (i, &neighbor) in neighbors.iter().enumerate() {
                if neighbor >= center {
                    code |= 1 << i;
                }
            }
            
            lbp[(y * width + x) as usize] = code;
        }
    }
    
    lbp
}

/// Extract features from LBP image using regional histograms
fn extract_lbp_features(lbp: &[u8], grid_x: usize, grid_y: usize) -> Vec<bool> {
    let width = 64;
    let height = 64;
    let region_w = width / grid_x;
    let region_h = height / grid_y;
    
    let mut bits = Vec::new();
    
    // For each region
    for gy in 0..grid_y {
        for gx in 0..grid_x {
            let start_x = gx * region_w;
            let start_y = gy * region_h;
            let end_x = (start_x + region_w).min(width);
            let end_y = (start_y + region_h).min(height);
            
            // Build histogram of LBP codes (256 bins)
            let mut histogram = [0u32; 256];
            
            for y in start_y..end_y {
                for x in start_x..end_x {
                    let lbp_code = lbp[y * width + x];
                    histogram[lbp_code as usize] += 1;
                }
            }
            
            // Use only uniform patterns (reduce 256 → 59 patterns)
            let uniform_bins = get_uniform_patterns();
            let mut uniform_histogram = vec![0u32; uniform_bins.len()];
            
            for (code, &count) in histogram.iter().enumerate() {
                if let Some(idx) = uniform_bins.iter().position(|&x| x == code as u8) {
                    uniform_histogram[idx] = count;
                }
            }
            
            // Convert histogram to 16 bits (quantize to most significant patterns)
            let top_patterns = get_top_k_indices(&uniform_histogram, 16);
            for i in 0..16 {
                bits.push(top_patterns.contains(&i));
            }
        }
    }
    
    bits
}

/// Get uniform LBP patterns (patterns with at most 2 transitions)
fn get_uniform_patterns() -> Vec<u8> {
    let mut patterns = Vec::new();
    
    for code in 0u8..=255 {
        let transitions = count_transitions(code);
        if transitions <= 2 {
            patterns.push(code);
        }
    }
    
    patterns
}

/// Count bit transitions in circular 8-bit code
fn count_transitions(code: u8) -> u32 {
    let mut transitions = 0;
    let mut prev_bit = (code >> 7) & 1;
    
    for i in 0..8 {
        let curr_bit = (code >> i) & 1;
        if curr_bit != prev_bit {
            transitions += 1;
        }
        prev_bit = curr_bit;
    }
    
    transitions
}

/// Get indices of top K values in array
fn get_top_k_indices(arr: &[u32], k: usize) -> Vec<usize> {
    let mut indexed: Vec<(usize, u32)> = arr.iter().enumerate().map(|(i, &v)| (i, v)).collect();
    indexed.sort_by(|a, b| b.1.cmp(&a.1));
    indexed.iter().take(k).map(|&(i, _)| i).collect()
}