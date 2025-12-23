use image::{GrayImage, ImageError, imageops};

/// 512-bit feature extraction using grid-based statistics
/// 8×8 grid = 64 regions, 8 bits per region = 512 bits total
pub fn extract_fingerprint_128bit(image_path: &str) -> Result<Vec<bool>, ImageError> {
    // 1. Read and preprocess
    let img = image::open(image_path)?.to_luma8();
    
    // 2. Resize to 64×64 for better detail preservation
    let resized = imageops::resize(
        &img,
        64,
        64,
        imageops::FilterType::Lanczos3
    );
    
    // 3. Normalize image
    let normalized = normalize_image(&resized);
    
    // 4. Extract grid-based features
    let bits = extract_grid_features(&normalized, 8, 8);
    
    assert_eq!(bits.len(), 512, "Expected 512 bits");
    
    println!("✅ Extracted 512 bits (8×8 grid with regional statistics)");
    
    Ok(bits)
}

/// Normalize image to have mean=128, std=50
fn normalize_image(img: &GrayImage) -> GrayImage {
    let (width, height) = img.dimensions();
    let mut normalized = GrayImage::new(width, height);
    
    // Calculate mean and std
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
    let std = variance.sqrt().max(1.0); // Avoid division by zero
    
    // Normalize: (x - mean) / std * 50 + 128
    for (x, y, pixel) in img.enumerate_pixels() {
        let val = pixel[0] as f32;
        let normalized_val = ((val - mean) / std * 50.0 + 128.0).clamp(0.0, 255.0) as u8;
        normalized.put_pixel(x, y, image::Luma([normalized_val]));
    }
    
    normalized
}

/// Extract 512-bit features from 8×8 grid
fn extract_grid_features(img: &GrayImage, grid_x: usize, grid_y: usize) -> Vec<bool> {
    let (width, height) = img.dimensions();
    let region_w = width as usize / grid_x;
    let region_h = height as usize / grid_y;
    
    let mut bits = Vec::with_capacity(grid_x * grid_y * 8);
    
    for gy in 0..grid_y {
        for gx in 0..grid_x {
            let start_x = gx * region_w;
            let start_y = gy * region_h;
            let end_x = start_x + region_w;
            let end_y = start_y + region_h;
            
            // Extract region
            let mut region_pixels = Vec::new();
            for y in start_y..end_y {
                for x in start_x..end_x {
                    region_pixels.push(img.get_pixel(x as u32, y as u32)[0]);
                }
            }
            
            // Calculate statistics
            let mean = calculate_mean(&region_pixels);
            let std = calculate_std(&region_pixels, mean);
            let edge_density = calculate_edge_density(img, start_x, start_y, end_x, end_y);
            let gradient_dir = calculate_gradient_direction(img, start_x, start_y, end_x, end_y);
            
            // Convert to bits (2 bits each = 8 bits per region)
            bits.extend(quantize_to_2bits(mean));
            bits.extend(quantize_to_2bits(std));
            bits.extend(quantize_to_2bits(edge_density));
            bits.extend(quantize_to_2bits(gradient_dir));
        }
    }
    
    bits
}

fn calculate_mean(pixels: &[u8]) -> f32 {
    let sum: u32 = pixels.iter().map(|&p| p as u32).sum();
    sum as f32 / pixels.len() as f32
}

fn calculate_std(pixels: &[u8], mean: f32) -> f32 {
    let variance: f32 = pixels
        .iter()
        .map(|&p| {
            let diff = p as f32 - mean;
            diff * diff
        })
        .sum::<f32>() / pixels.len() as f32;
    
    variance.sqrt()
}

fn calculate_edge_density(
    img: &GrayImage,
    start_x: usize,
    start_y: usize,
    end_x: usize,
    end_y: usize,
) -> f32 {
    let mut edge_count = 0;
    let mut total_count = 0;
    
    // Simple edge detection using gradient
    for y in start_y..(end_y - 1) {
        for x in start_x..(end_x - 1) {
            let curr = img.get_pixel(x as u32, y as u32)[0] as i32;
            let right = img.get_pixel((x + 1) as u32, y as u32)[0] as i32;
            let down = img.get_pixel(x as u32, (y + 1) as u32)[0] as i32;
            
            let gx = (right - curr).abs();
            let gy = (down - curr).abs();
            let gradient = (gx + gy) as f32;
            
            if gradient > 30.0 {  // Threshold for edge
                edge_count += 1;
            }
            total_count += 1;
        }
    }
    
    if total_count > 0 {
        edge_count as f32 / total_count as f32 * 255.0
    } else {
        0.0
    }
}

fn calculate_gradient_direction(
    img: &GrayImage,
    start_x: usize,
    start_y: usize,
    end_x: usize,
    end_y: usize,
) -> f32 {
    let mut sum_gx = 0.0;
    let mut sum_gy = 0.0;
    
    for y in start_y..(end_y - 1) {
        for x in start_x..(end_x - 1) {
            let curr = img.get_pixel(x as u32, y as u32)[0] as f32;
            let right = img.get_pixel((x + 1) as u32, y as u32)[0] as f32;
            let down = img.get_pixel(x as u32, (y + 1) as u32)[0] as f32;
            
            sum_gx += right - curr;
            sum_gy += down - curr;
        }
    }
    
    // Return angle in 0-255 range
    let angle = sum_gy.atan2(sum_gx);
    ((angle + std::f32::consts::PI) / (2.0 * std::f32::consts::PI) * 255.0) as f32
}

/// Quantize float value (0-255) to 2 bits
fn quantize_to_2bits(value: f32) -> Vec<bool> {
    let quantized = ((value / 255.0) * 3.0) as u8; // 0, 1, 2, or 3
    vec![
        (quantized & 0b01) != 0,
        (quantized & 0b10) != 0,
    ]
}

// Debug helper
#[allow(dead_code)]
pub fn print_binary_grid(bits: &[bool]) {
    println!("  Binary feature vector (512 bits):");
    for chunk in 0..(512 / 64) {
        print!("  ");
        for i in 0..64 {
            let idx = chunk * 64 + i;
            if idx < bits.len() {
                print!("{}", if bits[idx] { "1" } else { "0" });
            }
        }
        println!();
    }
}