use image::{GrayImage, ImageError, imageops, Luma};

/// 512-bit feature extraction using block-wise ridge orientation (Orientation Map)
/// 16×16 blocks = 256 blocks, each block -> 2 bits => 256 * 2 = 512 bits
///
/// ✅ Daha stabil (aynı parmak farklı foto)
/// ✅ LBP'ye göre daha ayırt edici
/// ✅ 512 bit -> FHE'de 1024'e göre daha hızlı
pub fn extract_fingerprint_128bit(image_path: &str) -> Result<Vec<bool>, ImageError> {
    let img = image::open(image_path)?.to_luma8();
    let normalized = normalize_contrast_minmax(&img);
    let resized = imageops::resize(&normalized, 256, 256, imageops::FilterType::Triangle);
    
    let blocks = 16usize;
    let bw = 16usize;
    let bh = 16usize;
    
    let mut bits = Vec::with_capacity(512);
    
    for by in 0..blocks {
        for bx in 0..blocks {
            let (gx, gy) = block_gradient_sum(&resized, bx * bw, by * bh, bw, bh);
            
            let angle = (gy as f64).atan2(gx as f64);
            let mut a = angle;
            if a < 0.0 { a += std::f64::consts::TAU; }
            
            // 4 yön (2 bit)
            let bin = ((a / std::f64::consts::TAU) * 4.0).floor() as usize % 4;
            
            bits.push((bin & 2) != 0);
            bits.push((bin & 1) != 0);
        }
    }
    
    Ok(bits)
}

fn normalize_contrast_minmax(img: &GrayImage) -> GrayImage {
    let (w, h) = img.dimensions();

    let mut min_v = 255u8;
    let mut max_v = 0u8;

    for y in 0..h {
        for x in 0..w {
            let v = img.get_pixel(x, y).0[0];
            if v < min_v { min_v = v; }
            if v > max_v { max_v = v; }
        }
    }

    // Flat image: return copy
    if max_v <= min_v + 5 {
        return img.clone();
    }

    let scale = 255.0 / ((max_v - min_v) as f32);
    let mut out = GrayImage::new(w, h);

    for y in 0..h {
        for x in 0..w {
            let v = img.get_pixel(x, y).0[0];
            let nv = ((v.saturating_sub(min_v)) as f32 * scale).round() as i32;
            out.put_pixel(x, y, Luma([nv.clamp(0, 255) as u8]));
        }
    }

    out
}

/// Sobel gradient sum over a block (fast)
fn block_gradient_sum(img: &GrayImage, x0: usize, y0: usize, bw: usize, bh: usize) -> (i32, i32) {
    let (w, h) = img.dimensions();
    let w = w as i32;
    let h = h as i32;

    let mut gx_sum: i32 = 0;
    let mut gy_sum: i32 = 0;

    // Safe ranges (avoid borders)
    let xs = (x0 as i32 + 1).min(w - 2);
    let ys = (y0 as i32 + 1).min(h - 2);
    let xe = ((x0 + bw) as i32 - 2).min(w - 2);
    let ye = ((y0 + bh) as i32 - 2).min(h - 2);

    for y in ys..=ye {
        for x in xs..=xe {
            let p = |xx: i32, yy: i32| -> i32 {
                img.get_pixel(xx as u32, yy as u32).0[0] as i32
            };

            let gx = -p(x-1,y-1) + p(x+1,y-1)
                   + -2*p(x-1,y) + 2*p(x+1,y)
                   + -p(x-1,y+1) + p(x+1,y+1);

            let gy = -p(x-1,y-1) - 2*p(x,y-1) - p(x+1,y-1)
                   +  p(x-1,y+1) + 2*p(x,y+1) + p(x+1,y+1);

            gx_sum += gx;
            gy_sum += gy;
        }
    }

    (gx_sum, gy_sum)
}
