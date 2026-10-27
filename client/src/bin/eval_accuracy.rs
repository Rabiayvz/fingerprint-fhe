// Plaintext accuracy evaluation for the feature extractor.
// No FHE/Trivium involved — runs in seconds over the whole dataset.

use client::feature_extraction::extract_fingerprint_128bit;
use client::matching::hamming_distance;

use std::collections::HashMap;
use std::fs;

const DATA_DIR: &str = "../data/fingerprints";
const BITS: usize = 512;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("FINGERPRINT FEATURE EXTRACTOR - ACCURACY EVALUATION");
    println!("{}", "=".repeat(70));
    println!("(Plaintext only, no FHE - should finish in a few seconds)\n");

    let mut templates: HashMap<String, Vec<Vec<bool>>> = HashMap::new();
    let mut count = 0;

    for entry in fs::read_dir(DATA_DIR)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("tif") {
            continue;
        }
        let stem = path.file_stem().unwrap().to_string_lossy().to_string();
        let subject_id = stem.split('_').next().unwrap().to_string();

        let bits = extract_fingerprint_128bit(path.to_str().unwrap())?;
        templates.entry(subject_id).or_default().push(bits);
        count += 1;
    }

    println!(
        "Loaded {} images across {} subjects\n",
        count,
        templates.len()
    );

    let mut genuine = Vec::new();
    let mut impostor = Vec::new();

    let subjects: Vec<&String> = templates.keys().collect();

    for i in 0..subjects.len() {
        let a = &templates[subjects[i]];

        for x in 0..a.len() {
            for y in (x + 1)..a.len() {
                genuine.push(hamming_distance(&a[x], &a[y]));
            }
        }

        for j in (i + 1)..subjects.len() {
            let b = &templates[subjects[j]];
            for x in 0..a.len() {
                for y in 0..b.len() {
                    impostor.push(hamming_distance(&a[x], &b[y]));
                }
            }
        }
    }

    print_stats("Genuine (same finger, different impression)", &genuine);
    print_stats("Impostor (different subjects)", &impostor);
    compute_eer(&genuine, &impostor);

    Ok(())
}

fn print_stats(label: &str, distances: &[usize]) {
    let n = distances.len();
    let sum: usize = distances.iter().sum();
    let mean = sum as f64 / n as f64;
    let variance = distances
        .iter()
        .map(|&d| {
            let diff = d as f64 - mean;
            diff * diff
        })
        .sum::<f64>()
        / n as f64;
    let std_dev = variance.sqrt();
    let min = *distances.iter().min().unwrap();
    let max = *distances.iter().max().unwrap();

    let sim = |d: f64| 100.0 * (1.0 - d / BITS as f64);

    println!("-- {} --", label);
    println!("   pairs: {}", n);
    println!(
        "   Hamming distance: min={} max={} mean={:.1} std={:.1}",
        min, max, mean, std_dev
    );
    println!(
        "   similarity %:     min={:.1}% max={:.1}% mean={:.1}%",
        sim(max as f64),
        sim(min as f64),
        sim(mean)
    );
    println!();
}

fn compute_eer(genuine: &[usize], impostor: &[usize]) {
    println!("-- FAR/FRR sweep (threshold = max allowed Hamming distance to accept) --");

    let mut best_threshold = 0usize;
    let mut best_gap = f64::MAX;
    let mut best_far = 0.0;
    let mut best_frr = 0.0;

    for threshold in 0..=BITS {
        let far =
            impostor.iter().filter(|&&d| d <= threshold).count() as f64 / impostor.len() as f64;
        let frr =
            genuine.iter().filter(|&&d| d > threshold).count() as f64 / genuine.len() as f64;
        let gap = (far - frr).abs();
        if gap < best_gap {
            best_gap = gap;
            best_threshold = threshold;
            best_far = far;
            best_frr = frr;
        }
    }

    let eer = (best_far + best_frr) / 2.0;
    println!("   approx. EER:      {:.2}%", eer * 100.0);
    println!(
        "   at threshold:     {} bits (similarity >= {:.1}%)",
        best_threshold,
        100.0 * (1.0 - best_threshold as f64 / BITS as f64)
    );
    println!("   FAR at EER point: {:.2}%", best_far * 100.0);
    println!("   FRR at EER point: {:.2}%\n", best_frr * 100.0);

    // Current hard-coded threshold in server/src/main.rs: distance <= 20% of BITS (80% similarity)
    let current_threshold = (BITS as f64 * 0.2) as usize;
    let far_cur =
        impostor.iter().filter(|&&d| d <= current_threshold).count() as f64 / impostor.len() as f64;
    let frr_cur =
        genuine.iter().filter(|&&d| d > current_threshold).count() as f64 / genuine.len() as f64;

    println!(
        "-- At current hard-coded threshold (80% similarity, distance <= {}) --",
        current_threshold
    );
    println!("   FAR: {:.2}%   FRR: {:.2}%", far_cur * 100.0, frr_cur * 100.0);
}
