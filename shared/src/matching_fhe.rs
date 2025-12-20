// shared/src/matching_fhe.rs
use tfhe::prelude::*;
use tfhe::{FheBool};

#[inline]
fn fhe_not(x: &FheBool, fhe_true: &FheBool) -> FheBool {
    x ^ fhe_true
}

#[inline]
fn fhe_or(a: &FheBool, b: &FheBool) -> FheBool {
    // a | b = a ^ b ^ (a & b)
    a ^ b ^ (a & b)
}

/// XOR-diff bits: 1 => different
pub fn diff_bits(a: &[FheBool], b: &[FheBool]) -> Vec<FheBool> {
    assert_eq!(a.len(), b.len());
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

/// Popcount for diff bits into an encrypted binary counter (LSB-first).
/// For 128 bits, 8 bits are enough (0..128).
pub fn popcount_128(diff: &[FheBool], fhe_true: &FheBool) -> Vec<FheBool> {
    assert_eq!(diff.len(), 128);

    let fhe_false = fhe_true ^ fhe_true;
    let mut acc = vec![fhe_false.clone(); 8]; // 8-bit counter

    for bit in diff.iter() {
        // Add 1-bit value `bit` into binary accumulator.
        let mut carry = bit.clone();
        for i in 0..acc.len() {
            let sum = &acc[i] ^ &carry;
            let new_carry = &acc[i] & &carry;
            acc[i] = sum;
            carry = new_carry;
        }
        // overflow ignored (max 128 fits in 8 bits)
    }

    acc
}

/// Compute (distance <= threshold) where distance is encrypted bits (LSB-first),
/// threshold is plaintext usize.
pub fn leq_constant(distance_bits_lsb: &[FheBool], threshold: usize, fhe_true: &FheBool) -> FheBool {
    // Convert threshold to bits (same width), MSB-first loop
    let k = distance_bits_lsb.len();
    let mut thr_bits = vec![false; k];
    for i in 0..k {
        thr_bits[i] = ((threshold >> i) & 1) == 1;
    }

    let fhe_false = fhe_true ^ fhe_true;

    // gt = false; eq = true
    let mut gt = fhe_false.clone();
    let mut eq = fhe_true.clone();

    for i in (0..k).rev() {
        let di = &distance_bits_lsb[i];

        if thr_bits[i] == false {
            // if thr=0, gt can happen when distance bit is 1 and all higher bits equal
            gt = fhe_or(&gt, &(&eq & di));
            // eq remains only if di==0
            eq = &eq & &fhe_not(di, fhe_true);
        } else {
            // thr=1: gt cannot be triggered at this bit
            // eq remains only if di==1
            eq = &eq & di;
        }
    }

    // distance <= threshold  <=>  NOT(gt)
    fhe_not(&gt, fhe_true)
}
