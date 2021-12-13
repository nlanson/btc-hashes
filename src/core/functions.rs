// Core functions module.
//
// Where all the core functions sit.
use crate::core::Primitive;

/// Choice
/// For each bit, if X is set, choose Y else choose Z.
pub fn choice<T: Primitive>(x: T, y: T, z: T) -> T {
    (x&y) ^ (!x&z)
}

/// Majority
/// Takes which ever bit is the majority of the three
pub fn majority<T: Primitive>(x: T, y: T, z: T) -> T {
    (x&y) ^ (x&z) ^ (y&z)
}

pub trait SigmaFunctions<T: Primitive> {
    /// Uppercase Sigma 0 (Σ0)
    fn usigma0(x: T) -> T;

    /// Uppercase Sigma 1 (Σ1)
    fn usigma1(x: T) -> T;

    /// Lowercase Sigma 0 (σ0)
    fn lsigma0(x: T) -> T;

    /// Lowercase Sigma 1 (σ1)
    fn lsigma1(x: T) -> T;
}

/// 32 bit Sigma Functions
impl SigmaFunctions<u32> for u32 {
    fn usigma0(x: u32) -> u32 {
        x.rotr(2) ^ x.rotr(13) ^ x.rotr(22)
    }
    
    fn usigma1(x: u32) -> u32 {
        x.rotr(6) ^ x.rotr(11) ^ x.rotr(25)
    }
    
    fn lsigma0(x: u32) -> u32 {
        x.rotr(7) ^ x.rotr(18) ^ (x>>3)
    }

    fn lsigma1(x: u32) -> u32 {
        x.rotr(17) ^ x.rotr(19) ^ (x>>10)
    }
}

impl SigmaFunctions<u64> for u64 {
    fn usigma0(x: u64) -> u64 {
        x.rotr(28) ^ x.rotr(34) ^ x.rotr(39)
    }
    
    fn usigma1(x: u64) -> u64 {
        x.rotr(14) ^ x.rotr(18) ^ x.rotr(41)
    }
    
    fn lsigma0(x: u64) -> u64 {
        x.rotr(1) ^ x.rotr(8) ^ (x>>7)
    }

    fn lsigma1(x: u64) -> u64 {
        x.rotr(19) ^ x.rotr(61) ^ (x>>6)
    }
}