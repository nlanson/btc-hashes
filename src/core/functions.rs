// Core functions module.
//
// Where all the core functions sit.
use crate::core::Primitive;
use std::ops::{
    BitAnd, BitXor, Not, Shr
};

/// Choice
/// For each bit, if X is set, choose Y else choose Z.
pub fn choice<T: Primitive + BitAnd<Output = T> + BitXor<Output = T> + Not<Output = T>>(x: T, y: T, z: T) -> T {
    (x&y) ^ (!x&z)
}

/// Majority
/// Takes which ever bit is the majority of the three
pub fn majority<T: Primitive + BitAnd<Output = T> + BitXor<Output = T>>(x: T, y: T, z: T) -> T {
    (x&y) ^ (x&z) ^ (y&z)
}

/// Uppercase Sigma 0 (Σ0)
pub fn usigma0<T: Primitive + BitXor<Output = T>>(x: T) -> T {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

/// Uppercase Sigma 1 (Σ1)
pub fn usigma1<T: Primitive + BitXor<Output = T>>(x: T) -> T {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

/// Lowercase Sigma 0 (σ0)
pub fn lsigma0<T: Primitive + BitXor<Output = T> + Shr<usize, Output = T>>(x: T) -> T {
    x.rotate_right(6) ^ x.rotate_right(11) ^ (x>>3)
}

/// Lowercase Sigma 1 (σ1)
pub fn lsigma1<T: Primitive + BitXor<Output = T> + Shr<usize, Output = T>>(x: T) -> T {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x>>10)
}