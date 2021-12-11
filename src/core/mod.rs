// Core module
//
// Where all the core parts of the Sha2 hash function family reside.
// This can be done because most parts are shared between the different
// hash functions.

pub mod message;
pub mod functions;
use std::ops::{
    Add, Rem, BitXor, BitAnd, Not, Shr
};



/// Sha2Engine trait
/// Includes methods that all Sha2 hash functions share on a high level.
pub trait Sha2Engine {
    /// Input data into the engine.
    fn input<I>(&mut self, data: I) where I: Iterator<Item=u8>;

    /// Complete the hash with the inputted data.
    fn hash<const N: usize>(self) -> [u8; N];
}

pub trait Primitive:
    Into<u128> +
    Add +
    Rem +
    BitAnd<Output = Self> +
    BitXor<Output = Self> +
    Not<Output = Self> +
    Shr<usize, Output = Self> +
    Copy
{
    fn rotate_right(&self, bits: usize) -> Self;

    fn add_mod<T: Primitive + From<u128>>(a: T, b: T, mod_pow: u32) -> T {
        let a: u128 = a.into();
        let b: u128 = b.into();
        T::from((a+b) % 2u128.pow(mod_pow))
    }
}

impl Primitive for u32{ 
    fn rotate_right(&self, bits: usize) -> Self {
        self.rotate_right(bits)
    }
}

impl Primitive for u64{
    fn rotate_right(&self, bits: usize) -> Self {
        self.rotate_right(bits)
    }
}