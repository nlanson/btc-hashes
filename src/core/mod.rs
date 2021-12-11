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



/// HashEngine trait
/// 
/// Includes methods that all Sha2 hash functions share on a high level.
/// The generic parameters indicate how many bits each word in the message schedule
/// and state registers should use as well as the length constraints for the Message.
pub trait HashEngine<const N: usize> {
    /// Input data into the engine.
    fn input<I>(&mut self, data: I) where I: Iterator<Item=u8>;

    /// Read the data inputted into the engine
    fn read_input(self) -> Vec<u8>;

    /// Complete the hash with the inputted data.
    fn hash(self) -> [u8; N];
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
    fn rotr(&self, bits: usize) -> Self;

    fn add_mod<T: Primitive + From<u128>>(a: T, b: T, mod_pow: u32) -> T {
        let a: u128 = a.into();
        let b: u128 = b.into();
        T::from((a+b) % 2u128.pow(mod_pow))
    }
}

impl Primitive for u32{ 
    fn rotr(&self, bits: usize) -> Self {
        self.rotate_right(bits as u32)
    }
}

impl Primitive for u64{
    fn rotr(&self, bits: usize) -> Self {
        self.rotate_right(bits as u32)
    }
}