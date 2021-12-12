// Core module
//
// Where all the core parts of the Sha2 hash function family reside.
// This can be done because most parts are shared between the different
// hash functions.

pub mod message;
pub mod functions;
pub mod state;
use std::ops::{
    Add, Rem, BitXor, BitAnd, Not, Shr
};



/// HashEngine trait
/// 
/// Includes methods that all Sha2 hash functions share on a high level.
/// The generic parameters indicate how many bits each word in the message schedule
/// and state registers should use as well as the length constraints for the Message.
pub trait HashEngine<const N: usize> {
    fn new() -> Self;
    
    /// Input data into the engine.
    fn input(&mut self, data: &[u8]);

    /// Read the data inputted into the engine
    fn read_input(self) -> Vec<u8>;

    /// Complete the hash with the inputted data.
    fn hash(self) -> [u8; N];
}

pub trait Primitive:
    Into<u128> +
    Into<u64> +
    Add +
    Rem +
    BitAnd<Output = Self> +
    BitXor<Output = Self> +
    Not<Output = Self> +
    Shr<usize, Output = Self> +
    Copy
{
    fn rotr(&self, bits: usize) -> Self;
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