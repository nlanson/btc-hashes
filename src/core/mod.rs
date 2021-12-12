// Core module
//
// Where all the core parts of the Sha2 hash function family reside.
// This can be done because most parts are shared between the different
// hash functions.

pub mod message;
pub mod functions;
pub mod state;
use message::{
    Message, MessageBlock, MessageSchedule, Pad
};
use state::{
    State, Compression
};
use std::ops::{
    Add, Rem, BitXor, BitAnd, Not, Shr
};

use crate::Sha256;



/// HashEngine trait
/// 
/// Includes methods that all Sha2 hash functions share on a high level.
/// Generic paramters
///     T: u32 or u64 to indicate how many bits each word has
///     N: The size of the final hash in bytes
///     M: The size of the message blocks in bytes
///     K: The amount of words in each message schedule
pub trait HashEngine<const N: usize, const M: usize>: Pad<M> {
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