// Core module
//
// Where all the core parts of the Sha2 hash function family reside.
// This can be done because most parts are shared between the different
// hash functions.

pub mod message;
pub mod functions;
pub mod state;
use message::Pad;
use std::ops::{
    Add, Rem, BitXor, BitAnd, Not, Shr
};


/// HashEngine trait
/// 
/// Includes methods that all Sha2 hash functions share on a high level.
/// Generic paramters
///     T: u32 or u64 to indicate how many bits each word has
///     D: The size of the final hash in bytes
///     S: The size of the message blocks in bytes,
///     L: Bits reserved for length extention attacks when padding
///     W: The amount of words in each message schedule,
pub trait HashEngine<T: Primitive, const D: usize, const S: usize, const L: usize, const W: usize>: Pad<S, L> {
    fn new() -> Self;
    
    /// Input data into the engine.
    fn input<I>(&mut self, data: I)
    where I: AsRef<[u8]>;

    /// Read the data inputted into the engine
    fn read_input(self) -> Vec<u8>;

    fn round_constants() -> [T; W];

    fn initial_constants() -> [T; 8];

    /// Complete the hash with the inputted data.
    fn hash(self) -> [u8; D];
}



pub trait Primitive:
    Into<u128> + 
    From<u32> + 
    Add +
    Rem +
    BitAnd<Output = Self> +
    BitXor<Output = Self> +
    Not<Output = Self> +
    Shr<usize, Output = Self> +
    Copy
{
    fn rotr(&self, bits: usize) -> Self;

    fn to_bytes(&self) -> Vec<u8>;
}

impl Primitive for u32 { 
    fn rotr(&self, bits: usize) -> Self {
        self.rotate_right(bits as u32)
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

impl Primitive for u64{
    fn rotr(&self, bits: usize) -> Self {
        self.rotate_right(bits as u32)
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}