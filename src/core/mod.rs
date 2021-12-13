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
///     S: The size of the message blocks in bytes
///     W: The amount of words in each message schedule,
pub trait HashEngine<T: Primitive, const D: usize, const S: usize, const L: usize, const W: usize>: Pad<S, L> {
    fn new() -> Self;
    
    /// Input data into the engine.
    fn input(&mut self, data: &[u8]);

    /// Read the data inputted into the engine
    fn read_input(self) -> Vec<u8>;

    fn round_constants() -> [T; W];

    fn initial_constants() -> [T; 8];

    /// Complete the hash with the inputted data.
    fn hash(self) -> [u8; D];
}

/// Macro to implement the different hash functions with differnet parameters.
/// 
/// ### Params
///  - Hash function name (Identifier)
///  - Bits to operate on (Type u32 or u64)
///  - Digest size in bytes (Number)
///  - Pad size indicating the length of the length appended to the padding (Number)
///  - Block size in bytes (Number)
///  - Schedule length as count (Number)
///  - Ignored state registers when concatenating the final state (Number)
///  - Initial constants (Array of 8 integers of the same type specified in $bits)
///  - Round constants (Array of $schedule_length of the same type specified in $bits)
macro_rules! hash_function {
    (
        $name: ident,
        $bits: ty,
        $digest_size: expr,
        $pad_size: expr,
        $block_size: expr,
        $schedule_length: expr,
        $ignored_state: expr,
        $initial_constants: expr,
        $round_constants: expr
    ) => {
        pub struct $name {
            input: Vec<u8>
        }

        impl HashEngine<$bits, $digest_size, $block_size, $pad_size, $schedule_length> for $name {
            fn new() -> Self {
                $name {
                    input: vec![]
                }
            }

            fn input(&mut self, data: &[u8]) {
                self.input.extend_from_slice(data);
            }

            fn read_input(self) -> Vec<u8> {
                self.input
            }

            fn initial_constants() -> [$bits; 8] {
                $initial_constants
            }

            fn round_constants() -> [$bits; $schedule_length] {
                $round_constants
            }

            fn hash(self) -> [u8; $digest_size] {
                let input = self.read_input();
                let message: Message<$block_size> = Self::pad(input);
                let blocks: Vec<MessageBlock<$block_size>> = MessageBlock::from_message(message);
                let mut state: State<$bits> = State::new(Self::initial_constants());
                for block in blocks {
                    let schedule: MessageSchedule<$bits, $schedule_length> = MessageSchedule::from(block);
                    state.compress(schedule, Self::round_constants());
                }

                let state = &state.read()[0..state.read().len()-$ignored_state];
                let mut digest = vec![];
                for i in 0..state.len() {
                    digest.extend(state[i].to_be_bytes());
                }
                digest.try_into().expect("Bad digest")
            }
        }

        impl Pad<$block_size, $pad_size> for $name { }
    };
}
pub(crate) use hash_function;

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