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
use std::convert::TryFrom;


pub trait HashEngine: Default {
    type Digest: Into<Vec<u8>> + IntoIterator<Item=u8> + TryFrom<Vec<u8>> + AsRef<[u8]> + Copy;
    type Midstate: Copy;
    const BLOCKSIZE: usize;

    fn input<I>(&mut self, data: I) where I: AsRef<[u8]>;

    fn reset(&mut self);

    fn midstate(&self) -> Self::Midstate;

    fn from_midstate(&mut self, midstate: Self::Midstate, length: usize);

    fn finalise(&mut self) -> Self::Digest;
}



pub trait KeyBasedHashEngine: HashEngine {
    fn new_with_key<I>(key: I) -> Self
    where I: AsRef<[u8]>;
}

#[derive(Clone, Copy, Debug)]
pub struct State<T: Copy, const N: usize> {
    registers: [T; N]
}

impl<T: Copy, const N: usize> State<T, N> {
    pub fn init(constants: [T; N]) -> State<T, N> {
        State {
            registers: constants
        }
    }

    /// Reads the state as the data type it is stored in.
    /// u32 or u64 in the case of SHA2 or RIPEMD
    pub fn read(&self) -> [T; N] {
        self.registers
    }

    pub fn update(&mut self, new_state: [T; N]) {
        self.registers = new_state;
    }
}


/// Primitive trait
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



/// Macro to create a new struct
macro_rules! hash_struct {
    ($name: ident, $block_size: expr, $length: ty, $state: ty, $state_len: expr) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name {
            buffer: [u8; $block_size],
            length: $length,                 // The length here is in bytes.
            state: State<$state, $state_len>
        }
    };
}

/// Macro to implement functions that require initial constants.
macro_rules! iconst_funcs {
    ($iconsts: expr, $block_size: expr) => {
        fn reset(&mut self) {
            self.buffer = [0; $block_size];
            self.length = 0;
            self.state = State::init($iconsts)
        }
    };
}

/// Functions related to midstate
macro_rules! midstate_funcs {
    ($length_ty: ty) => {
        fn midstate(&self) -> Self::Midstate {
            self.state.read() // extracting the entire state without omitting registers
        }
    
        fn from_midstate(&mut self, midstate: Self::Midstate, length: usize) {
            // If the length mod blocksize is not zero, panic.
            // This is done because, the hasher has no way of knowing whether there was any
            // data in the hasher's buffer that is unaccounted for in the given state.
            assert_eq!(length%Self::BLOCKSIZE, 0);

            self.length = length as $length_ty;
            self.state.update(midstate);
        } 
    }
}

/// Macro to implement hash function data inputting
macro_rules! input_func {
    (
        $length_ty: ty
    ) => {
        fn input<I>(&mut self, data: I) //Code for this function was sourced from bitcoin-hashes crate and adapted to this library. Thanks :)
        where I: AsRef<[u8]> {
            let mut input = data.as_ref();
            
            //while there is still data in the input slice...
            while input.len() != 0 {
                let buffer_index = self.length as usize%Self::BLOCKSIZE;   // Get the current index of the buffer
                let r = Self::BLOCKSIZE - buffer_index;                    // Get the remaining length of the buffer until BLOCKSIZE
                let to_write = std::cmp::min(r, input.len());              // Get the length of the data to copy into the buffer (which ever is smaller, remaining length of the buffer or the remaining length of the input.)

                // Insert the required amount of input data into the buffer
                self.buffer[buffer_index..buffer_index+to_write].copy_from_slice(&input[..to_write]);
                self.length += to_write as $length_ty;                     // Add to the total length of the data being hashed

                // If the total length mod BLOCKSIZE is zero, that means we have enough new data in the buffer
                // to process a block.   (if buffer_index+to_write == Self::BLOCKSIZE)
                if self.length%(Self::BLOCKSIZE as $length_ty) == 0 {
                    let blocks: Vec<MessageBlock<{Self::BLOCKSIZE}>> = MessageBlock::from_message(Message::new(self.buffer[..Self::BLOCKSIZE].to_vec()));
                    assert_eq!(blocks.len(), 1);
                    Self::process_block(&mut self.state, blocks[0]);
                }
                input = &input[to_write..]; // Remove the data we placed into the buffer from the input
            }
        }
    };
}

macro_rules! impl_default {
    ($name: ident, $iconsts: expr, $block_size: expr) => {
        impl Default for $name {
            fn default() -> Self {
                Self {
                    buffer: [0; $block_size],
                    length: 0,
                    state: State::init($iconsts)
                }
            }
        }
    };
}

pub(crate) use hash_struct;
pub(crate) use iconst_funcs;
pub(crate) use midstate_funcs;
pub(crate) use input_func;
pub(crate) use impl_default;