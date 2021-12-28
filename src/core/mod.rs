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


pub trait HashEngine {
    type Digest: Into<Vec<u8>> + IntoIterator<Item=u8> + TryFrom<Vec<u8>> + AsRef<[u8]> + Copy;
    type Midsate;
    const BLOCKSIZE: usize;

    fn new() -> Self;

    fn input<I>(&mut self, data: I) where I: AsRef<[u8]>;

    fn reset(&mut self);

    fn midstate(&self) -> Self::Midsate;

    fn from_midstate(&mut self, midstate: Self::Midsate);

    fn finalise(&mut self) -> Self::Digest;
}



pub trait KeyBasedHashEngine: HashEngine {
    fn key<I>(&mut self, key: I) where I: AsRef<[u8]>;
}

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

/// Macro to create a new struct
macro_rules! hash_struct {
    ($name: ident, $length: ty, $state: ty, $state_len: expr) => {
        pub struct $name {
            buffer: Vec<u8>,
            length: $length,
            state: State<$state, $state_len>
        }
    };
}

/// Macro to implement functions that require initial constants.
macro_rules! iconst_funcs {
    ($iconsts: expr) => {
        fn new() -> Self {
            Self {
                buffer: vec![],
                length: 0,
                state: State::init($iconsts)
            }
        }

        fn reset(&mut self) {
            self.buffer = vec![];
            self.length = 0;
            self.state = State::init($iconsts)
        }
    };
}

/// Functions related to midstate
macro_rules! midstate_funcs {
    () => {
        fn midstate(&self) -> Self::Midsate {
            self.state.read() // extracting the entire state without omitting registers
        }
    
        fn from_midstate(&mut self, midstate: Self::Midsate) {
            self.state.update(midstate);
        } 
    }
}

/// Macro to implement hash function data inputting
macro_rules! input_func {
    (
        $length_ty: ty
    ) => {
        fn input<I>(&mut self, data: I)
        where I: AsRef<[u8]> {
            self.buffer.extend(data.as_ref());
            self.length += (data.as_ref().len() * 8) as $length_ty;
            while self.buffer.len() >= Self::BLOCKSIZE {
                let blocks: Vec<MessageBlock<{Self::BLOCKSIZE}>> = MessageBlock::from_message(Message::new(self.buffer[..Self::BLOCKSIZE].to_vec()));
                assert_eq!(blocks.len(), 1);
                Self::process_block(&mut self.state, blocks[0]);
                self.buffer = self.buffer.split_off(Self::BLOCKSIZE);
            }
        }
    };
}

pub(crate) use hash_struct;
pub(crate) use iconst_funcs;
pub(crate) use midstate_funcs;
pub(crate) use input_func;



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