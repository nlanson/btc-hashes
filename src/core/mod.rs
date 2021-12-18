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
    const BLOCKSIZE: usize;

    fn new() -> Self;

    /// Takes in new inputs
    fn input<I>(&mut self, data: I) where I: AsRef<[u8]>;

    fn reset(&mut self);

    fn hash(&self) -> Self::Digest;
}

pub trait KeyBasedHashEngine: HashEngine {
    fn key<I>(&mut self, key: I) where I: AsRef<[u8]>;
}

pub struct State<T: Copy> {
    registers: [T; 8]
}

impl<T: Copy> State<T> {
    pub fn init(constants: [T; 8]) -> State<T> {
        State {
            registers: constants
        }
    }

    pub fn read(&self) -> [T; 8] {
        self.registers
    }

    pub fn update(&mut self, new_state: [T; 8]) {
        self.registers = new_state;
    }
}

macro_rules! basic_hash_struct {
    ($name: ident) => {
        pub struct $name {
            input: Vec<u8>
        }
    };
}

macro_rules! input_function {
    () => {
        fn input<I>(&mut self, data: I)
        where I: AsRef<[u8]> {
            self.input.extend_from_slice(data.as_ref())
        }
    };
}

macro_rules! default_function {
    () => {
        fn new() -> Self {
            Self {
                input: vec![]
            }
        }
    }
}

macro_rules! reset_engine {
    () => {
        fn reset(&mut self) {
            self.input = vec![]
        }
    };
}

pub(crate) use basic_hash_struct;
pub(crate) use input_function;
pub(crate) use default_function;
pub(crate) use reset_engine;



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