// The message module
//
// Sha2 hash functions operate on messages and message blocks.
// Messages are created by padding the intput data and message
// blocks are created by splitting the message into 512 or 1024
// bit blocks.


use std::convert::TryInto;
use crate::core::{
    functions, Primitive
};



/// Trait to pad input data into Message Structs.
/// 
/// Padding differs from each Sha2 hash function.
/// The const generic is used to indicate the modulus of the final
/// message length in bytes.
pub trait Pad<const N: usize> {
    /// Pad the input data in multiples of N*8 bits
    fn pad(&self) -> Message;
}

/// Message struct
/// The message is the original data followed by padding.
#[derive(Debug)]
pub struct Message(pub Vec<u8>);

impl Message {
    pub fn new(message: Vec<u8>) -> Message {
        Message(message)
    }
}


/// Message block struct.
/// Message blocks are groups of 512 or 1024 bits. These bits are 
/// the bits that the main computations are performed on.
#[derive(Debug)]
pub struct MessageBlock<const N: usize>([u8; N]);

impl<const N: usize> MessageBlock<N> {
    /// Create message blocks from a message.
    /// Message blocks are split into N byte chunks where N is either 64 or 128
    /// depending on the hash function being used.
    pub fn from_message(message: Message) -> Vec<MessageBlock<N>> {
        message.0
            .chunks(N)
            .into_iter()
            .map(|chunk| MessageBlock::from(chunk))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl<const N: usize> From<&[u8]> for MessageBlock<N> {
    fn from(slice: &[u8]) -> MessageBlock<N> {
        let a: [u8; N] = slice.try_into().expect("Bad slice");
        MessageBlock(a)
    }
}


/// Message schedule struct
/// The message schedule is an array of words of lengthg 64 or 80.
#[derive(Debug)]
pub struct MessageSchedule<T: Primitive, const N: usize>([Word<T>; N]);

impl From<MessageBlock<64>> for MessageSchedule<u32, 64> {
    fn from(block: MessageBlock<64>) -> MessageSchedule<u32, 64> {
        // Create the initial 16 words from the message block
        let mut words: Vec<Word<u32>> = block.0
            .chunks(4)
            .into_iter()
            .map(|chunk| {
                let chunk: [u8; 4] = chunk.try_into().expect("Bad chunk");
                Word::new(unsafe { std::mem::transmute(chunk) })
            })
            .collect();

        // Extend the intial schedule to 64 words
        // W[i] = σ1(W[i−2]) + W[i−7] + σ0(W[i−15]) + W[i−16]
        for i in 16..64 {
            let a = functions::lsigma1(words[i-2].value);
            let b = words[i-7].value;
            let c = functions::lsigma0(words[i-15].value);
            let d = words[i-16].value;

            let nv: u64 = a as u64 + b as u64 + c as u64 + d as u64;
            words.push(Word::new((nv%2u64.pow(32)) as u32))
        }

        let words: [Word<u32>; 64] = words.try_into().expect("Bad words");
        MessageSchedule(words)
    }
}

/// Word struct
/// The value in a word can be either a 32 or 64 bit integer, hence the
/// generic constraint for integers is applied.
#[derive(Copy, Clone, Debug)]
pub struct Word<T: Primitive> {
    value: T
}

impl<T: Primitive> Word<T> {
    pub fn new(value: T) -> Word<T> {
        Word { value }
    }
}