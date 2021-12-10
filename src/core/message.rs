// The message module
//
// Sha2 hash functions operate on messages and message blocks.
// Messages are created by padding the intput data and message
// blocks are created by splitting the message into 512 or 1024
// bit blocks.


// Dependencies
use std::convert::TryInto;



/// Trait to pad input data into Message Structs
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
pub struct Message(Vec<u8>);

impl Message {
    pub fn new(message: Vec<u8>) -> Message {
        Message(message)
    }
}

/// Message block struct
/// Message blocks are groups of 512 or 1024 bits. These bits are 
/// the bits that the main computations are performed on.
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
}

impl<const N: usize> From<&[u8]> for MessageBlock<N> {
    fn from(slice: &[u8]) -> MessageBlock<N> {
        let a: [u8; N] = slice.try_into().expect("Bad slice");
        MessageBlock(a)
    }
}