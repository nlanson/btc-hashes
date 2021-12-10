// The SHA256 module is where the SHA256 hash function is implemented.
//

use crate::core::{
    Sha2Engine,
    message::{
        Pad,
        Message,
        MessageBlock
    },
    functions
};

const SHA256_BLOCK_SIZE: usize = 64;

pub struct Sha256 {
    input: Vec<u8>
}

impl Sha2Engine for Sha256 {
    fn input<I>(&mut self, data: I) where I: Iterator<Item=u8> {
        for i in data {
            self.input.push(i);
        }
    }

    fn hash<const N: usize>(self) -> [u8; N] {
        let message = self.pad();
        let blocks: Vec<MessageBlock<SHA256_BLOCK_SIZE>> = MessageBlock::from_message(message);

        todo!();
    }
}

impl Pad<SHA256_BLOCK_SIZE> for Sha256 {
    /// Takes in the input data for the hash and pads by:
    /// 
    /// 1. Appending a single set bit
    /// 2. Appending unset bits until the length is 64 bits less than a multiple of 512
    /// 3. Appending the length, L, of the original data in the last 64 bits
    /// 
    /// The message in the end should be a multiple of 512 in bits.
    fn pad(&self) -> Message {
        // Append 0x80 to the data then keep appending 0x00 until the length of the data modulo 64 is 56.
        // Then append the original length of the data. This makes the length of the message a multiple of 512 bits.
        let mut data = self.input.clone();
        let len = data.len().to_be_bytes();
        data.push(0x80);
        while data.len() % SHA256_BLOCK_SIZE != 56 {
            data.push(0x00);
        }
        data.extend(len);


        Message::new(data)
    }
}