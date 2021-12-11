// The SHA256 module is where the SHA256 hash function is implemented.
//

use crate::core::{
    HashEngine,
    message::{
        Pad,
        Message,
        MessageBlock,
        MessageSchedule
    }
};

const SHA256_BLOCK_SIZE: usize = 64;

pub struct Sha256 {
    input: Vec<u8>
}

impl HashEngine<SHA256_BLOCK_SIZE> for Sha256 {
    fn input<I>(&mut self, data: I) where I: Iterator<Item=u8> {
        for i in data {
            self.input.push(i);
        }
    }

    fn read_input(self) -> Vec<u8> {
        self.input
    }

    fn hash(self) -> [u8; SHA256_BLOCK_SIZE] {
        let message: Message<SHA256_BLOCK_SIZE> = Self::pad(self.read_input());
        let blocks: Vec<MessageBlock<SHA256_BLOCK_SIZE>> = MessageBlock::from_message(message);
        for block in blocks {
            let schedule: MessageSchedule<u32, SHA256_BLOCK_SIZE> = MessageSchedule::from(block);

            //compression with state registers...
        }

        todo!();
    
    }
}

impl Pad<SHA256_BLOCK_SIZE> for Sha256 { }