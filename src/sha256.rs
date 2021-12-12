// The SHA256 module is where the SHA256 hash function is implemented.
//

use std::convert::TryInto;

use crate::{
    core::{
        HashEngine,
        message::{
            Pad,
            Message,
            MessageBlock,
            MessageSchedule
        },
        state::{State, Compression}
    },
    constants::{
        SHA256_INITIAL_CONSTANTS,
        SHA256_ROUND_CONSTANTS
    }
};

const SHA256_DIGEST_SIZE: usize = 32;
const SHA256_BLOCK_SIZE: usize = 64;

pub struct Sha256 {
    input: Vec<u8>
}

impl HashEngine<SHA256_DIGEST_SIZE> for Sha256 {
    fn new() -> Self {
        Sha256 {
            input: vec![]
        }
    }

    fn input(&mut self, data: &[u8]) {
        self.input.extend_from_slice(data);
    }

    fn read_input(self) -> Vec<u8> {
        self.input
    }

    fn hash(self) -> [u8; SHA256_DIGEST_SIZE] {
        let input = self.read_input();
        let message: Message<SHA256_BLOCK_SIZE> = Self::pad(input);
        let blocks: Vec<MessageBlock<SHA256_BLOCK_SIZE>> = MessageBlock::from_message(message);
        let mut state = State::new(SHA256_INITIAL_CONSTANTS);
        for block in blocks {
            let schedule: MessageSchedule<u32, SHA256_BLOCK_SIZE> = MessageSchedule::from(block);
            state.compute_schedule(schedule, SHA256_ROUND_CONSTANTS);
        }

        let mut result: Vec<u8> = vec![];
        for val in state.read() {
            result.extend(val.to_be_bytes());
        }
        result.try_into().expect("Invalid digest length")
    }
}

impl Pad<SHA256_BLOCK_SIZE> for Sha256 { }

#[cfg(test)]
mod tests {
    use super::{
        HashEngine, Sha256
    };
    
    #[test]
    fn sha256() {
        let mut hasher = Sha256::new();
        hasher.input(b"abc");
        
        let digest_string = hasher.hash().iter().map(|x| { format!("{:02x}", x) }).collect::<String>();
        assert_eq!(digest_string, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    }
}