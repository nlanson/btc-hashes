// The SHA224 module is where the SHA224 hash function is implemented.
//
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
        SHA224_INITIAL_CONSTANTS,
        SHA256_ROUND_CONSTANTS
    }
};
use std::convert::TryInto;


const SHA224_DIGEST_SIZE: usize = 28;
const SHA224_BLOCK_SIZE: usize = 64;

pub struct Sha224 {
    input: Vec<u8>
}

impl HashEngine<SHA224_DIGEST_SIZE, SHA224_BLOCK_SIZE> for Sha224 {
    fn new() -> Self {
        Sha224 {
            input: vec![]
        }
    }

    fn input(&mut self, data: &[u8]) {
        self.input.extend_from_slice(data);
    }

    fn read_input(self) -> Vec<u8> {
        self.input
    }

    fn hash(self) -> [u8; SHA224_DIGEST_SIZE] {
        let input = self.read_input();
        let message: Message<SHA224_BLOCK_SIZE> = Self::pad(input);
        let blocks: Vec<MessageBlock<SHA224_BLOCK_SIZE>> = MessageBlock::from_message(message);
        let mut state = State::new(SHA224_INITIAL_CONSTANTS);
        for block in blocks {
            let schedule: MessageSchedule<u32, SHA224_BLOCK_SIZE> = MessageSchedule::from(block);
            state.compute_schedule(schedule, SHA256_ROUND_CONSTANTS);
        }

        let state = &state.read()[0..SHA224_DIGEST_SIZE/4];
        let mut digest = vec![];
        for i in 0..state.len() {
            digest.extend(state[i].to_be_bytes());
        }
        digest.try_into().expect("Bad digest")
    }
}

impl Pad<SHA224_BLOCK_SIZE> for Sha224 { }


#[cfg(test)]
mod tests {
    use super::{
        HashEngine, Sha224
    };
    
    #[test]
    fn sha224() {
        let cases: Vec<(Vec<u8>, &str)> = vec![
            (vec![0x61, 0x62, 0x63], "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"),
            (vec![], "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"),
            (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".to_vec(), "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"),
            (b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".to_vec(), "c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3")
        ];
        
        
        for case in cases {
            let mut hasher = Sha224::new();
            hasher.input(&case.0);
            let digest = hasher.hash().iter().map(|x| format!("{:02x}", x)).collect::<String>();
            assert_eq!(digest, case.1);
        }
    }
}