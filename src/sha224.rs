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
        state::{
            State,
            Compression
        }
    },
    constants::{
        SHA224_INITIAL_CONSTANTS,
        SHA256_ROUND_CONSTANTS
    }
};
use std::convert::TryInto;

crate::core::hash_function!(Sha224, u32, 28, 8, 64, 64, 1, SHA224_INITIAL_CONSTANTS, SHA256_ROUND_CONSTANTS);

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