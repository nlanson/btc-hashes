// The SHA256 module is where the SHA256 hash function is implemented.
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
        SHA256_INITIAL_CONSTANTS,
        SHA256_ROUND_CONSTANTS
    }
};
use std::convert::TryInto;

crate::core::hash_function!(Sha256, u32, 32, 8, 64, 64, 0, SHA256_INITIAL_CONSTANTS, SHA256_ROUND_CONSTANTS);

#[cfg(test)]
mod tests {
    use super::{
        HashEngine, Sha256
    };
    
    #[test]
    fn sha256() {
        let cases: Vec<(Vec<u8>, &str)> = vec![
            (vec![0x61, 0x62, 0x63], "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            (vec![
                0x61 ,0x62, 0x63, 0x64, 0x62, 0x63, 0x64, 0x65, 0x63, 0x64, 0x65, 0x66, 0x64, 0x65, 0x66, 0x67, 0x65, 0x66, 0x67, 0x68, 0x66, 0x67, 0x68, 0x69, 0x67,
                0x68, 0x69, 0x6a, 0x68, 0x69, 0x6a, 0x6b, 0x69, 0x6a, 0x6b, 0x6c, 0x6a, 0x6b, 0x6c, 0x6d, 0x6b, 0x6c, 0x6d, 0x6e, 0x6c, 0x6d, 0x6e, 0x6f, 0x6d, 0x6e,
                0x6f, 0x70, 0x6e, 0x6f, 0x70, 0x71],
             "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
            (vec![], "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".to_vec(), "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
            (b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".to_vec(), "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1")
        ];
        
        
        for case in cases {
            let mut hasher = Sha256::new();
            hasher.input(&case.0);
            let digest = hasher.hash().iter().map(|x| format!("{:02x}", x)).collect::<String>();
            assert_eq!(digest, case.1);
        }
    }
}