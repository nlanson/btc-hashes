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
        SHA384_INITIAL_CONSTANTS,
        SHA512_ROUND_CONSTANTS
    }
};
use std::convert::TryInto;

crate::core::hash_function!(Sha384, u64, 48, 16, 128, 80, 2, SHA384_INITIAL_CONSTANTS, SHA512_ROUND_CONSTANTS);

#[cfg(test)]
mod tests {
    use super::{
        HashEngine, Sha384
    };
    
    #[test]
    fn sha384() {
        let cases: Vec<(Vec<u8>, &str)> = vec![
            (vec![0x61, 0x62, 0x63], "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"),
            (vec![], "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"),
            (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".to_vec(), "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b"),
            (b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".to_vec(), "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039")
        ];
        
        
        for case in cases {
            let mut hasher = Sha384::new();
            hasher.input(&case.0);
            let digest = hasher.hash().iter().map(|x| format!("{:02x}", x)).collect::<String>();
            assert_eq!(digest, case.1);
        }
    }
}