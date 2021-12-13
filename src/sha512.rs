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
        SHA512_INITIAL_CONSTANTS,
        SHA512_ROUND_CONSTANTS
    }
};
use std::convert::TryInto;

crate::core::hash_function!(Sha512, u64, 64, 16, 128, 80, 0, SHA512_INITIAL_CONSTANTS, SHA512_ROUND_CONSTANTS);

#[cfg(test)]
mod tests {
    use super::{
        HashEngine, Sha512
    };
    
    #[test]
    fn sha512() {
        let cases: Vec<(Vec<u8>, &str)> = vec![
            (vec![0x61, 0x62, 0x63], "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
            (vec![], "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),
            (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".to_vec(), "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445"),
            (b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".to_vec(), "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909")
        ];
        
        
        for case in cases {
            let mut hasher = Sha512::new();
            hasher.input(&case.0);
            let digest = hasher.hash().iter().map(|x| format!("{:02x}", x)).collect::<String>();
            assert_eq!(digest, case.1);
        }
    }
}