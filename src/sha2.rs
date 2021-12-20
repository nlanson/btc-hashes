// The SHA2 module is where the SHA2 hash function family is implemented
//
use crate::{
    core::{
        message::{
            Message,
            MessageBlock,
            MessageSchedule
        },
        HashEngine,
        State,
        functions::sha2::*,
        basic_hash_struct,
        default_function,
        input_function,
        reset_engine
    },
    constants::{
        SHA224_INITIAL_CONSTANTS,
        SHA256_INITIAL_CONSTANTS,
        SHA384_INITIAL_CONSTANTS,
        SHA512_INITIAL_CONSTANTS,
        SHA256_ROUND_CONSTANTS,
        SHA512_ROUND_CONSTANTS
    },
    
};
use std::convert::TryInto;



/// Macro to pad SHA2 hash engine inputs according to each hash function.
macro_rules! sha2_input_padding {
    ($length_ty: ty, $blocksize: expr) => {
        fn pad_input(&self) -> Vec<u8> {
            let mut data = self.input.clone();
            let length: $length_ty = (data.len()*8) as $length_ty;
            data.push(0x80);
            while data.len() % $blocksize != $blocksize-((<$length_ty>::BITS/8)as usize) {
                data.push(0x00);
            }
            data.extend(length.to_be_bytes());
            data
        }
    };
}

/// Macro to run the SHA2 compression accordingly for each hash function
macro_rules! sha2_compression {
    ($constants: expr, $schedule_length: expr, $base: ty, $extended: ty, $modulo: expr) => {
        fn process_block(state: &mut State<$base, 8>, block: MessageBlock<{Self::BLOCKSIZE}>) {
            let schedule: MessageSchedule<$base, $schedule_length> = MessageSchedule::from(block);
            let _state = state.read();
            let mut a = _state[0];
            let mut b = _state[1];
            let mut c = _state[2];
            let mut d = _state[3];
            let mut e = _state[4];
            let mut f = _state[5];
            let mut g = _state[6];
            let mut h = _state[7];
            
            for i in 0..$schedule_length {
                let t1: $base = (
                    (
                        <$base>::usigma1(e) as $extended +
                        choice(e, f, g) as $extended +
                        h as $extended +
                        $constants[i] as $extended +
                        schedule.0[i].value as $extended
                    ) %(2 as $extended).pow($modulo)
                ) as $base;
    
                let t2: $base = (
                    (
                        <$base>::usigma0(a) as $extended +
                        majority(a, b, c) as $extended
                    ) % (2 as $extended).pow($modulo)
                ) as $base;
                
                h = g;
                g = f;
                f = e;
                e = d;
                d = c;
                c = b;
                b = a;
                a = ((t1 as $extended + t2 as $extended) % (2 as $extended).pow($modulo)) as $base;
                e = ((e as $extended + t1 as $extended) % (2 as $extended).pow($modulo)) as $base;
    
            }  
            
            // update the state
            let new_state: [$base; 8] = [
                ((_state[0] as $extended + a as $extended)%(2 as $extended).pow($modulo)) as $base,
                ((_state[1] as $extended + b as $extended)%(2 as $extended).pow($modulo)) as $base,
                ((_state[2] as $extended + c as $extended)%(2 as $extended).pow($modulo)) as $base,
                ((_state[3] as $extended + d as $extended)%(2 as $extended).pow($modulo)) as $base,
                ((_state[4] as $extended + e as $extended)%(2 as $extended).pow($modulo)) as $base,
                ((_state[5] as $extended + f as $extended)%(2 as $extended).pow($modulo)) as $base,
                ((_state[6] as $extended + g as $extended)%(2 as $extended).pow($modulo)) as $base,
                ((_state[7] as $extended + h as $extended)%(2 as $extended).pow($modulo)) as $base
            ];
    
            state.update(new_state);
        }
    };
}

#[allow(unused_macros)]
macro_rules! impl_hash_engine_sha2 {
    (
        $name: ident, $digest_size: expr, $blocksize: expr, $word_ty: ty, $consts: expr
    ) => {
        impl HashEngine for $name {
            type Digest = [u8; $digest_size];
            const BLOCKSIZE: usize = $blocksize;

            default_function!();
            input_function!();
            reset_engine!();

            fn hash(&self) -> Self::Digest {
                let message: Message<{Self::BLOCKSIZE}> = Message::new(self.pad_input());
                let blocks: Vec<MessageBlock<{Self::BLOCKSIZE}>> = MessageBlock::from_message(message);
                let mut state: State<$word_ty, 8> = State::init($consts);
                for block in blocks {
                    Self::process_block(&mut state, block);
                }

                // Collecting  the required state by omitting unused state registers
                // This is done by reversing the state, skipping required bytes,     *(Skip value = (state bytes - digest bytes) / word bytes)
                // concatenating each word in little endian then reversing the little
                // endian collection again.
                //
                // This is more efficient than the previous method of converting
                // every word in the state into bytes then excluding unused bytes
                // because unused words are not converted in the first place.
                //      let mut digest = vec![];
                //      for h in state.read() {
                //          digest.extend(h.to_be_bytes());
                //      }
                //      digest[..$digest_size].try_into().expect("Bad State")
                state.read()
                    .iter()
                    .rev()
                    .skip(((state.read().len() * <$word_ty>::BITS as usize/8) - $digest_size) / (<$word_ty>::BITS/8) as usize)
                    .flat_map( |reg|
                        reg.to_le_bytes()
                    )
                    .rev()
                    .collect::<Vec<u8>>()
                    .try_into()
                    .expect("Bad digest")
            }
        }
    };
}

// Define the four SHA2 Hash functions and their block size
basic_hash_struct!(Sha224);
basic_hash_struct!(Sha256);    const SHA256_BLOCKSIZE: usize = 64;
basic_hash_struct!(Sha384);
basic_hash_struct!(Sha512);    const SHA512_BLOCKSIZE: usize = 128;

// Implement the hash engine trait for the SHA2 hash functions
impl_hash_engine_sha2!(Sha224, 28, SHA256_BLOCKSIZE, u32, SHA224_INITIAL_CONSTANTS);
impl_hash_engine_sha2!(Sha256, 32, SHA256_BLOCKSIZE, u32, SHA256_INITIAL_CONSTANTS);
impl_hash_engine_sha2!(Sha384, 48, SHA512_BLOCKSIZE, u64, SHA384_INITIAL_CONSTANTS);
impl_hash_engine_sha2!(Sha512, 64, SHA512_BLOCKSIZE, u64, SHA512_INITIAL_CONSTANTS);


impl Sha224 {
    sha2_input_padding!(u64, SHA256_BLOCKSIZE);
    sha2_compression!(SHA256_ROUND_CONSTANTS, 64, u32, u64, 32);
}

impl Sha256 {
    sha2_input_padding!(u64, SHA256_BLOCKSIZE);
    sha2_compression!(SHA256_ROUND_CONSTANTS, 64, u32, u64, 32);
}

impl Sha384 {
    sha2_input_padding!(u128, SHA512_BLOCKSIZE);
    sha2_compression!(SHA512_ROUND_CONSTANTS, 80, u64, u128, 64);
}

impl Sha512 {
    sha2_input_padding!(u128, SHA512_BLOCKSIZE);
    sha2_compression!(SHA512_ROUND_CONSTANTS, 80, u64, u128, 64);
}





#[cfg(test)]
mod tests {
    use super::{HashEngine, Sha224, Sha256, Sha384, Sha512};

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