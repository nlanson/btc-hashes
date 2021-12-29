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
        hash_struct,
        iconst_funcs,
        midstate_funcs,
        input_func,
        impl_default
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
use std::{
    convert::TryInto,
    mem::size_of_val
};

/// Macro to run the SHA2 compression accordingly for each hash function
macro_rules! sha2_compression {
    ($constants: expr, $schedule_length: expr, $base: ty) => {
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
                let t1: $base = <$base>::usigma1(e)
                    .wrapping_add(choice(e, f, g))
                    .wrapping_add(h)
                    .wrapping_add($constants[i])
                    .wrapping_add(schedule.0[i].value);
                
                let t2: $base = <$base>::usigma0(a)
                    .wrapping_add(majority(a, b, c));
                
                h = g;
                g = f;
                f = e;
                e = d;
                d = c;
                c = b;
                b = a;
                a = t1.wrapping_add(t2);
                e = e.wrapping_add(t1);
    
            }  
            
            // update the state
            let new_state: [$base; 8] = [
                _state[0].wrapping_add(a),
                _state[1].wrapping_add(b),
                _state[2].wrapping_add(c),
                _state[3].wrapping_add(d),
                _state[4].wrapping_add(e),
                _state[5].wrapping_add(f),
                _state[6].wrapping_add(g),
                _state[7].wrapping_add(h)
            ];
    
            state.update(new_state);
        }
    }
}

/// Macro to implement input padding for SHA2 hash functions
macro_rules! sha2_pad_fbuffer {
    () => {
        /// Pad the final buffer upon hash finalisation
        fn pad_fbuffer(&self) -> Message<{Self::BLOCKSIZE}> {
            let mut fmsg_data: Vec<u8> = if self.buffer.len() + size_of_val(&self.length) + 1 >= Self::BLOCKSIZE {
                Vec::with_capacity(Self::BLOCKSIZE*2)
            } else {
                Vec::with_capacity(Self::BLOCKSIZE)
            };
            fmsg_data.extend_from_slice(&self.buffer);
            fmsg_data.push(0x80);                             // append single '1' bit
            while fmsg_data.len()%Self::BLOCKSIZE != Self::BLOCKSIZE-size_of_val(&self.length) {
                fmsg_data.push(0x00);                         // pad with zeroes
            }
            fmsg_data.extend(self.length.to_be_bytes()); // append original data length
            assert_eq!(fmsg_data.len()%Self::BLOCKSIZE, 0);   // check the padded data mod blocksize is zero
    
            Message::new(fmsg_data)
        }
    };
}

/// Macro to implement hash finalisation for SHA2 hash functions
macro_rules! sha2_finalisation {
    ($digest_size: expr) => {
        fn finalise(&mut self) -> Self::Digest {
            assert!(self.buffer.len() <= Self::BLOCKSIZE); // check the buffer is less than or equal to one block size.
    
            // Get the final blocks
            let fblocks: Vec<MessageBlock<{Self::BLOCKSIZE}>> = MessageBlock::from_message(self.pad_fbuffer());
            
            assert!(fblocks.len() <= 2);
            for fblock in fblocks {
                Self::process_block(&mut self.state, fblock);
            }
    
            self.state.read()
                .iter()
                .rev()
                .skip(((self.state.read().len() * size_of_val(&self.state.read()[0])) - $digest_size) / size_of_val(&self.state.read()[0]))
                .flat_map( |reg|
                    reg.to_le_bytes()
                )
                .rev()
                .collect::<Vec<u8>>()
                .try_into()
                .expect("Bad digest")
        }
    }
}



// Define the 4 SHA2 hash function structs and implementations here
hash_struct!(Sha224, u64, u32, 8);
hash_struct!(Sha256, u64, u32, 8);
hash_struct!(Sha384, u128, u64, 8);
hash_struct!(Sha512, u128, u64, 8);

impl_default!(Sha224, SHA224_INITIAL_CONSTANTS);
impl_default!(Sha256, SHA256_INITIAL_CONSTANTS);
impl_default!(Sha384, SHA384_INITIAL_CONSTANTS);
impl_default!(Sha512, SHA512_INITIAL_CONSTANTS);

impl HashEngine for Sha224 {
    type Digest = [u8; 28];
    type Midsate = [u32; 8];
    const BLOCKSIZE: usize = 64;

    input_func!(u64);
    iconst_funcs!(SHA224_INITIAL_CONSTANTS);
    midstate_funcs!();
    sha2_finalisation!(28);
}

impl HashEngine for Sha256 {
    type Digest = [u8; 32];
    type Midsate = [u32; 8];
    const BLOCKSIZE: usize = 64;

    input_func!(u64);
    iconst_funcs!(SHA256_INITIAL_CONSTANTS);
    midstate_funcs!();
    sha2_finalisation!(32);
}

impl HashEngine for Sha384 {
    type Digest = [u8; 48];
    type Midsate = [u64; 8];
    const BLOCKSIZE: usize = 128;

    input_func!(u128);
    iconst_funcs!(SHA384_INITIAL_CONSTANTS);
    midstate_funcs!();
    sha2_finalisation!(48);
}

impl HashEngine for Sha512 {
    type Digest = [u8; 64];
    type Midsate = [u64; 8];
    const BLOCKSIZE: usize = 128;

    input_func!(u128);
    iconst_funcs!(SHA512_INITIAL_CONSTANTS);
    midstate_funcs!();
    sha2_finalisation!(64);
}

impl Sha224 {
    sha2_compression!(SHA256_ROUND_CONSTANTS, 64, u32);
    sha2_pad_fbuffer!();

    pub fn new() -> Self {
        Self::default()
    }
}

impl Sha256 {
    sha2_compression!(SHA256_ROUND_CONSTANTS, 64, u32);
    sha2_pad_fbuffer!();

    pub fn new() -> Self {
        Self::default()
    }
}

impl Sha384 {
    sha2_compression!(SHA512_ROUND_CONSTANTS, 80, u64);
    sha2_pad_fbuffer!();

    pub fn new() -> Self {
        Self::default()
    }
}

impl Sha512 {
    sha2_compression!(SHA512_ROUND_CONSTANTS, 80, u64);
    sha2_pad_fbuffer!();

    pub fn new() -> Self {
        Self::default()
    }
}




#[allow(unused_macros)]
macro_rules! sha2_hash_finalisation {
    ($digest_size: expr) => {
        assert!(self.buffer.len() <= Self::BLOCKSIZE); // check the buffer is less than or equal to one block size.

        // Get the final blocks
        let fblocks: Vec<MessageBlock<{Self::BLOCKSIZE}>> = {
            let mut fmsg_data: Vec<u8> = if self.buffer.len() + size_of_val(&self.length) + 1 >= Self::BLOCKSIZE {
                Vec::with_capacity(Self::BLOCKSIZE*2)
            } else {
                Vec::with_capacity(Self::BLOCKSIZE)
            };
            fmsg_data.extend_from_slice(&self.buffer);
            fmsg_data.push(0x80);                             // append single '1' bit
            while fmsg_data.len()%Self::BLOCKSIZE != Self::BLOCKSIZE-size_of_val(&self.length) {
                fmsg_data.push(0x00);                         // pad with zeroes
            }
            fmsg_data.extend(self.length.to_be_bytes()); // append original data length
            assert_eq!(fmsg_data.len()%Self::BLOCKSIZE, 0);   // check the padded data mod blocksize is zero

            MessageBlock::from_message(Message::new(fmsg_data))
        };
        
        
        assert!(fblocks.len() <= 2);
        for fblock in fblocks {
            Self::process_block(&mut self.state, fblock);
        }

        self.state.read()
            .iter()
            .rev()
            .skip(((self.state.read().len() * size_of_val(&self.state.read()[0])) - $digest_size) / size_of_val(&self.state.read()[0]))
            .flat_map( |reg|
                reg.to_le_bytes()
            )
            .rev()
            .collect::<Vec<u8>>()
            .try_into()
            .expect("Bad digest")
    };
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
            let digest = hasher.finalise().iter().map(|x| format!("{:02x}", x)).collect::<String>();
            assert_eq!(digest, case.1);
        }
    }

    #[test]
    fn sha256() {
        let cases: Vec<(Vec<u8>, &str)> = vec![
            (vec![0x61, 0x62, 0x63], "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            (b"0000000000000000000000000000000000000000000000000000000000000000".to_vec(), "60e05bd1b195af2f94112fa7197a5c88289058840ce7c6df9693756bc6250f55"),
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
            println!("Midstate = {:?}", hasher.midstate());
            let digest = hasher.finalise().iter().map(|x| format!("{:02x}", x)).collect::<String>();
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
            let digest = hasher.finalise().iter().map(|x| format!("{:02x}", x)).collect::<String>();
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
            let digest = hasher.finalise().iter().map(|x| format!("{:02x}", x)).collect::<String>();
            assert_eq!(digest, case.1);
        }
    }
}