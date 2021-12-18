use crate::{
    core::{
        HashEngine,
        State,
        functions::*,
        basic_hash_struct,
        default_function,
        input_function,
        reset_engine
    }
};

basic_hash_struct!(Ripemd160);

impl HashEngine for Ripemd160 {
    type Digest = [u8; 20];
    const BLOCKSIZE: usize = 64;


    default_function!();
    input_function!();
    reset_engine!();

    fn hash(&self) -> Self::Digest {
        // The RIPEMD160 page:
        // https://homes.esat.kuleuven.be/~bosselae/ripemd160.html#:~:text=RIPEMD%2D160%20is%20a%20160,Antoon%20Bosselaers%2C%20and%20Bart%20Preneel.&text=A%20128%2Dbit%20hash%20result,19%20evaluations%20of%20the%20function.
        //
        // steps:
        // 1. pad into t 16 word blocks where each word is 32 bits
        // 2. do the compression

        
        todo!();
    }
}