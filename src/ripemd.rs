use crate::{
    core::{
        message::{
            Message,
            MessageBlock
        },
        HashEngine,
        State,
        functions::ripemd160,
        basic_hash_struct,
        default_function,
        input_function,
        reset_engine
    }
};

basic_hash_struct!(Ripemd160);

impl Ripemd160 {
    fn pad_input(&self) -> Vec<u8> {
        let mut input = self.input.clone();
        let len = (input.len()*8) as u64;
        input.push(0x80);
        while self.input.len() % 64 != 56 {
            input.push(0x00);
        }
        input.extend(len.to_le_bytes());    // RIPEMD-160 padding denotes the message length in 64 bit little endian.

        input
    }
}

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
        // 1. Pad into t 16 word blocks where each word is 32 bits
        // 2. Do the compression which consists of:
        //      Initializing a buffer with 5 constants.
        //      Then for each block, copy the buffer values into variables (A,B,C,D,E) and (A',B',C',D',E')
        //      and run 80 rounds of compression on each set of variables. The round details can be found in
        //      the above link.
        //      The primed and non-primed set of variables run through different compression in parallel.
        //
        //      The buffer is then set to the following
        //          D' += C + MDbuf[1];
        //          MDbuf[1] = MDbuf[2] + D + E';
        //          MDbuf[2] = MDbuf[3] + E + A';
        //          MDbuf[3] = MDbuf[4] + A + B';
        //          MDbuf[4] = MDbuf[0] + B + C';
        //          MDbuf[0] = D';
        //      where '+' denotes integer addition modulo 32.
        //
        //      The next block follows...

        let message: Message<64> = Message::new(self.pad_input());
        let blocks: Vec<MessageBlock<64>> = MessageBlock::from_message(message);

        todo!();
    }
}