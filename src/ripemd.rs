use crate::{
    core::{
        message::{
            Message,
            MessageBlock,
            MessageSchedule,
            Word
        },
        HashEngine,
        State,
        functions::ripemd160::*,
        basic_hash_struct,
        default_function,
        input_function,
        reset_engine
    },
    constants::RIPEMD160_INITIAL_CONSTANTS
};

basic_hash_struct!(Ripemd160);

impl Ripemd160 {
    fn pad_input(&self) -> Vec<u8> {
        let mut input = self.input.clone();
        let len = (input.len()*8) as u64;
        input.push(0x80);
        while input.len() % 64 != 56 {
            input.push(0x00);
        }
        input.extend(len.to_le_bytes());    // RIPEMD-160 padding denotes the message length in 64 bit little endian.

        input
    }
}

macro_rules! round {
    ($func: ident, $a: expr, $b: expr, $c: expr, $d: expr, $e: expr, $word: expr, $const: expr, $rol: expr) => {        
        $a = $a.wrapping_add($func($b, $c, $d).wrapping_add($word).wrapping_add($const));
        $a = $a.rotate_left($rol).wrapping_add($e);
        $c = $c.rotate_left(10);
    };
}

macro_rules! round_block {
    ($words: expr, $func: ident, $buf: expr, $word_ord: expr, $rol_vals: expr, $const: expr) => {
        for x in 0..15 {
            round!($func, *$buf[0], *$buf[1], *$buf[2], *$buf[3], *$buf[4], $words[$word_ord[x]].value, $const, $rol_vals[x]);
            $buf.rotate_right(1);
        }
    };
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
        let mut mdbuf: State<u32, 5> = State::init(RIPEMD160_INITIAL_CONSTANTS);
        for block in blocks {
            let words: [Word<u32>; 16] = MessageSchedule::from(block).0;
            let buffer = mdbuf.read();
            let (mut aa, mut bb, mut cc, mut dd, mut ee) = (buffer[0], buffer[1], buffer[2], buffer[3], buffer[4]);
            let (mut aaa, mut bbb, mut ccc, mut ddd, mut eee) = (buffer[0], buffer[1], buffer[2], buffer[3], buffer[4]);

            /* round 1 */
            round_block!(
                words, f, [&mut aa, &mut bb, &mut cc, &mut dd, &mut ee],
                [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
                [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8],
                0x00000000
            );

            /* round 2 */
            round_block!(
                words, g, [&mut ee, &mut aa, &mut bb, &mut cc, &mut dd],
                [7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8],
                [7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12],
                0x5a827999
            );

            /* round 3 */
            round_block!(
                words, h, [&mut dd, &mut ee, &mut aa, &mut bb, &mut cc],
                [3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12],
                [11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5],
                0x6ed9eba1
            );

            /* round 4 */
            round_block!(
                words, i, [&mut cc, &mut dd, &mut ee, &mut aa, &mut bb],
                [1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2],
                [11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12],
                0x8f1bbcdc
            );

            /* round 5 */
            round_block!(
                words, j, [&mut bb, &mut cc, &mut dd, &mut ee, &mut aa],
                [4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13],
                [9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6],
                0xa953fd4e
            );

            // run paralell rounds JJJ through to FFF...

            
            //update state...
            // ddd += cc + MDbuf[1];               /* final result for MDbuf[0] */
            // MDbuf[1] = MDbuf[2] + dd + eee;
            // MDbuf[2] = MDbuf[3] + ee + aaa;
            // MDbuf[3] = MDbuf[4] + aa + bbb;
            // MDbuf[4] = MDbuf[0] + bb + ccc;
            // MDbuf[0] = ddd;
            
        }

        todo!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ripemd160() {
        let mut e = Ripemd160::new();
        e.input(b"abc");
        e.hash();
    }
}