use std::convert::TryInto;

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
    ($words: expr, $func: ident, $buf: expr, $word_ord: expr, $rol_ord: expr, $const: expr) => {
        let mut buf: [&mut u32; 5] = $buf;
        for x in 0..16 {
            *buf[0] = buf[0].wrapping_add( $func(*buf[1], *buf[2], *buf[3]) ).wrapping_add($words[$word_ord[x]].value).wrapping_add($const);
            *buf[0] = buf[0].rotate_left($rol_ord[x]).wrapping_add(*buf[4]);
            *buf[2] = buf[2].rotate_left(10);
            buf.rotate_right(1);
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

        let message: Message<64> = Message::new(self.pad_input());
        let blocks: Vec<MessageBlock<{Self::BLOCKSIZE}>> = MessageBlock::from_message(message);
        let mut mdbuf: State<u32, 5> = State::init(RIPEMD160_INITIAL_CONSTANTS);
        for block in blocks {
            let mut schedule: MessageSchedule<u32, 16> = MessageSchedule::from(block);
            schedule.reverse_words(); //RIPEMD160 words are little endian
            let words = schedule.0;
            let buffer = mdbuf.read();
            let (mut aa, mut bb, mut cc, mut dd, mut ee) = (buffer[0], buffer[1], buffer[2], buffer[3], buffer[4]);
            let (mut aaa, mut bbb, mut ccc, mut ddd, mut eee) = (buffer[0], buffer[1], buffer[2], buffer[3], buffer[4]);

            /* round 1 */
            round!(
                words, f, [&mut aa, &mut bb, &mut cc, &mut dd, &mut ee],
                [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
                [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8],
                0x00000000
            );

            /* round 2 */
            round!(
                words, g, [&mut ee, &mut aa, &mut bb, &mut cc, &mut dd],
                [7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8],
                [7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12],
                0x5a827999
            );

            /* round 3 */
            round!(
                words, h, [&mut dd, &mut ee, &mut aa, &mut bb, &mut cc],
                [3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12],
                [11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5],
                0x6ed9eba1
            );

            /* round 4 */
            round!(
                words, i, [&mut cc, &mut dd, &mut ee, &mut aa, &mut bb],
                [1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2],
                [11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12],
                0x8f1bbcdc
            );

            /* round 5 */
            round!(
                words, j, [&mut bb, &mut cc, &mut dd, &mut ee, &mut aa],
                [4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13],
                [9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6],
                0xa953fd4e
            );

            /* parallel round 1 */
            round!(
                words, j, [&mut aaa, &mut bbb, &mut ccc, &mut ddd, &mut eee],
                [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12],
                [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6],
                0x50a28be6
            );

            /* parallel round 2 */
            round!(
                words, i, [&mut eee, &mut aaa, &mut bbb, &mut ccc, &mut ddd],
                [6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2],
                [9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11],
                0x5c4dd124
            );

            /* parallel round 3 */
            round!(
                words, h, [&mut ddd, &mut eee, &mut aaa, &mut bbb, &mut ccc],
                [15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13],
                [9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5],
                0x6d703ef3
            );

            /* parallel round 4 */
            round!(
                words, g, [&mut ccc, &mut ddd, &mut eee, &mut aaa, &mut bbb],
                [8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14],
                [15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8],
                0x7a6d76e9
            );

            /* parallel round 5 */
            round!(
                words, f, [&mut bbb, &mut ccc, &mut ddd, &mut eee, &mut aaa],
                [12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11],
                [8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11],
                0x00000000
            );

            
            // update state...
            let new_state: [u32; 5] = [
                ddd.wrapping_add(cc).wrapping_add(buffer[1]),
                buffer[2].wrapping_add(dd).wrapping_add(eee),
                buffer[3].wrapping_add(ee).wrapping_add(aaa),
                buffer[4].wrapping_add(aa).wrapping_add(bbb),
                buffer[0].wrapping_add(bb).wrapping_add(ccc)
            ];
            mdbuf.update(new_state);
        }

        mdbuf.read()
            .iter()
            .flat_map(|buf|
                buf.to_le_bytes()
            )
            .collect::<Vec<u8>>()
            .try_into()
            .expect("Bad digest")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ripemd160() {
        let cases: Vec<(Vec<u8>, &str)> = vec![
            (vec![], "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
            (b"a".to_vec(), "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
            (b"abc".to_vec(), "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
            (b"message digest".to_vec(), "5d0689ef49d2fae572b881b123a85ffa21595f36"),
            (b"abcdefghijklmnopqrstuvwxyz".to_vec(), "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"),
            (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".to_vec(), "12a053384a9c0c88e405a06c27dcf49ada62eb2b"),
            (b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".to_vec(), "b0e20b6e3116640286ed3a87a5713079b21f5189"),
            (b"12345678901234567890123456789012345678901234567890123456789012345678901234567890".to_vec(), "9b752e45573d4b39f4dbd3323cab82bf63326bfb")
        ];
        
        
        for case in cases {
            let mut hasher = Ripemd160::new();
            hasher.input(&case.0);
            let digest = hasher.hash().iter().map(|x| format!("{:02x}", x)).collect::<String>();
            assert_eq!(digest, case.1);
        }
    }
}