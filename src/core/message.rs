// The message module
//
// Sha2 hash functions operate on messages and message blocks.
// Messages are created by padding the intput data and message
// blocks are created by splitting the message into 512 or 1024
// bit blocks.


use crate::core::{
    functions::sha2::SigmaFunctions,
    Primitive
};


/// Message struct
///
/// The message is the original data followed by padding.
/// Generics:
///     N: The length of the message mod N should be zero.
#[derive(Debug)]
pub struct Message<const N: usize>(pub Vec<u8>);

impl<const N: usize> Message<N> {
    pub fn new(message: Vec<u8>) -> Message<N> {
        assert_eq!(message.len()%N,  0);
        Message(message)
    }
}


/// Message block struct.
/// 
/// Message blocks are groups of 512 or 1024 bits.
/// Generics:
///     N: The message block must be N bytes long
#[derive(Debug, Copy, Clone)]
pub struct MessageBlock<const N: usize>(pub [u8; N]);

impl<const N: usize> MessageBlock<N> {
    /// Create message blocks from a message.
    /// Message blocks are split into N byte chunks where N is either 64 or 128
    /// depending on the hash function being used.
    pub fn from_message(message: Message<N>) -> Vec<MessageBlock<N>> {
        message.0
            .chunks(N)
            .into_iter()
            .map(|chunk| MessageBlock::from(chunk))
            .collect()
    }
}

impl<const N: usize> From<&[u8]> for MessageBlock<N> {
    fn from(slice: &[u8]) -> MessageBlock<N> {
        let mut a = [0u8; N];
        a.copy_from_slice(slice);

        MessageBlock(a)
    }
}


/// Message schedule struct
/// 
/// The message schedule is an array of words of lengthg 64 or 80.
/// Generics:
///     T: The integer type being operated on  (u32 or u64)
///     N: The amount of words in each schedule (64 for 32bit and 80 for 64 bit)
#[derive(Debug)]
pub struct MessageSchedule<T: Primitive, const N: usize>(pub [Word<T>; N]);

// 32 bit message schedule
impl<const N: usize, const W: usize> From<MessageBlock<N>> for MessageSchedule<u32, W> {
    fn from(block: MessageBlock<N>) -> MessageSchedule<u32, W> {
        // Create the initial 16 words from the message block
        let mut words: Vec<Word<u32>> = block.0
            .chunks(4)
            .into_iter()
            .map(|chnk_slc| { //Words are big endian.
                let mut chunk = [0u8; 4];
                chunk.copy_from_slice(chnk_slc);
                chunk.reverse();
                Word::new(unsafe { std::mem::transmute(chunk) })
            })
            .collect();

        // Extend the intial schedule to 64 words
        // W[i] = σ1(W[i−2]) + W[i−7] + σ0(W[i−15]) + W[i−16]
        // This loop is only entered when computing a SHA224 or SHA256 schedule.
        for i in 16..W {
            let value: u32 = (
                (
                    u32::lsigma1(words[i-2].value)  as u64 +
                    words[i-7].value                as u64 +
                    u32::lsigma0(words[i-15].value) as u64 +
                    words[i-16].value               as u64
                ) % 2u64.pow(32)
            ) as u32;
            
            words.push(Word::new(value));
        }

        assert_eq!(words.len(), W);
        let mut schedule_words = [Word::new(0); W];
        schedule_words.copy_from_slice(&words);
        MessageSchedule(schedule_words)
    }
}


// 64 bit message schedule
impl<const N: usize, const W: usize> From<MessageBlock<N>> for MessageSchedule<u64, W> {
    fn from(block: MessageBlock<N>) -> MessageSchedule<u64, W> {
        // Create the initial 16 words from the message block
        let mut words: Vec<Word<u64>> = block.0
            .chunks(8)
            .into_iter()
            .map(|chnk_slc| {
                let mut chunk = [0u8; 8];
                chunk.copy_from_slice(chnk_slc);
                chunk.reverse();
                Word::new(unsafe { std::mem::transmute(chunk) })
            })
            .collect();

        // Extend the intial schedule to 64 words
        // W[i] = σ1(W[i−2]) + W[i−7] + σ0(W[i−15]) + W[i−16]
        // This loop is only entered when computing a SHA384 or SHA512 schedule.
        for i in 16..W {
            let value: u64 = (
                (
                    u64::lsigma1(words[i-2].value)  as u128 +
                    words[i-7].value                as u128 +
                    u64::lsigma0(words[i-15].value) as u128 +
                    words[i-16].value               as u128
                ) % 2u128.pow(64)
            ) as u64;
            
            words.push(Word::new(value));
        }

        assert_eq!(words.len(), W);
        let mut schedule_words = [Word::new(0); W];
        schedule_words.copy_from_slice(&words);
        MessageSchedule(schedule_words)
    }
}

impl<const N: usize> MessageSchedule<u32, N> {
    /// Reverse the endian ness for each word in the schedule.
    /// Used in RIPEMD160
    pub fn reverse_words(&mut self) {        
        for word in self.0.iter_mut() {
            *word = Word::new(word.value.swap_bytes());
        }
    }
}

/// Word struct
/// 
/// The value in a word can be either a 32 or 64 bit integer, hence the
/// generic constraint for integers is applied.
#[derive(Copy, Clone, Debug)]
pub struct Word<T: Primitive> {
    pub value: T
}

impl<T: Primitive> Word<T> {
    pub fn new(value: T) -> Word<T> {
        Word { value }
    }
}