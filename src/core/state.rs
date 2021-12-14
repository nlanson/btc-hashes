use crate::core::{
    Primitive,
    message::{
        MessageSchedule
    },
    functions::*
};

pub struct State<T: Primitive> {
    registers: [T; 8]
}

impl<T: Primitive+SigmaFunctions<T>> State<T> {
    pub fn new(values: [T; 8]) -> State<T> {
        State {
            registers: values
        }
    }

    pub fn read(&self) -> [T; 8] {
        self.registers
    }
}

/// Compression trait
/// Generics:
///     A: The algorithm
///     T: The integer type being operated on
///     N: Schedule length
pub trait Compression<T: Primitive, const N: usize> {
    /// Process a message schedule, completing N rounds of compression.
    fn compress(&mut self, schedule: MessageSchedule<T, N>, k: [T; N]);
}

// 32 bit SHA2 compression
impl Compression<u32, 64> for State<u32> {
    fn compress(&mut self, schedule: MessageSchedule<u32, 64>, k: [u32; 64]) {
        // read the state
        let state = self.registers;
        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        // compression rounds
        for i in 0..schedule.0.len(){
            let t1: u32 = (
                (
                    u32::usigma1(e) as u64 +
                    choice(e, f, g) as u64 +
                    h as u64+ k[i] as u64 +
                    schedule.0[i].value as u64
                ) %2u64.pow(32)
            )as u32;

            let t2: u32 = (
                (
                    u32::usigma0(a) as u64 +
                    majority(a, b, c) as u64
                ) % 2u64.pow(32)
            )as u32;
            
            h = g;
            g = f;
            f = e;
            e = d;
            d = c;
            c = b;
            b = a;
            a = ((t1 as u64 + t2 as u64) % 2u64.pow(32)) as u32;
            e = ((e as u64 + t1 as u64) % 2u64.pow(32)) as u32;

        }
        
        // update the state
        let new_state: [u32; 8] = [
            ((state[0] as u64 + a as u64)%2u64.pow(32)) as u32,
            ((state[1] as u64 + b as u64)%2u64.pow(32)) as u32,
            ((state[2] as u64 + c as u64)%2u64.pow(32)) as u32,
            ((state[3] as u64 + d as u64)%2u64.pow(32)) as u32,
            ((state[4] as u64 + e as u64)%2u64.pow(32)) as u32,
            ((state[5] as u64 + f as u64)%2u64.pow(32)) as u32,
            ((state[6] as u64 + g as u64)%2u64.pow(32)) as u32,
            ((state[7] as u64 + h as u64)%2u64.pow(32)) as u32
        ];
        self.registers = new_state;
    }
}

// 64 bit SHA2 compression
impl Compression<u64, 80> for State<u64> {
    fn compress(&mut self, schedule: MessageSchedule<u64, 80>, k: [u64; 80]) {
        // read the state
        let state = self.registers;
        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        // compression rounds
        for i in 0..schedule.0.len(){
            let t1: u64 = (
                (
                    u64::usigma1(e) as u128 +
                    choice(e, f, g) as u128 +
                    h as u128 +
                    k[i] as u128 +
                    schedule.0[i].value as u128
                ) %2u128.pow(64)
            )as u64;

            let t2: u64 = (
                (
                    u64::usigma0(a) as u128 +
                    majority(a, b, c) as u128
                ) % 2u128.pow(64)
            )as u64;
            
            h = g;
            g = f;
            f = e;
            e = d;
            d = c;
            c = b;
            b = a;
            a = ((t1 as u128 + t2 as u128) % 2u128.pow(64)) as u64;
            e = ((e as u128 + t1 as u128) % 2u128.pow(64)) as u64;

        }
        
        // update the state
        let new_state: [u64; 8] = [
            ((state[0] as u128 + a as u128)%2u128.pow(64)) as u64,
            ((state[1] as u128 + b as u128)%2u128.pow(64)) as u64,
            ((state[2] as u128 + c as u128)%2u128.pow(64)) as u64,
            ((state[3] as u128 + d as u128)%2u128.pow(64)) as u64,
            ((state[4] as u128 + e as u128)%2u128.pow(64)) as u64,
            ((state[5] as u128 + f as u128)%2u128.pow(64)) as u64,
            ((state[6] as u128 + g as u128)%2u128.pow(64)) as u64,
            ((state[7] as u128 + h as u128)%2u128.pow(64)) as u64
        ];
        self.registers = new_state;
    }
}