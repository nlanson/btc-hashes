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

impl<T: Primitive> State<T> {
    pub fn new(values: [T; 8]) -> State<T> {
        State {
            registers: values
        }
    }

    pub fn read(&self) -> [T; 8] {
        self.registers
    }
}

pub trait Compression<T: Primitive, const N: usize> {
    /// Process a message schedule, completing N rounds of compression.
    fn compute_schedule(&mut self, schedule: MessageSchedule<T, N>, k: [T; N]);
}

impl<const N: usize> Compression<u32, N> for State<u32> {
    fn compute_schedule(&mut self, schedule: MessageSchedule<u32, N>, k: [u32; N]) {
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