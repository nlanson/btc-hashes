// The core api module is where methods that are shared accross all SHA2 hash functions
// will be.
//
// Since the difference between the different hash functions are only slight, the core
// api module can house code that is common accross all the functions.


/// Sha2Engine trait
/// Includes methods that all Sha2 hash functions share on a high level.
pub trait Sha2Engine {
    /// Input data into the engine.
    fn input<I>(&mut self, data: I) where I: AsRef<[u8]>;

    /// Complete the hash with the inputted data.
    fn hash<const N: usize>(self) -> [u8; N];
}

/// Functions module includes functions that are used by the Sha2 hashing family.
pub mod functions {
    /// Choice
    /// For each bit, if X is set, choose Y else choose Z.
    pub fn choice(x: u32, y: u32, z: u32) -> u32 {
        (x&y) ^ (!x&z)
    }

    /// Majority
    /// Takes which ever bit is the majority of the three
    pub fn majority(x: u32, y: u32, z: u32) -> u32 {
        (x&y) ^ (x&z) ^ (y&z)
    }

    /// Uppercase Sigma 0 (Σ0)
    pub fn usigma0(x: u32) -> u32 {
        x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
    }

    /// Uppercase Sigma 1 (Σ1)
    pub fn usigma1(x: u32) -> u32 {
        x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
    }

    /// Lowercase Sigma 0 (σ0)
    pub fn lsigma0(x: u32) -> u32 {
        x.rotate_right(6) ^ x.rotate_right(11) ^ (x>>3)
    }

    /// Lowercase Sigma 1 (σ1)
    pub fn lsigma1(x: u32) -> u32 {
        x.rotate_right(17) ^ x.rotate_right(19) ^ (x>>10)
    }
}