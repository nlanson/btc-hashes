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
    /// (X & Y ) ^
    /// (!X & Z)
    pub fn choice(x: u32, y: u32, z: u32) -> u32 {
        todo!();
    }

    /// Majority
    /// (X & Y) ^
    /// (X & Z) ^
    /// (Y & Z)
    pub fn majority(x: u32, y: u32, z: u32) -> u32 {
        todo!();
    }

    /// Uppercase Sigma 0 (Σ0)
    /// RotR(X, 2)  ^
    /// RotR(X, 13) ^
    /// RotR(X, 22)
    pub fn usigma0(x: u32) -> u32 {
        todo!();
    }

    /// Uppercase Sigma 1 (Σ1)
    /// RotR(X, 6)  ^
    /// RotR(X, 11) ^
    /// RotR(X, 25)
    pub fn usigma1(x: u32) -> u32 {
        todo!();
    }

    /// Lowercase Sigma 0 (σ0)
    /// RotR(X, 7)  ^
    /// RotR(X, 18) ^
    /// ShR(X, 3)
    pub fn lsigma0(x: u32) -> u32 {
        todo!();
    }

    /// Lowercase Sigma 1 (σ1)
    /// RotR(X, 17) ^
    /// RotR(X, 19) ^
    /// ShR(X, 10)
    pub fn lsigma1(x: u32) -> u32 {
        todo!();
    }
}