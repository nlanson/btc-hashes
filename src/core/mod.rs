// Core module
//
// Where all the core parts of the Sha2 hash function family reside.
// This can be done because most parts are shared between the different
// hash functions.
//
// Modules:
pub mod message;
pub mod functions;



/// Sha2Engine trait
/// Includes methods that all Sha2 hash functions share on a high level.
pub trait Sha2Engine {
    /// Input data into the engine.
    fn input<I>(&mut self, data: I) where I: Iterator<Item=u8>;

    /// Complete the hash with the inputted data.
    fn hash<const N: usize>(self) -> [u8; N];
}