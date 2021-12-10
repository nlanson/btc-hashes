// Another Rust implementation of the SHA2 hash family.
//
// Written in 2021 by
//  Noah Lanson
//
// Todo:
//   - Data padding tests
//   - Message block from message tests
//   - Message schedule creation (words)
//   - The rest of the hash function...

// Code modules
mod constants;
mod core;
mod sha256;


/// API
pub use sha256::Sha256;