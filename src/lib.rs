// Another Rust implementation of the SHA2 hash family.
//
// Written in 2021 by
//  Noah Lanson
//
// Todo:
//   - Data padding tests
//   - Message block from message tests
//   - Message schedule creation tests
//   - Compression functions for each message block
//   - Apply logic into Sha 224, 384 and 512

// Code modules
mod constants;
mod core;
mod sha256;


/// API
pub use sha256::Sha256;