// Another Rust implementation of the SHA2 hash family.
//
// Written in 2021 by
//  Noah Lanson
//
// Todo:
//   - Hash engine data stores (prior to hash finalization)
//   - Data padding (512 bit for SHA256)
//   - The rest of the hash function...

// Code modules
mod constants;
mod core;
mod sha256;


/// API
pub use sha256::Sha256;