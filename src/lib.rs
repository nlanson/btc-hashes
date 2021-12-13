// Another Rust implementation of the SHA2 hash family.
//
// Written in 2021 by
//  Noah Lanson
//
// Todo:
//   - SHA-384

// Code modules
mod core;
mod constants;
mod sha224;
mod sha256;
mod sha512;


/// API
pub use crate::core::HashEngine;
pub use sha256::Sha256;
pub use sha224::Sha224;
pub use sha512::Sha512;