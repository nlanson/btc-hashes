// Another Rust implementation of the SHA2 hash family.
//
// Written in 2021 by
//  Noah Lanson
//
// Todo:
//    - Extend the scope of this library to cover all Bitcoin hashes.
//      This includes:
//          RIPEMD-160
//          HMAC functions
//          PBKDF2
//  
//    - Reduce duplicate code in SHA2 module.

// Code modules
mod core;
mod constants;
mod sha2;


/// API
pub use crate::core::HashEngine;
pub use sha2::Sha224;
pub use sha2::Sha256;
pub use sha2::Sha384;
pub use sha2::Sha512;