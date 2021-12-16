// Another Rust implementation of the SHA2 hash family.
//
// Written in 2021 by
//  Noah Lanson
//
// Todo:
//    - Write
//        RIPEMD-160
//        PBKDF2
//        HMAC test cases
//  
//    - Reduce duplicate code in SHA2 module.

// Code modules
mod core;
mod constants;
mod sha2;
mod hmac;


/// API
pub use crate::core::HashEngine;
pub use sha2::Sha224;
pub use sha2::Sha256;
pub use sha2::Sha384;
pub use sha2::Sha512;