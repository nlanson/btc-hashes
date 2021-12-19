// Another Rust implementation of the SHA2 hash family.
//
// Written in 2021 by
//  Noah Lanson
//
// Todo:
//    - Write
//        RIPEMD-160
//        HMAC test cases (https://datatracker.ietf.org/doc/html/rfc4231#section-4)
//  
//    - Reduce duplicate code in SHA2 module.
//
//    - Implement midstate extraction and starting a hash from a given midstate and data.

// Code modules
mod core;
mod constants;
mod sha2;
mod ripemd;
mod hmac;
mod pbkdf2;


/// API
pub use crate::core::HashEngine;
pub use crate::core::KeyBasedHashEngine;
pub use sha2::Sha224;
pub use sha2::Sha256;
pub use sha2::Sha384;
pub use sha2::Sha512;
pub use hmac::Hmac;
pub use pbkdf2::PBKDF2;