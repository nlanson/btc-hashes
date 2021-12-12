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
//          > this includes updating the rotational and shift values of the sigma functions
//            and creating and implementing hash engine struct and traits for the other
//            functions.
//   - Look into generalizing the [`HashEngine::hash()`] method.

// Code modules
mod core;
mod constants;
mod sha256;
mod sha224;


/// API
pub use crate::core::HashEngine;
pub use sha256::Sha256;
pub use sha224::Sha224;