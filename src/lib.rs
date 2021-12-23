// Another Rust implementation of the SHA2 hash family.
//
// Written in 2021 by
//  Noah Lanson
//
// Todo:
//    - Write
//        HMAC test cases (https://datatracker.ietf.org/doc/html/rfc4231#section-4)
//  
//    - RipeMD160
//          > Need to update MessageSchedule to accomadate for little-endian words and big-endian words
//            since sha2 uses big-endian words and ripemd160 uses little endian words.
//          > Unit tests
//
//    - Implement midstate extraction and starting a hash from a given midstate and data.
//          > This will change the order of how the hash engine hashes inputted data.
//            In order to extract midstate, the hash engine will need to hash data as it
//            is inputted. Upon input, if there is enough data to create a block, the block
//            is created and then processed. The result of the processed block in the state
//            is the midstate.
//            When the hash is to be finished, the hash engine will process the final block
//            which consists of any remaining data + padding + length bits.
//            This can make hashing things that contain the same starting data much more efficient
//            by allowing the custom specification of midstate data. (eg TapLeaf hashes)


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