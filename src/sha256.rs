// The SHA256 module is where the SHA256 hash function is implemented.
//

use crate::core::{
    Sha2Engine,
    functions
};

pub struct Sha256 {

}

impl Sha2Engine for Sha256 {
    fn input<I>(&mut self, data: I) where I: AsRef<[u8]> {

        todo!();
    }

    fn hash<const N: usize>(self) -> [u8; N] {

        todo!();
    }
}