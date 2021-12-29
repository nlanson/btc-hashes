// HMAC Function Module
//
//
//  Todo:
//    - Implement midstate for HMAC by conceptually splitting the single engine into
//      two engines. The definition for a hmac function can be generalised as 
//              HMAC(K, m) = H((K' ^ opad) || H(K'^ipad || m))
//                  where K is the key
//                        m is the message
//                        H is the hash function
//                        ipad is a blocksized byte array of 0x36
//                        opad is a blocksized byte array of 0x5c
//
//      The function can be split into two hash engines, both with their own midstate
//      because there are two hash functions. The inner and the outer.
//


use crate::core::{
    HashEngine,
    KeyBasedHashEngine
};
use std::marker::PhantomData;


pub struct Hmac<T: HashEngine> {
    hash: PhantomData<T>,
    key: Vec<u8>,
    message: Vec<u8>
}

/// Struct used to represent the inner and outer hash midstates of a HMAC function
pub struct HmacMidState<T: HashEngine> {
    inner: T::Digest,
    outer: T::Digest
}

const OPAD: u8 = 0x5c;
const IPAD: u8 = 0x36;


impl<T: HashEngine> KeyBasedHashEngine for Hmac<T> {
    // this function/trait should not exist. it is unecessary and only causes problems as an API function. 
    // however, this trait is necessary for the PBKDF2 struct to restict what hash functions it can
    // take in so it stays until I can think of a better solution.
    //
    // changing the key after a message block has been processed by the inner hash function stuffs up
    // the state of the inner hash function.
    fn key<I>(&mut self, key: I)
    where I: AsRef<[u8]> {
        self.key.extend(key.as_ref());
    }
}


impl<T: HashEngine> HashEngine for Hmac<T> {
    type Digest = T::Digest;
    type Midsate = HmacMidState<T>;
    const BLOCKSIZE: usize = T::BLOCKSIZE;

    fn reset(&mut self) {
        self.key = vec![];
        self.message = vec![];
    }

    /// Add data to be used as part of the message
    fn input<I>(&mut self, data: I)
    where I: AsRef<[u8]> {
        self.message.extend(data.as_ref())
    }

    fn midstate(&self) -> Self::Midsate {
        unimplemented!();
    }

    fn from_midstate(&mut self, midstate: Self::Midsate) {
        unimplemented!();
    }

    fn finalise(&mut self) -> Self::Digest {
        let mut key = self.key.clone();
        if key.len() > Self::BLOCKSIZE {
            let mut e = T::default();
            e.input(key);
            key = e.finalise().into();
        }
        if key.len() < Self::BLOCKSIZE {
            let mut padding = vec![];
            padding.resize(Self::BLOCKSIZE-key.len(), 0x00);
            key.extend(padding);
        }
        assert_eq!(key.len(), Self::BLOCKSIZE);

        let opad_key: Vec<u8> = key.iter().map(|x| x^OPAD).collect();
        let ipad_key: Vec<u8> = key.iter().map(|x| x^IPAD).collect();
        
        
        // digest = hash(opad_key || hash(ipad_key || message))
        let mut e = T::default();
        e.input(ipad_key);
        e.input(self.message.clone());
        let h: Vec<u8> = e.finalise().into();
        e.reset();
        e.input(opad_key);
        e.input(h);
        e.finalise()
    }
}

impl<T: HashEngine> Default for Hmac<T> {
    fn default() -> Self {
        Self {
            hash: PhantomData::<T>,
            key: vec![],
            message: vec![]
        }
    }
}

impl<T: HashEngine> Hmac<T> {
    pub fn new<I>(key: I) -> Self
    where I: AsRef<[u8]> {
        Self {
            hash: PhantomData::<T>,
            key: key.as_ref().to_vec(),
            message: vec![]
        }
    }

    pub fn input_key<I>(&mut self, key: I) 
    where I: AsRef<[u8]> {
        self.key.extend(key.as_ref())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::HashEngine;
    use crate::Sha256;

    #[test]
    fn hmac_sha256() {
        let mut engine: Hmac<Sha256> = Hmac::new(b"key");
        engine.input(b"The quick brown fox jumps over the lazy dog");
        let digest = engine.finalise().iter().map(|x| format!("{:02x}", x)).collect::<String>();
        assert_eq!(digest, "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");
    }
}