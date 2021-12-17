use crate::core::{HashEngine, KeyBasedHashEngine};
use std::marker::PhantomData;


pub struct Hmac<T: HashEngine> {
    hash: PhantomData<T>,
    key: Vec<u8>,
    message: Vec<u8>
}

const OPAD: u8 = 0x5c;
const IPAD: u8 = 0x36;

impl<T: HashEngine> KeyBasedHashEngine for Hmac<T> {
    /// Add data to be used as the key
    fn key<I>(&mut self, data: I)
    where I: AsRef<[u8]> {
        self.key.extend(data.as_ref())
    }
}

impl<T: HashEngine> HashEngine for Hmac<T> {
    type Digest = T::Digest;
    const BLOCKSIZE: usize = T::BLOCKSIZE;
    
    fn new() -> Self {
        Self {
            hash: PhantomData,
            key: vec![],
            message: vec![]
        }
    }

    fn reset(&mut self) {
        self.key = vec![];
        self.message = vec![];
    }

    /// Add data to be used as part of the message
    fn input<I>(&mut self, data: I)
    where I: AsRef<[u8]> {
        self.message.extend(data.as_ref())
    }

    fn hash(&self) -> Self::Digest {
        let mut key = self.key.clone();
        if key.len() > Self::BLOCKSIZE {
            let mut e = T::new();
            e.input(key);
            key = e.hash().into();
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
        let mut e = T::new();
        e.input(ipad_key);
        e.input(self.message.clone());
        let h: Vec<u8> = e.hash().into();
        e.reset();
        e.input(opad_key);
        e.input(h);
        e.hash()
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::Sha256;

    #[test]
    fn hmac_sha256() {
        let mut engine: Hmac<Sha256> = Hmac::new();
        engine.key(b"key");
        engine.input(b"The quick brown fox jumps over the lazy dog");
        let digest = engine.hash().iter().map(|x| format!("{:02x}", x)).collect::<String>();
        assert_eq!(digest, "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");
    }
}