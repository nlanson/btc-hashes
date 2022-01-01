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

const OPAD: u8 = 0x5c;
const IPAD: u8 = 0x36;

pub struct Hmac<T: HashEngine> {
    inner: T,
    outer: T,
    istate: HmacMidState<T>,
    msg_buffer: Vec<u8>
}

/// Struct used to represent the inner and outer hash midstates of a HMAC function
#[derive(Clone, Copy, Debug)]
pub struct HmacMidState<T: HashEngine> {
    inner: T::Midstate,
    outer: T::Midstate
}

impl<T: HashEngine> Default for Hmac<T> {
    fn default() -> Self {        
        Self {
            inner: T::default(),             // Hasher with no data inputted
            outer: T::default(),
            istate: HmacMidState::default(), // HmacMidstate with empty key
            msg_buffer: vec![]
        }
    }
}

impl<T: HashEngine> Default for HmacMidState<T> {
    fn default() -> Self {
        // The midstate for default hmac is the midstate of each inner hash function where there is no input data
        // padded upto blocksize.

        // compute the primed key, where the key is an empty byte array.
        let mut key: Vec<u8> = vec![];
        if key.len() > T::BLOCKSIZE {
            let mut e = T::default();
            e.input(key);
            key = e.finalise().into();
        }
        if key.len() < T::BLOCKSIZE {
            let mut padding = vec![];
            padding.resize(T::BLOCKSIZE-key.len(), 0x00);
            key.extend(padding);
        }
        assert_eq!(key.len(), T::BLOCKSIZE);

        let opad_key: Vec<u8> = key.iter().map(|x| x^OPAD).collect();
        let ipad_key: Vec<u8> = key.iter().map(|x| x^IPAD).collect();
        drop(key);
        let mut iengine: T = T::default();
        iengine.input(ipad_key);
        let mut oengine: T = T::default();
        oengine.input(opad_key);
        Self {
            inner: iengine.midstate(),
            outer: oengine.midstate()
        }
    }
}

impl<T: HashEngine+Copy> HashEngine for Hmac<T> {
    type Digest = T::Digest;
    type Midstate = HmacMidState<T>;
    const BLOCKSIZE: usize = T::BLOCKSIZE;

    fn reset(&mut self) {
        self.inner.from_midstate(self.istate.inner, T::BLOCKSIZE); // reset the inner and outer hash engine midstate's to the primed key midstate.
        self.outer.from_midstate(self.istate.outer, T::BLOCKSIZE);
        self.msg_buffer = vec![];
    }

    fn input<I>(&mut self, data: I)
    where I: AsRef<[u8]> {
        self.inner.input(data);
    }

    fn midstate(&self) -> Self::Midstate {
        HmacMidState {
            inner: self.inner.midstate(),
            outer: self.outer.midstate()
        }
    }

    fn from_midstate(&mut self, midstate: Self::Midstate, length: usize) {
        self.inner.from_midstate(midstate.inner, length);
        self.outer.from_midstate(midstate.outer, length);
    }

    fn finalise(&mut self) -> Self::Digest {
        self.outer.input(self.inner.finalise());
        self.outer.finalise()
    }
}

impl<T: HashEngine+Copy> KeyBasedHashEngine for Hmac<T> {
    fn new_with_key<I>(key: I) -> Self
    where I: AsRef<[u8]> {
        let mut engine = Self::default();

        //Prime the key and xor it with opad/ipad
        let mut key = key.as_ref().to_vec();
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
        assert_eq!(opad_key.len(), T::BLOCKSIZE);
        assert_eq!(ipad_key.len(), T::BLOCKSIZE);

        // Input the result into respective inner/outer engines.
        engine.inner.input(ipad_key);  //the inner/outer engines have not yet hashed anything. (see Hmac<T>::default())
        engine.outer.input(opad_key);

        // Set the initial state of outer and inner engine's to the opad/ipad keys.
        // By storing the initial state of the inner and outer engines, there is no need
        // to store the key and recompute the states for the inner and outer engines.
        engine.istate = HmacMidState {
            inner: engine.inner.midstate(),
            outer: engine.outer.midstate()
        };

        engine
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::HashEngine;
    use crate::Sha256;

    #[test]
    fn hmac_sha256() {
        let mut engine: Hmac<Sha256> = Hmac::new_with_key(b"key");
        engine.input(b"The quick brown fox jumps over the lazy dog");
        let digest = engine.finalise().iter().map(|x| format!("{:02x}", x)).collect::<String>();
        assert_eq!(digest, "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");
    }

    #[ignore]
    #[test]
    fn midstate() {
        // Create a new engine with key "key".
        let engine: Hmac<Sha256> = Hmac::new_with_key(b"key");
        let midstate: HmacMidState<Sha256> = engine.midstate();

        // Create a new engine without a key
        let mut engine: Hmac<Sha256> = Hmac::default();
        //copy in the midstate from the engine with the key into the engine without the key. 
        engine.from_midstate(midstate, 64); // length is set to 64 here becasue the midstate of the inner and outer engines have been fed the blocksized ipad/opad keys.
        engine.input(b"The quick brown fox jumps over the lazy dog");
        let digest = engine.finalise().iter().map(|x| format!("{:02x}", x)).collect::<String>();
        assert_eq!(digest, "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");
    }
}