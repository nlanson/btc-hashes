use crate::{ HashEngine, KeyBasedHashEngine };
use std::{
    marker::PhantomData,
    convert::TryInto
};

pub struct PBKDF2<T: HashEngine> {
    hash: PhantomData<T>,
    password: Vec<u8>,
    salt: Vec<u8>,
    iter: usize
}

impl<T: KeyBasedHashEngine> PBKDF2<T> {
    /// Set how many iterations will be used
    pub fn iter(&mut self, count: usize) {
        self.iter = count;
    }

    /// Input salt to be used in key derivation
    pub fn salt<I>(&mut self, salt: I)
    where I: AsRef<[u8]> {
        self.salt.extend(salt.as_ref());
    }

    // F(Password, Salt, c, i) = U1 ^ U2 ^ ⋯ ^ Uc
    fn f_compression(&self) -> T::Digest {
        let mut prf = T::new();
        prf.key(&self.password);
        prf.input(&self.salt);
        prf.input(1u32.to_be_bytes());
        let mut u: Vec<T::Digest> = vec![prf.hash()];
        prf.reset();
        for i in 1..self.iter {
            prf.key(&self.password);
            prf.input(&u[i-1]);
            u.push(prf.hash());
            prf.reset();
        }

        while u.len() != 1 {
            let xor: Result<_, _> = u[0]
                        .into_iter()
                        .zip(u[1].into_iter())
                        .map(|(x, y)| x^y)
                        .collect::<Vec<u8>>()
                        .try_into();
                        
            // For some stupid reason, I cannot call .expect() after converting Vec<u8> into T::Digest using try_into()
            // Spent a while looking for a solution but the closest I came to was a stale github issue on the Rust compiler
            // repository.
            // Calling expect() just looks nicer than having a ugly match block so it does not matter.
            u[0] = match xor {
                Ok(x) => x,
                _ => panic!("bad xor")
            };
            u.remove(1);
        }

        u[0]
    }
}

impl<T: KeyBasedHashEngine> HashEngine for PBKDF2<T> {
    type Digest = T::Digest;
    const BLOCKSIZE: usize = T::BLOCKSIZE;

    fn new() -> Self {
        Self {
            hash: PhantomData,
            password: vec![],
            salt: vec![],
            iter: 1
        }
    }

    /// Input the password to be hashed
    fn input<I>(&mut self, data: I)
    where I: AsRef<[u8]> {
        self.password.extend(data.as_ref());
    }

    /// Reset the inputted password, salt and iteration count
    fn reset(&mut self) {
        self.password = vec![];
        self.salt = vec![];
        self.iter = 1;
    }

    fn hash(&mut self) -> Self::Digest {
        // DK = T1 + T2 + ⋯ + Tdklen/hlen
        // Ti = F(Password, Salt, c, i)
        // Since dklen and hlen are the same for Bitcoin, only one round of F() needs to be run.
        
        Self::f_compression(&self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        HashEngine, Hmac, Sha512, Sha384
    };

    #[test]
    fn pbkdf2_hmac_sha512() {
        // Test cases from: https://stackoverflow.com/questions/15593184/pbkdf2-hmac-sha-512-test-vectors
        let mut e = PBKDF2::<Hmac<Sha512>>::new();
        e.input(b"password");
        e.salt(b"salt");

        // 1 iteration
        e.iter(1);
        let digest = e.hash().iter().map(|x| format!("{:02x}", x)).collect::<String>();
        assert_eq!(digest, "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce");

        // 2 iterations
        e.iter(2);
        let digest = e.hash().iter().map(|x| format!("{:02x}", x)).collect::<String>();
        assert_eq!(digest, "e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53cf76cab2868a39b9f7840edce4fef5a82be67335c77a6068e04112754f27ccf4e");
    
        // 4096 iterations
        e.iter(4096);
        let digest = e.hash().iter().map(|x| format!("{:02x}", x)).collect::<String>();
        assert_eq!(digest, "d197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f457b5143f30602641b3d55cd335988cb36b84376060ecd532e039b742a239434af2d5");

        // update data
        e.reset();
        e.input(b"passwordPASSWORDpassword");
        e.salt(b"saltSALTsaltSALTsaltSALTsaltSALTsalt");
        e.iter(4096);
        let digest = e.hash().iter().map(|x| format!("{:02x}", x)).collect::<String>();
        assert_eq!(digest, "8c0511f4c6e597c6ac6315d8f0362e225f3c501495ba23b868c005174dc4ee71115b59f9e60cd9532fa33e0f75aefe30225c583a186cd82bd4daea9724a3d3b8");
    }

    #[test]
    #[ignore]
    // great test to run for speed benching
    fn pbkdf2_speed_test() {
        let mut e = PBKDF2::<Hmac<Sha384>>::new();
        e.input(b"password");
        e.input(b"salt");
        e.iter(69420);
        e.hash();
    }
}