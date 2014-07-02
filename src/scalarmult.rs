use libc::{c_int,c_uchar};
use std::rand::Rng;
use serialize::{Encodable,Encoder,Decodable,Decoder};
use std::slice::MutableCloneableVector;
use super::randombytes::rng;
use base32;
use std::from_str::FromStr;
use std::fmt::{Show,Formatter,FormatError};
use std::hash::Hash;
use std::hash::Writer;

#[link(name="tweetnacl", kind="static")]
extern {
    fn crypto_scalarmult_curve25519_tweet(q: *mut c_uchar, n: *const c_uchar, p: *const c_uchar) -> c_int;
    fn crypto_scalarmult_curve25519_tweet_base(q: *mut c_uchar, n: *const c_uchar) -> c_int;
}

pub static BYTES: uint = 32;
pub static SCALARBYTES: uint = 32;

#[deriving(Eq)]
pub struct PublicKey {
    pub pk: [u8, ..BYTES] 
}

impl PublicKey {
    pub fn from(key: &[u8]) -> PublicKey {
        assert_eq!(key.len(), BYTES);
        PublicKey {
            pk : {
                let mut k = [0, ..BYTES];
                k.copy_from(key);
                k
            }
        }
    }
}

impl Clone for PublicKey {
    fn clone(&self) -> PublicKey {
        PublicKey::from(self.pk)
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &PublicKey) -> Option<Ordering> {
        self.pk.as_slice().partial_cmp(&other.pk.as_slice())
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &PublicKey) -> bool {
        self.pk == other.pk
    }
}

impl <S: Writer> Hash<S> for PublicKey {
    fn hash(&self, state: &mut S) {
        self.pk.hash(state)
    }
}

impl Show for PublicKey {
    fn fmt(&self, formatter: &mut Formatter) -> Result<(), FormatError> {
        base32::encode(self.pk).as_slice().as_str_ascii().fmt(formatter)
    }
}

impl FromStr for PublicKey {
    fn from_str(s: &str) -> Option<PublicKey> {
        s.to_ascii_opt().and_then(|s| base32::decode(s)).and_then(|pk|
                                                                  if pk.len() == 32 {
                                                                      Some(PublicKey::from(pk.as_slice()))
                                                                  } else {
                                                                      None
                                                                  })
    }
}

impl <S: Encoder<E>, E> Encodable<S, E> for PublicKey {
    fn encode(&self, s: &mut S) -> Result<(), E> {
        self.pk.encode(s)
    }
}

impl <D: Decoder<E>, E> Decodable<D, E> for PublicKey {
    fn decode(d: &mut D) -> Result<PublicKey, E> {
        let pk: Vec<u8> = try!(Decodable::decode(d));
        assert_eq!(pk.len(), BYTES);
        let mut ret = PublicKey { pk: [0, ..BYTES] };
        ret.pk.copy_from(pk.as_slice());
        return Ok(ret);
    }
}

pub struct Keypair {
    pk: [u8, ..BYTES],
    sk: [u8, ..SCALARBYTES]
}

impl Keypair {
    pub fn generate() -> Keypair {
        let mut ret = Keypair { sk: [0, ..SCALARBYTES], pk: [0, ..BYTES] };
        rng().fill_bytes(ret.sk.as_mut_slice());
        unsafe {
            assert_eq!(crypto_scalarmult_curve25519_tweet_base(ret.pk.as_mut_ptr(), ret.sk.as_ptr()), 0);
        }
        return ret;
    }

    pub fn ecdh(&self, pk: &PublicKey) -> PublicKey {
        let mut ret = PublicKey { pk: [0, ..BYTES] };
        unsafe {
            assert_eq!(crypto_scalarmult_curve25519_tweet(ret.pk.as_mut_ptr(), self.sk.as_ptr(), pk.pk.as_ptr()), 0);
        }
        return ret;
    }

    pub fn public(&self) -> PublicKey {
        PublicKey { pk: self.pk }
    }
}

impl <S: Encoder<E>, E> Encodable<S, E> for Keypair {
    fn encode(&self, s: &mut S) -> Result<(), E> {
        self.sk.encode(s)
    }
}

impl <D: Decoder<E>, E> Decodable<D, E> for Keypair {
    fn decode(d: &mut D) -> Result<Keypair, E> {
        let sk: Vec<u8> = try!(Decodable::decode(d));
        assert_eq!(sk.len(), SCALARBYTES);
        let mut ret = Keypair { pk: [0, ..BYTES], sk: [0, ..SCALARBYTES] };
        ret.sk.copy_from(sk.as_slice());
        unsafe {
            assert_eq!(crypto_scalarmult_curve25519_tweet_base(ret.pk.as_mut_ptr(), ret.sk.as_ptr()), 0);
        }
        return Ok(ret);
    }
}

impl Drop for Keypair {
    fn drop(&mut self) {
        unsafe {
            ::std::intrinsics::volatile_set_memory(self.pk.as_mut_ptr(), 0, BYTES);
            ::std::intrinsics::volatile_set_memory(self.sk.as_mut_ptr(), 0, SCALARBYTES);
        }
    }
}
