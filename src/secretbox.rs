use libc::{c_int,c_uchar,c_ulonglong};
use std::rand::Rng;
use serialize::{Encodable,Encoder,Decodable,Decoder};
use std::slice::MutableCloneableVector;
use super::randombytes::rng;

pub static KEYBYTES: uint = 32;
pub static NONCEBYTES: uint = 24;
pub static ZEROBYTES: uint = 32;
pub static BOXZEROBYTES: uint = 16;

#[link(name="tweetnacl", kind="static")]
extern {
    fn crypto_secretbox_xsalsa20poly1305_tweet(c: *mut c_uchar, m: *const c_uchar, d: c_ulonglong, n: *const c_uchar, k: *const c_uchar) -> c_int;
    fn crypto_secretbox_xsalsa20poly1305_tweet_open(m: *mut c_uchar, c: *const c_uchar, d: c_ulonglong, n: *const c_uchar, k: *const c_uchar) -> c_int;
}

pub fn generate_nonce() -> [u8, ..NONCEBYTES] {
    let mut nonce = [0, ..NONCEBYTES];
    rng().fill_bytes(nonce.as_mut_slice());
    nonce
}

pub struct Key {
    key: [u8, ..KEYBYTES]
}

impl Clone for Key {
    fn clone(&self) -> Key {
        Key::from(self.key)
    }
}

impl Key {
    pub fn generate() -> Key {
        Key {
            key: {
                let mut key = [0, ..KEYBYTES];
                rng().fill_bytes(key.as_mut_slice());
                key
            }
        }
    }

    pub fn from(key: &[u8]) -> Key {
        assert_eq!(key.len(), KEYBYTES);
        Key {
            key: {
                let mut k = [0, ..KEYBYTES];
                k.copy_from(key);
                k
            }
        }
    }

    pub fn encrypt(&self, msg: &[u8], nonce: &[u8, ..NONCEBYTES]) -> Vec<u8> {
        let plaintext = {
            let mut vec = Vec::from_elem(ZEROBYTES+msg.len(), 0u8);
            vec.mut_slice_from(ZEROBYTES).copy_from(msg.as_slice());
            vec
        };

        let mut ciphertext = Vec::from_elem(plaintext.len(), 0u8);

        unsafe {
            assert_eq!(crypto_secretbox_xsalsa20poly1305_tweet(ciphertext.as_mut_ptr(), plaintext.as_ptr(), plaintext.len() as c_ulonglong, nonce.as_ptr(), self.key.as_ptr()), 0);
        }

        ciphertext.slice_from(BOXZEROBYTES).to_owned()
    }

    pub fn decrypt(&self, nonce: &[u8, ..NONCEBYTES], msg: &[u8]) -> Option<Vec<u8>> {
        let ciphertext = {
            let mut vec = Vec::from_elem(BOXZEROBYTES+msg.len(), 0u8);
            vec.mut_slice_from(BOXZEROBYTES).copy_from(msg.as_slice());
            vec
        };

        let mut plaintext = Vec::from_elem(ciphertext.len(), 0u8);

        unsafe {
            if crypto_secretbox_xsalsa20poly1305_tweet_open(plaintext.as_mut_ptr(), ciphertext.as_ptr(), ciphertext.len() as c_ulonglong, nonce.as_ptr(), self.key.as_ptr()) == 0 {
                Some(plaintext.slice_from(ZEROBYTES).to_owned())
            } else {
                None
            }
        }
    }
}

impl <S: Encoder<E>, E> Encodable<S, E> for Key {
    fn encode(&self, s: &mut S) -> Result<(), E> {
        self.key.encode(s)
    }
}

impl <D: Decoder<E>, E> Decodable<D, E> for Key {
    fn decode(d: &mut D) -> Result<Key, E> {
        let key: Vec<u8> = try!(Decodable::decode(d));
        assert_eq!(key.len(), KEYBYTES);
        let mut ret = Key { key: [0, ..KEYBYTES] };
        ret.key.copy_from(key.as_slice());
        return Ok(ret);
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        unsafe {
            ::std::intrinsics::volatile_set_memory(self.key.as_mut_ptr(), 0, KEYBYTES);
        }
    }
}
