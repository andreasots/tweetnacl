pub mod hmacsha512 {
    use serialize::{Encoder,Encodable,Decoder,Decodable};
    use std::slice::MutableCloneableVector;
    use super::super::hash::sha512;

    pub static KEYBYTES: uint = sha512::BYTES;
    pub static BYTES: uint = sha512::BYTES;

    pub struct Key {
        pub key: [u8, ..KEYBYTES]
    }

    impl Key {
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
    }

    impl Drop for Key {
        fn drop(&mut self) {
            unsafe {
                ::std::intrinsics::volatile_set_memory(self.key.as_mut_ptr(), 0, KEYBYTES);
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

    pub fn auth(data: &[u8], key: &Key) -> [u8, ..BYTES] {
        let mut ohash = Vec::with_capacity(2*sha512::BYTES);
        ohash = ohash.append({
            let mut okey = [0, ..sha512::BYTES];
            for (i, b) in key.key.iter().enumerate() {
                okey[i] = b ^ 0x5c;
            }
            okey
        });
        ohash = ohash.append({
            let mut ihash = Vec::with_capacity(data.len()+sha512::BYTES);
            ihash = ihash.append({
                let mut ikey = [0, ..sha512::BYTES];
                for (i, b) in key.key.iter().enumerate() {
                    ikey[i] = b ^ 0x36;
                }
                ikey
            });
            sha512::hash(ihash.append(data).as_slice())
        });
        sha512::hash(ohash.as_slice())
    }

    pub fn verify(tag: &[u8, ..BYTES], data: &[u8], key: &Key) -> bool {
        let mut res = 0;
        for (&a, &b) in tag.iter().zip(auth(data, key).iter()) {
            res |= a ^ b;
        }
        return res == 0;
    }
}


