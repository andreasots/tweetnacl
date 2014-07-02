pub mod sha512 {
    use libc::{c_int,c_uchar,c_ulonglong};

    #[link(name="tweetnacl", kind="static")]
    extern {
        fn crypto_hash_sha512_tweet(out: *mut c_uchar, m: *const c_uchar, n: c_ulonglong) -> c_int;
    }

    pub static BYTES: uint = 64;

     pub fn hash(input: &[u8]) -> [u8, ..BYTES] {
         let mut ret = [0, ..BYTES];
         unsafe {
             assert_eq!(crypto_hash_sha512_tweet(ret.as_mut_ptr(), input.as_ptr(), input.len() as c_ulonglong), 0);
         }
         return ret;
    }
}

