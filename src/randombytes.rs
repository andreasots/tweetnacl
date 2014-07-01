use libc;
use std;
use std::rand::Rng;
use std::rand::os::OsRng;
use std::kinds::marker;

pub struct TaskOSRng {
    rng: *mut OsRng,
    marker: marker::NoSend,
}

impl Rng for TaskOSRng {
    #[inline]
    fn next_u32(&mut self) -> u32 {
        unsafe {
            (*self.rng).next_u32()
        }
    }

    #[inline]
    fn next_u64(&mut self) -> u64 {
        unsafe {
            (*self.rng).next_u64()
        }
    }
    
    #[inline]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        unsafe {
            (*self.rng).fill_bytes(dest)
        }
    }
}

pub fn rng() -> TaskOSRng {
    local_data_key!(tls_osrng: Box<OsRng>);
    match tls_osrng.get() {
        None => {
            let mut rng = box OsRng::new().unwrap();
            let ptr = &mut *rng as *mut OsRng;
            tls_osrng.replace(Some(rng));
            TaskOSRng { rng: ptr, marker: marker::NoSend }
        }
        Some(rng) => TaskOSRng {
            rng: &**rng as *const _ as *mut OsRng,
            marker: marker::NoSend
        }
    }
}

#[allow(dead_code)]
#[no_mangle]
pub unsafe extern "C" fn randombytes(buf: *mut libc::c_uchar, len: libc::c_ulonglong) {
	assert!(len < std::uint::MAX as u64);
	std::slice::raw::mut_buf_as_slice(buf, len as uint, |buf| rng().fill_bytes(buf))
}
