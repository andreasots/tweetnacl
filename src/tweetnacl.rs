#![crate_id = "tweetnacl#20140427"]
#![crate_type = "rlib"]
#![feature(default_type_params)]

extern crate libc;
extern crate serialize;
extern crate base32 = "crockford-base32";

pub mod auth;
pub mod hash;
pub mod scalarmult;
pub mod secretbox;
mod randombytes;
