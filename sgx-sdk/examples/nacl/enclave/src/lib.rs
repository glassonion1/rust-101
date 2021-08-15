#![crate_name = "naclenclave"]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd;

use crypto_box::{
    aead::{Aead, Payload},
    ChaChaBox, SecretKey,
};
use sgx_rand::Rng;
use sgx_tstd::{slice, string::String};
use sgx_types::sgx_status_t;

pub const KEY_SIZE: usize = 32;

#[no_mangle]
pub extern "C" fn ecall_get_encryption_key(message: *const u8, len: usize) -> sgx_status_t {
    let str_slice = unsafe { slice::from_raw_parts(message, len) };

    let message = String::from_utf8(str_slice.to_vec()).unwrap();
    println!("{}", message);

    let mut bytes = [0u8; KEY_SIZE];
    let mut rnd = sgx_rand::ChaChaRng::new_unseeded();
    rnd.fill_bytes(&mut bytes);

    println!("{:?}", bytes);

    // generates key pair
    let secret_key = SecretKey::from(bytes);

    let public_key = secret_key.public_key();

    println!("{:?}", secret_key);
    println!("{:?}", public_key);

    sgx_status_t::SGX_SUCCESS
}
