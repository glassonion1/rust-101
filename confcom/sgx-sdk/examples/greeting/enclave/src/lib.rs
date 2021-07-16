#![crate_name = "greetingenclave"]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate sgx_types;

use sgx_types::sgx_status_t;
use std::slice;
use std::string::String;

extern "C" {
    // OCALLS
    pub fn pong(message: *const u8, len: usize);
}

#[no_mangle]
pub extern "C" fn ping(message: *const u8, len: usize) -> sgx_status_t {
    let str_slice = unsafe { slice::from_raw_parts(message, len) };

    let ping = String::from_utf8(str_slice.to_vec()).unwrap();
    println!("{}", ping);

    let msg = String::from(ping + " pong");
    unsafe {
        pong(msg.as_ptr() as *const u8, msg.len());
    }

    sgx_status_t::SGX_SUCCESS
}
