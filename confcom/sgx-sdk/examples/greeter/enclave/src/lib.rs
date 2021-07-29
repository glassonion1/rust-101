#![crate_name = "greeterenclave"]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd;

use sgx_tstd::{slice, string::String};
use sgx_types::sgx_status_t;

extern "C" {
    // OCALLS
    pub fn ocall_pong(message: *const u8, len: usize);
}

#[no_mangle]
pub extern "C" fn ecall_ping(message: *const u8, len: usize) -> sgx_status_t {
    let str_slice = unsafe { slice::from_raw_parts(message, len) };

    let message = String::from_utf8(str_slice.to_vec()).unwrap();
    println!("{}", message);

    let msg = String::from(message + " pong");
    unsafe {
        ocall_pong(msg.as_ptr() as *const u8, msg.len());
    }

    sgx_status_t::SGX_SUCCESS
}
