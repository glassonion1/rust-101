#![crate_name = "sealeddataenclave"]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd;

use sgx_tseal::SgxSealedData;
use sgx_tstd::slice;
use sgx_types::{sgx_sealed_data_t, sgx_status_t};

#[no_mangle]
pub extern "C" fn create_sealeddata(message: *const u8, message_len: usize) -> sgx_status_t {
    let message_slice = unsafe { slice::from_raw_parts(message, message_len) };

    let aad: [u8; 0] = [0_u8; 0];
    let result = SgxSealedData::<[u8]>::seal_data(&aad, &message_slice);
    let sealed_data = match result {
        Ok(x) => x,
        Err(ret) => {
            return ret;
        }
    };

    let mut sealed_log = sgx_sealed_data_t::default();
    let sealed_log_ptr = &mut sealed_log as *mut sgx_sealed_data_t;
    let ret = unsafe { sealed_data.to_raw_sealed_data_t(sealed_log_ptr, 1024) };

    if ret.is_none() {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    println!("key_request.key_name: {}", sealed_log.key_request.key_name);
    println!(
        "key_request.key_policy: {}",
        sealed_log.key_request.key_policy
    );
    println!("plain_text_offset: {}", sealed_log.plain_text_offset);
    println!("payload_size: {}", sealed_log.aes_data.payload_size);
    println!(
        "payload_tag: {:?}",
        sealed_log.aes_data.payload_tag.to_vec()
    );

    sgx_status_t::SGX_SUCCESS
}
