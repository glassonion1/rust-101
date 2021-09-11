#![crate_name = "sealeddataenclave"]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd;

use sgx_tseal::SgxSealedData;
use sgx_tstd::{slice, str};
use sgx_types::{sgx_sealed_data_t, sgx_status_t};

const SEALED_LOG_SIZE: usize = 640;

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

    let mut sealed_log: [u8; SEALED_LOG_SIZE] = [0; SEALED_LOG_SIZE];
    let p_sealed_log = sealed_log.as_mut_ptr() as *mut sgx_sealed_data_t;
    let ret = unsafe { sealed_data.to_raw_sealed_data_t(p_sealed_log, SEALED_LOG_SIZE as u32) };

    if ret.is_none() {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    println!("{:?}", sealed_log);

    unsafe {
        println!(
            "key_request.key_name: {}",
            (*p_sealed_log).key_request.key_name
        );
        println!(
            "key_request.key_policy: {}",
            (*p_sealed_log).key_request.key_policy
        );
        println!("plain_text_offset: {}", (*p_sealed_log).plain_text_offset);
        println!("payload_size: {}", (*p_sealed_log).aes_data.payload_size);
        println!(
            "payload_tag: {:?}",
            (*p_sealed_log).aes_data.payload_tag.to_vec()
        );
    }

    let opt = unsafe {
        SgxSealedData::<[u8]>::from_raw_sealed_data_t(p_sealed_log, SEALED_LOG_SIZE as u32)
    };
    let sealed_data = match opt {
        Some(x) => x,
        None => {
            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        }
    };

    let result = sealed_data.unseal_data();
    let unsealed_data = match result {
        Ok(x) => x,
        Err(ret) => {
            return ret;
        }
    };

    let data = unsealed_data.get_decrypt_txt();

    println!("{:?}", data);
    println!("{:?}", str::from_utf8(data).unwrap());

    sgx_status_t::SGX_SUCCESS
}
