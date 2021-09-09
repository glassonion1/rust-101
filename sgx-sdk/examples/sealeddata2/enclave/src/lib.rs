#![crate_name = "sealeddataenclave"]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd;

use sgx_tseal::SgxSealedData;
use sgx_tstd::{slice, str};
use sgx_types::{sgx_attributes_t, sgx_sealed_data_t, sgx_status_t};

const SEALED_LOG_SIZE: usize = 640;

#[no_mangle]
pub extern "C" fn create_sealeddata(message: *const u8, message_len: usize) -> sgx_status_t {
    let message_slice = unsafe { slice::from_raw_parts(message, message_len) };

    let attribute_mask = sgx_attributes_t {
        flags: sgx_types::TSEAL_DEFAULT_FLAGSMASK,
        xfrm: 0,
    };
    let aad: [u8; 0] = [0_u8; 0];
    let result = SgxSealedData::<[u8]>::seal_data_ex(
        sgx_types::SGX_KEYPOLICY_MRENCLAVE,
        attribute_mask,
        sgx_types::TSEAL_DEFAULT_MISCMASK,
        &aad,
        &message_slice,
    );
    let sealed_data = match result {
        Ok(x) => x,
        Err(ret) => {
            return ret;
        }
    };

    let mut sealed_log_arr: [u8; SEALED_LOG_SIZE] = [0; SEALED_LOG_SIZE];
    let sealed_log = sealed_log_arr.as_mut_ptr();
    let ret = unsafe {
        sealed_data
            .to_raw_sealed_data_t(sealed_log as *mut sgx_sealed_data_t, SEALED_LOG_SIZE as u32)
    };

    if ret.is_none() {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    println!("{:?}", sealed_log_arr);

    let raw_sealed_log = sealed_log as *const sgx_sealed_data_t;

    unsafe {
        println!(
            "key_request.key_name: {}",
            (*raw_sealed_log).key_request.key_name
        );
        println!(
            "key_request.key_policy: {}",
            (*raw_sealed_log).key_request.key_policy
        );
        println!("plain_text_offset: {}", (*raw_sealed_log).plain_text_offset);
        println!("payload_size: {}", (*raw_sealed_log).aes_data.payload_size);
        println!(
            "payload_tag: {:?}",
            (*raw_sealed_log).aes_data.payload_tag.to_vec()
        );
    }

    let opt = unsafe {
        SgxSealedData::<[u8]>::from_raw_sealed_data_t(
            sealed_log as *mut sgx_sealed_data_t,
            SEALED_LOG_SIZE as u32,
        )
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
