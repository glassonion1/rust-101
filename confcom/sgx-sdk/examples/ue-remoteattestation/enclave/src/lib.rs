#![crate_name = "greetingenclave"]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd;
extern crate http_req;
extern crate serde;
extern crate serde_json;
extern crate sgx_rand;

use crate::sgx_rand::Rng;

use sgx_tcrypto::SgxEccHandle;
use sgx_tse::rsgx_create_report;
use sgx_tstd::{ptr, slice, string::String};
use sgx_types::*;

mod client;
mod hex;

extern "C" {
    pub fn ocall_sgx_init_quote(
        ret_val: *mut sgx_status_t,
        ret_ti: *mut sgx_target_info_t,
        ret_gid: *mut sgx_epid_group_id_t,
    ) -> sgx_status_t;
    pub fn ocall_get_quote(
        ret_val: *mut sgx_status_t,
        p_sigrl: *const u8,
        sigrl_len: u32,
        p_report: *const sgx_report_t,
        quote_type: sgx_quote_sign_type_t,
        p_spid: *const sgx_spid_t,
        p_nonce: *const sgx_quote_nonce_t,
        p_qe_report: *mut sgx_report_t,
        p_quote: *mut u8,
        maxlen: u32,
        p_quote_len: *mut u32,
    ) -> sgx_status_t;
}

fn as_u32_le(array: &[u8; 4]) -> u32 {
    ((array[0] as u32) << 0)
        + ((array[1] as u32) << 8)
        + ((array[2] as u32) << 16)
        + ((array[3] as u32) << 24)
}

#[no_mangle]
pub extern "C" fn ping(
    message: *const u8,
    len: usize,
    sign_type: sgx_quote_sign_type_t,
) -> sgx_status_t {
    let str_slice = unsafe { slice::from_raw_parts(message, len) };

    let ping = String::from_utf8(str_slice.to_vec()).unwrap();
    println!("{}", ping);

    let mut ti: sgx_target_info_t = sgx_target_info_t::default();
    let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
    let mut eg: sgx_epid_group_id_t = sgx_epid_group_id_t::default();

    let res = unsafe {
        ocall_sgx_init_quote(
            &mut rt as *mut sgx_status_t,
            &mut ti as *mut sgx_target_info_t,
            &mut eg as *mut sgx_epid_group_id_t,
        )
    };

    if res != sgx_status_t::SGX_SUCCESS {
        return res;
    }

    if rt != sgx_status_t::SGX_SUCCESS {
        return rt;
    }

    // TODO: ias_key
    let eg_num = as_u32_le(&eg);
    let sigrl_vec = client::get_sigrl_from_intel(eg_num, "");

    let ecc_handle = SgxEccHandle::new();
    let _result = ecc_handle.open();
    let (prv_k, pub_k) = ecc_handle.create_key_pair().unwrap();

    // Generate the report
    let mut report_data: sgx_report_data_t = sgx_report_data_t::default();
    let mut pub_k_gx = pub_k.gx.clone();
    pub_k_gx.reverse();
    let mut pub_k_gy = pub_k.gy.clone();
    pub_k_gy.reverse();
    report_data.d[..32].clone_from_slice(&pub_k_gx);
    report_data.d[32..].clone_from_slice(&pub_k_gy);

    let rep = match rsgx_create_report(&ti, &report_data) {
        Ok(r) => {
            println!("Report creation => success {:?}", r.body.mr_signer.m);
            Some(r)
        }
        Err(e) => {
            println!("Report creation => failed {:?}", e);
            None
        }
    };

    let mut quote_nonce = sgx_quote_nonce_t { rand: [0; 16] };
    let mut os_rng = sgx_rand::SgxRng::new().unwrap();
    os_rng.fill_bytes(&mut quote_nonce.rand);
    println!("rand finished");
    let mut qe_report = sgx_report_t::default();
    const RET_QUOTE_BUF_LEN: u32 = 2048;
    let mut return_quote_buf: [u8; RET_QUOTE_BUF_LEN as usize] = [0; RET_QUOTE_BUF_LEN as usize];
    let mut quote_len: u32 = 0;

    // Generate the quote
    let (p_sigrl, sigrl_len) = if sigrl_vec.len() == 0 {
        (ptr::null(), 0)
    } else {
        (sigrl_vec.as_ptr(), sigrl_vec.len() as u32)
    };

    let p_report = (&rep.unwrap()) as *const sgx_report_t;

    // TODO: spid
    let spid = hex::decode_spid("2C149BFA94A61D306A96211AED155BE8");
    let p_spid = &spid as *const sgx_spid_t;

    let p_nonce = &quote_nonce as *const sgx_quote_nonce_t;
    let p_qe_report = &mut qe_report as *mut sgx_report_t;
    let p_quote = return_quote_buf.as_mut_ptr();
    let p_quote_len = &mut quote_len as *mut u32;

    let _result = unsafe {
        ocall_get_quote(
            &mut rt as *mut sgx_status_t,
            p_sigrl,
            sigrl_len,
            p_report,
            sign_type,
            p_spid,
            p_nonce,
            p_qe_report,
            p_quote,
            RET_QUOTE_BUF_LEN,
            p_quote_len,
        )
    };

    sgx_status_t::SGX_SUCCESS
}
