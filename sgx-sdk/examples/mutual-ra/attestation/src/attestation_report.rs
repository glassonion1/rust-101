use sgx_rand::Rng;
use sgx_tse::{rsgx_create_report, rsgx_verify_report};
use sgx_tstd::{ptr, string::String, vec::Vec};
use sgx_types::*;

use crate::ias::Client;

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

pub fn create(
    ias_key: String,
    spid: sgx_spid_t,
    pub_k: &sgx_ec256_public_t,
    sign_type: sgx_quote_sign_type_t,
) -> Result<(String, String, String), sgx_status_t> {
    let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
    let mut ti: sgx_target_info_t = sgx_target_info_t::default();
    let mut eg: sgx_epid_group_id_t = sgx_epid_group_id_t::default();

    let res = unsafe {
        ocall_sgx_init_quote(
            &mut rt as *mut sgx_status_t,
            &mut ti as *mut sgx_target_info_t,
            &mut eg as *mut sgx_epid_group_id_t,
        )
    };

    if res != sgx_status_t::SGX_SUCCESS {
        return Err(res);
    }

    if rt != sgx_status_t::SGX_SUCCESS {
        return Err(rt);
    }

    let client = Client::new(ias_key);

    let eg_num = as_u32_le(&eg);
    let sigrl_vec = match client.get_sigrl(eg_num) {
        Ok(r) => r,
        Err(e) => {
            println!("client.get_sigrl failed with {:?}", e);
            return Err(e);
        }
    };
    let (p_sigrl, sigrl_len) = if sigrl_vec.len() == 0 {
        (ptr::null(), 0)
    } else {
        (sigrl_vec.as_ptr(), sigrl_vec.len() as u32)
    };

    let mut report_data: sgx_report_data_t = sgx_report_data_t::default();
    let mut pub_k_gx = pub_k.gx.clone();
    pub_k_gx.reverse();
    let mut pub_k_gy = pub_k.gy.clone();
    pub_k_gy.reverse();
    report_data.d[..32].clone_from_slice(&pub_k_gx);
    report_data.d[32..].clone_from_slice(&pub_k_gy);

    let report = match rsgx_create_report(&ti, &report_data) {
        Ok(r) => {
            println!("Report creation => success {:?}", r.body.mr_signer.m);
            r
        }
        Err(e) => {
            println!("Report creation => failed {:?}", e);
            return Err(e);
        }
    };

    let mut quote_nonce = sgx_quote_nonce_t { rand: [0; 16] };
    let mut os_rng = match sgx_rand::SgxRng::new() {
        Ok(r) => r,
        Err(_) => return Err(sgx_status_t::SGX_ERROR_UNEXPECTED),
    };
    os_rng.fill_bytes(&mut quote_nonce.rand);
    println!("rand finished");

    let mut qe_report = sgx_report_t::default();
    const RET_QUOTE_BUF_LEN: u32 = 2048;
    let mut return_quote_buf: [u8; RET_QUOTE_BUF_LEN as usize] = [0; RET_QUOTE_BUF_LEN as usize];
    let mut quote_len: u32 = 0;

    let p_report = (&report) as *const sgx_report_t;
    let p_spid = &spid as *const sgx_spid_t;
    let p_nonce = &quote_nonce as *const sgx_quote_nonce_t;
    let p_qe_report = &mut qe_report as *mut sgx_report_t;
    let p_quote = return_quote_buf.as_mut_ptr();
    let p_quote_len = &mut quote_len as *mut u32;

    let result = unsafe {
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

    if result != sgx_status_t::SGX_SUCCESS {
        return Err(result);
    }
    if rt != sgx_status_t::SGX_SUCCESS {
        println!("ocall_get_quote returned {}", rt);
        return Err(rt);
    }

    match rsgx_verify_report(&qe_report) {
        Ok(()) => println!("rsgx_verify_report passed!"),
        Err(e) => {
            println!("rsgx_verify_report failed with {:?}", e);
            return Err(e);
        }
    }

    // Check if the qe_report is produced on the same platform
    if ti.mr_enclave.m != qe_report.body.mr_enclave.m
        || ti.attributes.flags != qe_report.body.attributes.flags
        || ti.attributes.xfrm != qe_report.body.attributes.xfrm
    {
        println!("qe_report does not match current target_info!");
        return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
    }

    let quote_vec: Vec<u8> = return_quote_buf[..quote_len as usize].to_vec();
    match client.post_report(quote_vec) {
        Ok(r) => Ok(r),
        Err(e) => {
            println!("client.post_report failed with {:?}", e);
            return Err(e);
        }
    }
}
