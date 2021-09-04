#![crate_name = "remoteattestationenclave"]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd;
extern crate base64;
extern crate http_req;
extern crate serde;
extern crate serde_json;
extern crate sgx_rand;

use crate::sgx_rand::Rng;

use hex;
use serde_json::Value;
use sgx_tse::{rsgx_create_report, rsgx_verify_report};
use sgx_tstd::{env, ptr, str, string::String, time::SystemTime, vec::Vec};
use sgx_types::*;

mod client;

type SignatureAlgorithms = &'static [&'static webpki::SignatureAlgorithm];
static SUPPORTED_SIG_ALGS: SignatureAlgorithms = &[
    &webpki::ECDSA_P256_SHA256,
    &webpki::ECDSA_P256_SHA384,
    &webpki::ECDSA_P384_SHA256,
    &webpki::ECDSA_P384_SHA384,
    &webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    &webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    &webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
    &webpki::RSA_PKCS1_2048_8192_SHA256,
    &webpki::RSA_PKCS1_2048_8192_SHA384,
    &webpki::RSA_PKCS1_2048_8192_SHA512,
    &webpki::RSA_PKCS1_3072_8192_SHA384,
];

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
    // Optional
    pub fn ocall_get_update_info(
        ret_val: *mut sgx_status_t,
        platformBlob: *const sgx_platform_info_t,
        enclaveTrusted: i32,
        update_info: *mut sgx_update_info_bit_t,
    ) -> sgx_status_t;
}

pub fn decode_spid(hex: &str) -> sgx_spid_t {
    let mut spid = sgx_spid_t::default();
    let hex = hex.trim();

    if hex.len() < 16 * 2 {
        println!("Input spid file len ({}) is incorrect!", hex.len());
        return spid;
    }

    let decoded_vec = hex::decode(hex).unwrap();

    spid.id.copy_from_slice(&decoded_vec[..16]);

    spid
}

fn as_u32_le(array: &[u8; 4]) -> u32 {
    ((array[0] as u32) << 0)
        + ((array[1] as u32) << 8)
        + ((array[2] as u32) << 16)
        + ((array[3] as u32) << 24)
}

fn create_attestation_report(
    ias_key: &str,
    spid: sgx_spid_t,
    sign_type: sgx_quote_sign_type_t,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), sgx_status_t> {
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

    let eg_num = as_u32_le(&eg);
    let sigrl_vec = match client::get_sigrl_from_intel(ias_key, eg_num) {
        Ok(r) => r,
        Err(e) => {
            println!("client::get_sigrl_from_intel failed with {:?}", e);
            return Err(e);
        }
    };
    let (p_sigrl, sigrl_len) = if sigrl_vec.len() == 0 {
        (ptr::null(), 0)
    } else {
        (sigrl_vec.as_ptr(), sigrl_vec.len() as u32)
    };

    let report_data: sgx_report_data_t = sgx_report_data_t::default();
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
    match client::post_report_to_intel(ias_key, quote_vec) {
        Ok(r) => Ok(r),
        Err(e) => {
            println!("client::post_report_to_intel failed with {:?}", e);
            return Err(e);
        }
    }
}

fn verify_intel_sign(
    attn_report: Vec<u8>,
    sig: Vec<u8>,
    cert: Vec<u8>,
) -> Result<(), sgx_status_t> {
    let now = match webpki::Time::try_from(SystemTime::now()) {
        Ok(r) => r,
        Err(e) => {
            println!("webpki::Time::try_from failed with {:?}", e);
            return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
        }
    };

    let root_ca_raw = include_bytes!("../ca.crt");
    let root_ca_pem = pem::parse(root_ca_raw).expect("failed to parse pem file.");
    let root_ca = root_ca_pem.contents;

    let mut root_store = rustls::RootCertStore::empty();
    root_store
        .add(&rustls::Certificate(root_ca.clone()))
        .unwrap();

    let trust_anchors: Vec<webpki::TrustAnchor> = root_store
        .roots
        .iter()
        .map(|cert| cert.to_trust_anchor())
        .collect();

    let mut chain: Vec<&[u8]> = Vec::new();
    chain.push(&root_ca);

    let report_cert = webpki::EndEntityCert::from(&cert).unwrap();

    match report_cert.verify_is_valid_tls_server_cert(
        SUPPORTED_SIG_ALGS,
        &webpki::TLSServerTrustAnchors(&trust_anchors),
        &chain,
        now,
    ) {
        Ok(r) => r,
        Err(e) => {
            println!("verify_is_valid_tls_server_cert failed with {:?}", e);
            return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
        }
    };

    match report_cert.verify_signature(&webpki::RSA_PKCS1_2048_8192_SHA256, &attn_report, &sig) {
        Ok(_) => Ok(()),
        Err(e) => {
            println!("verify_signature failed with {:?}", e);
            Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
        }
    }
}

fn get_quote_from_attn_report(attn_report: Vec<u8>) -> Result<sgx_quote_t, sgx_status_t> {
    let attn_report: Value = serde_json::from_slice(&attn_report).unwrap();

    // Check timestamp is within 24H
    if let Value::String(time) = &attn_report["timestamp"] {
        let time_fixed = time.clone() + "+0000";
        println!("Time = {}", time_fixed);
    } else {
        println!("Failed to fetch timestamp from attestation report");
        return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
    }

    if let Value::String(version) = &attn_report["version"] {
        if version != "4" {
            return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
        }
    }

    // Verify quote status (mandatory field)
    if let Value::String(quote_status) = &attn_report["isvEnclaveQuoteStatus"] {
        match quote_status.as_ref() {
            "OK" => (),
            "GROUP_OUT_OF_DATE" | "GROUP_REVOKED" | "CONFIGURATION_NEEDED" => {
                // Verify platformInfoBlob for further info if status not OK
                // This is optional
                if let Value::String(pib) = &attn_report["platformInfoBlob"] {
                    let mut buf = Vec::new();

                    // the TLV Header (4 bytes/8 hexes) should be skipped
                    let n = (pib.len() - 8) / 2;
                    for i in 0..n {
                        buf.push(u8::from_str_radix(&pib[(i * 2 + 8)..(i * 2 + 10)], 16).unwrap());
                    }

                    let mut update_info = sgx_update_info_bit_t::default();
                    let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
                    let res = unsafe {
                        ocall_get_update_info(
                            &mut rt as *mut sgx_status_t,
                            buf.as_slice().as_ptr() as *const sgx_platform_info_t,
                            1,
                            &mut update_info as *mut sgx_update_info_bit_t,
                        )
                    };
                    if res != sgx_status_t::SGX_SUCCESS {
                        println!("res={:?}", res);
                        return Err(res);
                    }

                    if rt != sgx_status_t::SGX_SUCCESS {
                        println!("rt={:?}", rt);
                        // Borrow of packed field is unsafe in future Rust releases
                        unsafe {
                            println!("update_info.pswUpdate: {}", update_info.pswUpdate);
                            println!("update_info.csmeFwUpdate: {}", update_info.csmeFwUpdate);
                            println!("update_info.ucodeUpdate: {}", update_info.ucodeUpdate);
                        }
                        //return Err(rt);
                    }
                } else {
                    println!("Failed to fetch platformInfoBlob from attestation report");
                    return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
                }
            }
            _ => return Err(sgx_status_t::SGX_ERROR_UNEXPECTED),
        }
    } else {
        println!("Failed to fetch isvEnclaveQuoteStatus from attestation report");
        return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
    }

    match &attn_report["isvEnclaveQuoteBody"] {
        Value::String(quote_raw) => {
            let quote = base64::decode(&quote_raw).unwrap();

            let sgx_quote: sgx_quote_t = unsafe { ptr::read(quote.as_ptr() as *const _) };
            Ok(sgx_quote)
        }
        _ => {
            println!("Failed to fetch isvEnclaveQuoteBody from attestation report");
            Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
        }
    }
}

#[no_mangle]
pub extern "C" fn verify(sign_type: sgx_quote_sign_type_t) -> sgx_status_t {
    println!("verify started");

    let ias_key = env::var("IAS_KEY").expect("IAS_KEY is not set");
    let spid_env = env::var("SPID").expect("SPID is not set");
    let spid = decode_spid(&spid_env);

    let (attn_report, sig, cert) = match create_attestation_report(&ias_key, spid, sign_type) {
        Ok(r) => r,
        Err(e) => {
            println!("Error in create_attestation_report: {:?}", e);
            return e;
        }
    };

    match verify_intel_sign(attn_report.clone(), sig, cert) {
        Ok(_) => (),
        Err(e) => return e,
    };

    let sgx_quote = match get_quote_from_attn_report(attn_report) {
        Ok(r) => r,
        Err(e) => return e,
    };

    // Borrow of packed field is unsafe in future Rust releases
    // ATTENTION
    // DO SECURITY CHECK ON DEMAND
    // DO SECURITY CHECK ON DEMAND
    // DO SECURITY CHECK ON DEMAND
    unsafe {
        println!("sgx quote version = {}", sgx_quote.version);
        println!("sgx quote signature type = {}", sgx_quote.sign_type);
        println!(
            "sgx quote report_data = {}",
            sgx_quote
                .report_body
                .report_data
                .d
                .iter()
                .map(|c| format!("{:02x}", c))
                .collect::<String>()
        );
        println!(
            "sgx quote mr_enclave = {}",
            sgx_quote
                .report_body
                .mr_enclave
                .m
                .iter()
                .map(|c| format!("{:02x}", c))
                .collect::<String>()
        );
        println!(
            "sgx quote mr_signer = {}",
            sgx_quote
                .report_body
                .mr_signer
                .m
                .iter()
                .map(|c| format!("{:02x}", c))
                .collect::<String>()
        );
    };

    sgx_status_t::SGX_SUCCESS
}
