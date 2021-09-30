use serde_json::Value;
use sgx_tstd::{ptr, string::String, time::SystemTime, vec::Vec};
use sgx_types::{sgx_platform_info_t, sgx_quote_t, sgx_status_t, sgx_update_info_bit_t};

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
    pub fn ocall_get_update_info(
        ret_val: *mut sgx_status_t,
        platform_blob: *const sgx_platform_info_t,
        enclave_trusted: i32,
        update_info: *mut sgx_update_info_bit_t,
    ) -> sgx_status_t;
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

    let root_ca_raw = include_bytes!("../AttestationReportSigningCACert.pem");
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

fn extract_quote_from_attn_report(attn_report: Vec<u8>) -> Result<sgx_quote_t, sgx_status_t> {
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
                        return Err(rt);
                    }
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

pub fn verify_ra_cert(cert_der: &[u8]) -> Result<(), sgx_status_t> {
    // Search for Public Key prime256v1 OID
    let prime256v1_oid = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    let mut offset = cert_der
        .windows(prime256v1_oid.len())
        .position(|window| window == prime256v1_oid)
        .unwrap();
    offset += 11; // 10 + TAG (0x03)

    // Obtain Public Key length
    let mut len = cert_der[offset] as usize;
    if len > 0x80 {
        len = (cert_der[offset + 1] as usize) * 0x100 + (cert_der[offset + 2] as usize);
        offset += 2;
    }

    // Obtain Public Key
    offset += 1;
    let pub_k = cert_der[offset + 2..offset + len].to_vec(); // skip "00 04"

    // Search for Netscape Comment OID
    let ns_cmt_oid = &[
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x42, 0x01, 0x0D,
    ];
    let mut offset = cert_der
        .windows(ns_cmt_oid.len())
        .position(|window| window == ns_cmt_oid)
        .unwrap();
    offset += 12; // 11 + TAG (0x04)

    // Obtain Netscape Comment length
    let mut len = cert_der[offset] as usize;
    if len > 0x80 {
        len = (cert_der[offset + 1] as usize) * 0x100 + (cert_der[offset + 2] as usize);
        offset += 2;
    }

    // Obtain Netscape Comment
    offset += 1;
    let payload = cert_der[offset..offset + len].to_vec();

    // Extract each field
    let mut iter = payload.split(|x| *x == 0x7C);
    let attn_report_raw = iter.next().unwrap();
    let attn_report = attn_report_raw.to_vec();

    let sig_raw = iter.next().unwrap();
    let sig = base64::decode(&sig_raw).unwrap();

    let cert_raw = iter.next().unwrap();
    let cert = base64::decode(&cert_raw).unwrap();

    verify_intel_sign(attn_report.clone(), sig, cert)?;

    let sgx_quote = extract_quote_from_attn_report(attn_report)?;

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

    if sgx_quote.report_body.report_data.d.to_vec() == pub_k.to_vec() {
        println!("ue RA done!");
    }

    Ok(())
}
