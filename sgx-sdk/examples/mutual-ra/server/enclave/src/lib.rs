#![crate_name = "remoteattestationenclave"]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd;

use hex;
use sgx_tcrypto::SgxEccHandle;
use sgx_tstd::io::{Read, Write};
use sgx_tstd::{env, str, vec::Vec};
use sgx_tstd::{net::TcpStream, sync::Arc};
use sgx_types::*;

use attestation::attestation_report;
use attestation::ecdsa;
use attestation::verifier::ClientVerifier;

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

#[no_mangle]
pub extern "C" fn run_server_session(
    socket_fd: c_int,
    sign_type: sgx_quote_sign_type_t,
) -> sgx_status_t {
    let ias_key = env::var("IAS_KEY").expect("IAS_KEY is not set");
    let spid_env = env::var("SPID").expect("SPID is not set");
    let spid = decode_spid(&spid_env);

    // Generate Keypair
    let ecc_handle = SgxEccHandle::new();
    let _result = ecc_handle.open();
    let (prv_k, pub_k) = ecc_handle.create_key_pair().unwrap();

    let (attn_report, sig, cert) =
        match attestation_report::create(ias_key, spid, &pub_k, sign_type) {
            Ok(r) => r,
            Err(e) => {
                println!("Error in create_attestation_report: {:?}", e);
                return e;
            }
        };

    let payload = attn_report + "|" + &sig + "|" + &cert;
    let (key_der, cert_der) = match ecdsa::gen_ecc_cert(payload, &prv_k, &pub_k, &ecc_handle) {
        Ok(r) => r,
        Err(e) => {
            println!("Error in gen_ecc_cert: {:?}", e);
            return e;
        }
    };
    let _result = ecc_handle.close();

    // create server config by setting ClientVerifier object as an argument
    let mut cfg = rustls::ServerConfig::new(Arc::new(ClientVerifier::new(true)));
    // set the server cert on config
    let mut certs = Vec::new();
    certs.push(rustls::Certificate(cert_der));
    let privkey = rustls::PrivateKey(key_der);
    cfg.set_single_cert_with_ocsp_and_sct(certs, privkey, vec![], vec![])
        .unwrap();

    let mut sess = rustls::ServerSession::new(&Arc::new(cfg));
    let mut conn = TcpStream::new(socket_fd).unwrap();

    let mut tls = rustls::Stream::new(&mut sess, &mut conn);
    let mut plaintext = [0u8; 1024];
    match tls.read(&mut plaintext) {
        Ok(_) => println!("Client said: {}", str::from_utf8(&plaintext).unwrap()),
        Err(e) => {
            println!("Error in read_to_end: {:?}", e);
            panic!("");
        }
    };

    tls.write("hello back".as_bytes()).unwrap();

    sgx_status_t::SGX_SUCCESS
}
