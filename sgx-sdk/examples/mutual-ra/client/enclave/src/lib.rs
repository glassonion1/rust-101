#![crate_name = "remoteattestationenclave"]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd;

use hex;
use sgx_tcrypto::SgxEccHandle;
use sgx_tstd::io::{self, Read, Write};
use sgx_tstd::{env, net::TcpStream, str, sync::Arc, vec::Vec};
use sgx_types::*;

use attestation::attestation_report;
use attestation::ecdsa;
use attestation::verifier::ServerVerifier;

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
pub extern "C" fn run_client_session(
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

    // create client config
    let mut cfg = rustls::ClientConfig::new();
    // set the client cert into config
    let mut certs = Vec::new();
    certs.push(rustls::Certificate(cert_der));
    let privkey = rustls::PrivateKey(key_der);
    cfg.set_single_client_cert(certs, privkey).unwrap();

    // set ServerVerifier object into config
    cfg.dangerous()
        .set_certificate_verifier(Arc::new(ServerVerifier::new(true)));
    cfg.versions.clear();
    cfg.versions.push(rustls::ProtocolVersion::TLSv1_3);

    let dns_name = webpki::DNSNameRef::try_from_ascii_str("localhost").unwrap();
    let mut sess = rustls::ClientSession::new(&Arc::new(cfg), dns_name);
    let mut conn = TcpStream::new(socket_fd).unwrap();

    let mut tls = rustls::Stream::new(&mut sess, &mut conn);
    tls.write("hello".as_bytes()).unwrap();

    let mut plaintext = Vec::new();
    match tls.read_to_end(&mut plaintext) {
        Ok(_) => {
            println!("Server replied: {}", str::from_utf8(&plaintext).unwrap());
        }
        Err(ref err) if err.kind() == io::ErrorKind::ConnectionAborted => {
            println!("EOF (tls)");
        }
        Err(e) => println!("Error in read_to_end: {:?}", e),
    }

    sgx_status_t::SGX_SUCCESS
}
