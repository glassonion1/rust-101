use sgx_tstd::{str, string::String, vec::Vec};
use sgx_types::sgx_status_t;

use http_req::{
    request::{Method, Request},
    response::Headers,
    uri::Uri,
};

use crate::cert;

pub const DEV_HOSTNAME: &'static str = "api.trustedservices.intel.com";
pub const SIGRL_SUFFIX: &'static str = "/sgx/dev/attestation/v3/sigrl/";
pub const REPORT_SUFFIX: &'static str = "/sgx/dev/attestation/v3/report";

pub fn get_sigrl_from_intel(ias_key: &str, gid: u32) -> Result<Vec<u8>, sgx_status_t> {
    println!("get_sigrl_from_intel");

    let uri_str = format!("https://{}{}/{:08x}", DEV_HOSTNAME, SIGRL_SUFFIX, gid);
    let uri: Uri = uri_str.parse().expect("Invalid uri");
    let host = uri.host_header().expect("Not found host in the uri");

    let mut headers = Headers::new();
    headers.insert("Ocp-Apim-Subscription-Key", ias_key);
    headers.insert("HOST", &host);
    headers.insert("Connection", "close");

    let mut request = Request::new(&uri);
    request.headers(headers);
    request.method(Method::GET);

    let mut res_body = Vec::new();
    let resp = request.send(&mut res_body);

    match resp {
        Ok(r) => match u16::from(r.status_code()) {
            200 => Ok(res_body),
            _ => {
                println!("{:?}", r);
                Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER)
            }
        },
        Err(msg) => {
            println!("request error: {}", msg);
            Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
        }
    }
}

pub fn post_report_from_intel(
    ias_key: &str,
    quote: Vec<u8>,
) -> Result<(String, String, String), sgx_status_t> {
    println!("post_report_from_intel");

    let uri_str = format!("https://{}{}", DEV_HOSTNAME, REPORT_SUFFIX);
    let uri: Uri = uri_str.parse().expect("Invalid uri");
    let host = uri.host_header().expect("Not found host in the uri");

    let encoded_quote = base64::encode(&quote[..]);
    let encoded_json = format!("{{\"isvEnclaveQuote\":\"{}\"}}\r\n", encoded_quote);

    let mut headers = Headers::new();
    headers.insert("Ocp-Apim-Subscription-Key", ias_key);
    headers.insert("HOST", &host);
    headers.insert("Connection", "close");
    let len = encoded_json.len();
    headers.insert("Content-Type", "application/json");
    headers.insert("Content-Length", &len);

    let mut request = Request::new(&uri);
    request.headers(headers);
    request.method(Method::POST);
    request.body(&encoded_json.as_bytes());

    let mut res_body = Vec::new();
    let resp = request.send(&mut res_body);

    match resp {
        Ok(r) => match u16::from(r.status_code()) {
            200 => {
                let (sig, sig_cert) = parse_response_headers(r.headers());
                let body = String::from_utf8(res_body.clone()).unwrap();
                println!("{}", body);
                Ok((body, sig, sig_cert))
            }
            _ => {
                println!("{:?}", r);
                Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER)
            }
        },
        Err(msg) => {
            println!("request error: {}", msg);
            Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
        }
    }
}

fn parse_response_headers(headers: &Headers) -> (String, String) {
    let sig = headers.get("X-IASReport-Signature").unwrap().clone();

    let mut sig_cert = headers
        .get("X-IASReport-Signing-Certificate")
        .unwrap()
        .clone();
    sig_cert = sig_cert.replace("%0A", "");
    sig_cert = cert::percent_decode(sig_cert);
    let v: Vec<&str> = sig_cert.split("-----").collect();
    let sig_cert = String::from(v[2]);

    (sig, sig_cert)
}
