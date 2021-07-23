use serde::{Deserialize, Serialize};
use sgx_tstd::{str, string::String, vec::Vec};

use http_req::{
    request::{Method, Request},
    response::Headers,
    uri::Uri,
};

pub const DEV_HOSTNAME: &'static str = "api.trustedservices.intel.com";
pub const SIGRL_SUFFIX: &'static str = "/sgx/dev/attestation/v3/sigrl/";
pub const REPORT_SUFFIX: &'static str = "/sgx/dev/attestation/v3/report";

pub fn get_sigrl_from_intel(gid: u32, ias_key: &str) -> Vec<u8> {
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

    let mut body = Vec::new();
    let resp = request.send(&mut body);

    match resp {
        Ok(r) => match u16::from(r.status_code()) {
            200 => body,
            _ => {
                let b = String::from_utf8(body).unwrap();
                println!("error: {}", b);
                Vec::new()
            }
        },
        _ => {
            let b = String::from_utf8(body).unwrap();
            println!("error: {}", b);
            Vec::new()
        }
    }
}
