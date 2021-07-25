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

pub fn get_sigrl_from_intel(ias_key: &str, gid: u32) -> Vec<u8> {
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
            200 => res_body,
            _ => {
                println!("{:?}", r);
                Vec::new()
            }
        },
        Err(msg) => {
            println!("request error: {}", msg);
            Vec::new()
        }
    }
}

pub fn post_report_from_intel(ias_key: &str, quote: Vec<u8>) -> Vec<u8> {
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

    let b = String::from_utf8(res_body.clone()).unwrap();
    println!("{}", b);

    match resp {
        Ok(r) => match u16::from(r.status_code()) {
            200 => res_body,
            _ => {
                //let b = String::from_utf8(res_body).unwrap();
                println!("{:?}", r);
                Vec::new()
            }
        },
        Err(msg) => {
            println!("request error: {}", msg);
            Vec::new()
        }
    }
}
