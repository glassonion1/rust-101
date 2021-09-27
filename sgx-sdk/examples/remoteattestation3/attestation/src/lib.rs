#![crate_name = "attestation"]
#![crate_type = "rlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]
#![allow(improper_ctypes)]
#![allow(non_camel_case_types)]

#[macro_use]
extern crate sgx_tstd;

pub mod attestation_report;
pub mod ecdsa;
pub mod ias;
mod verification;
pub mod verifier;
