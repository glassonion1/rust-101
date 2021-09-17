#![crate_name = "measurementenclave"]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd;

use sgx_tstd::{slice, string::String, vec::Vec};
use sgx_types::sgx_status_t;

const TARO: &str = "taro";
const HANAKO: &str = "hanako";
const NATSUKO: &str = "natsuko";

fn get_votings() -> Vec<&'static str> {
    let candidates = vec![TARO, HANAKO, NATSUKO];
    let len = 99;
    let mut votes: Vec<&str> = Vec::with_capacity(len);
    for i in 0..len {
        let c = candidates[i % 3];
        votes.push(c);
    }

    votes
}

#[no_mangle]
pub extern "C" fn ecall_vote(ballot: *const u8, ballot_len: usize) -> sgx_status_t {
    let ballot_slice = unsafe { slice::from_raw_parts(ballot, ballot_len) };

    let ballot = String::from_utf8(ballot_slice.to_vec()).unwrap();
    println!("I vote {}.", ballot);

    let mut votings = get_votings();

    votings.push(&ballot);

    let mut result_taro = 0;
    let mut result_hanako = 0;
    let mut result_natsuko = 0;

    // Summarize
    for v in votings {
        if v == TARO {
            result_taro += 1;
        }
        if v == HANAKO {
            result_hanako += 1;
        }
        if v == NATSUKO {
            result_natsuko += 1;
        }
    }

    println!("taro: {}", result_taro);
    println!("hanako: {}", result_hanako);
    println!("natsuko: {}", result_natsuko);

    sgx_status_t::SGX_SUCCESS
}
