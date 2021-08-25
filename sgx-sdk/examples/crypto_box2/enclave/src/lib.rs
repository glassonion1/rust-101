#![crate_name = "cryptoboxenclave"]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd;

use crypto_box::{
    aead::{generic_array::GenericArray, Aead, Payload},
    ChaChaBox, PublicKey, SecretKey,
};
use sgx_tstd::{io::Read, ptr, slice};
use sgx_types::sgx_status_t;

const KEY_SIZE: usize = 32;

#[no_mangle]
pub extern "C" fn ecall_encrypt(
    in_nonce: *const u8,
    in_nonce_len: usize,
    in_msg: *const u8,
    in_msg_len: usize,
    in_pubkey: *const u8,
    in_pubkey_len: usize,
    out_ciphertext: *mut u8,
    _out_max_len: usize,
    out_ciphertext_len: &mut usize,
    out_pubkey: *mut u8,
    _out_pubkey_len: usize,
) -> sgx_status_t {
    let nonce = unsafe { slice::from_raw_parts(in_nonce, in_nonce_len) };
    let nonce = GenericArray::from_slice(nonce);
    let msg = unsafe { slice::from_raw_parts(in_msg, in_msg_len) };
    let mut pubkey_slice = unsafe { slice::from_raw_parts(in_pubkey, in_pubkey_len) };
    let mut buf = [0; KEY_SIZE];
    pubkey_slice.read_exact(&mut buf).unwrap();
    let alice_public_key = PublicKey::from(buf);

    let mut rnd = [0u8; KEY_SIZE];
    getrandom::getrandom(&mut rnd).unwrap();

    // generates key pair
    let bob_secret_key = SecretKey::from(rnd);
    let bob_public_key = bob_secret_key.public_key();

    println!("Bob's secret key: {:?}", bob_secret_key.to_bytes());
    println!("Bob's public key: {:?}", bob_public_key);

    let ciphertext = ChaChaBox::new(&alice_public_key, &bob_secret_key)
        .encrypt(
            nonce,
            Payload {
                msg: msg,
                aad: b"".as_ref(), // Additional Authentication data
            },
        )
        .unwrap();

    println!("cipertext: {:?}", ciphertext);

    *out_ciphertext_len = ciphertext.len();

    let b_pubkey = bob_public_key.as_bytes();

    unsafe {
        ptr::copy_nonoverlapping(ciphertext.as_ptr(), out_ciphertext, ciphertext.len());
        ptr::copy_nonoverlapping(b_pubkey.as_ptr(), out_pubkey, b_pubkey.len());
    }

    sgx_status_t::SGX_SUCCESS
}
