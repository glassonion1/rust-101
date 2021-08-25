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
use once_cell::sync::OnceCell;
use sgx_tstd::{io::Read, ptr, slice};
use sgx_types::sgx_status_t;

const KEY_SIZE: usize = 32;

static SECRET_KEY: OnceCell<[u8; KEY_SIZE]> = OnceCell::new();

#[no_mangle]
pub extern "C" fn ecall_get_encryption_key(
    out_pubkey: *mut u8,
    _out_pubkey_len: usize,
) -> sgx_status_t {
    // generates key pair
    let mut rnd = [0u8; KEY_SIZE];
    getrandom::getrandom(&mut rnd).unwrap();
    let secret_key = SecretKey::from(rnd);
    let public_key = secret_key.public_key();

    println!("Bob's secret key: {:?}", secret_key);
    println!("Bob's public key: {:?}", public_key);

    SECRET_KEY.set(secret_key.to_bytes()).unwrap();

    let v_pubkey = public_key.as_bytes();

    unsafe {
        ptr::copy_nonoverlapping(v_pubkey.as_ptr(), out_pubkey, v_pubkey.len());
    }

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn ecall_decrypt(
    in_nonce: *const u8,
    in_nonce_len: usize,
    in_pubkey: *const u8,
    in_pubkey_len: usize,
    in_ciphertext: *mut u8,
    in_ciphertext_len: usize,
) -> sgx_status_t {
    let nonce = unsafe { slice::from_raw_parts(in_nonce, in_nonce_len) };
    let nonce = GenericArray::from_slice(nonce);

    let mut pubkey_slice = unsafe { slice::from_raw_parts(in_pubkey, in_pubkey_len) };
    let mut buf = [0; KEY_SIZE];
    pubkey_slice.read_exact(&mut buf).unwrap();
    let alice_public_key = PublicKey::from(buf);

    let ciphertext = unsafe { slice::from_raw_parts(in_ciphertext, in_ciphertext_len) };

    // secret key
    let b = SECRET_KEY.get().unwrap();
    let bob_secret_key = SecretKey::from(*b);

    // decrypts the cipertext
    let decrypted = ChaChaBox::new(&alice_public_key, &bob_secret_key)
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad: b"".as_ref(),
            },
        )
        .unwrap();

    let decrypted = sgx_tstd::str::from_utf8(&decrypted).unwrap();
    println!("decrypted message: {}", decrypted);

    sgx_status_t::SGX_SUCCESS
}
