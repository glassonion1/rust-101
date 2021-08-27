#![crate_name = "cryptoboxenclave"]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd;

use crypto_box::{
    aead::{Aead, Payload},
    ChaChaBox, SecretKey,
};
use rand_chacha::rand_core::SeedableRng;
use sgx_trts::trts::rsgx_read_rand;
use sgx_tstd::string::String;
use sgx_types::sgx_status_t;

const KEY_SIZE: usize = 32;

#[no_mangle]
pub extern "C" fn ecall_encrypt() -> sgx_status_t {
    // generates random from chacha20
    let mut seed = [0u8; KEY_SIZE];
    match rsgx_read_rand(&mut seed) {
        Ok(_) => (),
        Err(e) => return e,
    };

    let mut rng = rand_chacha::ChaChaRng::from_seed(seed);
    // generates Alice's key pair
    let alice_secret_key = SecretKey::generate(&mut rng);
    let alice_public_key = alice_secret_key.public_key();
    // generates Bob's key pair
    let bob_secret_key = SecretKey::generate(&mut rng);
    let bob_public_key = bob_secret_key.public_key();
    // generates a nonce.
    let nonce = crypto_box::generate_nonce(&mut rng);

    // encrypts the plaintext
    let plaintext = "hello Bob";
    let ciphertext = ChaChaBox::new(&bob_public_key, &alice_secret_key)
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext.as_bytes(),
                aad: b"".as_ref(), // Additional Authentication data
            },
        )
        .unwrap();

    // outputs the ciphertext of string
    let t = ciphertext
        .iter()
        .map(|&c| format!("{:02x}", c))
        .collect::<String>();
    println!("{}", t);

    // decrypts the cipertext
    let decrypted = ChaChaBox::new(&alice_public_key, &bob_secret_key)
        .decrypt(
            &nonce,
            Payload {
                msg: &ciphertext,
                aad: b"".as_ref(),
            },
        )
        .unwrap();

    let decrypted = sgx_tstd::str::from_utf8(&decrypted).unwrap();
    println!("{}", decrypted);

    sgx_status_t::SGX_SUCCESS
}
