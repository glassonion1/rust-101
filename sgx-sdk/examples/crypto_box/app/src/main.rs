use crypto_box::{
    aead::{Aead, Payload},
    ChaChaBox, PublicKey, SecretKey,
};
use rand_chacha::rand_core::SeedableRng;
use sgx_types::*;
use sgx_urts::SgxEnclave;
use std::io::Read;

static ENCLAVE_FILE: &'static str = "enclave.signed.so";
const MAX_OUT_LEN: usize = 1024;
const KEY_SIZE: usize = 32;

extern "C" {
    fn ecall_encrypt(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        in_nonce: *const u8,
        in_noce_len: usize,
        in_msg: *const u8,
        in_msg_len: usize,
        in_pubkey: *const u8,
        in_pubkey_len: usize,
        out_ciphertext: *mut u8,
        out_max_len: usize,
        out_ciphertext_len: &mut usize,
        out_pubkey: *mut u8,
        out_pubkey_len: usize,
    ) -> sgx_status_t;
}

fn init_enclave() -> SgxResult<SgxEnclave> {
    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;
    // call sgx_create_enclave to initialize an enclave instance
    // Debug Support: set 2nd parameter to 1
    let debug = 1;
    let mut misc_attr = sgx_misc_attribute_t {
        secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 },
        misc_select: 0,
    };
    SgxEnclave::create(
        ENCLAVE_FILE,
        debug,
        &mut launch_token,
        &mut launch_token_updated,
        &mut misc_attr,
    )
}

fn main() {
    let enclave = match init_enclave() {
        Ok(r) => {
            println!("[+] Init Enclave Successful {}!", r.geteid());
            r
        }
        Err(x) => {
            println!("[-] Init Enclave Failed {}!", x.as_str());
            return;
        }
    };

    let mut rng = rand_chacha::ChaChaRng::from_seed(Default::default());

    // generates key pair
    let alice_secret_key = SecretKey::generate(&mut rng);
    let alice_public_key = alice_secret_key.public_key();

    println!("Alice's secret key: {:?}", alice_secret_key.to_bytes());
    println!("Alice's public key: {:?}", alice_public_key);

    let nonce = crypto_box::generate_nonce(&mut rng);

    let msg = String::from("hello bob!");
    let b_pubkey = alice_public_key.as_bytes();

    let mut retval = sgx_status_t::SGX_SUCCESS;
    let mut ciphertext = vec![0; MAX_OUT_LEN];
    let mut ciphertext_len = MAX_OUT_LEN;
    let mut bob_public_key = vec![0; KEY_SIZE];

    let result = unsafe {
        ecall_encrypt(
            enclave.geteid(),
            &mut retval,
            nonce.as_ptr(),
            nonce.len(),
            msg.as_ptr() as *const u8,
            msg.len(),
            b_pubkey.as_ptr(),
            b_pubkey.len(),
            ciphertext.as_mut_ptr(),
            MAX_OUT_LEN,
            &mut ciphertext_len,
            bob_public_key.as_mut_ptr(),
            KEY_SIZE,
        )
    };
    if result != sgx_status_t::SGX_SUCCESS {
        println!("[-] ECALL Enclave Failed {}!", result.as_str());
        return;
    }
    if retval != sgx_status_t::SGX_SUCCESS {
        println!("[-] ECALL Enclave Failed {}!", retval.as_str());
        return;
    }

    let ciphertext = &ciphertext[0..ciphertext_len];
    println!("{:?}", ciphertext);
    println!("{:?}", bob_public_key);
    let mut buf = [0; KEY_SIZE];
    (&bob_public_key[..]).read_exact(&mut buf).unwrap();
    let bob_public_key = PublicKey::from(buf);

    // decrypts the cipertext
    let decrypted = ChaChaBox::new(&bob_public_key, &alice_secret_key)
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad: b"".as_ref(),
            },
        )
        .unwrap();

    let decrypted = std::str::from_utf8(&decrypted).unwrap();
    println!("{}", decrypted);

    assert_eq!(msg, decrypted);

    println!("[+] nacl success...");
    enclave.destroy();
}
