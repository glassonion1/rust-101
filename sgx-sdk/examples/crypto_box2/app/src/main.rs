use crypto_box::{
    aead::{Aead, Payload},
    ChaChaBox, PublicKey, SecretKey,
};
use sgx_types::*;
use sgx_urts::SgxEnclave;
use std::io::Read;

static ENCLAVE_FILE: &'static str = "enclave.signed.so";
const KEY_SIZE: usize = 32;

extern "C" {
    fn ecall_get_encryption_key(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        out_pubkey: *mut u8,
        out_pubkey_len: usize,
    ) -> sgx_status_t;

    fn ecall_decrypt(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        in_nonce: *const u8,
        in_noce_len: usize,
        in_pubkey: *const u8,
        in_pubkey_len: usize,
        in_ciphertext: *const u8,
        in_ciphertext_len: usize,
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

    // gets bob's public key
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let mut key = vec![0; KEY_SIZE];
    let key_ptr = key.as_mut_ptr();

    let result =
        unsafe { ecall_get_encryption_key(enclave.geteid(), &mut retval, key_ptr, key.len()) };
    if result != sgx_status_t::SGX_SUCCESS {
        println!("[-] ECALL Enclave Failed {}!", result.as_str());
        return;
    }
    if retval != sgx_status_t::SGX_SUCCESS {
        println!("[-] ECALL Enclave Failed {}!", retval.as_str());
        return;
    }

    let mut buf = [0; KEY_SIZE];
    (&key[..]).read_exact(&mut buf).unwrap();
    let bob_public_key = PublicKey::from(buf);

    // generates key pair
    let mut rng = rand_core::OsRng;
    let alice_secret_key = SecretKey::generate(&mut rng);
    let alice_public_key = alice_secret_key.public_key();

    println!("Alice's secret key: {:?}", alice_secret_key);
    println!("Alice's public key: {:?}", alice_public_key);

    let nonce = crypto_box::generate_nonce(&mut rng);
    let msg = String::from("hello bob!");
    // ecrypts the message
    let ciphertext = ChaChaBox::new(&bob_public_key, &alice_secret_key)
        .encrypt(
            &nonce,
            Payload {
                msg: msg.as_bytes(),
                aad: b"".as_ref(), // Additional Authentication data
            },
        )
        .unwrap();

    println!("encrypted message: {:?}", ciphertext);

    let mut retval = sgx_status_t::SGX_SUCCESS;
    let b_pubkey = alice_public_key.as_bytes();

    let result = unsafe {
        ecall_decrypt(
            enclave.geteid(),
            &mut retval,
            nonce.as_ptr(),
            nonce.len(),
            b_pubkey.as_ptr(),
            b_pubkey.len(),
            ciphertext.as_ptr(),
            ciphertext.len(),
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

    println!("[+] crypto_box success...");
    enclave.destroy();
}
