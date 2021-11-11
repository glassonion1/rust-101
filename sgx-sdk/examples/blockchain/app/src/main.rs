use anyhow::Result;
use crypto_box::{
    aead::{Aead, Payload},
    ChaChaBox, PublicKey, SecretKey,
};
use sgx_types::*;
use sgx_urts::SgxEnclave;
use std::io::Read;
use std::str::FromStr;
use web3::contract::{Contract, Options};
use web3::types::Address;

static ENCLAVE_FILE: &'static str = "enclave.signed.so";
const KEY_SIZE: usize = 32;

extern "C" {
    fn ecall_get_encryption_key(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
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

#[tokio::main]
async fn main() -> Result<()> {
    let enclave = match init_enclave() {
        Ok(r) => {
            println!("[+] Init Enclave Successful {}!", r.geteid());
            r
        }
        Err(x) => {
            println!("[-] Init Enclave Failed {}!", x.as_str());
            return Ok(());
        }
    };

    // gets server public key
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let mut key = vec![0; KEY_SIZE];
    let key_ptr = key.as_mut_ptr();

    let result =
        unsafe { ecall_get_encryption_key(enclave.geteid(), &mut retval, key_ptr, key.len()) };

    if result != sgx_status_t::SGX_SUCCESS {
        println!("[-] ECALL Enclave Failed {}!", result.as_str());
        return Ok(());
    }
    if retval != sgx_status_t::SGX_SUCCESS {
        println!("[-] ECALL Enclave Failed {}!", retval.as_str());
        return Ok(());
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

    let transport = web3::transports::Http::new("http://host.docker.internal:8545")?;
    let web3 = web3::Web3::new(transport);

    let accounts = web3.eth().accounts().await?;

    let contract_addr = Address::from_str("5fbdb2315678afecb367f032d93f642f64180aa3").unwrap();
    let contract = Contract::from_json(
        web3.eth(),
        contract_addr,
        include_bytes!("../contract/abi/storage.json"),
    )
    .unwrap();

    let value = format!("{:?}", ciphertext);
    println!("{}", value.clone());

    let tx = contract
        .call("addValue", (value,), accounts[0], Options::default())
        .await?;
    println!("TxHash: {}", tx);

    println!("[+] crypto_box success...");
    enclave.destroy();

    Ok(())
}
