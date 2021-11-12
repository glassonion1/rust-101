use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use sgx_types::*;
use sgx_urts::SgxEnclave;
use std::convert::TryInto;
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

#[derive(Clone)]
struct Enclave {
    eid: sgx_enclave_id_t,
}

#[derive(Serialize, Clone)]
struct ResponseBody {
    message: String,
}

#[derive(Serialize, Clone)]
struct EncryptionKey {
    key: [u8; 32],
}

#[derive(Deserialize, Clone)]
struct Message {
    ciphertext: String,
    public_key: String,
    nonce: String,
}

#[get("/encription_key")]
async fn get_encription_key(enclave: web::Data<Enclave>) -> impl Responder {
    // gets server public key
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let mut key = vec![0; KEY_SIZE];
    let key_ptr = key.as_mut_ptr();

    let result = unsafe { ecall_get_encryption_key(enclave.eid, &mut retval, key_ptr, key.len()) };
    if result != sgx_status_t::SGX_SUCCESS {
        return HttpResponse::BadRequest().json(ResponseBody {
            message: result.as_str().to_string(),
        });
    }
    if retval != sgx_status_t::SGX_SUCCESS {
        return HttpResponse::BadRequest().json(ResponseBody {
            message: retval.as_str().to_string(),
        });
    }
    HttpResponse::Ok().json(EncryptionKey {
        key: key.try_into().expect("slice with incorrect length"),
    })
}

async fn register_contract(value: String) -> web3::contract::Result<()> {
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

    let value = format!("{:?}", &value);
    println!("{}", value.clone());

    let tx = contract
        .call("addValue", (value,), accounts[0], Options::default())
        .await?;
    println!("TxHash: {}", tx);

    Ok(())
}

#[post("/messages")]
async fn post_messages(msg: web::Json<Message>, enclave: web::Data<Enclave>) -> impl Responder {
    /*
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let nonce = msg.nonce.as_bytes();
    let b_pubkey = msg.public_key.as_bytes();
    let ciphertext = msg.ciphertext.as_bytes();

    print!("nonce: {}", msg.nonce);
    print!("key: {}", msg.public_key);
    print!("text: {}", msg.ciphertext);
    print!("eid: {}", enclave.eid);

    let result = unsafe {
        ecall_decrypt(
            enclave.eid,
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
        return HttpResponse::BadRequest().json(ResponseBody {
            message: result.as_str().to_string(),
        });
    }
    if retval != sgx_status_t::SGX_SUCCESS {
        println!("[-] ECALL Enclave Failed {}!", retval.as_str());
        return HttpResponse::BadRequest().json(ResponseBody {
            message: retval.as_str().to_string(),
        });
    }

    */

    // Register value into blockchain
    let result = register_contract(msg.ciphertext.clone()).await;

    match result {
        Ok(posts) => HttpResponse::Created().json(posts),
        _ => HttpResponse::BadRequest().body("failed to register contract"),
    }
    //HttpResponse::Created().body("test")
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

#[actix_web::main]
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

    let eid = enclave.geteid();

    HttpServer::new(move || {
        App::new()
            .data(Enclave { eid: eid })
            .service(get_encription_key)
            .service(post_messages)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await?;

    println!("[+] crypto_box success...");
    enclave.destroy();

    Ok(())
}
