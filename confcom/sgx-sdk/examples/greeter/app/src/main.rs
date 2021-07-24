use sgx_types::*;
use sgx_urts::SgxEnclave;
use std::slice;

static ENCLAVE_FILE: &'static str = "enclave.signed.so";

#[no_mangle]
pub extern "C" fn pong(message: *const u8, len: usize) {
    let str_slice = unsafe { slice::from_raw_parts(message, len) };
    println!("{}", String::from_utf8(str_slice.to_vec()).unwrap());
}

extern "C" {
    fn ping(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        message: *const u8,
        len: usize,
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

    let msg = String::from("ping");
    let mut retval = sgx_status_t::SGX_SUCCESS;

    let result = unsafe {
        ping(
            enclave.geteid(),
            &mut retval,
            msg.as_ptr() as *const u8,
            msg.len(),
        )
    };
    match result {
        sgx_status_t::SGX_SUCCESS => {}
        _ => {
            println!("[-] ECALL Enclave Failed {}!", result.as_str());
            return;
        }
    }
    println!("[+] greeting success...");
    enclave.destroy();
}
