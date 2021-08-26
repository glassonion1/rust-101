use sgx_types::*;
use sgx_urts::SgxEnclave;
use std::{io::Read, ptr, slice};

static ENCLAVE_FILE: &'static str = "enclave.signed.so";

extern "C" {
    fn ecall_encrypt(eid: sgx_enclave_id_t, retval: *mut sgx_status_t) -> sgx_status_t;
}

#[no_mangle]
pub extern "C" fn ocall_getrandom(out_dest: *mut u8, out_dest_len: usize) -> sgx_status_t {
    let mut dest_slice = unsafe { slice::from_raw_parts(out_dest, out_dest_len) };
    let mut tmp = vec![0u8; out_dest_len];
    let mut dest = &mut tmp;
    dest_slice.read_exact(&mut dest).unwrap();

    let ret = getrandom::getrandom(&mut dest);
    if ret != Ok(()) {
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    }

    unsafe {
        ptr::copy_nonoverlapping(dest.as_ptr(), out_dest, dest.len());
    }

    sgx_status_t::SGX_SUCCESS
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

    let mut retval = sgx_status_t::SGX_SUCCESS;

    let result = unsafe { ecall_encrypt(enclave.geteid(), &mut retval) };
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
