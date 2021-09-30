use sgx_types::*;
use sgx_urts::SgxEnclave;
use std::net::TcpListener;
use std::os::unix::io::AsRawFd;

use crate::event_fd::{CancellableIncoming, EventFd};
mod event_fd;

static ENCLAVE_FILE: &'static str = "enclave.signed.so";

#[no_mangle]
pub extern "C" fn ocall_sgx_init_quote(
    ret_ti: *mut sgx_target_info_t,
    ret_gid: *mut sgx_epid_group_id_t,
) -> sgx_status_t {
    println!("Entering ocall_sgx_init_quote");
    unsafe { sgx_init_quote(ret_ti, ret_gid) }
}

#[no_mangle]
pub extern "C" fn ocall_get_quote(
    p_sigrl: *const u8,
    sigrl_len: u32,
    p_report: *const sgx_report_t,
    quote_type: sgx_quote_sign_type_t,
    p_spid: *const sgx_spid_t,
    p_nonce: *const sgx_quote_nonce_t,
    p_qe_report: *mut sgx_report_t,
    p_quote: *mut u8,
    _maxlen: u32,
    p_quote_len: *mut u32,
) -> sgx_status_t {
    println!("Entering ocall_get_quote");

    let mut real_quote_len: u32 = 0;

    let ret = unsafe { sgx_calc_quote_size(p_sigrl, sigrl_len, &mut real_quote_len as *mut u32) };

    if ret != sgx_status_t::SGX_SUCCESS {
        println!("sgx_calc_quote_size returned {}", ret);
        return ret;
    }

    println!("quote size = {}", real_quote_len);
    unsafe {
        *p_quote_len = real_quote_len;
    }

    let ret = unsafe {
        sgx_get_quote(
            p_report,
            quote_type,
            p_spid,
            p_nonce,
            p_sigrl,
            sigrl_len,
            p_qe_report,
            p_quote as *mut sgx_quote_t,
            real_quote_len,
        )
    };

    if ret != sgx_status_t::SGX_SUCCESS {
        println!("sgx_calc_quote_size returned {}", ret);
        return ret;
    }

    println!("sgx_calc_quote_size returned {}", ret);
    ret
}

#[no_mangle]
pub extern "C" fn ocall_get_update_info(
    platform_blob: *const sgx_platform_info_t,
    enclave_trusted: i32,
    update_info: *mut sgx_update_info_bit_t,
) -> sgx_status_t {
    unsafe { sgx_report_attestation_status(platform_blob, enclave_trusted, update_info) }
}

extern "C" {
    fn run_server_session(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        socket_fd: c_int,
        sign_type: sgx_quote_sign_type_t,
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

    println!("Running as server...");

    // https://stackoverflow.com/questions/56692961/graceful-exit-tcplistener-incoming
    let shutdown = EventFd::new();
    let listener = TcpListener::bind("0.0.0.0:3443").unwrap();
    let incoming = CancellableIncoming::new(&listener, &shutdown);

    for stream in incoming {
        match stream {
            Ok(socket) => {
                println!("connects new client");
                let mut retval = sgx_status_t::SGX_SUCCESS;
                let sign_type = sgx_quote_sign_type_t::SGX_LINKABLE_SIGNATURE;

                let result = unsafe {
                    run_server_session(enclave.geteid(), &mut retval, socket.as_raw_fd(), sign_type)
                };
                if result != sgx_status_t::SGX_SUCCESS {
                    println!("[-] ECALL Enclave Failed {}!", result.as_str());
                    return;
                }
                if retval != sgx_status_t::SGX_SUCCESS {
                    println!("[-] ECALL Enclave Failed {}!", retval.as_str());
                    return;
                }
            }
            Err(e) => panic!("Unexpected error: {}", e),
        }
    }

    match shutdown.add(1) {
        Ok(s) => {
            println!("{}", s);
        }
        Err(e) => {
            println!("{}", e);
        }
    };

    println!("[+] Done!");
    enclave.destroy();
}
