use rand_core::{impls, CryptoRng, Error, RngCore};
use sgx_tstd::num::NonZeroU32;
use sgx_types::*;

extern "C" {
    pub fn ocall_getrandom(
        ret_val: *mut sgx_status_t,
        out_dest: *mut u8,
        out_dest_len: usize,
    ) -> sgx_status_t;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct OsRng;

impl CryptoRng for OsRng {}

impl RngCore for OsRng {
    fn next_u32(&mut self) -> u32 {
        impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if let Err(e) = self.try_fill_bytes(dest) {
            panic!("Error: {}", e);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
        let dest_ptr = dest.as_mut_ptr();

        let res = unsafe { ocall_getrandom(&mut rt as *mut sgx_status_t, dest_ptr, dest.len()) };
        if res != sgx_status_t::SGX_SUCCESS {
            return Err(NonZeroU32::new(Error::INTERNAL_START).unwrap().into());
        }
        if rt != sgx_status_t::SGX_SUCCESS {
            return Err(NonZeroU32::new(Error::INTERNAL_START).unwrap().into());
        }

        Ok(())
    }
}
