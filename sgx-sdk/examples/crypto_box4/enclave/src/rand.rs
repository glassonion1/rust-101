use rand_core::{impls, CryptoRng, Error, RngCore};
use sgx_trts::trts::rsgx_read_rand;
use sgx_tstd::num::NonZeroU32;

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
        match rsgx_read_rand(dest) {
            Ok(()) => Ok(()),
            Err(_) => Err(NonZeroU32::new(Error::INTERNAL_START).unwrap().into()),
        }
    }
}
