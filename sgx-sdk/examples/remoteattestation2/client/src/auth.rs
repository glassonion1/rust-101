use crate::cert::verify_ra_cert;
use sgx_types::*;

pub struct ServerAuth {
    outdated_ok: bool,
}

impl ServerAuth {
    pub fn new(outdated_ok: bool) -> ServerAuth {
        ServerAuth { outdated_ok }
    }
}

impl rustls::ServerCertVerifier for ServerAuth {
    fn verify_server_cert(
        &self,
        _roots: &rustls::RootCertStore,
        _certs: &[rustls::Certificate],
        _hostname: webpki::DNSNameRef,
        _ocsp: &[u8],
    ) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
        println!("--received-server cert: {:?}", _certs);

        match verify_ra_cert(&_certs[0].0) {
            Ok(()) => Ok(rustls::ServerCertVerified::assertion()),
            Err(sgx_status_t::SGX_ERROR_UPDATE_NEEDED) => {
                if self.outdated_ok {
                    println!("outdated_ok is set, overriding outdated error");
                    Ok(rustls::ServerCertVerified::assertion())
                } else {
                    Err(rustls::TLSError::WebPKIError(
                        webpki::Error::ExtensionValueInvalid,
                    ))
                }
            }
            Err(_) => Err(rustls::TLSError::WebPKIError(
                webpki::Error::ExtensionValueInvalid,
            )),
        }
    }
}
