use crate::verification;
use sgx_types::*;

pub struct ClientVerifier {
    outdated_ok: bool,
}

impl ClientVerifier {
    pub fn new(outdated_ok: bool) -> ClientVerifier {
        ClientVerifier {
            outdated_ok: outdated_ok,
        }
    }
}

impl rustls::ClientCertVerifier for ClientVerifier {
    fn client_auth_root_subjects(
        &self,
        _sni: Option<&webpki::DNSName>,
    ) -> Option<rustls::DistinguishedNames> {
        Some(rustls::DistinguishedNames::new())
    }

    fn verify_client_cert(
        &self,
        certs: &[rustls::Certificate],
        _sni: Option<&webpki::DNSName>,
    ) -> Result<rustls::ClientCertVerified, rustls::TLSError> {
        println!("--received-client cert: {:?}", certs);

        match verification::verify_ra_cert(&certs[0].0) {
            Ok(()) => Ok(rustls::ClientCertVerified::assertion()),
            Err(sgx_status_t::SGX_ERROR_UPDATE_NEEDED) => {
                if self.outdated_ok {
                    println!("outdated_ok is set, overriding outdated error");
                    Ok(rustls::ClientCertVerified::assertion())
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
