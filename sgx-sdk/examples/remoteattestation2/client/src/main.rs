use std::io::{self, BufReader, Read, Write};
use std::net::TcpStream;
use std::str;
use std::sync::Arc;

const SERVER_HOST: &str = "localhost";
const SERVER_PORT: &str = "3443";

mod cert;
mod pib;
mod verifier;

fn make_config() -> rustls::ClientConfig {
    let mut config = rustls::ClientConfig::new();

    let client_cert = include_bytes!("../../cert/client.crt");
    let mut cc_reader = BufReader::new(&client_cert[..]);

    let client_pkcs8_key = include_bytes!("../../cert/client.pkcs8");
    let mut client_key_reader = BufReader::new(&client_pkcs8_key[..]);

    let certs = rustls::internal::pemfile::certs(&mut cc_reader).unwrap();
    let privk = rustls::internal::pemfile::pkcs8_private_keys(&mut client_key_reader);

    config
        .set_single_client_cert(certs, privk.unwrap()[0].clone())
        .unwrap();

    config
        .dangerous()
        .set_certificate_verifier(Arc::new(verifier::ServerVerifier::new(true)));
    config.versions.clear();
    config.versions.push(rustls::ProtocolVersion::TLSv1_3);

    config
}

fn main() {
    println!("Starting ra-client");

    let addr = format!("{}:{}", SERVER_HOST, SERVER_PORT);

    println!("Connecting to {}", addr);

    let client_config = make_config();
    let dns_name = webpki::DNSNameRef::try_from_ascii_str(SERVER_HOST).unwrap();
    let mut sess = rustls::ClientSession::new(&Arc::new(client_config), dns_name);

    let mut conn = TcpStream::connect(addr).unwrap();

    let mut tls = rustls::Stream::new(&mut sess, &mut conn);

    tls.write_all(b"hello").unwrap();

    let mut plaintext = Vec::new();
    match tls.read_to_end(&mut plaintext) {
        Ok(_) => {
            println!("Server replied: {}", str::from_utf8(&plaintext).unwrap());
        }
        Err(ref err) if err.kind() == io::ErrorKind::ConnectionAborted => {
            println!("EOF (tls)");
        }
        Err(e) => println!("Error in read_to_end: {:?}", e),
    }
}
