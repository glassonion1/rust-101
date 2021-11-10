use crypto_box::{
    aead::{Aead, Payload},
    ChaChaBox, PublicKey, SecretKey,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct EncryptionKey {
    key: [u8; 32],
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let resp =
        reqwest::blocking::get("http://127.0.0.1:8080/encription_key")?.json::<EncryptionKey>()?;
    println!("{:?}", resp.key);

    let server_public_key = PublicKey::from(resp.key);
    println!("{:?}", server_public_key);

    // generates random from os rng
    let mut rng = rand_core::OsRng;
    // generates private key
    let secret_key = SecretKey::generate(&mut rng);
    let nonce = crypto_box::generate_nonce(&mut rng);

    // encrypts the plaintext
    let plaintext = "hello Bob";
    let ciphertext = ChaChaBox::new(&server_public_key, &secret_key)
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext.as_bytes(),
                aad: b"".as_ref(), // Additional Authentication data
            },
        )
        .unwrap();

    let public_key = secret_key.public_key();

    // Posto

    Ok(())
}
