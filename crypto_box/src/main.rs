use crypto_box::{
    aead::{Aead, Payload},
    ChaChaBox, SecretKey,
};
use rand_chacha::rand_core::SeedableRng;

fn main() {
    // generates random from chacha20
    let mut rng = rand_chacha::ChaChaRng::from_seed(Default::default());
    // generates Alice's key pair
    let alice_secret_key = SecretKey::generate(&mut rng);
    let alice_public_key = alice_secret_key.public_key();
    // generates Bob's key pair
    let bob_secret_key = SecretKey::generate(&mut rng);
    let bob_public_key = bob_secret_key.public_key();
    // generates a nonce.
    let nonce = crypto_box::generate_nonce(&mut rng);

    // encrypts the plaintext
    let plaintext = "hello Bob";
    let ciphertext = ChaChaBox::new(&bob_public_key, &alice_secret_key)
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext.as_bytes(),
                aad: b"".as_ref(), // Additional Authentication data
            },
        )
        .unwrap();

    // outputs the ciphertext of string
    let t = ciphertext
        .iter()
        .map(|&c| format!("{:02x}", c))
        .collect::<String>();
    println!("{}", t);

    // decrypts the cipertext
    let decrypted = ChaChaBox::new(&alice_public_key, &bob_secret_key)
        .decrypt(
            &nonce,
            Payload {
                msg: &ciphertext,
                aad: b"".as_ref(),
            },
        )
        .unwrap();

    let decrypted = std::str::from_utf8(&decrypted).unwrap();
    println!("{}", decrypted);

    assert_eq!(plaintext, decrypted);
}
