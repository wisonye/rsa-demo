use rand::thread_rng;
use rsa::{
    pkcs1v15::{SigningKey, VerifyingKey},
    rand_core::{CryptoRng, RngCore},
    PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey,
};
use sha2::Sha256;
use signature::{RandomizedSigner, Verifier};

///
///
///
fn pub_key_encrypt_and_private_key_decrypt<T: RngCore + CryptoRng>(
    rng: &mut T,
    public_key: &RsaPublicKey,
    private_key: &RsaPrivateKey,
) {
    let original_content = "Hey, this is the unencrypted text:)".to_string();
    println!(
        ">>> original_content (len: {}): {original_content}",
        original_content.len()
    );

    let bytes = original_content.as_bytes();
    println!(">>> bytes (len: {}): {bytes:?}", bytes.len());
    // println!("bytes back to string: {:#?}", String::from_utf8(bytes.to_vec()).unwrap());

    // Encrypt
    let encrypted_bytes = public_key
        .encrypt(rng, PaddingScheme::new_pkcs1v15_encrypt(), &bytes)
        .expect("failed to encrypt");
    println!(
        ">>> encrypted_bytes (len: {}): {encrypted_bytes:?}",
        encrypted_bytes.len()
    );

    // Decrypt
    let decrypted_bytes = private_key
        .decrypt(PaddingScheme::new_pkcs1v15_encrypt(), &encrypted_bytes)
        .expect("failed to decrypt");
    println!(
        ">>> decrypted_bytes  (len: {}): {decrypted_bytes:?}",
        decrypted_bytes.len()
    );

    let decrypted_string = String::from_utf8(decrypted_bytes).unwrap();
    println!(">>> decrypted_string: {decrypted_string:?}");

    assert_eq!(original_content, decrypted_string);
}

///
///
///
fn private_key_sign_and_public_key_verify<T: RngCore + CryptoRng>(
    rng: &mut T,
    sign_key: &SigningKey<Sha256>,
    verify_key: &VerifyingKey<Sha256>,
) {
    let original_content = "The message will be signed by private key:)".to_string();
    println!(
        "\n<<< content_from_me (len: {}): {original_content}",
        original_content.len()
    );

    let bytes = original_content.as_bytes();
    println!("<<< bytes (len: {}): {bytes:?}", bytes.len());

    // Sign
    let signed_hash = sign_key.sign_with_rng(rng, bytes);
    println!(
        "<<< signed_hash: (len: {}) {signed_hash:?}",
        signed_hash.len()
    );

    // Verify
    let verify_result = verify_key.verify(bytes, &signed_hash);
    println!(
        "<<< verify_result: {}",
        if verify_result.is_ok() {
            "Passed signature verification"
        } else {
            "Failed signature verification"
        }
    );
}

///
///
///
fn main() {
    let mut rng = thread_rng();
    let bits = 2048;

    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);
    let signing_key: SigningKey<Sha256> = SigningKey::new(private_key.clone());
    let verifying_key: VerifyingKey<_> = (&signing_key).into();

    pub_key_encrypt_and_private_key_decrypt(&mut rng, &public_key, &private_key);

    private_key_sign_and_public_key_verify(&mut rng, &signing_key, &verifying_key);
}
