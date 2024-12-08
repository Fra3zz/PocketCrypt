use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding};
use rand::rngs::OsRng;

pub fn generate_rsa_keys(key_size: usize) -> Result<(String, String), Box<dyn std::error::Error>> {
    let mut rng = OsRng;

    // Generate a new private key
    let private_key = RsaPrivateKey::new(&mut rng, key_size)?;
    let public_key = RsaPublicKey::from(&private_key);

    // Convert keys to PEM format with specified line endings
    let private_key_pem = private_key.to_pkcs1_pem(LineEnding::LF)?.to_string();
    let public_key_pem = public_key.to_pkcs1_pem(LineEnding::LF)?.to_string();

    Ok((private_key_pem, public_key_pem))
}
