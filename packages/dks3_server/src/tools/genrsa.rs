use std::error::Error;

use rand::rngs::StdRng;
use rand::SeedableRng;
use rsa::{PrivateKeyPemEncoding, PublicKeyPemEncoding, RSAPrivateKey, RSAPublicKey};

const SIZE: usize = 2048;

fn main() -> Result<(), Box<dyn Error>> {
    let mut rng = StdRng::from_entropy();

    let private_key = RSAPrivateKey::new(&mut rng, SIZE).expect("failed to generate a key");
    let public_key = RSAPublicKey::from(&private_key);

    println!("private key:\n{}", private_key.to_pem_pkcs1()?);
    println!("public key:\n{}", public_key.to_pem_pkcs1()?);

    Ok(())
}
