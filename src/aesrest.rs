use std::fs::File;
use std::io::{Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr64BE;
use rand::{RngCore, rngs::OsRng};
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};
use argon2::Argon2;

type Aes256Ctr = Ctr64BE<Aes256>;

/// Process a salt and key material input (password) with Argon2.
#[allow(unused)]
pub fn a2(password: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut okm = [0u8; 32];
    let _ = Argon2::default().hash_password_into(password, salt, &mut okm);
    okm
}

/// This function includes the fixed salt and mixes the salt
/// with the provided input material (password). The salt and password
/// go through Argon2, and then SHAKE256.
#[allow(unused)]
pub fn derive_key(password: &[u8], length: usize) -> Vec<u8> {
        let mut hasher = Shake256::default();
    let salt = b"07f9c8d6ab8d13f8bf68bcd8464186de";
    hasher.update(&a2(password, salt));
    let mut reader = hasher.finalize_xof();
    let mut key = vec![0u8; length];
    XofReader::read(&mut reader, &mut key);
    key
}

/// This function generates a nonce for counter mode AES-256
/// that is baesd on truncated epoch nanoseconds + 16 bytes
/// from system entropy.
#[allow(unused)]
fn generate_nonce() -> [u8; 16] {
    let mut nonce = [0u8; 16];
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let timestamp_nanos = now.as_nanos();
    nonce[0..8].copy_from_slice(&timestamp_nanos.to_le_bytes()[0..8]);
    OsRng.fill_bytes(&mut nonce[8..16]);
    nonce
}

/// This function encrypts the Dilithium secret key with the resulting key material,
/// writing the ciphertext to a file.
#[allow(unused)]
pub fn encrypt_key(mut input_data: Vec<u8>, output_file: &str, keymaterial: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let nonce = generate_nonce();
    let mut cipher = Aes256Ctr::new(keymaterial.into(), &nonce.into());
    cipher.apply_keystream(&mut input_data);
    let outdata: &[u8] = &input_data;
    let mut output = File::create(output_file)?;
    output.write_all(&nonce)?;
    output.write_all(&outdata)?;

    Ok(())
}

/// Read the ciphertext key file and decrypt it, returning the private key
/// data to the function caller for signing.
#[allow(unused)]
pub fn decrypt_key(input_file: &str, keymaterial: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut file = File::open(input_file)?;
    let mut nonce = [0u8; 16];
    file.read_exact(&mut nonce)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    let mut cipher = Aes256Ctr::new(keymaterial.into(), &nonce.into());
    cipher.apply_keystream(&mut data);

    Ok(data)
}
