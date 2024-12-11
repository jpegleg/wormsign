use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr64BE;
use rand::{RngCore, rngs::OsRng};
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};
type Aes256Ctr = Ctr64BE<Aes256>;

pub fn derive_key(password: &[u8], length: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    let salteze = b"07f9c8d6ab8d13f8bf68bcd8464186de";
    hasher.update(salteze);
    hasher.update(password);
    let mut reader = hasher.finalize_xof();
    let mut key = vec![0u8; length];
    XofReader::read(&mut reader, &mut key);
    key
}

fn generate_nonce() -> [u8; 16] {
    let mut nonce = [0u8; 16];
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let timestamp_nanos = now.as_nanos();
    nonce[0..8].copy_from_slice(&timestamp_nanos.to_le_bytes()[0..8]);
    OsRng.fill_bytes(&mut nonce[8..16]);
    nonce
}

pub fn encrypt_file(input_file: &str, output_file: &str, keymaterial: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::open(input_file)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    let nonce = generate_nonce();

    let mut cipher = Aes256Ctr::new(keymaterial.into(), &nonce.into());
    cipher.apply_keystream(&mut data);

    let mut output = File::create(output_file)?;
    output.write_all(&nonce)?;
    output.write_all(&data)?;

    Ok(())
}

pub fn decrypt_file(input_file: &str, output_file: &str, keymaterial: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::open(input_file)?;
    let mut nonce = [0u8; 16];
    file.read_exact(&mut nonce)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    let mut cipher = Aes256Ctr::new(keymaterial.into(), &nonce.into());
    cipher.apply_keystream(&mut data);

    let mut output = File::create(output_file)?;
    output.write_all(&data)?;

    Ok(())
}
