#[cfg(feature = "aes")]
mod aes256ctr;
mod api;
mod fips202;
mod ntt;
mod packing;
mod params;
mod poly;
mod polyvec;
mod randombytes;
mod reduce;
mod rounding;
mod sign;
mod symmetric;

pub use params::*;

pub use api::*;

mod aesrest;

#[cfg(test)]
mod tests {
    #[test]
    fn datetest() {
      use chrono::prelude::*;
      assert_eq!(Utc::now().to_string().is_empty(), false);
      let dt_nano = NaiveDate::from_ymd_opt(2014, 11, 28).unwrap().and_hms_nano_opt(12, 0, 9, 1).unwrap().and_local_timezone(Utc).unwrap();
      assert_eq!(format!("{:?}", dt_nano), "2014-11-28T12:00:09.000000001Z");
    }

    #[test]
    fn encrypttest() {
      use crate::Keypair;
      use crate::aesrest;
      use std::os::unix::fs::PermissionsExt;
      use std::fs::{set_permissions, File};
      use std::io::{self, Write};
      use zeroize::Zeroize;

      let keys = Keypair::generate();
      let key_path = "/tmp/wormsign_test.key";
      let pub_path = "/tmp/wormsign_test.pub";
      let _ = File::create(key_path).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to create key file {}: {}", key_path, e)));
      let _ = set_permissions(&key_path, PermissionsExt::from_mode(0o600)).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to set permissions on {}: {}", key_path, e)));
      let mut puboutput = File::create(pub_path).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to create public key file {}: {}", pub_path, e))).expect("failed to create public key");
      let _ = puboutput.write_all(&keys.public).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to write public key: {}", e)));
      let _ = std::io::stdout().flush().map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to flush stdout: {}", e)));
      let password = "000000999999888888777777666666555555";
      let mut keymaterial = aesrest::derive_key(password.as_bytes(), 32);
      let results = aesrest::encrypt_key(keys.expose_secret().to_vec(), key_path, &keymaterial).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to encrypt key file: {}", e)));
      keymaterial.zeroize();
      assert!(results.is_ok());
    }

    #[test]
    fn decrypttest() {
      use crate::Keypair;
      use crate::aesrest;
      use std::os::unix::fs::PermissionsExt;
      use std::fs::{set_permissions, File};
      use std::io::{self,  Write};
      use zeroize::Zeroize;

      let keys = Keypair::generate();
      let key_path = "/tmp/wormsign_test.key";
      let pub_path = "/tmp/wormsign_test.pub";
      let _ = File::create(key_path).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to create key file {}: {}", key_path, e)));
      let _ = set_permissions(&key_path, PermissionsExt::from_mode(0o600)).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to set permissions on {}: {}", key_path, e)));
      let mut puboutput = File::create(pub_path).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to create public key file {}: {}", pub_path, e))).expect("failed to create public key");
      let _ = puboutput.write_all(&keys.public).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to write public key: {}", e)));
      let _ = std::io::stdout().flush().map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to flush stdout: {}", e)));
      let password = "000000999999888888777777666666555555";
      let mut keymaterial = aesrest::derive_key(password.as_bytes(), 32);
      let _ = aesrest::encrypt_key(keys.expose_secret().to_vec(), key_path, &keymaterial).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to encrypt key file: {}", e)));
      let results = aesrest::decrypt_key(key_path, &keymaterial);
      keymaterial.zeroize();
      assert!(results.is_ok());
    }

    #[test]
    fn dilithiumtest() {
      use crate::verify;
      use crate::Keypair;

      let keys = Keypair::generate();
      let msg = [0u8; 32];
      let sig = keys.sign(&msg);
      let sig_verify = verify(&sig, &msg, &keys.public);
      assert!(sig_verify.is_ok());
    }
}
