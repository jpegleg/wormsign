use crate::params::{PUBLICKEYBYTES, SECRETKEYBYTES, SIGNBYTES};
use crate::sign::*;

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct Keypair {
  pub public: [u8; PUBLICKEYBYTES],
  secret: [u8; SECRETKEYBYTES],
}

/// Secret key elided.
impl std::fmt::Debug for Keypair {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "public: {:?}\nsecret: <elided>", self.public)
  }
}

pub enum SignError {
  Input,
  Verify,
}


impl Keypair {
/// Re-implement the Keypair
/// to add the loadit function
/// for loading an existing keypair.
  pub fn loadit(pub_bytes: Vec<u8>, sec_bytes: Vec<u8>) -> Self {
    Self {
      public: pub_bytes.try_into().unwrap(),
      secret: sec_bytes.try_into().unwrap(),
    }
  }

/// From upstream: expose_secret, generate, and sign.
  pub fn expose_secret(&self) -> &[u8] {
    &self.secret
  }

  pub fn generate() -> Keypair {
    let mut public = [0u8; PUBLICKEYBYTES];
    let mut secret = [0u8; SECRETKEYBYTES];
    crypto_sign_keypair(&mut public, &mut secret, None);
    Keypair { public, secret }
  }

  pub fn sign(&self, msg: &[u8]) -> [u8; SIGNBYTES] {
    let mut sig = [0u8; SIGNBYTES];
    crypto_sign_signature(&mut sig, msg, &self.secret);
    sig
  }

}

/// Verify a signature by supplying the signature, message, and public key as &[u8].
pub fn verify(
  sig: &[u8],
  msg: &[u8],
  public_key: &[u8],
) -> Result<(), SignError> {
  if sig.len() != SIGNBYTES {
    return Err(SignError::Input);
  }
  crypto_sign_verify(&sig, &msg, public_key)
}
