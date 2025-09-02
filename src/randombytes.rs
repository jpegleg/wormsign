use rand::TryRngCore;
use rand::rngs::OsRng;

/// Generate random bytes from OS RNG.
pub fn randombytes(x: &mut [u8], len: usize) {
  OsRng.try_fill_bytes(&mut x[..len]).expect("OS failed to provide entropy")
}
