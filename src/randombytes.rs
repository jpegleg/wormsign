use rand::TryRngCore;
use rand::rngs::OsRng;

pub fn randombytes(x: &mut [u8], len: usize) {
  OsRng.try_file_bytes(&mut x[..len]).expect("OS failed to provide entropy")
}
