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
