//! A simple, correct TOTP library.

use hmac::{Hmac, Mac, NewMac};
use sha2::Sha512;

// TODO Make `no-std`!

const STEP: u64 = 30; // 30 seconds.

type Hmac512 = Hmac<Sha512>;

pub fn totp(digits: u32, secret: &[u8], time: u64) -> String {
    // Hash the secret and the time together.
    let mut mac = Hmac512::new_varkey(secret).unwrap();
    mac.update(&to_bytes(time_factor(time)));
    let hash: &[u8] = &mac.finalize().into_bytes();

    // Magic from the RFC.
    let offset: usize = (hash.last().unwrap() & 0xf) as usize;
    let binary: u64 = (((hash[offset] & 0x7f) as u64) << 24)
        | (((hash[offset + 1] & 0xff) as u64) << 16)
        | (((hash[offset + 2] & 0xff) as u64) << 8)
        | ((hash[offset + 3] & 0xff) as u64);

    format!("{:08}", binary % (10_u64.pow(digits)))
}

/// Convert a `u64` into its individual bytes.
fn to_bytes(n: u64) -> Vec<u8> {
    let mask = 0x00000000000000ff;
    let mut vec: Vec<u8> = (0..8).map(|i| (mask & (n >> (i * 8))) as u8).collect();
    vec.reverse();
    vec
}

/// The `T` value required for TOTP.
fn time_factor(time: u64) -> u64 {
    time / STEP
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_bytes_test() {
        assert_eq!(vec![0, 0, 0, 0, 0, 0, 0, 1], to_bytes(time_factor(59)));
        assert_eq!(
            vec![0, 0, 0, 0, 0x02, 0x35, 0x23, 0xec],
            to_bytes(time_factor(1111111109))
        );
        assert_eq!(
            vec![0, 0, 0, 0, 0x27, 0xbc, 0x86, 0xaa],
            to_bytes(time_factor(20000000000))
        );
    }

    #[test]
    fn totp_tests() {
        let secret: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";
        assert_eq!(64, secret.len());
        assert_eq!("90693936", totp(8, secret, 59));
        assert_eq!("25091201", totp(8, secret, 1111111109));
        assert_eq!("93441116", totp(8, secret, 1234567890));
        assert_eq!("38618901", totp(8, secret, 2000000000));
        assert_eq!("47863826", totp(8, secret, 20000000000));
    }
}
