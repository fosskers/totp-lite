//! A simple, correct TOTP library.

use core::clone::Clone;
use core::default::Default;
use digest::{BlockInput, FixedOutputDirty, Reset, Update};
use hmac::{Hmac, Mac, NewMac};
pub use sha1::Sha1;
pub use sha2::{Sha256, Sha512};

// TODO Make `no-std`!

const STEP: u64 = 30; // 30 seconds.

/// Produce a Time-based One-time Password with default settings.
pub fn totp<H>(digits: u32, secret: &[u8], time: u64) -> String
where
    H: Update + BlockInput + Reset + FixedOutputDirty + Clone + Default,
{
    // Hash the secret and the time together.
    let mut mac: Hmac<H> = Hmac::new_varkey(secret).unwrap();
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
    fn totp1_tests() {
        let secret: &[u8] = b"12345678901234567890";
        assert_eq!(20, secret.len());

        let pairs = vec![
            ("94287082", 59),
            ("07081804", 1111111109),
            ("14050471", 1111111111),
            ("89005924", 1234567890),
            ("69279037", 2000000000),
            ("65353130", 20000000000),
        ];

        pairs.into_iter().for_each(|(expected, time)| {
            assert_eq!(expected, totp::<Sha1>(8, secret, time));
        });
    }

    #[test]
    fn totp256_tests() {
        let secret: &[u8] = b"12345678901234567890123456789012";
        assert_eq!(32, secret.len());

        let pairs = vec![
            ("46119246", 59),
            ("68084774", 1111111109),
            ("67062674", 1111111111),
            ("91819424", 1234567890),
            ("90698825", 2000000000),
            ("77737706", 20000000000),
        ];

        pairs.into_iter().for_each(|(expected, time)| {
            assert_eq!(expected, totp::<Sha256>(8, secret, time));
        });
    }

    #[test]
    fn totp512_tests() {
        let secret: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";
        assert_eq!(64, secret.len());

        let pairs = vec![
            ("90693936", 59),
            ("25091201", 1111111109),
            ("99943326", 1111111111),
            ("93441116", 1234567890),
            ("38618901", 2000000000),
            ("47863826", 20000000000),
        ];

        pairs.into_iter().for_each(|(expected, time)| {
            assert_eq!(expected, totp::<Sha512>(8, secret, time));
        });
    }
}
