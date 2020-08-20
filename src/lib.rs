//! A simple, correct TOTP library.
//!
//! Time-based One-time Passwords are a useful way to authenticate a client,
//! since a valid password expires long before it could ever be guessed by an
//! attacker. This library provides an implementation of TOTP that matches its
//! specification [RFC6238], along with a simple interface.
//!
//! # Usage
//!
//! The [`totp`](fn.totp.hmtl) function is likely what you need. It uses the
//! default time step of 30 seconds and produces 8 digits of output:
//!
//! ```
//! use std::time::{SystemTime, UNIX_EPOCH};
//! use totp_lite::{totp, Sha512};
//!
//! // Negotiated between you and the authenticating service.
//! let password: &[u8] = b"secret";
//!
//! // The number of seconds since the Unix Epoch.
//! let seconds: u64 = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
//!
//! // Specify the desired Hash algorithm via a type parameter.
//! // `Sha1` and `Sha256` are also available.
//! let result: String = totp::<Sha512>(password, seconds);
//! assert_eq!(8, result.len());
//! ```
//!
//! For full control over how the algorithm is configured, consider
//! [`totp_custom`](fn.totp_custom.html).
//!
//! # `no_std`
//!
//! As-is, this crate satisfies `no_std`. You will need to find the current time
//! without using `std::time::SystemTime`.
//!
//! # Resources
//! - [RFC6238: TOTP][RFC6238]
//! - [RFC6238 Errata](https://www.rfc-editor.org/errata_search.php?rfc=6238)
//!
//! [RFC6238]: https://tools.ietf.org/html/rfc6238

use core::clone::Clone;
use core::default::Default;
use digest::{BlockInput, FixedOutputDirty, Reset, Update};
use hmac::{Hmac, Mac, NewMac};
pub use sha1::Sha1;
pub use sha2::{Sha256, Sha512};

// TODO Make `no-std`!

/// 30 seconds.
pub const DEFAULT_STEP: u64 = 30;

/// 8 digits of output.
pub const DEFAULT_DIGITS: u32 = 8;

/// Produce a Time-based One-time Password with default settings.
///
///
pub fn totp<H>(secret: &[u8], time: u64) -> String
where
    H: Update + BlockInput + Reset + FixedOutputDirty + Clone + Default,
{
    totp_custom::<H>(DEFAULT_STEP, DEFAULT_DIGITS, secret, time)
}

/// Produce a Time-based One-time Password with full control over algorithm parameters.
pub fn totp_custom<H>(step: u64, digits: u32, secret: &[u8], time: u64) -> String
where
    H: Update + BlockInput + Reset + FixedOutputDirty + Clone + Default,
{
    // Hash the secret and the time together.
    let mut mac: Hmac<H> = Hmac::new_varkey(secret).unwrap();
    mac.update(&to_bytes(time / step));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_bytes_test() {
        assert_eq!(vec![0, 0, 0, 0, 0, 0, 0, 1], to_bytes(59 / DEFAULT_STEP));
        assert_eq!(
            vec![0, 0, 0, 0, 0x02, 0x35, 0x23, 0xec],
            to_bytes(1111111109 / DEFAULT_STEP)
        );
        assert_eq!(
            vec![0, 0, 0, 0, 0x27, 0xbc, 0x86, 0xaa],
            to_bytes(20000000000 / DEFAULT_STEP)
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
            assert_eq!(expected, totp::<Sha1>(secret, time));
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
            assert_eq!(expected, totp::<Sha256>(secret, time));
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
            assert_eq!(expected, totp::<Sha512>(secret, time));
        });
    }
}
