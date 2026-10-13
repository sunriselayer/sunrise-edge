//! Custody's own private Ed25519 seed file.
//!
//! Format matches `apps/cli/src/seed.rs`'s development seed file exactly
//! (64 lowercase/uppercase hex digits plus an optional trailing newline), but
//! under custody's own exact-mode ownership policy (`0600` file under a
//! `0700` directory) rather than the development loader's weaker "no
//! group/other bits" check. The seed is never logged, printed, or included
//! in any error.

use std::path::Path;

use sunrise_edge_client::LocalSigner;

use super::error::CustodyError;
use super::fsperm::{read_private_file, write_private_file};
use crate::hex::{decode_hex_32, encode_hex};

/// Required exact key file mode.
pub(super) const KEY_FILE_MODE: u32 = 0o600;
/// Required exact parent-directory mode.
pub(super) const KEY_DIR_MODE: u32 = 0o700;

const SEED_HEX_LEN: usize = 64;
const MAX_READ_LEN: usize = SEED_HEX_LEN + 2;

/// Loads custody's private signing key from `path`.
pub fn load_signer(path: &Path) -> Result<LocalSigner, CustodyError> {
    let buffer = read_private_file(path, KEY_FILE_MODE, KEY_DIR_MODE, MAX_READ_LEN)?;
    let text_bytes: &[u8] = match buffer.len() {
        SEED_HEX_LEN => &buffer,
        len if len == SEED_HEX_LEN + 1 && buffer[SEED_HEX_LEN] == b'\n' => &buffer[..SEED_HEX_LEN],
        _ => {
            return Err(CustodyError::FileTooLarge {
                path: path.to_path_buf(),
                maximum: SEED_HEX_LEN,
            });
        }
    };
    let text = std::str::from_utf8(text_bytes).map_err(|_| CustodyError::KeyFileMalformed)?;
    let seed = decode_hex_32("key file", text).map_err(|_| CustodyError::KeyFileMalformed)?;
    Ok(LocalSigner::from_seed(seed))
}

/// Generates a new key file at `path` from the OS random source, refusing
/// to overwrite an existing path. Returns the derived signer so the caller
/// can print its public address without ever printing the seed.
pub fn generate(path: &Path) -> Result<LocalSigner, CustodyError> {
    let mut seed = [0_u8; 32];
    {
        use std::io::Read;
        let mut source =
            std::fs::File::open("/dev/urandom").map_err(CustodyError::RandomSourceFailed)?;
        source
            .read_exact(&mut seed)
            .map_err(CustodyError::RandomSourceFailed)?;
    }
    let mut hex = encode_hex(&seed);
    hex.push('\n');
    write_private_file(path, KEY_DIR_MODE, KEY_FILE_MODE, hex.as_bytes(), false)?;
    Ok(LocalSigner::from_seed(seed))
}

#[cfg(test)]
mod tests {
    use super::super::fsperm::test_support::TempDir;
    use super::*;

    #[test]
    fn generate_then_load_derive_the_same_address() {
        let dir = TempDir::new(0o700);
        let path = dir.child("key");
        let generated = generate(&path).unwrap();
        let loaded = load_signer(&path).unwrap();
        assert_eq!(generated.address(), loaded.address());
    }

    #[test]
    fn generate_refuses_to_overwrite_an_existing_key() {
        let dir = TempDir::new(0o700);
        let path = dir.child("key");
        generate(&path).unwrap();
        assert!(generate(&path).is_err());
    }

    #[test]
    fn two_generated_keys_are_different() {
        let dir = TempDir::new(0o700);
        let a = generate(&dir.child("a")).unwrap();
        let b = generate(&dir.child("b")).unwrap();
        assert_ne!(a.address(), b.address());
    }
}
