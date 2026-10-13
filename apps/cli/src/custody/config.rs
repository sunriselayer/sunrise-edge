//! Fixed, file-pinned custody configuration.
//!
//! Every protocol-context field, the publisher identity custody will ever
//! sign for, and the one operator UID permitted to request a signature are
//! all read from one local, custody-owned, mode-`0600` file under a
//! mode-`0700` directory before any request is ever accepted. None of these
//! fields are negotiable from a caller, a peer, or a response.

use std::collections::BTreeMap;
use std::path::Path;

use sunrise_edge_client::{
    Address, AtomicityDomainId, ChainId,
    ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_BINDING_ID,
    ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID, Epoch, ExpectedProtocolContext,
    HashSuiteId, ProtocolVersion, SignatureSchemeId,
};

use super::error::CustodyError;
use super::fsperm::read_private_file;
use crate::hex::decode_hex_32;

/// Maximum accepted config file size: generous for this fixed, seven-key
/// file, bounding it before any parsing is attempted.
const MAX_CONFIG_FILE_BYTES: usize = 4096;
/// Required exact file mode.
pub(super) const CONFIG_FILE_MODE: u32 = 0o600;
/// Required exact parent-directory mode.
pub(super) const CONFIG_DIR_MODE: u32 = 0o700;

const REQUIRED_KEYS: &[&str] = &[
    "chain_id",
    "protocol_version",
    "epoch",
    "hash_suite_id",
    "domain",
    "publisher_public_key",
    "operator_uid",
];

/// The complete, locally trusted custody configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustodyConfig {
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
    epoch: Epoch,
    hash_suite_id: HashSuiteId,
    domain: AtomicityDomainId,
    publisher: Address,
    operator_uid: u32,
}

impl CustodyConfig {
    /// Loads and validates ownership/permissions/content for `path`.
    pub fn load(path: &Path) -> Result<Self, CustodyError> {
        let bytes = read_private_file(
            path,
            CONFIG_FILE_MODE,
            CONFIG_DIR_MODE,
            MAX_CONFIG_FILE_BYTES,
        )?;
        let text = std::str::from_utf8(&bytes).map_err(|_| CustodyError::ConfigNotUtf8)?;
        Self::parse(text)
    }

    fn parse(text: &str) -> Result<Self, CustodyError> {
        let mut fields: BTreeMap<&str, &str> = BTreeMap::new();
        for (index, raw_line) in text.lines().enumerate() {
            let line = raw_line.trim_end_matches('\r');
            if line.is_empty() {
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .ok_or(CustodyError::ConfigMalformedLine { line: index + 1 })?;
            if fields.insert(key, value).is_some() {
                return Err(CustodyError::ConfigDuplicateKey {
                    key: key.to_string(),
                });
            }
        }
        for key in REQUIRED_KEYS {
            if !fields.contains_key(key) {
                return Err(CustodyError::ConfigMissingKey { key });
            }
        }
        for key in fields.keys() {
            if !REQUIRED_KEYS.contains(key) {
                return Err(CustodyError::ConfigUnknownKey {
                    key: (*key).to_string(),
                });
            }
        }

        let chain_id = ChainId::new(fields["chain_id"]).map_err(CustodyError::Type)?;
        let protocol_version = ProtocolVersion::new(parse_decimal(
            fields["protocol_version"],
            "protocol_version",
        )?);
        let epoch = Epoch::new(parse_decimal(fields["epoch"], "epoch")?);
        let hash_suite_id =
            HashSuiteId::new(parse_decimal(fields["hash_suite_id"], "hash_suite_id")?);
        let domain_bytes = decode_hex_32("domain", fields["domain"])
            .map_err(|_| CustodyError::ConfigInvalidHex { key: "domain" })?;
        let domain = AtomicityDomainId::new(domain_bytes).map_err(CustodyError::Type)?;
        let publisher_bytes = decode_hex_32("publisher_public_key", fields["publisher_public_key"])
            .map_err(|_| CustodyError::ConfigInvalidHex {
                key: "publisher_public_key",
            })?;
        let publisher = Address::new(publisher_bytes);
        let operator_uid: u32 = parse_decimal(fields["operator_uid"], "operator_uid")?;

        Ok(Self {
            chain_id,
            protocol_version,
            epoch,
            hash_suite_id,
            domain,
            publisher,
            operator_uid,
        })
    }

    /// Builds the one trusted expected protocol context every custody
    /// operation (`approve` and `serve`) recomputes everything under.
    pub fn expected_context(&self) -> Result<ExpectedProtocolContext, CustodyError> {
        ExpectedProtocolContext::new(
            self.chain_id.clone(),
            self.protocol_version,
            self.epoch,
            self.hash_suite_id,
            ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID,
            SignatureSchemeId::Ed25519.as_u16(),
            ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_BINDING_ID,
            self.domain,
        )
        .map_err(CustodyError::ExpectedContext)
    }

    /// The one publisher identity custody ever signs for.
    #[must_use]
    pub const fn publisher(&self) -> Address {
        self.publisher
    }

    /// The one UID `serve` accepts a request from.
    #[must_use]
    pub const fn operator_uid(&self) -> u32 {
        self.operator_uid
    }
}

fn parse_decimal<T: std::str::FromStr>(value: &str, key: &'static str) -> Result<T, CustodyError> {
    value
        .parse::<T>()
        .map_err(|_| CustodyError::ConfigInvalidInteger { key })
}

#[cfg(test)]
mod tests {
    use super::super::fsperm::test_support::TempDir;
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn valid_text() -> String {
        format!(
            "chain_id=sunrise-local-devnet\nprotocol_version=3\nepoch=0\nhash_suite_id=1\ndomain={}\npublisher_public_key={}\noperator_uid=1001\n",
            "11".repeat(32),
            "22".repeat(32)
        )
    }

    fn write_config(dir: &TempDir, text: &str) -> std::path::PathBuf {
        let path = dir.child("config");
        std::fs::write(&path, text).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    #[test]
    fn loads_a_valid_config() {
        let dir = TempDir::new(0o700);
        let path = write_config(&dir, &valid_text());
        let config = CustodyConfig::load(&path).unwrap();
        assert_eq!(config.operator_uid(), 1001);
        assert_eq!(*config.publisher().as_bytes(), [0x22; 32]);
        config.expected_context().unwrap();
    }

    #[test]
    fn rejects_a_missing_key() {
        let dir = TempDir::new(0o700);
        let text = valid_text().replace("operator_uid=1001\n", "");
        let path = write_config(&dir, &text);
        assert!(matches!(
            CustodyConfig::load(&path),
            Err(CustodyError::ConfigMissingKey {
                key: "operator_uid"
            })
        ));
    }

    #[test]
    fn rejects_an_unknown_key() {
        let dir = TempDir::new(0o700);
        let mut text = valid_text();
        text.push_str("unexpected=1\n");
        let path = write_config(&dir, &text);
        assert!(matches!(
            CustodyConfig::load(&path),
            Err(CustodyError::ConfigUnknownKey { .. })
        ));
    }

    #[test]
    fn rejects_a_duplicate_key() {
        let dir = TempDir::new(0o700);
        let mut text = valid_text();
        text.push_str("operator_uid=2002\n");
        let path = write_config(&dir, &text);
        assert!(matches!(
            CustodyConfig::load(&path),
            Err(CustodyError::ConfigDuplicateKey { .. })
        ));
    }

    #[test]
    fn rejects_a_malformed_line() {
        let dir = TempDir::new(0o700);
        let mut text = valid_text();
        text.push_str("not-a-key-value-line\n");
        let path = write_config(&dir, &text);
        assert!(matches!(
            CustodyConfig::load(&path),
            Err(CustodyError::ConfigMalformedLine { .. })
        ));
    }

    #[test]
    fn rejects_group_readable_config_file_mode() {
        let dir = TempDir::new(0o700);
        let path = write_config(&dir, &valid_text());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(matches!(
            CustodyConfig::load(&path),
            Err(CustodyError::UnexpectedMode { .. })
        ));
    }

    #[test]
    fn rejects_an_insecure_parent_directory_mode() {
        let dir = TempDir::new(0o755);
        let path = write_config(&dir, &valid_text());
        assert!(matches!(
            CustodyConfig::load(&path),
            Err(CustodyError::UnexpectedMode { .. })
        ));
    }
}
