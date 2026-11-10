//! Private, fixed original-genesis bond role and trust configuration.
//! Every process loads its own OS-owned copy; no request may select a role,
//! key, genesis root, hash suite, resource or peer UID.

use std::{collections::BTreeMap, error::Error, fmt, path::Path};

use sunrise_edge_client::{
    Address, AtomicityDomainId, ChainId,
    ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_BINDING_ID,
    ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID, Epoch, ExpectedProtocolContext,
    HashAlgorithmId, HashSuite, HashSuiteId, HashSuiteResolver, HashSuiteSchedule, ProtocolVersion,
    SignatureSchemeId, bond_registration::BondResourceId,
};

use super::{error::CustodyError, fsperm::read_private_file};
use crate::hex::decode_hex_32;

pub(super) const MAX_CONFIG_BYTES: usize = 4096;
const KEYS: [&str; 14] = [
    "chain_id",
    "protocol_version",
    "suite",
    "domain",
    "genesis_digest",
    "source_key",
    "validator_key",
    "resource_domain",
    "resource_id",
    "cli_uid",
    "broker_uid",
    "inner_worker_uid",
    "outer_worker_uid",
    "inner_approver_uid",
];
const OUTER_APPROVER_UID: &str = "outer_approver_uid";

/// A closed, redacted validation error; input bytes and private paths are not
/// included in its display text.
#[derive(Debug)]
pub(super) enum BondConfigError {
    File(CustodyError),
    Invalid(&'static str),
    WrongRoleUid {
        role: BondRole,
        expected: u32,
        actual: u32,
    },
}

impl fmt::Display for BondConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File(error) => write!(f, "bond config file refused: {error}"),
            Self::Invalid(reason) => write!(f, "bond config refused: {reason}"),
            Self::WrongRoleUid {
                role,
                expected,
                actual,
            } => {
                write!(f, "bond {role:?} UID must be {expected}, got {actual}")
            }
        }
    }
}

impl Error for BondConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::File(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CustodyError> for BondConfigError {
    fn from(error: CustodyError) -> Self {
        Self::File(error)
    }
}

/// The only accepted local OS identities. Peer credentials, never wire data,
/// must supply the observed UID passed to `check_role_uid`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum BondRole {
    Cli,
    Broker,
    InnerWorker,
    OuterWorker,
    InnerApprover,
    OuterApprover,
}

/// One complete immutable original-genesis profile.
#[derive(Clone, Debug)]
pub(super) struct BondConfig {
    raw: Vec<u8>,
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
    suite: HashSuiteSchedule,
    domain: AtomicityDomainId,
    genesis_digest: [u8; 32],
    source_key: [u8; 32],
    validator_key: [u8; 32],
    resource: BondResourceId,
    uids: [u32; 6],
}

impl BondConfig {
    /// Reads a mode-0600 regular file beneath a mode-0700 directory owned by
    /// this process, retaining its exact bytes for cross-role pin comparison.
    pub(super) fn load(path: &Path) -> Result<Self, BondConfigError> {
        let raw = read_private_file(path, 0o600, 0o700, MAX_CONFIG_BYTES)?;
        Self::parse(raw)
    }

    fn parse(raw: Vec<u8>) -> Result<Self, BondConfigError> {
        let text = std::str::from_utf8(&raw).map_err(|_| BondConfigError::Invalid("UTF-8"))?;
        let mut fields = BTreeMap::new();
        for line in text.lines() {
            if line.is_empty() || line.contains('\r') {
                return Err(BondConfigError::Invalid("empty or CR line"));
            }
            let (key, value) = line
                .split_once('=')
                .ok_or(BondConfigError::Invalid("line shape"))?;
            if value.is_empty() || fields.insert(key, value).is_some() {
                return Err(BondConfigError::Invalid("empty or duplicate value"));
            }
        }
        if fields.len() != KEYS.len() + 1
            || !KEYS
                .iter()
                .chain([&OUTER_APPROVER_UID])
                .all(|key| fields.contains_key(*key))
        {
            return Err(BondConfigError::Invalid("required keys"));
        }
        let field = |key| -> Result<&str, BondConfigError> {
            fields
                .get(key)
                .copied()
                .ok_or(BondConfigError::Invalid("required key"))
        };
        let chain_id =
            ChainId::new(field("chain_id")?).map_err(|_| BondConfigError::Invalid("chain_id"))?;
        let protocol_version =
            ProtocolVersion::new(decimal(field("protocol_version")?, "protocol_version")?);
        let suite = parse_suite(field("suite")?)?;
        let domain = AtomicityDomainId::new(hex32(field("domain")?, "domain")?)
            .map_err(|_| BondConfigError::Invalid("domain"))?;
        let genesis_digest = hex32(field("genesis_digest")?, "genesis_digest")?;
        let source_key = hex32(field("source_key")?, "source_key")?;
        let validator_key = hex32(field("validator_key")?, "validator_key")?;
        for (key, value) in [("source_key", source_key), ("validator_key", validator_key)] {
            sunrise_edge_client::validate_ed25519_owner_address(
                &value,
                sunrise_edge_client::Ed25519OwnerAddressPolicy::CanonicalPrimeOrder,
            )
            .map_err(|_| BondConfigError::Invalid(key))?;
        }
        if source_key == validator_key {
            return Err(BondConfigError::Invalid("signer keys must differ"));
        }
        let resource = BondResourceId::new(
            decimal(field("resource_domain")?, "resource_domain")?,
            hex32(field("resource_id")?, "resource_id")?,
        )
        .map_err(|_| BondConfigError::Invalid("resource"))?;
        let uids = [
            decimal(field("cli_uid")?, "cli_uid")?,
            decimal(field("broker_uid")?, "broker_uid")?,
            decimal(field("inner_worker_uid")?, "inner_worker_uid")?,
            decimal(field("outer_worker_uid")?, "outer_worker_uid")?,
            decimal(field("inner_approver_uid")?, "inner_approver_uid")?,
            decimal(field(OUTER_APPROVER_UID)?, OUTER_APPROVER_UID)?,
        ];
        for (index, uid) in uids.iter().enumerate() {
            if uids[..index].contains(uid) {
                return Err(BondConfigError::Invalid(
                    "role UIDs must be pairwise distinct",
                ));
            }
        }
        let result = Self {
            raw: raw.clone(),
            chain_id,
            protocol_version,
            suite,
            domain,
            genesis_digest,
            source_key,
            validator_key,
            resource,
            uids,
        };
        result.resolver()?;
        result.expected_context()?;
        Ok(result)
    }

    pub(super) fn expected_context(&self) -> Result<ExpectedProtocolContext, BondConfigError> {
        ExpectedProtocolContext::new(
            self.chain_id.clone(),
            self.protocol_version,
            Epoch::new(0),
            self.suite.suite.id,
            ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID,
            SignatureSchemeId::Ed25519.as_u16(),
            ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_BINDING_ID,
            self.domain,
        )
        .map_err(|_| BondConfigError::Invalid("protocol context"))
    }

    pub(super) fn resolver(&self) -> Result<HashSuiteResolver, BondConfigError> {
        HashSuiteResolver::new(
            self.chain_id.clone(),
            self.protocol_version,
            vec![self.suite.clone()],
        )
        .map_err(|_| BondConfigError::Invalid("hash suite"))
    }

    pub(super) fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }
    pub(super) fn genesis_digest(&self) -> [u8; 32] {
        self.genesis_digest
    }
    pub(super) fn source_key(&self) -> Address {
        Address::new(self.source_key)
    }
    pub(super) fn validator_key(&self) -> [u8; 32] {
        self.validator_key
    }
    pub(super) fn validator_key_address(&self) -> Address {
        Address::new(self.validator_key)
    }
    pub(super) fn resource(&self) -> BondResourceId {
        self.resource
    }
    pub(super) fn domain(&self) -> AtomicityDomainId {
        self.domain
    }
    pub(super) fn cli_uid(&self) -> u32 {
        self.uids[0]
    }
    pub(super) fn broker_uid(&self) -> u32 {
        self.uids[1]
    }
    pub(super) fn inner_worker_uid(&self) -> u32 {
        self.uids[2]
    }
    pub(super) fn outer_worker_uid(&self) -> u32 {
        self.uids[3]
    }
    pub(super) fn inner_approver_uid(&self) -> u32 {
        self.uids[4]
    }
    pub(super) fn outer_approver_uid(&self) -> u32 {
        self.uids[5]
    }

    pub(super) fn check_role_uid(
        &self,
        role: BondRole,
        actual: u32,
    ) -> Result<(), BondConfigError> {
        let expected = match role {
            BondRole::Cli => self.cli_uid(),
            BondRole::Broker => self.broker_uid(),
            BondRole::InnerWorker => self.inner_worker_uid(),
            BondRole::OuterWorker => self.outer_worker_uid(),
            BondRole::InnerApprover => self.inner_approver_uid(),
            BondRole::OuterApprover => self.outer_approver_uid(),
        };
        if actual != expected {
            return Err(BondConfigError::WrongRoleUid {
                role,
                expected,
                actual,
            });
        }
        Ok(())
    }
}

fn decimal<T: std::str::FromStr>(text: &str, key: &'static str) -> Result<T, BondConfigError> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(BondConfigError::Invalid(key));
    }
    text.parse().map_err(|_| BondConfigError::Invalid(key))
}

fn hex32(text: &str, key: &'static str) -> Result<[u8; 32], BondConfigError> {
    decode_hex_32(key, text).map_err(|_| BondConfigError::Invalid(key))
}

fn parse_suite(value: &str) -> Result<HashSuiteSchedule, BondConfigError> {
    if value.len() > 256 {
        return Err(BondConfigError::Invalid("suite"));
    }
    let parts: Vec<_> = value.split(':').collect();
    if parts.len() != 8 || parts[0] != "0" {
        return Err(BondConfigError::Invalid("suite epoch"));
    }
    let id: u16 = decimal(parts[1], "suite id")?;
    if id == 0 {
        return Err(BondConfigError::Invalid("suite id"));
    }
    let algorithm = |part: &str| match part {
        "1" => Ok(HashAlgorithmId::Sha2_256),
        "2" => Ok(HashAlgorithmId::Sha3_256),
        _ => Err(BondConfigError::Invalid("suite algorithm")),
    };
    Ok(HashSuiteSchedule {
        activation_epoch: Epoch::new(0),
        suite: HashSuite {
            id: HashSuiteId::new(id),
            transaction_hash: algorithm(parts[2])?,
            object_digest: algorithm(parts[3])?,
            effects_hash: algorithm(parts[4])?,
            code_hash: algorithm(parts[5])?,
            config_hash: algorithm(parts[6])?,
            certificate_hash: algorithm(parts[7])?,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::custody::fsperm::test_support::{TempDir, write_mode_file};
    use sunrise_edge_client::LocalSigner;

    fn valid() -> String {
        let source = crate::hex::encode_hex(LocalSigner::from_seed([7; 32]).address().as_bytes());
        let validator =
            crate::hex::encode_hex(LocalSigner::from_seed([8; 32]).address().as_bytes());
        format!(
            "chain_id=bond-test\nprotocol_version=1\nsuite=0:1:1:1:1:1:1:1\ndomain={}\ngenesis_digest={}\nsource_key={source}\nvalidator_key={validator}\nresource_domain=1\nresource_id={}\ncli_uid=1001\nbroker_uid=1002\ninner_worker_uid=1003\nouter_worker_uid=1004\ninner_approver_uid=1005\nouter_approver_uid=1006\n",
            "11".repeat(32),
            "22".repeat(32),
            "33".repeat(32)
        )
    }

    #[test]
    fn exact_private_config_and_distinct_roles() {
        let dir = TempDir::new(0o700);
        let path = dir.child("config");
        let text = valid();
        write_mode_file(&path, 0o600, text.as_bytes());
        let config = BondConfig::load(&path).unwrap();
        assert_eq!(config.raw_bytes(), text.as_bytes());
        assert_eq!(config.expected_context().unwrap().epoch(), Epoch::new(0));
        config
            .check_role_uid(BondRole::OuterApprover, 1006)
            .unwrap();
        assert!(
            config
                .check_role_uid(BondRole::InnerApprover, 1006)
                .is_err()
        );
        write_mode_file(
            &path,
            0o600,
            valid()
                .replace("outer_approver_uid=1006", "outer_approver_uid=1005")
                .as_bytes(),
        );
        assert!(BondConfig::load(&path).is_err());
    }

    #[test]
    fn malformed_or_unsupported_pins_refuse() {
        let raw = valid();
        for changed in [
            raw.replace("suite=0:1:1", "suite=1:1:1"),
            raw.replace("suite=0:1:1", "suite=0:1:3"),
            raw.replace("resource_domain=1", "resource_domain=-1"),
            format!("{raw}unknown=x\n"),
            raw.replace("cli_uid=1001", "cli_uid=1002"),
        ] {
            assert!(BondConfig::parse(changed.into_bytes()).is_err());
        }
    }
}
