//! Explicit, fail-closed trusted configuration for one Durable Object
//! validator instance.
//!
//! Every field here is trusted deployment/bootstrap data, never a value an
//! untrusted HTTP caller or Worker request may select: chain, protocol
//! version, epoch, atomicity domain, validator identity/signing secret,
//! writer fence, and the pinned genesis authority key and manifest digest
//! this instance is authorized to install. There is no notion of a
//! caller-selected namespace anywhere in this module.

use core::fmt;

use canonical_encoding::{CanonicalDecodingError, decode_digest32};
use execution::paid_execution::{MAX_PAID_FEE_POLICY_BYTES, PaidFeePolicy, decode_paid_fee_policy};
use protocol_types::{
    ChainId, Digest32, Epoch, HashSuite, ProtocolVersion, TypeError, ValidatorId,
};
use runtime::{AtomicityDomainId, WriterFenceGeneration};

/// Explicit format version for the encoded [`TrustedAdapterConfig`] bytes.
pub const ADAPTER_CONFIG_FORMAT_VERSION: u16 = 1;

/// Reuses the shared bound on an encoded chain identifier.
pub const MAX_ADAPTER_CHAIN_ID_BYTES: usize = node_core::MAX_CHAIN_ID_BYTES;

/// Maximum encoded length accepted for the pinned genesis manifest digest
/// field. `encode_digest32` currently produces a small fixed-size frame;
/// this bound is deliberately generous headroom, not a measured maximum.
pub const MAX_ADAPTER_DIGEST_BYTES: usize = 128;

/// Maximum accepted total length of encoded [`TrustedAdapterConfig`] bytes.
pub const MAX_ADAPTER_CONFIG_BYTES: usize = 2
    + 2
    + 2
    + MAX_ADAPTER_CHAIN_ID_BYTES
    + 4
    + 8
    + 32
    + 32
    + 32
    + 8
    + 32
    + 2
    + MAX_ADAPTER_DIGEST_BYTES
    + 8
    + 8
    + 2
    + MAX_PAID_FEE_POLICY_BYTES;

/// Trusted, explicitly configured identity and admission pin for one
/// embedded validator instance.
///
/// Construction only ever happens through [`decode_trusted_adapter_config`]:
/// there is no `Default` and no builder that could be handed an
/// attacker-controlled or empty domain/chain.
pub struct TrustedAdapterConfig {
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
    epoch: Epoch,
    domain: AtomicityDomainId,
    validator_id: ValidatorId,
    validator_signing_secret: [u8; 32],
    writer_fence: WriterFenceGeneration,
    genesis_authority_public_key: [u8; 32],
    genesis_manifest_digest: Digest32,
    created_checkpoint: u64,
    operation_timeout_millis: u64,
    paid_fee_policy: PaidFeePolicy,
}

impl fmt::Debug for TrustedAdapterConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustedAdapterConfig")
            .field("chain_id", &self.chain_id)
            .field("protocol_version", &self.protocol_version)
            .field("epoch", &self.epoch)
            .field("domain", &self.domain)
            .field("validator_id", &self.validator_id)
            .field("validator_signing_secret", &"<redacted>")
            .field("writer_fence", &self.writer_fence.get())
            .field(
                "genesis_authority_public_key",
                &self.genesis_authority_public_key,
            )
            .field("genesis_manifest_digest", &self.genesis_manifest_digest)
            .field("created_checkpoint", &self.created_checkpoint)
            .field("operation_timeout_millis", &self.operation_timeout_millis)
            .field("paid_fee_policy", &self.paid_fee_policy)
            .finish()
    }
}
impl TrustedAdapterConfig {
    /// Returns the pinned chain identifier.
    #[must_use]
    pub fn chain_id(&self) -> &ChainId {
        &self.chain_id
    }

    /// Returns the pinned protocol version.
    #[must_use]
    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    /// Returns the configured epoch.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the pinned atomicity-domain identity.
    #[must_use]
    pub const fn domain(&self) -> AtomicityDomainId {
        self.domain
    }

    /// Returns this validator instance own identity.
    #[must_use]
    pub const fn validator_id(&self) -> ValidatorId {
        self.validator_id
    }

    /// Returns the raw Ed25519 signing seed for this validator instance.
    #[must_use]
    pub const fn validator_signing_secret(&self) -> &[u8; 32] {
        &self.validator_signing_secret
    }

    /// Returns the durable writer-fence generation this instance asserts.
    #[must_use]
    pub const fn writer_fence(&self) -> WriterFenceGeneration {
        self.writer_fence
    }

    /// Returns the pinned genesis authority Ed25519 verification key.
    #[must_use]
    pub const fn genesis_authority_public_key(&self) -> &[u8; 32] {
        &self.genesis_authority_public_key
    }

    /// Returns the pinned expected digest of the genesis manifest this
    /// instance is authorized to install.
    #[must_use]
    pub const fn genesis_manifest_digest(&self) -> &Digest32 {
        &self.genesis_manifest_digest
    }

    /// Returns the trusted, durably-advancing chain-progress checkpoint
    /// this instance stamps on every fast-path prepare/apply, with the
    /// exact same trust origin as
    /// `PreinstalledWasmComposition::new`'s parameter in native-http: a
    /// caller-supplied bootstrap value, never wall-clock time or an
    /// HTTP/DO request.
    #[must_use]
    pub const fn created_checkpoint(&self) -> u64 {
        self.created_checkpoint
    }

    /// Returns the fixed millisecond budget every durable operation
    /// context is allotted from the moment the host reports `now`.
    #[must_use]
    pub const fn operation_timeout_millis(&self) -> u64 {
        self.operation_timeout_millis
    }

    /// Returns the trusted, already-committed paid fee policy this
    /// instance charges fast-path admission against.
    #[must_use]
    pub const fn paid_fee_policy(&self) -> &PaidFeePolicy {
        &self.paid_fee_policy
    }
}

/// Errors that reject an encoded [`TrustedAdapterConfig`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdapterConfigError {
    /// The buffer ended before a required fixed-size field.
    Truncated,
    /// The buffer carried bytes past the last declared field.
    TrailingBytes,
    /// The overall buffer exceeded [`MAX_ADAPTER_CONFIG_BYTES`].
    TooLarge,
    /// The format version was not [`ADAPTER_CONFIG_FORMAT_VERSION`].
    UnsupportedFormatVersion(u16),
    /// The hash-suite identifier was not the current genesis suite.
    ///
    /// This adapter admits only the current [`HashSuite::genesis`] profile
    /// and fails closed on every other identifier, implemented or not,
    /// rather than silently downgrading or guessing an activation epoch.
    UnsupportedHashSuite(u16),
    /// The declared chain-identifier length exceeded the bound or the
    /// bytes were not valid UTF-8, or [`ChainId::new`] rejected them.
    InvalidChainId,
    /// [`AtomicityDomainId::new`] rejected the domain bytes (all zero).
    InvalidDomain,
    /// [`WriterFenceGeneration::new`] rejected the writer-fence value
    /// (zero).
    InvalidWriterFence,
    /// The embedded genesis manifest digest frame failed to decode.
    InvalidGenesisManifestDigest(CanonicalDecodingError),
    /// The writer fence, created checkpoint, or operation timeout was
    /// zero, or the embedded paid fee-policy frame failed to decode.
    InvalidOperationTimeout,
    /// [`WriterFenceGeneration::new`]-style non-zero rule applied to
    /// `created_checkpoint`: zero is rejected the same way a zero writer
    /// fence is, since both are meant to durably advance from genesis.
    InvalidCreatedCheckpoint,
    /// The embedded paid fee-policy frame failed to decode.
    InvalidPaidFeePolicy,
}

impl fmt::Display for AdapterConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("adapter config buffer is truncated"),
            Self::TrailingBytes => f.write_str("adapter config buffer has trailing bytes"),
            Self::TooLarge => f.write_str("adapter config buffer exceeds the maximum length"),
            Self::UnsupportedFormatVersion(version) => {
                write!(
                    f,
                    "adapter config format version {version} is not supported"
                )
            }
            Self::UnsupportedHashSuite(id) => {
                write!(f, "hash suite id {id} is not the supported genesis suite")
            }
            Self::InvalidChainId => f.write_str("adapter config chain id is invalid"),
            Self::InvalidDomain => f.write_str("adapter config atomicity domain is invalid"),
            Self::InvalidWriterFence => f.write_str("adapter config writer fence is invalid"),
            Self::InvalidGenesisManifestDigest(error) => {
                write!(
                    f,
                    "adapter config genesis manifest digest is invalid: {error}"
                )
            }
            Self::InvalidOperationTimeout => {
                f.write_str("adapter config operation timeout must be non-zero")
            }
            Self::InvalidCreatedCheckpoint => {
                f.write_str("adapter config created checkpoint must be non-zero")
            }
            Self::InvalidPaidFeePolicy => {
                f.write_str("adapter config paid fee policy frame is invalid")
            }
        }
    }
}

impl std::error::Error for AdapterConfigError {}
struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], AdapterConfigError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(AdapterConfigError::Truncated)?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(AdapterConfigError::Truncated)?;
        self.offset = end;
        Ok(slice)
    }

    fn take_u16(&mut self) -> Result<u16, AdapterConfigError> {
        let slice = self.take(2)?;
        Ok(u16::from_be_bytes([slice[0], slice[1]]))
    }

    fn take_u32(&mut self) -> Result<u32, AdapterConfigError> {
        let slice = self.take(4)?;
        Ok(u32::from_be_bytes(slice.try_into().unwrap_or_default()))
    }

    fn take_u64(&mut self) -> Result<u64, AdapterConfigError> {
        let slice = self.take(8)?;
        Ok(u64::from_be_bytes(slice.try_into().unwrap_or_default()))
    }

    fn take_array32(&mut self) -> Result<[u8; 32], AdapterConfigError> {
        let slice = self.take(32)?;
        slice.try_into().map_err(|_| AdapterConfigError::Truncated)
    }

    fn finish(self) -> Result<(), AdapterConfigError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(AdapterConfigError::TrailingBytes)
        }
    }
}

/// Decodes and fully validates one trusted adapter configuration.
///
/// Layout (all integers big-endian, exact length, no trailing bytes):
/// `format_version:u16, hash_suite_id:u16, chain_id_len:u16, chain_id,
/// protocol_version:u32, epoch:u64, domain:[u8;32], validator_id:[u8;32],
/// validator_signing_secret:[u8;32], writer_fence:u64,
/// genesis_authority_public_key:[u8;32], digest_len:u16, digest_frame,
/// created_checkpoint:u64, operation_timeout_millis:u64,
/// fee_policy_len:u16, fee_policy_frame`.
/// Unknown format version or hash suite fails closed rather than guessing
/// a compatible interpretation.
pub fn decode_trusted_adapter_config(
    bytes: &[u8],
) -> Result<TrustedAdapterConfig, AdapterConfigError> {
    if bytes.len() > MAX_ADAPTER_CONFIG_BYTES {
        return Err(AdapterConfigError::TooLarge);
    }
    let mut cursor = Cursor::new(bytes);
    let format_version = cursor.take_u16()?;
    if format_version != ADAPTER_CONFIG_FORMAT_VERSION {
        return Err(AdapterConfigError::UnsupportedFormatVersion(format_version));
    }
    let hash_suite_id = cursor.take_u16()?;
    if hash_suite_id != HashSuite::genesis().id.get() {
        return Err(AdapterConfigError::UnsupportedHashSuite(hash_suite_id));
    }
    let chain_id_len = usize::from(cursor.take_u16()?);
    if chain_id_len > MAX_ADAPTER_CHAIN_ID_BYTES {
        return Err(AdapterConfigError::InvalidChainId);
    }
    let chain_id_bytes = cursor.take(chain_id_len)?;
    let chain_id_text =
        core::str::from_utf8(chain_id_bytes).map_err(|_| AdapterConfigError::InvalidChainId)?;
    let chain_id =
        ChainId::new(chain_id_text).map_err(|_: TypeError| AdapterConfigError::InvalidChainId)?;
    let protocol_version = ProtocolVersion::new(cursor.take_u32()?);
    let epoch = Epoch::new(cursor.take_u64()?);
    let domain_bytes = cursor.take_array32()?;
    let domain = AtomicityDomainId::new(domain_bytes)
        .map_err(|_: TypeError| AdapterConfigError::InvalidDomain)?;
    let validator_id = ValidatorId::new(cursor.take_array32()?);
    let validator_signing_secret = cursor.take_array32()?;
    let writer_fence_value = cursor.take_u64()?;
    let writer_fence = WriterFenceGeneration::new(writer_fence_value)
        .ok_or(AdapterConfigError::InvalidWriterFence)?;
    let genesis_authority_public_key = cursor.take_array32()?;
    let digest_len = usize::from(cursor.take_u16()?);
    if digest_len > MAX_ADAPTER_DIGEST_BYTES {
        return Err(AdapterConfigError::InvalidGenesisManifestDigest(
            CanonicalDecodingError::FrameTooLarge(digest_len),
        ));
    }
    let digest_bytes = cursor.take(digest_len)?;
    let genesis_manifest_digest =
        decode_digest32(digest_bytes).map_err(AdapterConfigError::InvalidGenesisManifestDigest)?;
    let created_checkpoint = cursor.take_u64()?;
    if created_checkpoint == 0 {
        return Err(AdapterConfigError::InvalidCreatedCheckpoint);
    }
    let operation_timeout_millis = cursor.take_u64()?;
    if operation_timeout_millis == 0 {
        return Err(AdapterConfigError::InvalidOperationTimeout);
    }
    let fee_policy_len = usize::from(cursor.take_u16()?);
    if fee_policy_len > MAX_PAID_FEE_POLICY_BYTES {
        return Err(AdapterConfigError::InvalidPaidFeePolicy);
    }
    let fee_policy_bytes = cursor.take(fee_policy_len)?;
    cursor.finish()?;
    let paid_fee_policy = decode_paid_fee_policy(fee_policy_bytes)
        .map_err(|_| AdapterConfigError::InvalidPaidFeePolicy)?;
    Ok(TrustedAdapterConfig {
        chain_id,
        protocol_version,
        epoch,
        domain,
        validator_id,
        validator_signing_secret,
        writer_fence,
        genesis_authority_public_key,
        genesis_manifest_digest,
        created_checkpoint,
        operation_timeout_millis,
        paid_fee_policy,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use canonical_encoding::encode_digest32;
    use protocol_types::{Digest32, HashAlgorithmId};

    fn valid_bytes() -> Vec<u8> {
        let digest = Digest32::new(HashAlgorithmId::Sha2_256, [7; 32]);
        let digest_frame = encode_digest32(&digest).unwrap();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ADAPTER_CONFIG_FORMAT_VERSION.to_be_bytes());
        bytes.extend_from_slice(&HashSuite::genesis().id.get().to_be_bytes());
        let chain_id = b"sunrise-edge-do-devnet";
        bytes.extend_from_slice(&(chain_id.len() as u16).to_be_bytes());
        bytes.extend_from_slice(chain_id);
        bytes.extend_from_slice(&3_u32.to_be_bytes()); // protocol_version
        bytes.extend_from_slice(&0_u64.to_be_bytes()); // epoch
        bytes.extend_from_slice(&[1; 32]); // domain
        bytes.extend_from_slice(&[2; 32]); // validator_id
        bytes.extend_from_slice(&[3; 32]); // signing secret
        bytes.extend_from_slice(&1_u64.to_be_bytes()); // writer fence
        bytes.extend_from_slice(&[4; 32]); // genesis authority public key
        bytes.extend_from_slice(&(digest_frame.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&digest_frame);
        bytes.extend_from_slice(&7_u64.to_be_bytes()); // created_checkpoint
        bytes.extend_from_slice(&30_000_u64.to_be_bytes()); // operation_timeout_millis
        bytes.extend_from_slice(&0_u16.to_be_bytes()); // fee_policy_len (deliberately empty)
        bytes
    }

    // `valid_bytes` deliberately carries an empty (invalid) fee-policy
    // frame: building a real `PaidFeePolicy` needs a full publication/
    // instance/gas-schedule fixture out of proportion for this module
    // own unit tests, and every other field this module owns is already
    // exercised by the fields decoded strictly before it. This test
    // proves every prior field (chain id, protocol version, epoch,
    // domain, validator id/secret, writer fence, genesis authority/
    // digest, created checkpoint, operation timeout) parses and passes
    // its own validation before decoding reaches the fee policy at all.
    #[test]
    fn decodes_every_field_up_to_the_fee_policy() {
        assert_eq!(
            decode_trusted_adapter_config(&valid_bytes()).unwrap_err(),
            AdapterConfigError::InvalidPaidFeePolicy
        );
    }

    #[test]
    fn rejects_unsupported_format_version() {
        let mut bytes = valid_bytes();
        bytes[1] = 2;
        assert_eq!(
            decode_trusted_adapter_config(&bytes).unwrap_err(),
            AdapterConfigError::UnsupportedFormatVersion(2)
        );
    }

    #[test]
    fn rejects_unknown_hash_suite() {
        let mut bytes = valid_bytes();
        bytes[2..4].copy_from_slice(&99_u16.to_be_bytes());
        assert_eq!(
            decode_trusted_adapter_config(&bytes).unwrap_err(),
            AdapterConfigError::UnsupportedHashSuite(99)
        );
    }

    #[test]
    fn rejects_zero_domain() {
        let mut bytes = valid_bytes();
        let domain_start = 2 + 2 + 2 + "sunrise-edge-do-devnet".len() + 4 + 8;
        bytes[domain_start..domain_start + 32].fill(0);
        assert_eq!(
            decode_trusted_adapter_config(&bytes).unwrap_err(),
            AdapterConfigError::InvalidDomain
        );
    }

    #[test]
    fn rejects_zero_writer_fence() {
        let mut bytes = valid_bytes();
        let fence_start = 2 + 2 + 2 + "sunrise-edge-do-devnet".len() + 4 + 8 + 32 + 32 + 32;
        bytes[fence_start..fence_start + 8].fill(0);
        assert_eq!(
            decode_trusted_adapter_config(&bytes).unwrap_err(),
            AdapterConfigError::InvalidWriterFence
        );
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut bytes = valid_bytes();
        bytes.push(0);
        assert_eq!(
            decode_trusted_adapter_config(&bytes).unwrap_err(),
            AdapterConfigError::TrailingBytes
        );
    }

    #[test]
    fn rejects_truncated_buffer() {
        let bytes = valid_bytes();
        let truncated = &bytes[..bytes.len() - 1];
        assert!(decode_trusted_adapter_config(truncated).is_err());
    }
}
