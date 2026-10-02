//! Bounded offline initial-bond registration, not execution or membership.
//!
//! The supplied generation-one row is only a signed prediction. The normal
//! ordered owner must execute the original separately signed custody leg and
//! compare its actual result. This module reuses core codecs, framing and
//! verification; it has no storage, transport or activation capability.

use std::{error::Error, fmt, path::Path};

use crypto::{CryptoError, SignatureSigner};
use execution::publication::PublicationContext;
use hashing::HashSuiteResolver;
use node_core::bond_lifecycle::registration::BondRegistrationPreparationRequest;
use node_core::genesis::GenesisManifest;
use node_core::ordered_economics::OrderedEconomicsPolicy;
use protocol_types::{AtomicityDomainId, Digest32, ValidatorId};
use validator_set::ValidatorSet;

use crate::key::LocalSigner;
use crate::local_genesis::{PinnedGenesis, load_pinned_genesis, validator_set_from_record};
use crate::ordered_economics_client::OrderedGenesisTrustError;

pub use execution::local_execution::MAX_LOCAL_EXECUTION_INTENT_BYTES;
pub use node_core::bond_lifecycle::registration::{
    BondRegistrationError, BondRegistrationIntent, BondResourceId, MAX_BOND_REGISTRATION_BYTES,
    MAX_BOND_REGISTRATION_ROW_BYTES, SignedBondRegistrationIntent,
    decode_signed_bond_registration_intent, encode_signed_bond_registration_intent,
    verify_signed_bond_registration,
};
pub use node_core::fast_path::records::{
    FastPathBondRecord, decode_fastpath_bond_record, encode_fastpath_bond_record,
};

/// Offline preparation failures. None means an application was executed.
#[derive(Debug)]
pub enum LocalBondRegistrationError {
    Genesis(OrderedGenesisTrustError),
    InvalidResourceId,
    Registration(BondRegistrationError),
    SignerMismatch,
    Crypto(CryptoError),
    SignatureLength,
}

impl fmt::Display for LocalBondRegistrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Genesis(error) => write!(formatter, "registration genesis pin rejected: {error}"),
            Self::InvalidResourceId => formatter.write_str("invalid predicted bond resource id"),
            Self::Registration(error) => write!(formatter, "registration claim rejected: {error}"),
            Self::SignerMismatch => {
                formatter.write_str("registration signer differs from the prepared actual key")
            }
            Self::Crypto(error) => write!(formatter, "registration signature failed: {error}"),
            Self::SignatureLength => formatter.write_str("registration signature is not 64 bytes"),
        }
    }
}

impl Error for LocalBondRegistrationError {}

/// Locally pinned first-epoch inputs read from one authenticated manifest.
/// The domain is a separate local ordered-engine pin, not a manifest field.
pub struct BondRegistrationContext {
    pinned: PinnedGenesis,
    resolver: HashSuiteResolver,
    policy: OrderedEconomicsPolicy,
}

impl BondRegistrationContext {
    /// Reads once and checks canonical bytes, commitment, context and genesis
    /// signature before core preparation. No endpoint selects any of these pins.
    #[allow(clippy::result_large_err)]
    pub fn load(
        manifest_path: &Path,
        resolver: &HashSuiteResolver,
        expected_digest: [u8; 32],
        expected_context: &PublicationContext,
        domain: AtomicityDomainId,
    ) -> Result<Self, LocalBondRegistrationError> {
        let pinned: PinnedGenesis =
            load_pinned_genesis(manifest_path, resolver, expected_digest, expected_context)
                .map_err(OrderedGenesisTrustError::from)
                .map_err(LocalBondRegistrationError::Genesis)?;
        let validator_set: ValidatorSet = validator_set_from_record(
            &pinned.manifest.validator_set,
            expected_context,
            "bond registration supports only Ed25519 genesis validators",
        )
        .map_err(OrderedGenesisTrustError::InvalidValidatorSet)
        .map_err(LocalBondRegistrationError::Genesis)?;
        let policy: OrderedEconomicsPolicy = OrderedEconomicsPolicy::new(
            expected_context.clone(),
            domain,
            pinned.digest,
            Some(&pinned.manifest),
            validator_set,
            resolver.clone(),
        )
        .map_err(OrderedGenesisTrustError::Policy)
        .map_err(LocalBondRegistrationError::Genesis)?;
        Ok(Self {
            pinned,
            resolver: resolver.clone(),
            policy,
        })
    }

    /// Validates a supplied row prediction and authenticated custody leg. The
    /// new identity is derived from this signer's actual owned key, never from
    /// a caller-supplied validator-id/public-key pair. Does not sign or execute.
    #[allow(clippy::result_large_err)]
    pub fn prepare(
        &self,
        signer: &LocalSigner,
        request_id: [u8; 32],
        leg: Vec<u8>,
        predicted_initial_row: FastPathBondRecord,
    ) -> Result<PreparedLocalBondRegistration, LocalBondRegistrationError> {
        let resource: BondResourceId = BondResourceId::new(
            predicted_initial_row.resource_domain,
            predicted_initial_row.resource,
        )
        .map_err(|_| LocalBondRegistrationError::InvalidResourceId)?;
        let request: BondRegistrationPreparationRequest = BondRegistrationPreparationRequest {
            context: self.policy.context().clone(),
            request_id,
            authorization_key: *signer.address().as_bytes(),
            resource_context: predicted_initial_row.context.clone(),
            resource,
            leg,
            predicted_initial_row,
        };
        let prepared: node_core::bond_lifecycle::registration::PreparedBondRegistration =
            node_core::bond_lifecycle::registration::prepare_bond_registration(
                &self.resolver,
                &self.pinned.manifest,
                self.pinned.digest,
                request,
            )
            .map_err(LocalBondRegistrationError::Registration)?;
        Ok(PreparedLocalBondRegistration {
            manifest: self.pinned.manifest.clone(),
            resolver: self.resolver.clone(),
            genesis_digest: self.pinned.digest,
            prepared,
        })
    }
}

/// Immutable, structurally validated registration claim. No public mutable
/// intent or independent signing-key assertion can replace its prepared fields.
pub struct PreparedLocalBondRegistration {
    manifest: GenesisManifest,
    resolver: HashSuiteResolver,
    genesis_digest: Digest32,
    prepared: node_core::bond_lifecycle::registration::PreparedBondRegistration,
}

impl PreparedLocalBondRegistration {
    #[must_use]
    pub fn intent(&self) -> &BondRegistrationIntent {
        &self.prepared.intent
    }

    #[must_use]
    pub fn validator_id(&self) -> ValidatorId {
        self.prepared.intent.validator_id
    }

    /// Signs with the same actual key, then independently verifies the exact
    /// encoded outer envelope and original inner leg using the core owner.
    /// Callers can reserve/validate their output destination before this step.
    #[allow(clippy::result_large_err)]
    pub fn sign(&self, signer: &LocalSigner) -> Result<Vec<u8>, LocalBondRegistrationError> {
        if signer.address().as_bytes() != &self.prepared.intent.authorization_key {
            return Err(LocalBondRegistrationError::SignerMismatch);
        }
        let signature_bytes: Vec<u8> = signer
            .sign_framed(&self.prepared.signing_frame)
            .map_err(LocalBondRegistrationError::Crypto)?;
        let signature: [u8; 64] = signature_bytes
            .try_into()
            .map_err(|_| LocalBondRegistrationError::SignatureLength)?;
        let signed: SignedBondRegistrationIntent = SignedBondRegistrationIntent {
            intent: self.prepared.intent.clone(),
            signature,
        };
        let bytes: Vec<u8> = encode_signed_bond_registration_intent(&signed)
            .map_err(LocalBondRegistrationError::Registration)?;
        verify_signed_bond_registration(
            &self.resolver,
            &self.manifest,
            self.genesis_digest,
            &bytes,
        )
        .map_err(LocalBondRegistrationError::Registration)?;
        Ok(bytes)
    }
}
