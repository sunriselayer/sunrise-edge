//! Bounded offline initial-bond registration, not execution or membership.
//!
//! The supplied generation-one row is only a signed prediction. The normal
//! ordered owner must execute the original separately signed custody leg and
//! compare its actual result. This module reuses core codecs, framing and
//! verification; it has no storage, transport or activation capability.

use std::{error::Error, fmt, path::Path};

use crypto::CryptoError;
use execution::publication::PublicationContext;
use hashing::HashSuiteResolver;
use node_core::bond_lifecycle::registration::BondRegistrationPreparationRequest;
use node_core::genesis::VerifiedGenesisRoot;
use node_core::ordered_economics::OrderedEconomicsPolicy;
use protocol_types::{AtomicityDomainId, ValidatorId};

use crate::key::LocalSigner;
use crate::local_genesis::load_verified_genesis_root;
use crate::ordered_economics_client::OrderedGenesisTrustError;
use crate::signing_frame::PreparedSigningFrame;
use crate::{Address, ClientError, ExternalSigner, SuccessorWorkflowAuthority};

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
    CurrentContextMismatch,
    /// External provider identity or opaque provider failure.
    ExternalSigning(Box<ClientError>),
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
            Self::CurrentContextMismatch => formatter.write_str(
                "registration signing context differs from the verified current successor",
            ),
            Self::ExternalSigning(error) => {
                write!(formatter, "registration signing refused: {error}")
            }
        }
    }
}

impl Error for LocalBondRegistrationError {}

/// Locally pinned first-epoch inputs read from one authenticated manifest.
/// The domain is a separate local ordered-engine pin, not a manifest field.
pub struct BondRegistrationContext {
    root: VerifiedGenesisRoot,
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
        let root: VerifiedGenesisRoot =
            load_verified_genesis_root(manifest_path, resolver, expected_digest, expected_context)
                .map_err(OrderedGenesisTrustError::from)
                .map_err(LocalBondRegistrationError::Genesis)?;
        let policy: OrderedEconomicsPolicy =
            OrderedEconomicsPolicy::from_genesis_root(&root, domain)
                .map_err(OrderedGenesisTrustError::Policy)
                .map_err(LocalBondRegistrationError::Genesis)?;
        Ok(Self { root, policy })
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
        self.prepare_for_public_key(
            *signer.address().as_bytes(),
            request_id,
            leg,
            predicted_initial_row,
        )
    }

    /// Prepares against an explicitly configured public identity. The existing
    /// core derives the validator ID and rejects original ID/key reuse.
    #[allow(clippy::result_large_err)]
    pub fn prepare_for_public_key(
        &self,
        authorization_key: [u8; 32],
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
            authorization_key,
            resource_context: predicted_initial_row.context.clone(),
            resource,
            leg,
            predicted_initial_row: predicted_initial_row.clone(),
        };
        let prepared: node_core::bond_lifecycle::registration::PreparedBondRegistration =
            node_core::bond_lifecycle::registration::prepare_bond_registration(&self.root, request)
                .map_err(LocalBondRegistrationError::Registration)?;
        Ok(PreparedLocalBondRegistration {
            root: self.root.clone(),
            signing: PreparedSigningFrame::new(
                Address::new(authorization_key),
                prepared.intent.authorization_scheme,
                prepared.signing_frame,
            )
            .map_err(external_error)?,
            intent: prepared.intent,
            predicted_initial_row,
        })
    }
}

/// Immutable, structurally validated registration claim. No public mutable
/// intent or independent signing-key assertion can replace its prepared fields.
#[derive(Clone)]
pub struct PreparedLocalBondRegistration {
    root: VerifiedGenesisRoot,
    signing: PreparedSigningFrame,
    intent: BondRegistrationIntent,
    predicted_initial_row: FastPathBondRecord,
}

impl PreparedLocalBondRegistration {
    /// Original immutable trust root for independently recomputing commitments.
    #[must_use]
    pub fn genesis_root(&self) -> &VerifiedGenesisRoot {
        &self.root
    }

    #[must_use]
    pub fn intent(&self) -> &BondRegistrationIntent {
        &self.intent
    }

    #[must_use]
    pub fn validator_id(&self) -> ValidatorId {
        self.intent.validator_id
    }

    /// Signs with the same actual key, then independently verifies the exact
    /// encoded outer envelope and original inner leg using the core owner.
    /// Callers can reserve/validate their output destination before this step.
    #[allow(clippy::result_large_err)]
    pub fn sign(&self, signer: &LocalSigner) -> Result<Vec<u8>, LocalBondRegistrationError> {
        self.clone().sign_and_finalize_with(signer)
    }

    /// Exact predicted row whose commitment is bound to the outer envelope.
    #[must_use]
    pub fn predicted_initial_row(&self) -> &FastPathBondRecord {
        &self.predicted_initial_row
    }

    /// Immutable outer frame; the already-signed inner leg remains in the intent.
    #[must_use]
    pub fn signable_frame(&self) -> &[u8] {
        self.signing.frame()
    }

    /// Consumes the signature and re-verifies the original outer and custody
    /// leg under the retained original genesis scope before returning output.
    #[allow(clippy::result_large_err)]
    pub fn finalize(self, signature: Vec<u8>) -> Result<Vec<u8>, LocalBondRegistrationError> {
        let bytes: Vec<u8> = encode_registration(self.intent, signature)?;
        verify_signed_bond_registration(&self.root, &bytes)
            .map_err(LocalBondRegistrationError::Registration)?;
        verify_registration_frame(&self.signing, &bytes)?;
        Ok(bytes)
    }

    /// Checks the configured external identity and finalizes its returned signature.
    #[allow(clippy::result_large_err)]
    pub fn sign_and_finalize_external<S: ExternalSigner>(
        self,
        signer: &S,
    ) -> Result<Vec<u8>, LocalBondRegistrationError> {
        let signature: Vec<u8> = self.signing.sign_external(signer).map_err(external_error)?;
        self.finalize(signature)
    }

    /// Existing development key convenience, preserving signer-mismatch errors.
    #[allow(clippy::result_large_err)]
    pub fn sign_and_finalize_with(
        self,
        signer: &LocalSigner,
    ) -> Result<Vec<u8>, LocalBondRegistrationError> {
        let signature: Vec<u8> = sign_registration(&self.signing, signer)?;
        self.finalize(signature)
    }
}

/// Current-epoch registration preparation against an opaque verified chain.
/// The custody resource remains in the immutable original profile; the
/// registration and generic leg use the actual current context.
#[allow(clippy::result_large_err)]
pub fn prepare_successor_bond_registration<'a>(
    workflow: &'a SuccessorWorkflowAuthority,
    declared: &PublicationContext,
    signer: &LocalSigner,
    request_id: [u8; 32],
    leg: Vec<u8>,
    predicted_initial_row: FastPathBondRecord,
) -> Result<PreparedSuccessorBondRegistration<'a>, LocalBondRegistrationError> {
    prepare_successor_bond_registration_for_public_key(
        workflow,
        declared,
        *signer.address().as_bytes(),
        request_id,
        leg,
        predicted_initial_row,
    )
}

/// Public-key-only successor preparation under the same verified chain scope.
#[allow(clippy::result_large_err)]
pub fn prepare_successor_bond_registration_for_public_key<'a>(
    workflow: &'a SuccessorWorkflowAuthority,
    declared: &PublicationContext,
    authorization_key: [u8; 32],
    request_id: [u8; 32],
    leg: Vec<u8>,
    predicted_initial_row: FastPathBondRecord,
) -> Result<PreparedSuccessorBondRegistration<'a>, LocalBondRegistrationError> {
    workflow
        .require_signing_context(declared)
        .map_err(|_| LocalBondRegistrationError::CurrentContextMismatch)?;
    let resource: BondResourceId = BondResourceId::new(
        predicted_initial_row.resource_domain,
        predicted_initial_row.resource,
    )
    .map_err(|_| LocalBondRegistrationError::InvalidResourceId)?;
    let request: BondRegistrationPreparationRequest = BondRegistrationPreparationRequest {
        context: declared.clone(),
        request_id,
        authorization_key,
        resource_context: predicted_initial_row.context.clone(),
        resource,
        leg,
        predicted_initial_row: predicted_initial_row.clone(),
    };
    let prepared: node_core::bond_lifecycle::registration::PreparedBondRegistration =
        node_core::bond_lifecycle::registration::prepare_bond_registration_successor(
            workflow.genesis_root(),
            workflow.authority(),
            request,
        )
        .map_err(LocalBondRegistrationError::Registration)?;
    Ok(PreparedSuccessorBondRegistration {
        workflow,
        signing: PreparedSigningFrame::new(
            Address::new(authorization_key),
            prepared.intent.authorization_scheme,
            prepared.signing_frame,
        )
        .map_err(external_error)?,
        intent: prepared.intent,
        predicted_initial_row,
    })
}

/// The current context and full chain remain borrowed until the exact signed
/// registration envelope is reverified by the same core RegistrationScope.
#[derive(Clone)]
pub struct PreparedSuccessorBondRegistration<'a> {
    workflow: &'a SuccessorWorkflowAuthority,
    signing: PreparedSigningFrame,
    intent: BondRegistrationIntent,
    predicted_initial_row: FastPathBondRecord,
}

impl PreparedSuccessorBondRegistration<'_> {
    /// Retained verified chain and current registration scope.
    #[must_use]
    pub fn workflow(&self) -> &SuccessorWorkflowAuthority {
        self.workflow
    }

    #[must_use]
    pub fn validator_id(&self) -> ValidatorId {
        self.intent.validator_id
    }

    #[must_use]
    pub fn intent(&self) -> &BondRegistrationIntent {
        &self.intent
    }

    #[allow(clippy::result_large_err)]
    pub fn sign(
        &self,
        signer: &LocalSigner,
        declared: &PublicationContext,
    ) -> Result<Vec<u8>, LocalBondRegistrationError> {
        self.workflow
            .require_signing_context(declared)
            .map_err(|_| LocalBondRegistrationError::CurrentContextMismatch)?;
        if self.intent.context != *declared {
            return Err(LocalBondRegistrationError::CurrentContextMismatch);
        }
        self.clone().sign_and_finalize_with(signer)
    }

    /// Exact immutable predicted row, retained with its signed custody leg.
    #[must_use]
    pub fn predicted_initial_row(&self) -> &FastPathBondRecord {
        &self.predicted_initial_row
    }

    /// Immutable current-context outer frame to sign.
    #[must_use]
    pub fn signable_frame(&self) -> &[u8] {
        self.signing.frame()
    }

    /// Consumes the signature and authenticates under the same retained current
    /// chain scope without accepting replacement context or custody inputs.
    #[allow(clippy::result_large_err)]
    pub fn finalize(self, signature: Vec<u8>) -> Result<Vec<u8>, LocalBondRegistrationError> {
        let bytes: Vec<u8> = encode_registration(self.intent, signature)?;
        node_core::bond_lifecycle::registration::verify_signed_bond_registration_successor(
            self.workflow.genesis_root(),
            self.workflow.authority(),
            &bytes,
        )
        .map_err(LocalBondRegistrationError::Registration)?;
        verify_registration_frame(&self.signing, &bytes)?;
        Ok(bytes)
    }

    /// Checks the provider's expected identity before signing the current envelope.
    #[allow(clippy::result_large_err)]
    pub fn sign_and_finalize_external<S: ExternalSigner>(
        self,
        signer: &S,
    ) -> Result<Vec<u8>, LocalBondRegistrationError> {
        let signature: Vec<u8> = self.signing.sign_external(signer).map_err(external_error)?;
        self.finalize(signature)
    }

    /// Existing development convenience preserving the actual-key mismatch check.
    #[allow(clippy::result_large_err)]
    pub fn sign_and_finalize_with(
        self,
        signer: &LocalSigner,
    ) -> Result<Vec<u8>, LocalBondRegistrationError> {
        let signature: Vec<u8> = sign_registration(&self.signing, signer)?;
        self.finalize(signature)
    }
}

#[allow(clippy::result_large_err)]
fn sign_registration(
    signing: &PreparedSigningFrame,
    signer: &LocalSigner,
) -> Result<Vec<u8>, LocalBondRegistrationError> {
    if signer.address() != signing.expected() {
        return Err(LocalBondRegistrationError::SignerMismatch);
    }
    signing
        .sign_with(signer)
        .map_err(LocalBondRegistrationError::Crypto)
}

#[allow(clippy::result_large_err)]
fn encode_registration(
    intent: BondRegistrationIntent,
    signature_bytes: Vec<u8>,
) -> Result<Vec<u8>, LocalBondRegistrationError> {
    let signature: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| LocalBondRegistrationError::SignatureLength)?;
    let signed: SignedBondRegistrationIntent = SignedBondRegistrationIntent { intent, signature };
    let bytes: Vec<u8> = encode_signed_bond_registration_intent(&signed)
        .map_err(LocalBondRegistrationError::Registration)?;
    Ok(bytes)
}

fn external_error(error: ClientError) -> LocalBondRegistrationError {
    LocalBondRegistrationError::ExternalSigning(Box::new(error))
}

#[allow(clippy::result_large_err)]
fn verify_registration_frame(
    signing: &PreparedSigningFrame,
    bytes: &[u8],
) -> Result<(), LocalBondRegistrationError> {
    let signed: SignedBondRegistrationIntent = decode_signed_bond_registration_intent(bytes)
        .map_err(LocalBondRegistrationError::Registration)?;
    if !signing.verify(&signed.signature).map_err(|_| {
        LocalBondRegistrationError::Registration(BondRegistrationError::Invalid(
            "registration outer signature",
        ))
    })? {
        return Err(LocalBondRegistrationError::Registration(
            BondRegistrationError::Invalid("registration outer signature"),
        ));
    }
    Ok(())
}
