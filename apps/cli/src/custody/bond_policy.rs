//! Original-genesis bond signing policy shared by the approval broker and the
//! two isolated workers. Every request is reconstructed from the verified
//! genesis manifest; neither worker accepts a caller-supplied signing frame.

use std::path::Path;

use sunrise_edge_client::{
    Address, LocalSigner, PublicationContext, RequestId, VerifiedGenesisRoot,
    bond_registration::{
        BondRegistrationContext, PreparedLocalBondRegistration, decode_fastpath_bond_record,
        encode_fastpath_bond_record, preview_original_bond_registration_content,
    },
    load_verified_genesis_root,
    local_execution::{decode_signed_local_execution, encode_signed_local_execution},
};

use super::{
    bond_config::BondConfig,
    bond_currentness,
    bond_inner::{BondInnerRequest, BondInnerTrust, MAX_REVIEW_BYTES, PreparedBondInner},
    bond_wire::{self, BondPhase, BondRequest},
};
use crate::{error::CliError, hex::encode_hex};

fn invalid(message: &'static str) -> CliError {
    CliError::LocalExecution(Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message,
    )))
}

fn failure(error: impl std::error::Error + Send + Sync + 'static) -> CliError {
    CliError::LocalExecution(Box::new(error))
}

/// All approved bytes, including the exact reconstructed frame and the
/// locally pinned role configuration. The request alone cannot pick trust.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct BondApprovalContent {
    pub(super) phase: BondPhase,
    pub(super) request_id: RequestId,
    pub(super) inner_request_id: RequestId,
    pub(super) expected_key: Address,
    pub(super) config: Vec<u8>,
    pub(super) request: Vec<u8>,
    pub(super) meaning: Vec<u8>,
    pub(super) frame: Vec<u8>,
}

enum PreparedOwner {
    Inner(Box<PreparedBondInner>),
    Outer(Box<PreparedLocalBondRegistration>),
}

pub(super) struct PreparedBondOperation {
    pub(super) content: BondApprovalContent,
    pub(super) review: String,
    owner: PreparedOwner,
    currentness_requery_pending: bool,
}

impl PreparedBondOperation {
    pub(super) fn finalize(self, signature: Vec<u8>) -> Result<Vec<u8>, CliError> {
        if self.currentness_requery_pending {
            return Err(invalid(
                "bond currentness decision-point requery is not implemented",
            ));
        }
        match self.owner {
            PreparedOwner::Inner(inner) => {
                let signed = inner.prepared.finalize(signature).map_err(failure)?;
                encode_signed_local_execution(&signed).map_err(failure)
            }
            PreparedOwner::Outer(outer) => outer.finalize(signature).map_err(failure),
        }
    }

    pub(super) fn sign_with(self, signer: &LocalSigner) -> Result<[u8; 64], CliError> {
        if self.currentness_requery_pending {
            return Err(invalid(
                "bond currentness decision-point requery is not implemented",
            ));
        }
        if signer.address() != self.content.expected_key {
            return Err(invalid("bond worker key differs from the pinned phase key"));
        }
        match self.owner {
            PreparedOwner::Inner(inner) => Ok(inner
                .prepared
                .sign_and_finalize_with(signer)
                .map_err(failure)?
                .signature),
            PreparedOwner::Outer(outer) => {
                let bytes = outer.sign_and_finalize_with(signer).map_err(failure)?;
                let signed =
                    sunrise_edge_client::bond_registration::decode_signed_bond_registration_intent(
                        &bytes,
                    )
                    .map_err(failure)?;
                Ok(signed.signature)
            }
        }
    }
}

pub(super) struct BondTrust {
    config: BondConfig,
    inner: BondInnerTrust,
    outer: BondRegistrationContext,
    resolver: sunrise_edge_client::HashSuiteResolver,
    root: VerifiedGenesisRoot,
}

impl BondTrust {
    pub(super) fn load(config: BondConfig, manifest_path: &Path) -> Result<Self, CliError> {
        let expected = config.expected_context().map_err(failure)?;
        let resolver = config.resolver().map_err(failure)?;
        let context = PublicationContext::new(
            expected.chain_id().clone(),
            expected.protocol_version(),
            expected.epoch(),
        )
        .map_err(failure)?;
        let root =
            load_verified_genesis_root(manifest_path, &resolver, config.genesis_digest(), &context)
                .map_err(failure)?;
        let inner = BondInnerTrust::new(expected, config.source_key(), root.clone())?;
        let outer = BondRegistrationContext::load(
            manifest_path,
            &resolver,
            config.genesis_digest(),
            &context,
            config.domain(),
        )
        .map_err(failure)?;
        Ok(Self {
            config,
            inner,
            outer,
            resolver,
            root,
        })
    }

    pub(super) fn config(&self) -> &BondConfig {
        &self.config
    }

    pub(super) fn currentness_root(&self) -> &VerifiedGenesisRoot {
        &self.root
    }

    pub(super) fn require_signing_ready(&self) -> Result<(), CliError> {
        if self.config.currentness().is_some() {
            return Err(invalid(
                "bond currentness decision-point requery is not implemented",
            ));
        }
        Ok(())
    }

    /// Derive the exact reviewed Coin reference before the one live
    /// prepare-inner observation. The final prepare repeats all checks.
    pub(super) fn source_ref_for_observation(
        &self,
        request: &BondInnerRequest,
    ) -> Result<sunrise_edge_client::ObjectRef, CliError> {
        self.check_inner_pins(request)?;
        Ok(self.inner.prepare(request)?.source_ref)
    }

    fn check_inner_pins(&self, request: &BondInnerRequest) -> Result<(), CliError> {
        if request.validator_key != self.config.validator_key()
            || request.resource != self.config.resource()
        {
            return Err(invalid(
                "bond request validator or resource differs from the role pin",
            ));
        }
        Ok(())
    }

    fn prepare_reviewed_inner(
        &self,
        request: &BondInnerRequest,
    ) -> Result<PreparedBondInner, CliError> {
        self.check_inner_pins(request)?;
        let mut inner = self.inner.prepare(request)?;
        match (
            self.config.currentness(),
            request.local_observation.as_ref(),
        ) {
            (None, None) => {}
            (Some(_), Some(frame)) => inner.review.push_str(&bond_currentness::review_locator(
                self,
                &inner.source_ref,
                frame,
            )?),
            _ => return Err(invalid("bond request and local node pin profile differ")),
        }
        if inner.review.len() > MAX_REVIEW_BYTES {
            return Err(invalid("bond inner review exceeds its bound"));
        }
        Ok(inner)
    }

    pub(super) fn prepare(&self, request: &BondRequest) -> Result<PreparedBondOperation, CliError> {
        match request {
            BondRequest::Inner(inner_request) => self.prepare_inner(inner_request, request),
            BondRequest::Outer {
                inner,
                signed_leg,
                row,
                outer_request_id,
            } => self.prepare_outer(inner, signed_leg, row, *outer_request_id, request),
        }
    }

    fn prepare_inner(
        &self,
        inner_request: &BondInnerRequest,
        whole_request: &BondRequest,
    ) -> Result<PreparedBondOperation, CliError> {
        let inner = self.prepare_reviewed_inner(inner_request)?;
        let frame = inner.prepared.signable_frame().to_vec();
        let review = inner.review.clone();
        Ok(PreparedBondOperation {
            content: BondApprovalContent {
                phase: BondPhase::Inner,
                request_id: inner_request.request_id,
                inner_request_id: inner_request.request_id,
                expected_key: self.config.source_key(),
                config: self.config.raw_bytes().to_vec(),
                request: bond_wire::encode_request(whole_request).map_err(failure)?,
                meaning: review.as_bytes().to_vec(),
                frame,
            },
            review,
            owner: PreparedOwner::Inner(Box::new(inner)),
            currentness_requery_pending: self.config.currentness().is_some(),
        })
    }

    fn prepare_outer(
        &self,
        inner_request: &BondInnerRequest,
        signed_leg: &[u8],
        row: &[u8],
        outer_request_id: RequestId,
        whole_request: &BondRequest,
    ) -> Result<PreparedBondOperation, CliError> {
        let inner = self.prepare_reviewed_inner(inner_request)?;
        let predicted_ref = inner.predicted_ref.clone();
        let amount = inner.amount;
        let decoded_leg = decode_signed_local_execution(signed_leg).map_err(failure)?;
        if inner.prepared.intent() != &decoded_leg.intent {
            return Err(invalid(
                "signed bond leg differs from the pinned whole-Coin transfer",
            ));
        }
        let verified_leg = inner
            .prepared
            .finalize(decoded_leg.signature.to_vec())
            .map_err(failure)?;
        if encode_signed_local_execution(&verified_leg).map_err(failure)? != signed_leg {
            return Err(invalid(
                "signed bond leg is not its canonical authenticated bytes",
            ));
        }
        let decoded_row = decode_fastpath_bond_record(row).map_err(failure)?;
        if encode_fastpath_bond_record(&decoded_row).map_err(failure)? != row {
            return Err(invalid("predicted bond row is not canonical"));
        }
        if decoded_row.custody_object != predicted_ref || decoded_row.amount != amount {
            return Err(invalid(
                "predicted bond row differs from the whole-Coin transfer effect",
            ));
        }
        let outer = self
            .outer
            .prepare_for_public_key(
                self.config.validator_key(),
                *outer_request_id.as_bytes(),
                signed_leg.to_vec(),
                decoded_row,
            )
            .map_err(failure)?;
        let content = preview_original_bond_registration_content(&self.resolver, &outer, row)
            .map_err(failure)?;
        if content.signed_leg != signed_leg || content.predicted_row != row {
            return Err(invalid(
                "bond registration content differs from approved input",
            ));
        }
        let review = format!(
            "profile=original-genesis-bond-registration\nauthorizing=false\nsigned=false\nexecuted=false\nsource_snapshot_unverified=true\ninner_request_id={}\nouter_request_id={}\nsource_key={}\nvalidator_key={}\ngenesis_digest={}\ninner_review_begin\n{}inner_review_end\nsigned_leg_hex={}\npredicted_row_hex={}\nouter_intent_hex={}\nouter_frame_hex={}\n",
            inner_request.request_id,
            outer_request_id,
            self.config.source_key(),
            self.config.validator_key_address(),
            self.root.digest(),
            inner.review,
            encode_hex(signed_leg),
            encode_hex(row),
            encode_hex(&content.outer_intent),
            encode_hex(outer.signable_frame()),
        );
        Ok(PreparedBondOperation {
            content: BondApprovalContent {
                phase: BondPhase::Outer,
                request_id: outer_request_id,
                inner_request_id: inner_request.request_id,
                expected_key: self.config.validator_key_address(),
                config: self.config.raw_bytes().to_vec(),
                request: bond_wire::encode_request(whole_request).map_err(failure)?,
                meaning: review.as_bytes().to_vec(),
                frame: outer.signable_frame().to_vec(),
            },
            review,
            owner: PreparedOwner::Outer(Box::new(outer)),
            currentness_requery_pending: self.config.currentness().is_some(),
        })
    }
}
