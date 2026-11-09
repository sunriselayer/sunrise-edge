//! Non-authorizing original-genesis Standard Asset bond-deposit preparation.
//! This module constructs an exact local frame and review; it never approves,
//! signs, sends a request to custody, or treats a caller object as live state.

use protocol_types::HashPurpose;
use public_standard_asset::{SCHEMA_VERSION, coin_amount, coin_type_tag, transfer_arguments};
use sunrise_edge_client::local_execution::{
    InstanceRecord, LocalExecutionMode, LocalExecutionPolicy, ResolvedExecutionScope,
    generic_object_result_semantics, instance_target,
};
use sunrise_edge_client::publication::{
    authenticate_publication_submission, verify_publication_interface,
};
use sunrise_edge_client::{
    AccessEntry, AccessManifest, AccessMode, Address, Digest32, ExpectedProtocolContext, Object,
    ObjectRef, Owner, PreparedLocalExecution, ProtocolCustodyPurpose, ProtocolCustodyScope,
    RequestId, VerifiedGenesisRoot, bond_registration::BondResourceId, call::CallIntent,
    encode_object,
};

use super::asset_trust::PinnedAssetTrust;
use crate::{error::CliError, hex::encode_hex};

const MAX_REVIEW_BYTES: usize = 64 * 1024;

fn failure(error: impl std::error::Error + Send + Sync + 'static) -> CliError {
    CliError::LocalExecution(Box::new(error))
}

fn invalid(message: &'static str) -> CliError {
    failure(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message,
    ))
}

/// Caller-supplied source snapshot and replay fields. No caller chooses code,
/// entrypoint, transfer operand, policy digest, frame or predicted mutation.
pub(crate) struct BondInnerRequest {
    pub(crate) source_coin_bytes: Vec<u8>,
    pub(crate) validator_key: [u8; 32],
    pub(crate) resource: BondResourceId,
    pub(crate) nonce: u64,
    pub(crate) request_id: RequestId,
    pub(crate) gas_limit: u64,
}

pub(crate) struct PreparedBondInner {
    pub(crate) prepared: PreparedLocalExecution,
    pub(crate) review: String,
    pub(crate) predicted_ref: ObjectRef,
    pub(crate) amount: u64,
}

/// Immutable original root and its independently rebuilt known-code trust.
/// The configured source key is not inferred from the unsigned request.
pub(crate) struct BondInnerTrust {
    trust: PinnedAssetTrust,
    root: VerifiedGenesisRoot,
    source_key: Address,
    scope: ResolvedExecutionScope,
}

impl BondInnerTrust {
    pub(crate) fn new(
        expected: ExpectedProtocolContext,
        source_key: Address,
        root: VerifiedGenesisRoot,
    ) -> Result<Self, CliError> {
        sunrise_edge_client::validate_ed25519_owner_address(
            source_key.as_bytes(),
            sunrise_edge_client::Ed25519OwnerAddressPolicy::CanonicalPrimeOrder,
        )
        .map_err(failure)?;
        let trust = PinnedAssetTrust::from_original_scope(expected, source_key, root.clone())?;
        let context = &trust.context;
        let semantics =
            generic_object_result_semantics(&trust.resolver, context).map_err(failure)?;
        let candidate = authenticate_publication_submission(
            &trust.resolver,
            context,
            &semantics,
            root.manifest().publication.clone(),
        )
        .map_err(failure)?;
        let interface = verify_publication_interface(candidate, Vec::new()).map_err(failure)?;
        let initialization = &root.manifest().initialization.intent.call;
        let record = InstanceRecord {
            context: context.clone(),
            creator: initialization.sender,
            seed: initialization.instance.seed,
            code: trust.fee_policy.code.clone(),
            revision: 1,
            initializer: public_standard_asset::INITIALIZER.to_owned(),
        };
        let target = instance_target(&trust.resolver, &record).map_err(failure)?;
        if target != trust.fee_policy.instance {
            return Err(invalid(
                "bond genesis Standard Asset instance differs from initializer",
            ));
        }
        Ok(Self {
            trust,
            root,
            source_key,
            scope: ResolvedExecutionScope {
                instance: record,
                target,
                interface,
            },
        })
    }

    pub(crate) fn prepare(
        &self,
        request: &BondInnerRequest,
    ) -> Result<PreparedBondInner, CliError> {
        sunrise_edge_client::validate_ed25519_owner_address(
            &request.validator_key,
            sunrise_edge_client::Ed25519OwnerAddressPolicy::CanonicalPrimeOrder,
        )
        .map_err(failure)?;
        if request.gas_limit == 0 {
            return Err(invalid("bond inner gas limit must be positive"));
        }
        let resource = self
            .root
            .manifest()
            .economics_policy
            .resources
            .iter()
            .find(|entry| entry.resource_id == request.resource)
            .ok_or_else(|| invalid("bond resource is absent from the signed genesis policy"))?;
        let bond = resource
            .bond
            .as_ref()
            .filter(|bond| bond.enabled)
            .ok_or_else(|| invalid("bond resource is not enabled"))?;
        let asset = sunrise_edge_client::ObjectId::new(*request.resource.value());
        let coin_tag = coin_type_tag(&self.trust.origin, &asset).map_err(failure)?;
        if request.resource.domain() != public_standard_asset::ASSET_OPAQUE_DOMAIN
            || resource.context != self.trust.context
            || resource.code != self.trust.fee_policy.code
            || resource.instance != self.trust.fee_policy.instance
            || resource.ty != coin_tag
            || resource.schema != SCHEMA_VERSION
            || resource.transfer_entrypoint != "transfer"
            || self.scope.interface.argument_layout("transfer").is_none()
        {
            return Err(invalid(
                "bond resource is not the pinned Standard Asset revision-one transfer",
            ));
        }
        let source_object: Object = self.trust.decode_bounded_object(
            &request.source_coin_bytes,
            "bond source coin exceeds the accepted size",
            "bond source coin is not canonical",
        )?;
        self.trust.validate_owned_object(
            &source_object,
            &coin_tag,
            "bond source is not owned by the pinned source key",
            "bond source schema differs from the signed resource",
            "bond source is not the signed resource Coin type",
        )?;
        let amount = coin_amount(&source_object.data).map_err(failure)?;
        if amount == 0
            || amount < bond.min_bond.get()
            || bond
                .max_validator_exposure
                .is_some_and(|max| amount > max.get())
        {
            return Err(invalid(
                "bond source amount is outside the signed bond limits",
            ));
        }
        let epoch = self.trust.context.epoch();
        let source_digest: Digest32 = self
            .trust
            .resolver
            .hash_for_purpose(epoch, HashPurpose::Object, &request.source_coin_bytes)
            .map_err(failure)?;
        let source: ObjectRef = ObjectRef {
            id: source_object.id,
            version: source_object.version,
            digest: source_digest,
        };
        let deposit_scope = ProtocolCustodyScope {
            purpose: ProtocolCustodyPurpose::BondCollateral,
            chain_id: self.trust.context.chain_id().clone(),
            subject: request.validator_key,
            resource: *request.resource.value(),
        };
        let token = execution::protocol_custody::derive_deposit_owner_token(
            &self.trust.resolver,
            &self.trust.context,
            source_object.id,
            &deposit_scope,
        )
        .map_err(failure)?;
        let mut predicted_object = source_object.clone();
        predicted_object.version = predicted_object
            .version
            .checked_add(1)
            .ok_or_else(|| invalid("bond source version overflows"))?;
        predicted_object.owner = Owner::ProtocolCustody(deposit_scope);
        let predicted_bytes = encode_object(&predicted_object).map_err(failure)?;
        let predicted: ObjectRef = ObjectRef {
            id: predicted_object.id,
            version: predicted_object.version,
            digest: self
                .trust
                .resolver
                .hash_for_purpose(epoch, HashPurpose::Object, &predicted_bytes)
                .map_err(failure)?,
        };
        let call = CallIntent {
            context: self.trust.context.clone(),
            request_id: *request.request_id.as_bytes(),
            sender: *self.source_key.as_bytes(),
            nonce: request.nonce,
            code: resource.code.clone(),
            instance: resource.instance.clone(),
            entrypoint: resource.transfer_entrypoint.clone(),
            type_arguments: resource.ty.args().to_vec(),
            access: AccessManifest {
                entries: vec![AccessEntry {
                    object_ref: source.clone(),
                    mode: AccessMode::Write,
                }],
            },
            arguments: transfer_arguments(&token).map_err(failure)?,
            gas_limit: request.gas_limit,
        };
        let policy = LocalExecutionPolicy::generic_object_results(self.trust.context.clone());
        let prepared = PreparedLocalExecution::prepare(
            self.source_key,
            &self.trust.resolver,
            &self.trust.expected,
            &policy,
            LocalExecutionMode::Call,
            call,
            Vec::new(),
            std::slice::from_ref(&self.scope),
        )
        .map_err(failure)?;
        let mut review = format!(
            "profile=original-genesis-standard-asset-bond-inner\nauthorizing=false\nsigned=false\nexecuted=false\nsource_snapshot_unverified=true\nchain_id={}\nprotocol_version={}\nepoch={}\ndomain={}\ngenesis_digest={}\ncode_revision=1\ncode_artifact_digest={}\ncode_dependencies=none\nentrypoint=transfer\nsource_owner={}\nsource_id={}\nsource_version={}\nsource_digest={}\namount={}\ntransfer=whole-coin-unchanged\nvalidator_key={}\nresource_domain={}\nresource={}\ndeposit_token={}\npredicted_owner=BondCollateral\npredicted_id={}\npredicted_version={}\npredicted_digest={}\nrequest_id={}\nnonce={}\ngas_limit={}\nunsigned_frame_hex={}\n",
            self.trust.context.chain_id(),
            self.trust.context.protocol_version().get(),
            epoch.get(),
            self.trust.expected.domain(),
            self.trust.genesis_digest,
            resource.code.artifact_digest(),
            self.source_key,
            source.id,
            source.version,
            source.digest,
            amount,
            encode_hex(&request.validator_key),
            request.resource.domain(),
            encode_hex(request.resource.value()),
            encode_hex(&token),
            predicted.id,
            predicted.version,
            predicted.digest,
            request.request_id,
            request.nonce,
            request.gas_limit,
            encode_hex(prepared.signable_frame()),
        );
        review.push_str(&format!(
            "code_origin_publisher={}\ncode_origin_seed={}\ninstance_creator={}\ninstance_seed={}\ninstance_revision={}\ninstance_record_digest={}\nsource_schema={}\nsource_type_hex={}\nsource_object_hex={}\npredicted_object_hex={}\npolicy_digest={}\nunsigned_intent_hex={}\n",
            encode_hex(self.trust.origin.publisher()),
            encode_hex(self.trust.origin.seed()),
            encode_hex(&resource.instance.creator),
            encode_hex(&resource.instance.seed),
            resource.instance.revision,
            resource.instance.record_digest,
            source_object.schema_version,
            encode_hex(&sunrise_edge_client::package_types::encode_scoped_type_tag(&resource.ty).map_err(failure)?),
            encode_hex(&request.source_coin_bytes),
            encode_hex(&predicted_bytes),
            prepared.intent().policy_digest,
            encode_hex(&sunrise_edge_client::local_execution::encode_local_execution_intent(prepared.intent()).map_err(failure)?),
        ));
        if review.len() > MAX_REVIEW_BYTES {
            return Err(invalid("bond inner review exceeds its bound"));
        }
        Ok(PreparedBondInner {
            prepared,
            review,
            predicted_ref: predicted,
            amount,
        })
    }
}
