//! Immutable recognized Standard Asset positive-Split proposals (DR-0267).
//!
//! No key, approval, IPC, network, state mutation or currentness authority lives
//! here. Two separate retained owners prepare the recognized local leg and then
//! its exact outer fee claim. A future protected consumer must handle BOTH key
//! uses; protecting only the outer claim does not isolate the historical key.

use protocol_types::HashPurpose;
use std::{error::Error, fmt};
use sunrise_edge_client::call::{CallIntent, InstanceTarget};
use sunrise_edge_client::call_values::{CallValue, encode_call_value};
use sunrise_edge_client::local_execution::{
    InstanceRecord, LocalExecutionMode, LocalExecutionPolicy, ResolvedExecutionScope,
    SignedLocalExecutionIntent, derive_local_created_object_id, encode_signed_local_execution,
    generic_object_result_semantics, instance_target, local_execution_event_digest,
};
use sunrise_edge_client::package_types::{
    ScopedTypeArg, ScopedTypeTag, derive_scoped_type_id, verify_scoped_type_id,
};
use sunrise_edge_client::publication::{
    AuthenticatedPublicationCandidate, VerifiedPublicationInterface,
    authenticate_publication_submission, verify_publication_interface,
};
use sunrise_edge_client::{
    AccessEntry, AccessManifest, AccessMode, Address, ArtifactParts, CodeArtifact, Digest32,
    ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_BINDING_ID,
    ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID, Ed25519OwnerAddressPolicy,
    Epoch, ExpectedProtocolContext, FeeClaimIntent, FeeClaimOperation, FeeClaimPrepareRequest,
    FeeClaimReview, HashSuiteResolver, MAX_AUTHENTICATED_OBJECT_BODY_BYTES,
    MAX_FEE_CLAIM_INTENT_BYTES, MAX_FEE_CLAIM_PREPARE_REQUEST_BYTES, Object, ObjectId, ObjectRef,
    Owner, PreparedFeeClaim, PreparedLocalExecution, ProtocolCustodyPurpose, ProtocolCustodyScope,
    PublicationContext, SignatureSchemeId, SuccessorWorkflowAuthority, UnverifiedDependencyRef,
    ValidatorId, VerifiedGenesisRoot, decode_fee_claim_intent, decode_object,
    encode_fee_claim_intent, encode_object, validate_ed25519_owner_address,
};

/// Aggregate rendered meaning plus the unchanged generic outer review.
pub const MAX_POSITIVE_SPLIT_REVIEW_BYTES: usize = 128 * 1024;

/// Refusal of this closed proposal policy; underlying diagnostics are not exposed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PositiveSplitError {
    /// Unrecognized exact root, resource, code, instance or policy.
    Resource,
    /// The supplied workflow/claimant is not the supported historical scope.
    Authority,
    /// A retained object or signed leg differs from the recognized operation.
    Content,
    /// A canonical encoding, signature or explicit bound was refused.
    Canonical,
    /// A complete, terminal-safe bounded review could not be produced.
    Review,
}
impl fmt::Display for PositiveSplitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "positive Split proposal refused: {self:?}")
    }
}
impl Error for PositiveSplitError {}

/// Explicit local historical claimant pin, never selected from a peer response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoricalClaimantPin {
    /// Original certificate committee epoch supported by this first profile.
    pub certificate_epoch: Epoch,
    /// Validator identity inside that historical committee.
    pub validator: ValidatorId,
    /// Independently retained Ed25519 public identity.
    pub public_key: Address,
}

/// Exact requested positive operation; nonce and entitlement freshness are unproven.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PositiveSplitTerms {
    /// Existing escrow subject, independently selected for this proposal.
    pub escrow_request_id: [u8; 32],
    /// New outer AND embedded-leg replay identifier.
    pub request_id: [u8; 32],
    /// Positive strict partial amount in the retained fee object.
    pub amount: u64,
    /// Complete release recipient.
    pub recipient: Address,
    /// Explicit captured sender nonce; this module does not query it.
    pub nonce: u64,
    /// Explicit fuel within the existing local-execution ceiling.
    pub gas_limit: u64,
}

/// Bounded canonical fee-object preimage and its separately retained reference.
/// The hash epoch is a local provenance assertion, not a fetched currentness proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedFeeObject {
    /// Complete canonical object, including owner, type, version and body.
    pub canonical_bytes: Vec<u8>,
    /// Exact expected reference from the retained escrow proposal.
    pub reference: ObjectRef,
    /// Hash-suite epoch asserted for this retained object in the same protocol.
    pub hash_epoch: Epoch,
}

#[derive(Clone)]
struct KnownStandardAsset {
    context: PublicationContext,
    code: UnverifiedDependencyRef,
    asset: ObjectId,
    coin: ScopedTypeTag,
    scope: ResolvedExecutionScope,
}

impl KnownStandardAsset {
    fn from_root(root: &VerifiedGenesisRoot) -> Result<Self, PositiveSplitError> {
        let context: PublicationContext = root.genesis_context().clone();
        let resolver: &HashSuiteResolver = root.genesis_resolver();
        let fee: &sunrise_edge_client::PaidFeePolicy = &root.manifest().fee_policy;
        let asset: ObjectId = match fee.type_arguments.as_slice() {
            [ScopedTypeArg::Opaque { domain, value }]
                if *domain == public_standard_asset::ASSET_OPAQUE_DOMAIN =>
            {
                ObjectId::new(*value)
            }
            _ => return Err(PositiveSplitError::Resource),
        };
        let coin: ScopedTypeTag = public_standard_asset::coin_type_tag(fee.code.origin(), &asset)
            .map_err(|_| PositiveSplitError::Resource)?;
        let reservation: ScopedTypeTag =
            public_standard_asset::reservation_type_tag(fee.code.origin(), &asset)
                .map_err(|_| PositiveSplitError::Resource)?;
        let original_policy: LocalExecutionPolicy =
            LocalExecutionPolicy::generic_object_results(context.clone());
        let resource = root
            .manifest()
            .economics_policy
            .resources
            .iter()
            .find(|entry| {
                entry.resource_id.domain() == public_standard_asset::ASSET_OPAQUE_DOMAIN
                    && entry.resource_id.value() == asset.as_bytes()
            })
            .ok_or(PositiveSplitError::Resource)?;
        if fee.context != context
            || fee.schema != public_standard_asset::SCHEMA_VERSION
            || fee.asset_type != coin
            || fee.reservation_type != reservation
            || fee.reserve_entrypoint != "reserve"
            || fee.reserve_all_entrypoint != "reserve_all"
            || fee.settle_entrypoint != "settle"
            || fee.base_policy_digest
                != original_policy
                    .digest(resolver)
                    .map_err(|_| PositiveSplitError::Resource)?
            || resource.ty != coin
            || !resource.fee_escrow
            || resource.context != context
            || resource.code != fee.code
            || resource.instance != fee.instance
            || resource.schema != fee.schema
            || resource.split_entrypoint != "split"
            || resource.transfer_entrypoint != "transfer"
        {
            return Err(PositiveSplitError::Resource);
        }
        let semantics: Digest32 = generic_object_result_semantics(resolver, &context)
            .map_err(|_| PositiveSplitError::Resource)?;
        let candidate: AuthenticatedPublicationCandidate = authenticate_publication_submission(
            resolver,
            &context,
            &semantics,
            root.manifest().publication.clone(),
        )
        .map_err(|_| PositiveSplitError::Resource)?;
        let package: public_standard_asset::StandardAssetPackage =
            public_standard_asset::build_package(fee.code.origin())
                .map_err(|_| PositiveSplitError::Resource)?;
        let expected: CodeArtifact = CodeArtifact::new(ArtifactParts {
            context: context.clone(),
            origin: fee.code.origin().clone(),
            revision: 1,
            wasm_profile: public_standard_asset::REQUIRED_WASM_PROFILE,
            semantics,
            wasm: package.wasm,
            unverified_abi: package.encoded_abi,
            exports: package.exports,
            unverified_dependencies: Vec::new(),
        })
        .map_err(|_| PositiveSplitError::Resource)?;
        let code: UnverifiedDependencyRef = UnverifiedDependencyRef::new(
            expected.origin().clone(),
            1,
            context.clone(),
            *candidate.digest(),
        )
        .map_err(|_| PositiveSplitError::Resource)?;
        if candidate.artifact() != &expected || fee.code != code {
            return Err(PositiveSplitError::Resource);
        }
        // The complete signed root has already authenticated initialization.
        // Reconstruct its exact known initializer and pin the retained instance.
        let initialization: &SignedLocalExecutionIntent = &root.manifest().initialization;
        let call: &CallIntent = &initialization.intent.call;
        let instance: InstanceRecord = InstanceRecord {
            context: context.clone(),
            creator: call.sender,
            seed: call.instance.seed,
            code: code.clone(),
            revision: 1,
            initializer: public_standard_asset::INITIALIZER.into(),
        };
        let target: InstanceTarget =
            instance_target(resolver, &instance).map_err(|_| PositiveSplitError::Resource)?;
        if initialization.intent.mode != LocalExecutionMode::Instantiate
            || call.context != context
            || call.code != code
            || call.instance != target
            || fee.instance != target
            || call.entrypoint != public_standard_asset::INITIALIZER
            || !call.type_arguments.is_empty()
            || !call.access.entries.is_empty()
            || !initialization.intent.authorizations.is_empty()
            || call.arguments
                != public_standard_asset::no_arguments()
                    .map_err(|_| PositiveSplitError::Resource)?
        {
            return Err(PositiveSplitError::Resource);
        }
        let interface: VerifiedPublicationInterface =
            verify_publication_interface(candidate, Vec::new())
                .map_err(|_| PositiveSplitError::Resource)?;
        Ok(Self {
            context,
            code,
            asset,
            coin,
            scope: ResolvedExecutionScope {
                instance,
                target,
                interface,
            },
        })
    }
}

/// Locally pinned recognized resource and verified successor/historical authority.
/// Only the original genesis fee resource/certificate epoch is supported here.
#[derive(Clone)]
pub struct StandardAssetPositiveSplitPolicy<'a> {
    workflow: &'a SuccessorWorkflowAuthority,
    claimant: HistoricalClaimantPin,
    known: KnownStandardAsset,
}
impl<'a> StandardAssetPositiveSplitPolicy<'a> {
    /// Loads no key, network or mutable replacement preimage.
    pub fn new(
        workflow: &'a SuccessorWorkflowAuthority,
        claimant: HistoricalClaimantPin,
    ) -> Result<Self, PositiveSplitError> {
        if claimant.certificate_epoch != workflow.genesis_root().genesis_context().epoch()
            || claimant.certificate_epoch >= workflow.expected_context().epoch()
        {
            return Err(PositiveSplitError::Authority);
        }
        let member: &sunrise_edge_client::ValidatorInfo = workflow
            .ordered_policy()
            .certificate_set(claimant.certificate_epoch)
            .and_then(|set| set.get(claimant.validator))
            .ok_or(PositiveSplitError::Authority)?;
        if member.signature_scheme != SignatureSchemeId::Ed25519
            || member.public_key.as_slice() != claimant.public_key.as_bytes()
        {
            return Err(PositiveSplitError::Authority);
        }
        let known: KnownStandardAsset = KnownStandardAsset::from_root(workflow.genesis_root())?;
        Ok(Self {
            workflow,
            claimant,
            known,
        })
    }

    /// Constructs only the recognized leg from full retained object/terms.
    pub fn prepare_leg(
        &self,
        terms: PositiveSplitTerms,
        object: RetainedFeeObject,
    ) -> Result<PreparedPositiveSplitLeg<'a>, PositiveSplitError> {
        self.workflow
            .require_signing_context(self.workflow.expected_context())
            .map_err(|_| PositiveSplitError::Authority)?;
        let prepared: PreparedLocalExecution = prepare_recognized_leg(
            &self.known,
            self.workflow.ordered_policy().resolver(),
            self.workflow.expected_context(),
            self.workflow.ordered_policy().domain(),
            self.claimant,
            &terms,
            &object,
        )?;
        let review: PositiveSplitMeaning = PositiveSplitMeaning::build(
            self.claimant,
            self.workflow.expected_context().clone(),
            self.workflow.genesis_root().digest(),
            self.workflow.ordered_policy().anchor(),
            &self.known,
            &terms,
            &object,
            prepared.signable_frame(),
        )?;
        Ok(PreparedPositiveSplitLeg {
            policy: self.clone(),
            terms,
            object,
            prepared,
            review,
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn prepare_recognized_leg(
    known: &KnownStandardAsset,
    resolver: &HashSuiteResolver,
    context: &PublicationContext,
    domain: sunrise_edge_client::AtomicityDomainId,
    claimant: HistoricalClaimantPin,
    terms: &PositiveSplitTerms,
    retained: &RetainedFeeObject,
) -> Result<PreparedLocalExecution, PositiveSplitError> {
    if retained.canonical_bytes.len() > MAX_AUTHENTICATED_OBJECT_BODY_BYTES
        || retained.hash_epoch > context.epoch()
        || terms.request_id == [0; 32]
        || terms.escrow_request_id == [0; 32]
        || terms.nonce == u64::MAX
        || sunrise_edge_client::is_reserved_paid_request_id(&terms.request_id)
        || terms.gas_limit == 0
        || terms.gas_limit > sunrise_edge_client::local_execution::MAX_LOCAL_EXECUTION_GAS
        || context.chain_id() != known.context.chain_id()
        || context.protocol_version() != known.context.protocol_version()
        || context.epoch() <= known.context.epoch()
    {
        return Err(PositiveSplitError::Content);
    }
    validate_ed25519_owner_address(
        terms.recipient.as_bytes(),
        Ed25519OwnerAddressPolicy::CanonicalPrimeOrder,
    )
    .map_err(|_| PositiveSplitError::Content)?;
    let object: Object =
        decode_object(&retained.canonical_bytes).map_err(|_| PositiveSplitError::Canonical)?;
    let digest: Digest32 = resolver
        .hash_for_purpose(
            retained.hash_epoch,
            HashPurpose::Object,
            &retained.canonical_bytes,
        )
        .map_err(|_| PositiveSplitError::Canonical)?;
    let owner: Owner = Owner::ProtocolCustody(ProtocolCustodyScope {
        purpose: ProtocolCustodyPurpose::FeeEscrow,
        chain_id: context.chain_id().clone(),
        subject: terms.escrow_request_id,
        resource: *known.asset.as_bytes(),
    });
    if encode_object(&object).map_err(|_| PositiveSplitError::Canonical)?
        != retained.canonical_bytes
        || object.id != retained.reference.id
        || object.version != retained.reference.version
        || object.version == 0
        || object.version == u64::MAX
        || digest != retained.reference.digest
        || object.owner != owner
        || object.schema_version != public_standard_asset::SCHEMA_VERSION
        || !verify_scoped_type_id(resolver, &object.type_hash, context.epoch(), &known.coin)
            .map_err(|_| PositiveSplitError::Canonical)?
    {
        return Err(PositiveSplitError::Content);
    }
    let held: u64 = public_standard_asset::coin_amount(&object.data)
        .map_err(|_| PositiveSplitError::Content)?;
    if terms.amount == 0 || terms.amount >= held {
        return Err(PositiveSplitError::Content);
    }
    let policy: LocalExecutionPolicy =
        LocalExecutionPolicy::generic_object_results(context.clone());
    let expected: ExpectedProtocolContext = ExpectedProtocolContext::new(
        context.chain_id().clone(),
        context.protocol_version(),
        context.epoch(),
        resolver
            .suite_for_epoch(context.epoch())
            .map_err(|_| PositiveSplitError::Authority)?
            .id,
        ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID,
        SignatureSchemeId::Ed25519.as_u16(),
        ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_BINDING_ID,
        domain,
    )
    .map_err(|_| PositiveSplitError::Authority)?;
    let call: CallIntent = CallIntent {
        context: context.clone(),
        request_id: terms.request_id,
        sender: *claimant.public_key.as_bytes(),
        nonce: terms.nonce,
        code: known.code.clone(),
        instance: known.scope.target.clone(),
        entrypoint: "split".into(),
        type_arguments: known.coin.args().to_vec(),
        access: AccessManifest {
            entries: vec![AccessEntry {
                object_ref: retained.reference.clone(),
                mode: AccessMode::Write,
            }],
        },
        arguments: public_standard_asset::split_arguments(terms.amount, terms.recipient.as_bytes())
            .map_err(|_| PositiveSplitError::Content)?,
        gas_limit: terms.gas_limit,
    };
    PreparedLocalExecution::prepare(
        claimant.public_key,
        resolver,
        &expected,
        &policy,
        LocalExecutionMode::Call,
        call,
        Vec::new(),
        std::slice::from_ref(&known.scope),
    )
    .map_err(|_| PositiveSplitError::Content)
}

/// Immutable operation meaning under retained inputs; not entitlement/currentness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PositiveSplitMeaning {
    amount: u64,
    remaining: u64,
    text: String,
}
impl PositiveSplitMeaning {
    #[allow(clippy::too_many_arguments)]
    fn build(
        claimant: HistoricalClaimantPin,
        context: PublicationContext,
        genesis: Digest32,
        anchor: Digest32,
        known: &KnownStandardAsset,
        terms: &PositiveSplitTerms,
        object: &RetainedFeeObject,
        frame: &[u8],
    ) -> Result<Self, PositiveSplitError> {
        if !context
            .chain_id()
            .as_str()
            .bytes()
            .all(|byte| (0x20..=0x7e).contains(&byte))
            || frame.len() > MAX_POSITIVE_SPLIT_REVIEW_BYTES / 8
        {
            return Err(PositiveSplitError::Review);
        }
        let decoded: Object =
            decode_object(&object.canonical_bytes).map_err(|_| PositiveSplitError::Canonical)?;
        let held: u64 = public_standard_asset::coin_amount(&decoded.data)
            .map_err(|_| PositiveSplitError::Content)?;
        let remaining: u64 = held
            .checked_sub(terms.amount)
            .filter(|value| *value > 0)
            .ok_or(PositiveSplitError::Content)?;
        let text: String = format!(
            concat!(
                "review_kind=recognized_standard_asset_positive_split_proposal\n",
                "claim_entitlement=not_proven\nescrow_and_nonce_freshness=not_proven\n",
                "chain_id={}\nprotocol_version={}\nexecution_epoch={}\ncertificate_epoch={}\n",
                "genesis_digest={}\nordered_anchor={}\nvalidator={}\nclaimant={}\n",
                "resource_domain={}\nresource={}\ncode_artifact={}\ncode_revision={}\n",
                "code_origin_publisher={}\ncode_origin_seed={}\nresource_epoch={}\n",
                "instance_creator={}\ninstance_seed={}\nentrypoint=split\n",
                "escrow_request={}\nrequest={}\nfee_object={}\nfee_version={}\nfee_digest={}\n",
                "asserted_object_hash_epoch={}\nfee_schema={}\nfee_type_hash={}\nowner_kind=fee_escrow\n",
                "mode=call\nexecution_profile=4\naccess=one_exact_write\nauthorizations=none\n",
                "retained_balance={}\nrelease_amount={}\nretained_remainder={}\nrecipient={}\n",
                "nonce={}\ngas_limit={}\nleg_frame={}\n"
            ),
            context.chain_id(),
            context.protocol_version().get(),
            context.epoch().get(),
            claimant.certificate_epoch.get(),
            genesis,
            anchor,
            claimant.validator,
            claimant.public_key,
            public_standard_asset::ASSET_OPAQUE_DOMAIN,
            known.asset,
            known.code.artifact_digest(),
            known.code.revision(),
            crate::hex::encode_hex(known.code.origin().publisher()),
            crate::hex::encode_hex(known.code.origin().seed()),
            known.context.epoch().get(),
            crate::hex::encode_hex(&known.scope.target.creator),
            crate::hex::encode_hex(&known.scope.target.seed),
            crate::hex::encode_hex(&terms.escrow_request_id),
            crate::hex::encode_hex(&terms.request_id),
            object.reference.id,
            object.reference.version,
            object.reference.digest,
            object.hash_epoch.get(),
            decoded.schema_version,
            decoded.type_hash,
            held,
            terms.amount,
            remaining,
            terms.recipient,
            terms.nonce,
            terms.gas_limit,
            crate::hex::encode_hex(frame)
        );
        if text.len() > MAX_POSITIVE_SPLIT_REVIEW_BYTES / 2 {
            return Err(PositiveSplitError::Review);
        }
        Ok(Self {
            amount: terms.amount,
            remaining,
            text,
        })
    }
    /// Released amount conditional on acceptance against the actual escrow.
    #[must_use]
    pub const fn amount(&self) -> u64 {
        self.amount
    }
    /// Remainder of the retained object preimage, not a current balance query.
    #[must_use]
    pub const fn retained_remainder(&self) -> u64 {
        self.remaining
    }
    /// Complete bounded recognized meaning and exact leg frame, with limitations.
    #[must_use]
    pub fn render_text(&self) -> &str {
        &self.text
    }
}

/// First immutable stage. Only this recognized leg can consume its signature.
pub struct PreparedPositiveSplitLeg<'a> {
    policy: StandardAssetPositiveSplitPolicy<'a>,
    terms: PositiveSplitTerms,
    object: RetainedFeeObject,
    prepared: PreparedLocalExecution,
    review: PositiveSplitMeaning,
}
impl<'a> PreparedPositiveSplitLeg<'a> {
    /// Frame reconstructed from recognized semantics, never an arbitrary input.
    #[must_use]
    pub fn signable_frame(&self) -> &[u8] {
        self.prepared.signable_frame()
    }
    /// Immutable complete meaning of this exact leg.
    #[must_use]
    pub fn review(&self) -> &PositiveSplitMeaning {
        &self.review
    }
    /// Independently authenticates the returned signature and predicts the known
    /// split's one payout. Prediction grants no execution/receipt authority.
    pub fn finalize(
        self,
        signature: Vec<u8>,
    ) -> Result<SignedPositiveSplitLeg<'a>, PositiveSplitError> {
        let signed: SignedLocalExecutionIntent = self
            .prepared
            .finalize(signature)
            .map_err(|_| PositiveSplitError::Canonical)?;
        let resolver: &HashSuiteResolver = self.policy.workflow.ordered_policy().resolver();
        let context: &PublicationContext = self.policy.workflow.expected_context();
        let event: Digest32 = local_execution_event_digest(resolver, &signed)
            .map_err(|_| PositiveSplitError::Canonical)?;
        let id: ObjectId = derive_local_created_object_id(
            resolver,
            context,
            &self.policy.known.context,
            &self.policy.known.scope.target,
            &self.policy.known.code,
            event,
            0,
        )
        .map_err(|_| PositiveSplitError::Canonical)?;
        let payout: Object = Object {
            id,
            version: 1,
            owner: Owner::Address(self.terms.recipient),
            type_hash: derive_scoped_type_id(resolver, context.epoch(), &self.policy.known.coin)
                .map_err(|_| PositiveSplitError::Canonical)?,
            schema_version: public_standard_asset::SCHEMA_VERSION,
            data: encode_call_value(
                &public_standard_asset::coin_body_layout(),
                &CallValue::U64(self.terms.amount),
            )
            .map_err(|_| PositiveSplitError::Canonical)?,
        };
        let payout_bytes: Vec<u8> =
            encode_object(&payout).map_err(|_| PositiveSplitError::Canonical)?;
        let expected_payout: ObjectRef = ObjectRef {
            id,
            version: 1,
            digest: resolver
                .hash_for_purpose(context.epoch(), HashPurpose::Object, &payout_bytes)
                .map_err(|_| PositiveSplitError::Canonical)?,
        };
        let bytes: Vec<u8> =
            encode_signed_local_execution(&signed).map_err(|_| PositiveSplitError::Canonical)?;
        Ok(SignedPositiveSplitLeg {
            policy: self.policy,
            terms: self.terms,
            object: self.object,
            review: self.review,
            bytes,
            expected_payout,
        })
    }
}

/// Authenticated recognized leg retained before asking a host for an outer intent.
pub struct SignedPositiveSplitLeg<'a> {
    policy: StandardAssetPositiveSplitPolicy<'a>,
    terms: PositiveSplitTerms,
    object: RetainedFeeObject,
    review: PositiveSplitMeaning,
    bytes: Vec<u8>,
    expected_payout: ObjectRef,
}
impl<'a> SignedPositiveSplitLeg<'a> {
    /// Exact canonical signed leg for the existing seed-free prepare request.
    #[must_use]
    pub fn canonical_signed_leg(&self) -> &[u8] {
        &self.bytes
    }
    /// Independently predicted ref conditional on executing the recognized code.
    #[must_use]
    pub fn predicted_payout(&self) -> &ObjectRef {
        &self.expected_payout
    }
    /// Closed request whose selectors cannot differ from the reviewed leg.
    #[must_use]
    pub fn request(&self) -> FeeClaimPrepareRequest {
        FeeClaimPrepareRequest {
            context: self.policy.workflow.expected_context().clone(),
            escrow_request_id: self.terms.escrow_request_id,
            request_id: self.terms.request_id,
            validator_id: self.policy.claimant.validator,
            claimant_public_key: *self.policy.claimant.public_key.as_bytes(),
            recipient: self.terms.recipient,
            signed_leg: Some(self.bytes.clone()),
        }
    }
    /// Rechecks bounded canonical saved files against BOTH retained owners.
    /// Generation and row digests are displayed host proposals, not certified here.
    pub fn prepare_claim(
        self,
        request_bytes: &[u8],
        intent_bytes: &[u8],
    ) -> Result<PreparedPositiveSplitClaim<'a>, PositiveSplitError> {
        if request_bytes.len() > MAX_FEE_CLAIM_PREPARE_REQUEST_BYTES
            || intent_bytes.len() > MAX_FEE_CLAIM_INTENT_BYTES
        {
            return Err(PositiveSplitError::Canonical);
        }
        let request: FeeClaimPrepareRequest = FeeClaimPrepareRequest::decode(request_bytes)
            .map_err(|_| PositiveSplitError::Canonical)?;
        let intent: FeeClaimIntent =
            decode_fee_claim_intent(intent_bytes).map_err(|_| PositiveSplitError::Canonical)?;
        if request
            .encode()
            .map_err(|_| PositiveSplitError::Canonical)?
            != request_bytes
            || encode_fee_claim_intent(&intent).map_err(|_| PositiveSplitError::Canonical)?
                != intent_bytes
            || request != self.request()
            || intent.certificate_epoch != self.policy.claimant.certificate_epoch
            || intent.resource_id.domain() != public_standard_asset::ASSET_OPAQUE_DOMAIN
            || intent.resource_id.value() != self.policy.known.asset.as_bytes()
            || intent.expected_fee_output != self.object.reference
            || intent.share_amount != self.terms.amount
            || intent.expected_generation == 0
            || !matches!(&intent.operation, FeeClaimOperation::Split {leg, expected_payout:Some(payout)}
                if leg == &self.bytes && payout == &self.expected_payout)
        {
            return Err(PositiveSplitError::Content);
        }
        let prepared: PreparedFeeClaim<'a> =
            PreparedFeeClaim::prepare(self.policy.workflow, &request, intent)
                .map_err(|_| PositiveSplitError::Authority)?;
        let generic: FeeClaimReview =
            FeeClaimReview::build(&prepared).map_err(|_| PositiveSplitError::Review)?;
        let labels: &str = "payout_prediction=conditional_not_a_receipt\nproposed_row_digests_and_generation=not_independently_certified\n";
        let generic_text: String = generic.render_text();
        let total: usize = self
            .review
            .render_text()
            .len()
            .checked_add(labels.len())
            .and_then(|length| length.checked_add(generic_text.len()))
            .ok_or(PositiveSplitError::Review)?;
        if total > MAX_POSITIVE_SPLIT_REVIEW_BYTES {
            return Err(PositiveSplitError::Review);
        }
        let text: String = format!("{}{labels}{generic_text}", self.review.render_text());
        Ok(PreparedPositiveSplitClaim {
            prepared,
            review: text,
        })
    }
}

/// Second immutable stage; the generic renderer and all canonical bytes stay unchanged.
pub struct PreparedPositiveSplitClaim<'a> {
    prepared: PreparedFeeClaim<'a>,
    review: String,
}
impl PreparedPositiveSplitClaim<'_> {
    /// Exact historical claimant frame, independently reconstructed by the SDK.
    #[must_use]
    pub fn signable_frame(&self) -> &[u8] {
        self.prepared.signable_frame()
    }
    /// Complete bounded recognized meaning AND the unchanged non-authorizing review.
    #[must_use]
    pub fn review_text(&self) -> &str {
        &self.review
    }
    /// Accepts only a signature for this retained outer frame/historical identity.
    pub fn finalize(self, signature: Vec<u8>) -> Result<Vec<u8>, PositiveSplitError> {
        self.prepared
            .finalize(signature)
            .map_err(|_| PositiveSplitError::Canonical)
    }
}

#[cfg(test)]
mod tests;
