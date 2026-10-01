//! The canonical domain-separated DR-0153 authority anchor,
//! [`OrderedEconomicsPolicy`]/[`OrderedEconomicsEnvironment`], the
//! [`Ed25519ConsensusVerifier`] glue adapter, and the pure
//! [`authenticate_candidate`] check.
//!
//! "Pure" here is load-bearing: every check below is decided from the
//! candidate's own canonical bytes plus the already-loaded pinned
//! policy/resolver/leg-policy, with zero storage reads, no clock and no
//! identity allocation. That is what lets
//! [`super::OrderedEconomicsError::Unauthenticated`] be a deterministic
//! retained rejection rather than a stop.
use super::*;
use bond_lifecycle::slash::decode_slash_intent;
use bond_lifecycle::{
    BondLifecycleOperation, SignedBondLifecycleIntent, bond_lifecycle_intent_digest,
    bond_lifecycle_signing_frame, decode_signed_bond_lifecycle_intent,
};
use canonical_encoding::encode_digest32;
use consensus::{
    ChainedHotStuff, ConsensusError, ConsensusParameters, ConsensusVerifier,
    FrozenFrontierCertifier, verify_frozen_frontier_quorum,
};
use crypto::{
    Ed25519OwnerAddressPolicy, Ed25519Verifier, SignatureVerifier, validate_ed25519_owner_address,
};
use execution::local_execution::{
    AuthenticatedLocalExecutionIntent, LocalContractEngine, LocalExecutionPolicy,
    authenticate_local_execution,
};
use execution::publication::{PublicationContext, encode_publication_context};
use fee_claims::codec::{FeeClaimOperation, SignedFeeClaimIntent, decode_signed_fee_claim_intent};
use fee_claims::{fee_claim_intent_digest, fee_claim_signing_frame};
use genesis::{GenesisManifest, genesis_manifest_commitment, genesis_manifest_signing_frame};
use protocol_types::{SignatureSchemeId, ValidatorId};
use validator_set::{ValidatorInfo, ValidatorSet};

/// Searched-for frame identifier of the canonical DR-0153 authority-anchor
/// preimage. Distinct from every other allocated `0x64xx` identifier; this
/// frame is never persisted or transported, only hashed.
pub const ORDERED_ECONOMICS_ANCHOR_FRAME_TYPE: u16 = 0x6441;
const ANCHOR_ENCODING_VERSION: u16 = 1;
const HANDOFF_ANCHOR_ENCODING_VERSION: u16 = 2;

/// Fixed logical-domain label separating this anchor from any other digest
/// that might one day be derived over the same fields.
const ANCHOR_DOMAIN_LABEL: &[u8] = b"se/ordered-economics/anchor/v1";
const HANDOFF_ANCHOR_DOMAIN_LABEL: &[u8] = b"se/ordered-economics/anchor/v2";

/// Derives the canonical consensus genesis anchor DR-0153 requires: a
/// domain-separated digest binding the logical ordered-economics domain, the
/// chain/protocol/epoch replay boundary, the atomicity domain, the
/// independently pinned signed-genesis digest, the exact active
/// validator-set identity, the fixed [`ConsensusParameters::genesis`] and,
/// for a handoff-capable signed genesis, its positive Freeze height.
///
/// The raw genesis-manifest digest alone is deliberately *not* the anchor: it
/// binds none of the consensus identity, so two profiles differing only in
/// validator set, epoch or parameters would otherwise share a genesis block
/// and accept one another's certificates.
///
/// This is the one production constructor. SDK, operator and tests must all
/// derive the anchor through it (or through
/// [`OrderedEconomicsPolicy::new`], which calls it) so no caller can select
/// alternative parameters locally.
pub fn ordered_economics_authority_anchor(
    resolver: &HashSuiteResolver,
    context: &PublicationContext,
    domain: AtomicityDomainId,
    genesis_digest: Digest32,
    minimum_freeze_block_height: u64,
    validator_set: &ValidatorSet,
) -> Result<Digest32, OrderedEconomicsError> {
    if resolver.chain_id() != context.chain_id()
        || resolver.protocol_version() != context.protocol_version()
    {
        return Err(OrderedEconomicsError::Policy(
            "ordered economics anchor resolver does not match the pinned context",
        ));
    }
    if validator_set.epoch() != context.epoch() {
        return Err(OrderedEconomicsError::Policy(
            "ordered economics anchor validator set is not the pinned epoch",
        ));
    }
    let parameters: ConsensusParameters = ConsensusParameters::genesis();
    let set_digest: Digest32 = validator_set.digest(resolver).map_err(|_| {
        OrderedEconomicsError::Policy("ordered economics anchor validator set identity")
    })?;
    let handoff_capable: bool = minimum_freeze_block_height != 0;
    let mut frame: CanonicalStruct = CanonicalStruct::new(
        ORDERED_ECONOMICS_ANCHOR_FRAME_TYPE,
        if handoff_capable {
            HANDOFF_ANCHOR_ENCODING_VERSION
        } else {
            ANCHOR_ENCODING_VERSION
        },
    );
    frame.field_bytes(
        1,
        if handoff_capable {
            HANDOFF_ANCHOR_DOMAIN_LABEL.to_vec()
        } else {
            ANCHOR_DOMAIN_LABEL.to_vec()
        },
    )?;
    frame.field_bytes(
        2,
        encode_publication_context(context)
            .map_err(|_| OrderedEconomicsError::Policy("ordered economics anchor context"))?,
    )?;
    frame.field_bytes(3, domain.as_bytes().to_vec())?;
    frame.field_bytes(4, encode_digest32(&genesis_digest)?)?;
    frame.field_bytes(5, encode_digest32(&set_digest)?)?;
    frame.field_u16(6, parameters.protocol.as_u16())?;
    frame.field_u32(7, parameters.max_block_transactions)?;
    frame.field_u64(8, parameters.view_timeout_millis)?;
    if handoff_capable {
        frame.field_u64(9, minimum_freeze_block_height)?;
    }
    let preimage: Vec<u8> = frame.finish()?;
    Ok(resolver.hash_for_purpose(context.epoch(), HashPurpose::ProtocolConfig, &preimage)?)
}

/// Fixed-epoch anchor for one closed DR-0153 profile: pins the exact existing
/// consensus engine, chain/protocol/epoch replay boundary, atomicity domain
/// and independently pinned genesis digest every ordered-economics operation
/// must match. Historical cross-epoch workflows stay out of scope for this
/// profile.
#[derive(Clone)]
pub struct OrderedEconomicsPolicy {
    context: PublicationContext,
    domain: AtomicityDomainId,
    genesis_digest: Digest32,
    minimum_freeze_block_height: u64,
    anchor: Digest32,
    engine: ChainedHotStuff,
    resolver: HashSuiteResolver,
}

impl OrderedEconomicsPolicy {
    /// Creates the canonical anchor for one fixed-epoch profile and the
    /// existing [`ConsensusParameters::genesis`] engine around it. A supplied
    /// signed genesis manifest must match the independently pinned digest,
    /// context and initial validator set; only that path enables Freeze.
    /// `None` preserves the historical fixed-epoch profile but cannot Freeze.
    pub fn new(
        context: PublicationContext,
        domain: AtomicityDomainId,
        genesis_digest: Digest32,
        genesis_manifest: Option<&GenesisManifest>,
        validator_set: ValidatorSet,
        resolver: HashSuiteResolver,
    ) -> Result<Self, OrderedEconomicsError> {
        let minimum_freeze_block_height: u64 = match genesis_manifest {
            Some(manifest) => {
                if manifest.context() != &context || manifest.validator_set.context != context {
                    return Err(OrderedEconomicsError::Policy(
                        "signed genesis manifest does not match ordered context",
                    ));
                }
                let derived_digest: Digest32 = genesis_manifest_commitment(&resolver, manifest)
                    .map_err(|_| {
                        OrderedEconomicsError::Policy(
                            "signed genesis manifest commitment is invalid",
                        )
                    })?;
                if derived_digest != genesis_digest {
                    return Err(OrderedEconomicsError::Policy(
                        "signed genesis manifest does not match the pinned digest",
                    ));
                }
                let frame: Vec<u8> = genesis_manifest_signing_frame(manifest).map_err(|_| {
                    OrderedEconomicsError::Policy("signed genesis manifest frame is invalid")
                })?;
                let verifier: Ed25519Verifier =
                    Ed25519Verifier::from_verifying_key_bytes(&manifest.genesis_authority)
                        .map_err(|_| {
                            OrderedEconomicsError::Policy(
                                "signed genesis manifest authority is invalid",
                            )
                        })?;
                if !verifier
                    .verify_framed(&frame, &manifest.signature)
                    .map_err(|_| {
                        OrderedEconomicsError::Policy("signed genesis manifest verification failed")
                    })?
                {
                    return Err(OrderedEconomicsError::Policy(
                        "signed genesis manifest signature is invalid",
                    ));
                }
                let signed_members: Vec<ValidatorInfo> = manifest
                    .validator_set
                    .validators
                    .iter()
                    .map(|entry| ValidatorInfo {
                        id: entry.id,
                        voting_power: entry.voting_power,
                        signature_scheme: entry.signature_scheme,
                        public_key: entry.public_key.clone(),
                    })
                    .collect();
                let signed_set: ValidatorSet = ValidatorSet::new(context.epoch(), signed_members)
                    .map_err(|_| {
                    OrderedEconomicsError::Policy("signed genesis validator set is invalid")
                })?;
                if signed_set.validators() != validator_set.validators() {
                    return Err(OrderedEconomicsError::Policy(
                        "ordered validator set disagrees with signed genesis",
                    ));
                }
                manifest.minimum_freeze_block_height
            }
            None => 0,
        };
        let anchor: Digest32 = ordered_economics_authority_anchor(
            &resolver,
            &context,
            domain,
            genesis_digest,
            minimum_freeze_block_height,
            &validator_set,
        )?;
        let engine: ChainedHotStuff = ChainedHotStuff::new(
            context.chain_id().clone(),
            context.protocol_version(),
            context.epoch(),
            validator_set,
            ConsensusParameters::genesis(),
            resolver.clone(),
            anchor,
        )
        .map_err(policy_error)?;
        Ok(Self {
            context,
            domain,
            genesis_digest,
            minimum_freeze_block_height,
            anchor,
            engine,
            resolver,
        })
    }

    /// Returns the pinned existing consensus engine instance.
    #[must_use]
    pub const fn engine(&self) -> &ChainedHotStuff {
        &self.engine
    }

    /// Returns the fixed chain/protocol/epoch replay boundary.
    #[must_use]
    pub const fn context(&self) -> &PublicationContext {
        &self.context
    }

    /// Returns the logical atomicity domain ordered economics writes into.
    #[must_use]
    pub const fn domain(&self) -> AtomicityDomainId {
        self.domain
    }

    /// Returns the independently pinned signed genesis manifest digest.
    #[must_use]
    pub const fn genesis_digest(&self) -> Digest32 {
        self.genesis_digest
    }

    /// Minimum proposal height authorized by the signed genesis schedule.
    /// Zero denotes a historical manifest and disables Freeze entirely.
    #[must_use]
    pub const fn minimum_freeze_block_height(&self) -> u64 {
        self.minimum_freeze_block_height
    }

    /// Returns the derived canonical consensus genesis anchor actually used
    /// as this engine's genesis block.
    #[must_use]
    pub const fn anchor(&self) -> Digest32 {
        self.anchor
    }

    /// Returns the registered authority for `validator_id` in the pinned
    /// active set, or `None` when it is not a member. Zero storage I/O: the
    /// set is already loaded into [`Self::engine`].
    #[must_use]
    pub fn registered_validator(&self, validator_id: ValidatorId) -> Option<&ValidatorInfo> {
        self.engine.validator_set().get(validator_id)
    }

    /// Pure authentication under the fixed profile, without a VM, store or clock.
    pub fn authenticate_candidate(
        &self,
        candidate: &OrderedCandidate,
    ) -> Result<(), OrderedEconomicsError> {
        let leg_policy: LocalExecutionPolicy =
            LocalExecutionPolicy::generic_object_results(self.context.clone());
        let authentication: CandidateAuthentication<'_> = CandidateAuthentication {
            policy: self,
            resolver: &self.resolver,
            leg_policy: &leg_policy,
        };
        authenticate_with_policy(&authentication, candidate)
    }

    /// Digest of the exact production candidate frame, using its signed epoch.
    pub fn candidate_digest(
        &self,
        candidate: &OrderedCandidate,
    ) -> Result<Digest32, OrderedEconomicsError> {
        let bytes: Vec<u8> = encode_ordered_candidate(candidate)?;
        super::engine::candidate_digest(&self.resolver, candidate.context.epoch(), &bytes)
    }

    pub(super) fn history_component_digest(
        &self,
        bytes: &[u8],
    ) -> Result<Digest32, OrderedEconomicsError> {
        Ok(self
            .resolver
            .hash_for_purpose(self.context.epoch(), HashPurpose::NodeEvent, bytes)?)
    }
}

struct CandidateAuthentication<'a> {
    policy: &'a OrderedEconomicsPolicy,
    resolver: &'a HashSuiteResolver,
    leg_policy: &'a LocalExecutionPolicy,
}

fn policy_error(_error: ConsensusError) -> OrderedEconomicsError {
    OrderedEconomicsError::Policy("ordered economics policy does not match consensus authority")
}

/// Every dependency one ordered-economics invocation needs, borrowed for its
/// duration. All fields are public per the `node_core::ordered_economics`
/// contract; this type grants no authority beyond what each field already
/// carries.
pub struct OrderedEconomicsEnvironment<'a> {
    /// Fixed-epoch policy anchor.
    pub policy: &'a OrderedEconomicsPolicy,
    /// Active hash suite resolver.
    pub resolver: &'a HashSuiteResolver,
    /// Historical resolvers for bounded backward-compatible verification.
    pub history: &'a [HashSuiteResolver],
    /// Local execution admission/authentication policy.
    pub leg_policy: &'a LocalExecutionPolicy,
    /// Local contract execution engine.
    pub engine: &'a dyn LocalContractEngine,
    /// Blob store backing large object bodies.
    pub blobs: &'a dyn BlobStore,
}

/// Adapts the existing [`crypto::Ed25519Verifier`]/[`SignatureVerifier`] to
/// [`consensus::ConsensusVerifier`]. Holds no state and duplicates no
/// algorithm: it only routes an already-framed message/signature/public-key
/// triple to the one existing Ed25519 verifier, rejecting every other
/// signature scheme up front (this fixed profile registers only Ed25519
/// validators, exactly like [`crate::fast_path`]'s own validator-set
/// installation).
pub(crate) struct Ed25519ConsensusVerifier;

impl ConsensusVerifier for Ed25519ConsensusVerifier {
    fn verify_framed(
        &self,
        _validator: ValidatorId,
        scheme: SignatureSchemeId,
        public_key: &[u8],
        framed: &[u8],
        signature: &[u8],
    ) -> Result<bool, String> {
        if scheme != SignatureSchemeId::Ed25519 {
            return Ok(false);
        }
        let verifier = Ed25519Verifier::from_verifying_key_bytes(public_key)
            .map_err(|error| error.to_string())?;
        verifier
            .verify_framed(framed, signature)
            .map_err(|error| error.to_string())
    }
}

/// Returns the trusted registered Ed25519 verifying key for `validator_id`.
///
/// This fixed-epoch profile pins exactly one validator set, so an envelope's
/// outer signature is fully verifiable *purely*: there is no need to read a
/// committed row first to learn which key to trust. The committed row's own
/// authorization key is still checked by the existing handler, and
/// [`super::preflight`] separately requires it to still agree with this
/// trusted authority before any fresh work.
fn trusted_registered_key<'a>(
    env: &'a CandidateAuthentication<'a>,
    validator_id: ValidatorId,
) -> Result<&'a [u8], OrderedEconomicsError> {
    let info: &ValidatorInfo = env.policy.registered_validator(validator_id).ok_or(
        OrderedEconomicsError::Unauthenticated(
            "ordered candidate names a validator outside the pinned validator set",
        ),
    )?;
    if info.signature_scheme != SignatureSchemeId::Ed25519 {
        return Err(OrderedEconomicsError::Unauthenticated(
            "ordered candidate validator is not registered for Ed25519",
        ));
    }
    Ok(info.public_key.as_slice())
}

/// Verifies one already domain-framed outer envelope signature against the
/// trusted registered key, purely.
fn verify_outer_signature(
    public_key: &[u8],
    framed: &[u8],
    signature: &[u8; 64],
    message: &'static str,
) -> Result<(), OrderedEconomicsError> {
    let verifier: Ed25519Verifier = Ed25519Verifier::from_verifying_key_bytes(public_key)
        .map_err(|_| OrderedEconomicsError::Unauthenticated(message))?;
    if !verifier
        .verify_framed(framed, signature.as_slice())
        .map_err(|_| OrderedEconomicsError::Unauthenticated(message))?
    {
        return Err(OrderedEconomicsError::Unauthenticated(message));
    }
    Ok(())
}

/// Requires a signed payout/release recipient to be a canonical prime-order
/// Ed25519 owner address.
///
/// This is a *pure* property of the signed envelope, so it belongs here rather
/// than deep inside the handler: decided during authentication it is a
/// deterministic retained rejection every replica agrees on, whereas raised
/// only at execution it would look like an unknown handler failure and stop
/// the applied prefix, letting one malformed-but-signed envelope wedge a
/// whole three-chain window.
fn require_owner_address(
    recipient: &objects::Address,
    message: &'static str,
) -> Result<(), OrderedEconomicsError> {
    validate_ed25519_owner_address(
        recipient.as_bytes(),
        Ed25519OwnerAddressPolicy::CanonicalPrimeOrder,
    )
    .map_err(|_| OrderedEconomicsError::Unauthenticated(message))
}

/// Authenticates one embedded local-execution leg's own Ed25519 signature
/// (self-verifying against the sender address it declares) and its declared
/// replay identity, purely, with no clock or storage read.
fn authenticate_leg(
    env: &CandidateAuthentication<'_>,
    candidate: &OrderedCandidate,
    leg: &[u8],
) -> Result<AuthenticatedLocalExecutionIntent, OrderedEconomicsError> {
    let authenticated: AuthenticatedLocalExecutionIntent =
        authenticate_local_execution(env.resolver, env.leg_policy, leg).map_err(|_| {
            OrderedEconomicsError::Unauthenticated("invalid ordered candidate leg signature")
        })?;
    let call = &authenticated.intent().call;
    if call.request_id != candidate.request_id {
        return Err(OrderedEconomicsError::Unauthenticated(
            "ordered candidate leg request id does not equal the candidate's own",
        ));
    }
    if call.context != candidate.context {
        return Err(OrderedEconomicsError::Unauthenticated(
            "ordered candidate leg context does not equal the candidate's own",
        ));
    }
    Ok(authenticated)
}

/// Returns every leg embedded in one bond-lifecycle operation, in the exact
/// order [`bond_lifecycle::handle_bond_lifecycle`] itself authenticates them.
pub(crate) fn bond_lifecycle_legs(operation: &BondLifecycleOperation) -> Vec<&[u8]> {
    match operation {
        BondLifecycleOperation::Deposit { leg }
        | BondLifecycleOperation::Withdraw { leg }
        | BondLifecycleOperation::Reactivate { leg } => vec![leg.as_slice()],
        BondLifecycleOperation::Replace {
            deposit_leg,
            release_leg,
            ..
        } => vec![deposit_leg.as_slice(), release_leg.as_slice()],
        BondLifecycleOperation::Unbond { .. } => Vec::new(),
    }
}

/// Pure authentication: decodes `candidate.intent` per `candidate.kind` using
/// the exact existing decoder that kind's handler already uses, then verifies
///
/// * the candidate's own context against the pinned profile,
/// * the embedded envelope's declared context and request identity,
/// * the outer envelope signature against the pinned *registered* validator
///   key (for [`OrderedOperationKind::FeeClaim`] this additionally requires
///   the signed certificate epoch to equal the pinned profile epoch, so the
///   historical key the handler will use is the pinned one),
/// * every embedded local-execution leg's own signature, request id and
///   context, and
/// * for evidence, the complete cryptographic proof against the pinned set,
///
/// all before any clock or storage read. [`OrderedOperationKind::BondSlash`]
/// carries no outer signature by construction: DR-0137 authorizes it by its
/// validly signed forfeiture leg plus independently re-verified committed
/// evidence at execution, so this function authenticates exactly those parts
/// it can prove purely and does not pretend an outer signature exists.
pub fn authenticate_candidate(
    env: &OrderedEconomicsEnvironment<'_>,
    candidate: &OrderedCandidate,
) -> Result<(), OrderedEconomicsError> {
    let authentication: CandidateAuthentication<'_> = CandidateAuthentication {
        policy: env.policy,
        resolver: env.resolver,
        leg_policy: env.leg_policy,
    };
    authenticate_with_policy(&authentication, candidate)
}

fn authenticate_with_policy(
    env: &CandidateAuthentication<'_>,
    candidate: &OrderedCandidate,
) -> Result<(), OrderedEconomicsError> {
    if candidate.context != *env.policy.context() {
        return Err(OrderedEconomicsError::Unauthenticated(
            "ordered candidate context does not match the pinned policy",
        ));
    }
    // The canonical candidate bytes must round-trip exactly: a caller that
    // built this value in memory has not yet proven it encodes canonically,
    // and its digest is what the shared order will name.
    let encoded: Vec<u8> = encode_ordered_candidate(candidate)
        .map_err(|_| OrderedEconomicsError::Unauthenticated("noncanonical ordered candidate"))?;
    match decode_ordered_candidate(&encoded) {
        Ok(round_tripped) if round_tripped == *candidate => {}
        _ => {
            return Err(OrderedEconomicsError::Unauthenticated(
                "noncanonical ordered candidate",
            ));
        }
    }
    match candidate.kind {
        OrderedOperationKind::FeeClaim => authenticate_fee_claim(env, candidate),
        OrderedOperationKind::BondLifecycle => authenticate_bond_lifecycle(env, candidate),
        OrderedOperationKind::BondSlash => authenticate_bond_slash(env, candidate),
        OrderedOperationKind::Evidence => authenticate_evidence(env, candidate),
        OrderedOperationKind::Freeze => authenticate_freeze(env, candidate),
        OrderedOperationKind::DrainSet => authenticate_drain_set(env, candidate),
    }
}

/// Purely validates the Freeze candidate's own bytes. The signed-genesis
/// height and committed next-set state are checked separately before honest
/// proposal/vote and again when the ordered block executes.
fn authenticate_freeze(
    env: &CandidateAuthentication<'_>,
    candidate: &OrderedCandidate,
) -> Result<(), OrderedEconomicsError> {
    if env.policy.minimum_freeze_block_height() == 0 {
        return Err(OrderedEconomicsError::Unauthenticated(
            "freeze is not enabled by the signed genesis profile",
        ));
    }
    let intent = super::freeze::decode_freeze_intent(&candidate.intent)
        .map_err(|_| OrderedEconomicsError::Unauthenticated("invalid freeze candidate intent"))?;
    if intent.context != candidate.context || intent.request_id != candidate.request_id {
        return Err(OrderedEconomicsError::Unauthenticated(
            "freeze candidate context or request id mismatch",
        ));
    }
    Ok(())
}

/// Purely validates the DrainSet candidate's own bytes: its structural
/// self-consistency (checked by [`super::drain_set::decode_drain_set_intent`]
/// itself), its binding to the candidate's own context/request id, and the
/// pinned outgoing quorum's own signatures and voting power over
/// `intent.selected_votes` -- with zero storage reads. Every registered
/// signer's key and voting power come from the pinned profile's own loaded
/// [`validator_set::ValidatorSet`], never a storage read; this is exactly why
/// [`FrozenFrontierCertifier`] and [`verify_frozen_frontier_quorum`] are
/// stateless.
///
/// Whether this replica's own local drain-union reconstruction actually
/// matches `intent.drain_union_identity` -- and whether `intent`'s declared
/// committed-Freeze binding matches the *actually* committed one -- can only
/// be proven through durable storage; see
/// [`super::drain_set::require_drain_set_readiness`] and
/// [`super::drain_set::preflight_drain_set`].
fn authenticate_drain_set(
    env: &CandidateAuthentication<'_>,
    candidate: &OrderedCandidate,
) -> Result<(), OrderedEconomicsError> {
    let intent = super::drain_set::decode_drain_set_intent(&candidate.intent).map_err(|_| {
        OrderedEconomicsError::Unauthenticated("invalid drain set candidate intent")
    })?;
    if intent.context != candidate.context || intent.request_id != candidate.request_id {
        return Err(OrderedEconomicsError::Unauthenticated(
            "drain set candidate context or request id mismatch",
        ));
    }
    let identity = &intent.drain_union_identity;
    let certifier: FrozenFrontierCertifier = FrozenFrontierCertifier::new(
        env.policy.context().chain_id().clone(),
        env.policy.context().protocol_version(),
        env.policy.context().epoch(),
        env.policy.engine().validator_set().clone(),
    )
    .map_err(|_| OrderedEconomicsError::Unauthenticated("drain set certifier context"))?;
    verify_frozen_frontier_quorum(
        &certifier,
        &intent.selected_votes,
        env.policy.domain(),
        identity.closure_request_id,
        identity.closure_height,
        &Ed25519ConsensusVerifier,
    )
    .map_err(|_| OrderedEconomicsError::Unauthenticated("drain set frontier quorum"))?;
    // Authentication must also prove that the immutable record this
    // candidate would install can be encoded within the same frame ceiling.
    // Otherwise a future wider signature scheme could pass the intent bound
    // yet wedge committed execution on an oversized record.
    let first_possible_height: u64 =
        identity
            .closure_height
            .checked_add(1)
            .ok_or(OrderedEconomicsError::Unauthenticated(
                "drain set closure height overflow",
            ))?;
    let record: super::drain_set::DrainSetRecord = super::drain_set::DrainSetRecord {
        closed_epoch: candidate.context.epoch(),
        request_id: candidate.request_id,
        committed_at_block_height: first_possible_height,
        drain_union_identity: identity.clone(),
        selected_votes: intent.selected_votes.clone(),
    };
    super::drain_set::encode_drain_set_record(&record).map_err(|_| {
        OrderedEconomicsError::Unauthenticated("drain set record cannot be encoded")
    })?;
    Ok(())
}

fn authenticate_fee_claim(
    env: &CandidateAuthentication<'_>,
    candidate: &OrderedCandidate,
) -> Result<(), OrderedEconomicsError> {
    let signed: SignedFeeClaimIntent =
        decode_signed_fee_claim_intent(&candidate.intent).map_err(|_| {
            OrderedEconomicsError::Unauthenticated("invalid fee claim candidate intent")
        })?;
    if signed.intent.context != candidate.context
        || signed.intent.request_id != candidate.request_id
    {
        return Err(OrderedEconomicsError::Unauthenticated(
            "fee claim candidate context or request id mismatch",
        ));
    }
    // This closed profile pins exactly one epoch/set, so the certificate
    // epoch whose historical key the handler will verify against must be the
    // pinned epoch. Without this, the outer signature would only be
    // verifiable against a historical key no longer pinned here.
    if signed.intent.certificate_epoch != env.policy.context().epoch() {
        return Err(OrderedEconomicsError::Unauthenticated(
            "fee claim certificate epoch is not the pinned profile epoch",
        ));
    }
    let public_key: Vec<u8> = trusted_registered_key(env, signed.intent.validator_id)?.to_vec();
    let intent_digest: Digest32 = fee_claim_intent_digest(env.resolver, &signed.intent)
        .map_err(|_| OrderedEconomicsError::Unauthenticated("fee claim intent digest"))?;
    let framed: Vec<u8> = fee_claim_signing_frame(&signed.intent.context, intent_digest)
        .map_err(|_| OrderedEconomicsError::Unauthenticated("fee claim signing frame"))?;
    verify_outer_signature(
        &public_key,
        &framed,
        &signed.signature,
        "fee claim candidate envelope signature",
    )?;
    match &signed.intent.operation {
        FeeClaimOperation::ZeroShare => {
            if signed.intent.share_amount != 0 {
                return Err(OrderedEconomicsError::Unauthenticated(
                    "zero-share fee claim declares a positive share amount",
                ));
            }
        }
        FeeClaimOperation::Split {
            leg,
            expected_payout,
        } => {
            // A v1 split that never signed its own payout reference can never
            // be proven: purely decidable, so refuse rather than stop.
            if expected_payout.is_none() {
                return Err(OrderedEconomicsError::Unauthenticated(
                    "fee claim split does not sign its own payout reference",
                ));
            }
            require_owner_address(
                &signed.intent.recipient,
                "fee claim recipient is not a canonical Ed25519 owner address",
            )?;
            authenticate_leg(env, candidate, leg)?;
        }
        FeeClaimOperation::FinalTransfer { leg } => {
            require_owner_address(
                &signed.intent.recipient,
                "fee claim recipient is not a canonical Ed25519 owner address",
            )?;
            authenticate_leg(env, candidate, leg)?;
        }
    }
    Ok(())
}

fn authenticate_bond_lifecycle(
    env: &CandidateAuthentication<'_>,
    candidate: &OrderedCandidate,
) -> Result<(), OrderedEconomicsError> {
    let signed: SignedBondLifecycleIntent = decode_signed_bond_lifecycle_intent(&candidate.intent)
        .map_err(|_| {
            OrderedEconomicsError::Unauthenticated("invalid bond lifecycle candidate intent")
        })?;
    if signed.intent.context != candidate.context
        || signed.intent.request_id != candidate.request_id
    {
        return Err(OrderedEconomicsError::Unauthenticated(
            "bond lifecycle candidate context or request id mismatch",
        ));
    }
    let public_key: Vec<u8> = trusted_registered_key(env, signed.intent.validator_id)?.to_vec();
    let intent_digest: Digest32 = bond_lifecycle_intent_digest(env.resolver, &signed.intent)
        .map_err(|_| OrderedEconomicsError::Unauthenticated("bond lifecycle intent digest"))?;
    let framed: Vec<u8> = bond_lifecycle_signing_frame(&signed.intent.context, intent_digest)
        .map_err(|_| OrderedEconomicsError::Unauthenticated("bond lifecycle signing frame"))?;
    verify_outer_signature(
        &public_key,
        &framed,
        &signed.signature,
        "bond lifecycle candidate envelope signature",
    )?;
    // Purely decidable envelope shape checks. Raising them here makes a
    // malformed-but-signed operation a deterministic retained rejection
    // instead of an unknown handler failure that would stop the prefix.
    match &signed.intent.operation {
        BondLifecycleOperation::Unbond { recipient } => require_owner_address(
            recipient,
            "bond unbond recipient is not a canonical Ed25519 owner address",
        )?,
        BondLifecycleOperation::Replace {
            release_recipient, ..
        } => require_owner_address(
            release_recipient,
            "bond replace release recipient is not a canonical Ed25519 owner address",
        )?,
        BondLifecycleOperation::Deposit { .. }
        | BondLifecycleOperation::Withdraw { .. }
        | BondLifecycleOperation::Reactivate { .. } => {}
    }
    for leg in bond_lifecycle_legs(&signed.intent.operation) {
        authenticate_leg(env, candidate, leg)?;
    }
    // `Replace`'s two legs must share one sender and consecutive nonces --
    // also purely decidable from the signed bytes alone.
    if let BondLifecycleOperation::Replace {
        deposit_leg,
        release_leg,
        ..
    } = &signed.intent.operation
    {
        let deposit = authenticate_leg(env, candidate, deposit_leg)?;
        let release = authenticate_leg(env, candidate, release_leg)?;
        let deposit_call = &deposit.intent().call;
        let release_call = &release.intent().call;
        if deposit_call.sender != release_call.sender
            || deposit_call.nonce.checked_add(1) != Some(release_call.nonce)
        {
            return Err(OrderedEconomicsError::Unauthenticated(
                "bond replace legs require one sender and consecutive nonces",
            ));
        }
    }
    Ok(())
}

fn authenticate_bond_slash(
    env: &CandidateAuthentication<'_>,
    candidate: &OrderedCandidate,
) -> Result<(), OrderedEconomicsError> {
    let intent = decode_slash_intent(&candidate.intent).map_err(|_| {
        OrderedEconomicsError::Unauthenticated("invalid bond slash candidate intent")
    })?;
    if intent.context != candidate.context || intent.request_id != candidate.request_id {
        return Err(OrderedEconomicsError::Unauthenticated(
            "bond slash candidate context or request id mismatch",
        ));
    }
    // Fixed-epoch profile: evidence is only ever accepted, and only ever
    // slashable, against the pinned epoch/set.
    if intent.evidence_epoch != env.policy.context().epoch() {
        return Err(OrderedEconomicsError::Unauthenticated(
            "bond slash evidence epoch is not the pinned profile epoch",
        ));
    }
    trusted_registered_key(env, intent.validator_id)?;
    // DR-0137 requires exactly this policy for the forfeiture leg, so that
    // restart can independently reconstruct it from the retained transition
    // context alone. Checking it here keeps the failure pure.
    if *env.leg_policy != LocalExecutionPolicy::generic_object_results(intent.context.clone()) {
        return Err(OrderedEconomicsError::Unauthenticated(
            "bond slash leg policy is not the restart-reconstructible policy",
        ));
    }
    authenticate_leg(env, candidate, &intent.leg)?;
    Ok(())
}

fn authenticate_evidence(
    env: &CandidateAuthentication<'_>,
    candidate: &OrderedCandidate,
) -> Result<(), OrderedEconomicsError> {
    let submission = super::evidence_submission::decode_ordered_evidence_submission(
        &candidate.intent,
    )
    .map_err(|_| OrderedEconomicsError::Unauthenticated("invalid evidence candidate intent"))?;
    let evidence = super::evidence_submission::build_decoded_evidence(
        &submission,
        env.policy.context().chain_id(),
        env.policy.context().protocol_version(),
    )?;
    if evidence.epoch() != env.policy.context().epoch() {
        return Err(OrderedEconomicsError::Unauthenticated(
            "evidence candidate epoch/set is not the pinned profile",
        ));
    }
    trusted_registered_key(env, evidence.validator())?;
    verify_evidence_proof(env, &evidence)
}

/// Verifies one decoded equivocation-evidence envelope's complete
/// cryptographic proof (both signed statements, plus class (b)'s independent
/// object-conflict re-derivation) against the pinned validator set, purely.
fn verify_evidence_proof(
    env: &CandidateAuthentication<'_>,
    evidence: &equivocation::DecodedEquivocationEvidence,
) -> Result<(), OrderedEconomicsError> {
    let validator_set: ValidatorSet = env.policy.engine().validator_set().clone();
    let result = match evidence {
        equivocation::DecodedEquivocationEvidence::FastVote(inner) => {
            consensus::verify_fast_vote_equivocation_evidence(
                inner,
                validator_set,
                &Ed25519ConsensusVerifier,
            )
        }
        equivocation::DecodedEquivocationEvidence::ObjectConflict(inner) => {
            consensus::verify_fast_vote_object_conflict_evidence(
                inner,
                validator_set,
                &Ed25519ConsensusVerifier,
            )
        }
        equivocation::DecodedEquivocationEvidence::EpochTransition(inner) => {
            consensus::verify_epoch_transition_equivocation_evidence(
                inner,
                validator_set,
                &Ed25519ConsensusVerifier,
            )
        }
    };
    result.map_err(|_| OrderedEconomicsError::Unauthenticated("invalid evidence candidate proof"))
}
