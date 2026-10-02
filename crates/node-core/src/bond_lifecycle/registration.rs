//! DR-0179's self-authenticated, ordered-only initial bond registration.
//!
//! Preparation and codecs expose claims, never a mutation permit. Only the
//! private committed ordered dispatcher may install a generation-one bond.
use super::*;
use crate::admission_profile::{
    ExternalRequestLane, VerifiedAdmissionProfile, require_external_request_lane,
};
use crate::genesis::GenesisManifest;
use crypto::{Ed25519OwnerAddressPolicy, validate_ed25519_owner_address};

pub use bonds::BondResourceId;
pub use codec::{
    decode_bond_registration_anchor, decode_bond_registration_intent,
    decode_signed_bond_registration_intent, encode_bond_registration_anchor,
    encode_bond_registration_intent, encode_signed_bond_registration_intent,
};
pub use handler::verify_registered_bond_chain;
pub(crate) use handler::{handle_bond_registration_ordered, preflight_registration};

mod codec;
mod handler;
#[cfg(test)]
mod tests;

/// Maximum exact signed registration envelope (one bounded execution leg).
pub const MAX_BOND_REGISTRATION_BYTES: usize = MAX_LOCAL_EXECUTION_INTENT_BYTES + 4_096;
/// Existing owning bound for one canonical resulting bond row.
pub const MAX_BOND_REGISTRATION_ROW_BYTES: usize =
    crate::fast_path::records::MAX_BOND_TRANSITION_ROW_BYTES;
/// Maximum exact anchor, including the envelope and generation-one row.
pub const MAX_BOND_REGISTRATION_ANCHOR_BYTES: usize =
    MAX_BOND_REGISTRATION_BYTES + MAX_BOND_REGISTRATION_ROW_BYTES + 4_096;

/// Deterministic caller-invalid results against healthy admitted inputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BondRegistrationRefusal {
    /// A fully verified registration already roots this identity.
    AlreadyRegistered,
    /// The admitted generic contract reported a trap.
    Trapped,
    /// The execution produced effects outside the exact custody transfer.
    ForbiddenEffects,
    /// Nominal value is not a conserved positive u64.
    InvalidAmount,
    /// Amount or enabled policy does not satisfy the committed minimum.
    BelowMinimum,
    /// Amount exceeds the committed maximum exposure.
    AboveMaximum,
    /// Actual generation-one row differs from the signer's pinned digest.
    InitialRowMismatch,
}

/// Closed registration error contract. Only `Refused` is business refusal;
/// missing/corrupt/fenced/ambiguous inputs and unclassified failures stop.
#[derive(Debug)]
pub enum BondRegistrationError {
    /// Pure canonical/signature/context validation failed.
    Invalid(&'static str),
    /// A required observation is missing, corrupt or inconsistent.
    Prerequisite(&'static str),
    /// Positively classified healthy-input business refusal.
    Refused(BondRegistrationRefusal),
    /// Shared durable boundary error, including fencing/ambiguity.
    Node(NodeCoreError),
    /// Shared admitted leg failure, not guessed business refusal.
    Admission(LocalExecutionAdmissionError),
    /// Shared deterministic executor/capability boundary failure.
    Execution(LocalExecutionError),
}
impl fmt::Display for BondRegistrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) | Self::Prerequisite(message) => f.write_str(message),
            Self::Refused(refusal) => write!(f, "bond registration refused: {refusal:?}"),
            Self::Node(error) => error.fmt(f),
            Self::Admission(error) => error.fmt(f),
            Self::Execution(error) => error.fmt(f),
        }
    }
}
impl Error for BondRegistrationError {}
impl From<NodeCoreError> for BondRegistrationError {
    fn from(error: NodeCoreError) -> Self {
        Self::Node(error)
    }
}
impl From<LocalExecutionAdmissionError> for BondRegistrationError {
    fn from(error: LocalExecutionAdmissionError) -> Self {
        Self::Admission(error)
    }
}
impl From<LocalExecutionError> for BondRegistrationError {
    fn from(error: LocalExecutionError) -> Self {
        Self::Execution(error)
    }
}
impl From<DurableReadError> for BondRegistrationError {
    fn from(error: DurableReadError) -> Self {
        Self::Node(error.into())
    }
}
impl From<RuntimeError> for BondRegistrationError {
    fn from(error: RuntimeError) -> Self {
        Self::Node(error.into())
    }
}
impl From<DurableInvocationError> for BondRegistrationError {
    fn from(error: DurableInvocationError) -> Self {
        Self::Node(error.into())
    }
}
impl From<CanonicalEncodingError> for BondRegistrationError {
    fn from(error: CanonicalEncodingError) -> Self {
        Self::Node(error.into())
    }
}
impl From<CanonicalDecodingError> for BondRegistrationError {
    fn from(error: CanonicalDecodingError) -> Self {
        Self::Node(error.into())
    }
}
impl From<HashingError> for BondRegistrationError {
    fn from(error: HashingError) -> Self {
        Self::Node(error.into())
    }
}
impl From<execution::publication::PublicationError> for BondRegistrationError {
    fn from(_error: execution::publication::PublicationError) -> Self {
        Self::Invalid("registration publication context framing")
    }
}

/// The exact independently signed generation-one claim (`0x64E0/v1`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BondRegistrationIntent {
    /// First outgoing causal-genesis operation context.
    pub context: PublicationContext,
    /// Nonzero external Ordered-lane identity, shared by the exact leg.
    pub request_id: [u8; 32],
    /// Must equal the exact canonical authorization key.
    pub validator_id: ValidatorId,
    /// Ed25519 only for this profile.
    pub authorization_scheme: SignatureSchemeId,
    /// Actual canonical prime-order Ed25519 authorization key.
    pub authorization_key: [u8; 32],
    /// Genesis-pinned defining resource context, never peer policy authority.
    pub resource_context: PublicationContext,
    /// Exact generic resource identity.
    pub resource: BondResourceId,
    /// Independently signed generic custody execution leg.
    pub leg: Vec<u8>,
    /// Existing ExecutionEffects digest of the predicted generation-one row.
    pub expected_initial_row_digest: Digest32,
    /// Independently configured signed-genesis identity.
    pub pinned_genesis_digest: Digest32,
}

/// Exact outer signature envelope (`0x64E1/v1`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedBondRegistrationIntent {
    /// Exact registration claim.
    pub intent: BondRegistrationIntent,
    /// Ed25519 signature by `intent.authorization_key` over its framed digest.
    pub signature: [u8; 64],
}

/// Immutable registered-chain root (`0x64E2/v1`), not execution proof alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BondRegistrationAnchor {
    /// Original operation context.
    pub context: PublicationContext,
    /// Natural key validator identity.
    pub validator_id: ValidatorId,
    /// Exact authenticated `0x64E1/v1` original envelope.
    pub signed_registration: Vec<u8>,
    /// Exact independently produced generation-one row.
    pub resulting_row: Vec<u8>,
}

/// Offline bounded preparation input. The predicted row remains an untrusted
/// claim until actual ordered execution reproduces it byte-exactly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BondRegistrationPreparationRequest {
    /// Trusted first-epoch context to compare against the local manifest.
    pub context: PublicationContext,
    /// Original Ordered request ID.
    pub request_id: [u8; 32],
    /// Derive from the same actual SigningKey that will sign the result.
    pub authorization_key: [u8; 32],
    /// Defining genesis resource context.
    pub resource_context: PublicationContext,
    /// Generic collateral resource identity.
    pub resource: BondResourceId,
    /// Existing canonical independently signed local execution leg.
    pub leg: Vec<u8>,
    /// Bounded predicted generation-one row; never installed by preparation.
    pub predicted_initial_row: FastPathBondRecord,
}

/// Pure preparation result with the exact signature framing bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedBondRegistration {
    /// Validated structural claim, not a state/execution permit.
    pub intent: BondRegistrationIntent,
    /// Central `0x2001` frame to sign with the actual new validator key.
    pub signing_frame: Vec<u8>,
}

/// Natural immutable anchor key for this chain and new validator.
pub fn bond_registration_anchor_key(
    chain: &ChainId,
    validator: &ValidatorId,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut key: Vec<u8> = local_instance_state::FASTPATH_STATE_PREFIX.to_vec();
    key.extend_from_slice(b"bond-registration/");
    key.extend(canonical_encoding::encode_chain_id(chain)?);
    key.extend_from_slice(validator.as_bytes());
    validate_transactional_state_key(&key)?;
    Ok(key)
}

/// NodeEvent identity of the exact unsigned canonical intent.
pub fn bond_registration_intent_digest(
    resolver: &HashSuiteResolver,
    intent: &BondRegistrationIntent,
) -> Result<Digest32, BondRegistrationError> {
    Ok(resolver.hash_for_purpose(
        intent.context.epoch(),
        HashPurpose::NodeEvent,
        &encode_bond_registration_intent(intent)?,
    )?)
}

/// Distinct domain with self-describing digest payload, not old lifecycle's
/// bare digest payload. Historical lifecycle signature framing is unchanged.
pub fn bond_registration_signing_frame(
    context: &PublicationContext,
    intent_digest: Digest32,
) -> Result<Vec<u8>, BondRegistrationError> {
    let domain: SignatureDomain = SignatureDomain {
        chain_id: context.chain_id().clone(),
        protocol_version: context.protocol_version(),
        epoch: context.epoch(),
        signature_scheme_id: SignatureSchemeId::Ed25519,
        message_type: SignatureMessageType::new("FastPathBondRegistration")
            .map_err(|_| BondRegistrationError::Invalid("registration signature family"))?,
    };
    crypto::frame_signature_message(&domain, &encode_digest32(&intent_digest)?)
        .map_err(|_| BondRegistrationError::Invalid("registration signature framing"))
}

/// NodeEvent identity of the exact signed envelope, never candidate digest.
pub fn bond_registration_receipt_digest(
    resolver: &HashSuiteResolver,
    context: &PublicationContext,
    signed_bytes: &[u8],
) -> Result<Digest32, BondRegistrationError> {
    let signed: SignedBondRegistrationIntent =
        decode_signed_bond_registration_intent(signed_bytes)?;
    if signed.intent.context != *context {
        return Err(BondRegistrationError::Invalid(
            "registration receipt context",
        ));
    }
    Ok(resolver.hash_for_purpose(context.epoch(), HashPurpose::NodeEvent, signed_bytes)?)
}

pub(crate) fn authenticate_registration(
    resolver: &HashSuiteResolver,
    profile: &VerifiedAdmissionProfile,
    registry: &ValidatorSet,
    economics: &FastPathEconomicsPolicy,
    leg_policy: &LocalExecutionPolicy,
    signed_bytes: &[u8],
) -> Result<
    (
        SignedBondRegistrationIntent,
        AuthenticatedLocalExecutionIntent,
    ),
    BondRegistrationError,
> {
    let signed: SignedBondRegistrationIntent =
        decode_signed_bond_registration_intent(signed_bytes)?;
    let leg: AuthenticatedLocalExecutionIntent = authenticate_intent(
        resolver,
        profile,
        registry,
        economics,
        leg_policy,
        &signed.intent,
    )?;
    let frame: Vec<u8> = bond_registration_signing_frame(
        &signed.intent.context,
        bond_registration_intent_digest(resolver, &signed.intent)?,
    )?;
    let verifier: Ed25519Verifier =
        Ed25519Verifier::from_verifying_key_bytes(&signed.intent.authorization_key)
            .map_err(|_| BondRegistrationError::Invalid("registration authorization key"))?;
    if !verifier
        .verify_framed(&frame, &signed.signature)
        .map_err(|_| BondRegistrationError::Invalid("registration outer signature"))?
    {
        return Err(BondRegistrationError::Invalid(
            "registration outer signature",
        ));
    }
    Ok((signed, leg))
}

fn authenticate_intent(
    resolver: &HashSuiteResolver,
    profile: &VerifiedAdmissionProfile,
    registry: &ValidatorSet,
    economics: &FastPathEconomicsPolicy,
    leg_policy: &LocalExecutionPolicy,
    intent: &BondRegistrationIntent,
) -> Result<AuthenticatedLocalExecutionIntent, BondRegistrationError> {
    if !profile.is_causal()
        || intent.context != *profile.context()
        || intent.resource_context != *profile.context()
        || intent.pinned_genesis_digest != profile.genesis_digest()
        || resolver.chain_id() != profile.context().chain_id()
        || resolver.protocol_version() != profile.context().protocol_version()
        || registry.epoch() != profile.context().epoch()
        || *leg_policy != LocalExecutionPolicy::generic_object_results(intent.context.clone())
    {
        return Err(BondRegistrationError::Invalid(
            "registration requires pinned first causal epoch",
        ));
    }
    require_external_request_lane(profile, ExternalRequestLane::Ordered, &intent.request_id)?;
    if intent.authorization_scheme != SignatureSchemeId::Ed25519
        || intent.validator_id.as_bytes() != &intent.authorization_key
    {
        return Err(BondRegistrationError::Invalid(
            "registration identity must equal its Ed25519 key",
        ));
    }
    validate_ed25519_owner_address(
        &intent.authorization_key,
        Ed25519OwnerAddressPolicy::CanonicalPrimeOrder,
    )
    .map_err(|_| {
        BondRegistrationError::Invalid("registration requires canonical prime-order key")
    })?;
    if registry.validators().iter().any(|entry| {
        entry.id == intent.validator_id
            || entry.public_key.as_slice() == intent.authorization_key.as_slice()
    }) {
        return Err(BondRegistrationError::Invalid(
            "registration reuses a signed genesis identity or key",
        ));
    }
    let resource: &FastPathEconomicsResourcePolicy = initial_resource(economics, intent)?;
    let leg: AuthenticatedLocalExecutionIntent =
        authenticate_local_execution(resolver, leg_policy, &intent.leg)?;
    let call = &leg.intent().call;
    if call.context != intent.context
        || call.request_id != intent.request_id
        || call.code != resource.code
        || call.instance != resource.instance
        || call.entrypoint != resource.transfer_entrypoint
        || !matches!(call.access.entries.as_slice(), [entry] if entry.mode == AccessMode::Write)
    {
        return Err(BondRegistrationError::Invalid(
            "registration leg identity or generic resource target",
        ));
    }
    Ok(leg)
}

pub(crate) fn initial_resource<'a>(
    economics: &'a FastPathEconomicsPolicy,
    intent: &BondRegistrationIntent,
) -> Result<&'a FastPathEconomicsResourcePolicy, BondRegistrationError> {
    if economics.context != intent.resource_context {
        return Err(BondRegistrationError::Invalid(
            "registration resource authority context",
        ));
    }
    economics
        .resources
        .iter()
        .find(|entry| {
            entry.resource_id == intent.resource && entry.context == intent.resource_context
        })
        .filter(|entry| entry.bond.is_some())
        .ok_or(BondRegistrationError::Invalid(
            "registration resource absent from signed genesis policy",
        ))
}

fn pinned_inputs(
    resolver: &HashSuiteResolver,
    manifest: &GenesisManifest,
    pinned: Digest32,
) -> Result<(VerifiedAdmissionProfile, ValidatorSet, LocalExecutionPolicy), BondRegistrationError> {
    let profile: VerifiedAdmissionProfile =
        VerifiedAdmissionProfile::from_pinned_genesis(resolver, manifest, pinned)?;
    let validators: Vec<validator_set::ValidatorInfo> = manifest
        .validator_set
        .validators
        .iter()
        .map(|entry| validator_set::ValidatorInfo {
            id: entry.id,
            voting_power: entry.voting_power,
            signature_scheme: entry.signature_scheme,
            public_key: entry.public_key.clone(),
        })
        .collect();
    let registry: ValidatorSet = ValidatorSet::new(manifest.context().epoch(), validators)
        .map_err(|_| BondRegistrationError::Invalid("registration genesis registry"))?;
    let leg_policy: LocalExecutionPolicy =
        LocalExecutionPolicy::generic_object_results(manifest.context().clone());
    Ok((profile, registry, leg_policy))
}

/// Verify bounded canonical original material and both signatures against
/// independent local pins. The returned claims grant no execution authority.
pub fn verify_signed_bond_registration(
    resolver: &HashSuiteResolver,
    manifest: &GenesisManifest,
    pinned_genesis_digest: Digest32,
    bytes: &[u8],
) -> Result<SignedBondRegistrationIntent, BondRegistrationError> {
    let (profile, registry, leg_policy) = pinned_inputs(resolver, manifest, pinned_genesis_digest)?;
    Ok(authenticate_registration(
        resolver,
        &profile,
        &registry,
        &manifest.economics_policy,
        &leg_policy,
        bytes,
    )?
    .0)
}

/// Validate a predicted row and signed leg under a locally pinned signed
/// genesis and return exactly what the actual new key must sign. No VM, store
/// read, state seeding, membership or readiness authority is created.
pub fn prepare_bond_registration(
    resolver: &HashSuiteResolver,
    manifest: &GenesisManifest,
    pinned_genesis_digest: Digest32,
    request: BondRegistrationPreparationRequest,
) -> Result<PreparedBondRegistration, BondRegistrationError> {
    let (profile, registry, leg_policy) = pinned_inputs(resolver, manifest, pinned_genesis_digest)?;
    let row: &FastPathBondRecord = &request.predicted_initial_row;
    let row_bytes: Vec<u8> = encode_fastpath_bond_record(row)?;
    if row_bytes.len() > MAX_BOND_REGISTRATION_ROW_BYTES {
        return Err(BondRegistrationError::Invalid(
            "registration predicted row bound",
        ));
    }
    let intent: BondRegistrationIntent = BondRegistrationIntent {
        context: request.context,
        request_id: request.request_id,
        validator_id: ValidatorId::new(request.authorization_key),
        authorization_scheme: SignatureSchemeId::Ed25519,
        authorization_key: request.authorization_key,
        resource_context: request.resource_context,
        resource: request.resource,
        leg: request.leg,
        expected_initial_row_digest: bond_row_digest(resolver, row.lifecycle_epoch, &row_bytes)
            .map_err(|_| BondRegistrationError::Invalid("registration predicted row digest"))?,
        pinned_genesis_digest,
    };
    let leg: AuthenticatedLocalExecutionIntent = authenticate_intent(
        resolver,
        &profile,
        &registry,
        &manifest.economics_policy,
        &leg_policy,
        &intent,
    )?;
    validate_initial_row(
        &intent,
        row,
        &leg,
        initial_resource(&manifest.economics_policy, &intent)?,
    )?;
    let signing_frame: Vec<u8> = bond_registration_signing_frame(
        &intent.context,
        bond_registration_intent_digest(resolver, &intent)?,
    )?;
    Ok(PreparedBondRegistration {
        intent,
        signing_frame,
    })
}

pub(crate) fn validate_initial_row(
    intent: &BondRegistrationIntent,
    row: &FastPathBondRecord,
    leg: &AuthenticatedLocalExecutionIntent,
    resource: &FastPathEconomicsResourcePolicy,
) -> Result<(), BondRegistrationError> {
    let config: &BondResourceConfig =
        resource
            .bond
            .as_ref()
            .ok_or(BondRegistrationError::Invalid(
                "registration resource not bond-enabled",
            ))?;
    let source: &ObjectRef = &leg.intent().call.access.entries[0].object_ref;
    let slashable: u64 =
        intent
            .context
            .epoch()
            .get()
            .checked_add(1)
            .ok_or(BondRegistrationError::Invalid(
                "registration liability epoch overflow",
            ))?;
    if row.context != intent.resource_context
        || row.validator_id != intent.validator_id
        || row.resource_domain != intent.resource.domain()
        || row.resource != *intent.resource.value()
        || row.generation != 1
        || row.lifecycle_epoch != intent.context.epoch()
        || row.custody_object_epoch != intent.context.epoch()
        || row.slashable_from_epoch != Epoch::new(slashable)
        || row.state != FastPathBondState::Active
        || row.authorization_scheme != intent.authorization_scheme
        || row.authorization_key != intent.authorization_key
        || row.custody_object.id != source.id
        || source.version.checked_add(1) != Some(row.custody_object.version)
        || row.authority.object_id != source.id
        || row.authority.instance_context != resource.context
        || row.authority.code != resource.code
        || row.authority.instance != resource.instance
        || row.authority.ty != resource.ty
        || row.required_minimum != config.min_bond.get()
        || row.amount == 0
        || row.amount < config.min_bond.get()
        || !config.enabled
        || config
            .max_validator_exposure
            .is_some_and(|maximum| row.amount > maximum.get())
    {
        return Err(BondRegistrationError::Invalid(
            "registration generation-one row structural linkage",
        ));
    }
    Ok(())
}
