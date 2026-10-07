//! The canonical domain-separated DR-0153 authority anchor,
//! [`OrderedEconomicsPolicy`]/[`OrderedEconomicsEnvironment`], the
//! consensus-owned signature verification, and the pure
//! [`authenticate_candidate`] check.
//!
//! "Pure" here is load-bearing: every check below is decided from the
//! candidate's own canonical bytes plus the already-loaded pinned
//! policy/resolver/leg-policy, with zero storage reads, no clock and no
//! identity allocation. That is what lets
//! [`super::OrderedEconomicsError::Unauthenticated`] be a deterministic
//! retained rejection rather than a stop.
use super::seal;
use super::*;
use crate::admission_profile::{
    ExternalRequestLane, VerifiedAdmissionProfile, require_external_request_lane,
};
use bond_lifecycle::slash::{decode_slash_intent, slash_receipt_digest};
use bond_lifecycle::{
    BondLifecycleOperation, SignedBondLifecycleIntent, bond_lifecycle_intent_digest,
    bond_lifecycle_receipt_digest, bond_lifecycle_signing_frame,
    decode_signed_bond_lifecycle_intent,
};
use canonical_encoding::encode_digest32;
use consensus::{
    ChainedHotStuff, ConsensusError, ConsensusParameters, FrozenFrontierCertifier,
    verify_frozen_frontier_quorum,
};
use crypto::{
    Ed25519OwnerAddressPolicy, Ed25519Verifier, SignatureVerifier, validate_ed25519_owner_address,
};
use execution::local_execution::{
    AuthenticatedLocalExecutionIntent, LocalContractEngine, LocalExecutionPolicy,
    authenticate_local_execution,
};
use execution::paid_execution::PaidContractEngine;
use execution::publication::{PublicationContext, encode_publication_context};
use fee_claims::codec::{FeeClaimOperation, SignedFeeClaimIntent, decode_signed_fee_claim_intent};
use fee_claims::{fee_claim_intent_digest, fee_claim_receipt_digest, fee_claim_signing_frame};
use genesis::{GenesisManifest, VerifiedGenesisRoot};
use protocol_types::{ProtocolVersion, SignatureSchemeId, ValidatorId};
use runtime::portable::PortableBlobRepository;
use validator_set::{ValidatorInfo, ValidatorSet};

/// Searched-for frame identifier of the canonical DR-0153 authority-anchor
/// preimage. Distinct from every other allocated `0x64xx` identifier; this
/// frame is never persisted or transported, only hashed.
pub const ORDERED_ECONOMICS_ANCHOR_FRAME_TYPE: u16 = 0x6441;
const ANCHOR_ENCODING_VERSION: u16 = 1;
const HANDOFF_ANCHOR_ENCODING_VERSION: u16 = 2;
/// DR-0189 first-successor anchor version: fields 1-9 exactly as v2 plus
/// field 10, the 0xD054 successor activation subject digest.
const SUCCESSOR_ANCHOR_ENCODING_VERSION: u16 = 3;

/// Fixed logical-domain label separating this anchor from any other digest
/// that might one day be derived over the same fields.
const ANCHOR_DOMAIN_LABEL: &[u8] = b"se/ordered-economics/anchor/v1";
const HANDOFF_ANCHOR_DOMAIN_LABEL: &[u8] = b"se/ordered-economics/anchor/v2";
const SUCCESSOR_ANCHOR_DOMAIN_LABEL: &[u8] = b"se/ordered-economics/anchor/v3-successor";

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
/// [`OrderedEconomicsPolicy::from_genesis_root`]/[`OrderedEconomicsPolicy::historical`],
/// which call it) so no caller can select alternative parameters locally.
pub fn ordered_economics_authority_anchor(
    resolver: &HashSuiteResolver,
    context: &PublicationContext,
    domain: AtomicityDomainId,
    genesis_digest: Digest32,
    minimum_freeze_block_height: u64,
    validator_set: &ValidatorSet,
) -> Result<Digest32, OrderedEconomicsError> {
    authority_anchor(
        resolver,
        context,
        domain,
        genesis_digest,
        minimum_freeze_block_height,
        validator_set,
        None,
    )
}

/// DR-0189 v3 first-successor anchor: the v2 preimage at the verified
/// successor context (field 2 at e+1, field 4 the original pinned genesis
/// digest, field 5 the verified e+1 set, field 9 the original signed positive
/// Freeze height) plus field 10, the verified 0xD054 subject digest. It only
/// hashes the given inputs; it never selects or inspects a key scope, so
/// every v1/v2 anchor and every existing key byte is unchanged.
pub(crate) fn ordered_economics_successor_anchor(
    resolver: &HashSuiteResolver,
    context: &PublicationContext,
    domain: AtomicityDomainId,
    genesis_digest: Digest32,
    minimum_freeze_block_height: u64,
    validator_set: &ValidatorSet,
    subject_digest: Digest32,
) -> Result<Digest32, OrderedEconomicsError> {
    if minimum_freeze_block_height == 0 {
        return Err(OrderedEconomicsError::Policy(
            "successor anchor requires the original signed positive Freeze height",
        ));
    }
    authority_anchor(
        resolver,
        context,
        domain,
        genesis_digest,
        minimum_freeze_block_height,
        validator_set,
        Some(subject_digest),
    )
}

fn authority_anchor(
    resolver: &HashSuiteResolver,
    context: &PublicationContext,
    domain: AtomicityDomainId,
    genesis_digest: Digest32,
    minimum_freeze_block_height: u64,
    validator_set: &ValidatorSet,
    successor_subject: Option<Digest32>,
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
    let (version, label): (u16, &[u8]) = match (successor_subject, handoff_capable) {
        (Some(_), true) => (
            SUCCESSOR_ANCHOR_ENCODING_VERSION,
            SUCCESSOR_ANCHOR_DOMAIN_LABEL,
        ),
        (Some(_), false) => {
            return Err(OrderedEconomicsError::Policy(
                "successor anchor requires a handoff-capable signed genesis",
            ));
        }
        (None, true) => (HANDOFF_ANCHOR_ENCODING_VERSION, HANDOFF_ANCHOR_DOMAIN_LABEL),
        (None, false) => (ANCHOR_ENCODING_VERSION, ANCHOR_DOMAIN_LABEL),
    };
    let mut frame: CanonicalStruct =
        CanonicalStruct::new(ORDERED_ECONOMICS_ANCHOR_FRAME_TYPE, version);
    frame.field_bytes(1, label.to_vec())?;
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
    if let Some(subject) = successor_subject {
        frame.field_bytes(10, encode_digest32(&subject)?)?;
    }
    let preimage: Vec<u8> = frame.finish()?;
    Ok(resolver.hash_for_purpose(context.epoch(), HashPurpose::ProtocolConfig, &preimage)?)
}

/// DR-0189 opaque scope of the five live ordered signing-safety key families
/// (`state`, `applied-height`, `vote-high`, `leader-proposal`, `vote`).
///
/// Only the three [`OrderedEconomicsPolicy`] constructors produce one:
/// [`OrderedEconomicsPolicy::from_genesis_root`] and
/// [`OrderedEconomicsPolicy::historical`] build the chain-only scope whose key
/// bytes are unchanged, and [`OrderedEconomicsPolicy::from_successor`] builds
/// the successor scope from verified inputs. The inner representation is
/// private to this module; callers use only the read-only selectors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OrderedKeyScope(KeyScope);

#[derive(Clone, Debug, PartialEq, Eq)]
enum KeyScope {
    Chain,
    Successor {
        protocol: ProtocolVersion,
        epoch: Epoch,
        anchor: Digest32,
    },
}

impl OrderedKeyScope {
    /// Read-only selector: whether this is a verified first-successor scope.
    pub(crate) const fn is_successor(&self) -> bool {
        matches!(self.0, KeyScope::Successor { .. })
    }

    /// Read-only selector: the exact bytes a successor safety-key builder
    /// appends after `encode_chain_id(chain)`, namely `protocol u32 BE`,
    /// `epoch u64 BE`, then `encode_digest32(v3 anchor)`. `None` for the
    /// chain-only scope, whose historical keys carry no such suffix.
    pub(crate) fn successor_scope_bytes(&self) -> Result<Option<Vec<u8>>, NodeCoreError> {
        match &self.0 {
            KeyScope::Chain => Ok(None),
            KeyScope::Successor {
                protocol,
                epoch,
                anchor,
            } => {
                let mut bytes: Vec<u8> = Vec::with_capacity(4 + 8 + 40);
                bytes.extend_from_slice(&protocol.get().to_be_bytes());
                bytes.extend_from_slice(&epoch.get().to_be_bytes());
                bytes.extend(encode_digest32(anchor)?);
                Ok(Some(bytes))
            }
        }
    }
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
    admission_profile: Option<VerifiedAdmissionProfile>,
    registration_economics: Option<crate::economics::FastPathEconomicsPolicy>,
    minimum_freeze_block_height: u64,
    anchor: Digest32,
    key_scope: OrderedKeyScope,
    /// DR-0189 Section 10: the one historical certificate scope a verified
    /// first successor accepts for imported fee claims, namely the original
    /// genesis committee at its own epoch e. `None` for every chain-scoped
    /// policy, whose fee claims stay pinned to the policy epoch.
    predecessor_certificates: Option<(Epoch, ValidatorSet)>,
    /// DR-0191 Section 2: the verified 0xD054 subject digest a successor
    /// policy was built from (v3 anchor field 10). The Seal chokepoint
    /// requires exactly this digest under predecessor tag 2. `None` for
    /// every chain-scoped policy, which accepts only tag 1 and genesis.
    successor_subject: Option<Digest32>,
    /// DR-0191 Section 6: every verified committee e_0..e_k-1 below a chain
    /// successor policy. Set only by `from_successor_chain`; it answers
    /// historical certificate scopes and never grants current membership.
    chain_committees: Option<std::sync::Arc<crate::serving_authority::VerifiedCommitteeHistory>>,
    /// DR-0191 Section 6: every genesis owner and verified registration of
    /// the chain that activated this epoch. Set only by
    /// `from_successor_chain`; never a membership stand-in.
    chain_owners: Option<std::sync::Arc<crate::serving_authority::VerifiedOwnerRegistry>>,
    engine: ChainedHotStuff,
    resolver: HashSuiteResolver,
}

impl OrderedEconomicsPolicy {
    /// Safety-key scope derived exclusively from a verified committee and
    /// its exact activating subject. This does not grant serving authority.
    pub(crate) fn scope_for_verified_epoch(
        root: &VerifiedGenesisRoot,
        history: &crate::serving_authority::VerifiedCommitteeHistory,
        epoch: Epoch,
        domain: AtomicityDomainId,
    ) -> Result<OrderedKeyScope, OrderedEconomicsError> {
        let (set, _): (&ValidatorSet, Digest32) = history
            .get(epoch)
            .ok_or(OrderedEconomicsError::Policy("scope epoch is not verified"))?;
        match history.provenance(epoch) {
            Some(crate::serving_authority::CommitteeProvenance::Genesis)
                if epoch == root.genesis_context().epoch() =>
            {
                Ok(OrderedKeyScope(KeyScope::Chain))
            }
            Some(crate::serving_authority::CommitteeProvenance::Link {
                subject_digest, ..
            }) => {
                let context: PublicationContext = PublicationContext::new(
                    root.genesis_context().chain_id().clone(),
                    root.genesis_context().protocol_version(),
                    epoch,
                )
                .map_err(|_| OrderedEconomicsError::Policy("scope context"))?;
                let anchor: Digest32 = ordered_economics_successor_anchor(
                    root.genesis_resolver(),
                    &context,
                    domain,
                    root.digest(),
                    root.manifest().minimum_freeze_block_height,
                    set,
                    subject_digest,
                )?;
                Ok(OrderedKeyScope(KeyScope::Successor {
                    protocol: context.protocol_version(),
                    epoch,
                    anchor,
                }))
            }
            _ => Err(OrderedEconomicsError::Policy("scope committee provenance")),
        }
    }
    /// Derives the fixed-epoch profile directly from one immutable
    /// [`VerifiedGenesisRoot`] (DR-0182).
    ///
    /// The root's context, digest, admission profile, original committee and
    /// resolver are already mutually consistent by construction, so this
    /// constructor performs no independent cross-check among them: that is
    /// not a missing validation gap, it is redundant, because the root makes
    /// disagreement among those values unrepresentable. Only a
    /// causal-admission root's positive Freeze height enables Freeze and
    /// initial bond registration.
    pub fn from_genesis_root(
        root: &VerifiedGenesisRoot,
        domain: AtomicityDomainId,
    ) -> Result<Self, OrderedEconomicsError> {
        let manifest: &GenesisManifest = root.manifest();
        let registration_economics: Option<crate::economics::FastPathEconomicsPolicy> = (manifest
            .commitment_profile
            == crate::logical_generation::CommitmentProfile::CausalAdmission)
            .then(|| manifest.economics_policy.clone());
        Self::build(
            root.genesis_context().clone(),
            domain,
            root.digest(),
            Some(root.admission_profile().clone()),
            registration_economics,
            manifest.minimum_freeze_block_height,
            root.genesis_committee().clone(),
            root.genesis_resolver().clone(),
            None,
        )
    }

    /// DR-0189 third constructor: the e+1 ordered profile of a verified
    /// first successor.
    ///
    /// Context, domain, set, subject and anchor come only from the verified
    /// [`crate::serving_authority::SuccessorPolicyInputs`]. There is no
    /// separate caller domain or epoch. The root must be the exact original
    /// pinned genesis of those inputs (digest, chain and protocol). The v3
    /// anchor is recomputed with the root resolver and the original signed
    /// minimum Freeze height and must equal the verified anchor. The
    /// original verified causal admission profile and Freeze height are
    /// retained, so ordered fencing and external-lane/causal checks stay
    /// active. Only registration economics is absent. Freeze, DrainSet,
    /// Seal and initial registration candidates are refused by the shared
    /// pure authentication chokepoint through the private key scope of this
    /// policy, never by an absent profile.
    pub fn from_successor(
        root: &VerifiedGenesisRoot,
        inputs: &crate::serving_authority::SuccessorPolicyInputs,
    ) -> Result<Self, OrderedEconomicsError> {
        let manifest: &GenesisManifest = root.manifest();
        let context: &PublicationContext = inputs.context();
        if root.digest() != inputs.genesis_digest() {
            return Err(OrderedEconomicsError::Policy(
                "successor policy root is not the verified original genesis",
            ));
        }
        if root.genesis_context().chain_id() != context.chain_id()
            || root.genesis_context().protocol_version() != context.protocol_version()
        {
            return Err(OrderedEconomicsError::Policy(
                "successor policy root chain or protocol differs from the verified context",
            ));
        }
        let mut policy: Self = Self::build(
            context.clone(),
            inputs.domain(),
            root.digest(),
            Some(root.admission_profile().clone()),
            None,
            manifest.minimum_freeze_block_height,
            inputs.validator_set().clone(),
            root.genesis_resolver().clone(),
            Some(inputs.subject_digest()),
        )?;
        if policy.anchor != inputs.anchor() {
            return Err(OrderedEconomicsError::Policy(
                "successor policy anchor differs from the verified successor anchor",
            ));
        }
        // The predecessor of a first successor is exactly the original
        // genesis epoch, whose committee digest the cut binding and the
        // terminal Seal verified. Nothing else can become a historical scope.
        let predecessor_epoch: Epoch = root.genesis_context().epoch();
        let committee: &ValidatorSet = root.genesis_committee();
        if predecessor_epoch.get().checked_add(1) != Some(context.epoch().get())
            || committee.epoch() != predecessor_epoch
            || committee.digest(root.genesis_resolver()).map_err(|_| {
                OrderedEconomicsError::Policy("successor predecessor committee digest")
            })? != inputs.predecessor_set_digest()
        {
            return Err(OrderedEconomicsError::Policy(
                "successor predecessor committee differs from the verified outgoing set",
            ));
        }
        policy.predecessor_certificates = Some((predecessor_epoch, committee.clone()));
        Ok(policy)
    }

    /// Creates the canonical anchor for one fixed-epoch profile with no
    /// signed genesis manifest at all.
    ///
    /// This is for a genuinely manifest-free historical consumer only: the
    /// resulting policy carries no admission profile, cannot Freeze and
    /// cannot authenticate initial bond registration; it can still mutate an
    /// already-installed historical profile.
    pub fn historical(
        context: PublicationContext,
        domain: AtomicityDomainId,
        genesis_digest: Digest32,
        validator_set: ValidatorSet,
        resolver: HashSuiteResolver,
    ) -> Result<Self, OrderedEconomicsError> {
        Self::build(
            context,
            domain,
            genesis_digest,
            None,
            None,
            0,
            validator_set,
            resolver,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build(
        context: PublicationContext,
        domain: AtomicityDomainId,
        genesis_digest: Digest32,
        admission_profile: Option<VerifiedAdmissionProfile>,
        registration_economics: Option<crate::economics::FastPathEconomicsPolicy>,
        minimum_freeze_block_height: u64,
        validator_set: ValidatorSet,
        resolver: HashSuiteResolver,
        // Supplied only by the DR-0189 successor constructor: selects both
        // the v3 anchor and the private successor key scope.
        successor_subject: Option<Digest32>,
    ) -> Result<Self, OrderedEconomicsError> {
        let anchor: Digest32 = match successor_subject {
            None => ordered_economics_authority_anchor(
                &resolver,
                &context,
                domain,
                genesis_digest,
                minimum_freeze_block_height,
                &validator_set,
            )?,
            Some(subject) => ordered_economics_successor_anchor(
                &resolver,
                &context,
                domain,
                genesis_digest,
                minimum_freeze_block_height,
                &validator_set,
                subject,
            )?,
        };
        let key_scope: OrderedKeyScope = match successor_subject {
            None => OrderedKeyScope(KeyScope::Chain),
            Some(_) => OrderedKeyScope(KeyScope::Successor {
                protocol: context.protocol_version(),
                epoch: context.epoch(),
                anchor,
            }),
        };
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
            admission_profile,
            registration_economics,
            minimum_freeze_block_height,
            anchor,
            key_scope,
            predecessor_certificates: None,
            successor_subject,
            chain_committees: None,
            chain_owners: None,
            engine,
            resolver,
        })
    }

    /// DR-0191 Section 2: the e_k ordered profile of verified chain link
    /// k-1. It runs the `from_successor` body except that the predecessor
    /// committee is the verified committee at `e_k - 1` from the chain
    /// history (exactly the genesis committee for one link), and that the
    /// signed genesis registration economics and the verified owner registry
    /// are retained for the scoped registration owner. Crate-private: only
    /// the chain owner holds the verified history.
    pub(crate) fn from_successor_chain(
        root: &VerifiedGenesisRoot,
        inputs: &crate::serving_authority::SuccessorPolicyInputs,
        committees: std::sync::Arc<crate::serving_authority::VerifiedCommitteeHistory>,
        owners: std::sync::Arc<crate::serving_authority::VerifiedOwnerRegistry>,
    ) -> Result<Self, OrderedEconomicsError> {
        let manifest: &GenesisManifest = root.manifest();
        let context: &PublicationContext = inputs.context();
        if root.digest() != inputs.genesis_digest()
            || root.genesis_context().chain_id() != context.chain_id()
            || root.genesis_context().protocol_version() != context.protocol_version()
        {
            return Err(OrderedEconomicsError::Policy(
                "successor policy root is not the verified original genesis",
            ));
        }
        let registration_economics: Option<crate::economics::FastPathEconomicsPolicy> = (manifest
            .commitment_profile
            == crate::logical_generation::CommitmentProfile::CausalAdmission)
            .then(|| manifest.economics_policy.clone());
        let mut policy: Self = Self::build(
            context.clone(),
            inputs.domain(),
            root.digest(),
            Some(root.admission_profile().clone()),
            registration_economics,
            manifest.minimum_freeze_block_height,
            inputs.validator_set().clone(),
            root.genesis_resolver().clone(),
            Some(inputs.subject_digest()),
        )?;
        if policy.anchor != inputs.anchor() {
            return Err(OrderedEconomicsError::Policy(
                "successor policy anchor differs from the verified successor anchor",
            ));
        }
        let predecessor_epoch: Epoch = context.epoch().get().checked_sub(1).map(Epoch::new).ok_or(
            OrderedEconomicsError::Policy("successor policy epoch has no predecessor"),
        )?;
        let (committee, digest): (&ValidatorSet, Digest32) = committees
            .get(predecessor_epoch)
            .ok_or(OrderedEconomicsError::Policy(
                "successor predecessor committee is not in the verified history",
            ))?;
        if committee.epoch() != predecessor_epoch
            || digest != inputs.predecessor_set_digest()
            || committees
                .get(context.epoch())
                .is_some_and(|(set, _)| set != inputs.validator_set())
        {
            return Err(OrderedEconomicsError::Policy(
                "successor predecessor committee differs from the verified outgoing set",
            ));
        }
        // The current committee must be the one certified by exactly the
        // verified link whose subject this policy is built from.
        match committees.provenance(context.epoch()) {
            Some(crate::serving_authority::CommitteeProvenance::Link {
                index,
                subject_digest,
            }) if subject_digest == inputs.subject_digest()
                && Some(u64::from(index))
                    == predecessor_epoch
                        .get()
                        .checked_sub(root.genesis_context().epoch().get()) => {}
            _ => {
                return Err(OrderedEconomicsError::Policy(
                    "successor committee provenance differs from the verified subject",
                ));
            }
        }
        policy.predecessor_certificates = Some((predecessor_epoch, committee.clone()));
        policy.chain_committees = Some(committees);
        policy.chain_owners = Some(owners);
        Ok(policy)
    }

    /// The verified owner registry of a chain successor policy; `None` for
    /// every chain-scoped and single-link policy.
    pub(crate) fn chain_owners(&self) -> Option<&crate::serving_authority::VerifiedOwnerRegistry> {
        self.chain_owners.as_deref()
    }

    pub(crate) const fn successor_subject(&self) -> Option<Digest32> {
        self.successor_subject
    }

    /// Returns the sole current active hash suite resolver this policy was
    /// derived from. [`OrderedEconomicsEnvironment`] and native HTTP
    /// `OrderedEconomicsState` obtain their resolver from this method rather
    /// than a separately supplied field (DR-0182).
    #[must_use]
    pub const fn resolver(&self) -> &HashSuiteResolver {
        &self.resolver
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

    /// Independently verified signed-genesis admission authority, when the
    /// caller supplied the pinned manifest. A manifest-free policy can only
    /// mutate a historical installed profile.
    #[must_use]
    pub const fn admission_profile(&self) -> Option<&VerifiedAdmissionProfile> {
        self.admission_profile.as_ref()
    }

    /// Signed first-genesis economics authority for initial registration only.
    pub(crate) fn registration_economics(
        &self,
    ) -> Option<&crate::economics::FastPathEconomicsPolicy> {
        self.registration_economics.as_ref()
    }

    /// Whether fresh ordered signatures require committed causal prerequisites.
    #[must_use]
    pub fn is_causal(&self) -> bool {
        self.admission_profile
            .as_ref()
            .is_some_and(VerifiedAdmissionProfile::is_causal)
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

    /// The private-representation scope of the live ordered signing-safety
    /// keys this policy reads and writes. Read-only: no caller can select or
    /// widen it.
    pub(crate) const fn key_scope(&self) -> &OrderedKeyScope {
        &self.key_scope
    }

    /// The committee whose keys certify a fee claim signed for
    /// `certificate_epoch`: the pinned set at the policy epoch, or, only for
    /// a verified first successor, the verified predecessor committee at its
    /// exact epoch. Every other epoch has no certificate scope.
    /// Read-only claimant key lookup. This never grants current consensus
    /// membership or widens the privately verified predecessor scope.
    #[must_use]
    pub fn certificate_set(&self, certificate_epoch: Epoch) -> Option<&ValidatorSet> {
        if certificate_epoch == self.context.epoch() {
            return Some(self.engine.validator_set());
        }
        // DR-0191: a chain successor answers any verified earlier epoch
        // from its verified committee history (e_0 escrow claimed at e_2+).
        if let Some(history) = self.chain_committees.as_deref() {
            return (certificate_epoch < self.context.epoch())
                .then(|| history.get(certificate_epoch))
                .flatten()
                .map(|(set, _)| set);
        }
        match &self.predecessor_certificates {
            Some((epoch, set)) if *epoch == certificate_epoch => Some(set),
            _ => None,
        }
    }

    /// Returns the registered authority for `validator_id` in the pinned
    /// active set, or `None` when it is not a member. Zero storage I/O: the
    /// set is already loaded into [`Self::engine`].
    #[must_use]
    pub fn registered_validator(&self, validator_id: ValidatorId) -> Option<&ValidatorInfo> {
        self.engine.validator_set().get(validator_id)
    }

    /// DR-0189 Section 10: the trusted key authority of one validator-signed
    /// bond lifecycle envelope. A pinned committee member is always its own
    /// authority. Only a verified first successor additionally recognizes a
    /// retired member of the verified predecessor committee, and only for the
    /// historical owner exit operations `Unbond` and `Withdraw`: a retired
    /// validator is refused as a consensus signer, never as the ordinary
    /// owner of its imported bond. The owning handler still verifies the
    /// imported bond row key, resource, generation, row digest, state, unlock
    /// epoch, legs, nonce and custody.
    pub(crate) fn bond_owner_authority(
        &self,
        validator_id: ValidatorId,
        operation: &BondLifecycleOperation,
    ) -> Option<BondOwnerKey<'_>> {
        if let Some(info) = self.engine.validator_set().get(validator_id) {
            return Some(BondOwnerKey::member(info));
        }
        match operation {
            // DR-0191 Section 6: a chain successor resolves a non-member
            // owner only from the verified owner registry (genesis key or
            // verified signed registration), never from latest membership.
            BondLifecycleOperation::Unbond { .. } | BondLifecycleOperation::Withdraw { .. } => {
                match self.chain_owners.as_deref() {
                    Some(owners) => match owners.owner(validator_id) {
                        Some(entry) => Some(BondOwnerKey {
                            scheme: entry.scheme(),
                            key: std::borrow::Cow::Borrowed(entry.key().as_slice()),
                            source: BondOwnerSource::Verified,
                        }),
                        // Never an existing owner's key under another id.
                        None if owners.names(validator_id, validator_id.as_bytes()) => None,
                        None => Some(BondOwnerKey {
                            scheme: SignatureSchemeId::Ed25519,
                            key: std::borrow::Cow::Owned(validator_id.as_bytes().to_vec()),
                            source: BondOwnerSource::SameEpochRegistrant,
                        }),
                    },
                    None => self
                        .predecessor_certificates
                        .as_ref()
                        .and_then(|(_, set): &(Epoch, ValidatorSet)| set.get(validator_id))
                        .map(BondOwnerKey::verified),
                }
            }
            BondLifecycleOperation::Deposit { .. }
            | BondLifecycleOperation::Replace { .. }
            | BondLifecycleOperation::Reactivate { .. } => None,
        }
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

    /// Exact event digest the original receipt of an *accepted* completion of
    /// `candidate` carries, given that candidate's own verified digest.
    ///
    /// Each branch calls the committing handler's own receipt derivation, so
    /// history verification cannot drift from the receipt the handler wrote.
    /// Fee-claim, bond-lifecycle and slash handlers key it by the exact signed
    /// envelope or slash-intent bytes they decoded; an embedded leg's
    /// `local_execution_event_digest` only seeds that leg's execution and
    /// custody capability, never this receipt. Evidence and the Freeze and
    /// DrainSet controls commit plain durable rows, which the orchestrator
    /// wraps in its own receipt over the candidate digest, exactly like every
    /// retained refusal.
    pub(super) fn accepted_receipt_digest(
        &self,
        candidate: &OrderedCandidate,
        candidate_digest: Digest32,
    ) -> Result<Digest32, OrderedEconomicsError> {
        let bytes: &[u8] = &candidate.intent;
        match candidate.kind {
            OrderedOperationKind::FeeClaim => {
                let signed: SignedFeeClaimIntent =
                    decode_signed_fee_claim_intent(bytes).map_err(receipt_digest_error)?;
                fee_claim_receipt_digest(&self.resolver, &signed.intent.context, bytes)
                    .map_err(receipt_digest_error)
            }
            OrderedOperationKind::BondLifecycle => {
                let signed: SignedBondLifecycleIntent =
                    decode_signed_bond_lifecycle_intent(bytes).map_err(receipt_digest_error)?;
                bond_lifecycle_receipt_digest(&self.resolver, &signed.intent.context, bytes)
                    .map_err(receipt_digest_error)
            }
            OrderedOperationKind::BondRegistration => {
                bond_lifecycle::registration::bond_registration_receipt_digest(
                    &self.resolver,
                    &candidate.context,
                    bytes,
                )
                .map_err(receipt_digest_error)
            }
            OrderedOperationKind::BondSlash => {
                let intent = decode_slash_intent(bytes).map_err(receipt_digest_error)?;
                slash_receipt_digest(&self.resolver, &intent.context, bytes)
                    .map_err(receipt_digest_error)
            }
            OrderedOperationKind::Evidence
            | OrderedOperationKind::Freeze
            | OrderedOperationKind::DrainSet => Ok(candidate_digest),
            OrderedOperationKind::Seal => Ok(candidate_digest),
        }
    }
}

struct CandidateAuthentication<'a> {
    policy: &'a OrderedEconomicsPolicy,
    leg_policy: &'a LocalExecutionPolicy,
}

impl<'a> CandidateAuthentication<'a> {
    /// Returns the sole current resolver, borrowed from `policy` rather than
    /// carried as a separately caller-selected field (DR-0182).
    fn resolver(&self) -> &'a HashSuiteResolver {
        self.policy.resolver()
    }
}

/// Immutable evidence about exact original bytes under this pinned policy.
/// It is not fresh admission, a reservation or permission to expose a vote.
/// Only the pure owning authenticator below can construct it.
pub(super) struct AuthenticatedOrderedOperation<'a> {
    candidate: &'a OrderedCandidate,
    digest: Digest32,
}

impl<'a> AuthenticatedOrderedOperation<'a> {
    pub(super) const fn candidate(&self) -> &'a OrderedCandidate {
        self.candidate
    }

    pub(super) const fn digest(&self) -> Digest32 {
        self.digest
    }
}

pub(super) fn authenticate_ordered_operation<'a>(
    env: &OrderedEconomicsEnvironment<'_>,
    candidate: &'a OrderedCandidate,
) -> Result<AuthenticatedOrderedOperation<'a>, OrderedEconomicsError> {
    authenticate_candidate(env, candidate)?;
    let bytes: Vec<u8> = encode_ordered_candidate(candidate)?;
    let digest: Digest32 =
        super::engine::candidate_digest(env.resolver(), candidate.context.epoch(), &bytes)?;
    Ok(AuthenticatedOrderedOperation { candidate, digest })
}

fn policy_error(_error: ConsensusError) -> OrderedEconomicsError {
    OrderedEconomicsError::Policy("ordered economics policy does not match consensus authority")
}

/// A handler receipt digest that cannot be re-derived from already
/// authenticated candidate bytes is inconsistent input: a stop, never a
/// silently different expected digest.
fn receipt_digest_error<E>(_error: E) -> OrderedEconomicsError {
    OrderedEconomicsError::Prerequisite("ordered accepted receipt digest is underivable")
}

/// Every dependency one ordered-economics invocation needs, borrowed for its
/// duration. All fields are public per the `node_core::ordered_economics`
/// contract; this type grants no authority beyond what each field already
/// carries.
pub struct OrderedEconomicsEnvironment<'a> {
    /// Fixed-epoch policy anchor.
    pub policy: &'a OrderedEconomicsPolicy,
    /// Historical resolvers for bounded backward-compatible verification.
    pub history: &'a [HashSuiteResolver],
    /// Local execution admission/authentication policy.
    pub leg_policy: &'a LocalExecutionPolicy,
    /// Local contract execution engine.
    pub engine: &'a dyn LocalContractEngine,
    /// Blob store backing large object bodies.
    pub blobs: &'a dyn BlobStore,
    /// DR-0187 live Seal-acceptance composition. None means Seal is not
    /// live-composed in this invocation: both ordinary historical
    /// reconstruction and any store lacking the SAMESTORE Seal capability
    /// must take this branch, and neither may fabricate an accepted Seal
    /// output from it. Only a caller composing the actual live outgoing
    /// host supplies Some.
    pub seal: Option<OrderedSealComposition<'a>>,
}

/// Borrowed composition the DR-0187 private acceptance-only business closure
/// needs beyond the ordinary candidate fields above: a separately pinned
/// genesis root and the paid-side policy/engine/blob repository
/// verify_live_seal_closure reuses to independently re-derive and compare
/// the complete post-drain business state.
pub struct OrderedSealComposition<'a> {
    /// Independently pinned genesis root this Seal's sole supported
    /// predecessor tag names.
    pub genesis_root: &'a VerifiedGenesisRoot,
    /// Existing deterministic paid execution policy for owned operations.
    pub paid_base_policy: &'a LocalExecutionPolicy,
    /// Existing deterministic paid execution engine.
    pub paid_engine: &'a dyn PaidContractEngine,
    /// Portable blob repository backing the independent source capture.
    pub blobs: &'a dyn PortableBlobRepository,
}

impl<'a> OrderedEconomicsEnvironment<'a> {
    /// Returns the sole current active hash suite resolver, borrowed from
    /// [`Self::policy`] rather than carried as a separately caller-selected
    /// field (DR-0182): `policy` and this environment's resolver can
    /// therefore never disagree.
    #[must_use]
    pub const fn resolver(&self) -> &'a HashSuiteResolver {
        self.policy.resolver()
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
    trusted_key_in(env.policy.engine().validator_set(), validator_id)
}

/// [`trusted_registered_key`] against one explicit trusted committee.
fn trusted_key_in(
    validator_set: &ValidatorSet,
    validator_id: ValidatorId,
) -> Result<&[u8], OrderedEconomicsError> {
    trusted_ed25519_key(validator_set.get(validator_id))
}

/// The trusted key authority of one validator-signed envelope: a pinned set
/// entry, or (Unbond/Withdraw only) a verified chain owner. Never a voter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BondOwnerKey<'a> {
    /// Authorization scheme of the trusted key.
    pub(crate) scheme: SignatureSchemeId,
    /// Canonical trusted key bytes.
    pub(crate) key: std::borrow::Cow<'a, [u8]>,
    /// Where the key came from; a same-epoch registrant is only a pure key
    /// until its committed anchor verifies in preflight and the handler.
    pub(crate) source: BondOwnerSource,
}

/// Provenance of a [`BondOwnerKey`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BondOwnerSource {
    /// A pinned current-set entry.
    Member,
    /// A verified predecessor committee entry or verified chain owner.
    Verified,
    /// DR-0191: an Unbond/Withdraw sender registered in this epoch after
    /// the cut. Registration forces id == key, but the id bytes are never
    /// authority alone: the committed anchor must verify under the policy
    /// scope, with its reads folded into the CAS set.
    SameEpochRegistrant,
}

impl<'a> BondOwnerKey<'a> {
    fn member(info: &'a ValidatorInfo) -> Self {
        Self {
            scheme: info.signature_scheme,
            key: std::borrow::Cow::Borrowed(info.public_key.as_slice()),
            source: BondOwnerSource::Member,
        }
    }
    fn verified(info: &'a ValidatorInfo) -> Self {
        Self {
            source: BondOwnerSource::Verified,
            ..Self::member(info)
        }
    }
}

fn trusted_ed25519_key(info: Option<&ValidatorInfo>) -> Result<&[u8], OrderedEconomicsError> {
    let info: &ValidatorInfo = info.ok_or(OrderedEconomicsError::Unauthenticated(
        "ordered candidate names a validator outside the pinned validator set",
    ))?;
    if info.signature_scheme != SignatureSchemeId::Ed25519 {
        return Err(OrderedEconomicsError::Unauthenticated(
            "ordered candidate validator is not registered for Ed25519",
        ));
    }
    Ok(info.public_key.as_slice())
}

fn trusted_owner_key(owner: Option<BondOwnerKey<'_>>) -> Result<Vec<u8>, OrderedEconomicsError> {
    let owner: BondOwnerKey<'_> = owner.ok_or(OrderedEconomicsError::Unauthenticated(
        "ordered candidate names a validator outside the pinned validator set",
    ))?;
    if owner.scheme != SignatureSchemeId::Ed25519 {
        return Err(OrderedEconomicsError::Unauthenticated(
            "ordered candidate validator is not registered for Ed25519",
        ));
    }
    Ok(owner.key.into_owned())
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
        authenticate_local_execution(env.resolver(), env.leg_policy, leg).map_err(|_| {
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
        leg_policy: env.leg_policy,
    };
    authenticate_with_policy(&authentication, candidate)
}

fn authenticate_with_policy(
    env: &CandidateAuthentication<'_>,
    candidate: &OrderedCandidate,
) -> Result<(), OrderedEconomicsError> {
    // The legacy first-link policy has no complete committee/owner history
    // and keeps its original early refusal. Only the private verified-chain
    // constructor connects the authorities that recurring controls and
    // registration require. The owning live/replay gate and Seal capability
    // still decide every handler call; a policy alone never permits a write.
    if env.policy.key_scope().is_successor()
        && (env.policy.chain_committees.is_none() || env.policy.chain_owners.is_none())
        && matches!(
            candidate.kind,
            OrderedOperationKind::Freeze
                | OrderedOperationKind::DrainSet
                | OrderedOperationKind::Seal
                | OrderedOperationKind::BondRegistration
        )
    {
        return Err(OrderedEconomicsError::UnsupportedSuccessorControl);
    }
    if candidate.context != *env.policy.context() {
        return Err(OrderedEconomicsError::Unauthenticated(
            "ordered candidate context does not match the pinned policy",
        ));
    }
    if let Some(profile) = env.policy.admission_profile() {
        require_external_request_lane(profile, ExternalRequestLane::Ordered, &candidate.request_id)
            .map_err(|_| {
                OrderedEconomicsError::Unauthenticated(
                    "ordered candidate request id is outside the verified external lane",
                )
            })?;
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
        OrderedOperationKind::BondRegistration => authenticate_bond_registration(env, candidate),
        OrderedOperationKind::BondSlash => authenticate_bond_slash(env, candidate),
        OrderedOperationKind::Evidence => authenticate_evidence(env, candidate),
        OrderedOperationKind::Freeze => authenticate_freeze(env, candidate),
        OrderedOperationKind::DrainSet => authenticate_drain_set(env, candidate),
        OrderedOperationKind::Seal => authenticate_seal(env, candidate),
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
        &consensus::Ed25519ConsensusVerifier::new(
            consensus::UnsupportedSignatureSchemeResponse::InvalidSignature,
        ),
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

/// Purely validates the Seal candidate own bytes (DR-0187): the predecessor
/// pin, the created_checkpoint/embedded cut-identity binding, the readiness
/// subject own internal consistency against this pinned profile, and the
/// target/request_id derivation, including the explicit high-bit
/// convention. The referenced certificate own quorum and every successor
/// current eligibility can only be proven through durable storage and the
/// staged blob; see `super::seal::require_seal_warrant`.
fn authenticate_seal(
    env: &CandidateAuthentication<'_>,
    candidate: &OrderedCandidate,
) -> Result<(), OrderedEconomicsError> {
    if !env.policy.is_causal() {
        return Err(OrderedEconomicsError::Unauthenticated(
            "seal is not authorized outside the causal admission profile",
        ));
    }
    if env.policy.minimum_freeze_block_height() == 0 {
        return Err(OrderedEconomicsError::Unauthenticated(
            "seal is not enabled by the signed genesis profile",
        ));
    }
    let intent = seal::decode_seal_intent(&candidate.intent)
        .map_err(|_| OrderedEconomicsError::Unauthenticated("invalid seal candidate intent"))?;
    // DR-0191 Section 6: the private scope alone selects the predecessor.
    // Chain (e_0): tag 1 naming the pinned genesis only. Successor S_k: tag 2
    // naming exactly the verified subject this policy was built from.
    let (expected_tag, expected_digest, digest_refusal): (u16, Digest32, &'static str) =
        match env.policy.successor_subject {
            None => (
                seal::SEAL_PREDECESSOR_TAG_GENESIS,
                env.policy.genesis_digest(),
                "seal predecessor digest is not the pinned genesis",
            ),
            Some(subject) => (
                seal::SEAL_PREDECESSOR_TAG_SUCCESSOR,
                subject,
                "seal predecessor digest is not the verified successor subject",
            ),
        };
    if intent.predecessor_tag != expected_tag {
        return Err(OrderedEconomicsError::Unauthenticated(
            "seal predecessor tag is unsupported",
        ));
    }
    if intent.predecessor_digest != expected_digest {
        return Err(OrderedEconomicsError::Unauthenticated(digest_refusal));
    }
    let cut_identity = seal::decode_seal_cut_identity(&intent).map_err(|_| {
        OrderedEconomicsError::Unauthenticated("invalid seal candidate cut identity")
    })?;
    if candidate.created_checkpoint != cut_identity.ordered_history.through_height {
        return Err(OrderedEconomicsError::Unauthenticated(
            "seal created checkpoint is not the cut history height",
        ));
    }
    if cut_identity.context != candidate.context
        || cut_identity.domain != env.policy.domain()
        || cut_identity.genesis_digest != env.policy.genesis_digest()
    {
        return Err(OrderedEconomicsError::Unauthenticated(
            "seal candidate cut identity does not match the pinned profile",
        ));
    }
    let subject = &intent.readiness_subject;
    if subject.epoch != candidate.context.epoch()
        || subject.chain_id != *candidate.context.chain_id()
        || subject.protocol_version != candidate.context.protocol_version()
        || subject.genesis_digest != env.policy.genesis_digest()
        || subject.domain != env.policy.domain()
    {
        return Err(OrderedEconomicsError::Unauthenticated(
            "seal readiness subject does not match the pinned profile",
        ));
    }
    let outgoing_set_digest = env
        .policy
        .engine()
        .validator_set()
        .digest(env.resolver())
        .map_err(|_| {
            OrderedEconomicsError::Unauthenticated("seal outgoing validator set digest")
        })?;
    if subject.outgoing_set_digest != outgoing_set_digest {
        return Err(OrderedEconomicsError::Unauthenticated(
            "seal readiness subject outgoing set digest differs",
        ));
    }
    let cut_digest =
        seal::seal_cut_identity_digest(env.resolver(), &cut_identity).map_err(|_| {
            OrderedEconomicsError::Unauthenticated("seal candidate cut identity digest")
        })?;
    if subject.cut_digest != cut_digest {
        return Err(OrderedEconomicsError::Unauthenticated(
            "seal readiness subject cut digest differs from the candidate own cut identity",
        ));
    }
    let subject_identity = subject.identity(env.resolver()).map_err(|_| {
        OrderedEconomicsError::Unauthenticated("seal readiness subject configuration")
    })?;
    let target = seal::seal_target_digest(
        env.resolver(),
        &candidate.context,
        subject_identity,
        intent.predecessor_tag,
        intent.predecessor_digest,
    )
    .map_err(|_| OrderedEconomicsError::Unauthenticated("seal target derivation"))?;
    let request_id = seal::seal_request_id(
        env.resolver(),
        &candidate.context,
        target,
        intent.certificate_digest,
    )
    .map_err(|_| OrderedEconomicsError::Unauthenticated("seal request derivation"))?;
    if candidate.request_id != request_id {
        return Err(OrderedEconomicsError::Unauthenticated(
            "seal candidate request id does not match its own derivation",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests/seal_pure_authentication.rs"]
mod seal_pure_authentication_tests;

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
    // The certificate epoch whose historical key the handler verifies must be
    // a scope this policy pins: its own epoch, or (verified first successor
    // only) the exact predecessor epoch of an imported escrow. The claimant
    // is an ordinary historical certificate member, never required to be a
    // current consensus member.
    let certificate_set: &ValidatorSet = env
        .policy
        .certificate_set(signed.intent.certificate_epoch)
        .ok_or(OrderedEconomicsError::Unauthenticated(
            "fee claim certificate epoch is not the pinned profile epoch",
        ))?;
    let public_key: Vec<u8> = trusted_key_in(certificate_set, signed.intent.validator_id)?.to_vec();
    let intent_digest: Digest32 = fee_claim_intent_digest(env.resolver(), &signed.intent)
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
    let public_key: Vec<u8> = trusted_owner_key(
        env.policy
            .bond_owner_authority(signed.intent.validator_id, &signed.intent.operation),
    )?;
    let intent_digest: Digest32 = bond_lifecycle_intent_digest(env.resolver(), &signed.intent)
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

fn authenticate_bond_registration(
    env: &CandidateAuthentication<'_>,
    candidate: &OrderedCandidate,
) -> Result<(), OrderedEconomicsError> {
    let scope: bond_lifecycle::registration::RegistrationScope<'_> =
        bond_lifecycle::registration::RegistrationScope::for_policy(env.policy).map_err(|_| {
            OrderedEconomicsError::Unauthenticated("registration verified scope unavailable")
        })?;
    let (signed, _) = bond_lifecycle::registration::authenticate_registration(
        &scope,
        bond_lifecycle::registration::RegistrationMode::Admit,
        env.leg_policy,
        &candidate.intent,
    )
    .map_err(|_| {
        OrderedEconomicsError::Unauthenticated("invalid initial bond registration authentication")
    })?;
    if signed.intent.context != candidate.context
        || signed.intent.request_id != candidate.request_id
    {
        return Err(OrderedEconomicsError::Unauthenticated(
            "registration candidate context or request mismatch",
        ));
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
                &consensus::Ed25519ConsensusVerifier::new(
                    consensus::UnsupportedSignatureSchemeResponse::InvalidSignature,
                ),
            )
        }
        equivocation::DecodedEquivocationEvidence::ObjectConflict(inner) => {
            consensus::verify_fast_vote_object_conflict_evidence(
                inner,
                validator_set,
                &consensus::Ed25519ConsensusVerifier::new(
                    consensus::UnsupportedSignatureSchemeResponse::InvalidSignature,
                ),
            )
        }
        equivocation::DecodedEquivocationEvidence::EpochTransition(inner) => {
            consensus::verify_epoch_transition_equivocation_evidence(
                inner,
                validator_set,
                &consensus::Ed25519ConsensusVerifier::new(
                    consensus::UnsupportedSignatureSchemeResponse::InvalidSignature,
                ),
            )
        }
    };
    result.map_err(|_| OrderedEconomicsError::Unauthenticated("invalid evidence candidate proof"))
}
