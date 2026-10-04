//! DR-0191 Section 2: the one private constructor of recurring chain
//! evidence. Every link runs the single private DR-0189 verifier body
//! (`verify::verify_successor_activation`); this module only bounds, orders
//! and folds links and records the verified committee and owner history.
//! It is not a second engine and keeps no state across invocations.

use super::*;
use crate::bond_lifecycle::registration::{
    RegisteredOwnerIdentity, bond_registration_anchor_key, verify_registration_identity,
};
use crate::business_reconstruction::BusinessReconstructionPlan;
use crate::genesis::VerifiedGenesisRoot;
use crate::local_instance_state::FASTPATH_STATE_PREFIX;
use crate::ordered_economics::OrderedEconomicsPolicy;
use protocol_types::{Epoch, SignatureSchemeId, ValidatorId};
use runtime::inactive_import::ImportRow;
use std::num::NonZeroU32;

/// Local resource budget, not a consensus rule. Exceeding it refuses before
/// any artifact access; it never truncates, skips or resets the chain. There
/// is deliberately no default: operators configure it explicitly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SuccessorChainBudget(NonZeroU32);

impl SuccessorChainBudget {
    /// A budget of at most `max_links` verified links per invocation.
    #[must_use]
    pub const fn new(max_links: NonZeroU32) -> Self {
        Self(max_links)
    }

    /// The configured maximum link count.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }

    /// The budget every existing single-link entry point delegates with.
    pub(crate) const ONE: Self = Self(NonZeroU32::MIN);
}

/// Untrusted operator pins for one link, supplied in link order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuccessorLinkPins {
    /// Epoch e_k history through the cut height T_k.
    pub cut_identity: OrderedHistoryIdentity,
    /// Epoch e_k history through the terminal Seal height h_k.
    pub manifest_identity: OrderedHistoryIdentity,
}

/// Untrusted per-link transport. The verifier lends the privately derived
/// read-only link plan or policy so archive readers can decode; every
/// returned value is still a claim.
pub trait SuccessorChainArtifacts {
    /// Whole saved cut of link `link`.
    fn saved_business_cut(
        &mut self,
        link: u32,
        plan: &BusinessReconstructionPlan<'_>,
    ) -> Result<SavedBusinessCut, SuccessorArtifactError>;
    /// Height `1..=identity.through_height` of link `link` history export.
    fn history_height(
        &mut self,
        link: u32,
        policy: &OrderedEconomicsPolicy,
        identity: &OrderedHistoryIdentity,
        height: u64,
    ) -> Result<OrderedHistoryHeightMaterial, SuccessorArtifactError>;
    /// Exactly `length` bytes of link `link` readiness certificate.
    fn readiness_certificate(
        &mut self,
        link: u32,
        length: u32,
    ) -> Result<Vec<u8>, SuccessorArtifactError>;
}

/// Where a committee in the verified history came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommitteeProvenance {
    /// The signed genesis committee at e_0.
    Genesis,
    /// The certified next set of verified link `index`.
    Link {
        index: u32,
        subject_digest: Digest32,
    },
}

/// Every verified committee from e_0 through the current epoch. Built only
/// in this module; no row, flag or decoded record constructs it.
#[derive(Clone, Debug)]
pub(crate) struct VerifiedCommitteeHistory {
    by_epoch: BTreeMap<Epoch, (ValidatorSet, Digest32, CommitteeProvenance)>,
}

impl VerifiedCommitteeHistory {
    fn genesis(root: &VerifiedGenesisRoot) -> Result<Self, SuccessorActivationError> {
        let committee: &ValidatorSet = root.genesis_committee();
        let digest: Digest32 = committee
            .digest(root.genesis_resolver())
            .map_err(|_| invalid("genesis committee digest"))?;
        let mut by_epoch: BTreeMap<Epoch, (ValidatorSet, Digest32, CommitteeProvenance)> =
            BTreeMap::new();
        by_epoch.insert(
            committee.epoch(),
            (committee.clone(), digest, CommitteeProvenance::Genesis),
        );
        Ok(Self { by_epoch })
    }

    /// Records link `index` certified next set at its own epoch. The epoch
    /// must be exactly one above the newest recorded epoch.
    fn push_link(
        &mut self,
        root: &VerifiedGenesisRoot,
        index: u32,
        link: &VerifiedSuccessorActivation,
    ) -> Result<(), SuccessorActivationError> {
        let set: &ValidatorSet = &link.policy_inputs.validator_set;
        let newest: Epoch = self.newest_epoch()?;
        if newest.get().checked_add(1) != Some(set.epoch().get())
            || set.epoch() != link.policy_inputs.context.epoch()
        {
            return Err(invalid("chain committee epochs are not contiguous"));
        }
        let digest: Digest32 = set
            .digest(root.genesis_resolver())
            .map_err(|_| invalid("chain committee digest"))?;
        if digest != link.subject.successor_set_digest {
            return Err(invalid("chain committee differs from the verified subject"));
        }
        self.by_epoch.insert(
            set.epoch(),
            (
                set.clone(),
                digest,
                CommitteeProvenance::Link {
                    index,
                    subject_digest: link.subject_digest,
                },
            ),
        );
        Ok(())
    }

    fn newest_epoch(&self) -> Result<Epoch, SuccessorActivationError> {
        self.by_epoch
            .keys()
            .next_back()
            .copied()
            .ok_or(invalid("chain committee history is empty"))
    }

    /// The verified committee and its digest at exactly `epoch`.
    pub(crate) fn get(&self, epoch: Epoch) -> Option<(&ValidatorSet, Digest32)> {
        self.by_epoch
            .get(&epoch)
            .map(|(set, digest, _)| (set, *digest))
    }

    /// Where the committee at `epoch` came from.
    pub(crate) fn provenance(&self, epoch: Epoch) -> Option<CommitteeProvenance> {
        self.by_epoch
            .get(&epoch)
            .map(|(_, _, provenance)| *provenance)
    }

    pub(crate) fn scopes(
        &self,
        root: &VerifiedGenesisRoot,
        domain: AtomicityDomainId,
    ) -> Result<Vec<crate::ordered_economics::OrderedKeyScope>, SuccessorActivationError> {
        self.by_epoch
            .keys()
            .map(|epoch: &Epoch| {
                OrderedEconomicsPolicy::scope_for_verified_epoch(root, self, *epoch, domain)
                    .map_err(SuccessorActivationError::from)
            })
            .collect()
    }

    /// Number of verified committees (links + 1).
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.by_epoch.len()
    }
}

/// Cryptographic provenance of one bond owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum OwnerProvenance {
    /// A signed-manifest genesis validator.
    Genesis { genesis_digest: Digest32 },
    /// A verified committed registration anchor.
    Registration {
        anchor_epoch: Epoch,
        intent_digest: Digest32,
        initial_row_digest: Digest32,
    },
}

/// One verified bond owner identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OwnerEntry {
    validator_id: ValidatorId,
    scheme: SignatureSchemeId,
    key: [u8; 32],
    provenance: OwnerProvenance,
}

impl OwnerEntry {
    /// Verified owner identity.
    pub(crate) const fn validator_id(&self) -> ValidatorId {
        self.validator_id
    }
    /// Verified owner authorization scheme.
    pub(crate) const fn scheme(&self) -> SignatureSchemeId {
        self.scheme
    }
    /// Verified owner authorization key.
    pub(crate) const fn key(&self) -> &[u8; 32] {
        &self.key
    }
    /// Verified owner provenance.
    pub(crate) const fn provenance(&self) -> &OwnerProvenance {
        &self.provenance
    }
}

/// Every genesis owner plus every cryptographically verified registration.
/// Membership in a set never stands in for provenance.
#[derive(Clone, Debug)]
pub(crate) struct VerifiedOwnerRegistry {
    by_id: BTreeMap<ValidatorId, OwnerEntry>,
    by_key: BTreeMap<[u8; 32], ValidatorId>,
}

impl VerifiedOwnerRegistry {
    fn genesis(root: &VerifiedGenesisRoot) -> Result<Self, SuccessorActivationError> {
        let mut registry: Self = Self {
            by_id: BTreeMap::new(),
            by_key: BTreeMap::new(),
        };
        for validator in root.genesis_committee().validators() {
            if validator.signature_scheme != SignatureSchemeId::Ed25519 {
                return Err(invalid("genesis owner scheme is not Ed25519"));
            }
            let key: [u8; 32] = validator
                .public_key
                .as_slice()
                .try_into()
                .map_err(|_| invalid("genesis owner key length"))?;
            registry.insert(OwnerEntry {
                validator_id: validator.id,
                scheme: validator.signature_scheme,
                key,
                provenance: OwnerProvenance::Genesis {
                    genesis_digest: root.digest(),
                },
            })?;
        }
        Ok(registry)
    }

    /// Byte-identical re-encounter is the same identity carried forward;
    /// any other repeat of an id or key refuses.
    fn insert(&mut self, entry: OwnerEntry) -> Result<(), SuccessorActivationError> {
        let by_id: Option<&OwnerEntry> = self.by_id.get(&entry.validator_id);
        let by_key: Option<&ValidatorId> = self.by_key.get(&entry.key);
        match (by_id, by_key) {
            (Some(existing), Some(id)) if *existing == entry && *id == entry.validator_id => Ok(()),
            (None, None) => {
                self.by_key.insert(entry.key, entry.validator_id);
                self.by_id.insert(entry.validator_id, entry);
                Ok(())
            }
            _ => Err(invalid("chain owner identity or key is reused")),
        }
    }

    /// Verified owner by id.
    pub(crate) fn owner(&self, validator_id: ValidatorId) -> Option<&OwnerEntry> {
        self.by_id.get(&validator_id)
    }

    /// Whether `id` or `key` names any verified owner.
    pub(crate) fn names(&self, validator_id: ValidatorId, key: &[u8]) -> bool {
        self.by_id.contains_key(&validator_id)
            || <[u8; 32]>::try_from(key).is_ok_and(|key: [u8; 32]| self.by_key.contains_key(&key))
    }

    /// Number of verified owners.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.by_id.len()
    }
}

/// Private chain evidence: no `Clone`, `Default` or serialization. The
/// current link is held directly so accessors are total.
pub(super) struct VerifiedSuccessorChain {
    current: VerifiedSuccessorActivation,
    previous: Vec<VerifiedSuccessorActivation>,
    committees: std::sync::Arc<VerifiedCommitteeHistory>,
    owners: std::sync::Arc<VerifiedOwnerRegistry>,
    /// Checked link count, `1..=budget`.
    link_count: u32,
}

impl VerifiedSuccessorChain {
    /// The last verified link, which activated the current epoch.
    pub(super) const fn current(&self) -> &VerifiedSuccessorActivation {
        &self.current
    }
    pub(crate) fn reconstruction_base<'c>(
        &'c self,
        root: &'c VerifiedGenesisRoot,
    ) -> Result<ReconstructionBase<'c>, SuccessorActivationError> {
        if root.digest() != self.current.policy_inputs.genesis_digest {
            return Err(invalid(
                "reconstruction root differs from the verified chain",
            ));
        }
        Ok(ReconstructionBase::successor(
            root,
            &self.current,
            &self.committees,
            &self.owners,
        ))
    }
    /// Verified committee history e_0 through the current epoch.
    pub(crate) fn committees(&self) -> &VerifiedCommitteeHistory {
        &self.committees
    }
    /// Verified owner registry.
    pub(crate) fn owners(&self) -> &VerifiedOwnerRegistry {
        &self.owners
    }
    /// The chain-aware ordered policy of the current epoch: the verified
    /// current link's inputs plus the shared verified committee and owner
    /// history. Never built from caller values.
    pub(super) fn current_policy(
        &self,
        root: &VerifiedGenesisRoot,
    ) -> Result<OrderedEconomicsPolicy, SuccessorActivationError> {
        if u32::try_from(self.previous.len())
            .ok()
            .and_then(|count: u32| count.checked_add(1))
            != Some(self.link_count)
        {
            return Err(invalid("verified chain retained link count differs"));
        }
        Ok(OrderedEconomicsPolicy::from_successor_chain(
            root,
            &self.current.policy_inputs,
            std::sync::Arc::clone(&self.committees),
            std::sync::Arc::clone(&self.owners),
        )?)
    }
    /// Number of verified links.
    pub(super) const fn link_count(&self) -> u32 {
        self.link_count
    }
}

fn invalid(message: &'static str) -> SuccessorActivationError {
    SuccessorActivationError::Invalid(message)
}

/// Copies the borrowed plan; every field is a shared borrow or `Copy`.
fn lend_plan<'p>(plan: &BusinessReconstructionPlan<'p>) -> BusinessReconstructionPlan<'p> {
    BusinessReconstructionPlan {
        genesis_root: plan.genesis_root,
        operation_context: plan.operation_context,
        domain: plan.domain,
        resolver_history: plan.resolver_history,
        ordered_policy: plan.ordered_policy,
        ordered_history_identity: plan.ordered_history_identity,
        ordered_leg_policy: plan.ordered_leg_policy,
        ordered_engine: plan.ordered_engine,
        paid_base_policy: plan.paid_base_policy,
        paid_engine: plan.paid_engine,
    }
}

/// Per-link view of the chain transport for the single link verifier.
struct LinkArtifacts<'t, 'p> {
    link: u32,
    plan: BusinessReconstructionPlan<'p>,
    transport: &'t mut dyn SuccessorChainArtifacts,
}

impl SuccessorArtifactSource for LinkArtifacts<'_, '_> {
    fn saved_business_cut(&mut self) -> Result<SavedBusinessCut, SuccessorArtifactError> {
        self.transport.saved_business_cut(self.link, &self.plan)
    }
    fn history_height(
        &mut self,
        identity: &OrderedHistoryIdentity,
        height: u64,
    ) -> Result<OrderedHistoryHeightMaterial, SuccessorArtifactError> {
        self.transport
            .history_height(self.link, self.plan.ordered_policy, identity, height)
    }
    fn readiness_certificate(&mut self, length: u32) -> Result<Vec<u8>, SuccessorArtifactError> {
        self.transport.readiness_certificate(self.link, length)
    }
}

/// The existing single-link transport seen as a one-link chain transport.
/// Any link other than 0 is missing, never a fallback.
pub(super) struct SingleLinkArtifacts<'s>(pub(super) &'s mut dyn SuccessorArtifactSource);

impl SuccessorChainArtifacts for SingleLinkArtifacts<'_> {
    fn saved_business_cut(
        &mut self,
        link: u32,
        _plan: &BusinessReconstructionPlan<'_>,
    ) -> Result<SavedBusinessCut, SuccessorArtifactError> {
        if link != 0 {
            return Err(SuccessorArtifactError::Missing);
        }
        self.0.saved_business_cut()
    }
    fn history_height(
        &mut self,
        link: u32,
        _policy: &OrderedEconomicsPolicy,
        identity: &OrderedHistoryIdentity,
        height: u64,
    ) -> Result<OrderedHistoryHeightMaterial, SuccessorArtifactError> {
        if link != 0 {
            return Err(SuccessorArtifactError::Missing);
        }
        self.0.history_height(identity, height)
    }
    fn readiness_certificate(
        &mut self,
        link: u32,
        length: u32,
    ) -> Result<Vec<u8>, SuccessorArtifactError> {
        if link != 0 {
            return Err(SuccessorArtifactError::Missing);
        }
        self.0.readiness_certificate(length)
    }
}

/// Every verified registration anchor among link `rows`, in ascending
/// (anchor epoch, id) order. A row under the anchor prefix whose key is not
/// the natural key of its own verified identity refuses.
fn registered_owners(
    root: &VerifiedGenesisRoot,
    committees: &VerifiedCommitteeHistory,
    owners: &VerifiedOwnerRegistry,
    rows: &[ImportRow],
) -> Result<Vec<RegisteredOwnerIdentity>, SuccessorActivationError> {
    let chain: &protocol_types::ChainId = root.genesis_context().chain_id();
    let prefix: Vec<u8> = [
        FASTPATH_STATE_PREFIX,
        b"bond-registration/".as_slice(),
        canonical_encoding::encode_chain_id(chain)?.as_slice(),
    ]
    .concat();
    let mut identities: Vec<RegisteredOwnerIdentity> = Vec::new();
    for row in rows {
        let ImportRow::State { key, value } = row else {
            continue;
        };
        if !key.starts_with(&prefix) {
            continue;
        }
        let bytes: &[u8] = value
            .as_deref()
            .ok_or(invalid("chain registration anchor is deleted"))?;
        let identity: RegisteredOwnerIdentity =
            verify_registration_identity(root, Some((committees, owners)), bytes)
                .map_err(|_| invalid("chain registration anchor does not authenticate"))?;
        if bond_registration_anchor_key(chain, &identity.validator_id)? != *key {
            return Err(invalid(
                "chain registration anchor is not at its natural key",
            ));
        }
        identities.push(identity);
    }
    identities.sort_by(|a: &RegisteredOwnerIdentity, b: &RegisteredOwnerIdentity| {
        (a.anchor_epoch, a.validator_id).cmp(&(b.anchor_epoch, b.validator_id))
    });
    Ok(identities)
}

fn record_registrations(
    owners: &mut VerifiedOwnerRegistry,
    root: &VerifiedGenesisRoot,
    committees: &VerifiedCommitteeHistory,
    link: &VerifiedSuccessorActivation,
) -> Result<(), SuccessorActivationError> {
    for identity in registered_owners(root, committees, owners, link.import.rows())? {
        owners.insert(OwnerEntry {
            validator_id: identity.validator_id,
            scheme: SignatureSchemeId::Ed25519,
            key: identity.key,
            provenance: OwnerProvenance::Registration {
                anchor_epoch: identity.anchor_epoch,
                intent_digest: identity.intent_digest,
                initial_row_digest: identity.initial_row_digest,
            },
        })?;
    }
    Ok(())
}

/// Section 2 fold. Pin count and pin 0 are checked before any artifact
/// call. Link 0 is exactly the DR-0189 link on the genesis base with the
/// caller plan. Links must be contiguous from e_0.
pub(super) fn verify_chain(
    plan: BusinessReconstructionPlan<'_>,
    pins: &[SuccessorLinkPins],
    budget: SuccessorChainBudget,
    artifacts: &mut dyn SuccessorChainArtifacts,
) -> Result<VerifiedSuccessorChain, SuccessorActivationError> {
    let links: usize = pins.len();
    let link_count: u32 = u32::try_from(links)
        .ok()
        .filter(|count: &u32| *count <= budget.get())
        .ok_or(SuccessorActivationError::ChainBudgetExceeded {
            links,
            budget: budget.get(),
        })?;
    let [first, later @ ..] = pins else {
        return Err(invalid("successor chain has no link"));
    };
    if first.cut_identity != *plan.ordered_history_identity {
        return Err(invalid("first link cut pin differs from the plan history"));
    }
    let root: &VerifiedGenesisRoot = plan.genesis_root;
    let genesis_epoch: Epoch = root.genesis_context().epoch();
    let mut committees: VerifiedCommitteeHistory = VerifiedCommitteeHistory::genesis(root)?;
    let mut owners: VerifiedOwnerRegistry = VerifiedOwnerRegistry::genesis(root)?;
    let mut current: VerifiedSuccessorActivation = {
        let mut transport: LinkArtifacts<'_, '_> = LinkArtifacts {
            link: 0,
            plan: lend_plan(&plan),
            transport: artifacts,
        };
        verify::verify_successor_activation(
            lend_plan(&plan),
            &first.manifest_identity,
            &mut transport,
        )?
    };
    if current.outgoing_context.epoch() != genesis_epoch {
        return Err(invalid("first link does not leave the genesis epoch"));
    }
    committees.push_link(root, 0, &current)?;
    record_registrations(&mut owners, root, &committees, &current)?;
    let mut previous: Vec<VerifiedSuccessorActivation> = Vec::with_capacity(later.len());
    for (ordinal, pin) in later.iter().enumerate() {
        let index: u32 = u32::try_from(ordinal)
            .ok()
            .and_then(|value: u32| value.checked_add(1))
            .ok_or(invalid("chain link index overflow"))?;
        if pin.cut_identity.context.epoch() != current.policy_inputs.context.epoch() {
            return Err(invalid("chain link is not contiguous with its predecessor"));
        }
        let committee_history: std::sync::Arc<VerifiedCommitteeHistory> =
            std::sync::Arc::new(committees.clone());
        let owner_history: std::sync::Arc<VerifiedOwnerRegistry> =
            std::sync::Arc::new(owners.clone());
        let policy: OrderedEconomicsPolicy = OrderedEconomicsPolicy::from_successor_chain(
            root,
            &current.policy_inputs,
            std::sync::Arc::clone(&committee_history),
            std::sync::Arc::clone(&owner_history),
        )?;
        let leg_policy: execution::local_execution::LocalExecutionPolicy =
            execution::local_execution::LocalExecutionPolicy::generic_object_results(
                policy.context().clone(),
            );
        let paid_policy: execution::local_execution::LocalExecutionPolicy =
            execution::local_execution::LocalExecutionPolicy::generic_object_results(
                policy.context().clone(),
            );
        let link_plan: BusinessReconstructionPlan<'_> = BusinessReconstructionPlan {
            genesis_root: root,
            operation_context: plan.operation_context,
            domain: plan.domain,
            resolver_history: plan.resolver_history,
            ordered_policy: &policy,
            ordered_history_identity: &pin.cut_identity,
            ordered_leg_policy: &leg_policy,
            ordered_engine: plan.ordered_engine,
            paid_base_policy: &paid_policy,
            paid_engine: plan.paid_engine,
        };
        let mut link_transport: LinkArtifacts<'_, '_> = LinkArtifacts {
            link: index,
            plan: lend_plan(&link_plan),
            transport: artifacts,
        };
        let base: ReconstructionBase<'_> =
            ReconstructionBase::successor(root, &current, &committee_history, &owner_history);
        let next: VerifiedSuccessorActivation = verify::verify_successor_activation_with_base(
            link_plan,
            base,
            &pin.manifest_identity,
            &mut link_transport,
        )?;
        if genesis_epoch.get().checked_add(u64::from(index))
            != Some(next.outgoing_context.epoch().get())
        {
            return Err(invalid("chain link skips, duplicates or reorders an epoch"));
        }
        committees.push_link(root, index, &next)?;
        record_registrations(&mut owners, root, &committees, &next)?;
        previous.push(current);
        current = next;
    }
    Ok(VerifiedSuccessorChain {
        current,
        previous,
        committees: std::sync::Arc::new(committees),
        owners: std::sync::Arc::new(owners),
        link_count,
    })
}

/// The existing single-link entries: the same owner with budget 1.
pub(super) fn verify_single_link(
    plan: BusinessReconstructionPlan<'_>,
    manifest_identity: &OrderedHistoryIdentity,
    artifacts: &mut dyn SuccessorArtifactSource,
) -> Result<VerifiedSuccessorChain, SuccessorActivationError> {
    let pins: [SuccessorLinkPins; 1] = [SuccessorLinkPins {
        cut_identity: plan.ordered_history_identity.clone(),
        manifest_identity: manifest_identity.clone(),
    }];
    let mut single: SingleLinkArtifacts<'_> = SingleLinkArtifacts(artifacts);
    verify_chain(plan, &pins, SuccessorChainBudget::ONE, &mut single)
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_types::HashAlgorithmId;

    fn root() -> VerifiedGenesisRoot {
        crate::serving_authority::tests::causal_root()
    }

    fn digest(seed: u8) -> Digest32 {
        Digest32::new(HashAlgorithmId::Sha2_256, [seed; 32])
    }

    #[test]
    fn budget_reports_its_configured_value_and_one_is_one() {
        let budget: SuccessorChainBudget = SuccessorChainBudget::new(NonZeroU32::new(8).unwrap());
        assert_eq!(budget.get(), 8);
        assert_eq!(SuccessorChainBudget::ONE.get(), 1);
    }

    #[test]
    fn genesis_registries_hold_exactly_the_signed_committee_and_owners() {
        let root: VerifiedGenesisRoot = root();
        let committees: VerifiedCommitteeHistory =
            VerifiedCommitteeHistory::genesis(&root).unwrap();
        let epoch: Epoch = root.genesis_context().epoch();
        assert_eq!(committees.len(), 1);
        assert_eq!(
            committees.provenance(epoch),
            Some(CommitteeProvenance::Genesis)
        );
        let (set, digest): (&ValidatorSet, Digest32) = committees.get(epoch).unwrap();
        assert_eq!(set, root.genesis_committee());
        assert_eq!(digest, set.digest(root.genesis_resolver()).unwrap());
        assert!(committees.get(Epoch::new(epoch.get() + 1)).is_none());
        let owners: VerifiedOwnerRegistry = VerifiedOwnerRegistry::genesis(&root).unwrap();
        assert_eq!(owners.len(), root.genesis_committee().validators().len());
        for validator in root.genesis_committee().validators() {
            let entry: &OwnerEntry = owners.owner(validator.id).unwrap();
            assert_eq!(entry.key().as_slice(), validator.public_key.as_slice());
            assert_eq!(
                entry.provenance(),
                &OwnerProvenance::Genesis {
                    genesis_digest: root.digest()
                }
            );
            assert!(owners.names(validator.id, &validator.public_key));
        }
    }

    #[test]
    fn owner_registry_carries_identical_identity_and_refuses_any_reuse() {
        let root: VerifiedGenesisRoot = root();
        let mut owners: VerifiedOwnerRegistry = VerifiedOwnerRegistry::genesis(&root).unwrap();
        let before: usize = owners.len();
        let registered: OwnerEntry = OwnerEntry {
            validator_id: ValidatorId::new([0x71; 32]),
            scheme: SignatureSchemeId::Ed25519,
            key: [0x71; 32],
            provenance: OwnerProvenance::Registration {
                anchor_epoch: root.genesis_context().epoch(),
                intent_digest: digest(0x72),
                initial_row_digest: digest(0x73),
            },
        };
        owners.insert(registered.clone()).unwrap();
        // The same identity carried into a later link is not a conflict.
        owners.insert(registered.clone()).unwrap();
        assert_eq!(owners.len(), before + 1);
        // Same id and key, other provenance: a replayed registration.
        let mut replayed: OwnerEntry = registered.clone();
        replayed.provenance = OwnerProvenance::Registration {
            anchor_epoch: Epoch::new(root.genesis_context().epoch().get() + 1),
            intent_digest: digest(0x74),
            initial_row_digest: digest(0x73),
        };
        assert!(owners.insert(replayed).is_err());
        // A retired genesis key under a fresh id.
        let genesis_key: [u8; 32] = root.genesis_committee().validators()[0]
            .public_key
            .as_slice()
            .try_into()
            .unwrap();
        let mut reused_key: OwnerEntry = registered.clone();
        reused_key.validator_id = ValidatorId::new([0x75; 32]);
        reused_key.key = genesis_key;
        assert!(owners.insert(reused_key).is_err());
        // A fresh key under an existing id.
        let mut reused_id: OwnerEntry = registered;
        reused_id.key = [0x76; 32];
        assert!(owners.insert(reused_id).is_err());
        assert_eq!(owners.len(), before + 1);
    }
}
