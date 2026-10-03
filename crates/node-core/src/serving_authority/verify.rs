//! The one module-private source-free verifier (DR-0189 Section 3). It
//! never takes a destination store, lifecycle, token or local key, and it
//! reruns completely on every call: there is no cache or memo.

use super::*;
use crate::business_reconstruction::inactive_import::verify_saved_business_import;
use crate::epoch_transition::check_next_set_eligibility;
use crate::genesis::VerifiedGenesisRoot;
use crate::local_instance_state::FASTPATH_STATE_PREFIX;
use crate::ordered_economics::{
    OrderedCandidate, OrderedEconomicsPolicy, OrderedHistoryComponentKind, OrderedHistoryVerifier,
    OrderedOperationKind, SEAL_PREDECESSOR_TAG_GENESIS, SealIntent, SealOutcome,
    VerifiedOrderedHistory, decode_ordered_candidate, decode_seal_cut_identity, decode_seal_intent,
    decode_seal_outcome, ordered_economics_successor_anchor, ordered_history_component_digest,
    seal_certificate_digest, seal_cut_identity_digest, seal_next_members, seal_target_digest,
};
use crate::{NodeDedupRecord, NodeResponseStatus};
use consensus::readiness::{
    MAX_READINESS_CERTIFICATE_BYTES, ReadinessCertificate, ReadinessCertifier, ReadinessSubject,
    decode_readiness_certificate, encode_readiness_certificate,
};
use consensus::{CommittedBlock, CommittedBlockProof, decode_committed_block_proof};
use hashing::HashSuiteResolver;
use protocol_types::Epoch;
use runtime::inactive_import::{ImportBinding, ImportRow};
use runtime::{VersionedStateReader, VersionedStateValue};

fn invalid(message: &'static str) -> SuccessorActivationError {
    SuccessorActivationError::Invalid(message)
}

/// Read-only state view over the exact re-executed plan `State` rows only.
/// It is the eligibility input of Section 3 step 6, never a destination
/// observation: a present row reads at a fixed non-initial revision, an
/// explicit deletion as a tombstone and an absent key as virgin.
struct PlanStateReader<'a> {
    rows: BTreeMap<&'a [u8], Option<&'a [u8]>>,
}

impl<'a> PlanStateReader<'a> {
    fn new(rows: &'a [ImportRow]) -> Self {
        let mut map: BTreeMap<&'a [u8], Option<&'a [u8]>> = BTreeMap::new();
        for row in rows {
            if let ImportRow::State { key, value } = row {
                map.insert(key.as_slice(), value.as_deref());
            }
        }
        Self { rows: map }
    }
}

impl VersionedStateReader for PlanStateReader<'_> {
    fn read_versioned_state(
        &self,
        _context: &DurableOperationContext,
        _domain: AtomicityDomainId,
        key: &[u8],
    ) -> Result<VersionedStateValue, DurableReadError> {
        let (revision, value): (StateRevision, Option<Vec<u8>>) = match self.rows.get(key) {
            None => (StateRevision::INITIAL, None),
            Some(value) => (StateRevision::new(1), value.map(<[u8]>::to_vec)),
        };
        VersionedStateValue::from_persisted_parts(revision, value)
            .map_err(|_| DurableReadError::InvalidPersistedState)
    }
}

fn component(
    material: &OrderedHistoryHeightMaterial,
    kind: OrderedHistoryComponentKind,
) -> Result<&[u8], SuccessorActivationError> {
    material
        .components
        .iter()
        .find(|(found, _)| *found == kind)
        .map(|(_, bytes)| bytes.as_slice())
        .ok_or(invalid("successor history component is missing"))
}

fn decode_proof(bytes: &[u8]) -> Result<CommittedBlockProof, SuccessorActivationError> {
    decode_committed_block_proof(bytes).map_err(|_| invalid("successor history proof encoding"))
}

/// Section 3 step 7: the raw plan must carry no epoch-scoped ordered row and
/// no live fast-path object or sender-nonce lock before activation.
fn refuse_plan_rows(rows: &[ImportRow]) -> Result<(), SuccessorActivationError> {
    let lock_prefix: Vec<u8> = [FASTPATH_STATE_PREFIX, b"lock/"].concat();
    let nonce_lock_prefix: Vec<u8> = [FASTPATH_STATE_PREFIX, b"nonce-lock/"].concat();
    for row in rows {
        let ImportRow::State { key, value } = row else {
            continue;
        };
        if crate::ordered_economics::engine::is_successor_scoped_ordered_key(key) {
            return Err(invalid("raw plan carries an epoch-scoped ordered row"));
        }
        if value.is_some() && (key.starts_with(&lock_prefix) || key.starts_with(&nonce_lock_prefix))
        {
            return Err(invalid("raw plan carries a live fast-path lock"));
        }
    }
    Ok(())
}

/// The original pinned genesis authority, its ordered policy and the cut
/// binding must all name the same outgoing chain, protocol, epoch, domain
/// and genesis. The predecessor policy is chain-scoped, never a successor.
fn require_predecessor(
    root: &VerifiedGenesisRoot,
    policy: &OrderedEconomicsPolicy,
    domain: AtomicityDomainId,
    binding: &ImportBinding,
) -> Result<(), SuccessorActivationError> {
    let context: &PublicationContext = root.genesis_context();
    if policy.key_scope().is_successor()
        || policy.genesis_digest() != root.digest()
        || policy.context() != context
        || policy.domain() != domain
        || root.manifest().minimum_freeze_block_height == 0
    {
        return Err(invalid(
            "successor predecessor policy is not the original pinned genesis authority",
        ));
    }
    if &binding.context.chain_id != context.chain_id()
        || binding.context.protocol_version != context.protocol_version()
        || binding.context.epoch != context.epoch()
        || binding.domain != domain
        || binding.genesis_digest != root.digest()
    {
        return Err(invalid(
            "verified cut binding differs from the pinned genesis",
        ));
    }
    Ok(())
}

/// Everything Section 3 steps 2 and 3 extract from the history through h.
struct VerifiedSuffix {
    suffix_proofs: Vec<(u64, Vec<u8>)>,
    seal_block: CommittedBlock,
    seal_material: OrderedHistoryHeightMaterial,
}

/// Independently verified facts the final derivation consumes.
struct Verified<'v> {
    import: VerifiedImportPlan,
    binding: ImportBinding,
    outgoing_context: PublicationContext,
    next_members: Vec<FastPathValidatorEntry>,
    next_set: ValidatorSet,
    intent: &'v SealIntent,
    seal_target: Digest32,
    seal_proof_bytes: &'v [u8],
    seal: SealClosure,
}

/// Derives the 0xD054 subject, the 0xD055 manifest, the e+1 context and the
/// v3 anchor from verified facts only, and assembles the evidence.
fn finish(
    resolver: &HashSuiteResolver,
    root: &VerifiedGenesisRoot,
    policy: &OrderedEconomicsPolicy,
    manifest_identity: &OrderedHistoryIdentity,
    verified: Verified<'_>,
    suffix: &VerifiedSuffix,
) -> Result<VerifiedSuccessorActivation, SuccessorActivationError> {
    let readiness: &ReadinessSubject = &verified.intent.readiness_subject;
    let successor_context: PublicationContext = PublicationContext::new(
        readiness.chain_id.clone(),
        readiness.protocol_version,
        readiness.next_epoch,
    )
    .map_err(|_| invalid("successor publication context"))?;
    let subject: SuccessorActivationSubject = SuccessorActivationSubject {
        chain_id: readiness.chain_id.clone(),
        protocol_version: readiness.protocol_version,
        outgoing_epoch: readiness.epoch,
        genesis_digest: root.digest(),
        domain: verified.binding.domain,
        seal_target: verified.seal_target,
        seal_request: verified.seal.request_id,
        seal_height: suffix.seal_block.height,
        seal_block_digest: suffix.seal_block.digest,
        successor_epoch: readiness.next_epoch,
        successor_set_digest: readiness.next_set_digest,
        schedule_digest: readiness.schedule_digest,
        cut_digest: readiness.cut_digest,
    };
    let subject_digest: Digest32 = successor_activation_subject_digest(resolver, &subject)?;
    let seal_proof_length: u32 = u32::try_from(verified.seal_proof_bytes.len())
        .map_err(|_| invalid("Seal proof length overflow"))?;
    let manifest: SuccessorActivationManifest = SuccessorActivationManifest {
        subject: subject.clone(),
        certificate_digest: verified.intent.certificate_digest,
        certificate_length: verified.intent.certificate_length,
        history: manifest_identity.clone(),
        seal_proof_digest: ordered_history_component_digest(policy, verified.seal_proof_bytes)?,
        seal_proof_length,
        package_digest: verified.binding.package_digest,
        plan_digest: verified.binding.plan_digest,
    };
    let manifest_digest: Digest32 = successor_activation_manifest_digest(resolver, &manifest)?;
    let anchor: Digest32 = ordered_economics_successor_anchor(
        resolver,
        &successor_context,
        verified.binding.domain,
        root.digest(),
        root.manifest().minimum_freeze_block_height,
        &verified.next_set,
        subject_digest,
    )?;
    let policy_inputs: SuccessorPolicyInputs = SuccessorPolicyInputs {
        context: successor_context,
        domain: verified.binding.domain,
        subject_digest,
        genesis_digest: root.digest(),
        validator_set: verified.next_set,
        anchor,
        generation_floor: verified.binding.generation_floor,
    };
    Ok(VerifiedSuccessorActivation {
        subject,
        subject_digest,
        manifest_digest,
        import: verified.import,
        next_members: verified.next_members,
        policy_inputs,
        outgoing_context: verified.outgoing_context,
        suffix_proofs: suffix.suffix_proofs.clone(),
        seal: verified.seal,
    })
}

/// Section 3 steps 2 and 3: reuse the existing ordered-history verifier for
/// heights 1 through h, with its narrowly scoped terminal-Seal extension, and
/// add the cut-height, empty-gap, terminal-shape and predecessor-link checks.
fn verify_suffix(
    policy: &OrderedEconomicsPolicy,
    cut_identity: &OrderedHistoryIdentity,
    manifest_identity: &OrderedHistoryIdentity,
    artifacts: &mut dyn SuccessorArtifactSource,
) -> Result<VerifiedSuffix, SuccessorActivationError> {
    let cut_height: u64 = cut_identity.through_height;
    let seal_height: u64 = manifest_identity.through_height;
    if manifest_identity.context != cut_identity.context
        || manifest_identity.domain != cut_identity.domain
        || manifest_identity.genesis_digest != cut_identity.genesis_digest
        || manifest_identity.anchor != cut_identity.anchor
        || seal_height <= cut_height
    {
        return Err(invalid(
            "manifest history is not a strict extension of the cut history",
        ));
    }
    let predecessor_height: u64 = seal_height
        .checked_sub(1)
        .filter(|height: &u64| *height != 0)
        .ok_or(invalid("successor Seal height has no predecessor height"))?;
    let mut verifier: OrderedHistoryVerifier =
        OrderedHistoryVerifier::new(policy.clone(), manifest_identity.clone())?;
    let mut suffix_proofs: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut predecessor_child: Option<Digest32> = None;
    let mut terminal: Option<(CommittedBlock, OrderedHistoryHeightMaterial)> = None;
    for height in 1..=seal_height {
        let material: OrderedHistoryHeightMaterial =
            artifacts.history_height(manifest_identity, height)?;
        let block: CommittedBlock = verifier.verify_next_height(&material)?;
        if height == cut_height
            && (block.view != cut_identity.through_view
                || block.digest != cut_identity.through_digest)
        {
            return Err(invalid(
                "history block at the cut height differs from the cut",
            ));
        }
        if height > cut_height {
            if height < seal_height && !block.transactions.is_empty() {
                return Err(invalid("history between the cut and the Seal is not empty"));
            }
            let proof_bytes: Vec<u8> =
                component(&material, OrderedHistoryComponentKind::CommitProof)?.to_vec();
            suffix_proofs.push((height, proof_bytes));
        }
        if height == predecessor_height {
            let proof: CommittedBlockProof = decode_proof(component(
                &material,
                OrderedHistoryComponentKind::CommitProof,
            )?)?;
            predecessor_child = Some(
                policy
                    .engine()
                    .proposal_digest(&proof.child)
                    .map_err(|_| invalid("successor predecessor child digest"))?,
            );
        }
        if height == seal_height {
            terminal = Some((block, material));
        }
    }
    let verified: VerifiedOrderedHistory = verifier.finish()?;
    if verified.identity() != manifest_identity {
        return Err(invalid(
            "verified history identity differs from the manifest",
        ));
    }
    let (seal_block, seal_material): (CommittedBlock, OrderedHistoryHeightMaterial) =
        terminal.ok_or(invalid("successor history has no terminal height"))?;
    if predecessor_child != Some(seal_block.digest) {
        return Err(invalid(
            "Seal predecessor child does not link to the Seal block",
        ));
    }
    let kinds: Vec<OrderedHistoryComponentKind> = seal_material
        .components
        .iter()
        .map(|(kind, _)| *kind)
        .collect();
    if seal_block.transactions.len() != 1
        || kinds
            != [
                OrderedHistoryComponentKind::CommitProof,
                OrderedHistoryComponentKind::Candidate,
                OrderedHistoryComponentKind::RequestHeader,
                OrderedHistoryComponentKind::RetainedOutcome,
                OrderedHistoryComponentKind::OriginalReceipt,
            ]
    {
        return Err(invalid(
            "terminal height is not one first-occurrence candidate",
        ));
    }
    let seal_proof: CommittedBlockProof = decode_proof(component(
        &seal_material,
        OrderedHistoryComponentKind::CommitProof,
    )?)?;
    if !seal_proof.child.transactions.is_empty() || !seal_proof.grandchild.transactions.is_empty() {
        return Err(invalid("Seal proof child and grandchild are not empty"));
    }
    Ok(VerifiedSuffix {
        suffix_proofs,
        seal_block,
        seal_material,
    })
}

/// Section 3 steps 4 and 5: the exact readiness certificate committed by the
/// terminal SealIntent (one certificate variant per committed Seal), over a
/// subject bound to the plan root, domain, outgoing set, cut and schedule.
fn verify_seal_certificate(
    resolver: &HashSuiteResolver,
    root: &VerifiedGenesisRoot,
    domain: AtomicityDomainId,
    binding: &ImportBinding,
    cut_identity: &OrderedHistoryIdentity,
    intent: &SealIntent,
    artifacts: &mut dyn SuccessorArtifactSource,
) -> Result<ReadinessCertificate, SuccessorActivationError> {
    let context: &PublicationContext = root.genesis_context();
    let subject: &ReadinessSubject = &intent.readiness_subject;
    let cut = decode_seal_cut_identity(intent)?;
    let cut_digest: Digest32 = seal_cut_identity_digest(resolver, &cut)?;
    if &cut.ordered_history != cut_identity
        || cut_digest != subject.cut_digest
        || cut_digest != binding.cut_digest
    {
        return Err(invalid("Seal cut identity differs from the verified cut"));
    }
    if &subject.chain_id != context.chain_id()
        || subject.protocol_version != context.protocol_version()
        || subject.epoch != context.epoch()
        || subject.genesis_digest != root.digest()
        || subject.domain != domain
        || subject.outgoing_set_digest != binding.validator_set_digest
    {
        return Err(invalid("Seal readiness subject differs from the plan root"));
    }
    if intent.predecessor_tag != SEAL_PREDECESSOR_TAG_GENESIS
        || intent.predecessor_digest != root.digest()
    {
        return Err(invalid("Seal predecessor is not the pinned genesis"));
    }
    let length: usize = usize::try_from(intent.certificate_length)
        .map_err(|_| invalid("Seal certificate length overflow"))?;
    if length == 0 || length > MAX_READINESS_CERTIFICATE_BYTES {
        return Err(invalid("Seal certificate length bound"));
    }
    let bytes: Vec<u8> = artifacts.readiness_certificate(intent.certificate_length)?;
    if bytes.len() != length {
        return Err(invalid(
            "readiness certificate length differs from the Seal",
        ));
    }
    if seal_certificate_digest(resolver, context.epoch(), &bytes)? != intent.certificate_digest {
        return Err(invalid(
            "readiness certificate digest differs from the Seal",
        ));
    }
    let certificate: ReadinessCertificate = decode_readiness_certificate(&bytes)?;
    if encode_readiness_certificate(&certificate)? != bytes {
        return Err(invalid("readiness certificate is noncanonical"));
    }
    if &certificate.subject != subject {
        return Err(invalid(
            "readiness certificate subject differs from the Seal",
        ));
    }
    ReadinessCertifier::new(resolver, subject, &certificate.next_set)?
        .verify_certificate(&certificate)?;
    Ok(certificate)
}

/// The one private source-free verifier. Every step reruns on every call.
pub(super) fn verify_successor_activation(
    plan: BusinessReconstructionPlan<'_>,
    manifest_identity: &OrderedHistoryIdentity,
    artifacts: &mut dyn SuccessorArtifactSource,
) -> Result<VerifiedSuccessorActivation, SuccessorActivationError> {
    // Copy every borrowed reference needed after `plan` moves.
    let root: &VerifiedGenesisRoot = plan.genesis_root;
    let policy: &OrderedEconomicsPolicy = plan.ordered_policy;
    let cut_identity: OrderedHistoryIdentity = plan.ordered_history_identity.clone();
    let domain: AtomicityDomainId = plan.domain;
    let operation: DurableOperationContext = plan.operation_context;
    let resolver: HashSuiteResolver = root.genesis_resolver().clone();
    let outgoing_context: PublicationContext = root.genesis_context().clone();
    let outgoing_epoch: Epoch = outgoing_context.epoch();
    // Step 1: independent saved-cut re-execution and exact raw plan.
    let saved: SavedBusinessCut = artifacts.saved_business_cut()?;
    let import: VerifiedImportPlan = verify_saved_business_import(plan, &saved)?;
    let binding: ImportBinding = import.binding().clone();
    require_predecessor(root, policy, domain, &binding)?;
    // Steps 2 and 3: history through the terminal Seal.
    let suffix: VerifiedSuffix =
        verify_suffix(policy, &cut_identity, manifest_identity, artifacts)?;
    let seal_material: &OrderedHistoryHeightMaterial = &suffix.seal_material;
    let candidate_bytes: &[u8] = component(seal_material, OrderedHistoryComponentKind::Candidate)?;
    let candidate: OrderedCandidate = decode_ordered_candidate(candidate_bytes)?;
    let candidate_digest: Digest32 = policy.candidate_digest(&candidate)?;
    if candidate.kind != OrderedOperationKind::Seal
        || candidate.created_checkpoint != cut_identity.through_height
        || suffix.seal_block.transactions.as_slice() != [candidate_digest]
        || candidate.request_id[0] & 0x80 == 0
    {
        return Err(invalid("terminal candidate is not the cut Seal"));
    }
    let intent: SealIntent = decode_seal_intent(&candidate.intent)?;
    // Steps 4 and 5.
    let certificate: ReadinessCertificate = verify_seal_certificate(
        &resolver,
        root,
        domain,
        &binding,
        &cut_identity,
        &intent,
        artifacts,
    )?;
    let subject_identity: Digest32 = intent.readiness_subject.identity(&resolver)?;
    let seal_target: Digest32 = seal_target_digest(
        &resolver,
        &outgoing_context,
        subject_identity,
        intent.predecessor_tag,
        intent.predecessor_digest,
    )?;
    // Step 6: eligibility re-derived from the plan State rows only. Its
    // fencing output is discarded.
    let next_members: Vec<FastPathValidatorEntry> = seal_next_members(&certificate);
    check_next_set_eligibility(
        &PlanStateReader::new(import.rows()),
        &operation,
        domain,
        &binding.context.chain_id,
        outgoing_epoch,
        &next_members,
    )?;
    // Step 7.
    refuse_plan_rows(import.rows())?;
    let receipt_bytes: &[u8] =
        component(seal_material, OrderedHistoryComponentKind::OriginalReceipt)?;
    let receipt: NodeDedupRecord = NodeDedupRecord::decode(receipt_bytes)?;
    if receipt.request_id().as_bytes() != &candidate.request_id {
        return Err(invalid("Seal original receipt names another request"));
    }
    // A committed but refused Seal never seals the source. The original
    // receipt must be the one accepted response carrying the exact 0xD053
    // outcome of this target, request, height and block.
    let accepted: Option<SealOutcome> = match receipt.responses() {
        [response] if response.status() == NodeResponseStatus::Accepted => {
            response.payload().map(decode_seal_outcome).transpose()?
        }
        _ => None,
    };
    let expected_outcome: SealOutcome = SealOutcome {
        target: seal_target,
        request: candidate.request_id,
        seal_block_height: suffix.seal_block.height,
        seal_block_digest: suffix.seal_block.digest,
    };
    if accepted != Some(expected_outcome) {
        return Err(invalid("terminal Seal is not the accepted Seal outcome"));
    }
    let seal_proof_bytes: &[u8] =
        component(seal_material, OrderedHistoryComponentKind::CommitProof)?;
    finish(
        &resolver,
        root,
        policy,
        manifest_identity,
        Verified {
            import,
            binding,
            outgoing_context,
            next_members,
            next_set: certificate.next_set,
            intent: &intent,
            seal_target,
            seal_proof_bytes,
            seal: SealClosure {
                candidate_digest,
                request_id: candidate.request_id,
                candidate: candidate_bytes.to_vec(),
                header: component(seal_material, OrderedHistoryComponentKind::RequestHeader)?
                    .to_vec(),
                outcome: component(seal_material, OrderedHistoryComponentKind::RetainedOutcome)?
                    .to_vec(),
                receipt: receipt_bytes.to_vec(),
                receipt_event_digest: receipt.event_digest(),
            },
        },
        &suffix,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::genesis::tests as fixture;

    fn state(key: &[u8], value: Option<&[u8]>) -> ImportRow {
        ImportRow::State {
            key: key.to_vec(),
            value: value.map(<[u8]>::to_vec),
        }
    }

    #[test]
    fn plan_reader_distinguishes_present_deleted_and_virgin_rows() {
        let rows: Vec<ImportRow> = vec![
            state(b"plan/present", Some(b"value")),
            state(b"plan/deleted", None),
        ];
        let reader: PlanStateReader<'_> = PlanStateReader::new(&rows);
        let operation: DurableOperationContext = fixture::context(1);
        let domain: AtomicityDomainId = fixture::domain();
        let present: VersionedStateValue = reader
            .read_versioned_state(&operation, domain, b"plan/present")
            .unwrap();
        assert_eq!(present.value(), Some(b"value".as_slice()));
        assert_ne!(present.revision(), StateRevision::INITIAL);
        let deleted: VersionedStateValue = reader
            .read_versioned_state(&operation, domain, b"plan/deleted")
            .unwrap();
        assert_eq!(deleted.value(), None);
        assert_ne!(deleted.revision(), StateRevision::INITIAL);
        let virgin: VersionedStateValue = reader
            .read_versioned_state(&operation, domain, b"plan/absent")
            .unwrap();
        assert_eq!(virgin.value(), None);
        assert_eq!(virgin.revision(), StateRevision::INITIAL);
    }

    #[test]
    fn plan_rows_refuse_every_epoch_scoped_row_and_only_live_locks() {
        let ordered: &[u8] = crate::ordered_economics::engine::ORDERED_ECONOMICS_STATE_PREFIX;
        for infix in [
            b"epoch-state/".as_slice(),
            b"epoch-applied-height/".as_slice(),
            b"epoch-vote-high/".as_slice(),
            b"epoch-leader-proposal/".as_slice(),
            b"epoch-vote/".as_slice(),
        ] {
            let key: Vec<u8> = [ordered, infix, b"planted".as_slice()].concat();
            assert!(refuse_plan_rows(&[state(&key, Some(b"x"))]).is_err());
            assert!(refuse_plan_rows(&[state(&key, None)]).is_err());
        }
        let chain_state: Vec<u8> = [ordered, b"state/".as_slice(), b"chain".as_slice()].concat();
        assert!(refuse_plan_rows(&[state(&chain_state, Some(b"x"))]).is_ok());
        for infix in [b"lock/".as_slice(), b"nonce-lock/".as_slice()] {
            let key: Vec<u8> = [FASTPATH_STATE_PREFIX, infix, b"held".as_slice()].concat();
            assert!(refuse_plan_rows(&[state(&key, Some(b"lock"))]).is_err());
            assert!(refuse_plan_rows(&[state(&key, None)]).is_ok());
        }
    }
}
