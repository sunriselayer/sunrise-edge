//! Invocation-local publication cache. New-node budget precedes storage I/O;
//! byte budget precedes decoding/authentication/retention of a returned row.
//!
//! A stored row is dispatched by its strict canonical frame type: the legacy
//! `PublicationSubmission` frame [`PUBLICATION_SUBMISSION_FRAME_TYPE`] keeps
//! its original verification rules, and the DR-0124 paid `SignedPaidIntent`
//! frame [`SIGNED_PAID_INTENT_FRAME_TYPE`] is
//! reauthenticated under its own trusted original resolver and must present a
//! committed successful paid Publish receipt. No third wrapper type or type ID
//! is allocated, and an unknown type fails closed. Both constants are the
//! same authoritative identifiers their defining `execution` modules encode
//! and decode against, imported rather than re-declared, so dispatch here can
//! never drift from the canonical wire type.
use super::*;
use execution::paid_execution::{
    MAX_SIGNED_PAID_INTENT_BYTES, PaidApplication, SIGNED_PAID_INTENT_FRAME_TYPE, SignedPaidIntent,
    authenticate_paid_intent, authenticate_paid_publication_candidate, decode_signed_paid_intent,
};
use execution::publication::PUBLICATION_SUBMISSION_FRAME_TYPE;

/// The actual provenance of one cached node.
#[derive(Clone)]
enum CachedProvenance {
    /// The root candidate of an in-flight admission that is not stored yet.
    Unstored,
    /// A stored legacy submission and its signed request identity.
    Legacy([u8; 32]),
    /// A stored paid Publish frame whose successful receipt was verified.
    Paid([u8; 32]),
}

#[derive(Clone)]
struct CachedPublication {
    candidate: AuthenticatedPublicationCandidate,
    provenance: CachedProvenance,
}
/// Private to node admission: create once for one store/domain/operation and
/// discard after that invocation. Cached assertions must join the final CAS.
#[derive(Default)]
pub(crate) struct PublicationLoadBudget {
    nodes: BTreeMap<PackageOrigin, CachedPublication>,
    reads: BTreeMap<Vec<u8>, StateRevision>,
    bytes: usize,
}

impl PublicationLoadBudget {
    /// Folds every read this budget accumulated into a caller's shared read
    /// map. Callers must carry the merged map into their fenced commit, so a
    /// policy or record row that changed under them rejects the whole
    /// invocation.
    pub(crate) fn merge_reads(
        &self,
        reads: &mut BTreeMap<Vec<u8>, StateRevision>,
    ) -> Result<(), PublicationAdmissionError> {
        for (key, revision) in &self.reads {
            insert_read(reads, key.clone(), *revision)?;
        }
        Ok(())
    }
}

/// Verifies one stored legacy `PublicationSubmission` row exactly as before.
#[allow(clippy::too_many_arguments)]
fn legacy_node<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    origin: &PackageOrigin,
    expected: Option<&UnverifiedDependencyRef>,
    bytes: &[u8],
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> Result<CachedPublication, PublicationAdmissionError> {
    let submission: PublicationSubmission = decode_publication_submission(bytes)?;
    if submission.request().artifact().origin() != origin
        || encode_publication_submission(&submission)? != bytes
    {
        return Err(PublicationAdmissionError::CorruptRecord);
    }
    if let Some(reference) = expected {
        match_reference(
            reference,
            submission.request().artifact(),
            submission.request().artifact_digest(),
        )?;
    }
    let policy: LocalPublicationPolicy = read_policy(
        store,
        context,
        domain,
        submission.request().artifact().context(),
        submission.request().artifact().wasm_profile(),
        reads,
    )?;
    let original: &HashSuiteResolver = resolver_for(resolver, history, policy.context())?;
    verify_publication_receipt(store, context, domain, original, &submission)?;
    let request_id: [u8; 32] = *submission.request_id();
    let candidate: AuthenticatedPublicationCandidate = authenticate_publication_submission(
        original,
        policy.context(),
        policy.semantics(),
        submission,
    )?;
    Ok(CachedPublication {
        candidate,
        provenance: CachedProvenance::Legacy(request_id),
    })
}

/// Verifies one stored DR-0124 paid Publish row.
///
/// The row is reauthenticated under the trusted original resolver selected for
/// its own recorded protocol context, its candidate is derived from that
/// authenticated intent alone (never from a fabricated `PublicationRequest`),
/// and its committed successful paid Publish receipt is required before the
/// artifact may be returned as a dependency.
#[allow(clippy::too_many_arguments)]
fn paid_node<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    origin: &PackageOrigin,
    expected: Option<&UnverifiedDependencyRef>,
    bytes: &[u8],
) -> Result<CachedPublication, PublicationAdmissionError> {
    if bytes.len() > MAX_SIGNED_PAID_INTENT_BYTES {
        return Err(PublicationAdmissionError::Limit);
    }
    let signed: SignedPaidIntent = decode_signed_paid_intent(bytes)?;
    let PaidApplication::Publish(artifact) = &signed.intent.application else {
        return Err(PublicationAdmissionError::CorruptRecord);
    };
    if artifact.origin() != origin {
        return Err(PublicationAdmissionError::CorruptRecord);
    }
    let original: &HashSuiteResolver = resolver_for(resolver, history, &signed.intent.context)?;
    let authenticated: AuthenticatedPaidIntent =
        authenticate_paid_intent(original, &signed.intent.context, bytes)?;
    let request_id: [u8; 32] =
        verify_paid_publication_receipt(store, context, domain, original, &authenticated, origin)?;
    let candidate: AuthenticatedPublicationCandidate =
        authenticate_paid_publication_candidate(original, &authenticated)?;
    if let Some(reference) = expected {
        match_reference(reference, candidate.artifact(), candidate.digest())?;
    }
    Ok(CachedPublication {
        candidate,
        provenance: CachedProvenance::Paid(request_id),
    })
}

#[allow(clippy::too_many_arguments)]
fn load_node<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    origin: &PackageOrigin,
    expected: Option<&UnverifiedDependencyRef>,
    budget: &mut PublicationLoadBudget,
) -> Result<Option<CachedPublication>, PublicationAdmissionError> {
    if origin.chain_id() != resolver.chain_id() {
        return Err(PublicationAdmissionError::CorruptRecord);
    }
    if let Some(cached) = budget.nodes.get(origin) {
        if let Some(reference) = expected {
            match_reference(
                reference,
                cached.candidate.artifact(),
                cached.candidate.digest(),
            )?;
        }
        return Ok(Some(cached.clone()));
    }
    if budget.nodes.len() >= MAX_INTERFACE_NODES {
        return Err(PublicationAdmissionError::Limit);
    }
    let key: Vec<u8> = publication_record_key(origin)?;
    let observed: VersionedStateValue = store.get_versioned_durable(context, domain, &key)?;
    let Some(bytes) = observed.value() else {
        if expected.is_some() {
            return Err(PublicationAdmissionError::MissingDependency);
        }
        return if observed.revision() == StateRevision::INITIAL {
            Ok(None)
        } else {
            Err(PublicationAdmissionError::CorruptRecord)
        };
    };
    // The budget counts the exact stored bytes of every retained row, never an
    // approximate candidate `encoded_len`.
    let total: usize = budget
        .bytes
        .checked_add(bytes.len())
        .ok_or(PublicationAdmissionError::Limit)?;
    if total > MAX_PUBLICATION_CLOSURE_BYTES {
        return Err(PublicationAdmissionError::Limit);
    }
    // Strict canonical type dispatch; no third wrapper frame exists and an
    // unknown stored type fails closed.
    let frame: canonical_encoding::CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
    let cached: CachedPublication = match frame.type_id() {
        PUBLICATION_SUBMISSION_FRAME_TYPE => legacy_node(
            store,
            context,
            domain,
            resolver,
            history,
            origin,
            expected,
            bytes,
            &mut budget.reads,
        )?,
        SIGNED_PAID_INTENT_FRAME_TYPE => paid_node(
            store, context, domain, resolver, history, origin, expected, bytes,
        )?,
        _ => return Err(PublicationAdmissionError::CorruptRecord),
    };
    insert_read(&mut budget.reads, key, observed.revision())?;
    budget.bytes = total;
    budget.nodes.insert(origin.clone(), cached.clone());
    Ok(Some(cached))
}

#[allow(clippy::too_many_arguments)]
fn interface<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    root: AuthenticatedPublicationCandidate,
    budget: &mut PublicationLoadBudget,
) -> Result<execution::publication::VerifiedPublicationInterface, PublicationAdmissionError> {
    let mut pending: Vec<UnverifiedDependencyRef> =
        root.artifact().unverified_dependencies().to_vec();
    let mut loaded: BTreeMap<PackageOrigin, AuthenticatedPublicationCandidate> = BTreeMap::new();
    while let Some(reference) = pending.pop() {
        if reference.origin() == root.artifact().origin() {
            return Err(PublicationAdmissionError::CorruptRecord);
        }
        if let Some(existing) = loaded.get(reference.origin()) {
            match_reference(&reference, existing.artifact(), existing.digest())?;
            continue;
        }
        let node: CachedPublication = load_node(
            store,
            context,
            domain,
            resolver,
            history,
            reference.origin(),
            Some(&reference),
            budget,
        )?
        .ok_or(PublicationAdmissionError::MissingDependency)?;
        pending.extend(
            node.candidate
                .artifact()
                .unverified_dependencies()
                .iter()
                .cloned(),
        );
        loaded.insert(reference.origin().clone(), node.candidate);
    }
    Ok(verify_publication_interface(
        root,
        loaded.into_values().collect(),
    )?)
}

/// Resolves the complete durable dependency closure of a root candidate that
/// is not stored yet, inside a shared invocation-local budget.
///
/// The root occupies one node and its exact ingress byte length in the same
/// budget every stored dependency uses, so one invocation cannot exceed the
/// closure bounds by splitting its reads across several loader calls. The root
/// itself is never treated as durable provenance: it is only the in-flight
/// candidate whose dependencies must already be durably published.
#[allow(clippy::too_many_arguments)]
pub(crate) fn load_unstored_root_with_budget<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    candidate: AuthenticatedPublicationCandidate,
    root_bytes: usize,
    budget: &mut PublicationLoadBudget,
) -> Result<execution::publication::VerifiedPublicationInterface, PublicationAdmissionError> {
    if history.len() > MAX_PUBLICATION_HISTORY {
        return Err(PublicationAdmissionError::Limit);
    }
    let origin: PackageOrigin = candidate.artifact().origin().clone();
    // A root that is already durably published in this same budget is not an
    // unstored root; admission separately asserts origin absence.
    if budget.nodes.contains_key(&origin) {
        return Err(PublicationAdmissionError::OriginExists);
    }
    if budget.nodes.len() >= MAX_INTERFACE_NODES {
        return Err(PublicationAdmissionError::Limit);
    }
    let total: usize = budget
        .bytes
        .checked_add(root_bytes)
        .ok_or(PublicationAdmissionError::Limit)?;
    if total > MAX_PUBLICATION_CLOSURE_BYTES {
        return Err(PublicationAdmissionError::Limit);
    }
    budget.bytes = total;
    budget.nodes.insert(
        origin,
        CachedPublication {
            candidate: candidate.clone(),
            provenance: CachedProvenance::Unstored,
        },
    );
    interface(store, context, domain, resolver, history, candidate, budget)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn load_unstored_root<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    candidate: AuthenticatedPublicationCandidate,
    root_bytes: usize,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> Result<execution::publication::VerifiedPublicationInterface, PublicationAdmissionError> {
    let mut budget: PublicationLoadBudget = PublicationLoadBudget {
        nodes: BTreeMap::new(),
        reads: reads.clone(),
        bytes: 0,
    };
    let result = load_unstored_root_with_budget(
        store,
        context,
        domain,
        resolver,
        history,
        candidate,
        root_bytes,
        &mut budget,
    )?;
    *reads = budget.reads;
    Ok(result)
}

/// Resolves the exact durable dependency closure of one authenticated paid
/// Publish candidate, and returns both the verified interface and the exact
/// dependency candidate vector the engine and the independent verifier must
/// both receive. It grants no publication authority: the caller separately
/// asserts origin absence and commits the record only on a verified success.
#[allow(clippy::too_many_arguments)]
pub(crate) fn load_paid_publish_closure<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    candidate: AuthenticatedPublicationCandidate,
    root_bytes: usize,
    budget: &mut PublicationLoadBudget,
) -> Result<
    (
        execution::publication::VerifiedPublicationInterface,
        Vec<AuthenticatedPublicationCandidate>,
    ),
    PublicationAdmissionError,
> {
    let interface = load_unstored_root_with_budget(
        store, context, domain, resolver, history, candidate, root_bytes, budget,
    )?;
    let dependencies: Vec<AuthenticatedPublicationCandidate> = interface.dependencies().to_vec();
    Ok((interface, dependencies))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn load_verified_publication_with_budget<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    origin: &PackageOrigin,
    budget: &mut PublicationLoadBudget,
) -> Result<Option<VerifiedDurablePublication>, PublicationAdmissionError> {
    if history.len() > MAX_PUBLICATION_HISTORY {
        return Err(PublicationAdmissionError::Limit);
    }
    let Some(root) = load_node(
        store, context, domain, resolver, history, origin, None, budget,
    )?
    else {
        return Ok(None);
    };
    let view: execution::publication::VerifiedPublicationInterface = interface(
        store,
        context,
        domain,
        resolver,
        history,
        root.candidate.clone(),
        budget,
    )?;
    let record: VerifiedPublicationRecord = match root.provenance {
        CachedProvenance::Legacy(request_id) => {
            let legacy_request: execution::publication::PublicationRequest = root
                .candidate
                .request()
                .ok_or(PublicationAdmissionError::CorruptRecord)?
                .clone();
            VerifiedPublicationRecord::Legacy(PublicationSubmission::new(
                request_id,
                legacy_request,
            )?)
        }
        CachedProvenance::Paid(request_id) => VerifiedPublicationRecord::Paid { request_id },
        // `load_node` only ever returns stored provenance.
        CachedProvenance::Unstored => return Err(PublicationAdmissionError::CorruptRecord),
    };
    let reads: Vec<StateReadAssertion> = budget
        .reads
        .iter()
        .map(|(key, revision)| StateReadAssertion::new(key.clone(), *revision))
        .collect::<Result<_, RuntimeError>>()?;
    Ok(Some(VerifiedDurablePublication {
        record,
        interface: view,
        reads,
    }))
}

#[cfg(test)]
mod dispatch_tests {
    use super::{PUBLICATION_SUBMISSION_FRAME_TYPE, SIGNED_PAID_INTENT_FRAME_TYPE};

    /// Pins the two dispatch constants to their allocated canonical values.
    /// A change to either constant's defining module without an explicit
    /// protocol/encoding version would break this stable vector rather than
    /// silently redirecting the loader's dispatch to a different frame type.
    #[test]
    fn dispatch_frame_types_are_stable() {
        assert_eq!(PUBLICATION_SUBMISSION_FRAME_TYPE, 0x6308);
        assert_eq!(SIGNED_PAID_INTENT_FRAME_TYPE, 0x6413);
        assert_ne!(
            PUBLICATION_SUBMISSION_FRAME_TYPE,
            SIGNED_PAID_INTENT_FRAME_TYPE
        );
    }
}
