//! Invocation-local publication cache. New-node budget precedes storage I/O;
//! byte budget precedes decoding/authentication/retention of a returned row.
use super::*;

#[derive(Clone)]
struct CachedPublication {
    candidate: AuthenticatedPublicationCandidate,
    request_id: Option<[u8; 32]>,
}
/// Private to node admission: create once for one store/domain/operation and
/// discard after that invocation. Cached assertions must join the final CAS.
#[derive(Default)]
pub(crate) struct PublicationLoadBudget {
    nodes: BTreeMap<PackageOrigin, CachedPublication>,
    reads: BTreeMap<Vec<u8>, StateRevision>,
    bytes: usize,
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
    let total: usize = budget
        .bytes
        .checked_add(bytes.len())
        .ok_or(PublicationAdmissionError::Limit)?;
    if total > MAX_PUBLICATION_CLOSURE_BYTES {
        return Err(PublicationAdmissionError::Limit);
    }
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
        &mut budget.reads,
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
    insert_read(&mut budget.reads, key, observed.revision())?;
    let cached: CachedPublication = CachedPublication {
        candidate,
        request_id: Some(request_id),
    };
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
    if root_bytes > MAX_PUBLICATION_CLOSURE_BYTES {
        return Err(PublicationAdmissionError::Limit);
    }
    let mut budget: PublicationLoadBudget = PublicationLoadBudget {
        nodes: BTreeMap::new(),
        reads: reads.clone(),
        bytes: root_bytes,
    };
    budget.nodes.insert(
        candidate.artifact().origin().clone(),
        CachedPublication {
            candidate: candidate.clone(),
            request_id: None,
        },
    );
    let result = interface(
        store,
        context,
        domain,
        resolver,
        history,
        candidate,
        &mut budget,
    )?;
    *reads = budget.reads;
    Ok(result)
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
    let request_id: [u8; 32] = root
        .request_id
        .ok_or(PublicationAdmissionError::CorruptRecord)?;
    let view: execution::publication::VerifiedPublicationInterface = interface(
        store,
        context,
        domain,
        resolver,
        history,
        root.candidate.clone(),
        budget,
    )?;
    let legacy_request: execution::publication::PublicationRequest = root
        .candidate
        .request()
        .ok_or(PublicationAdmissionError::CorruptRecord)?
        .clone();
    let submission: PublicationSubmission = PublicationSubmission::new(request_id, legacy_request)?;
    let reads: Vec<StateReadAssertion> = budget
        .reads
        .iter()
        .map(|(key, revision)| StateReadAssertion::new(key.clone(), *revision))
        .collect::<Result<_, RuntimeError>>()?;
    Ok(Some(VerifiedDurablePublication {
        submission,
        interface: view,
        reads,
    }))
}
