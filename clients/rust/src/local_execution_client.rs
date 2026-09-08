//! Explicit zero-fee local execution. Endpoint claims are not inclusion proofs.
use crate::{
    Client, ClientError, ExpectedProtocolContext, HashSuiteResolver, LocalSigner, Method,
    NodeResponseStatus, RequestId, Transport, WireRequest,
};
use crypto::SignatureSigner;
use execution::call::CallIntent;
use execution::local_execution::*;
use execution::publication::{
    self, AuthenticatedPublicationCandidate, PublicationContext, UnverifiedDependencyRef,
    VerifiedPublicationInterface,
};
use node_wire::{
    HttpNodeResult, NODE_EVENT_MEDIA_TYPE, NODE_RESULT_MEDIA_TYPE, QUERY_RESULT_MEDIA_TYPE,
};

fn invalid(message: &'static str) -> ClientError {
    LocalExecutionError::Invalid(message).into()
}

/// Invocation-wide cache. Candidate clones share their Arc-backed publication.
#[derive(Default)]
struct PublicationCache {
    nodes: std::collections::BTreeMap<
        abi::package_types::PackageOrigin,
        (UnverifiedDependencyRef, AuthenticatedPublicationCandidate),
    >,
    bytes: usize,
}
impl PublicationCache {
    fn get(
        &self,
        reference: &UnverifiedDependencyRef,
    ) -> Result<Option<AuthenticatedPublicationCandidate>, ClientError> {
        match self.nodes.get(reference.origin()) {
            Some((prior, candidate)) if prior == reference => Ok(Some(candidate.clone())),
            Some(_) => Err(invalid("conflicting exact code reference")),
            None => Ok(None),
        }
    }
    fn check_new_node(&self) -> Result<(), ClientError> {
        if self.nodes.len() >= execution::call_authorization::MAX_EXECUTION_CODE_NODES {
            return Err(invalid("publication closure nodes"));
        }
        Ok(())
    }
    fn retain(&mut self, candidate: AuthenticatedPublicationCandidate) -> Result<(), ClientError> {
        let request = candidate
            .request()
            .ok_or_else(|| invalid("paid publication candidate has no legacy request"))?;
        let artifact = request.artifact();
        let reference: UnverifiedDependencyRef = UnverifiedDependencyRef::new(
            artifact.origin().clone(),
            artifact.revision(),
            artifact.context().clone(),
            *request.artifact_digest(),
        )?;
        if self.get(&reference)?.is_some() {
            return Ok(());
        }
        self.check_new_node()?;
        // Canonical submission wrapper adds 10 + 6 + 32 + 6 bytes to its request.
        let bytes: usize = self
            .bytes
            .checked_add(publication::encode_publication_request(request)?.len())
            .and_then(|value| value.checked_add(54))
            .ok_or_else(|| invalid("publication closure bytes"))?;
        if bytes > execution::call_authorization::MAX_EXECUTION_CODE_BYTES {
            return Err(invalid("publication closure bytes"));
        }
        self.nodes
            .insert(reference.origin().clone(), (reference, candidate));
        self.bytes = bytes;
        Ok(())
    }
}

/// Signs exact locally pinned instance/code/input bytes after ABI validation.
/// Caller must first verify the remote context independently of TLS.
pub fn build_signed_local_execution(
    signer: &LocalSigner,
    resolver: &HashSuiteResolver,
    expected: &ExpectedProtocolContext,
    mode: LocalExecutionMode,
    call: CallIntent,
    instance: &InstanceRecord,
    interface: &VerifiedPublicationInterface,
) -> Result<SignedLocalExecutionIntent, ClientError> {
    let policy: LocalExecutionPolicy = LocalExecutionPolicy::new(
        crate::publication_client::trusted_context(resolver, expected)?,
    );
    let scopes: Vec<ResolvedExecutionScope> = vec![ResolvedExecutionScope {
        instance: instance.clone(),
        target: instance_target(resolver, instance)?,
        interface: interface.clone(),
    }];
    build_signed_general_execution(
        signer,
        resolver,
        expected,
        &policy,
        mode,
        call,
        Vec::new(),
        &scopes,
    )
}

/// Signs one common execution intent after shared scope/authority validation.
/// The policy and complete exact scopes are locally trusted inputs. Independently
/// verify the endpoint context before calling this offline signing operation.
#[allow(clippy::too_many_arguments)] // Keep trust inputs distinct from unsigned invocation data.
pub fn build_signed_general_execution(
    signer: &LocalSigner,
    resolver: &HashSuiteResolver,
    expected: &ExpectedProtocolContext,
    policy: &LocalExecutionPolicy,
    mode: LocalExecutionMode,
    call: CallIntent,
    authorizations: Vec<execution::call_authorization::CallAuthorization>,
    scopes: &[ResolvedExecutionScope],
) -> Result<SignedLocalExecutionIntent, ClientError> {
    let context: PublicationContext =
        crate::publication_client::trusted_context(resolver, expected)?;
    if policy.context() != &context
        || call.context != context
        || call.sender != *signer.address().as_bytes()
    {
        return Err(invalid("signer or trusted policy context mismatch"));
    }
    let intent: LocalExecutionIntent = LocalExecutionIntent {
        authorizations,
        mode,
        policy_digest: policy.digest(resolver)?,
        call,
    };
    execution::execution_scopes::validate_local_execution_scopes(
        resolver, policy, &intent, scopes,
    )?;
    let frame: Vec<u8> = local_execution_signing_frame(&context, &intent)?;
    let bytes: Vec<u8> = signer.sign_framed(&frame)?;
    let signature: [u8; 64] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| invalid("signature length"))?;
    let signed: SignedLocalExecutionIntent = SignedLocalExecutionIntent { intent, signature };
    authenticate_local_execution(resolver, policy, &encode_signed_local_execution(&signed)?)?;
    Ok(signed)
}

impl<T: Transport> Client<T> {
    /// Resolves only signed exact instance pins; server claims cannot replace them.
    /// Root may be a locally prepared initializer record. Other records must match
    /// their signed revision and record digest under the supplied trusted resolver.
    #[allow(clippy::too_many_arguments)] // Explicit trust inputs and locally pinned root view.
    pub fn query_execution_scopes(
        &self,
        call: &CallIntent,
        authorizations: &[execution::call_authorization::CallAuthorization],
        instance: InstanceRecord,
        interface: VerifiedPublicationInterface,
        resolver: &HashSuiteResolver,
        expected: &ExpectedProtocolContext,
        policy: &LocalExecutionPolicy,
    ) -> Result<Vec<ResolvedExecutionScope>, ClientError> {
        execution::call_authorization::validate_call_authorizations(call, authorizations)?;
        let mut cache: PublicationCache = PublicationCache::default();
        for candidate in std::iter::once(interface.candidate()).chain(interface.dependencies()) {
            cache.retain(candidate.clone())?;
        }
        let mut scopes: Vec<ResolvedExecutionScope> = vec![ResolvedExecutionScope {
            target: instance_target(resolver, &instance)?,
            instance,
            interface,
        }];
        if scopes[0].target != call.instance {
            return Err(invalid("root instance pin mismatch"));
        }
        for target in authorizations
            .iter()
            .flat_map(|entry| [&entry.caller, &entry.callee])
        {
            if scopes.iter().any(|scope| scope.target == target.instance) {
                continue;
            }
            if scopes.len() >= execution::call_authorization::MAX_EXECUTION_SCOPES {
                return Err(invalid("execution scope limit"));
            }
            let record: InstanceRecord = self
                .query_instance(
                    target.instance.creator,
                    target.instance.seed,
                    resolver,
                    expected,
                )?
                .ok_or_else(|| invalid("authorized instance absent"))?;
            if instance_target(resolver, &record)? != target.instance {
                return Err(invalid("authorized instance differs from signed pin"));
            }
            let interface: VerifiedPublicationInterface = self.query_executable_interface_cached(
                &record.code,
                resolver,
                expected,
                policy,
                &mut cache,
            )?;
            scopes.push(ResolvedExecutionScope {
                instance: record,
                target: target.instance.clone(),
                interface,
            });
        }
        Ok(scopes)
    }

    /// Fetches and authenticates a bounded exact executable publication closure.
    /// All original hash contexts use the caller's resolver, never remote schedules.
    pub fn query_executable_interface(
        &self,
        reference: &UnverifiedDependencyRef,
        resolver: &HashSuiteResolver,
        expected: &ExpectedProtocolContext,
    ) -> Result<VerifiedPublicationInterface, ClientError> {
        self.query_executable_interface_for_policy(
            reference,
            resolver,
            expected,
            &LocalExecutionPolicy::new(crate::publication_client::trusted_context(
                resolver, expected,
            )?),
        )
    }

    /// Verifies executable code under explicitly trusted profile capabilities.
    /// Profile three permits exact profile-two dependencies, without retry or downgrade.
    pub fn query_executable_interface_for_policy(
        &self,
        reference: &UnverifiedDependencyRef,
        resolver: &HashSuiteResolver,
        expected: &ExpectedProtocolContext,
        policy: &LocalExecutionPolicy,
    ) -> Result<VerifiedPublicationInterface, ClientError> {
        self.query_executable_interface_cached(
            reference,
            resolver,
            expected,
            policy,
            &mut PublicationCache::default(),
        )
    }

    fn query_executable_interface_cached(
        &self,
        reference: &UnverifiedDependencyRef,
        resolver: &HashSuiteResolver,
        expected: &ExpectedProtocolContext,
        policy: &LocalExecutionPolicy,
        cache: &mut PublicationCache,
    ) -> Result<VerifiedPublicationInterface, ClientError> {
        if policy.context() != &crate::publication_client::trusted_context(resolver, expected)? {
            return Err(invalid("execution policy context"));
        }
        let mut pending: Vec<UnverifiedDependencyRef> = vec![reference.clone()];
        let mut candidates: Vec<AuthenticatedPublicationCandidate> = Vec::new();
        let mut origins: std::collections::BTreeSet<abi::package_types::PackageOrigin> =
            std::collections::BTreeSet::new();
        while let Some(reference) = pending.pop() {
            let cached: Option<AuthenticatedPublicationCandidate> = cache.get(&reference)?;
            if !origins.insert(reference.origin().clone()) {
                continue;
            }
            let candidate: AuthenticatedPublicationCandidate = if let Some(candidate) = cached {
                candidate
            } else {
                cache.check_new_node()?;
                let submission = self
                    .query_publication_with_semantics(
                        reference.origin(),
                        resolver,
                        expected,
                        reference.context(),
                        |artifact| match artifact.wasm_profile() {
                            2 => Ok(local_execution_semantics(resolver, reference.context())?),
                            3 if policy.profile() == 3 => {
                                Ok(general_execution_semantics(resolver, reference.context())?)
                            }
                            _ => Err(invalid("publication profile is not locally permitted")),
                        },
                    )?
                    .ok_or_else(|| invalid("publication absent"))?;
                let request = submission.request();
                let artifact = request.artifact();
                let semantics = *artifact.semantics();
                if artifact.revision() != reference.revision()
                    || artifact.context() != reference.context()
                    || request.artifact_digest() != reference.artifact_digest()
                {
                    return Err(invalid("exact code reference mismatch"));
                }
                let candidate = publication::authenticate_publication_submission(
                    resolver,
                    reference.context(),
                    &semantics,
                    submission,
                )?;
                cache.retain(candidate.clone())?;
                candidate
            };
            let artifact = candidate.artifact();
            let semantics = match artifact.wasm_profile() {
                2 => local_execution_semantics(resolver, reference.context())?,
                3 if policy.profile() == 3 => {
                    general_execution_semantics(resolver, reference.context())?
                }
                _ => return Err(invalid("publication profile is not locally permitted")),
            };
            if artifact.semantics() != &semantics {
                return Err(invalid("publication semantics"));
            }
            pending.extend_from_slice(artifact.unverified_dependencies());
            if pending.len() > publication::MAX_INTERFACE_NODES * publication::MAX_INTERFACE_NODES {
                return Err(invalid("publication closure edges"));
            }
            candidates.push(candidate);
        }
        if candidates.is_empty() {
            return Err(invalid("missing root code"));
        }
        let root = candidates.remove(0);
        publication::verify_publication_interface(root, candidates)
            .map_err(|_| invalid("publication ABI closure"))
    }

    /// Returns the server's canonical instance claim after exact selector/context checks.
    /// Use a locally pinned record when authorizing calls; this unsigned query is not
    /// proof that an instance was created or that its code was executed.
    pub fn query_instance(
        &self,
        creator: [u8; 32],
        seed: [u8; 32],
        resolver: &HashSuiteResolver,
        expected: &ExpectedProtocolContext,
    ) -> Result<Option<InstanceRecord>, ClientError> {
        crate::publication_client::trusted_context(resolver, expected)?;
        self.query_verified_context(expected)?;
        let hex =
            |bytes: &[u8]| -> String { bytes.iter().map(|byte| format!("{byte:02x}")).collect() };
        let request: WireRequest = WireRequest {
            method: Method::Get,
            path: format!("/v1/contracts/instances/{}/{}", hex(&creator), hex(&seed)),
            content_type: None,
            body: vec![],
            deadline: None,
        };
        let response = self.transport().send(&request)?;
        if response.status == 404 {
            return Ok(None);
        }
        let bytes = crate::client::expect_success(response, QUERY_RESULT_MEDIA_TYPE)?;
        let record: InstanceRecord = decode_instance_record(&bytes)?;
        if record.creator != creator
            || record.seed != seed
            || record.context.chain_id() != expected.chain_id()
            || record.context.epoch() > expected.epoch()
        {
            return Err(invalid("instance selector or context"));
        }
        instance_target(resolver, &record)?;
        Ok(Some(record))
    }

    /// Checks exact result selectors, signed-event hash, gas, and outer/inner status.
    pub fn submit_local_execution(
        &self,
        signed: &SignedLocalExecutionIntent,
        resolver: &HashSuiteResolver,
        instance_resolver: &HashSuiteResolver,
    ) -> Result<LocalExecutionResult, ClientError> {
        let request: WireRequest = WireRequest {
            method: Method::Post,
            path: "/v1/contracts/executions".to_owned(),
            content_type: Some(NODE_EVENT_MEDIA_TYPE),
            body: encode_signed_local_execution(signed)?,
            deadline: None,
        };
        let response = self.transport().send(&request)?;
        let result: HttpNodeResult = HttpNodeResult::decode(&crate::client::expect_success(
            response,
            NODE_RESULT_MEDIA_TYPE,
        )?)?;
        let id: RequestId = RequestId::new(signed.intent.call.request_id)?;
        if result.request_id() != id {
            return Err(ClientError::SubmitResponseRequestIdMismatch {
                expected: id,
                actual: result.request_id(),
            });
        }
        let [ack] = result.responses() else {
            return Err(ClientError::ExecutionAcknowledgementMismatch);
        };
        if ack.request_id() != id {
            return Err(ClientError::ExecutionAcknowledgementMismatch);
        }
        let decoded: LocalExecutionResult = decode_local_execution_result(
            ack.payload()
                .ok_or(ClientError::ExecutionAcknowledgementMismatch)?,
        )?;
        validate_local_execution_result(resolver, instance_resolver, signed, &decoded)?;
        let expected_status: NodeResponseStatus = match decoded.effects.status {
            execution::ExecutionStatus::Success => NodeResponseStatus::Accepted,
            execution::ExecutionStatus::Failure { .. } => NodeResponseStatus::Rejected,
        };
        if ack.status() != expected_status {
            return Err(ClientError::ExecutionAcknowledgementMismatch);
        }
        Ok(decoded)
    }
}
