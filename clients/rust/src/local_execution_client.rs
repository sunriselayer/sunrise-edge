//! Explicit zero-fee local execution. Endpoint claims are not inclusion proofs.
use crate::{
    Client, ClientError, ExpectedProtocolContext, HashSuiteResolver, LocalSigner, Method,
    NodeResponseStatus, RequestId, Transport, WireRequest,
};
use crypto::SignatureSigner;
use execution::call::{CallIntent, bind_call_intent};
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
    let context: PublicationContext =
        crate::publication_client::trusted_context(resolver, expected)?;
    if call.context != context
        || instance.context.epoch() > expected.epoch()
        || call.sender != *signer.address().as_bytes()
        || call.code != instance.code
        || call.instance != instance_target(resolver, instance)?
    {
        return Err(invalid("signer, context, code or instance mismatch"));
    }
    let metadata = interface
        .executable_abi(call.code.origin())
        .ok_or_else(|| invalid("nonexecutable publication"))?;
    if metadata.initializer.as_deref() != Some(instance.initializer.as_str()) {
        return Err(invalid("instance initializer differs from signed metadata"));
    }
    match mode {
        LocalExecutionMode::Instantiate => {
            if instance.creator != call.sender
                || instance.context != context
                || call.entrypoint != instance.initializer
            {
                return Err(invalid("instance creation authority"));
            }
        }
        LocalExecutionMode::Call => {
            if call.entrypoint == instance.initializer {
                return Err(invalid("initializer cannot be called again"));
            }
        }
    }
    bind_call_intent(&call, interface).map_err(LocalExecutionError::from)?;
    let policy: LocalExecutionPolicy = LocalExecutionPolicy::new(context.clone());
    if call.gas_limit > policy.max_gas() {
        return Err(invalid("gas exceeds committed local policy"));
    }
    let intent: LocalExecutionIntent = LocalExecutionIntent {
        mode,
        policy_digest: policy.digest(resolver)?,
        call,
    };
    let frame: Vec<u8> = local_execution_signing_frame(&context, &intent)?;
    let bytes: Vec<u8> = signer.sign_framed(&frame)?;
    let signature: [u8; 64] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| invalid("signature length"))?;
    let signed: SignedLocalExecutionIntent = SignedLocalExecutionIntent { intent, signature };
    authenticate_local_execution(resolver, &policy, &encode_signed_local_execution(&signed)?)?;
    Ok(signed)
}

impl<T: Transport> Client<T> {
    /// Fetches and authenticates a bounded exact executable publication closure.
    /// All original hash contexts use the caller's resolver, never remote schedules.
    pub fn query_executable_interface(
        &self,
        reference: &UnverifiedDependencyRef,
        resolver: &HashSuiteResolver,
        expected: &ExpectedProtocolContext,
    ) -> Result<VerifiedPublicationInterface, ClientError> {
        let mut pending: Vec<UnverifiedDependencyRef> = vec![reference.clone()];
        let mut candidates: Vec<AuthenticatedPublicationCandidate> = Vec::new();
        let mut origins = std::collections::BTreeSet::new();
        let mut total: usize = 0;
        while let Some(reference) = pending.pop() {
            if !origins.insert(reference.origin().clone()) {
                continue;
            }
            if origins.len() > publication::MAX_INTERFACE_NODES {
                return Err(invalid("publication closure nodes"));
            }
            let semantics = local_execution_semantics(resolver, reference.context())?;
            let submission = self
                .query_publication_in_context(
                    reference.origin(),
                    resolver,
                    expected,
                    reference.context(),
                    &semantics,
                )?
                .ok_or_else(|| invalid("publication absent"))?;
            let request = submission.request();
            let artifact = request.artifact();
            if artifact.revision() != reference.revision()
                || artifact.context() != reference.context()
                || request.artifact_digest() != reference.artifact_digest()
            {
                return Err(invalid("exact code reference mismatch"));
            }
            total = total
                .checked_add(publication::encode_publication_submission(&submission)?.len())
                .ok_or_else(|| invalid("publication closure bytes"))?;
            if total > node_core::publication::MAX_PUBLICATION_CLOSURE_BYTES {
                return Err(invalid("publication closure bytes"));
            }
            pending.extend_from_slice(artifact.unverified_dependencies());
            if pending.len() > publication::MAX_INTERFACE_NODES * publication::MAX_INTERFACE_NODES {
                return Err(invalid("publication closure edges"));
            }
            candidates.push(publication::authenticate_publication_submission(
                resolver,
                reference.context(),
                &semantics,
                submission,
            )?);
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
