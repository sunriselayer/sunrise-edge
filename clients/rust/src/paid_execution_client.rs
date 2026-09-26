//! Public paid Call/Instantiate/Publish client surface (DR-0126).

use crate::{
    Client, ClientError, ExpectedProtocolContext, HashSuiteResolver, LocalSigner, Method,
    NodeResponseStatus, RequestId, Transport, WireRequest,
};
use crypto::SignatureSigner;
use execution::local_execution::{LocalExecutionPolicy, instance_target};
use execution::paid_execution::{
    FeeSourceConsent, PaidApplication, PaidExecutionResult, PaidExecutionStatus, PaidFeePolicy,
    PaidIntent, PaidResultKind, PaidResultTarget, SignedPaidIntent, authenticate_paid_intent,
    decode_paid_execution_result, decode_paid_fee_policy, encode_signed_paid_intent,
    paid_fee_policy_digest, paid_intent_signing_frame, quote_paid_intent,
};
use execution::publication::PublicationContext;
use execution::publication::{
    AuthenticatedPublicationCandidate, UnverifiedDependencyRef, VerifiedPublicationInterface,
};
use node_wire::{
    HttpNodeResult, NODE_EVENT_MEDIA_TYPE, NODE_RESULT_MEDIA_TYPE, QUERY_RESULT_MEDIA_TYPE,
};
use objects::{Object, Owner, decode_object};

pub const PAID_EXECUTION_PATH: &str = "/v1/contracts/paid-executions";
pub const PAID_FEE_POLICY_PATH: &str = "/v1/contracts/paid-fee-policy";

/// Builds and independently re-authenticates one signed paid intent. The
/// caller must obtain `fee_policy` through [`Client::query_paid_fee_policy`]
/// and validate its fee source through [`Client::validate_paid_fee_source`]
/// before invoking this offline signing operation.
#[allow(clippy::too_many_arguments)]
pub fn build_signed_paid_execution(
    signer: &LocalSigner,
    resolver: &HashSuiteResolver,
    expected: &ExpectedProtocolContext,
    fee_policy: &PaidFeePolicy,
    consent: FeeSourceConsent,
    application: PaidApplication,
    request_id: RequestId,
    nonce: u64,
    gas_limit: u64,
    authorizations: Vec<execution::call_authorization::CallAuthorization>,
) -> Result<SignedPaidIntent, ClientError> {
    let context: PublicationContext =
        crate::publication_client::trusted_context(resolver, expected)?;
    if fee_policy.context != context {
        return Err(ClientError::PaidExecution(
            execution::paid_execution::PaidExecutionError::ContextMismatch,
        ));
    }
    let base_policy: LocalExecutionPolicy =
        LocalExecutionPolicy::generic_object_results(context.clone());
    let intent: PaidIntent = PaidIntent {
        context: context.clone(),
        request_id: *request_id.as_bytes(),
        sender: *signer.address().as_bytes(),
        nonce,
        fee_policy_digest: paid_fee_policy_digest(resolver, fee_policy)?,
        consent,
        application,
        gas_limit,
        authorizations,
    };
    let frame: Vec<u8> = paid_intent_signing_frame(&context, &intent)?;
    let signature_bytes: Vec<u8> = signer.sign_framed(&frame)?;
    let signature: [u8; 64] = signature_bytes
        .as_slice()
        .try_into()
        .map_err(|_| ClientError::PaidExecutionAcknowledgementMismatch)?;
    let signed: SignedPaidIntent = SignedPaidIntent { intent, signature };
    let encoded: Vec<u8> = encode_signed_paid_intent(&signed)?;
    let authenticated = authenticate_paid_intent(resolver, &context, &encoded)?;
    quote_paid_intent(&authenticated, resolver, &base_policy, fee_policy)?;
    Ok(signed)
}

impl<T: Transport> Client<T> {
    /// Fetches and authenticates a profile-four publication closure across
    /// both genuine legacy and paid provenance. Unlike the zero-fee helper,
    /// this never requires or fabricates a legacy `PublicationSubmission`
    /// for a paid record.
    pub fn query_paid_executable_interface(
        &self,
        root: &UnverifiedDependencyRef,
        resolver: &HashSuiteResolver,
        expected: &ExpectedProtocolContext,
    ) -> Result<VerifiedPublicationInterface, ClientError> {
        crate::publication_client::trusted_context(resolver, expected)?;
        let mut pending: Vec<UnverifiedDependencyRef> = vec![root.clone()];
        let mut expected_by_origin: std::collections::BTreeMap<
            abi::package_types::PackageOrigin,
            UnverifiedDependencyRef,
        > = std::collections::BTreeMap::new();
        let mut candidates: Vec<AuthenticatedPublicationCandidate> = Vec::new();
        while let Some(reference) = pending.pop() {
            if let Some(prior) = expected_by_origin.get(reference.origin()) {
                if prior != &reference {
                    return Err(ClientError::PaidExecution(
                        execution::paid_execution::PaidExecutionError::Invalid(
                            "conflicting exact paid code reference",
                        ),
                    ));
                }
                continue;
            }
            if expected_by_origin.len() >= execution::publication::MAX_INTERFACE_NODES {
                return Err(ClientError::PaidExecution(
                    execution::paid_execution::PaidExecutionError::Invalid(
                        "paid publication closure nodes",
                    ),
                ));
            }
            expected_by_origin.insert(reference.origin().clone(), reference.clone());
            let result = self
                .query_publication_with_semantics(
                    reference.origin(),
                    resolver,
                    expected,
                    reference.context(),
                    |artifact| {
                        Ok(execution::local_execution::generic_object_result_semantics(
                            resolver,
                            artifact.context(),
                        )?)
                    },
                )?
                .ok_or(ClientError::PaidExecution(
                    execution::paid_execution::PaidExecutionError::Invalid(
                        "paid publication dependency absent",
                    ),
                ))?;
            let candidate: AuthenticatedPublicationCandidate = match result {
                crate::PublicationQueryResult::Legacy(submission) => {
                    let semantics = execution::local_execution::generic_object_result_semantics(
                        resolver,
                        submission.request().artifact().context(),
                    )?;
                    execution::publication::authenticate_publication_submission(
                        resolver,
                        reference.context(),
                        &semantics,
                        submission,
                    )?
                }
                crate::PublicationQueryResult::Paid(signed) => {
                    let encoded: Vec<u8> = encode_signed_paid_intent(&signed)?;
                    let authenticated =
                        authenticate_paid_intent(resolver, reference.context(), &encoded)?;
                    execution::paid_execution::authenticate_paid_publication_candidate(
                        resolver,
                        &authenticated,
                    )?
                }
            };
            let artifact = candidate.artifact();
            if artifact.origin() != reference.origin()
                || artifact.revision() != reference.revision()
                || artifact.context() != reference.context()
                || candidate.digest() != reference.artifact_digest()
            {
                return Err(ClientError::PaidExecution(
                    execution::paid_execution::PaidExecutionError::Invalid(
                        "exact paid code reference mismatch",
                    ),
                ));
            }
            pending.extend_from_slice(artifact.unverified_dependencies());
            candidates.push(candidate);
        }
        let root_candidate: AuthenticatedPublicationCandidate =
            candidates
                .first()
                .cloned()
                .ok_or(ClientError::PaidExecution(
                    execution::paid_execution::PaidExecutionError::Invalid(
                        "missing paid publication root",
                    ),
                ))?;
        execution::publication::verify_publication_interface(
            root_candidate,
            candidates.into_iter().skip(1).collect(),
        )
        .map_err(execution::paid_execution::PaidExecutionError::from)
        .map_err(ClientError::PaidExecution)
    }

    /// Fetches the exact installed policy after the mandatory independently
    /// configured protocol-context check and validates its canonical digest.
    pub fn query_paid_fee_policy(
        &self,
        resolver: &HashSuiteResolver,
        expected: &ExpectedProtocolContext,
    ) -> Result<PaidFeePolicy, ClientError> {
        let context: PublicationContext =
            crate::publication_client::trusted_context(resolver, expected)?;
        self.query_verified_context(expected)?;
        let request: WireRequest = WireRequest {
            method: Method::Get,
            path: PAID_FEE_POLICY_PATH.to_owned(),
            content_type: None,
            body: Vec::new(),
            deadline: None,
        };
        let response = self.transport().send(&request)?;
        let body: Vec<u8> = crate::client::expect_success(response, QUERY_RESULT_MEDIA_TYPE)?;
        let policy: PaidFeePolicy = decode_paid_fee_policy(&body)?;
        if policy.context != context {
            return Err(ClientError::PaidExecution(
                execution::paid_execution::PaidExecutionError::ContextMismatch,
            ));
        }
        paid_fee_policy_digest(resolver, &policy)?;
        Ok(policy)
    }

    /// Resolves and verifies the exact live inline fee source before signing:
    /// current protocol provenance, object reference, address owner, policy
    /// asset type and schema must all match. Blob-backed sources fail closed
    /// until the generic client has an authenticated blob fetch surface.
    pub fn validate_paid_fee_source(
        &self,
        signer: &LocalSigner,
        resolver: &HashSuiteResolver,
        expected: &ExpectedProtocolContext,
        policy: &PaidFeePolicy,
        consent: &FeeSourceConsent,
    ) -> Result<Object, ClientError> {
        let context: PublicationContext =
            crate::publication_client::trusted_context(resolver, expected)?;
        if policy.context != context {
            return Err(ClientError::PaidFeeSourceInvalid);
        }
        let result = self.query_object(consent.source.id)?;
        let node_wire::HttpObjectQueryResult::CurrentInline {
            object_id,
            object_version,
            digest,
            creating_chain_id,
            creating_protocol_version,
            canonical_object_bytes,
            ..
        } = result
        else {
            return Err(ClientError::PaidFeeSourceInvalid);
        };
        if creating_chain_id != *expected.chain_id()
            || creating_protocol_version != expected.protocol_version()
            || object_id != consent.source.id
            || object_version.get() != consent.source.version
            || digest != consent.source.digest
        {
            return Err(ClientError::PaidFeeSourceInvalid);
        }
        let object: Object = decode_object(&canonical_object_bytes)
            .map_err(|_| ClientError::PaidFeeSourceInvalid)?;
        let type_matches: bool = abi::package_types::verify_scoped_type_id(
            resolver,
            &object.type_hash,
            expected.epoch(),
            &policy.asset_type,
        )
        .map_err(|_| ClientError::PaidFeeSourceInvalid)?;
        if object.id != consent.source.id
            || object.version != consent.source.version
            || object.owner != Owner::Address(signer.address())
            || object.schema_version != policy.schema
            || !type_matches
        {
            return Err(ClientError::PaidFeeSourceInvalid);
        }
        Ok(object)
    }

    /// Submits exact signed bytes and binds the one canonical result to the
    /// request, application kind/target, outer status and trusted resolver.
    pub fn submit_paid_execution(
        &self,
        signed: &SignedPaidIntent,
        resolver: &HashSuiteResolver,
    ) -> Result<PaidExecutionResult, ClientError> {
        let request: WireRequest = WireRequest {
            method: Method::Post,
            path: PAID_EXECUTION_PATH.to_owned(),
            content_type: Some(NODE_EVENT_MEDIA_TYPE),
            body: encode_signed_paid_intent(signed)?,
            deadline: None,
        };
        let response = self.transport().send(&request)?;
        let body: Vec<u8> = crate::client::expect_success(response, NODE_RESULT_MEDIA_TYPE)?;
        let outer: HttpNodeResult = HttpNodeResult::decode(&body)?;
        let request_id: RequestId = RequestId::new(signed.intent.request_id)?;
        if outer.request_id() != request_id {
            return Err(ClientError::SubmitResponseRequestIdMismatch {
                expected: request_id,
                actual: outer.request_id(),
            });
        }
        let [ack] = outer.responses() else {
            return Err(ClientError::PaidExecutionAcknowledgementMismatch);
        };
        let payload: &[u8] = ack
            .payload()
            .ok_or(ClientError::PaidExecutionAcknowledgementMismatch)?;
        let result: PaidExecutionResult = decode_paid_execution_result(payload)?;
        if ack.request_id() != request_id || result.request_id != signed.intent.request_id {
            return Err(ClientError::PaidExecutionAcknowledgementMismatch);
        }
        let expected_status: NodeResponseStatus = if result.status == PaidExecutionStatus::Success {
            NodeResponseStatus::Accepted
        } else {
            NodeResponseStatus::Rejected
        };
        if ack.status() != expected_status {
            return Err(ClientError::PaidExecutionAcknowledgementMismatch);
        }
        validate_paid_execution_target(&signed.intent.application, &result, resolver)?;
        Ok(result)
    }
}

/// Binds a decoded [`PaidExecutionResult`]'s kind/target to the exact
/// submitted application: a `Publish` result must name the exact artifact's
/// own `PackageOrigin`, and an `Instantiate`/`Call` result must name the
/// exact call's own `InstanceTarget`. Shared by the direct submission path
/// ([`Client::submit_paid_execution`]) and the FastVote apply path
/// (`fastvote_client::Client::apply_fastvote`) so both enforce identical
/// acknowledgement binding for every [`PaidApplication`] kind, rather than
/// two independently maintained checks that could silently diverge.
pub(crate) fn validate_paid_execution_target(
    application: &PaidApplication,
    result: &PaidExecutionResult,
    resolver: &HashSuiteResolver,
) -> Result<(), ClientError> {
    match (application, &result.kind, &result.target) {
        (
            PaidApplication::Publish(artifact),
            PaidResultKind::Publish,
            PaidResultTarget::Package(origin),
        ) if origin == artifact.origin() => Ok(()),
        (
            PaidApplication::Instantiate(call),
            PaidResultKind::Instantiate,
            PaidResultTarget::Instance(record),
        ) if instance_target(resolver, record)? == call.instance => Ok(()),
        (PaidApplication::Call(call), PaidResultKind::Call, PaidResultTarget::Instance(record))
            if instance_target(resolver, record)? == call.instance =>
        {
            Ok(())
        }
        _ => Err(ClientError::PaidExecutionAcknowledgementMismatch),
    }
}
