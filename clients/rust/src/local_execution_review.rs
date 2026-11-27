//! Bounded, non-authorizing presentation of a prepared local/general call.
//!
//! The review rechecks the exact typed intent, policy, scopes and signing
//! frame retained by `PreparedLocalExecution`. It neither signs nor proves
//! durable instance/code authority, currentness, or contract safety.

use abi::package_types::{
    MAX_PACKAGE_CHAIN_ID_BYTES, PackageTypeError, encode_scoped_type_arguments,
};
use execution::call::InstanceTarget;
use execution::call_authorization::ExecutionTarget;
use execution::local_execution::{
    LocalExecutionError, LocalExecutionIntent, LocalExecutionMode, LocalExecutionPolicy,
    ResolvedExecutionScope, decode_local_execution_intent, encode_local_execution_intent,
    local_execution_signing_frame,
};
use execution::publication::UnverifiedDependencyRef;
use objects::AccessMode;

use crate::HashSuiteResolver;
use crate::local_execution_client::PreparedLocalExecution;
use crate::review_presentation::{DisplayTextError, display_safe};

/// Maximum rendered review bytes. A valid large invocation may be refused for
/// presentation without changing its protocol validity or truncating content.
pub const MAX_LOCAL_EXECUTION_REVIEW_BYTES: usize = 96 * 1024;

/// A refusal to present every field of the exact prepared operation.
#[derive(Debug)]
pub enum LocalExecutionReviewError {
    /// Existing local execution codec or scope check failed.
    Execution(LocalExecutionError),
    /// Existing scoped type-argument codec failed.
    Type(PackageTypeError),
    /// Re-encoded typed intent did not decode to the same value.
    IntentMismatch,
    /// Prepared policy, identity or signing frame differs from its preimages.
    BindingMismatch,
    /// Text could not be shown verbatim without terminal control characters.
    Undisplayable(String),
    /// The complete presentation exceeds its fixed byte budget.
    Limit,
}

impl std::fmt::Display for LocalExecutionReviewError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Execution(error) => write!(f, "local execution review: {error}"),
            Self::Type(error) => write!(f, "local execution review type arguments: {error}"),
            Self::IntentMismatch => f.write_str("local execution review intent mismatch"),
            Self::BindingMismatch => f.write_str("local execution review binding mismatch"),
            Self::Undisplayable(field) => write!(f, "local execution review undisplayable {field}"),
            Self::Limit => f.write_str("local execution review exceeds display byte limit"),
        }
    }
}
impl std::error::Error for LocalExecutionReviewError {}
impl From<LocalExecutionError> for LocalExecutionReviewError {
    fn from(error: LocalExecutionError) -> Self {
        Self::Execution(error)
    }
}
impl From<PackageTypeError> for LocalExecutionReviewError {
    fn from(error: PackageTypeError) -> Self {
        Self::Type(error)
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(result, "{byte:02x}");
    }
    result
}

struct Renderer {
    output: String,
}
impl Renderer {
    fn new() -> Self {
        Self {
            output: String::new(),
        }
    }

    fn push(&mut self, label: &str, value: &str) -> Result<(), LocalExecutionReviewError> {
        let next = self
            .output
            .len()
            .checked_add(label.len())
            .and_then(|size| value.len().checked_add(2).and_then(|n| size.checked_add(n)))
            .ok_or(LocalExecutionReviewError::Limit)?;
        if next > MAX_LOCAL_EXECUTION_REVIEW_BYTES {
            return Err(LocalExecutionReviewError::Limit);
        }
        self.output.push_str(label);
        self.output.push('=');
        self.output.push_str(value);
        self.output.push('\n');
        Ok(())
    }

    fn bytes(&mut self, label: &str, value: &[u8]) -> Result<(), LocalExecutionReviewError> {
        let encoded_len = value
            .len()
            .checked_mul(2)
            .ok_or(LocalExecutionReviewError::Limit)?;
        let next = self
            .output
            .len()
            .checked_add(label.len())
            .and_then(|size| encoded_len.checked_add(2).and_then(|n| size.checked_add(n)))
            .ok_or(LocalExecutionReviewError::Limit)?;
        if next > MAX_LOCAL_EXECUTION_REVIEW_BYTES {
            return Err(LocalExecutionReviewError::Limit);
        }
        self.push(label, &hex(value))
    }

    fn text(
        &mut self,
        label: &str,
        value: &str,
        maximum: usize,
    ) -> Result<(), LocalExecutionReviewError> {
        let safe = display_safe(value, maximum).map_err(|error| match error {
            DisplayTextError::Limit { .. } => LocalExecutionReviewError::Limit,
            DisplayTextError::Undisplayable => {
                LocalExecutionReviewError::Undisplayable(label.to_owned())
            }
        })?;
        self.push(label, &safe)
    }
}

fn code(
    renderer: &mut Renderer,
    prefix: &str,
    reference: &UnverifiedDependencyRef,
) -> Result<(), LocalExecutionReviewError> {
    let origin = reference.origin();
    renderer.text(
        &format!("{prefix}.chain_id"),
        origin.chain_id().as_str(),
        MAX_PACKAGE_CHAIN_ID_BYTES,
    )?;
    renderer.bytes(&format!("{prefix}.publisher"), origin.publisher())?;
    renderer.bytes(&format!("{prefix}.seed"), origin.seed())?;
    renderer.push(
        &format!("{prefix}.revision"),
        &reference.revision().to_string(),
    )?;
    renderer.push(
        &format!("{prefix}.protocol_version"),
        &reference.context().protocol_version().get().to_string(),
    )?;
    renderer.push(
        &format!("{prefix}.epoch"),
        &reference.context().epoch().get().to_string(),
    )?;
    renderer.push(
        &format!("{prefix}.artifact_digest"),
        &reference.artifact_digest().to_string(),
    )
}

fn instance(
    renderer: &mut Renderer,
    prefix: &str,
    target: &InstanceTarget,
) -> Result<(), LocalExecutionReviewError> {
    renderer.bytes(&format!("{prefix}.creator"), &target.creator)?;
    renderer.bytes(&format!("{prefix}.seed"), &target.seed)?;
    renderer.push(&format!("{prefix}.revision"), &target.revision.to_string())?;
    renderer.push(
        &format!("{prefix}.record_digest"),
        &target.record_digest.to_string(),
    )
}

fn target(
    renderer: &mut Renderer,
    prefix: &str,
    value: &ExecutionTarget,
) -> Result<(), LocalExecutionReviewError> {
    instance(renderer, &format!("{prefix}.instance"), &value.instance)?;
    code(renderer, &format!("{prefix}.code"), &value.code)
}

/// Immutable presentation and exact canonical bytes from one prepared owner.
/// The byte accessors are for an independent approver to compare against the
/// eventual signer input; constructing this value grants no signing authority.
pub struct LocalExecutionReview {
    display: String,
    intent_bytes: Vec<u8>,
    signable_frame: Vec<u8>,
}
impl LocalExecutionReview {
    /// Rechecks and presents the same immutable content that will be signed.
    pub fn build(prepared: &PreparedLocalExecution) -> Result<Self, LocalExecutionReviewError> {
        let intent = prepared.intent();
        let intent_bytes = encode_local_execution_intent(intent)?;
        if intent_bytes.len() > MAX_LOCAL_EXECUTION_REVIEW_BYTES {
            return Err(LocalExecutionReviewError::Limit);
        }
        if decode_local_execution_intent(&intent_bytes)? != *intent {
            return Err(LocalExecutionReviewError::IntentMismatch);
        }
        if intent.call.sender != *prepared.sender().as_bytes()
            || intent.policy_digest != prepared.policy().digest(prepared.resolver())?
        {
            return Err(LocalExecutionReviewError::BindingMismatch);
        }
        execution::execution_scopes::validate_local_execution_scopes(
            prepared.resolver(),
            prepared.policy(),
            intent,
            prepared.scopes(),
        )?;
        let signable_frame = local_execution_signing_frame(&intent.call.context, intent)?;
        if signable_frame.len() > MAX_LOCAL_EXECUTION_REVIEW_BYTES {
            return Err(LocalExecutionReviewError::Limit);
        }
        if signable_frame != prepared.signable_frame() {
            return Err(LocalExecutionReviewError::BindingMismatch);
        }

        Self::render(
            intent,
            prepared.policy(),
            Some(prepared.scopes()),
            intent_bytes,
            signable_frame,
        )
    }

    /// Rebuilds the signed-field review and exact frame from a saved canonical
    /// Call intent under a separately selected local policy. The publication
    /// closure/scopes are not reverified by this offline review; the original
    /// preparation owner must have validated them before export.
    pub fn from_saved_call(
        bytes: &[u8],
        resolver: &HashSuiteResolver,
        policy: &LocalExecutionPolicy,
    ) -> Result<Self, LocalExecutionReviewError> {
        if bytes.len() > MAX_LOCAL_EXECUTION_REVIEW_BYTES {
            return Err(LocalExecutionReviewError::Limit);
        }
        let intent = decode_local_execution_intent(bytes)?;
        if encode_local_execution_intent(&intent)? != bytes {
            return Err(LocalExecutionReviewError::IntentMismatch);
        }
        if intent.mode != LocalExecutionMode::Call
            || intent.call.context != *policy.context()
            || intent.policy_digest != policy.digest(resolver)?
            || intent.call.gas_limit > policy.max_gas()
        {
            return Err(LocalExecutionReviewError::BindingMismatch);
        }
        execution::call_authorization::validate_call_authorizations(
            &intent.call,
            &intent.authorizations,
        )
        .map_err(|_| LocalExecutionReviewError::BindingMismatch)?;
        let frame = local_execution_signing_frame(policy.context(), &intent)?;
        if frame.len() > MAX_LOCAL_EXECUTION_REVIEW_BYTES {
            return Err(LocalExecutionReviewError::Limit);
        }
        Self::render(&intent, policy, None, bytes.to_vec(), frame)
    }

    fn render(
        intent: &LocalExecutionIntent,
        policy: &LocalExecutionPolicy,
        scopes: Option<&[ResolvedExecutionScope]>,
        intent_bytes: Vec<u8>,
        signable_frame: Vec<u8>,
    ) -> Result<Self, LocalExecutionReviewError> {
        let mut out = Renderer::new();
        out.text(
            "chain_id",
            intent.call.context.chain_id().as_str(),
            MAX_PACKAGE_CHAIN_ID_BYTES,
        )?;
        out.push(
            "protocol_version",
            &intent.call.context.protocol_version().get().to_string(),
        )?;
        out.push("epoch", &intent.call.context.epoch().get().to_string())?;
        out.push(
            "mode",
            match intent.mode {
                LocalExecutionMode::Instantiate => "instantiate",
                LocalExecutionMode::Call => "call",
            },
        )?;
        out.push("policy.profile", &policy.profile().to_string())?;
        out.push("policy.max_gas", &policy.max_gas().to_string())?;
        out.push("policy.digest", &intent.policy_digest.to_string())?;
        out.bytes("policy.canonical_bytes", &policy.encode()?)?;
        out.bytes("request_id", &intent.call.request_id)?;
        out.bytes("sender", &intent.call.sender)?;
        out.push("nonce", &intent.call.nonce.to_string())?;
        code(&mut out, "code", &intent.call.code)?;
        instance(&mut out, "instance", &intent.call.instance)?;
        out.text(
            "entrypoint",
            &intent.call.entrypoint,
            abi::MAX_ENTRYPOINT_BYTES,
        )?;
        out.push(
            "type_argument_count",
            &intent.call.type_arguments.len().to_string(),
        )?;
        out.bytes(
            "type_arguments.canonical_bytes",
            &encode_scoped_type_arguments(
                intent.call.context.chain_id(),
                &intent.call.type_arguments,
            )?,
        )?;
        out.push(
            "access_count",
            &intent.call.access.entries.len().to_string(),
        )?;
        for (index, entry) in intent.call.access.entries.iter().enumerate() {
            let prefix = format!("access[{index}]");
            out.push(
                &format!("{prefix}.object_id"),
                &entry.object_ref.id.to_string(),
            )?;
            out.push(
                &format!("{prefix}.version"),
                &entry.object_ref.version.to_string(),
            )?;
            out.push(
                &format!("{prefix}.digest"),
                &entry.object_ref.digest.to_string(),
            )?;
            out.push(
                &format!("{prefix}.mode"),
                match entry.mode {
                    AccessMode::Read => "read",
                    AccessMode::Write => "write",
                    AccessMode::Consume => "consume",
                },
            )?;
        }
        out.bytes("arguments.opaque_hex", &intent.call.arguments)?;
        out.push("gas_limit", &intent.call.gas_limit.to_string())?;
        out.push(
            "authorization_count",
            &intent.authorizations.len().to_string(),
        )?;
        for (index, authorization) in intent.authorizations.iter().enumerate() {
            let prefix = format!("authorization[{index}]");
            target(&mut out, &format!("{prefix}.caller"), &authorization.caller)?;
            target(&mut out, &format!("{prefix}.callee"), &authorization.callee)?;
            out.text(
                &format!("{prefix}.entrypoint"),
                &authorization.entrypoint,
                abi::MAX_ENTRYPOINT_BYTES,
            )?;
            out.bytes(
                &format!("{prefix}.type_arguments.canonical_bytes"),
                &encode_scoped_type_arguments(
                    intent.call.context.chain_id(),
                    &authorization.type_arguments,
                )?,
            )?;
            out.push(
                &format!("{prefix}.object_count"),
                &authorization.objects.len().to_string(),
            )?;
            for (object_index, object) in authorization.objects.iter().enumerate() {
                out.push(
                    &format!("{prefix}.object[{object_index}].id"),
                    &object.object_id.to_string(),
                )?;
                out.push(
                    &format!("{prefix}.object[{object_index}].mode"),
                    match object.mode {
                        AccessMode::Read => "read",
                        AccessMode::Write => "write",
                        AccessMode::Consume => "consume",
                    },
                )?;
            }
        }
        if let Some(scopes) = scopes {
            out.push("scope_count", &scopes.len().to_string())?;
            for (index, scope) in scopes.iter().enumerate() {
                let prefix = format!("scope[{index}]");
                instance(&mut out, &format!("{prefix}.target"), &scope.target)?;
                out.text(
                    &format!("{prefix}.initializer"),
                    &scope.instance.initializer,
                    abi::MAX_ENTRYPOINT_BYTES,
                )?;
                let candidates = std::iter::once(scope.interface.candidate())
                    .chain(scope.interface.dependencies());
                for (node_index, candidate) in candidates.enumerate() {
                    let artifact = candidate.artifact();
                    let node = format!("{prefix}.code_node[{node_index}]");
                    out.bytes(&format!("{node}.publisher"), artifact.origin().publisher())?;
                    out.bytes(&format!("{node}.seed"), artifact.origin().seed())?;
                    out.push(
                        &format!("{node}.revision"),
                        &artifact.revision().to_string(),
                    )?;
                    out.push(&format!("{node}.digest"), &candidate.digest().to_string())?;
                    out.push(
                        &format!("{node}.wasm_profile"),
                        &artifact.wasm_profile().to_string(),
                    )?;
                    out.push(
                        &format!("{node}.semantics"),
                        &artifact.semantics().to_string(),
                    )?;
                    out.push(
                        &format!("{node}.wasm_bytes"),
                        &artifact.wasm().len().to_string(),
                    )?;
                }
            }
        } else {
            out.push("scope_validation", "not_replayed_from_saved_intent")?;
        }
        Ok(Self {
            display: out.output,
            intent_bytes,
            signable_frame,
        })
    }

    /// Complete display-safe `key=value` review; no field is truncated.
    #[must_use]
    pub fn display(&self) -> &str {
        &self.display
    }
    /// Exact canonical intent bytes independently rechecked from the owner.
    #[must_use]
    pub fn intent_bytes(&self) -> &[u8] {
        &self.intent_bytes
    }
    /// Exact bytes the prepared owner will pass to the signer.
    #[must_use]
    pub fn signable_frame(&self) -> &[u8] {
        &self.signable_frame
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renderer_refuses_control_text_and_oversized_hex_without_partial_review() {
        let mut out = Renderer::new();
        assert!(matches!(
            out.text("entrypoint", "run\x1b[31m", 256),
            Err(LocalExecutionReviewError::Undisplayable(field)) if field == "entrypoint"
        ));
        assert!(out.output.is_empty());
        let oversized = vec![0u8; MAX_LOCAL_EXECUTION_REVIEW_BYTES / 2];
        assert!(matches!(
            out.bytes("arguments", &oversized),
            Err(LocalExecutionReviewError::Limit)
        ));
        assert!(out.output.is_empty());
    }
}
