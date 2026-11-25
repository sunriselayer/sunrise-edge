//! Bounded, non-authorizing review of the exact prepared paid intent.
//!
//! The caller still has to establish fee-source currentness and code/instance
//! provenance. This snapshot neither approves nor signs an operation. It is
//! suitable as the content input for a future operation-specific custody
//! approval: every displayed value comes from the immutable prepared owner,
//! and the complete canonical intent, policy, and signing frame remain
//! available for exact-byte comparison.

use abi::package_types::{encode_scoped_type_arguments, encode_scoped_type_tag};
use execution::call::CallIntent;
use execution::call_authorization::encode_call_authorizations;
use execution::paid_execution::{
    PaidApplication, PaidExecutionError, decode_paid_intent, encode_paid_fee_policy,
    encode_paid_intent, paid_fee_policy_digest, paid_intent_signing_frame,
};
use execution::publication::{PublicationError, UnverifiedDependencyRef, artifact_commitment};
use hashing::HashingError;
use objects::AccessMode;
use protocol_types::HashPurpose;

use crate::paid_execution_client::PreparedPaidExecution;
use crate::review_presentation::{DisplayTextError, display_safe};

/// Upper bound on the rendered review text. Large opaque arguments or
/// authorization tables refuse review rather than being truncated.
pub const MAX_PAID_REVIEW_BYTES: usize = 128 * 1024;

/// A failure to build a complete, bounded review.
#[derive(Debug)]
pub enum PaidExecutionReviewError {
    /// Canonical paid intent, policy, or signing-frame validation failed.
    Paid(PaidExecutionError),
    /// Publication commitment recomputation failed.
    Publication(PublicationError),
    /// Hash-suite lookup for the displayed code and ABI digests failed.
    Hashing(HashingError),
    /// Canonical type-argument or authorization encoding failed.
    Content(Box<dyn std::error::Error + Send + Sync>),
    /// The retained prepared content is internally inconsistent.
    Inconsistent,
    /// A text field cannot be shown safely.
    Text,
    /// Aggregate display output would exceed [`MAX_PAID_REVIEW_BYTES`].
    TooLarge,
}

impl std::fmt::Display for PaidExecutionReviewError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Paid(error) => write!(f, "paid review: {error}"),
            Self::Publication(error) => write!(f, "paid review: {error}"),
            Self::Hashing(error) => write!(f, "paid review: {error}"),
            Self::Content(error) => write!(f, "paid review content: {error}"),
            Self::Inconsistent => f.write_str("prepared paid intent is internally inconsistent"),
            Self::Text => f.write_str("paid review text is not displayable"),
            Self::TooLarge => f.write_str("paid review exceeds the display limit"),
        }
    }
}

impl std::error::Error for PaidExecutionReviewError {}

impl From<PaidExecutionError> for PaidExecutionReviewError {
    fn from(error: PaidExecutionError) -> Self {
        Self::Paid(error)
    }
}
impl From<PublicationError> for PaidExecutionReviewError {
    fn from(error: PublicationError) -> Self {
        Self::Publication(error)
    }
}
impl From<HashingError> for PaidExecutionReviewError {
    fn from(error: HashingError) -> Self {
        Self::Hashing(error)
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

struct Lines {
    text: String,
}
impl Lines {
    fn new() -> Self {
        Self {
            text: String::new(),
        }
    }

    fn add(&mut self, name: &str, value: impl AsRef<str>) -> Result<(), PaidExecutionReviewError> {
        let value = value.as_ref();
        let next = self
            .text
            .len()
            .checked_add(name.len())
            .and_then(|n| n.checked_add(value.len()))
            .and_then(|n| n.checked_add(2))
            .ok_or(PaidExecutionReviewError::TooLarge)?;
        if next > MAX_PAID_REVIEW_BYTES {
            return Err(PaidExecutionReviewError::TooLarge);
        }
        self.text.push_str(name);
        self.text.push('=');
        self.text.push_str(value);
        self.text.push('\n');
        Ok(())
    }

    fn add_hex(&mut self, name: &str, bytes: &[u8]) -> Result<(), PaidExecutionReviewError> {
        let hex_len = bytes
            .len()
            .checked_mul(2)
            .ok_or(PaidExecutionReviewError::TooLarge)?;
        if self
            .text
            .len()
            .checked_add(name.len())
            .and_then(|n| n.checked_add(hex_len))
            .and_then(|n| n.checked_add(2))
            .filter(|&n| n <= MAX_PAID_REVIEW_BYTES)
            .is_none()
        {
            return Err(PaidExecutionReviewError::TooLarge);
        }
        self.add(name, hex(bytes))
    }
}

fn render_dependency(
    lines: &mut Lines,
    prefix: &str,
    code: &UnverifiedDependencyRef,
) -> Result<(), PaidExecutionReviewError> {
    let chain_id = display_safe(
        code.origin().chain_id().as_str(),
        abi::package_types::MAX_PACKAGE_CHAIN_ID_BYTES,
    )
    .map_err(|_: DisplayTextError| PaidExecutionReviewError::Text)?;
    lines.add(&format!("{prefix}.chain_id"), chain_id)?;
    lines.add_hex(&format!("{prefix}.publisher"), code.origin().publisher())?;
    lines.add_hex(&format!("{prefix}.seed"), code.origin().seed())?;
    lines.add(&format!("{prefix}.revision"), code.revision().to_string())?;
    lines.add(
        &format!("{prefix}.protocol_version"),
        code.context().protocol_version().get().to_string(),
    )?;
    lines.add(
        &format!("{prefix}.epoch"),
        code.context().epoch().get().to_string(),
    )?;
    lines.add(
        &format!("{prefix}.digest"),
        code.artifact_digest().to_string(),
    )?;
    Ok(())
}

fn render_call(lines: &mut Lines, call: &CallIntent) -> Result<(), PaidExecutionReviewError> {
    render_dependency(lines, "code", &call.code)?;
    lines.add_hex("instance.creator", &call.instance.creator)?;
    lines.add_hex("instance.seed", &call.instance.seed)?;
    lines.add("instance.revision", call.instance.revision.to_string())?;
    lines.add(
        "instance.record_digest",
        call.instance.record_digest.to_string(),
    )?;
    let entrypoint = display_safe(&call.entrypoint, abi::MAX_ENTRYPOINT_BYTES)
        .map_err(|_: DisplayTextError| PaidExecutionReviewError::Text)?;
    lines.add("entrypoint", entrypoint)?;
    lines.add("type_argument_count", call.type_arguments.len().to_string())?;
    let type_args = encode_scoped_type_arguments(call.context.chain_id(), &call.type_arguments)
        .map_err(|error| PaidExecutionReviewError::Content(Box::new(error)))?;
    lines.add_hex("type_arguments.canonical", &type_args)?;
    lines.add("access_count", call.access.entries.len().to_string())?;
    for (index, entry) in call.access.entries.iter().enumerate() {
        lines.add(
            &format!("access[{index}].object_id"),
            entry.object_ref.id.to_string(),
        )?;
        lines.add(
            &format!("access[{index}].version"),
            entry.object_ref.version.to_string(),
        )?;
        lines.add(
            &format!("access[{index}].digest"),
            entry.object_ref.digest.to_string(),
        )?;
        let mode = match entry.mode {
            AccessMode::Read => "read",
            AccessMode::Write => "write",
            AccessMode::Consume => "consume",
        };
        lines.add(&format!("access[{index}].mode"), mode)?;
    }
    lines.add_hex("arguments.opaque", &call.arguments)?;
    Ok(())
}

/// Immutable review content tied to one [`PreparedPaidExecution`].
pub struct PaidExecutionReview {
    text: String,
    intent_bytes: Vec<u8>,
    policy_bytes: Vec<u8>,
    frame_bytes: Vec<u8>,
}

impl PaidExecutionReview {
    /// Rechecks the canonical intent, installed policy digest, and exact
    /// signing frame, then renders all fee consent fields and the selected
    /// application's operation-specific content under a hard output bound.
    pub fn build(prepared: &PreparedPaidExecution) -> Result<Self, PaidExecutionReviewError> {
        let intent = prepared.intent();
        let intent_bytes = encode_paid_intent(intent)?;
        if decode_paid_intent(&intent_bytes)? != *intent {
            return Err(PaidExecutionReviewError::Inconsistent);
        }
        let policy_bytes = encode_paid_fee_policy(prepared.fee_policy())?;
        let policy_digest = paid_fee_policy_digest(prepared.resolver(), prepared.fee_policy())?;
        if policy_digest != intent.fee_policy_digest
            || intent.sender != *prepared.sender().as_bytes()
        {
            return Err(PaidExecutionReviewError::Inconsistent);
        }
        let frame_bytes = paid_intent_signing_frame(&intent.context, intent)?;
        if frame_bytes != prepared.signable_frame() {
            return Err(PaidExecutionReviewError::Inconsistent);
        }
        let mut lines = Lines::new();
        let chain_id = display_safe(
            intent.context.chain_id().as_str(),
            abi::package_types::MAX_PACKAGE_CHAIN_ID_BYTES,
        )
        .map_err(|_: DisplayTextError| PaidExecutionReviewError::Text)?;
        lines.add("chain_id", chain_id)?;
        lines.add(
            "protocol_version",
            intent.context.protocol_version().get().to_string(),
        )?;
        lines.add("epoch", intent.context.epoch().get().to_string())?;
        lines.add(
            "hash_suite_id",
            prepared
                .resolver()
                .suite_for_epoch(intent.context.epoch())?
                .id
                .get()
                .to_string(),
        )?;
        lines.add_hex("sender", &intent.sender)?;
        lines.add_hex("request_id", &intent.request_id)?;
        lines.add("nonce", intent.nonce.to_string())?;
        lines.add("fee_policy_digest", intent.fee_policy_digest.to_string())?;
        let policy = prepared.fee_policy();
        lines.add(
            "policy.base_policy_digest",
            policy.base_policy_digest.to_string(),
        )?;
        render_dependency(&mut lines, "policy.code", &policy.code)?;
        lines.add_hex("policy.instance.creator", &policy.instance.creator)?;
        lines.add_hex("policy.instance.seed", &policy.instance.seed)?;
        lines.add(
            "policy.instance.revision",
            policy.instance.revision.to_string(),
        )?;
        lines.add(
            "policy.instance.record_digest",
            policy.instance.record_digest.to_string(),
        )?;
        for (name, value) in [
            ("policy.reserve_entrypoint", &policy.reserve_entrypoint),
            (
                "policy.reserve_all_entrypoint",
                &policy.reserve_all_entrypoint,
            ),
            ("policy.settle_entrypoint", &policy.settle_entrypoint),
        ] {
            lines.add(
                name,
                display_safe(value, abi::MAX_ENTRYPOINT_BYTES)
                    .map_err(|_: DisplayTextError| PaidExecutionReviewError::Text)?,
            )?;
        }
        lines.add(
            "policy.type_argument_count",
            policy.type_arguments.len().to_string(),
        )?;
        lines.add_hex(
            "policy.type_arguments.canonical",
            &encode_scoped_type_arguments(intent.context.chain_id(), &policy.type_arguments)
                .map_err(|error| PaidExecutionReviewError::Content(Box::new(error)))?,
        )?;
        lines.add_hex(
            "policy.asset_type.canonical",
            &encode_scoped_type_tag(&policy.asset_type)
                .map_err(|error| PaidExecutionReviewError::Content(Box::new(error)))?,
        )?;
        lines.add_hex(
            "policy.reservation_type.canonical",
            &encode_scoped_type_tag(&policy.reservation_type)
                .map_err(|error| PaidExecutionReviewError::Content(Box::new(error)))?,
        )?;
        lines.add("policy.schema", policy.schema.to_string())?;
        lines.add_hex("policy.fee_recipient", &policy.fee_recipient)?;
        lines.add(
            "policy.gas.base_fee",
            policy.gas_schedule.base_fee.to_string(),
        )?;
        lines.add(
            "policy.gas.execution_price",
            policy.gas_schedule.execution_price.to_string(),
        )?;
        lines.add(
            "policy.gas.read_price",
            policy.gas_schedule.read_price.to_string(),
        )?;
        lines.add(
            "policy.gas.write_price",
            policy.gas_schedule.write_price.to_string(),
        )?;
        lines.add(
            "policy.gas.storage_price",
            policy.gas_schedule.storage_price.to_string(),
        )?;
        lines.add(
            "policy.gas.system_module_price",
            policy.gas_schedule.system_module_price.to_string(),
        )?;
        for (name, value) in [
            ("policy.conversion_divisor", policy.conversion_divisor),
            ("policy.reserve_allowance", policy.reserve_allowance),
            ("policy.settle_allowance", policy.settle_allowance),
            ("policy.memory_bytes", policy.memory_bytes),
            ("policy.output_bytes", policy.output_bytes),
            (
                "policy.publish_artifact_byte_price",
                policy.publish_artifact_byte_price,
            ),
            (
                "policy.publish_closure_node_price",
                policy.publish_closure_node_price,
            ),
        ] {
            lines.add(name, value.to_string())?;
        }
        for (name, value) in [
            ("policy.calls", policy.calls),
            ("policy.handles", policy.handles),
            ("policy.creations", policy.creations),
            ("policy.events", policy.events),
        ] {
            lines.add(name, value.to_string())?;
        }
        lines.add("fee_source.id", intent.consent.source.id.to_string())?;
        lines.add(
            "fee_source.version",
            intent.consent.source.version.to_string(),
        )?;
        lines.add(
            "fee_source.digest",
            intent.consent.source.digest.to_string(),
        )?;
        lines.add(
            "fee_source.access",
            match intent.consent.access {
                execution::paid_execution::ReservationAccessKind::Write => "write",
                execution::paid_execution::ReservationAccessKind::Consume => "consume",
            },
        )?;
        lines.add("max_fee", intent.consent.max_fee.get().to_string())?;
        lines.add_hex("refund_recipient", &intent.consent.refund_recipient)?;
        lines.add("gas_limit", intent.gas_limit.to_string())?;
        match &intent.application {
            PaidApplication::Call(call) => {
                lines.add("operation", "call")?;
                render_call(&mut lines, call)?;
            }
            PaidApplication::Instantiate(call) => {
                lines.add("operation", "instantiate")?;
                render_call(&mut lines, call)?;
            }
            PaidApplication::Publish(artifact) => {
                lines.add("operation", "publish")?;
                lines.add_hex("origin.publisher", artifact.origin().publisher())?;
                lines.add_hex("origin.seed", artifact.origin().seed())?;
                lines.add("revision", artifact.revision().to_string())?;
                lines.add("wasm_profile", artifact.wasm_profile().to_string())?;
                lines.add("semantics", artifact.semantics().to_string())?;
                lines.add(
                    "artifact_commitment",
                    artifact_commitment(prepared.resolver(), &intent.context, artifact)?
                        .to_string(),
                )?;
                lines.add("wasm_bytes", artifact.wasm().len().to_string())?;
                lines.add(
                    "wasm_contract_code_digest",
                    prepared
                        .resolver()
                        .hash_for_purpose(
                            intent.context.epoch(),
                            HashPurpose::ContractCode,
                            artifact.wasm(),
                        )?
                        .to_string(),
                )?;
                lines.add("abi_bytes", artifact.unverified_abi().len().to_string())?;
                lines.add(
                    "abi_contract_code_digest",
                    prepared
                        .resolver()
                        .hash_for_purpose(
                            intent.context.epoch(),
                            HashPurpose::ContractCode,
                            artifact.unverified_abi(),
                        )?
                        .to_string(),
                )?;
                lines.add("export_count", artifact.exports().len().to_string())?;
                for (index, export) in artifact.exports().iter().enumerate() {
                    let safe = display_safe(export, execution::MAX_CONTRACT_ENTRYPOINT_NAME_BYTES)
                        .map_err(|_: DisplayTextError| PaidExecutionReviewError::Text)?;
                    lines.add(&format!("export[{index}]"), safe)?;
                }
                lines.add(
                    "dependency_count",
                    artifact.unverified_dependencies().len().to_string(),
                )?;
                for (index, dependency) in artifact.unverified_dependencies().iter().enumerate() {
                    render_dependency(&mut lines, &format!("dependency[{index}]"), dependency)?;
                }
            }
        }
        lines.add(
            "authorization_count",
            intent.authorizations.len().to_string(),
        )?;
        if !intent.authorizations.is_empty() {
            let auth = encode_call_authorizations(&intent.authorizations)
                .map_err(|error| PaidExecutionReviewError::Content(Box::new(error)))?;
            lines.add_hex("authorizations.canonical", &auth)?;
        }
        lines.add("canonical_intent_bytes", intent_bytes.len().to_string())?;
        lines.add("canonical_policy_bytes", policy_bytes.len().to_string())?;
        lines.add("signing_frame_bytes", frame_bytes.len().to_string())?;
        Ok(Self {
            text: lines.text,
            intent_bytes,
            policy_bytes,
            frame_bytes,
        })
    }

    /// Bounded display-safe summary; opaque arguments are exact hex.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }
    /// Exact canonical unsigned paid intent.
    #[must_use]
    pub fn intent_bytes(&self) -> &[u8] {
        &self.intent_bytes
    }
    /// Exact canonical policy whose digest the intent signs.
    #[must_use]
    pub fn policy_bytes(&self) -> &[u8] {
        &self.policy_bytes
    }
    /// Exact bytes the protected signer would have to sign.
    #[must_use]
    pub fn frame_bytes(&self) -> &[u8] {
        &self.frame_bytes
    }
}
