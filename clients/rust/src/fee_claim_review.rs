//! Bounded, non-authorizing fee-claim review and presentation.
//!
//! [DR-0214](../../../docs/architecture/decisions/0214-protected-custody-and-review-boundary.md)
//! lists the fee-claim review row: "exact intent/request, claimant from the
//! certificate's historical committee, certificate/workflow provenance,
//! claim recipient/resource/amount and relevant epochs; current membership
//! cannot replace historical identity." [DR-0237](../../../docs/architecture/decisions/0237-bounded-publication-review-presentation.md)
//! supplies the one existing bounded, non-authorizing presentation consumer
//! pattern this module follows for fee claims: given the same immutable
//! [`PreparedFeeClaim`] that is signed, it performs a defensive
//! self-consistency recheck of that already-typed owner's retained
//! canonical bytes, digest and signing frame using only the existing
//! fee-claim/local-execution codecs, and exposes a bounded, display-safe
//! snapshot of every material field.
//!
//! # Explicit non-claims
//!
//! This is NOT a signer, an approval endpoint, or proof of certified row
//! authenticity. Building a [`FeeClaimReview`] loads no signing seed,
//! contacts no signer or node, and submits nothing. [`PreparedFeeClaim`]
//! already binds the claimant to `certificate_set(intent.certificate_epoch)`
//! -- the historical committee, never the current one -- before this module
//! ever runs; this module re-derives the same digest/frame the prepared
//! owner retained as a defensive regression check, and does not perform or
//! replace that committee lookup, the embedded leg's own signature
//! authentication at commit time, or any economics/entitlement
//! verification. A peer-supplied claim, amount, resource or payout ref is
//! rendered exactly as retained; a successful [`FeeClaimReview`] is a
//! bounded, legible restatement of that retained content, never a
//! certification that the underlying escrow row, committee membership or
//! economics are authentic or correct.
use execution::call::{CallIntent, InstanceTarget};
use execution::call_authorization::{CallAuthorization, ExecutionTarget};
use execution::local_execution::{
    LocalExecutionError, LocalExecutionMode, SignedLocalExecutionIntent,
    decode_signed_local_execution,
};
use execution::publication::UnverifiedDependencyRef;
use hashing::HashSuiteResolver;
use node_core::fee_claims::codec::{
    FeeClaimCodecError, FeeClaimIntent, FeeClaimOperation, decode_fee_claim_intent,
    encode_fee_claim_intent,
};
use node_core::fee_claims::{FeeClaimError, fee_claim_intent_digest, fee_claim_signing_frame};
use objects::{AccessMode, Address, ObjectRef};
use protocol_types::Digest32;

use crate::fee_claim_client::PreparedFeeClaim;

/// Maximum total bytes across every rendered label, value and line
/// separator in one review, counted *before* any raw byte payload (call
/// arguments, a signed leg, a signature) is hex-encoded -- hex encoding
/// doubles the allocation, so the check runs against the pre-encoded
/// length first. Deliberately smaller than the protocol's own structural
/// ceilings (a single call-argument payload alone may reach 64 KiB, and a
/// signed leg may reach roughly three times that), so a legitimately large
/// claim's review refuses rather than silently truncating; the signing and
/// execution paths carry no such presentation-only ceiling.
pub const MAX_FEE_CLAIM_REVIEW_OUTPUT_BYTES: usize = 64 * 1024;

/// Fail-closed errors for bounded, non-authorizing fee-claim review.
///
/// Every variant rejects the input outright; none silently truncates,
/// drops, or substitutes a field, and none performs any signing or network
/// action.
#[derive(Debug)]
pub enum FeeClaimReviewError {
    /// Defensive self-consistency recheck failed (intent codec).
    Codec(FeeClaimCodecError),
    /// Defensive self-consistency recheck failed (digest/frame recomputation).
    Core(FeeClaimError),
    /// A `Split`/`FinalTransfer` embedded leg failed to decode as a signed
    /// local execution intent. Fails the entire review closed; no partial
    /// review is ever returned for a malformed leg.
    Execution(LocalExecutionError),
    /// Re-decoding the freshly re-encoded intent produced different
    /// structural content.
    IntentRoundTripMismatch,
    /// The freshly recomputed intent digest differs from the one
    /// [`PreparedFeeClaim`] retained.
    DigestMismatch,
    /// The freshly recomputed signing frame differs from the one
    /// [`PreparedFeeClaim`] retained.
    FrameMismatch,
    /// Embedded call context or replay ID differs from the outer claim.
    LegBindingMismatch,
    /// A field required for review contains bytes that cannot be safely
    /// displayed (non-printable, control, or non-ASCII text).
    UndisplayableField(&'static str),
    /// A field, collection, or the aggregate snapshot exceeded its explicit
    /// bound before or during presentation.
    Limit {
        field: &'static str,
        actual: usize,
        maximum: usize,
    },
}

impl std::fmt::Display for FeeClaimReviewError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Codec(error) => write!(f, "fee claim review codec error: {error}"),
            Self::Core(error) => write!(f, "fee claim review core error: {error}"),
            Self::Execution(error) => write!(f, "fee claim review leg error: {error}"),
            Self::IntentRoundTripMismatch => {
                f.write_str("fee claim review: intent does not round-trip through its codec")
            }
            Self::DigestMismatch => {
                f.write_str("fee claim review: recomputed intent digest mismatch")
            }
            Self::LegBindingMismatch => {
                f.write_str("fee claim review: leg context or request ID differs from the claim")
            }
            Self::FrameMismatch => {
                f.write_str("fee claim review: recomputed signing frame mismatch")
            }
            Self::UndisplayableField(field) => {
                write!(f, "fee claim review: field '{field}' is not displayable")
            }
            Self::Limit {
                field,
                actual,
                maximum,
            } => write!(
                f,
                "fee claim review: field '{field}' length/count {actual} exceeds {maximum}"
            ),
        }
    }
}

impl std::error::Error for FeeClaimReviewError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Codec(error) => Some(error),
            Self::Core(error) => Some(error),
            Self::Execution(error) => Some(error),
            _ => None,
        }
    }
}

impl From<FeeClaimCodecError> for FeeClaimReviewError {
    fn from(error: FeeClaimCodecError) -> Self {
        Self::Codec(error)
    }
}
impl From<FeeClaimError> for FeeClaimReviewError {
    fn from(error: FeeClaimError) -> Self {
        Self::Core(error)
    }
}
impl From<LocalExecutionError> for FeeClaimReviewError {
    fn from(error: LocalExecutionError) -> Self {
        Self::Execution(error)
    }
}

/// Accepts only printable, non-control ASCII bytes and bounds the byte
/// length before copying. Rejecting rather than stripping or truncating
/// keeps this function from silently hiding bytes a terminal would
/// otherwise interpret as control sequences.
fn display_safe(
    field: &'static str,
    value: &str,
    maximum: usize,
) -> Result<String, FeeClaimReviewError> {
    if value.len() > maximum {
        return Err(FeeClaimReviewError::Limit {
            field,
            actual: value.len(),
            maximum,
        });
    }
    if value.bytes().any(|byte| !(0x20..=0x7E).contains(&byte)) {
        return Err(FeeClaimReviewError::UndisplayableField(field));
    }
    Ok(value.to_owned())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

const fn access_mode_label(mode: AccessMode) -> &'static str {
    match mode {
        AccessMode::Read => "read",
        AccessMode::Write => "write",
        AccessMode::Consume => "consume",
    }
}

/// Minimal internal accumulator enforcing the aggregate byte-count
/// presentation budget as each rendered line is produced. Not a framework:
/// it only counts and joins `label=value` lines.
struct BoundedRenderer {
    lines: Vec<(String, String)>,
    total_bytes: usize,
}

impl BoundedRenderer {
    fn new() -> Self {
        Self {
            lines: Vec::new(),
            total_bytes: 0,
        }
    }

    fn push(
        &mut self,
        label: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<(), FeeClaimReviewError> {
        let label: String = label.into();
        let value: String = value.into();
        let line_bytes: usize = label
            .len()
            .checked_add(1)
            .and_then(|running| running.checked_add(value.len()))
            .and_then(|running| running.checked_add(1))
            .ok_or(FeeClaimReviewError::Limit {
                field: "total_output_bytes",
                actual: usize::MAX,
                maximum: MAX_FEE_CLAIM_REVIEW_OUTPUT_BYTES,
            })?;
        let total: usize =
            self.total_bytes
                .checked_add(line_bytes)
                .ok_or(FeeClaimReviewError::Limit {
                    field: "total_output_bytes",
                    actual: usize::MAX,
                    maximum: MAX_FEE_CLAIM_REVIEW_OUTPUT_BYTES,
                })?;
        if total > MAX_FEE_CLAIM_REVIEW_OUTPUT_BYTES {
            return Err(FeeClaimReviewError::Limit {
                field: "total_output_bytes",
                actual: total,
                maximum: MAX_FEE_CLAIM_REVIEW_OUTPUT_BYTES,
            });
        }
        self.total_bytes = total;
        self.lines.push((label, value));
        Ok(())
    }

    /// Checks `raw`'s doubled byte length against the remaining aggregate
    /// budget *before* allocating its hex encoding, then hex-encodes and
    /// pushes it as one line.
    fn push_hex(
        &mut self,
        label: impl Into<String>,
        raw: &[u8],
    ) -> Result<String, FeeClaimReviewError> {
        let label: String = label.into();
        let hex_len: usize = raw.len().checked_mul(2).ok_or(FeeClaimReviewError::Limit {
            field: "raw_byte_payload",
            actual: usize::MAX,
            maximum: MAX_FEE_CLAIM_REVIEW_OUTPUT_BYTES,
        })?;
        if hex_len > MAX_FEE_CLAIM_REVIEW_OUTPUT_BYTES {
            return Err(FeeClaimReviewError::Limit {
                field: "raw_byte_payload",
                actual: hex_len,
                maximum: MAX_FEE_CLAIM_REVIEW_OUTPUT_BYTES,
            });
        }
        let projected: usize =
            self.total_bytes
                .checked_add(hex_len)
                .ok_or(FeeClaimReviewError::Limit {
                    field: "total_output_bytes",
                    actual: usize::MAX,
                    maximum: MAX_FEE_CLAIM_REVIEW_OUTPUT_BYTES,
                })?;
        if projected > MAX_FEE_CLAIM_REVIEW_OUTPUT_BYTES {
            return Err(FeeClaimReviewError::Limit {
                field: "total_output_bytes",
                actual: projected,
                maximum: MAX_FEE_CLAIM_REVIEW_OUTPUT_BYTES,
            });
        }
        let value: String = hex(raw);
        self.push(label, value.clone())?;
        Ok(value)
    }

    fn finish(self) -> Vec<(String, String)> {
        self.lines
    }
}

/// Bounded, display-safe presentation of one [`ObjectRef`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectRefReview {
    id_hex: String,
    version: u64,
    digest_hex: String,
}
impl ObjectRefReview {
    /// Referenced object identifier, as lowercase hex.
    #[must_use]
    pub fn id_hex(&self) -> &str {
        &self.id_hex
    }
    /// Referenced object version.
    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }
    /// Referenced object digest (algorithm-prefixed hex).
    #[must_use]
    pub fn digest_hex(&self) -> &str {
        &self.digest_hex
    }
}

fn render_object_ref(
    renderer: &mut BoundedRenderer,
    prefix: &str,
    object_ref: &ObjectRef,
) -> Result<ObjectRefReview, FeeClaimReviewError> {
    let id_hex: String = object_ref.id.to_string();
    renderer.push(format!("{prefix}.id"), id_hex.clone())?;
    renderer.push(format!("{prefix}.version"), object_ref.version.to_string())?;
    let digest_hex: String = object_ref.digest.to_string();
    renderer.push(format!("{prefix}.digest"), digest_hex.clone())?;
    Ok(ObjectRefReview {
        id_hex,
        version: object_ref.version,
        digest_hex,
    })
}

/// Bounded, display-safe presentation of one [`InstanceTarget`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstanceTargetReview {
    creator_hex: String,
    seed_hex: String,
    revision: u64,
    record_digest_hex: String,
}
impl InstanceTargetReview {
    /// Claimed instance creator, as lowercase hex.
    #[must_use]
    pub fn creator_hex(&self) -> &str {
        &self.creator_hex
    }
    /// Creator-scoped instance creation seed, as lowercase hex.
    #[must_use]
    pub fn seed_hex(&self) -> &str {
        &self.seed_hex
    }
    /// Exact instance authorization revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    /// Exact instance record commitment (algorithm-prefixed hex).
    #[must_use]
    pub fn record_digest_hex(&self) -> &str {
        &self.record_digest_hex
    }
}

fn render_instance_target(
    renderer: &mut BoundedRenderer,
    prefix: &str,
    instance: &InstanceTarget,
) -> Result<InstanceTargetReview, FeeClaimReviewError> {
    let creator_hex: String = renderer.push_hex(format!("{prefix}.creator"), &instance.creator)?;
    let seed_hex: String = renderer.push_hex(format!("{prefix}.seed"), &instance.seed)?;
    renderer.push(format!("{prefix}.revision"), instance.revision.to_string())?;
    let record_digest_hex: String = instance.record_digest.to_string();
    renderer.push(format!("{prefix}.record_digest"), record_digest_hex.clone())?;
    Ok(InstanceTargetReview {
        creator_hex,
        seed_hex,
        revision: instance.revision,
        record_digest_hex,
    })
}

/// Bounded, display-safe presentation of one [`UnverifiedDependencyRef`]
/// naming exact call/instance/authorization code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodeReferenceReview {
    chain_id: String,
    publisher_hex: String,
    seed_hex: String,
    revision: u64,
    protocol_version: u32,
    epoch: u64,
    artifact_digest_hex: String,
}
impl CodeReferenceReview {
    /// Code origin's declared chain identifier (printable, display-safe).
    #[must_use]
    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }
    /// Code origin's declared publisher reference, as lowercase hex.
    #[must_use]
    pub fn publisher_hex(&self) -> &str {
        &self.publisher_hex
    }
    /// Code origin's declared creation seed, as lowercase hex.
    #[must_use]
    pub fn seed_hex(&self) -> &str {
        &self.seed_hex
    }
    /// Exact code revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    /// Code's declared context protocol version.
    #[must_use]
    pub const fn protocol_version(&self) -> u32 {
        self.protocol_version
    }
    /// Code's declared context epoch.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }
    /// Exact code artifact commitment digest (algorithm-prefixed hex).
    #[must_use]
    pub fn artifact_digest_hex(&self) -> &str {
        &self.artifact_digest_hex
    }
}

fn render_code_reference(
    renderer: &mut BoundedRenderer,
    prefix: &str,
    code: &UnverifiedDependencyRef,
) -> Result<CodeReferenceReview, FeeClaimReviewError> {
    let origin = code.origin();
    let chain_id: String = display_safe(
        "code.origin.chain_id",
        origin.chain_id().as_str(),
        abi::package_types::MAX_PACKAGE_CHAIN_ID_BYTES,
    )?;
    renderer.push(format!("{prefix}.chain_id"), chain_id.clone())?;
    let publisher_hex: String =
        renderer.push_hex(format!("{prefix}.publisher"), origin.publisher())?;
    let seed_hex: String = renderer.push_hex(format!("{prefix}.seed"), origin.seed())?;
    renderer.push(format!("{prefix}.revision"), code.revision().to_string())?;
    let protocol_version: u32 = code.context().protocol_version().get();
    renderer.push(
        format!("{prefix}.protocol_version"),
        protocol_version.to_string(),
    )?;
    let epoch: u64 = code.context().epoch().get();
    renderer.push(format!("{prefix}.epoch"), epoch.to_string())?;
    let artifact_digest_hex: String = code.artifact_digest().to_string();
    renderer.push(
        format!("{prefix}.artifact_digest"),
        artifact_digest_hex.clone(),
    )?;
    Ok(CodeReferenceReview {
        chain_id,
        publisher_hex,
        seed_hex,
        revision: code.revision(),
        protocol_version,
        epoch,
        artifact_digest_hex,
    })
}

/// Bounded, display-safe presentation of one [`ExecutionTarget`] (an
/// authorization's caller or callee frame).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionTargetReview {
    instance: InstanceTargetReview,
    code: CodeReferenceReview,
}
impl ExecutionTargetReview {
    /// Exact independently named instance target.
    #[must_use]
    pub fn instance(&self) -> &InstanceTargetReview {
        &self.instance
    }
    /// Exact code reference.
    #[must_use]
    pub fn code(&self) -> &CodeReferenceReview {
        &self.code
    }
}

fn render_execution_target(
    renderer: &mut BoundedRenderer,
    prefix: &str,
    target: &ExecutionTarget,
) -> Result<ExecutionTargetReview, FeeClaimReviewError> {
    let instance: InstanceTargetReview =
        render_instance_target(renderer, &format!("{prefix}.instance"), &target.instance)?;
    let code: CodeReferenceReview =
        render_code_reference(renderer, &format!("{prefix}.code"), &target.code)?;
    Ok(ExecutionTargetReview { instance, code })
}

/// Bounded, display-safe presentation of one declared access/authorization
/// object reference and its mode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessEntryReview {
    object_ref: ObjectRefReview,
    mode: &'static str,
}
impl AccessEntryReview {
    /// Declared object reference.
    #[must_use]
    pub fn object_ref(&self) -> &ObjectRefReview {
        &self.object_ref
    }
    /// Declared access mode (`"read"`, `"write"`, or `"consume"`).
    #[must_use]
    pub const fn mode(&self) -> &'static str {
        self.mode
    }
}

/// Bounded, display-safe presentation of one authorization's original
/// signed input selector.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedObjectReview {
    object_id_hex: String,
    mode: &'static str,
}
impl AuthorizedObjectReview {
    /// Original signed input object identifier, as lowercase hex.
    #[must_use]
    pub fn object_id_hex(&self) -> &str {
        &self.object_id_hex
    }
    /// Maximum delegated access mode (`"read"`, `"write"`, or `"consume"`).
    #[must_use]
    pub const fn mode(&self) -> &'static str {
        self.mode
    }
}

/// Bounded, display-safe presentation of one reusable [`CallAuthorization`]
/// capability declared by the embedded leg.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallAuthorizationReview {
    caller: ExecutionTargetReview,
    callee: ExecutionTargetReview,
    entrypoint: String,
    type_arguments: Vec<String>,
    objects: Vec<AuthorizedObjectReview>,
}
impl CallAuthorizationReview {
    /// Exact permitted calling frame.
    #[must_use]
    pub fn caller(&self) -> &ExecutionTargetReview {
        &self.caller
    }
    /// Exact selected execution frame.
    #[must_use]
    pub fn callee(&self) -> &ExecutionTargetReview {
        &self.callee
    }
    /// Committed callee export (printable, display-safe).
    #[must_use]
    pub fn entrypoint(&self) -> &str {
        &self.entrypoint
    }
    /// Ordered concrete generic arguments, each rendered bounded and safe.
    #[must_use]
    pub fn type_arguments(&self) -> &[String] {
        &self.type_arguments
    }
    /// Ordered original input selectors and their delegated mode.
    #[must_use]
    pub fn objects(&self) -> &[AuthorizedObjectReview] {
        &self.objects
    }
}

/// Recursively renders one bounded, display-safe [`abi::package_types::ScopedTypeArg`]
/// (and any nested nominal tag) into one safe text line. Nesting depth and
/// node count are already bounded by the existing scoped-type decoder that
/// produced the value, so this recursion cannot run unbounded.
fn render_scoped_type_arg(
    arg: &abi::package_types::ScopedTypeArg,
) -> Result<String, FeeClaimReviewError> {
    match arg {
        abi::package_types::ScopedTypeArg::Opaque { domain, value } => {
            Ok(format!("opaque(domain={domain:#06x},value={})", hex(value)))
        }
        abi::package_types::ScopedTypeArg::Nominal(tag) => render_scoped_type_tag(tag),
    }
}

fn render_scoped_type_tag(
    tag: &abi::package_types::ScopedTypeTag,
) -> Result<String, FeeClaimReviewError> {
    let chain: String = display_safe(
        "type_tag.chain_id",
        tag.origin().chain_id().as_str(),
        abi::package_types::MAX_PACKAGE_CHAIN_ID_BYTES,
    )?;
    let publisher_hex: String = hex(tag.origin().publisher());
    let seed_hex: String = hex(tag.origin().seed());
    let mut parts: Vec<String> = Vec::with_capacity(tag.args().len());
    for arg in tag.args() {
        parts.push(render_scoped_type_arg(arg)?);
    }
    Ok(format!(
        "nominal(chain={chain},publisher={publisher_hex},seed={seed_hex},constructor={:#06x},args=[{}])",
        tag.constructor(),
        parts.join(";"),
    ))
}

fn render_call_authorization(
    renderer: &mut BoundedRenderer,
    prefix: &str,
    authorization: &CallAuthorization,
) -> Result<CallAuthorizationReview, FeeClaimReviewError> {
    let caller: ExecutionTargetReview =
        render_execution_target(renderer, &format!("{prefix}.caller"), &authorization.caller)?;
    let callee: ExecutionTargetReview =
        render_execution_target(renderer, &format!("{prefix}.callee"), &authorization.callee)?;
    let entrypoint: String = display_safe(
        "authorization.entrypoint",
        &authorization.entrypoint,
        abi::MAX_ENTRYPOINT_BYTES,
    )?;
    renderer.push(format!("{prefix}.entrypoint"), entrypoint.clone())?;
    let mut type_arguments: Vec<String> = Vec::with_capacity(authorization.type_arguments.len());
    renderer.push(
        format!("{prefix}.type_argument_count"),
        authorization.type_arguments.len().to_string(),
    )?;
    for (index, arg) in authorization.type_arguments.iter().enumerate() {
        let rendered: String = render_scoped_type_arg(arg)?;
        renderer.push(
            format!("{prefix}.type_arguments[{index}]"),
            rendered.clone(),
        )?;
        type_arguments.push(rendered);
    }
    let mut objects: Vec<AuthorizedObjectReview> = Vec::with_capacity(authorization.objects.len());
    renderer.push(
        format!("{prefix}.object_count"),
        authorization.objects.len().to_string(),
    )?;
    for (index, object) in authorization.objects.iter().enumerate() {
        let object_id_hex: String = object.object_id.to_string();
        renderer.push(
            format!("{prefix}.objects[{index}].object_id"),
            object_id_hex.clone(),
        )?;
        let mode: &'static str = access_mode_label(object.mode);
        renderer.push(format!("{prefix}.objects[{index}].mode"), mode)?;
        objects.push(AuthorizedObjectReview {
            object_id_hex,
            mode,
        });
    }
    Ok(CallAuthorizationReview {
        caller,
        callee,
        entrypoint,
        type_arguments,
        objects,
    })
}

/// Bounded, display-safe presentation of one [`CallIntent`] -- the embedded
/// leg's exact call target, entrypoint, type arguments, declared access and
/// opaque argument bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallIntentReview {
    chain_id: String,
    protocol_version: u32,
    epoch: u64,
    request_id_hex: String,
    sender_hex: String,
    nonce: u64,
    code: CodeReferenceReview,
    instance: InstanceTargetReview,
    entrypoint: String,
    type_arguments: Vec<String>,
    access: Vec<AccessEntryReview>,
    arguments_hex: String,
    gas_limit: u64,
}
impl CallIntentReview {
    /// Expected replay context chain identifier (printable, display-safe).
    #[must_use]
    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }
    /// Expected replay context protocol version.
    #[must_use]
    pub const fn protocol_version(&self) -> u32 {
        self.protocol_version
    }
    /// Expected replay context epoch.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }
    /// Exact replay identity covered by the leg's own signature, as lowercase hex.
    #[must_use]
    pub fn request_id_hex(&self) -> &str {
        &self.request_id_hex
    }
    /// Claimed sender public key, as lowercase hex.
    #[must_use]
    pub fn sender_hex(&self) -> &str {
        &self.sender_hex
    }
    /// Signed sender sequence.
    #[must_use]
    pub const fn nonce(&self) -> u64 {
        self.nonce
    }
    /// Exact code revision reference.
    #[must_use]
    pub fn code(&self) -> &CodeReferenceReview {
        &self.code
    }
    /// Independent instance target.
    #[must_use]
    pub fn instance(&self) -> &InstanceTargetReview {
        &self.instance
    }
    /// Exact exported entrypoint name (printable, display-safe).
    #[must_use]
    pub fn entrypoint(&self) -> &str {
        &self.entrypoint
    }
    /// Ordered concrete type arguments, each rendered bounded and safe.
    #[must_use]
    pub fn type_arguments(&self) -> &[String] {
        &self.type_arguments
    }
    /// Signed access order, object references and modes.
    #[must_use]
    pub fn access(&self) -> &[AccessEntryReview] {
        &self.access
    }
    /// Exact call argument bytes, opaque/uninterpreted, as lowercase hex.
    #[must_use]
    pub fn arguments_hex(&self) -> &str {
        &self.arguments_hex
    }
    /// Signed execution gas ceiling.
    #[must_use]
    pub const fn gas_limit(&self) -> u64 {
        self.gas_limit
    }
}

fn render_call_intent(
    renderer: &mut BoundedRenderer,
    prefix: &str,
    call: &CallIntent,
) -> Result<CallIntentReview, FeeClaimReviewError> {
    let chain_id: String = display_safe(
        "call.context.chain_id",
        call.context.chain_id().as_str(),
        abi::package_types::MAX_PACKAGE_CHAIN_ID_BYTES,
    )?;
    renderer.push(format!("{prefix}.chain_id"), chain_id.clone())?;
    let protocol_version: u32 = call.context.protocol_version().get();
    renderer.push(
        format!("{prefix}.protocol_version"),
        protocol_version.to_string(),
    )?;
    let epoch: u64 = call.context.epoch().get();
    renderer.push(format!("{prefix}.epoch"), epoch.to_string())?;
    let request_id_hex: String =
        renderer.push_hex(format!("{prefix}.request_id"), &call.request_id)?;
    let sender_hex: String = renderer.push_hex(format!("{prefix}.sender"), &call.sender)?;
    renderer.push(format!("{prefix}.nonce"), call.nonce.to_string())?;
    let code: CodeReferenceReview =
        render_code_reference(renderer, &format!("{prefix}.code"), &call.code)?;
    let instance: InstanceTargetReview =
        render_instance_target(renderer, &format!("{prefix}.instance"), &call.instance)?;
    let entrypoint: String = display_safe(
        "call.entrypoint",
        &call.entrypoint,
        abi::MAX_ENTRYPOINT_BYTES,
    )?;
    renderer.push(format!("{prefix}.entrypoint"), entrypoint.clone())?;
    let mut type_arguments: Vec<String> = Vec::with_capacity(call.type_arguments.len());
    renderer.push(
        format!("{prefix}.type_argument_count"),
        call.type_arguments.len().to_string(),
    )?;
    for (index, arg) in call.type_arguments.iter().enumerate() {
        let rendered: String = render_scoped_type_arg(arg)?;
        renderer.push(
            format!("{prefix}.type_arguments[{index}]"),
            rendered.clone(),
        )?;
        type_arguments.push(rendered);
    }
    let mut access: Vec<AccessEntryReview> = Vec::with_capacity(call.access.entries.len());
    renderer.push(
        format!("{prefix}.access_count"),
        call.access.entries.len().to_string(),
    )?;
    for (index, entry) in call.access.entries.iter().enumerate() {
        let object_ref: ObjectRefReview = render_object_ref(
            renderer,
            &format!("{prefix}.access[{index}]"),
            &entry.object_ref,
        )?;
        let mode: &'static str = access_mode_label(entry.mode);
        renderer.push(format!("{prefix}.access[{index}].mode"), mode)?;
        access.push(AccessEntryReview { object_ref, mode });
    }
    let arguments_hex: String =
        renderer.push_hex(format!("{prefix}.arguments(opaque)"), &call.arguments)?;
    renderer.push(format!("{prefix}.gas_limit"), call.gas_limit.to_string())?;
    Ok(CallIntentReview {
        chain_id,
        protocol_version,
        epoch,
        request_id_hex,
        sender_hex,
        nonce: call.nonce,
        code,
        instance,
        entrypoint,
        type_arguments,
        access,
        arguments_hex,
        gas_limit: call.gas_limit,
    })
}

/// Bounded, display-safe presentation of one fully decoded
/// [`SignedLocalExecutionIntent`] embedded in a `Split`/`FinalTransfer`
/// fee-claim operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalExecutionLegReview {
    mode: &'static str,
    policy_digest_hex: String,
    call: CallIntentReview,
    authorizations: Vec<CallAuthorizationReview>,
    signature_hex: String,
    leg_bytes: Vec<u8>,
}
impl LocalExecutionLegReview {
    /// `"instantiate"` or `"call"`.
    #[must_use]
    pub const fn mode(&self) -> &'static str {
        self.mode
    }
    /// Exact committed execution-policy digest (algorithm-prefixed hex).
    #[must_use]
    pub fn policy_digest_hex(&self) -> &str {
        &self.policy_digest_hex
    }
    /// Exact call target, entrypoint, type arguments, access and arguments.
    #[must_use]
    pub fn call(&self) -> &CallIntentReview {
        &self.call
    }
    /// Ordered reusable signed capability ceilings.
    #[must_use]
    pub fn authorizations(&self) -> &[CallAuthorizationReview] {
        &self.authorizations
    }
    /// Leg signature, as lowercase hex.
    #[must_use]
    pub fn signature_hex(&self) -> &str {
        &self.signature_hex
    }
    /// Exact original canonical signed-leg bytes.
    #[must_use]
    pub fn leg_bytes(&self) -> &[u8] {
        &self.leg_bytes
    }
}

fn render_leg(
    renderer: &mut BoundedRenderer,
    prefix: &str,
    leg_bytes: &[u8],
) -> Result<LocalExecutionLegReview, FeeClaimReviewError> {
    let signed: SignedLocalExecutionIntent = decode_signed_local_execution(leg_bytes)?;
    renderer.push_hex(format!("{prefix}.raw_bytes"), leg_bytes)?;
    let mode: &'static str = match signed.intent.mode {
        LocalExecutionMode::Instantiate => "instantiate",
        LocalExecutionMode::Call => "call",
    };
    renderer.push(format!("{prefix}.mode"), mode)?;
    let policy_digest_hex: String = signed.intent.policy_digest.to_string();
    renderer.push(format!("{prefix}.policy_digest"), policy_digest_hex.clone())?;
    let call: CallIntentReview =
        render_call_intent(renderer, &format!("{prefix}.call"), &signed.intent.call)?;
    let mut authorizations: Vec<CallAuthorizationReview> =
        Vec::with_capacity(signed.intent.authorizations.len());
    renderer.push(
        format!("{prefix}.authorization_count"),
        signed.intent.authorizations.len().to_string(),
    )?;
    for (index, authorization) in signed.intent.authorizations.iter().enumerate() {
        authorizations.push(render_call_authorization(
            renderer,
            &format!("{prefix}.authorizations[{index}]"),
            authorization,
        )?);
    }
    let signature_hex: String =
        renderer.push_hex(format!("{prefix}.signature"), &signed.signature)?;
    Ok(LocalExecutionLegReview {
        mode,
        policy_digest_hex,
        call,
        authorizations,
        signature_hex,
        leg_bytes: leg_bytes.to_vec(),
    })
}

/// The closed fee-claim operation, fully decoded for `Split`/`FinalTransfer`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FeeClaimOperationReview {
    /// A zero-amount entitlement; no embedded leg.
    ZeroShare,
    /// A partial positive claim through the policy-pinned `split` entrypoint.
    Split {
        /// Fully decoded embedded leg.
        leg: LocalExecutionLegReview,
        /// Signed expected post-split payout ref (`v2` only).
        expected_payout: Option<ObjectRefReview>,
    },
    /// The final positive claim through the policy-pinned `transfer` entrypoint.
    FinalTransfer {
        /// Fully decoded embedded leg.
        leg: LocalExecutionLegReview,
    },
}

/// Immutable, display-safe, non-authorizing fee-claim review snapshot.
///
/// Built only from a [`PreparedFeeClaim`]'s own retained inputs. Building
/// one performs no signing or network action and accepts no replacement
/// content after construction. See the module docs for this review's
/// explicit non-claims: it is a legible restatement of retained content,
/// never certified row authenticity or economic correctness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeeClaimReview {
    chain_id: String,
    protocol_version: u32,
    epoch: u64,
    request_id_hex: String,
    escrow_request_id_hex: String,
    certificate_epoch: u64,
    validator_id_hex: String,
    claimant_hex: String,
    resource_domain: u16,
    resource_value_hex: String,
    expected_generation: u64,
    expected_fee_output: ObjectRefReview,
    expected_previous_row_digest_hex: String,
    expected_next_row_digest_hex: String,
    share_amount: u64,
    recipient_hex: String,
    operation: FeeClaimOperationReview,
    intent_digest_hex: String,
    frame_hex: String,
    intent_bytes: Vec<u8>,
    frame_bytes: Vec<u8>,
    lines: Vec<(String, String)>,
}

impl FeeClaimReview {
    /// Builds a bounded, display-safe, non-authorizing review snapshot from
    /// a [`PreparedFeeClaim`]'s own retained inputs.
    ///
    /// Performs a defensive self-consistency recheck (intent round-trip,
    /// recomputed digest, recomputed signing frame) against exactly what
    /// `prepared` retained, then renders every material field through one
    /// bounded internal renderer. Any mismatch, undisplayable field, or
    /// exceeded bound refuses with a typed error and builds no partial
    /// review. `prepared` is already bound to the historical certificate
    /// committee's claimant key ([`PreparedFeeClaim::claimant`]); this
    /// function does not re-derive or alter that authority.
    pub fn build(prepared: &PreparedFeeClaim<'_>) -> Result<Self, FeeClaimReviewError> {
        let resolver: &HashSuiteResolver = prepared.workflow().ordered_policy().resolver();
        let mut review: Self = Self::build_from_parts(
            prepared.intent(),
            prepared.claimant(),
            *prepared.intent_digest(),
            prepared.signable_frame(),
            resolver,
        )?;
        let total_bytes: usize = review
            .lines
            .iter()
            .map(|(label, value)| label.len() + value.len() + 2)
            .sum();
        let mut renderer: BoundedRenderer = BoundedRenderer {
            lines: review.lines,
            total_bytes,
        };
        let policy = prepared.workflow().ordered_policy();
        renderer.push(
            "workflow.genesis_digest",
            prepared.workflow().genesis_root().digest().to_string(),
        )?;
        renderer.push("workflow.domain", policy.domain().to_string())?;
        renderer.push("workflow.ordered_anchor", policy.anchor().to_string())?;
        review.lines = renderer.lines;
        Ok(review)
    }

    /// Private component-render seam: builds the same review from raw
    /// retained parts instead of a full verified [`PreparedFeeClaim`]. The
    /// public [`Self::build`] above accepts only a fully verified prepared
    /// claim; this private function exists so
    /// focused unit tests can exercise the renderer without constructing a
    /// complete certificate/committee/workflow fixture, and proves nothing
    /// about claimant authority on its own.
    fn build_from_parts(
        intent: &FeeClaimIntent,
        claimant: Address,
        intent_digest: Digest32,
        frame: &[u8],
        resolver: &HashSuiteResolver,
    ) -> Result<Self, FeeClaimReviewError> {
        let intent_bytes: Vec<u8> = encode_fee_claim_intent(intent)?;
        let redecoded: FeeClaimIntent = decode_fee_claim_intent(&intent_bytes)?;
        if &redecoded != intent {
            return Err(FeeClaimReviewError::IntentRoundTripMismatch);
        }
        let recomputed_digest: Digest32 = fee_claim_intent_digest(resolver, intent)?;
        if recomputed_digest != intent_digest {
            return Err(FeeClaimReviewError::DigestMismatch);
        }
        let recomputed_frame: Vec<u8> =
            fee_claim_signing_frame(&intent.context, recomputed_digest)?;
        if recomputed_frame.as_slice() != frame {
            return Err(FeeClaimReviewError::FrameMismatch);
        }

        let mut renderer: BoundedRenderer = BoundedRenderer::new();
        renderer.push("review_kind", "non_authorizing_content_inspection")?;
        renderer.push(
            "claimant_source",
            "verified_historical_certificate_committee",
        )?;
        renderer.push(
            "economic_fields",
            "host_proposed_enforced_by_ordered_execution",
        )?;
        renderer.push(
            "generic_code_and_arguments",
            "uninterpreted_not_business_approval",
        )?;
        renderer.push(
            "leg_signature_status",
            "displayed_not_authenticated_by_this_review",
        )?;

        let chain_id: String = display_safe(
            "context.chain_id",
            intent.context.chain_id().as_str(),
            abi::package_types::MAX_PACKAGE_CHAIN_ID_BYTES,
        )?;
        renderer.push("chain_id", chain_id.clone())?;
        let protocol_version: u32 = intent.context.protocol_version().get();
        renderer.push("protocol_version", protocol_version.to_string())?;
        let epoch: u64 = intent.context.epoch().get();
        renderer.push("epoch", epoch.to_string())?;
        let request_id_hex: String = renderer.push_hex("request_id", &intent.request_id)?;
        let escrow_request_id_hex: String =
            renderer.push_hex("escrow_request_id", &intent.escrow_request_id)?;
        let certificate_epoch: u64 = intent.certificate_epoch.get();
        renderer.push("certificate_epoch", certificate_epoch.to_string())?;
        let validator_id_hex: String = intent.validator_id.to_string();
        renderer.push("validator_id", validator_id_hex.clone())?;
        let claimant_hex: String = claimant.to_string();
        renderer.push("claimant", claimant_hex.clone())?;
        let resource_domain: u16 = intent.resource_id.domain();
        renderer.push("resource_id.domain", format!("{resource_domain:#06x}"))?;
        let resource_value_hex: String =
            renderer.push_hex("resource_id.value", intent.resource_id.value())?;
        renderer.push(
            "expected_generation",
            intent.expected_generation.to_string(),
        )?;
        let expected_fee_output: ObjectRefReview = render_object_ref(
            &mut renderer,
            "expected_fee_output",
            &intent.expected_fee_output,
        )?;
        let expected_previous_row_digest_hex: String =
            intent.expected_previous_row_digest.to_string();
        renderer.push(
            "expected_previous_row_digest",
            expected_previous_row_digest_hex.clone(),
        )?;
        let expected_next_row_digest_hex: String = intent.expected_next_row_digest.to_string();
        renderer.push(
            "expected_next_row_digest",
            expected_next_row_digest_hex.clone(),
        )?;
        renderer.push("share_amount", intent.share_amount.to_string())?;
        let recipient_hex: String = intent.recipient.to_string();
        renderer.push("recipient", recipient_hex.clone())?;

        if let FeeClaimOperation::Split { leg, .. } | FeeClaimOperation::FinalTransfer { leg } =
            &intent.operation
        {
            let signed: SignedLocalExecutionIntent = decode_signed_local_execution(leg)?;
            if signed.intent.call.context != intent.context
                || signed.intent.call.request_id != intent.request_id
            {
                return Err(FeeClaimReviewError::LegBindingMismatch);
            }
        }
        let operation: FeeClaimOperationReview = match &intent.operation {
            FeeClaimOperation::ZeroShare => {
                renderer.push("operation", "zero_share")?;
                FeeClaimOperationReview::ZeroShare
            }
            FeeClaimOperation::Split {
                leg,
                expected_payout,
            } => {
                renderer.push("operation", "split")?;
                let leg_review: LocalExecutionLegReview = render_leg(&mut renderer, "leg", leg)?;
                let expected_payout_review: Option<ObjectRefReview> = match expected_payout {
                    Some(object_ref) => Some(render_object_ref(
                        &mut renderer,
                        "operation.expected_payout",
                        object_ref,
                    )?),
                    None => None,
                };
                FeeClaimOperationReview::Split {
                    leg: leg_review,
                    expected_payout: expected_payout_review,
                }
            }
            FeeClaimOperation::FinalTransfer { leg } => {
                renderer.push("operation", "final_transfer")?;
                let leg_review: LocalExecutionLegReview = render_leg(&mut renderer, "leg", leg)?;
                FeeClaimOperationReview::FinalTransfer { leg: leg_review }
            }
        };

        let intent_digest_hex: String = intent_digest.to_string();
        renderer.push("intent_digest", intent_digest_hex.clone())?;
        let frame_hex: String = renderer.push_hex("frame", frame)?;

        Ok(Self {
            chain_id,
            protocol_version,
            epoch,
            request_id_hex,
            escrow_request_id_hex,
            certificate_epoch,
            validator_id_hex,
            claimant_hex,
            resource_domain,
            resource_value_hex,
            expected_generation: intent.expected_generation,
            expected_fee_output,
            expected_previous_row_digest_hex,
            expected_next_row_digest_hex,
            share_amount: intent.share_amount,
            recipient_hex,
            operation,
            intent_digest_hex,
            frame_hex,
            intent_bytes,
            frame_bytes: frame.to_vec(),
            lines: renderer.finish(),
        })
    }

    /// Replay-context chain identifier (printable, display-safe).
    #[must_use]
    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }
    /// Replay-context protocol version.
    #[must_use]
    pub const fn protocol_version(&self) -> u32 {
        self.protocol_version
    }
    /// Replay-context epoch.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }
    /// Exact replay identity covered by the claimant's signature, as lowercase hex.
    #[must_use]
    pub fn request_id_hex(&self) -> &str {
        &self.request_id_hex
    }
    /// Exact request id of the certified-apply intent that created the
    /// targeted escrow row, as lowercase hex.
    #[must_use]
    pub fn escrow_request_id_hex(&self) -> &str {
        &self.escrow_request_id_hex
    }
    /// Exact certificate epoch the signer binds this claim to. The claimant
    /// below is resolved from this epoch's historical committee, never the
    /// current one.
    #[must_use]
    pub const fn certificate_epoch(&self) -> u64 {
        self.certificate_epoch
    }
    /// Validator this claim is signed by and attributed to, as lowercase hex.
    #[must_use]
    pub fn validator_id_hex(&self) -> &str {
        &self.validator_id_hex
    }
    /// Expected claimant identity resolved from the historical certificate
    /// committee ([`PreparedFeeClaim::claimant`]), never the current
    /// committee or an untrusted response, as lowercase hex.
    #[must_use]
    pub fn claimant_hex(&self) -> &str {
        &self.claimant_hex
    }
    /// Expected fee resource's non-zero nominal-type domain.
    #[must_use]
    pub const fn resource_domain(&self) -> u16 {
        self.resource_domain
    }
    /// Expected fee resource's opaque value, as lowercase hex.
    #[must_use]
    pub fn resource_value_hex(&self) -> &str {
        &self.resource_value_hex
    }
    /// Exact current (pre-claim) generation the signer expects.
    #[must_use]
    pub const fn expected_generation(&self) -> u64 {
        self.expected_generation
    }
    /// Exact current `FeeEscrow` object ref the signer expects.
    #[must_use]
    pub fn expected_fee_output(&self) -> &ObjectRefReview {
        &self.expected_fee_output
    }
    /// Exact digest of the current (pre-claim) escrow row the signer
    /// expects (algorithm-prefixed hex).
    #[must_use]
    pub fn expected_previous_row_digest_hex(&self) -> &str {
        &self.expected_previous_row_digest_hex
    }
    /// Exact digest of the deterministically resulting escrow row this
    /// claim must produce (algorithm-prefixed hex).
    #[must_use]
    pub fn expected_next_row_digest_hex(&self) -> &str {
        &self.expected_next_row_digest_hex
    }
    /// Exact entitlement amount this claim releases.
    #[must_use]
    pub const fn share_amount(&self) -> u64 {
        self.share_amount
    }
    /// Exact recipient of a positive claim's released value, as lowercase hex.
    #[must_use]
    pub fn recipient_hex(&self) -> &str {
        &self.recipient_hex
    }
    /// The closed operation and its fully decoded embedded leg, if any.
    #[must_use]
    pub fn operation(&self) -> &FeeClaimOperationReview {
        &self.operation
    }
    /// Recomputed and matched fee-claim intent digest (algorithm-prefixed hex).
    #[must_use]
    pub fn intent_digest_hex(&self) -> &str {
        &self.intent_digest_hex
    }
    /// Exact recomputed and matched signing frame, as lowercase hex.
    #[must_use]
    pub fn frame_hex(&self) -> &str {
        &self.frame_hex
    }
    /// Exact bounded canonical (unsigned) intent bytes, for independent
    /// inspection or hashing with any tool. Not itself rendered as a line
    /// in [`Self::render_text`]: a `Split`/`FinalTransfer` intent already
    /// embeds the leg bytes rendered separately there, and the outer
    /// envelope can approach the protocol's own multi-hundred-kilobyte
    /// ceiling.
    #[must_use]
    pub fn intent_bytes(&self) -> &[u8] {
        &self.intent_bytes
    }
    /// Exact bounded signing frame bytes, byte-for-byte identical to
    /// [`PreparedFeeClaim::signable_frame`].
    #[must_use]
    pub fn frame_bytes(&self) -> &[u8] {
        &self.frame_bytes
    }
    /// Every rendered `(label, value)` line, in presentation order, exactly
    /// as counted against this review's aggregate byte budget.
    #[must_use]
    pub fn fields(&self) -> &[(String, String)] {
        &self.lines
    }
    /// The one complete bounded text rendering of every field this review
    /// counted toward its aggregate budget, as `label=value\n` lines in
    /// presentation order.
    #[must_use]
    pub fn render_text(&self) -> String {
        let capacity: usize = self
            .lines
            .iter()
            .map(|(label, value)| label.len() + value.len() + 2)
            .sum();
        let mut out: String = String::with_capacity(capacity);
        for (label, value) in &self.lines {
            out.push_str(label);
            out.push('=');
            out.push_str(value);
            out.push('\n');
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::AccessManifest;
    use abi::package_types::PackageOrigin;
    use execution::local_execution::{LocalExecutionIntent, encode_signed_local_execution};
    use execution::publication::PublicationContext;
    use objects::ObjectId;
    use protocol_types::{
        ChainId, Epoch, HashAlgorithmId, HashSuite, HashSuiteSchedule, ProtocolVersion, ValidatorId,
    };

    fn context() -> PublicationContext {
        PublicationContext::new(
            ChainId::new("fee-claim-review-test").unwrap(),
            ProtocolVersion::new(1),
            Epoch::new(1),
        )
        .unwrap()
    }

    fn base_intent(operation: FeeClaimOperation, share_amount: u64) -> FeeClaimIntent {
        FeeClaimIntent {
            context: context(),
            request_id: [2; 32],
            escrow_request_id: [1; 32],
            certificate_epoch: Epoch::new(3),
            validator_id: ValidatorId::new([3; 32]),
            resource_id: crate::bond_registration::BondResourceId::new(1, [9; 32]).unwrap(),
            expected_generation: 1,
            expected_fee_output: ObjectRef {
                id: ObjectId::new([10; 32]),
                version: 1,
                digest: Digest32::new(HashAlgorithmId::Sha2_256, [11; 32]),
            },
            expected_previous_row_digest: Digest32::new(HashAlgorithmId::Sha2_256, [12; 32]),
            expected_next_row_digest: Digest32::new(HashAlgorithmId::Sha2_256, [13; 32]),
            share_amount,
            recipient: Address::new([5; 32]),
            operation,
        }
    }

    fn signed_leg(arguments: Vec<u8>) -> Vec<u8> {
        let ctx: PublicationContext = context();
        let origin: PackageOrigin =
            PackageOrigin::unverified(ctx.chain_id().clone(), [0x11; 32], [0x22; 32]).unwrap();
        let code: UnverifiedDependencyRef = UnverifiedDependencyRef::new(
            origin,
            1,
            ctx.clone(),
            Digest32::new(HashAlgorithmId::Sha2_256, [0x33; 32]),
        )
        .unwrap();
        let instance: InstanceTarget = InstanceTarget {
            creator: [0x44; 32],
            seed: [0x55; 32],
            revision: 1,
            record_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x66; 32]),
        };
        let call: CallIntent = CallIntent {
            context: ctx,
            request_id: [2; 32],
            sender: [0x44; 32],
            nonce: 0,
            code,
            instance,
            entrypoint: "noop".to_owned(),
            type_arguments: Vec::new(),
            access: AccessManifest::default(),
            arguments,
            gas_limit: 1,
        };
        let intent: LocalExecutionIntent = LocalExecutionIntent {
            mode: LocalExecutionMode::Call,
            policy_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x88; 32]),
            call,
            authorizations: Vec::new(),
        };
        let signed: SignedLocalExecutionIntent = SignedLocalExecutionIntent {
            intent,
            signature: [0; 64],
        };
        encode_signed_local_execution(&signed).unwrap()
    }

    /// Builds a review directly from an unverified intent, bypassing the
    /// real certificate/committee/workflow fixture. This is a structural
    /// renderer test only; it proves nothing about claimant authority,
    /// which [`PreparedFeeClaim::prepare`] owns.
    fn built(intent: &FeeClaimIntent) -> Result<FeeClaimReview, FeeClaimReviewError> {
        let resolver: HashSuiteResolver = HashSuiteResolver::new(
            intent.context.chain_id().clone(),
            intent.context.protocol_version(),
            vec![HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: HashSuite::genesis(),
            }],
        )
        .unwrap();
        let digest: Digest32 = fee_claim_intent_digest(&resolver, intent).unwrap();
        let frame: Vec<u8> = fee_claim_signing_frame(&intent.context, digest).unwrap();
        FeeClaimReview::build_from_parts(intent, Address::new([7; 32]), digest, &frame, &resolver)
    }

    #[test]
    fn zero_share_renders_without_a_leg() {
        let intent: FeeClaimIntent = base_intent(FeeClaimOperation::ZeroShare, 0);
        let review: FeeClaimReview = built(&intent).unwrap();
        assert!(matches!(
            review.operation(),
            FeeClaimOperationReview::ZeroShare
        ));
        assert_eq!(review.share_amount(), 0);
        assert_eq!(review.certificate_epoch(), 3);
    }

    #[test]
    fn split_v1_has_no_expected_payout_field() {
        let leg: Vec<u8> = signed_leg(Vec::new());
        let intent: FeeClaimIntent = base_intent(
            FeeClaimOperation::Split {
                leg,
                expected_payout: None,
            },
            5,
        );
        let review: FeeClaimReview = built(&intent).unwrap();
        match review.operation() {
            FeeClaimOperationReview::Split {
                leg,
                expected_payout,
            } => {
                assert!(expected_payout.is_none());
                assert_eq!(leg.mode(), "call");
                assert_eq!(leg.call().entrypoint(), "noop");
            }
            other => panic!("expected Split, got {other:?}"),
        }
    }

    #[test]
    fn split_v2_renders_the_signed_expected_payout() {
        let leg: Vec<u8> = signed_leg(Vec::new());
        let payout: ObjectRef = ObjectRef {
            id: ObjectId::new([20; 32]),
            version: 2,
            digest: Digest32::new(HashAlgorithmId::Sha2_256, [21; 32]),
        };
        let intent: FeeClaimIntent = base_intent(
            FeeClaimOperation::Split {
                leg,
                expected_payout: Some(payout),
            },
            5,
        );
        let review: FeeClaimReview = built(&intent).unwrap();
        match review.operation() {
            FeeClaimOperationReview::Split {
                expected_payout, ..
            } => {
                assert_eq!(expected_payout.as_ref().unwrap().version(), 2);
            }
            other => panic!("expected Split, got {other:?}"),
        }
    }

    #[test]
    fn final_transfer_renders_the_full_raw_leg_content() {
        let leg_bytes: Vec<u8> = signed_leg(vec![0xAB, 0xCD]);
        let intent: FeeClaimIntent = base_intent(
            FeeClaimOperation::FinalTransfer {
                leg: leg_bytes.clone(),
            },
            9,
        );
        let review: FeeClaimReview = built(&intent).unwrap();
        match review.operation() {
            FeeClaimOperationReview::FinalTransfer { leg } => {
                assert_eq!(leg.leg_bytes(), leg_bytes.as_slice());
                assert_eq!(leg.call().arguments_hex(), "abcd");
                assert_eq!(leg.signature_hex(), hex(&[0u8; 64]));
            }
            other => panic!("expected FinalTransfer, got {other:?}"),
        }
    }

    #[test]
    fn malformed_leg_bytes_are_refused() {
        let intent: FeeClaimIntent =
            base_intent(FeeClaimOperation::FinalTransfer { leg: vec![0xFF; 8] }, 9);
        assert!(matches!(
            built(&intent),
            Err(FeeClaimReviewError::Execution(_))
        ));
    }

    #[test]
    fn control_bytes_in_the_context_chain_id_are_refused() {
        let mut intent: FeeClaimIntent = base_intent(FeeClaimOperation::ZeroShare, 0);
        intent.context = PublicationContext::new(
            ChainId::new("fee-claim\u{1}review").unwrap(),
            ProtocolVersion::new(1),
            Epoch::new(1),
        )
        .unwrap();
        assert!(matches!(
            built(&intent),
            Err(FeeClaimReviewError::UndisplayableField("context.chain_id"))
        ));
    }

    #[test]
    fn oversized_call_arguments_refuse_rather_than_truncate() {
        let leg: Vec<u8> = signed_leg(vec![0u8; 40_000]);
        let intent: FeeClaimIntent = base_intent(FeeClaimOperation::FinalTransfer { leg }, 9);
        assert!(matches!(
            built(&intent),
            Err(FeeClaimReviewError::Limit { .. })
        ));
    }

    #[test]
    fn differing_generation_is_visible_in_rendered_fields() {
        let first: FeeClaimIntent = base_intent(FeeClaimOperation::ZeroShare, 0);
        let mut second: FeeClaimIntent = first.clone();
        second.expected_generation += 1;
        let review_first: FeeClaimReview = built(&first).unwrap();
        let review_second: FeeClaimReview = built(&second).unwrap();
        assert_ne!(
            review_first.expected_generation(),
            review_second.expected_generation()
        );
        assert_ne!(review_first.fields(), review_second.fields());
    }
    #[test]
    fn mismatched_leg_replay_id_or_context_is_refused() {
        let leg: Vec<u8> = signed_leg(Vec::new());
        let mut intent: FeeClaimIntent = base_intent(FeeClaimOperation::FinalTransfer { leg }, 9);
        intent.request_id[0] ^= 1;
        assert!(matches!(
            built(&intent),
            Err(FeeClaimReviewError::LegBindingMismatch)
        ));
        intent.request_id[0] ^= 1;
        intent.context = PublicationContext::new(
            intent.context.chain_id().clone(),
            intent.context.protocol_version(),
            Epoch::new(intent.context.epoch().get() + 1),
        )
        .unwrap();
        assert!(matches!(
            built(&intent),
            Err(FeeClaimReviewError::LegBindingMismatch)
        ));
    }

    #[test]
    fn rendered_content_labels_proposals_and_opaque_semantics_without_authorizing_them() {
        let intent: FeeClaimIntent = base_intent(FeeClaimOperation::ZeroShare, 0);
        let review: FeeClaimReview = built(&intent).unwrap();
        let text: String = review.render_text();
        for label in [
            "review_kind=non_authorizing_content_inspection",
            "economic_fields=host_proposed_enforced_by_ordered_execution",
            "generic_code_and_arguments=uninterpreted_not_business_approval",
            "leg_signature_status=displayed_not_authenticated_by_this_review",
        ] {
            assert!(text.contains(label));
        }
        assert!(text.len() <= MAX_FEE_CLAIM_REVIEW_OUTPUT_BYTES);
    }
}
