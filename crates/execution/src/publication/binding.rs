//! Instantiation and metadata matching for generic publication object signatures.
//!
//! # Explicit Non-Claims
//!
//! - **NO executable capability or host rights:** Instantiating a generic object signature
//!   or matching object metadata grants NO execution capability, VM privileges, host rights,
//!   or transaction admission.
//! - **NO owner validation:** Object owners (address, shared, immutable, system) are NOT
//!   validated or checked by this module.
//! - **NO body layout or schema decoding:** Object payloads are treated as opaque byte slices;
//!   this module asserts NO value-layout compatibility or body schema conformance.
//! - **NO object digest verification:** Neither [`objects::ObjectRef::digest`] nor stored object data
//!   digests are authenticated or rehashed here.
//! - **NO transaction signature or state freshness:** This module asserts NO transaction
//!   authenticity, replay protection, nonce validity, state freshness, or publication authority.
//! - **NO substitute for admission:** Neither manifest nor loaded state is authenticated by
//!   this helper. Arbitrary owner or body modifications may still match metadata; this module
//!   cannot substitute for transaction, storage, or owner admission.
//! - **No legacy ABI or AssetId special cases:** Nominal types and opaque domains follow
//!   strict DR-0113 / DR-0115 rules without legacy global constructor registries or AssetId
//!   privileges.

use abi::call_values::{ValueError, ValueLayout, decode_call_value};
use std::collections::BTreeSet;
use std::fmt;

use abi::AccessManifest;
use abi::package_types::{
    MAX_SCOPED_TYPE_ARGS, MAX_SCOPED_TYPE_DEPTH, MAX_SCOPED_TYPE_NODES, PackageTypeError,
    ScopedTypeArg, ScopedTypeTag, encode_scoped_type_tag, verify_scoped_type_id,
};
use abi::public_abi::{
    ArgumentKind, MAX_ABI_OBJECT_PARAMS, MAX_ABI_OBJECT_RESULTS, MAX_ABI_TYPE_PARAMS,
    MAX_ENTRYPOINT_NAME_BYTES, ObjectMode, PackageAbi, PatternArgument, TypePattern,
};
use hashing::HashSuiteResolver;
use objects::{AccessMode, ObjectId};
use protocol_types::Epoch;

use super::VerifiedPublicationInterface;
use crate::ResolvedObject;

/// Maximum aggregate encoded byte size for bound object parameter types in one signature (256 KiB).
pub const MAX_BOUND_TYPE_BYTES: usize = 256 * 1024;

/// Concrete instantiated object parameter describing expected access mode, schema, and scoped type tag.
///
/// Asserts structural and nominal type expectations only; asserts NO ownership or body layout rights.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundObjectParameter {
    mode: ObjectMode,
    schema: u32,
    ty: ScopedTypeTag,
}

impl BoundObjectParameter {
    /// Returns the access mode.
    #[must_use]
    pub fn mode(&self) -> ObjectMode {
        self.mode
    }

    /// Returns the schema version identifier.
    #[must_use]
    pub fn schema(&self) -> u32 {
        self.schema
    }

    /// Returns a reference to the bound scoped nominal type tag.
    #[must_use]
    pub fn ty(&self) -> &ScopedTypeTag {
        &self.ty
    }
}

/// Concrete instantiated ordered typed object result slot (DR-0124).
///
/// Asserts structural and nominal type expectations only; asserts NO
/// ownership, current handle rights, or body layout rights.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundObjectResult {
    mode: ObjectMode,
    schema: u32,
    ty: ScopedTypeTag,
    optional: bool,
}

impl BoundObjectResult {
    /// Returns the maximum access mode deliverable through this slot.
    #[must_use]
    pub fn mode(&self) -> ObjectMode {
        self.mode
    }

    /// Returns the schema version identifier.
    #[must_use]
    pub fn schema(&self) -> u32 {
        self.schema
    }

    /// Returns a reference to the bound scoped nominal type tag.
    #[must_use]
    pub fn ty(&self) -> &ScopedTypeTag {
        &self.ty
    }

    /// Returns whether this slot may be delivered absent.
    #[must_use]
    pub fn optional(&self) -> bool {
        self.optional
    }
}

/// An instantiated entrypoint object signature bound against a verified publication interface.
///
/// Retains a reference to the enclosing [`VerifiedPublicationInterface`] to ensure verification
/// context remains bound without cloning candidate WASM or ABI code blobs.
///
/// Grants NO executable capability, host authority, or storage rights.
#[derive(Debug)]
pub struct BoundObjectSignature<'a> {
    interface: &'a VerifiedPublicationInterface,
    entrypoint: &'a str,
    objects: Vec<BoundObjectParameter>,
    results: Vec<BoundObjectResult>,
    arguments: &'a ValueLayout,
}

impl<'a> BoundObjectSignature<'a> {
    /// Returns the chain bound by the verified defining interface, not caller input.
    #[must_use]
    pub fn chain_id(&self) -> &protocol_types::ChainId {
        self.interface.abi().origin.chain_id()
    }

    pub(super) fn interface(&self) -> &VerifiedPublicationInterface {
        self.interface
    }

    /// Returns the entrypoint name borrowed from the verified package ABI.
    #[must_use]
    pub fn entrypoint(&self) -> &str {
        self.entrypoint
    }

    /// Returns the bound object parameters.
    #[must_use]
    pub fn objects(&self) -> &[BoundObjectParameter] {
        &self.objects
    }
    /// Returns the bound, ordered typed object result slots (DR-0124).
    #[must_use]
    pub fn results(&self) -> &[BoundObjectResult] {
        &self.results
    }
    /// Returns the argument layout from the exact verified interface for encoding.
    pub fn argument_layout(&self) -> &ValueLayout {
        self.arguments
    }
}

/// Validates canonical argument bytes against the bound entrypoint's signed layout.
/// This authenticates neither a call transaction nor application semantics and
/// grants no execution, object, owner, or state authority.
pub fn validate_call_arguments(
    signature: &BoundObjectSignature<'_>,
    bytes: &[u8],
) -> Result<(), ValueError> {
    decode_call_value(signature.arguments, bytes).map(|_| ())
}

/// Errors returned when binding object signatures or matching object input metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BindingError {
    /// Underlying package or scoped type error.
    Package(PackageTypeError),
    /// The requested entrypoint was not found in the verified publication interface ABI.
    UnknownEntrypoint,
    /// The number of supplied type arguments does not match the entrypoint declaration.
    ArgumentCount,
    /// A type argument kind (nominal vs opaque) or opaque domain does not match declaration.
    KindMismatch,
    /// A referenced package origin is neither self nor a directly declared dependency.
    UndeclaredOrigin,
    /// The defining package ABI does not declare the requested constructor.
    UnknownConstructor,
    /// Constructor argument arity does not match declaration.
    ArityMismatch,
    /// Aggregate or local resource limit exceeded.
    Limit(&'static str),
    /// Hash resolver chain does not match root publication origin chain.
    ChainMismatch,
    /// Number of manifest entries, resolved inputs, or signature objects do not match.
    InputCount,
    /// Duplicate object identifier present in input manifest.
    DuplicateObject,
    /// Declared access mode does not match resolved object or bound signature mode.
    AccessMismatch,
    /// Object reference identifier or version does not match loaded input object.
    ReferenceMismatch,
    /// Loaded object schema version does not match bound schema expectation.
    SchemaMismatch,
    /// Scoped type commitment verification failed under trusted hash history.
    TypeMismatch,
}

impl fmt::Display for BindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Package(err) => write!(f, "package type error: {err}"),
            Self::UnknownEntrypoint => write!(f, "unknown entrypoint"),
            Self::ArgumentCount => write!(f, "type argument count mismatch"),
            Self::KindMismatch => write!(f, "type argument kind mismatch"),
            Self::UndeclaredOrigin => write!(f, "undeclared package origin"),
            Self::UnknownConstructor => write!(f, "unknown constructor"),
            Self::ArityMismatch => write!(f, "constructor arity mismatch"),
            Self::Limit(msg) => write!(f, "binding limit exceeded: {msg}"),
            Self::ChainMismatch => write!(f, "chain mismatch"),
            Self::InputCount => write!(f, "input count mismatch"),
            Self::DuplicateObject => write!(f, "duplicate object identifier"),
            Self::AccessMismatch => write!(f, "access mode mismatch"),
            Self::ReferenceMismatch => write!(f, "object reference mismatch"),
            Self::SchemaMismatch => write!(f, "schema version mismatch"),
            Self::TypeMismatch => write!(f, "scoped type mismatch"),
        }
    }
}

impl std::error::Error for BindingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Package(err) => Some(err),
            _ => None,
        }
    }
}

impl From<PackageTypeError> for BindingError {
    fn from(err: PackageTypeError) -> Self {
        Self::Package(err)
    }
}

/// Instantiates generic object parameter signatures for an entrypoint against a verified publication interface.
///
/// # Explicit Non-Claims
///
/// Successfully binding an object signature establishes only that nominal type arguments satisfy
/// declared kinds, direct-dependency provenance, and DR-0113 resource limits. It grants NO
/// execution capability, host rights, constructor authorization, or publication authority.
pub fn bind_object_signature<'a>(
    interface: &'a VerifiedPublicationInterface,
    entrypoint: &str,
    type_arguments: &[ScopedTypeArg],
) -> Result<BoundObjectSignature<'a>, BindingError> {
    if entrypoint.len() > MAX_ENTRYPOINT_NAME_BYTES {
        return Err(BindingError::Limit("entrypoint"));
    }

    let (entrypoint_index, entrypoint_decl) = interface
        .abi()
        .entrypoints
        .iter()
        .enumerate()
        .find(|(_, ep)| ep.name == entrypoint)
        .ok_or(BindingError::UnknownEntrypoint)?;

    let expected_params: &[ArgumentKind] = &entrypoint_decl.type_parameters;
    if type_arguments.len() != expected_params.len() || type_arguments.len() > MAX_ABI_TYPE_PARAMS {
        return Err(BindingError::ArgumentCount);
    }

    for (arg, expected_kind) in type_arguments.iter().zip(expected_params) {
        match (arg, expected_kind) {
            (ScopedTypeArg::Nominal(tag), ArgumentKind::Nominal) => {
                validate_supplied_nominal_tag(tag, interface)?;
            }
            (ScopedTypeArg::Opaque { domain, .. }, ArgumentKind::Opaque(expected_domain)) => {
                if *domain == 0 || domain != expected_domain {
                    return Err(BindingError::KindMismatch);
                }
            }
            _ => return Err(BindingError::KindMismatch),
        }
    }

    if entrypoint_decl.objects.len() > MAX_ABI_OBJECT_PARAMS {
        return Err(BindingError::Limit("objects"));
    }

    let mut bound_objects: Vec<BoundObjectParameter> =
        Vec::with_capacity(entrypoint_decl.objects.len());
    let mut total_bound_bytes: usize = 0;

    for obj in &entrypoint_decl.objects {
        let mut node_count: usize = 0;
        let bound_tag: ScopedTypeTag =
            substitute_pattern_node(&obj.ty, type_arguments, 1, &mut node_count)?;

        let encoded: Vec<u8> = encode_scoped_type_tag(&bound_tag)?;
        total_bound_bytes = total_bound_bytes
            .checked_add(encoded.len())
            .ok_or(BindingError::Limit("bound type bytes"))?;
        if total_bound_bytes > MAX_BOUND_TYPE_BYTES {
            return Err(BindingError::Limit("bound type bytes"));
        }

        bound_objects.push(BoundObjectParameter {
            mode: obj.mode,
            schema: obj.schema,
            ty: bound_tag,
        });
    }

    let declared_results: &[abi::public_abi::ObjectResultDeclaration] = interface
        .executable_abi(&interface.abi().origin)
        .and_then(|executable| executable.results.get(entrypoint_index))
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    if declared_results.len() > MAX_ABI_OBJECT_RESULTS {
        return Err(BindingError::Limit("results"));
    }
    let mut bound_results: Vec<BoundObjectResult> = Vec::with_capacity(declared_results.len());
    for result in declared_results {
        let mut node_count: usize = 0;
        let bound_tag: ScopedTypeTag =
            substitute_pattern_node(&result.ty, type_arguments, 1, &mut node_count)?;

        let encoded: Vec<u8> = encode_scoped_type_tag(&bound_tag)?;
        total_bound_bytes = total_bound_bytes
            .checked_add(encoded.len())
            .ok_or(BindingError::Limit("bound type bytes"))?;
        if total_bound_bytes > MAX_BOUND_TYPE_BYTES {
            return Err(BindingError::Limit("bound type bytes"));
        }

        bound_results.push(BoundObjectResult {
            mode: result.mode,
            schema: result.schema,
            ty: bound_tag,
            optional: result.optional,
        });
    }

    Ok(BoundObjectSignature {
        interface,
        entrypoint: entrypoint_decl.name.as_str(),
        objects: bound_objects,
        results: bound_results,
        arguments: interface
            .argument_layout(entrypoint_decl.name.as_str())
            .ok_or(BindingError::UnknownEntrypoint)?,
    })
}

pub(super) fn validate_supplied_nominal_tag(
    tag: &ScopedTypeTag,
    interface: &VerifiedPublicationInterface,
) -> Result<(), BindingError> {
    encode_scoped_type_tag(tag)?;
    resolve_tag_constructors(tag, interface)
}

fn resolve_tag_constructors(
    tag: &ScopedTypeTag,
    interface: &VerifiedPublicationInterface,
) -> Result<(), BindingError> {
    if !interface.permits_type_origin(tag.origin()) {
        return Err(BindingError::UndeclaredOrigin);
    }
    let defining_abi: &PackageAbi = interface
        .defining_abi(tag.origin())
        .ok_or(BindingError::UndeclaredOrigin)?;

    let ctor = defining_abi
        .constructors
        .iter()
        .find(|c| c.local_id == tag.constructor())
        .ok_or(BindingError::UnknownConstructor)?;

    if tag.args().len() != ctor.arguments.len() {
        return Err(BindingError::ArityMismatch);
    }

    for (arg, expected_kind) in tag.args().iter().zip(&ctor.arguments) {
        match (arg, expected_kind) {
            (ScopedTypeArg::Nominal(nested_tag), ArgumentKind::Nominal) => {
                resolve_tag_constructors(nested_tag, interface)?;
            }
            (ScopedTypeArg::Opaque { domain, .. }, ArgumentKind::Opaque(expected_domain)) => {
                if *domain == 0 || domain != expected_domain {
                    return Err(BindingError::KindMismatch);
                }
            }
            _ => return Err(BindingError::KindMismatch),
        }
    }
    Ok(())
}

fn count_node(node_count: &mut usize) -> Result<(), PackageTypeError> {
    *node_count = node_count
        .checked_add(1)
        .ok_or(PackageTypeError::NodeLimitExceeded(usize::MAX))?;
    if *node_count > MAX_SCOPED_TYPE_NODES {
        return Err(PackageTypeError::NodeLimitExceeded(*node_count));
    }
    Ok(())
}

fn charge_nominal_subtree(
    tag: &ScopedTypeTag,
    depth: usize,
    node_count: &mut usize,
) -> Result<(), PackageTypeError> {
    count_node(node_count)?;
    if depth > MAX_SCOPED_TYPE_DEPTH {
        return Err(PackageTypeError::DepthLimitExceeded(depth));
    }
    if tag.args().len() > MAX_SCOPED_TYPE_ARGS {
        return Err(PackageTypeError::ArgCountLimitExceeded(tag.args().len()));
    }
    for arg in tag.args() {
        count_node(node_count)?;
        match arg {
            ScopedTypeArg::Nominal(nested) => {
                let next: usize = depth
                    .checked_add(1)
                    .ok_or(PackageTypeError::DepthLimitExceeded(usize::MAX))?;
                charge_nominal_subtree(nested, next, node_count)?;
            }
            ScopedTypeArg::Opaque { domain, .. } => {
                if *domain == 0 {
                    return Err(PackageTypeError::ZeroOpaqueDomain);
                }
            }
        }
    }
    Ok(())
}

fn substitute_pattern_node(
    pattern: &TypePattern,
    type_arguments: &[ScopedTypeArg],
    depth: usize,
    node_count: &mut usize,
) -> Result<ScopedTypeTag, BindingError> {
    count_node(node_count)?;
    if depth > MAX_SCOPED_TYPE_DEPTH {
        return Err(PackageTypeError::DepthLimitExceeded(depth).into());
    }
    if pattern.arguments.len() > MAX_SCOPED_TYPE_ARGS {
        return Err(PackageTypeError::ArgCountLimitExceeded(pattern.arguments.len()).into());
    }

    let mut args: Vec<ScopedTypeArg> = Vec::with_capacity(pattern.arguments.len());
    for pat_arg in &pattern.arguments {
        count_node(node_count)?;
        match pat_arg {
            PatternArgument::Nominal(nested_pat) => {
                let next_depth: usize = depth
                    .checked_add(1)
                    .ok_or(PackageTypeError::DepthLimitExceeded(usize::MAX))?;
                let nested_tag: ScopedTypeTag =
                    substitute_pattern_node(nested_pat, type_arguments, next_depth, node_count)?;
                args.push(ScopedTypeArg::Nominal(Box::new(nested_tag)));
            }
            PatternArgument::Opaque { domain, value } => {
                if *domain == 0 {
                    return Err(PackageTypeError::ZeroOpaqueDomain.into());
                }
                args.push(ScopedTypeArg::Opaque {
                    domain: *domain,
                    value: *value,
                });
            }
            PatternArgument::Parameter(idx) => {
                let supplied: &ScopedTypeArg = type_arguments
                    .get(*idx as usize)
                    .ok_or(BindingError::ArgumentCount)?;
                match supplied {
                    ScopedTypeArg::Nominal(supplied_tag) => {
                        let next_depth: usize = depth
                            .checked_add(1)
                            .ok_or(PackageTypeError::DepthLimitExceeded(usize::MAX))?;
                        charge_nominal_subtree(supplied_tag, next_depth, node_count)?;
                        args.push(ScopedTypeArg::Nominal(supplied_tag.clone()));
                    }
                    ScopedTypeArg::Opaque { domain, value } => {
                        args.push(ScopedTypeArg::Opaque {
                            domain: *domain,
                            value: *value,
                        });
                    }
                }
            }
        }
    }

    let tag: ScopedTypeTag = ScopedTypeTag::new(pattern.origin.clone(), pattern.constructor, args)?;
    Ok(tag)
}

/// Matches loaded object input metadata against a bound object signature.
///
/// # Explicit Non-Claims
///
/// This function verifies metadata correspondence only: access modes, object identifiers,
/// object versions, schema tokens, and scoped type commitments under hash history.
/// It deliberately performs NO [`objects::ObjectRef::digest`] verification, data hashing, body
/// inspection, or owner validation. Neither manifest nor loaded state is authenticated by
/// this helper, and arbitrary owner or body changes may still match metadata.
/// This helper returns `Ok(())` only and grants NO executable witness, storage authority,
/// or host capability. It cannot substitute for transaction, storage, or owner admission.
pub fn match_object_input_metadata(
    signature: &BoundObjectSignature<'_>,
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    manifest: &AccessManifest,
    inputs: &[ResolvedObject],
) -> Result<(), BindingError> {
    if resolver.chain_id() != signature.interface.abi().origin.chain_id() {
        return Err(BindingError::ChainMismatch);
    }

    let expected_len: usize = signature.objects.len();
    if expected_len > MAX_ABI_OBJECT_PARAMS
        || manifest.entries.len() != expected_len
        || inputs.len() != expected_len
    {
        return Err(BindingError::InputCount);
    }

    let mut seen_ids: BTreeSet<ObjectId> = BTreeSet::new();
    for entry in &manifest.entries {
        if !seen_ids.insert(entry.object_ref.id) {
            return Err(BindingError::DuplicateObject);
        }
    }

    for (i, bound) in signature.objects.iter().enumerate() {
        let manifest_entry = &manifest.entries[i];
        let input = &inputs[i];

        if manifest_entry.mode != input.mode {
            return Err(BindingError::AccessMismatch);
        }

        let mapped_mode: ObjectMode = match manifest_entry.mode {
            AccessMode::Read => ObjectMode::Read,
            AccessMode::Write => ObjectMode::Write,
            AccessMode::Consume => ObjectMode::Consume,
        };
        if mapped_mode != bound.mode {
            return Err(BindingError::AccessMismatch);
        }

        if manifest_entry.object_ref.id != input.object.id
            || manifest_entry.object_ref.version != input.object.version
        {
            return Err(BindingError::ReferenceMismatch);
        }

        if input.object.schema_version != bound.schema {
            return Err(BindingError::SchemaMismatch);
        }

        let valid: bool =
            verify_scoped_type_id(resolver, &input.object.type_hash, epoch, &bound.ty)?;
        if !valid {
            return Err(BindingError::TypeMismatch);
        }
    }

    Ok(())
}
