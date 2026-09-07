//! Bounded immutable artifact data. ABI declarations and dependencies remain
//! unverified; structural data validity is not publication or execution authority.

use super::PublicationError as E;
use crate::{
    CONTRACT_WASM_ADMISSION_PROFILE_VERSION, MAX_CONTRACT_ENTRYPOINT_NAME_BYTES,
    MAX_CONTRACT_ENTRYPOINTS, MAX_CONTRACT_WASM_BYTES,
};
use abi::package_types::{PackageOrigin, decode_package_origin, encode_package_origin};
use canonical_encoding::{
    CanonicalFrame, CanonicalStruct, decode_canonical_frame, decode_digest32, encode_digest32,
};
use protocol_types::{ChainId, Digest32, Epoch, ProtocolVersion};

/// Maximum bytes in an artifact or signed request before decoding.
pub const MAX_PUBLICATION_BYTES: usize = 5 * 1024 * 1024;
/// Maximum opaque, unverified ABI declaration bytes.
pub const MAX_ABI_DECLARATION_BYTES: usize = 64 * 1024;
/// Maximum exact but unverified dependency references.
pub const MAX_DEPENDENCIES: usize = 32;
/// Maximum encoded context bytes.
pub const MAX_CONTEXT_FRAME_BYTES: usize = 256;
/// Maximum encoded dependency-reference bytes.
pub const MAX_DEPENDENCY_FRAME_BYTES: usize = 1024;
/// Maximum UTF-8 chain identifier bytes.
pub const MAX_CHAIN_ID_BYTES: usize = 128;

const FRAME_TYPE_CONTEXT: u16 = 0x6301;
const FRAME_TYPE_DEPENDENCY: u16 = 0x6302;
const FRAME_TYPE_ARTIFACT: u16 = 0x6303;
const FRAME_TYPE_EXPORT_LIST: u16 = 0x6304;
const FRAME_TYPE_DEPENDENCY_LIST: u16 = 0x6305;
const FRAME_TYPE_REQUEST: u16 = 0x6306;
const MAX_EXPORT_LIST_BYTES: usize =
    18 + MAX_CONTRACT_ENTRYPOINTS * (6 + MAX_CONTRACT_ENTRYPOINT_NAME_BYTES);
const MAX_DEPENDENCY_LIST_BYTES: usize = 18 + MAX_DEPENDENCIES * (6 + MAX_DEPENDENCY_FRAME_BYTES);

const FRAME_VERSION_1: u16 = 1;

#[inline]
fn bound(field: &'static str, actual: usize, maximum: usize) -> Result<(), E> {
    if actual > maximum {
        Err(E::Limit {
            field,
            actual,
            maximum,
        })
    } else {
        Ok(())
    }
}

fn make_list_field_ids(count: usize) -> Result<Vec<u16>, E> {
    let mut fields: Vec<u16> = Vec::with_capacity(count.checked_add(1).ok_or(E::Limit {
        field: "list_fields",
        actual: usize::MAX,
        maximum: u16::MAX as usize,
    })?);
    fields.push(1);
    for idx in 0..count {
        let field_id: u16 = u16::try_from(idx.checked_add(2).ok_or(E::Limit {
            field: "list_field_id",
            actual: usize::MAX,
            maximum: u16::MAX as usize,
        })?)
        .map_err(|_| E::Limit {
            field: "list_field_id",
            actual: usize::MAX,
            maximum: u16::MAX as usize,
        })?;
        fields.push(field_id);
    }
    Ok(fields)
}

/// Structural publication context (chain ID, protocol version, epoch).
///
/// Provides bytes binding only, with no API to execute, instantiate, or persist.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicationContext {
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
    epoch: Epoch,
}

impl PublicationContext {
    /// Constructs unverified data; checks shape only, not authentication or authority.
    pub fn new(
        chain_id: ChainId,
        protocol_version: ProtocolVersion,
        epoch: Epoch,
    ) -> Result<Self, E> {
        let chain_str: &str = chain_id.as_str();
        if chain_str.trim().is_empty() {
            return Err(E::Empty("chain_id"));
        }
        bound("chain_id", chain_str.len(), MAX_CHAIN_ID_BYTES)?;
        Ok(Self {
            chain_id,
            protocol_version,
            epoch,
        })
    }

    /// Returns the recorded chain id without granting authority.
    pub fn chain_id(&self) -> &ChainId {
        &self.chain_id
    }

    /// Returns the recorded protocol version without granting authority.
    pub fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    /// Returns the recorded epoch without granting authority.
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }
}

/// Unverified reference to a package dependency.
///
/// Asserts a reference only, not existence, authentication, or provenance.
/// Provides bytes binding only, with no API to execute, instantiate, or persist.
/// Dependencies remain unverified at this layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnverifiedDependencyRef {
    origin: PackageOrigin,
    revision: u64,
    context: PublicationContext,
    artifact_digest: Digest32,
}

impl UnverifiedDependencyRef {
    /// Constructs unverified data; checks shape only, not authentication or authority.
    pub fn new(
        origin: PackageOrigin,
        revision: u64,
        context: PublicationContext,
        artifact_digest: Digest32,
    ) -> Result<Self, E> {
        if revision < 1 {
            return Err(E::InvalidRevision(revision));
        }
        if origin.chain_id() != context.chain_id() {
            return Err(E::ChainMismatch);
        }
        Ok(Self {
            origin,
            revision,
            context,
            artifact_digest,
        })
    }

    /// Returns the recorded origin without granting authority.
    pub fn origin(&self) -> &PackageOrigin {
        &self.origin
    }

    /// Returns the recorded revision without granting authority.
    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns the recorded context without granting authority.
    pub fn context(&self) -> &PublicationContext {
        &self.context
    }

    /// Returns the recorded artifact digest without granting authority.
    pub fn artifact_digest(&self) -> &Digest32 {
        &self.artifact_digest
    }
}

/// Unverified parts used to construct a [`CodeArtifact`].
///
/// Contains unverified origin, unverified ABI, and unverified dependencies.
/// Provides bytes binding only, with no API to execute, instantiate, or persist.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactParts {
    /// Caller-supplied context; unverified declaration data.
    pub context: PublicationContext,
    /// Caller-supplied origin; unverified declaration data.
    pub origin: PackageOrigin,
    /// Caller-supplied revision; unverified declaration data.
    pub revision: u64,
    /// Caller-supplied wasm profile; unverified declaration data.
    pub wasm_profile: u32,
    /// Caller-supplied semantics; unverified declaration data.
    pub semantics: Digest32,
    /// Caller-supplied wasm; unverified declaration data.
    pub wasm: Vec<u8>,
    /// Caller-supplied unverified abi; unverified declaration data.
    pub unverified_abi: Vec<u8>,
    /// Caller-supplied exports; unverified declaration data.
    pub exports: Vec<String>,
    /// Caller-supplied unverified dependencies; unverified declaration data.
    pub unverified_dependencies: Vec<UnverifiedDependencyRef>,
}

/// Bounded immutable artifact data, not validated WASM or ABI.
///
/// Contains unverified origin, unverified ABI bytes, and unverified dependencies.
/// Validates structural encoding bounds and canonical constraints only.
/// Provides bytes binding only, with no API to execute, instantiate, or persist,
/// and makes no authentication or authority claims.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodeArtifact {
    context: PublicationContext,
    origin: PackageOrigin,
    revision: u64,
    wasm_profile: u32,
    semantics: Digest32,
    wasm: Vec<u8>,
    unverified_abi: Vec<u8>,
    exports: Vec<String>,
    unverified_dependencies: Vec<UnverifiedDependencyRef>,
}

impl CodeArtifact {
    /// Constructs unverified data; checks shape only, not authentication or authority.
    pub fn new(parts: ArtifactParts) -> Result<Self, E> {
        if parts.revision != 1 {
            return Err(E::InvalidRevision(parts.revision));
        }
        if !matches!(
            parts.wasm_profile,
            CONTRACT_WASM_ADMISSION_PROFILE_VERSION | crate::TYPED_CONTRACT_WASM_PROFILE_VERSION
        ) {
            return Err(E::UnsupportedWasmProfile(parts.wasm_profile));
        }
        if parts.origin.chain_id() != parts.context.chain_id() {
            return Err(E::ChainMismatch);
        }
        if parts.wasm.is_empty() {
            return Err(E::Empty("wasm"));
        }
        bound("wasm", parts.wasm.len(), MAX_CONTRACT_WASM_BYTES)?;
        if parts.unverified_abi.is_empty() {
            return Err(E::Empty("unverified_abi"));
        }
        bound(
            "unverified_abi",
            parts.unverified_abi.len(),
            MAX_ABI_DECLARATION_BYTES,
        )?;

        if parts.exports.is_empty() {
            return Err(E::Empty("exports"));
        }
        bound("exports", parts.exports.len(), MAX_CONTRACT_ENTRYPOINTS)?;
        for name in &parts.exports {
            if name.is_empty() {
                return Err(E::Empty("export"));
            }
            bound("export", name.len(), MAX_CONTRACT_ENTRYPOINT_NAME_BYTES)?;
            if name == "memory" {
                return Err(E::ReservedExport);
            }
        }
        for i in 1..parts.exports.len() {
            if parts.exports[i] <= parts.exports[i - 1] {
                return Err(E::NonCanonicalOrder("exports"));
            }
        }

        bound(
            "dependencies",
            parts.unverified_dependencies.len(),
            MAX_DEPENDENCIES,
        )?;
        for dep in &parts.unverified_dependencies {
            if dep.origin() == &parts.origin {
                return Err(E::SelfDependency);
            }
            if dep.context().chain_id() != parts.context.chain_id() {
                return Err(E::ChainMismatch);
            }
        }
        for i in 1..parts.unverified_dependencies.len() {
            if parts.unverified_dependencies[i].origin()
                <= parts.unverified_dependencies[i - 1].origin()
            {
                return Err(E::NonCanonicalOrder("dependencies"));
            }
        }

        Ok(Self {
            context: parts.context,
            origin: parts.origin,
            revision: parts.revision,
            wasm_profile: parts.wasm_profile,
            semantics: parts.semantics,
            wasm: parts.wasm,
            unverified_abi: parts.unverified_abi,
            exports: parts.exports,
            unverified_dependencies: parts.unverified_dependencies,
        })
    }

    /// Returns the recorded context without granting authority.
    pub fn context(&self) -> &PublicationContext {
        &self.context
    }

    /// Returns the recorded origin without granting authority.
    pub fn origin(&self) -> &PackageOrigin {
        &self.origin
    }

    /// Returns the recorded revision without granting authority.
    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns the recorded wasm profile without granting authority.
    pub fn wasm_profile(&self) -> u32 {
        self.wasm_profile
    }

    /// Returns the recorded semantics without granting authority.
    pub fn semantics(&self) -> &Digest32 {
        &self.semantics
    }

    /// Returns the recorded wasm without granting authority.
    pub fn wasm(&self) -> &[u8] {
        &self.wasm
    }

    /// Returns the recorded unverified abi without granting authority.
    pub fn unverified_abi(&self) -> &[u8] {
        &self.unverified_abi
    }

    /// Returns the recorded exports without granting authority.
    pub fn exports(&self) -> &[String] {
        &self.exports
    }

    /// Returns the recorded unverified dependencies without granting authority.
    pub fn unverified_dependencies(&self) -> &[UnverifiedDependencyRef] {
        &self.unverified_dependencies
    }
}

/// Publication request containing a code artifact and unverified signature.
///
/// Provides bytes binding only, with no API to execute, instantiate, or persist.
/// Makes no authentication or authority claims; signature verification is handled
/// by higher-level authority layers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicationRequest {
    artifact: CodeArtifact,
    nonce: u64,
    artifact_digest: Digest32,
    signature: [u8; 64],
}

impl PublicationRequest {
    /// Constructs unverified data; checks shape only, not authentication or authority.
    pub fn new(
        artifact: CodeArtifact,
        nonce: u64,
        artifact_digest: Digest32,
        signature: [u8; 64],
    ) -> Self {
        Self {
            artifact,
            nonce,
            artifact_digest,
            signature,
        }
    }

    /// Returns the recorded artifact without granting authority.
    pub fn artifact(&self) -> &CodeArtifact {
        &self.artifact
    }

    /// Returns the recorded nonce without granting authority.
    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    /// Returns the recorded artifact digest without granting authority.
    pub fn artifact_digest(&self) -> &Digest32 {
        &self.artifact_digest
    }

    /// Returns the recorded signature without granting authority.
    pub fn signature(&self) -> &[u8; 64] {
        &self.signature
    }
}

/// Encodes exact bounded data using canonical framing; grants no authority.
pub fn encode_publication_context(context: &PublicationContext) -> Result<Vec<u8>, E> {
    let mut s: CanonicalStruct = CanonicalStruct::new(FRAME_TYPE_CONTEXT, FRAME_VERSION_1);
    s.field_str(1, context.chain_id().as_str())?;
    s.field_u32(2, context.protocol_version().get())?;
    s.field_u64(3, context.epoch().get())?;
    let bytes: Vec<u8> = s.finish()?;
    bound("context_frame", bytes.len(), MAX_CONTEXT_FRAME_BYTES)?;
    Ok(bytes)
}

/// Decodes unverified data with strict shape and resource bounds.
pub fn decode_publication_context(bytes: &[u8]) -> Result<PublicationContext, E> {
    bound("context_bytes", bytes.len(), MAX_CONTEXT_FRAME_BYTES)?;
    let frame: CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
    frame.require_type(FRAME_TYPE_CONTEXT)?;
    frame.require_version(FRAME_VERSION_1)?;
    frame.require_only_fields(&[1, 2, 3])?;
    let chain_str: &str = frame.required_str(1)?;
    let protocol_u32: u32 = frame.required_u32(2)?;
    let epoch_u64: u64 = frame.required_u64(3)?;
    bound("chain_id", chain_str.len(), MAX_CHAIN_ID_BYTES)?;
    let chain_id: ChainId = ChainId::new(chain_str)?;
    let protocol_version: ProtocolVersion = ProtocolVersion::new(protocol_u32);
    let epoch: Epoch = Epoch::new(epoch_u64);
    PublicationContext::new(chain_id, protocol_version, epoch)
}

/// Encodes exact bounded data using canonical framing; grants no authority.
pub fn encode_dependency_ref(dep: &UnverifiedDependencyRef) -> Result<Vec<u8>, E> {
    let mut s: CanonicalStruct = CanonicalStruct::new(FRAME_TYPE_DEPENDENCY, FRAME_VERSION_1);
    let origin_bytes = encode_package_origin(dep.origin())?;
    s.field_bytes(1, origin_bytes)?;
    s.field_u64(2, dep.revision())?;
    let context_bytes = encode_publication_context(dep.context())?;
    s.field_bytes(3, context_bytes)?;
    let digest_bytes = encode_digest32(dep.artifact_digest())?;
    s.field_bytes(4, digest_bytes)?;
    let bytes: Vec<u8> = s.finish()?;
    bound("dependency_frame", bytes.len(), MAX_DEPENDENCY_FRAME_BYTES)?;
    Ok(bytes)
}

/// Decodes unverified data with strict shape and resource bounds.
pub fn decode_dependency_ref(bytes: &[u8]) -> Result<UnverifiedDependencyRef, E> {
    bound("dependency_bytes", bytes.len(), MAX_DEPENDENCY_FRAME_BYTES)?;
    let frame: CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
    frame.require_type(FRAME_TYPE_DEPENDENCY)?;
    frame.require_version(FRAME_VERSION_1)?;
    frame.require_only_fields(&[1, 2, 3, 4])?;
    let origin_bytes = frame.required_field(1)?;
    let origin: PackageOrigin = decode_package_origin(origin_bytes)?;
    let revision: u64 = frame.required_u64(2)?;
    let context_bytes = frame.required_field(3)?;
    let context: PublicationContext = decode_publication_context(context_bytes)?;
    let digest_bytes = frame.required_field(4)?;
    let artifact_digest: Digest32 = decode_digest32(digest_bytes)?;
    UnverifiedDependencyRef::new(origin, revision, context, artifact_digest)
}

fn encode_export_list(exports: &[String]) -> Result<Vec<u8>, E> {
    if exports.is_empty() {
        return Err(E::Empty("exports"));
    }
    bound("exports", exports.len(), MAX_CONTRACT_ENTRYPOINTS)?;
    let count_u16: u16 = u16::try_from(exports.len()).map_err(|_| E::Limit {
        field: "exports",
        actual: exports.len(),
        maximum: MAX_CONTRACT_ENTRYPOINTS,
    })?;
    let mut s: CanonicalStruct = CanonicalStruct::new(FRAME_TYPE_EXPORT_LIST, FRAME_VERSION_1);
    s.field_u16(1, count_u16)?;
    for (idx, name) in exports.iter().enumerate() {
        if name.is_empty() {
            return Err(E::Empty("export"));
        }
        bound("export", name.len(), MAX_CONTRACT_ENTRYPOINT_NAME_BYTES)?;
        if name == "memory" {
            return Err(E::ReservedExport);
        }
        let field_id: u16 = u16::try_from(idx.checked_add(2).ok_or(E::Limit {
            field: "export_field_id",
            actual: usize::MAX,
            maximum: u16::MAX as usize,
        })?)
        .map_err(|_| E::Limit {
            field: "export_field_id",
            actual: usize::MAX,
            maximum: u16::MAX as usize,
        })?;
        s.field_str(field_id, name)?;
    }
    let bytes: Vec<u8> = s.finish()?;
    Ok(bytes)
}

fn decode_export_list(bytes: &[u8]) -> Result<Vec<String>, E> {
    bound("export_list_bytes", bytes.len(), MAX_EXPORT_LIST_BYTES)?;
    let frame: CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
    frame.require_type(FRAME_TYPE_EXPORT_LIST)?;
    frame.require_version(FRAME_VERSION_1)?;
    let count_u16: u16 = frame.required_u16(1)?;
    let count: usize = count_u16 as usize;
    if count == 0 {
        return Err(E::Empty("exports"));
    }
    bound("exports", count, MAX_CONTRACT_ENTRYPOINTS)?;
    let expected: Vec<u16> = make_list_field_ids(count)?;
    frame.require_only_fields(&expected)?;
    let mut exports: Vec<String> = Vec::with_capacity(count);
    for idx in 0..count {
        let field_id: u16 = u16::try_from(idx.checked_add(2).ok_or(E::Limit {
            field: "export_field_id",
            actual: usize::MAX,
            maximum: u16::MAX as usize,
        })?)
        .map_err(|_| E::Limit {
            field: "export_field_id",
            actual: usize::MAX,
            maximum: u16::MAX as usize,
        })?;
        let name = frame.required_str(field_id)?;
        if name.is_empty() {
            return Err(E::Empty("export"));
        }
        bound("export", name.len(), MAX_CONTRACT_ENTRYPOINT_NAME_BYTES)?;
        if name == "memory" {
            return Err(E::ReservedExport);
        }
        exports.push(name.to_string());
    }
    for i in 1..exports.len() {
        if exports[i] <= exports[i - 1] {
            return Err(E::NonCanonicalOrder("exports"));
        }
    }
    Ok(exports)
}

fn encode_dependency_list(deps: &[UnverifiedDependencyRef]) -> Result<Vec<u8>, E> {
    bound("dependencies", deps.len(), MAX_DEPENDENCIES)?;
    let count_u16: u16 = u16::try_from(deps.len()).map_err(|_| E::Limit {
        field: "dependencies",
        actual: deps.len(),
        maximum: MAX_DEPENDENCIES,
    })?;
    let mut s: CanonicalStruct = CanonicalStruct::new(FRAME_TYPE_DEPENDENCY_LIST, FRAME_VERSION_1);
    s.field_u16(1, count_u16)?;
    for (idx, dep) in deps.iter().enumerate() {
        let field_id: u16 = u16::try_from(idx.checked_add(2).ok_or(E::Limit {
            field: "dependency_field_id",
            actual: usize::MAX,
            maximum: u16::MAX as usize,
        })?)
        .map_err(|_| E::Limit {
            field: "dependency_field_id",
            actual: usize::MAX,
            maximum: u16::MAX as usize,
        })?;
        let dep_frame = encode_dependency_ref(dep)?;
        s.field_bytes(field_id, dep_frame)?;
    }
    let bytes: Vec<u8> = s.finish()?;
    Ok(bytes)
}

fn decode_dependency_list(bytes: &[u8]) -> Result<Vec<UnverifiedDependencyRef>, E> {
    bound(
        "dependency_list_bytes",
        bytes.len(),
        MAX_DEPENDENCY_LIST_BYTES,
    )?;
    let frame: CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
    frame.require_type(FRAME_TYPE_DEPENDENCY_LIST)?;
    frame.require_version(FRAME_VERSION_1)?;
    let count_u16: u16 = frame.required_u16(1)?;
    let count: usize = count_u16 as usize;
    bound("dependencies", count, MAX_DEPENDENCIES)?;
    let expected: Vec<u16> = make_list_field_ids(count)?;
    frame.require_only_fields(&expected)?;
    let mut deps: Vec<UnverifiedDependencyRef> = Vec::with_capacity(count);
    for idx in 0..count {
        let field_id: u16 = u16::try_from(idx.checked_add(2).ok_or(E::Limit {
            field: "dependency_field_id",
            actual: usize::MAX,
            maximum: u16::MAX as usize,
        })?)
        .map_err(|_| E::Limit {
            field: "dependency_field_id",
            actual: usize::MAX,
            maximum: u16::MAX as usize,
        })?;
        let dep_bytes = frame.required_field(field_id)?;
        let dep: UnverifiedDependencyRef = decode_dependency_ref(dep_bytes)?;
        deps.push(dep);
    }
    for i in 1..deps.len() {
        if deps[i].origin() <= deps[i - 1].origin() {
            return Err(E::NonCanonicalOrder("dependencies"));
        }
    }
    Ok(deps)
}

/// Encodes exact bounded data using canonical framing; grants no authority.
pub fn encode_code_artifact(artifact: &CodeArtifact) -> Result<Vec<u8>, E> {
    let mut s: CanonicalStruct = CanonicalStruct::new(FRAME_TYPE_ARTIFACT, FRAME_VERSION_1);
    let context_bytes = encode_publication_context(artifact.context())?;
    s.field_bytes(1, context_bytes)?;
    let origin_bytes = encode_package_origin(artifact.origin())?;
    s.field_bytes(2, origin_bytes)?;
    s.field_u64(3, artifact.revision())?;
    s.field_u32(4, artifact.wasm_profile())?;
    let semantics_bytes = encode_digest32(artifact.semantics())?;
    s.field_bytes(5, semantics_bytes)?;
    s.field_bytes(6, artifact.wasm().to_vec())?;
    s.field_bytes(7, artifact.unverified_abi().to_vec())?;
    let export_list_bytes = encode_export_list(artifact.exports())?;
    s.field_bytes(8, export_list_bytes)?;
    let dep_list_bytes = encode_dependency_list(artifact.unverified_dependencies())?;
    s.field_bytes(9, dep_list_bytes)?;
    let bytes: Vec<u8> = s.finish()?;
    bound("artifact_bytes", bytes.len(), MAX_PUBLICATION_BYTES)?;
    Ok(bytes)
}

/// Decodes unverified data with strict shape and resource bounds.
pub fn decode_code_artifact(bytes: &[u8]) -> Result<CodeArtifact, E> {
    bound("artifact_bytes", bytes.len(), MAX_PUBLICATION_BYTES)?;
    let frame: CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
    frame.require_type(FRAME_TYPE_ARTIFACT)?;
    frame.require_version(FRAME_VERSION_1)?;
    frame.require_only_fields(&[1, 2, 3, 4, 5, 6, 7, 8, 9])?;
    let context_bytes = frame.required_field(1)?;
    let context: PublicationContext = decode_publication_context(context_bytes)?;
    let origin_bytes = frame.required_field(2)?;
    let origin: PackageOrigin = decode_package_origin(origin_bytes)?;
    let revision: u64 = frame.required_u64(3)?;
    if revision != 1 {
        return Err(E::InvalidRevision(revision));
    }
    let wasm_profile: u32 = frame.required_u32(4)?;
    if !matches!(
        wasm_profile,
        CONTRACT_WASM_ADMISSION_PROFILE_VERSION | crate::TYPED_CONTRACT_WASM_PROFILE_VERSION
    ) {
        return Err(E::UnsupportedWasmProfile(wasm_profile));
    }
    let semantics_bytes = frame.required_field(5)?;
    let semantics: Digest32 = decode_digest32(semantics_bytes)?;
    let wasm_slice = frame.required_field(6)?;
    if wasm_slice.is_empty() {
        return Err(E::Empty("wasm"));
    }
    bound("wasm", wasm_slice.len(), MAX_CONTRACT_WASM_BYTES)?;
    let wasm = wasm_slice.to_vec();
    let abi_slice = frame.required_field(7)?;
    if abi_slice.is_empty() {
        return Err(E::Empty("unverified_abi"));
    }
    bound("unverified_abi", abi_slice.len(), MAX_ABI_DECLARATION_BYTES)?;
    let unverified_abi = abi_slice.to_vec();
    let export_list_bytes = frame.required_field(8)?;
    let exports: Vec<String> = decode_export_list(export_list_bytes)?;
    let dep_list_bytes = frame.required_field(9)?;
    let unverified_dependencies = decode_dependency_list(dep_list_bytes)?;
    let parts: ArtifactParts = ArtifactParts {
        context,
        origin,
        revision,
        wasm_profile,
        semantics,
        wasm,
        unverified_abi,
        exports,
        unverified_dependencies,
    };
    CodeArtifact::new(parts)
}

/// Encodes exact bounded data using canonical framing; grants no authority.
pub fn encode_publication_request(request: &PublicationRequest) -> Result<Vec<u8>, E> {
    let mut s: CanonicalStruct = CanonicalStruct::new(FRAME_TYPE_REQUEST, FRAME_VERSION_1);
    let artifact_bytes = encode_code_artifact(request.artifact())?;
    s.field_bytes(1, artifact_bytes)?;
    s.field_u64(2, request.nonce())?;
    let digest_bytes = encode_digest32(request.artifact_digest())?;
    s.field_bytes(3, digest_bytes)?;
    s.field_bytes(4, request.signature().to_vec())?;
    let bytes: Vec<u8> = s.finish()?;
    bound("publication_bytes", bytes.len(), MAX_PUBLICATION_BYTES)?;
    Ok(bytes)
}

/// Decodes unverified data with strict shape and resource bounds.
pub fn decode_publication_request(bytes: &[u8]) -> Result<PublicationRequest, E> {
    bound("publication_bytes", bytes.len(), MAX_PUBLICATION_BYTES)?;
    let frame: CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
    frame.require_type(FRAME_TYPE_REQUEST)?;
    frame.require_version(FRAME_VERSION_1)?;
    frame.require_only_fields(&[1, 2, 3, 4])?;
    let artifact_bytes = frame.required_field(1)?;
    let nonce: u64 = frame.required_u64(2)?;
    let digest_bytes = frame.required_field(3)?;
    let artifact_digest: Digest32 = decode_digest32(digest_bytes)?;
    let sig_bytes = frame.required_field(4)?;
    if sig_bytes.len() != 64 {
        return Err(E::InvalidSignatureLength(sig_bytes.len()));
    }
    let mut signature = [0u8; 64];
    signature.copy_from_slice(sig_bytes);
    let artifact: CodeArtifact = decode_code_artifact(artifact_bytes)?;
    Ok(PublicationRequest::new(
        artifact,
        nonce,
        artifact_digest,
        signature,
    ))
}
