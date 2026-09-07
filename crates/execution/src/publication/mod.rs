//! Authenticated publication candidates, not published or executable code.
//!
//! Exact WASM, opaque ABI declarations, dependency claims, and original context
//! are bound together. A signature cannot make an unverified ABI declaration or
//! copied package reference authoritative. No execution/persistence API accepts
//! the witness returned here; durable admission must discharge those obligations
//! and enforce origin absence, nonce/replay, and atomicity before publication.

mod artifact;
mod auth;
mod binding;
mod bodies;
mod interface;
mod submission;

pub use submission::{
    MAX_PUBLICATION_SUBMISSION_BYTES, PublicationSubmission, authenticate_publication_submission,
    decode_publication_submission, encode_publication_submission,
    publication_submission_signing_frame,
};

pub use binding::{
    BindingError, BoundObjectParameter, BoundObjectSignature, MAX_BOUND_TYPE_BYTES,
    bind_object_signature, match_object_input_metadata, validate_call_arguments,
};

pub use bodies::{
    BodyError, MAX_BOUND_BODY_BYTES, validate_nominal_body, validate_object_input_bodies,
};

pub use interface::{
    InterfaceError, MAX_INTERFACE_ABI_BYTES, MAX_INTERFACE_DEPTH, MAX_INTERFACE_NODES,
    VerifiedPublicationInterface, verify_publication_interface,
};

pub use artifact::{
    ArtifactParts, CodeArtifact, MAX_ABI_DECLARATION_BYTES, MAX_DEPENDENCIES,
    MAX_PUBLICATION_BYTES, PublicationContext, PublicationRequest, UnverifiedDependencyRef,
    decode_code_artifact, decode_dependency_ref, decode_publication_context,
    decode_publication_request, encode_code_artifact, encode_dependency_ref,
    encode_publication_context, encode_publication_request,
};
pub use auth::{
    AuthenticatedPublicationCandidate, artifact_commitment, authenticate_publication,
    publication_signing_frame,
};

/// Fail-closed errors for the candidate encoding and authentication boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicationError {
    /// Shared canonical encoding error.
    Encoding(canonical_encoding::CanonicalEncodingError),
    /// Shared canonical decoding error.
    Decoding(canonical_encoding::CanonicalDecodingError),
    /// Invalid package origin reference.
    Package(abi::package_types::PackageTypeError),
    /// Invalid protocol identifier.
    Type(protocol_types::TypeError),
    /// Hashing failed under the trusted suite.
    Hashing(hashing::HashingError),
    /// Signature framing or verification failed.
    Crypto(crypto::CryptoError),
    /// Publisher is not a canonical non-identity prime-order owning key.
    Owner(crypto::Ed25519OwnerAddressError),
    /// Non-executing WASM structural validation failed.
    Wasm(crate::ContractWasmValidationError),
    /// A deterministic byte or count limit was exceeded.
    Limit {
        field: &'static str,
        actual: usize,
        maximum: usize,
    },
    /// A required value was empty.
    Empty(&'static str),
    /// Unsupported artifact revision or zero dependency revision.
    InvalidRevision(u64),
    /// Unknown structural WASM profile.
    UnsupportedWasmProfile(u32),
    /// An unordered or duplicate entry prevents canonical interpretation.
    NonCanonicalOrder(&'static str),
    /// References name inconsistent chains.
    ChainMismatch,
    /// An initial package claims itself as a dependency.
    SelfDependency,
    /// Signature bytes must be exactly 64 bytes.
    InvalidSignatureLength(usize),
    /// The reserved memory export cannot be an entrypoint.
    ReservedExport,
    /// Request and trusted verifier contexts differ.
    ContextMismatch,
    /// The signed semantics commitment differs from the trusted expectation.
    SemanticsMismatch,
    /// The complete recomputed artifact commitment differs from the request.
    CommitmentMismatch,
    /// The publisher did not sign this exact framed request.
    InvalidSignature,
}

impl std::fmt::Display for PublicationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Encoding(e) => e.fmt(f),
            Self::Decoding(e) => e.fmt(f),
            Self::Package(e) => e.fmt(f),
            Self::Type(e) => e.fmt(f),
            Self::Hashing(e) => e.fmt(f),
            Self::Crypto(e) => e.fmt(f),
            Self::Owner(e) => e.fmt(f),
            Self::Wasm(e) => e.fmt(f),
            Self::Limit {
                field,
                actual,
                maximum,
            } => write!(f, "{field} length/count {actual} exceeds {maximum}"),
            Self::Empty(field) => write!(f, "{field} must not be empty"),
            Self::InvalidRevision(n) => write!(f, "unsupported publication revision {n}"),
            Self::UnsupportedWasmProfile(n) => write!(f, "unsupported WASM admission profile {n}"),
            Self::NonCanonicalOrder(field) => {
                write!(f, "{field} must be strictly ordered without duplicates")
            }
            Self::ChainMismatch => f.write_str("publication reference chain mismatch"),
            Self::SelfDependency => f.write_str("initial publication cannot depend on itself"),
            Self::InvalidSignatureLength(n) => {
                write!(f, "publication signature length {n}, expected 64")
            }
            Self::ReservedExport => f.write_str("memory is not a callable export"),
            Self::ContextMismatch => {
                f.write_str("publication context differs from trusted context")
            }
            Self::SemanticsMismatch => f.write_str("execution semantics commitment mismatch"),
            Self::CommitmentMismatch => f.write_str("artifact commitment mismatch"),
            Self::InvalidSignature => f.write_str("invalid publication signature"),
        }
    }
}

impl std::error::Error for PublicationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Encoding(e) => Some(e),
            Self::Decoding(e) => Some(e),
            Self::Package(e) => Some(e),
            Self::Type(e) => Some(e),
            Self::Hashing(e) => Some(e),
            Self::Crypto(e) => Some(e),
            Self::Owner(e) => Some(e),
            Self::Wasm(e) => Some(e),
            _ => None,
        }
    }
}

macro_rules! wrap_error {
    ($source:ty, $variant:ident) => {
        impl From<$source> for PublicationError {
            fn from(value: $source) -> Self {
                Self::$variant(value)
            }
        }
    };
}
wrap_error!(canonical_encoding::CanonicalEncodingError, Encoding);
wrap_error!(canonical_encoding::CanonicalDecodingError, Decoding);
wrap_error!(abi::package_types::PackageTypeError, Package);
wrap_error!(protocol_types::TypeError, Type);
wrap_error!(hashing::HashingError, Hashing);
wrap_error!(crypto::CryptoError, Crypto);
wrap_error!(crypto::Ed25519OwnerAddressError, Owner);
wrap_error!(crate::ContractWasmValidationError, Wasm);
