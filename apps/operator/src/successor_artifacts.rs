//! Successor artifact transport adapter (DR-0189 Section 3.1, Section 12).
//! Owned by the SDK so the operator and successor CLI workflows share one
//! transport; re-exported here for existing operator paths.

pub use sunrise_edge_client::successor_artifacts::{
    MAX_READINESS_CERTIFICATE_TRANSPORT_BYTES, SuccessorArtifactFiles, bounded_certificate_length,
};
