//! Successor artifact transport adapter (DR-0189 Section 3.1, Section 12).
//!
//! Implements the node-core `SuccessorArtifactSource` trait over the exact
//! existing saved business-cut, `history_export` and certificate-file
//! transports this operator already writes. Every returned value is
//! untrusted transport; node-core performs every verification. node-core
//! never depends on this crate, and this adapter never caches a result
//! across calls, matching the no-memo re-verification this trait feeds.

use crate::{
    business_cut::{CutArchiveError, read_business_cut_archive},
    immutable_archive::ImmutableArchive,
};
use node_core::business_reconstruction::{BusinessReconstructionPlan, cut::SavedBusinessCut};
use node_core::ordered_economics::{OrderedHistoryHeightMaterial, OrderedHistoryIdentity};
use node_core::serving_authority::{SuccessorArtifactError, SuccessorArtifactSource};
use sunrise_edge_client::ordered_history_archive::read_ordered_history_height;

/// Matches the DR-0178 wire bound this archive already stores: artifact
/// callers never request a certificate transport above this size.
const MAX_READINESS_CERTIFICATE_TRANSPORT_BYTES: usize = 1024 * 1024;

/// Owns three independently opened read-only transports: the saved business
/// cut (through T), the full ordered-history `history_export` directory
/// through the committed Seal height h, and the retained readiness
/// certificate directory. Opening this composition performs no
/// verification; every trait method call re-reads from disk. Holding each
/// directory handle and rechecking it around a read is a local-replacement
/// guard only, never cryptographic authority: the node-core source-free
/// verifier this trait feeds remains the sole authority over every
/// returned byte.
pub struct SuccessorArtifactFiles<'a> {
    plan: BusinessReconstructionPlan<'a>,
    cut_archive: ImmutableArchive,
    manifest_history: ImmutableArchive,
    certificate_archive: ImmutableArchive,
}

impl<'a> SuccessorArtifactFiles<'a> {
    /// `cut_archive` is the existing saved pre-Seal business cut (through
    /// T); `manifest_history` is a read-only handle on the full
    /// `history_export` directory through the committed Seal height h;
    /// `certificate_archive` holds the retained `certificate.bin` this host
    /// independently verified (DR-0178).
    #[must_use]
    pub fn new(
        plan: BusinessReconstructionPlan<'a>,
        cut_archive: ImmutableArchive,
        manifest_history: ImmutableArchive,
        certificate_archive: ImmutableArchive,
    ) -> Self {
        Self {
            plan,
            cut_archive,
            manifest_history,
            certificate_archive,
        }
    }

    /// Returns the three held directory handles so a long-lived host can
    /// rebuild a fresh, non-caching source for its next invocation.
    #[must_use]
    pub fn into_directories(self) -> (ImmutableArchive, ImmutableArchive, ImmutableArchive) {
        (
            self.cut_archive,
            self.manifest_history,
            self.certificate_archive,
        )
    }
}

fn cut_error(error: CutArchiveError) -> SuccessorArtifactError {
    match error {
        CutArchiveError::Io(_) => SuccessorArtifactError::Io,
        CutArchiveError::Invalid(_) | CutArchiveError::Core(_) | CutArchiveError::Source(_) => {
            SuccessorArtifactError::Malformed
        }
    }
}

fn attachment_error(_: std::io::Error) -> SuccessorArtifactError {
    SuccessorArtifactError::Io
}

impl<'a> SuccessorArtifactSource for SuccessorArtifactFiles<'a> {
    fn saved_business_cut(&mut self) -> Result<SavedBusinessCut, SuccessorArtifactError> {
        read_business_cut_archive(&self.plan, &self.cut_archive).map_err(cut_error)
    }

    fn history_height(
        &mut self,
        identity: &OrderedHistoryIdentity,
        height: u64,
    ) -> Result<OrderedHistoryHeightMaterial, SuccessorArtifactError> {
        self.manifest_history
            .ensure_attached()
            .map_err(attachment_error)?;
        let material = read_ordered_history_height(
            self.plan.ordered_policy,
            self.manifest_history.root(),
            identity,
            height,
        )
        .map_err(|_| SuccessorArtifactError::Malformed)?;
        self.manifest_history
            .ensure_attached()
            .map_err(attachment_error)?;
        Ok(material)
    }

    fn readiness_certificate(&mut self, length: u32) -> Result<Vec<u8>, SuccessorArtifactError> {
        let length: usize = bounded_certificate_length(length)?;
        let bytes: Vec<u8> = self
            .certificate_archive
            .read("certificate.bin", length)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    SuccessorArtifactError::Missing
                } else {
                    SuccessorArtifactError::Io
                }
            })?;
        if bytes.len() != length {
            return Err(SuccessorArtifactError::Malformed);
        }
        Ok(bytes)
    }
}

/// Exact DR-0189 Section 3.1 transport bound: `length <= 1 MiB`, else refuse.
/// A caller-claimed length never selects a larger read; the owning verifier
/// (SealIntent field 6) is the only source of a legitimate length.
fn bounded_certificate_length(length: u32) -> Result<usize, SuccessorArtifactError> {
    let length: usize = usize::try_from(length).map_err(|_| SuccessorArtifactError::Oversized)?;
    if length > MAX_READINESS_CERTIFICATE_TRANSPORT_BYTES {
        return Err(SuccessorArtifactError::Oversized);
    }
    Ok(length)
}

#[cfg(test)]
mod tests {
    use super::{MAX_READINESS_CERTIFICATE_TRANSPORT_BYTES, bounded_certificate_length};
    use node_core::serving_authority::SuccessorArtifactError;

    #[test]
    fn certificate_length_transport_is_bounded_exactly_at_one_mebibyte() {
        assert_eq!(bounded_certificate_length(0).unwrap(), 0);
        assert_eq!(
            bounded_certificate_length(
                u32::try_from(MAX_READINESS_CERTIFICATE_TRANSPORT_BYTES).unwrap()
            )
            .unwrap(),
            MAX_READINESS_CERTIFICATE_TRANSPORT_BYTES
        );
        assert!(matches!(
            bounded_certificate_length(
                u32::try_from(MAX_READINESS_CERTIFICATE_TRANSPORT_BYTES).unwrap() + 1
            ),
            Err(SuccessorArtifactError::Oversized)
        ));
        assert!(matches!(
            bounded_certificate_length(u32::MAX),
            Err(SuccessorArtifactError::Oversized)
        ));
    }
}
