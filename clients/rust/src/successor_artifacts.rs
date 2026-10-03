//! Successor artifact transport adapter (DR-0189 Section 3.1, Section 12).
//!
//! Implements the node-core SuccessorArtifactSource trait over the exact
//! existing saved business-cut, history_export and certificate-file
//! transports. Every returned value is untrusted transport; node-core
//! performs every verification. The adapter never caches a result across
//! calls, matching the no-memo re-verification this trait feeds. Shared by
//! the operator activation/host and by successor CLI workflows.

use crate::business_cut_archive::{CutArchiveError, read_business_cut_archive};
use crate::immutable_archive::ImmutableArchiveReader;
use crate::ordered_history_archive::read_ordered_history_height;
use node_core::business_reconstruction::{BusinessReconstructionPlan, cut::SavedBusinessCut};
use node_core::ordered_economics::{OrderedHistoryHeightMaterial, OrderedHistoryIdentity};
use node_core::serving_authority::{SuccessorArtifactError, SuccessorArtifactSource};

/// Matches the DR-0178 wire bound the certificate archive already stores:
/// artifact callers never request a certificate transport above this size.
pub const MAX_READINESS_CERTIFICATE_TRANSPORT_BYTES: usize = 1024 * 1024;

/// Owns three independently opened read-only transports: the saved business
/// cut (through T), the full ordered-history history_export directory
/// through the committed Seal height h, and the retained readiness
/// certificate directory. Opening performs no verification; every trait
/// call re-reads from disk. Holding each directory handle and rechecking it
/// around a read is a local-replacement guard only, never authority.
pub struct SuccessorArtifactFiles<'a> {
    plan: BusinessReconstructionPlan<'a>,
    cut_archive: ImmutableArchiveReader,
    manifest_history: ImmutableArchiveReader,
    certificate_archive: ImmutableArchiveReader,
}

impl<'a> SuccessorArtifactFiles<'a> {
    /// cut_archive is the saved pre-Seal business cut (through T);
    /// manifest_history the full history_export through the committed Seal
    /// height h; certificate_archive holds the retained certificate.bin.
    #[must_use]
    pub fn new(
        plan: BusinessReconstructionPlan<'a>,
        cut_archive: ImmutableArchiveReader,
        manifest_history: ImmutableArchiveReader,
        certificate_archive: ImmutableArchiveReader,
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
    pub fn into_directories(
        self,
    ) -> (ImmutableArchiveReader, ImmutableArchiveReader, ImmutableArchiveReader) {
        (self.cut_archive, self.manifest_history, self.certificate_archive)
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

impl SuccessorArtifactSource for SuccessorArtifactFiles<'_> {
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
            .map_err(|_| SuccessorArtifactError::Io)?;
        let material: OrderedHistoryHeightMaterial = read_ordered_history_height(
            self.plan.ordered_policy,
            self.manifest_history.root(),
            identity,
            height,
        )
        .map_err(|_| SuccessorArtifactError::Malformed)?;
        self.manifest_history
            .ensure_attached()
            .map_err(|_| SuccessorArtifactError::Io)?;
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

/// Exact DR-0189 Section 3.1 transport bound: length <= 1 MiB, else refuse.
/// A caller-claimed length never selects a larger read; the owning verifier
/// (SealIntent field 6) is the only source of a legitimate length.
pub fn bounded_certificate_length(length: u32) -> Result<usize, SuccessorArtifactError> {
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
        let maximum: u32 = u32::try_from(MAX_READINESS_CERTIFICATE_TRANSPORT_BYTES).unwrap();
        assert_eq!(bounded_certificate_length(0).unwrap(), 0);
        assert_eq!(
            bounded_certificate_length(maximum).unwrap(),
            MAX_READINESS_CERTIFICATE_TRANSPORT_BYTES
        );
        assert!(matches!(
            bounded_certificate_length(maximum + 1),
            Err(SuccessorArtifactError::Oversized)
        ));
        assert!(matches!(
            bounded_certificate_length(u32::MAX),
            Err(SuccessorArtifactError::Oversized)
        ));
    }
}
