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
use crate::ordered_history_archive::{
    read_ordered_history_height, read_verified_ordered_history_archive,
};
use node_core::business_reconstruction::{BusinessReconstructionPlan, cut::SavedBusinessCut};
use node_core::ordered_economics::{
    MAX_ORDERED_HISTORY_DESCRIPTOR_BYTES, OrderedEconomicsPolicy, OrderedHistoryHeightMaterial,
    OrderedHistoryIdentity, decode_ordered_history_identity,
};
use node_core::serving_authority::{
    SuccessorActivationError, SuccessorArtifactError, SuccessorArtifactSource,
    SuccessorChainArtifacts, SuccessorChainBudget, SuccessorLinkPins,
};
use std::path::Path;

/// Matches the DR-0178 wire bound the certificate archive already stores:
/// artifact callers never request a certificate transport above this size.
pub const MAX_READINESS_CERTIFICATE_TRANSPORT_BYTES: usize = 1024 * 1024;

/// Refuses an empty or over-budget chain before the caller opens a genesis
/// file or any archive. It never truncates or silently selects a prefix.
pub fn require_successor_chain_budget(
    links: usize,
    budget: SuccessorChainBudget,
) -> Result<(), SuccessorActivationError> {
    if links == 0 {
        return Err(SuccessorActivationError::Invalid(
            "successor chain is empty",
        ));
    }
    if u64::try_from(links).map_err(|_| SuccessorActivationError::ChainBudgetExceeded {
        links,
        budget: budget.get(),
    })? > u64::from(budget.get())
    {
        return Err(SuccessorActivationError::ChainBudgetExceeded {
            links,
            budget: budget.get(),
        });
    }
    Ok(())
}

/// Read-only directories for one link, in the same four roles used by the
/// original single-link workflow. Values are local untrusted transport pins.
pub struct SuccessorLinkArchiveDirectories<'p> {
    /// Ordered history through this link's cut height T.
    pub plan_history: &'p Path,
    /// The saved pre-Seal business cut of this link.
    pub cut: &'p Path,
    /// Full ordered history through this link's committed Seal height h.
    pub manifest_history: &'p Path,
    /// The retained readiness certificate named by the accepted Seal.
    pub certificate: &'p Path,
}

struct SuccessorLinkArchiveFiles {
    plan_history: ImmutableArchiveReader,
    cut: ImmutableArchiveReader,
    manifest_history: ImmutableArchiveReader,
    certificate: ImmutableArchiveReader,
    pins: SuccessorLinkPins,
}

/// Ordered held directory handles for all links. No verified result is
/// stored: each trait invocation rereads the original bytes and checks the
/// held directory attachments. Only core supplies a link's decoding policy.
pub struct SuccessorChainArtifactFiles {
    links: Vec<SuccessorLinkArchiveFiles>,
}

impl SuccessorChainArtifactFiles {
    /// Checks the complete link count before any archive I/O, then opens
    /// every link in order. Partial construction never yields a transport.
    pub fn open(
        directories: &[SuccessorLinkArchiveDirectories<'_>],
        budget: SuccessorChainBudget,
    ) -> Result<Self, SuccessorActivationError> {
        require_successor_chain_budget(directories.len(), budget)?;
        let mut links: Vec<SuccessorLinkArchiveFiles> = Vec::with_capacity(directories.len());
        for directory in directories {
            let plan_history: ImmutableArchiveReader =
                ImmutableArchiveReader::open(directory.plan_history)
                    .map_err(|_| SuccessorArtifactError::Io)?;
            let cut: ImmutableArchiveReader = ImmutableArchiveReader::open(directory.cut)
                .map_err(|_| SuccessorArtifactError::Io)?;
            let manifest_history: ImmutableArchiveReader =
                ImmutableArchiveReader::open(directory.manifest_history)
                    .map_err(|_| SuccessorArtifactError::Io)?;
            let certificate: ImmutableArchiveReader =
                ImmutableArchiveReader::open(directory.certificate)
                    .map_err(|_| SuccessorArtifactError::Io)?;
            let pins: SuccessorLinkPins = SuccessorLinkPins {
                cut_identity: read_identity(&plan_history)?,
                manifest_identity: read_identity(&manifest_history)?,
            };
            links.push(SuccessorLinkArchiveFiles {
                plan_history,
                cut,
                manifest_history,
                certificate,
                pins,
            });
        }
        Ok(Self { links })
    }

    /// The untrusted descriptor claims in their supplied link order. Core
    /// authenticates every claim and derives all later policies privately.
    #[must_use]
    pub fn pins(&self) -> Vec<SuccessorLinkPins> {
        self.links
            .iter()
            .map(|link: &SuccessorLinkArchiveFiles| link.pins.clone())
            .collect()
    }

    /// Rechecks every held input archive against a proposed output path.
    pub fn require_output_outside(&self, path: &Path) -> std::io::Result<()> {
        for link in &self.links {
            for archive in [
                &link.plan_history,
                &link.cut,
                &link.manifest_history,
                &link.certificate,
            ] {
                archive.require_output_outside(path)?;
            }
        }
        Ok(())
    }

    fn link(&self, index: u32) -> Result<&SuccessorLinkArchiveFiles, SuccessorArtifactError> {
        let index: usize = usize::try_from(index).map_err(|_| SuccessorArtifactError::Missing)?;
        let link: &SuccessorLinkArchiveFiles = self
            .links
            .get(index)
            .ok_or(SuccessorArtifactError::Missing)?;
        if read_identity(&link.plan_history)? != link.pins.cut_identity
            || read_identity(&link.manifest_history)? != link.pins.manifest_identity
        {
            return Err(SuccessorArtifactError::Malformed);
        }
        Ok(link)
    }
}

fn read_identity(
    archive: &ImmutableArchiveReader,
) -> Result<OrderedHistoryIdentity, SuccessorArtifactError> {
    let bytes: Vec<u8> = archive
        .read("identity.bin", MAX_ORDERED_HISTORY_DESCRIPTOR_BYTES)
        .map_err(|_| SuccessorArtifactError::Io)?;
    decode_ordered_history_identity(&bytes).map_err(|_| SuccessorArtifactError::Malformed)
}

impl SuccessorChainArtifacts for SuccessorChainArtifactFiles {
    fn saved_business_cut(
        &mut self,
        index: u32,
        plan: &BusinessReconstructionPlan<'_>,
    ) -> Result<SavedBusinessCut, SuccessorArtifactError> {
        let link: &SuccessorLinkArchiveFiles = self.link(index)?;
        link.plan_history
            .ensure_attached()
            .map_err(|_| SuccessorArtifactError::Io)?;
        let (identity, _ordered): (OrderedHistoryIdentity, Vec<OrderedHistoryHeightMaterial>) =
            read_verified_ordered_history_archive(plan.ordered_policy, link.plan_history.root())
                .map_err(|_| SuccessorArtifactError::Malformed)?;
        link.plan_history
            .ensure_attached()
            .map_err(|_| SuccessorArtifactError::Io)?;
        if identity != *plan.ordered_history_identity || identity != link.pins.cut_identity {
            return Err(SuccessorArtifactError::Malformed);
        }
        read_business_cut_archive(plan, &link.cut).map_err(cut_error)
    }

    fn history_height(
        &mut self,
        index: u32,
        policy: &OrderedEconomicsPolicy,
        identity: &OrderedHistoryIdentity,
        height: u64,
    ) -> Result<OrderedHistoryHeightMaterial, SuccessorArtifactError> {
        let link: &SuccessorLinkArchiveFiles = self.link(index)?;
        if *identity != link.pins.manifest_identity {
            return Err(SuccessorArtifactError::Malformed);
        }
        link.manifest_history
            .ensure_attached()
            .map_err(|_| SuccessorArtifactError::Io)?;
        let material: OrderedHistoryHeightMaterial =
            read_ordered_history_height(policy, link.manifest_history.root(), identity, height)
                .map_err(|_| SuccessorArtifactError::Malformed)?;
        link.manifest_history
            .ensure_attached()
            .map_err(|_| SuccessorArtifactError::Io)?;
        Ok(material)
    }

    fn readiness_certificate(
        &mut self,
        index: u32,
        length: u32,
    ) -> Result<Vec<u8>, SuccessorArtifactError> {
        let length: usize = bounded_certificate_length(length)?;
        let link: &SuccessorLinkArchiveFiles = self.link(index)?;
        let bytes: Vec<u8> = link
            .certificate
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
    ) -> (
        ImmutableArchiveReader,
        ImmutableArchiveReader,
        ImmutableArchiveReader,
    ) {
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
    use super::{
        MAX_READINESS_CERTIFICATE_TRANSPORT_BYTES, SuccessorChainArtifactFiles,
        SuccessorLinkArchiveDirectories, bounded_certificate_length,
    };
    use node_core::serving_authority::{
        SuccessorActivationError, SuccessorArtifactError, SuccessorChainBudget,
    };
    use std::{num::NonZeroU32, path::Path};

    #[test]
    fn chain_budget_refuses_before_opening_any_directory() {
        let missing: &Path = Path::new("/nonexistent/recurring-successor-budget-before-io");
        let directories: Vec<SuccessorLinkArchiveDirectories<'_>> = (0..2)
            .map(|_| SuccessorLinkArchiveDirectories {
                plan_history: missing,
                cut: missing,
                manifest_history: missing,
                certificate: missing,
            })
            .collect();
        let budget: SuccessorChainBudget = SuccessorChainBudget::new(NonZeroU32::MIN);
        assert!(matches!(
            SuccessorChainArtifactFiles::open(&directories, budget),
            Err(SuccessorActivationError::ChainBudgetExceeded {
                links: 2,
                budget: 1
            })
        ));
        assert!(matches!(
            SuccessorChainArtifactFiles::open(&[], budget),
            Err(SuccessorActivationError::Invalid(
                "successor chain is empty"
            ))
        ));
        assert!(!missing.exists());
    }

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
