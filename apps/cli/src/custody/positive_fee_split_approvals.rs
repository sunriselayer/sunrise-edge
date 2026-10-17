//! Complete phase approvals, sharing the existing permanent request tombstone.
use super::positive_fee_split_wire::{self as wire, Phase, Reader};
use super::{error::CustodyError, fsperm, revoke};
use std::path::{Path, PathBuf};
use sunrise_edge_client::{Address, RequestId};

pub(super) const MAX_TRUST_BYTES: usize = 2048;
pub(super) const MAX_MEANING_BYTES: usize =
    crate::positive_fee_claim_split::MAX_POSITIVE_SPLIT_REVIEW_BYTES;
pub(super) const MAX_FRAME_BYTES: usize = 16 * 1024;
const MAX_RECORD_BYTES: usize =
    wire::MAX_REQUEST_BYTES + MAX_TRUST_BYTES + MAX_MEANING_BYTES + MAX_FRAME_BYTES + 256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Content {
    pub(super) phase: Phase,
    pub(super) request_id: RequestId,
    pub(super) claimant: Address,
    pub(super) payload: Vec<u8>,
    pub(super) trust: Vec<u8>,
    pub(super) meaning: Vec<u8>,
    pub(super) frame: Vec<u8>,
}

fn path(dir: &Path, id: &RequestId, phase: Phase) -> PathBuf {
    let suffix: &str = match phase {
        Phase::Leg => "leg",
        Phase::Claim => "claim",
    };
    dir.join(format!("{id}.positive-fee-split.{suffix}"))
}

fn encode(content: &Content, expires: u64) -> Result<Vec<u8>, CustodyError> {
    let mut out: Vec<u8> = vec![1, content.phase as u8];
    out.extend_from_slice(content.request_id.as_bytes());
    out.extend_from_slice(content.claimant.as_bytes());
    out.extend_from_slice(&expires.to_be_bytes());
    for (bytes, max) in [
        (&content.payload, wire::MAX_REQUEST_BYTES),
        (&content.trust, MAX_TRUST_BYTES),
        (&content.meaning, MAX_MEANING_BYTES),
        (&content.frame, MAX_FRAME_BYTES),
    ] {
        wire::put_bytes(&mut out, bytes, max).map_err(CustodyError::Wire)?;
    }
    Ok(out)
}

fn decode(bytes: &[u8]) -> Result<(Content, u64), CustodyError> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(CustodyError::ApprovalMalformed);
    }
    let result: Result<(Content, u64), super::wire::CustodyWireError> = (|| {
        let mut r: Reader<'_> = Reader::new(bytes);
        if r.array::<1>()?[0] != 1 {
            return Err(super::wire::CustodyWireError::Truncated);
        }
        let phase: Phase = match r.array::<1>()?[0] {
            1 => Phase::Leg,
            2 => Phase::Claim,
            _ => return Err(super::wire::CustodyWireError::Truncated),
        };
        let request_id: RequestId =
            RequestId::new(r.array()?).map_err(super::wire::CustodyWireError::RequestId)?;
        let claimant: Address = Address::new(r.array()?);
        let expires: u64 = r.u64()?;
        let content: Content = Content {
            phase,
            request_id,
            claimant,
            payload: r.bytes(wire::MAX_REQUEST_BYTES)?,
            trust: r.bytes(MAX_TRUST_BYTES)?,
            meaning: r.bytes(MAX_MEANING_BYTES)?,
            frame: r.bytes(MAX_FRAME_BYTES)?,
        };
        r.finish()?;
        Ok((content, expires))
    })();
    result.map_err(CustodyError::Wire)
}

/// Only the explicit offline approver writes; phase records never overwrite.
pub(super) fn write(dir: &Path, content: &Content, expires: u64) -> Result<(), CustodyError> {
    if revoke::is_revoked(dir, &content.request_id)? {
        return Err(CustodyError::ApprovalRevoked);
    }
    let bytes: Vec<u8> = encode(content, expires)?;
    fsperm::write_private_file(
        &path(dir, &content.request_id, content.phase),
        0o700,
        0o600,
        &bytes,
        false,
    )?;
    if revoke::is_revoked(dir, &content.request_id)? {
        return Err(CustodyError::ApprovalRevoked);
    }
    Ok(())
}

/// Every byte of content, trusted binding, meaning and frame must match.
pub(super) fn authorize(dir: &Path, expected: &Content, now: u64) -> Result<(), CustodyError> {
    if revoke::is_revoked(dir, &expected.request_id)? {
        return Err(CustodyError::ApprovalRevoked);
    }
    let bytes: Vec<u8> = fsperm::read_private_file(
        &path(dir, &expected.request_id, expected.phase),
        0o600,
        0o700,
        MAX_RECORD_BYTES,
    )?;
    let (actual, expires): (Content, u64) = decode(&bytes)?;
    if actual != *expected || now >= expires {
        return Err(CustodyError::ApprovalMalformed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::fsperm::test_support::TempDir;
    use super::*;
    fn content(phase: Phase) -> Content {
        Content {
            phase,
            request_id: RequestId::new([7; 32]).unwrap(),
            claimant: Address::new([9; 32]),
            payload: vec![1],
            trust: vec![2],
            meaning: vec![3],
            frame: vec![4],
        }
    }
    #[test]
    fn phases_coexist_and_whole_content_expiry_and_permanent_cancellation_bind_both() {
        let dir = TempDir::new(0o700);
        let leg: Content = content(Phase::Leg);
        let claim: Content = content(Phase::Claim);
        write(&dir.0, &leg, 30).unwrap();
        write(&dir.0, &claim, 40).unwrap();
        let saved_leg: Vec<u8> = std::fs::read(path(&dir.0, &leg.request_id, Phase::Leg)).unwrap();
        let saved_claim: Vec<u8> =
            std::fs::read(path(&dir.0, &leg.request_id, Phase::Claim)).unwrap();
        assert!(write(&dir.0, &leg, 100).is_err());
        authorize(&dir.0, &leg, 29).unwrap();
        authorize(&dir.0, &claim, 39).unwrap();
        assert!(authorize(&dir.0, &leg, 30).is_err());
        for field in 0..4 {
            let mut changed: Content = leg.clone();
            match field {
                0 => changed.payload.push(1),
                1 => changed.trust.push(1),
                2 => changed.meaning.push(1),
                _ => changed.frame.push(1),
            }
            assert!(authorize(&dir.0, &changed, 1).is_err());
        }
        revoke::revoke(&dir.0, &leg.request_id).unwrap();
        for (phase, saved) in [(Phase::Leg, saved_leg), (Phase::Claim, saved_claim)] {
            let restored: PathBuf = path(&dir.0, &leg.request_id, phase);
            std::fs::remove_file(&restored).unwrap();
            super::super::fsperm::test_support::write_mode_file(&restored, 0o600, &saved);
        }
        assert!(authorize(&dir.0, &leg, 1).is_err());
        assert!(authorize(&dir.0, &claim, 1).is_err());
        assert!(write(&dir.0, &claim, 100).is_err());
        // Actual restored old files do not resurrect either phase.
        assert!(path(&dir.0, &leg.request_id, Phase::Leg).exists());
        assert!(path(&dir.0, &leg.request_id, Phase::Claim).exists());
    }
    #[test]
    fn phase_key_identity_and_malformed_or_trailing_record_refuse() {
        let leg: Content = content(Phase::Leg);
        let bytes: Vec<u8> = encode(&leg, 30).unwrap();
        for end in 0..bytes.len() {
            assert!(decode(&bytes[..end]).is_err());
        }
        let mut changed: Vec<u8> = bytes.clone();
        changed.push(0);
        assert!(decode(&changed).is_err());
        changed = bytes.clone();
        changed[1] = 3;
        assert!(decode(&changed).is_err());
        let dir = TempDir::new(0o700);
        write(&dir.0, &leg, 30).unwrap();
        assert!(authorize(&dir.0, &content(Phase::Claim), 1).is_err());
        let mut wrong_key: Content = leg.clone();
        wrong_key.claimant = Address::new([8; 32]);
        assert!(authorize(&dir.0, &wrong_key, 1).is_err());
    }
}
