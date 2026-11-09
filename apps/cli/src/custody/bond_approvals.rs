//! Broker-owned, create-only phase approvals for original-genesis bond.
//!
//! The broker alone writes these private records after observing each Unix
//! peer UID before reading its typed request. Neither protected key worker
//! can read or write this directory. Records bind the exact reconstructed
//! request, review meaning, frame, role configuration, signer key and both
//! operation IDs; a permanent tombstone can only reduce authority.

use std::path::{Path, PathBuf};

use sunrise_edge_client::{Address, RequestId};

use super::{
    bond_policy::BondApprovalContent,
    bond_wire::BondPhase,
    error::CustodyError,
    fsperm,
    positive_fee_split_wire::{Reader, put_bytes},
    revoke,
    wire::CustodyWireError,
};

const RECORD_VERSION: u8 = 1;
const MAX_CONFIG_BYTES: usize = 4096;
const MAX_REQUEST_BYTES: usize = super::bond_wire::MAX_REQUEST_BYTES;
const MAX_MEANING_BYTES: usize = 2
    * sunrise_edge_client::bond_registration::MAX_LOCAL_EXECUTION_INTENT_BYTES
    + 2 * sunrise_edge_client::bond_registration::MAX_BOND_REGISTRATION_ROW_BYTES
    + 128 * 1024;
const MAX_FRAME_BYTES: usize = 64 * 1024;
const MAX_RECORD_BYTES: usize = 1
    + 1
    + 4
    + 8
    + 32
    + 32
    + 32
    + MAX_CONFIG_BYTES
    + MAX_REQUEST_BYTES
    + MAX_MEANING_BYTES
    + MAX_FRAME_BYTES
    + 16;

fn path(dir: &Path, id: RequestId, phase: BondPhase) -> PathBuf {
    let suffix = match phase {
        BondPhase::Inner => "inner",
        BondPhase::Outer => "outer",
    };
    dir.join(format!("{id}.bond.{suffix}"))
}

fn encode(
    content: &BondApprovalContent,
    observed_approver_uid: u32,
    expires: u64,
) -> Result<Vec<u8>, CustodyError> {
    let mut out = vec![RECORD_VERSION, content.phase as u8];
    out.extend_from_slice(&observed_approver_uid.to_be_bytes());
    out.extend_from_slice(&expires.to_be_bytes());
    out.extend_from_slice(content.request_id.as_bytes());
    out.extend_from_slice(content.inner_request_id.as_bytes());
    out.extend_from_slice(content.expected_key.as_bytes());
    for (bytes, maximum) in [
        (&content.config, MAX_CONFIG_BYTES),
        (&content.request, MAX_REQUEST_BYTES),
        (&content.meaning, MAX_MEANING_BYTES),
        (&content.frame, MAX_FRAME_BYTES),
    ] {
        put_bytes(&mut out, bytes, maximum).map_err(CustodyError::Wire)?;
    }
    Ok(out)
}

fn decode(bytes: &[u8]) -> Result<(BondApprovalContent, u32, u64), CustodyError> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(CustodyError::ApprovalMalformed);
    }
    let mut reader = Reader::new(bytes);
    if reader.array::<1>().map_err(CustodyError::Wire)?[0] != RECORD_VERSION {
        return Err(CustodyError::ApprovalMalformed);
    }
    let phase = match reader.array::<1>().map_err(CustodyError::Wire)?[0] {
        1 => BondPhase::Inner,
        2 => BondPhase::Outer,
        _ => return Err(CustodyError::ApprovalMalformed),
    };
    let uid = u32::from_be_bytes(reader.array().map_err(CustodyError::Wire)?);
    let expires = reader.u64().map_err(CustodyError::Wire)?;
    let request_id = RequestId::new(reader.array().map_err(CustodyError::Wire)?)
        .map_err(|error| CustodyError::Wire(CustodyWireError::RequestId(error)))?;
    let inner_request_id = RequestId::new(reader.array().map_err(CustodyError::Wire)?)
        .map_err(|error| CustodyError::Wire(CustodyWireError::RequestId(error)))?;
    let expected_key = Address::new(reader.array().map_err(CustodyError::Wire)?);
    let content = BondApprovalContent {
        phase,
        request_id,
        inner_request_id,
        expected_key,
        config: reader.bytes(MAX_CONFIG_BYTES).map_err(CustodyError::Wire)?,
        request: reader
            .bytes(MAX_REQUEST_BYTES)
            .map_err(CustodyError::Wire)?,
        meaning: reader
            .bytes(MAX_MEANING_BYTES)
            .map_err(CustodyError::Wire)?,
        frame: reader.bytes(MAX_FRAME_BYTES).map_err(CustodyError::Wire)?,
    };
    reader.finish().map_err(CustodyError::Wire)?;
    if encode(&content, uid, expires)? != bytes {
        return Err(CustodyError::ApprovalMalformed);
    }
    Ok((content, uid, expires))
}

pub(super) fn write(
    dir: &Path,
    content: &BondApprovalContent,
    observed_approver_uid: u32,
    expires: u64,
    now: u64,
) -> Result<(), CustodyError> {
    if now >= expires || revoke::is_revoked(dir, &content.request_id)? {
        return Err(CustodyError::ApprovalRevoked);
    }
    let bytes = encode(content, observed_approver_uid, expires)?;
    fsperm::write_private_file(
        &path(dir, content.request_id, content.phase),
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

pub(super) fn authorize(
    dir: &Path,
    expected: &BondApprovalContent,
    expected_approver_uid: u32,
    now: u64,
) -> Result<(), CustodyError> {
    if revoke::is_revoked(dir, &expected.request_id)? {
        return Err(CustodyError::ApprovalRevoked);
    }
    let bytes = fsperm::read_private_file(
        &path(dir, expected.request_id, expected.phase),
        0o600,
        0o700,
        MAX_RECORD_BYTES,
    )?;
    let (actual, observed_uid, expires) = decode(&bytes)?;
    if actual != *expected || observed_uid != expected_approver_uid || now >= expires {
        return Err(CustodyError::ApprovalMalformed);
    }
    Ok(())
}

/// Uses one wall-clock sample for both phases of the release decision.
pub(super) fn authorize_for_sign(
    dir: &Path,
    content: &BondApprovalContent,
    inner: Option<&BondApprovalContent>,
    inner_approver_uid: u32,
    outer_approver_uid: u32,
    sampled_now: u64,
) -> Result<(), CustodyError> {
    match (content.phase, inner) {
        (BondPhase::Inner, None) => authorize(dir, content, inner_approver_uid, sampled_now),
        (BondPhase::Outer, Some(inner))
            if inner.phase == BondPhase::Inner && inner.request_id == content.inner_request_id =>
        {
            authorize(dir, inner, inner_approver_uid, sampled_now)?;
            authorize(dir, content, outer_approver_uid, sampled_now)
        }
        _ => Err(CustodyError::ApprovalMalformed),
    }
}

pub(super) fn revoke(dir: &Path, id: &RequestId) -> Result<(), CustodyError> {
    revoke::revoke(dir, id)
}

#[cfg(test)]
mod tests {
    use super::super::fsperm::test_support::TempDir;
    use super::*;

    fn content(phase: BondPhase) -> BondApprovalContent {
        BondApprovalContent {
            phase,
            request_id: RequestId::new([7; 32]).unwrap(),
            inner_request_id: RequestId::new([6; 32]).unwrap(),
            expected_key: Address::new([8; 32]),
            config: vec![1],
            request: vec![2],
            meaning: vec![3],
            frame: vec![4],
        }
    }

    #[test]
    fn exact_record_uid_expiry_restart_and_revoke() {
        let dir = TempDir::new(0o700);
        let approved = content(BondPhase::Outer);
        write(&dir.0, &approved, 2001, 50, 1).unwrap();
        authorize(&dir.0, &approved, 2001, 49).unwrap();
        assert!(authorize(&dir.0, &approved, 2002, 49).is_err());
        assert!(authorize(&dir.0, &approved, 2001, 50).is_err());
        let mut changed = approved.clone();
        changed.frame.push(0);
        assert!(authorize(&dir.0, &changed, 2001, 2).is_err());
        changed = approved.clone();
        changed.meaning.push(0);
        assert!(authorize(&dir.0, &changed, 2001, 2).is_err());
        assert!(write(&dir.0, &approved, 2001, 100, 2).is_err());
        let retained = std::fs::read(path(&dir.0, approved.request_id, approved.phase)).unwrap();
        // Reopening the same store models a broker restart: no in-memory
        // approval is required, and the exact saved bytes still govern.
        assert_eq!(decode(&retained).unwrap().0, approved);
        revoke(&dir.0, &approved.request_id).unwrap();
        assert!(authorize(&dir.0, &approved, 2001, 2).is_err());
        assert!(write(&dir.0, &approved, 2001, 100, 2).is_err());
        // Restoring the exact old approval cannot remove the tombstone.
        std::fs::remove_file(path(&dir.0, approved.request_id, approved.phase)).unwrap();
        super::super::fsperm::test_support::write_mode_file(
            &path(&dir.0, approved.request_id, approved.phase),
            0o600,
            &retained,
        );
        assert!(authorize(&dir.0, &approved, 2001, 2).is_err());
    }

    #[test]
    fn both_phase_expiries_use_the_release_sample() {
        let dir = TempDir::new(0o700);
        let mut inner = content(BondPhase::Inner);
        inner.request_id = RequestId::new([6; 32]).unwrap();
        let outer = content(BondPhase::Outer);
        write(&dir.0, &inner, 2001, 50, 1).unwrap();
        write(&dir.0, &outer, 2002, 51, 1).unwrap();
        authorize_for_sign(&dir.0, &outer, Some(&inner), 2001, 2002, 49).unwrap();
        assert!(authorize_for_sign(&dir.0, &outer, Some(&inner), 2001, 2002, 50).is_err());
        assert!(authorize_for_sign(&dir.0, &outer, Some(&inner), 2002, 2001, 49).is_err());
        assert!(authorize_for_sign(&dir.0, &outer, None, 2001, 2002, 49).is_err());
    }
}
