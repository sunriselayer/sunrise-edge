//! Closed adapter-local kind 6. No caller-supplied frame or trust configuration.
use super::wire::{CUSTODY_WIRE_VERSION, CustodyWireError};
use crate::positive_fee_claim_split::{PositiveSplitTerms, RetainedFeeObject};
use sunrise_edge_client::{
    Address, Epoch, MAX_AUTHENTICATED_OBJECT_BODY_BYTES, MAX_FEE_CLAIM_INTENT_BYTES,
    MAX_FEE_CLAIM_PREPARE_REQUEST_BYTES, decode_object_ref, encode_object_ref,
};

pub(super) const KIND: u8 = 6;
pub(super) const MAX_LEG_BYTES: usize = MAX_AUTHENTICATED_OBJECT_BODY_BYTES + 4096;
pub(super) const MAX_REQUEST_BYTES: usize = MAX_LEG_BYTES
    + sunrise_edge_client::local_execution::MAX_LOCAL_EXECUTION_INTENT_BYTES
    + MAX_FEE_CLAIM_PREPARE_REQUEST_BYTES
    + MAX_FEE_CLAIM_INTENT_BYTES
    + 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Phase {
    Leg = 1,
    Claim = 2,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct LegRequest {
    pub(super) terms: PositiveSplitTerms,
    pub(super) object: RetainedFeeObject,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Request {
    Leg(LegRequest),
    Claim {
        leg: LegRequest,
        signed_leg: Vec<u8>,
        request: Vec<u8>,
        intent: Vec<u8>,
    },
}

impl Request {
    pub(super) fn leg(&self) -> &LegRequest {
        match self {
            Self::Leg(leg) | Self::Claim { leg, .. } => leg,
        }
    }
    pub(super) const fn phase(&self) -> Phase {
        match self {
            Self::Leg(_) => Phase::Leg,
            Self::Claim { .. } => Phase::Claim,
        }
    }
}

pub(super) fn put_bytes(
    out: &mut Vec<u8>,
    bytes: &[u8],
    maximum: usize,
) -> Result<(), CustodyWireError> {
    if bytes.len() > maximum {
        return Err(CustodyWireError::ArtifactTooLarge {
            actual: bytes.len(),
            maximum,
        });
    }
    let n: u32 = u32::try_from(bytes.len()).map_err(|_| CustodyWireError::Truncated)?;
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

pub(super) struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    pub(super) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }
    pub(super) fn take(&mut self, n: usize) -> Result<&'a [u8], CustodyWireError> {
        let end: usize = self.at.checked_add(n).ok_or(CustodyWireError::Truncated)?;
        let bytes: &[u8] = self
            .bytes
            .get(self.at..end)
            .ok_or(CustodyWireError::Truncated)?;
        self.at = end;
        Ok(bytes)
    }
    pub(super) fn array<const N: usize>(&mut self) -> Result<[u8; N], CustodyWireError> {
        self.take(N)?
            .try_into()
            .map_err(|_| CustodyWireError::Truncated)
    }
    pub(super) fn u64(&mut self) -> Result<u64, CustodyWireError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    pub(super) fn bytes(&mut self, maximum: usize) -> Result<Vec<u8>, CustodyWireError> {
        let n: usize = u32::from_be_bytes(self.array()?) as usize;
        if n > maximum {
            return Err(CustodyWireError::ArtifactTooLarge { actual: n, maximum });
        }
        Ok(self.take(n)?.to_vec())
    }
    pub(super) fn finish(self) -> Result<(), CustodyWireError> {
        if self.at == self.bytes.len() {
            Ok(())
        } else {
            Err(CustodyWireError::LengthMismatch {
                declared: self.at,
                actual: self.bytes.len(),
            })
        }
    }
}

pub(super) fn encode(request: &Request) -> Result<Vec<u8>, CustodyWireError> {
    let leg: &LegRequest = request.leg();
    let mut out: Vec<u8> = vec![CUSTODY_WIRE_VERSION, KIND, request.phase() as u8];
    out.extend_from_slice(&leg.terms.escrow_request_id);
    out.extend_from_slice(&leg.terms.request_id);
    out.extend_from_slice(&leg.terms.amount.to_be_bytes());
    out.extend_from_slice(leg.terms.recipient.as_bytes());
    out.extend_from_slice(&leg.terms.nonce.to_be_bytes());
    out.extend_from_slice(&leg.terms.gas_limit.to_be_bytes());
    out.extend_from_slice(&leg.object.hash_epoch.get().to_be_bytes());
    let reference: Vec<u8> =
        encode_object_ref(&leg.object.reference).map_err(|_| CustodyWireError::Truncated)?;
    put_bytes(&mut out, &reference, 1024)?;
    put_bytes(
        &mut out,
        &leg.object.canonical_bytes,
        MAX_AUTHENTICATED_OBJECT_BODY_BYTES,
    )?;
    if let Request::Claim {
        signed_leg,
        request,
        intent,
        ..
    } = request
    {
        put_bytes(
            &mut out,
            signed_leg,
            sunrise_edge_client::local_execution::MAX_LOCAL_EXECUTION_INTENT_BYTES,
        )?;
        put_bytes(&mut out, request, MAX_FEE_CLAIM_PREPARE_REQUEST_BYTES)?;
        put_bytes(&mut out, intent, MAX_FEE_CLAIM_INTENT_BYTES)?;
    }
    if out.len() > MAX_REQUEST_BYTES || (request.phase() == Phase::Leg && out.len() > MAX_LEG_BYTES)
    {
        return Err(CustodyWireError::FrameTooLarge {
            actual: out.len(),
            maximum: MAX_REQUEST_BYTES,
        });
    }
    Ok(out)
}

pub(super) fn decode(bytes: &[u8]) -> Result<Request, CustodyWireError> {
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err(CustodyWireError::FrameTooLarge {
            actual: bytes.len(),
            maximum: MAX_REQUEST_BYTES,
        });
    }
    let mut r: Reader<'_> = Reader::new(bytes);
    let version: u8 = r.array::<1>()?[0];
    if version != CUSTODY_WIRE_VERSION {
        return Err(CustodyWireError::UnsupportedVersion(version));
    }
    let kind: u8 = r.array::<1>()?[0];
    if kind != KIND {
        return Err(CustodyWireError::UnsupportedMessageType(kind));
    }
    let phase: u8 = r.array::<1>()?[0];
    if !matches!(phase, 1 | 2) {
        return Err(CustodyWireError::UnsupportedMessageType(phase));
    }
    let terms: PositiveSplitTerms = PositiveSplitTerms {
        escrow_request_id: r.array()?,
        request_id: r.array()?,
        amount: r.u64()?,
        recipient: Address::new(r.array()?),
        nonce: r.u64()?,
        gas_limit: r.u64()?,
    };
    let hash_epoch: Epoch = Epoch::new(r.u64()?);
    let reference_bytes: Vec<u8> = r.bytes(1024)?;
    let reference: sunrise_edge_client::ObjectRef =
        decode_object_ref(&reference_bytes).map_err(|_| CustodyWireError::Truncated)?;
    if encode_object_ref(&reference).map_err(|_| CustodyWireError::Truncated)? != reference_bytes {
        return Err(CustodyWireError::Truncated);
    }
    let leg: LegRequest = LegRequest {
        terms,
        object: RetainedFeeObject {
            hash_epoch,
            reference,
            canonical_bytes: r.bytes(MAX_AUTHENTICATED_OBJECT_BODY_BYTES)?,
        },
    };
    let result: Request = if phase == 1 {
        Request::Leg(leg)
    } else {
        Request::Claim {
            leg,
            signed_leg: r
                .bytes(sunrise_edge_client::local_execution::MAX_LOCAL_EXECUTION_INTENT_BYTES)?,
            request: r.bytes(MAX_FEE_CLAIM_PREPARE_REQUEST_BYTES)?,
            intent: r.bytes(MAX_FEE_CLAIM_INTENT_BYTES)?,
        }
    };
    r.finish()?;
    if encode(&result)? != bytes {
        return Err(CustodyWireError::Truncated);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sunrise_edge_client::{Digest32, HashAlgorithmId, ObjectId, ObjectRef};
    fn leg() -> LegRequest {
        LegRequest {
            terms: PositiveSplitTerms {
                escrow_request_id: [1; 32],
                request_id: [2; 32],
                amount: 3,
                recipient: Address::new([4; 32]),
                nonce: 5,
                gas_limit: 6,
            },
            object: RetainedFeeObject {
                canonical_bytes: vec![7],
                hash_epoch: Epoch::new(8),
                reference: ObjectRef {
                    id: ObjectId::new([9; 32]),
                    version: 10,
                    digest: Digest32::new(HashAlgorithmId::Sha2_256, [11; 32]),
                },
            },
        }
    }
    #[test]
    fn exact_two_phase_roundtrip_and_foreign_family_refusal() {
        for request in [
            Request::Leg(leg()),
            Request::Claim {
                leg: leg(),
                signed_leg: vec![12],
                request: vec![13],
                intent: vec![14],
            },
        ] {
            let bytes: Vec<u8> = encode(&request).unwrap();
            assert_eq!(&bytes[..2], &[1, 6]);
            assert_eq!(decode(&bytes).unwrap(), request);
            assert!(super::super::wire::decode_request(&bytes).is_err());
            assert!(super::super::asset_wire::decode(&bytes).is_err());
            assert!(super::super::asset_split_merge_wire::decode(&bytes).is_err());
            assert!(super::super::asset_mint_burn_wire::decode(&bytes).is_err());
            assert!(super::super::asset_create_wire::decode(&bytes).is_err());
            for end in 0..bytes.len() {
                assert!(decode(&bytes[..end]).is_err());
            }
            let mut changed: Vec<u8> = bytes.clone();
            changed.push(0);
            assert!(decode(&changed).is_err());
            for (index, value) in [(0, 2), (1, 5), (2, 0), (2, 3)] {
                changed = bytes.clone();
                changed[index] = value;
                assert!(decode(&changed).is_err());
            }
        }
    }
    /// Adapter-local version, kind, phase, field order and lengths are pinned
    /// independently of this module's encoder. The nested canonical ObjectRef
    /// retains the existing protocol codec and its vectors.
    #[test]
    fn both_phase_adapter_layouts_are_stable() {
        let reference: Vec<u8> = encode_object_ref(&leg().object.reference).unwrap();
        let mut expected: Vec<u8> = vec![1, 6, 1];
        expected.extend_from_slice(&[1; 32]);
        expected.extend_from_slice(&[2; 32]);
        expected.extend_from_slice(&3_u64.to_be_bytes());
        expected.extend_from_slice(&[4; 32]);
        expected.extend_from_slice(&5_u64.to_be_bytes());
        expected.extend_from_slice(&6_u64.to_be_bytes());
        expected.extend_from_slice(&8_u64.to_be_bytes());
        expected.extend_from_slice(&(reference.len() as u32).to_be_bytes());
        expected.extend_from_slice(&reference);
        expected.extend_from_slice(&1_u32.to_be_bytes());
        expected.push(7);
        assert_eq!(encode(&Request::Leg(leg())).unwrap(), expected);
        expected[2] = 2;
        for byte in [12_u8, 13, 14] {
            expected.extend_from_slice(&1_u32.to_be_bytes());
            expected.push(byte);
        }
        assert_eq!(
            encode(&Request::Claim {
                leg: leg(),
                signed_leg: vec![12],
                request: vec![13],
                intent: vec![14],
            })
            .unwrap(),
            expected
        );
    }

    #[test]
    fn declared_and_actual_bounds_refuse_before_nested_allocation() {
        let mut changed: LegRequest = leg();
        changed.object.canonical_bytes = vec![0; MAX_AUTHENTICATED_OBJECT_BODY_BYTES + 1];
        assert!(encode(&Request::Leg(changed)).is_err());
        let mut bytes: Vec<u8> = encode(&Request::Leg(leg())).unwrap();
        // Fixed fields before the first length: version/kind/phase + two IDs,
        // amount/recipient/nonce/gas/hash epoch.
        let offset: usize = 3 + 64 + 8 + 32 + 8 + 8 + 8;
        bytes[offset..offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(decode(&bytes).is_err());
        assert!(decode(&vec![0; MAX_REQUEST_BYTES + 1]).is_err());
    }
}
