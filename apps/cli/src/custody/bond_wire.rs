//! Closed adapter-local original bond IPC. No message carries a signable
//! frame, key path, trust root, peer UID, or caller-selected operation kind.
//! Each key worker rebuilds its own exact frame from these bounded preimages.

use sunrise_edge_client::{
    MAX_AUTHENTICATED_OBJECT_BODY_BYTES, RequestId,
    bond_registration::{
        BondResourceId, MAX_BOND_REGISTRATION_ROW_BYTES, MAX_LOCAL_EXECUTION_INTENT_BYTES,
    },
};

use super::{
    bond_config::MAX_CONFIG_BYTES,
    bond_inner::BondInnerRequest,
    positive_fee_split_wire::{Reader, put_bytes},
    wire::CustodyWireError,
};

const VERSION: u8 = 1;
const INNER_KIND: u8 = 1;
const OUTER_KIND: u8 = 2;
const BROKER_APPROVE: u8 = 1;
const BROKER_CHECK: u8 = 2;
const BROKER_REVOKE: u8 = 3;
const BROKER_SIGN: u8 = 4;
const REPLY_APPROVED: u8 = 1;
const REPLY_REFUSED: u8 = 2;
const REPLY_SIGNED: u8 = 3;
const INNER_FIXED_BYTES: usize = 1 + 1 + 32 + 2 + 32 + 8 + 32 + 8 + 4;
pub(super) const MAX_REQUEST_BYTES: usize = INNER_FIXED_BYTES
    + MAX_AUTHENTICATED_OBJECT_BODY_BYTES
    + 4
    + MAX_LOCAL_EXECUTION_INTENT_BYTES
    + 4
    + MAX_BOND_REGISTRATION_ROW_BYTES
    + 32;
pub(super) const MAX_BROKER_MESSAGE_BYTES: usize =
    MAX_REQUEST_BYTES + 2 + 4 + 8 + 4 + MAX_CONFIG_BYTES;
pub(super) const MAX_REPLY_BYTES: usize = 2 + 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum BondRequest {
    Inner(BondInnerRequest),
    Outer {
        inner: BondInnerRequest,
        signed_leg: Vec<u8>,
        row: Vec<u8>,
        outer_request_id: RequestId,
    },
}

impl BondRequest {
    pub(super) fn inner(&self) -> &BondInnerRequest {
        match self {
            Self::Inner(inner) | Self::Outer { inner, .. } => inner,
        }
    }

    pub(super) const fn phase(&self) -> BondPhase {
        match self {
            Self::Inner(_) => BondPhase::Inner,
            Self::Outer { .. } => BondPhase::Outer,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum BondPhase {
    Inner = 1,
    Outer = 2,
}

fn decode_phase(byte: u8) -> Result<BondPhase, CustodyWireError> {
    match byte {
        1 => Ok(BondPhase::Inner),
        2 => Ok(BondPhase::Outer),
        _ => Err(CustodyWireError::UnsupportedMessageType(byte)),
    }
}

fn encode_inner(out: &mut Vec<u8>, inner: &BondInnerRequest) -> Result<(), CustodyWireError> {
    out.extend_from_slice(&inner.validator_key);
    out.extend_from_slice(&inner.resource.domain().to_be_bytes());
    out.extend_from_slice(inner.resource.value());
    out.extend_from_slice(&inner.nonce.to_be_bytes());
    out.extend_from_slice(inner.request_id.as_bytes());
    out.extend_from_slice(&inner.gas_limit.to_be_bytes());
    put_bytes(
        out,
        &inner.source_coin_bytes,
        MAX_AUTHENTICATED_OBJECT_BODY_BYTES,
    )?;
    Ok(())
}

fn decode_inner(r: &mut Reader<'_>) -> Result<BondInnerRequest, CustodyWireError> {
    let validator_key = r.array()?;
    let resource_domain = u16::from_be_bytes(r.array()?);
    let resource_id = r.array()?;
    let resource = BondResourceId::new(resource_domain, resource_id)
        .map_err(|_| CustodyWireError::Truncated)?;
    let nonce = r.u64()?;
    let request_id = RequestId::new(r.array()?).map_err(CustodyWireError::RequestId)?;
    let gas_limit = r.u64()?;
    let source_coin_bytes = r.bytes(MAX_AUTHENTICATED_OBJECT_BODY_BYTES)?;
    Ok(BondInnerRequest {
        source_coin_bytes,
        validator_key,
        resource,
        nonce,
        request_id,
        gas_limit,
    })
}

pub(super) fn encode_request(request: &BondRequest) -> Result<Vec<u8>, CustodyWireError> {
    let kind = match request {
        BondRequest::Inner(_) => INNER_KIND,
        BondRequest::Outer { .. } => OUTER_KIND,
    };
    let mut out = vec![VERSION, kind];
    encode_inner(&mut out, request.inner())?;
    if let BondRequest::Outer {
        signed_leg,
        row,
        outer_request_id,
        ..
    } = request
    {
        put_bytes(&mut out, signed_leg, MAX_LOCAL_EXECUTION_INTENT_BYTES)?;
        put_bytes(&mut out, row, MAX_BOND_REGISTRATION_ROW_BYTES)?;
        out.extend_from_slice(outer_request_id.as_bytes());
    }
    if out.len() > MAX_REQUEST_BYTES {
        return Err(CustodyWireError::FrameTooLarge {
            actual: out.len(),
            maximum: MAX_REQUEST_BYTES,
        });
    }
    Ok(out)
}

pub(super) fn decode_request(bytes: &[u8]) -> Result<BondRequest, CustodyWireError> {
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err(CustodyWireError::FrameTooLarge {
            actual: bytes.len(),
            maximum: MAX_REQUEST_BYTES,
        });
    }
    let mut r = Reader::new(bytes);
    if r.array::<1>()?[0] != VERSION {
        return Err(CustodyWireError::UnsupportedVersion(bytes[0]));
    }
    let kind = r.array::<1>()?[0];
    let inner = decode_inner(&mut r)?;
    let request = match kind {
        INNER_KIND => BondRequest::Inner(inner),
        OUTER_KIND => BondRequest::Outer {
            inner,
            signed_leg: r.bytes(MAX_LOCAL_EXECUTION_INTENT_BYTES)?,
            row: r.bytes(MAX_BOND_REGISTRATION_ROW_BYTES)?,
            outer_request_id: RequestId::new(r.array()?).map_err(CustodyWireError::RequestId)?,
        },
        _ => return Err(CustodyWireError::UnsupportedMessageType(kind)),
    };
    r.finish()?;
    Ok(request)
}

/// The broker receives only exact operation preimages or a phase-scoped
/// revocation ID. The authenticated Unix peer UID supplies the principal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum BrokerMessage {
    Approve {
        request: BondRequest,
        not_after: u64,
        config: Vec<u8>,
    },
    Check {
        request: BondRequest,
        config: Vec<u8>,
    },
    Sign {
        request: BondRequest,
        config: Vec<u8>,
    },
    Revoke {
        phase: BondPhase,
        request_id: RequestId,
    },
}

pub(super) fn encode_broker_message(message: &BrokerMessage) -> Result<Vec<u8>, CustodyWireError> {
    let mut out = vec![VERSION];
    match message {
        BrokerMessage::Approve {
            request,
            not_after,
            config,
        } => {
            out.push(BROKER_APPROVE);
            put_bytes(&mut out, &encode_request(request)?, MAX_REQUEST_BYTES)?;
            out.extend_from_slice(&not_after.to_be_bytes());
            put_bytes(&mut out, config, MAX_CONFIG_BYTES)?;
        }
        BrokerMessage::Check { request, config } => {
            out.push(BROKER_CHECK);
            put_bytes(&mut out, &encode_request(request)?, MAX_REQUEST_BYTES)?;
            put_bytes(&mut out, config, MAX_CONFIG_BYTES)?;
        }
        BrokerMessage::Sign { request, config } => {
            out.push(BROKER_SIGN);
            put_bytes(&mut out, &encode_request(request)?, MAX_REQUEST_BYTES)?;
            put_bytes(&mut out, config, MAX_CONFIG_BYTES)?;
        }
        BrokerMessage::Revoke { phase, request_id } => {
            out.push(BROKER_REVOKE);
            out.push(*phase as u8);
            out.extend_from_slice(request_id.as_bytes());
        }
    }
    if out.len() > MAX_BROKER_MESSAGE_BYTES {
        return Err(CustodyWireError::FrameTooLarge {
            actual: out.len(),
            maximum: MAX_BROKER_MESSAGE_BYTES,
        });
    }
    Ok(out)
}

pub(super) fn decode_broker_message(bytes: &[u8]) -> Result<BrokerMessage, CustodyWireError> {
    if bytes.len() > MAX_BROKER_MESSAGE_BYTES {
        return Err(CustodyWireError::FrameTooLarge {
            actual: bytes.len(),
            maximum: MAX_BROKER_MESSAGE_BYTES,
        });
    }
    let mut r = Reader::new(bytes);
    let version = r.array::<1>()?[0];
    if version != VERSION {
        return Err(CustodyWireError::UnsupportedVersion(version));
    }
    let kind = r.array::<1>()?[0];
    let message = match kind {
        BROKER_APPROVE => BrokerMessage::Approve {
            request: decode_request(&r.bytes(MAX_REQUEST_BYTES)?)?,
            not_after: r.u64()?,
            config: r.bytes(MAX_CONFIG_BYTES)?,
        },
        BROKER_CHECK => BrokerMessage::Check {
            request: decode_request(&r.bytes(MAX_REQUEST_BYTES)?)?,
            config: r.bytes(MAX_CONFIG_BYTES)?,
        },
        BROKER_SIGN => BrokerMessage::Sign {
            request: decode_request(&r.bytes(MAX_REQUEST_BYTES)?)?,
            config: r.bytes(MAX_CONFIG_BYTES)?,
        },
        BROKER_REVOKE => BrokerMessage::Revoke {
            phase: decode_phase(r.array::<1>()?[0])?,
            request_id: RequestId::new(r.array()?).map_err(CustodyWireError::RequestId)?,
        },
        _ => return Err(CustodyWireError::UnsupportedMessageType(kind)),
    };
    r.finish()?;
    Ok(message)
}

/// The broker returns a closed decision; a key worker may return a verified
/// Ed25519 signature. No error text or reviewed content is echoed here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Reply {
    Approved,
    Refused,
    Signed([u8; 64]),
}

pub(super) fn encode_reply(reply: &Reply) -> Vec<u8> {
    match reply {
        Reply::Approved => vec![VERSION, REPLY_APPROVED],
        Reply::Refused => vec![VERSION, REPLY_REFUSED],
        Reply::Signed(signature) => {
            let mut out = vec![VERSION, REPLY_SIGNED];
            out.extend_from_slice(signature);
            out
        }
    }
}

pub(super) fn decode_reply(bytes: &[u8]) -> Result<Reply, CustodyWireError> {
    if bytes.len() > MAX_REPLY_BYTES {
        return Err(CustodyWireError::FrameTooLarge {
            actual: bytes.len(),
            maximum: MAX_REPLY_BYTES,
        });
    }
    let mut r = Reader::new(bytes);
    let version = r.array::<1>()?[0];
    if version != VERSION {
        return Err(CustodyWireError::UnsupportedVersion(version));
    }
    let kind = r.array::<1>()?[0];
    let reply = match kind {
        REPLY_APPROVED => Reply::Approved,
        REPLY_REFUSED => Reply::Refused,
        REPLY_SIGNED => Reply::Signed(r.array()?),
        _ => return Err(CustodyWireError::UnsupportedStatus(kind)),
    };
    r.finish()?;
    Ok(reply)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inner() -> BondInnerRequest {
        BondInnerRequest {
            source_coin_bytes: vec![9, 8, 7],
            validator_key: [3; 32],
            resource: BondResourceId::new(1, [4; 32]).unwrap(),
            nonce: 2,
            request_id: RequestId::new([5; 32]).unwrap(),
            gas_limit: 500_000,
        }
    }

    #[test]
    fn strict_roundtrips_and_no_cross_family_decode() {
        let inner_request = BondRequest::Inner(inner());
        let outer = BondRequest::Outer {
            inner: inner().clone(),
            signed_leg: vec![1, 2],
            row: vec![3, 4],
            outer_request_id: RequestId::new([6; 32]).unwrap(),
        };
        for request in [inner_request, outer] {
            let encoded = encode_request(&request).unwrap();
            assert_eq!(decode_request(&encoded).unwrap(), request);
            for end in 0..encoded.len() {
                assert!(decode_request(&encoded[..end]).is_err());
            }
            let mut changed = encoded.clone();
            changed.push(0);
            assert!(decode_request(&changed).is_err());
            changed = encoded.clone();
            changed[0] = 9;
            assert!(decode_request(&changed).is_err());
            changed = encoded;
            changed[1] = 9;
            assert!(decode_request(&changed).is_err());
        }
    }

    #[test]
    fn broker_messages_and_replies_are_closed() {
        let request = BondRequest::Inner(inner());
        for message in [
            BrokerMessage::Approve {
                request: request.clone(),
                not_after: 100,
                config: vec![1, 2, 3],
            },
            BrokerMessage::Check {
                request,
                config: vec![1, 2, 3],
            },
            BrokerMessage::Sign {
                request: BondRequest::Inner(inner()),
                config: vec![1, 2, 3],
            },
            BrokerMessage::Revoke {
                phase: BondPhase::Inner,
                request_id: RequestId::new([5; 32]).unwrap(),
            },
        ] {
            let bytes = encode_broker_message(&message).unwrap();
            assert_eq!(decode_broker_message(&bytes).unwrap(), message);
            let mut trailing = bytes;
            trailing.push(0);
            assert!(decode_broker_message(&trailing).is_err());
        }
        assert!(
            encode_broker_message(&BrokerMessage::Check {
                request: BondRequest::Inner(inner()),
                config: vec![0; MAX_CONFIG_BYTES + 1],
            })
            .is_err()
        );
        for reply in [Reply::Approved, Reply::Refused, Reply::Signed([7; 64])] {
            let bytes = encode_reply(&reply);
            assert_eq!(decode_reply(&bytes).unwrap(), reply);
            let mut trailing = bytes;
            trailing.push(0);
            assert!(decode_reply(&trailing).is_err());
        }
    }
}
