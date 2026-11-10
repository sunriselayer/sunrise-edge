//! Exact, bounded original-bond local observation bytes. Decoded fields are
//! untrusted syntax-only locators, never a chain proof or signing authority.

use core::fmt;
use node_core::{MAX_AUTHENTICATED_OBJECT_BODY_BYTES, MAX_CHAIN_ID_BYTES};
use objects::{ObjectRef, decode_object_ref, encode_object_ref};
use protocol_types::{
    AtomicityDomainId, ChainId, Digest32, Epoch, HashAlgorithmId, ProtocolVersion, ValidatorId,
};
use runtime::{
    WriterFenceGeneration,
    portable::{MAX_PORTABLE_SNAPSHOT_NAMESPACE_BYTES, PortableSnapshotToken},
};

/// Maximum local request body, excluding the transport's four-byte length.
pub const MAX_REQUEST_BYTES: usize = MAX_AUTHENTICATED_OBJECT_BODY_BYTES + 4096;
/// Maximum local success response, excluding the transport's four-byte length.
pub const MAX_RESPONSE_BYTES: usize = 1024;
const REQUEST_MAGIC: &[u8; 8] = b"SRBREAD1";
const RESPONSE_MAGIC: &[u8; 8] = b"SRBOBS01";
const MAX_REFERENCE_BYTES: usize = 1024;

/// Refusal of malformed or oversized local observation bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OriginalBondCurrentnessWireError {
    /// The complete frame exceeds its closed bound.
    TooLarge,
    /// A field, canonical reference, or frame ending is invalid.
    Malformed(&'static str),
}

impl fmt::Display for OriginalBondCurrentnessWireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => f.write_str("original bond observation frame too large"),
            Self::Malformed(field) => write!(f, "original bond observation malformed: {field}"),
        }
    }
}

impl std::error::Error for OriginalBondCurrentnessWireError {}

type WireResult<T> = Result<T, OriginalBondCurrentnessWireError>;

fn malformed(field: &'static str) -> OriginalBondCurrentnessWireError {
    OriginalBondCurrentnessWireError::Malformed(field)
}

/// Syntax-only response from a designated local node. The caller must check
/// the authenticated server UID and all configured chain/host/genesis pins,
/// then requery at each separate approval or signing decision point.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginalBondLocalObservationFrame {
    /// Claimed serving validator, not the bond registration's new validator.
    pub validator: ValidatorId,
    /// Claimed chain identity.
    pub chain_id: ChainId,
    /// Claimed protocol version.
    pub protocol_version: ProtocolVersion,
    /// Full local namespace/domain/fence/mutation locator.
    pub token: PortableSnapshotToken,
    /// Claimed committed epoch.
    pub epoch: Epoch,
    /// Claimed committed validator-set digest.
    pub validator_set_digest: Digest32,
    /// Claimed original genesis digest.
    pub genesis_digest: Digest32,
    /// Claimed ordered-history anchor.
    pub anchor: Digest32,
    /// Claimed locally applied ordered height.
    pub through_height: u64,
    /// Claimed locally applied ordered view.
    pub through_view: u64,
    /// Claimed locally applied ordered digest.
    pub through_digest: Digest32,
    /// Claimed exact current Coin reference; the server checked its body.
    pub coin: ObjectRef,
}

/// Encodes the existing `SRBREAD1` request: magic, big-endian u16 canonical
/// reference length, reference, and the exact reviewed Coin body.
pub fn encode_request(reference: &ObjectRef, coin_body: &[u8]) -> WireResult<Vec<u8>> {
    if coin_body.is_empty() || coin_body.len() > MAX_AUTHENTICATED_OBJECT_BODY_BYTES {
        return Err(malformed("coin body length"));
    }
    let reference = encode_object_ref(reference).map_err(|_| malformed("object reference"))?;
    if reference.is_empty() || reference.len() > MAX_REFERENCE_BYTES {
        return Err(malformed("object reference length"));
    }
    let mut bytes = Vec::with_capacity(10 + reference.len() + coin_body.len());
    bytes.extend_from_slice(REQUEST_MAGIC);
    bytes.extend_from_slice(
        &u16::try_from(reference.len())
            .map_err(|_| malformed("object reference length"))?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(&reference);
    bytes.extend_from_slice(coin_body);
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err(OriginalBondCurrentnessWireError::TooLarge);
    }
    Ok(bytes)
}

/// Decodes one bounded request without treating the supplied Coin as state.
/// The local host must independently verify the canonical Coin and storage.
pub fn decode_request(bytes: &[u8]) -> WireResult<(ObjectRef, &[u8])> {
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err(OriginalBondCurrentnessWireError::TooLarge);
    }
    if bytes.len() < 11 || &bytes[..8] != REQUEST_MAGIC {
        return Err(malformed("request magic or length"));
    }
    let length = usize::from(u16::from_be_bytes([bytes[8], bytes[9]]));
    let end = 10usize
        .checked_add(length)
        .ok_or_else(|| malformed("reference length"))?;
    if length == 0 || length > MAX_REFERENCE_BYTES || end >= bytes.len() {
        return Err(malformed("reference or body length"));
    }
    let reference =
        decode_object_ref(&bytes[10..end]).map_err(|_| malformed("object reference"))?;
    if encode_object_ref(&reference).map_err(|_| malformed("object reference"))? != bytes[10..end] {
        return Err(malformed("noncanonical object reference"));
    }
    let body = &bytes[end..];
    if body.len() > MAX_AUTHENTICATED_OBJECT_BODY_BYTES {
        return Err(OriginalBondCurrentnessWireError::TooLarge);
    }
    Ok((reference, body))
}

fn put_digest(bytes: &mut Vec<u8>, value: Digest32) {
    bytes.extend_from_slice(&value.algorithm().as_u16().to_be_bytes());
    bytes.extend_from_slice(&value.bytes());
}

/// Encodes exactly the existing success frame. Its literal zero proof byte
/// means `chain_state_proof=false`; there is no success-shaped refusal frame.
pub fn encode_response(value: &OriginalBondLocalObservationFrame) -> WireResult<Vec<u8>> {
    let chain = value.chain_id.as_str().as_bytes();
    let namespace = value.token.namespace();
    let coin = encode_object_ref(&value.coin).map_err(|_| malformed("object reference"))?;
    if chain.is_empty()
        || chain.len() > MAX_CHAIN_ID_BYTES
        || namespace.is_empty()
        || namespace.len() > MAX_PORTABLE_SNAPSHOT_NAMESPACE_BYTES
        || coin.is_empty()
        || coin.len() > MAX_REFERENCE_BYTES
    {
        return Err(malformed("response field length"));
    }
    let mut bytes = Vec::with_capacity(MAX_RESPONSE_BYTES);
    bytes.extend_from_slice(RESPONSE_MAGIC);
    bytes.push(0);
    bytes.extend_from_slice(value.validator.as_bytes());
    bytes.extend_from_slice(
        &u16::try_from(chain.len())
            .map_err(|_| malformed("chain length"))?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(chain);
    bytes.extend_from_slice(&value.protocol_version.get().to_be_bytes());
    bytes.extend_from_slice(value.token.domain().as_bytes());
    bytes.extend_from_slice(
        &u16::try_from(namespace.len())
            .map_err(|_| malformed("namespace length"))?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(namespace);
    bytes.extend_from_slice(&value.token.writer_fence().get().to_be_bytes());
    bytes.extend_from_slice(&value.token.mutation_sequence().to_be_bytes());
    bytes.extend_from_slice(&value.epoch.get().to_be_bytes());
    put_digest(&mut bytes, value.validator_set_digest);
    put_digest(&mut bytes, value.genesis_digest);
    put_digest(&mut bytes, value.anchor);
    bytes.extend_from_slice(&value.through_height.to_be_bytes());
    bytes.extend_from_slice(&value.through_view.to_be_bytes());
    put_digest(&mut bytes, value.through_digest);
    bytes.extend_from_slice(
        &u16::try_from(coin.len())
            .map_err(|_| malformed("object reference length"))?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(&coin);
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(OriginalBondCurrentnessWireError::TooLarge);
    }
    Ok(bytes)
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> WireResult<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| malformed("length"))?;
        let field = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| malformed("truncated"))?;
        self.offset = end;
        Ok(field)
    }

    fn u16(&mut self) -> WireResult<u16> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().map_err(|_| malformed("u16"))?,
        ))
    }

    fn u32(&mut self) -> WireResult<u32> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().map_err(|_| malformed("u32"))?,
        ))
    }

    fn u64(&mut self) -> WireResult<u64> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().map_err(|_| malformed("u64"))?,
        ))
    }

    fn digest(&mut self) -> WireResult<Digest32> {
        let algorithm =
            HashAlgorithmId::try_from(self.u16()?).map_err(|_| malformed("digest algorithm"))?;
        let digest: [u8; 32] = self.take(32)?.try_into().map_err(|_| malformed("digest"))?;
        Ok(Digest32::new(algorithm, digest))
    }

    fn length_bytes(&mut self, maximum: usize) -> WireResult<&'a [u8]> {
        let length = usize::from(self.u16()?);
        if length == 0 || length > maximum {
            return Err(malformed("length-prefixed field"));
        }
        self.take(length)
    }
}

/// Decodes one complete success frame, rejecting unknown digest algorithms,
/// unsupported proof bytes, noncanonical references and trailing data.
/// All returned values remain untrusted until the caller checks its pins.
pub fn decode_response(bytes: &[u8]) -> WireResult<OriginalBondLocalObservationFrame> {
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(OriginalBondCurrentnessWireError::TooLarge);
    }
    let mut r = Reader { bytes, offset: 0 };
    if r.take(8)? != RESPONSE_MAGIC || r.take(1)? != [0] {
        return Err(malformed("response magic or proof byte"));
    }
    let validator = ValidatorId::new(r.take(32)?.try_into().map_err(|_| malformed("validator"))?);
    let chain = std::str::from_utf8(r.length_bytes(MAX_CHAIN_ID_BYTES)?)
        .map_err(|_| malformed("chain UTF-8"))?;
    let chain_id = ChainId::new(chain).map_err(|_| malformed("chain"))?;
    let protocol_version = ProtocolVersion::new(r.u32()?);
    let domain = AtomicityDomainId::new(r.take(32)?.try_into().map_err(|_| malformed("domain"))?)
        .map_err(|_| malformed("domain"))?;
    let namespace = r
        .length_bytes(MAX_PORTABLE_SNAPSHOT_NAMESPACE_BYTES)?
        .to_vec();
    let fence = WriterFenceGeneration::new(r.u64()?).ok_or_else(|| malformed("writer fence"))?;
    let mutation = r.u64()?;
    let token = PortableSnapshotToken::new(namespace, domain, fence, mutation)
        .map_err(|_| malformed("portable token"))?;
    let epoch = Epoch::new(r.u64()?);
    let validator_set_digest = r.digest()?;
    let genesis_digest = r.digest()?;
    let anchor = r.digest()?;
    let through_height = r.u64()?;
    let through_view = r.u64()?;
    let through_digest = r.digest()?;
    let coin_bytes = r.length_bytes(MAX_REFERENCE_BYTES)?;
    let coin = decode_object_ref(coin_bytes).map_err(|_| malformed("object reference"))?;
    if encode_object_ref(&coin).map_err(|_| malformed("object reference"))? != coin_bytes
        || r.offset != bytes.len()
    {
        return Err(malformed("noncanonical reference or trailing bytes"));
    }
    let result = OriginalBondLocalObservationFrame {
        validator,
        chain_id,
        protocol_version,
        token,
        epoch,
        validator_set_digest,
        genesis_digest,
        anchor,
        through_height,
        through_view,
        through_digest,
        coin,
    };
    if encode_response(&result)? != bytes {
        return Err(malformed("noncanonical response"));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use objects::ObjectId;

    const REQUEST_VECTOR: &str = concat!(
        "5352425245414431008c534e5245044001000300010030000000534e5245014001000100010020000000",
        "1111111111111111111111111111111111111111111111111111111111111111",
        "0200080000000700000000000000030038000000534e52450301010002000100020000000100",
        "0200200000002222222222222222222222222222222222222222222222222222222222222222",
        "636f696e",
    );
    const RESPONSE_VECTOR: &str = concat!(
        "5352424f425330310033333333333333333333333333333333333333333333333333333333333333",
        "3300016e000000014444444444444444444444444444444444444444444444444444444444444444",
        "00056c6f63616c0000000000000009000000000000000a0000000000000000000155555555555555",
        "55555555555555555555555555555555555555555555555555000166666666666666666666666666",
        "66666666666666666666666666666666666666000177777777777777777777777777777777777777",
        "77777777777777777777777777000000000000000000000000000000000001777777777777777777",
        "7777777777777777777777777777777777777777777777008c534e52450440010003000100300000",
        "00534e52450140010001000100200000001111111111111111111111111111111111111111111111",
        "1111111111111111110200080000000700000000000000030038000000534e524503010100020001",
        "00020000000100020020000000222222222222222222222222222222222222222222222222222222",
        "2222222222",
    );

    fn hex(input: &str) -> Vec<u8> {
        input
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    fn reference() -> ObjectRef {
        ObjectRef {
            id: ObjectId::new([0x11; 32]),
            version: 7,
            digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x22; 32]),
        }
    }

    fn observation() -> OriginalBondLocalObservationFrame {
        OriginalBondLocalObservationFrame {
            validator: ValidatorId::new([0x33; 32]),
            chain_id: ChainId::new("n").unwrap(),
            protocol_version: ProtocolVersion::new(1),
            token: PortableSnapshotToken::new(
                b"local".to_vec(),
                AtomicityDomainId::new([0x44; 32]).unwrap(),
                WriterFenceGeneration::new(9).unwrap(),
                10,
            )
            .unwrap(),
            epoch: Epoch::new(0),
            validator_set_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x55; 32]),
            genesis_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x66; 32]),
            anchor: Digest32::new(HashAlgorithmId::Sha2_256, [0x77; 32]),
            through_height: 0,
            through_view: 0,
            through_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x77; 32]),
            coin: reference(),
        }
    }

    #[test]
    fn frozen_local_request_and_success_response() {
        let request = hex(REQUEST_VECTOR);
        assert_eq!(encode_request(&reference(), b"coin").unwrap(), request);
        assert_eq!(
            decode_request(&request).unwrap(),
            (reference(), &b"coin"[..])
        );
        let response = hex(RESPONSE_VECTOR);
        assert_eq!(encode_response(&observation()).unwrap(), response);
        assert_eq!(decode_response(&response).unwrap(), observation());
    }

    #[test]
    fn local_request_refuses_unknown_magic_lengths_and_noncanonical_reference() {
        let valid = hex(REQUEST_VECTOR);
        let mut changed = valid.clone();
        changed[7] = b'2';
        assert!(decode_request(&changed).is_err());
        changed = valid.clone();
        changed[8..10].copy_from_slice(&0u16.to_be_bytes());
        assert!(decode_request(&changed).is_err());
        changed = valid.clone();
        changed[8..10].copy_from_slice(&1025u16.to_be_bytes());
        assert!(decode_request(&changed).is_err());
        changed = valid.clone();
        changed.truncate(changed.len() - 4); // no Coin body
        assert!(decode_request(&changed).is_err());
        changed = valid.clone();
        changed[10] = b'X'; // canonical ObjectRef magic
        assert!(decode_request(&changed).is_err());
        assert!(decode_request(&vec![0; MAX_REQUEST_BYTES + 1]).is_err());
        assert!(
            encode_request(
                &reference(),
                &vec![0; MAX_AUTHENTICATED_OBJECT_BODY_BYTES + 1]
            )
            .is_err()
        );
    }

    #[test]
    fn local_response_refuses_proof_algorithms_lengths_trailing_and_oversize() {
        let valid = hex(RESPONSE_VECTOR);
        let mut changed = valid.clone();
        changed[7] = b'2';
        assert!(decode_response(&changed).is_err());
        changed = valid.clone();
        changed[8] = 1; // no chain proof is accepted on this route
        assert!(decode_response(&changed).is_err());
        changed = valid.clone();
        let algorithm = changed
            .windows(4)
            .position(|bytes| bytes == [0, 1, 0x55, 0x55])
            .unwrap();
        changed[algorithm] = 0;
        changed[algorithm + 1] = 0;
        assert!(decode_response(&changed).is_err());
        changed = valid.clone();
        changed[41..43].copy_from_slice(&1025u16.to_be_bytes()); // chain length
        assert!(decode_response(&changed).is_err());
        changed = valid.clone();
        changed.pop();
        assert!(decode_response(&changed).is_err());
        changed = valid.clone();
        changed.push(0);
        assert!(decode_response(&changed).is_err());
        assert!(decode_response(&vec![0; MAX_RESPONSE_BYTES + 1]).is_err());
    }
}
