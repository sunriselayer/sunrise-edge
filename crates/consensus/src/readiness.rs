//! DR-0178 bounded conditional-readiness statements and weighted certificates.
//! These are public assertions, not constructors for local completeness,
//! durable retention, membership activation or ordinary signing authority.

use canonical_encoding::{
    CanonicalDecodingError, CanonicalEncodingError, CanonicalStruct, decode_canonical_frame,
    decode_digest32, encode_chain_id, encode_digest32,
};
use crypto::{
    CryptoError, Ed25519OwnerAddressPolicy, Ed25519Verifier, SignatureDomain, SignatureMessageType,
    SignatureVerifier, frame_signature_message, validate_ed25519_owner_address,
};
use hashing::{HashSuiteResolver, HashingError};
use protocol_types::{
    AtomicityDomainId, ChainId, Digest32, Epoch, HashPurpose, ProtocolVersion, SignatureSchemeId,
    ValidatorId,
};
use protocol_upgrades::{HashSuiteScheduleConfig, encode_hash_suite_schedule};
use std::{collections::BTreeSet, error::Error, fmt};
use validator_set::{ValidatorSet, ValidatorSetError, decode_validator_set, encode_validator_set};

pub const MAX_READINESS_MEMBERS: usize = 256;
pub const MAX_READINESS_SET_BYTES: usize = 64 * 1024;
pub const MAX_READINESS_SUBJECT_BYTES: usize = 16 * 1024;
pub const MAX_READINESS_VOTE_BYTES: usize = 4 * 1024;
pub const MAX_READINESS_CERTIFICATE_BYTES: usize = 1024 * 1024;
const SUBJECT: u16 = 0xD040;
const PAYLOAD: u16 = 0xD041;
const VOTE: u16 = 0xD042;
const CERTIFICATE: u16 = 0xD043;

/// A failed closed readiness assertion. No failure permits fallback signing.
#[derive(Debug)]
pub enum ReadinessError {
    Invalid(&'static str),
    Encoding(CanonicalEncodingError),
    Decoding(CanonicalDecodingError),
    Hashing(HashingError),
    Crypto(CryptoError),
    ValidatorSet(ValidatorSetError),
}
impl fmt::Display for ReadinessError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => out.write_str(message),
            Self::Encoding(error) => error.fmt(out),
            Self::Decoding(error) => error.fmt(out),
            Self::Hashing(error) => error.fmt(out),
            Self::Crypto(error) => error.fmt(out),
            Self::ValidatorSet(error) => error.fmt(out),
        }
    }
}
impl Error for ReadinessError {}
macro_rules! conversion {
    ($source:ty, $variant:ident) => {
        impl From<$source> for ReadinessError {
            fn from(error: $source) -> Self {
                Self::$variant(error)
            }
        }
    };
}
conversion!(CanonicalEncodingError, Encoding);
conversion!(CanonicalDecodingError, Decoding);
conversion!(HashingError, Hashing);
conversion!(CryptoError, Crypto);
conversion!(ValidatorSetError, ValidatorSet);

fn bounded(bytes: &[u8], maximum: usize) -> Result<(), ReadinessError> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(ReadinessError::Invalid("readiness component byte bound"));
    }
    Ok(())
}

/// One nonexclusive pre-Seal assertion. Local package and physical coordinates
/// are deliberately absent. The caller must independently derive authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadinessSubject {
    pub chain_id: ChainId,
    pub protocol_version: ProtocolVersion,
    pub epoch: Epoch,
    pub genesis_digest: Digest32,
    pub domain: AtomicityDomainId,
    pub outgoing_set_digest: Digest32,
    pub cut_digest: Digest32,
    pub next_epoch: Epoch,
    pub next_set_digest: Digest32,
    pub schedule_digest: Digest32,
}

impl ReadinessSubject {
    pub fn validate(&self) -> Result<(), ReadinessError> {
        if self.chain_id.as_str().len() > 128 || self.protocol_version.get() == 0 {
            return Err(ReadinessError::Invalid("readiness chain/protocol bound"));
        }
        if self.epoch.get().checked_add(1) != Some(self.next_epoch.get()) {
            return Err(ReadinessError::Invalid("readiness epoch must be adjacent"));
        }
        Ok(())
    }
    pub fn identity(&self, resolver: &HashSuiteResolver) -> Result<Digest32, ReadinessError> {
        self.check_configuration(resolver)?;
        Ok(resolver.hash_for_purpose(
            self.epoch,
            HashPurpose::NodeEvent,
            &encode_readiness_subject(self)?,
        )?)
    }
    fn check_configuration(&self, resolver: &HashSuiteResolver) -> Result<(), ReadinessError> {
        self.validate()?;
        if &self.chain_id != resolver.chain_id()
            || self.protocol_version != resolver.protocol_version()
            || self.schedule_digest != readiness_schedule_digest(resolver, self.epoch)?
        {
            return Err(ReadinessError::Invalid(
                "readiness local configuration mismatch",
            ));
        }
        Ok(())
    }
}

/// Complete, separately trusted local schedule; genesis is not its authority.
pub fn readiness_schedule_digest(
    resolver: &HashSuiteResolver,
    epoch: Epoch,
) -> Result<Digest32, ReadinessError> {
    if !(1..=64).contains(&resolver.schedules().len()) {
        return Err(ReadinessError::Invalid("readiness schedule entry bound"));
    }
    let schedule: HashSuiteScheduleConfig =
        HashSuiteScheduleConfig::new(resolver.schedules().to_vec())
            .map_err(|_| ReadinessError::Invalid("readiness schedule is not canonical"))?;
    let bytes: Vec<u8> = encode_hash_suite_schedule(&schedule)
        .map_err(|_| ReadinessError::Invalid("readiness schedule encoding"))?;
    Ok(resolver.hash_for_purpose(epoch, HashPurpose::NodeEvent, &bytes)?)
}

/// Admissibility is stricter than historical ZIP-215 verification, unchanged
/// for old messages. Apply to all members, not just a locally available key.
pub fn validate_readiness_set(set: &ValidatorSet) -> Result<(), ReadinessError> {
    if !(1..=MAX_READINESS_MEMBERS).contains(&set.validators().len()) {
        return Err(ReadinessError::Invalid("readiness member bound"));
    }
    for member in set.validators() {
        let key: &[u8; 32] = member
            .public_key
            .as_slice()
            .try_into()
            .map_err(|_| ReadinessError::Invalid("readiness key length"))?;
        if member.signature_scheme != SignatureSchemeId::Ed25519 {
            return Err(ReadinessError::Invalid("readiness requires Ed25519"));
        }
        validate_ed25519_owner_address(key, Ed25519OwnerAddressPolicy::CanonicalPrimeOrder)
            .map_err(|_| ReadinessError::Invalid("readiness key must be canonical prime order"))?;
    }
    bounded(&encode_validator_set(set)?, MAX_READINESS_SET_BYTES)
}

pub fn encode_readiness_subject(subject: &ReadinessSubject) -> Result<Vec<u8>, ReadinessError> {
    subject.validate()?;
    let mut frame: CanonicalStruct = CanonicalStruct::new(SUBJECT, 1);
    frame.field_bytes(1, encode_chain_id(&subject.chain_id)?)?;
    frame.field_u32(2, subject.protocol_version.get())?;
    frame.field_u64(3, subject.epoch.get())?;
    frame.field_bytes(4, encode_digest32(&subject.genesis_digest)?)?;
    frame.field_bytes(5, subject.domain.as_bytes())?;
    frame.field_bytes(6, encode_digest32(&subject.outgoing_set_digest)?)?;
    frame.field_bytes(7, encode_digest32(&subject.cut_digest)?)?;
    frame.field_u64(8, subject.next_epoch.get())?;
    frame.field_bytes(9, encode_digest32(&subject.next_set_digest)?)?;
    frame.field_bytes(10, encode_digest32(&subject.schedule_digest)?)?;
    let bytes: Vec<u8> = frame.finish()?;
    bounded(&bytes, MAX_READINESS_SUBJECT_BYTES)?;
    Ok(bytes)
}

pub fn decode_readiness_subject(bytes: &[u8]) -> Result<ReadinessSubject, ReadinessError> {
    bounded(bytes, MAX_READINESS_SUBJECT_BYTES)?;
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(SUBJECT)?;
    frame.require_version(1)?;
    frame.require_only_fields(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10])?;
    let chain = decode_canonical_frame(frame.required_field(1)?)?;
    chain.require_type(0x0105)?;
    chain.require_version(1)?;
    chain.require_only_fields(&[1])?;
    let chain_text: &str = chain.required_str(1)?;
    if chain_text.len() > 128 {
        return Err(ReadinessError::Invalid("readiness chain byte bound"));
    }
    let domain_bytes: [u8; 32] = frame
        .required_field(5)?
        .try_into()
        .map_err(|_| ReadinessError::Invalid("readiness domain length"))?;
    let subject: ReadinessSubject = ReadinessSubject {
        chain_id: ChainId::new(chain_text.to_owned())
            .map_err(|_| ReadinessError::Invalid("readiness chain"))?,
        protocol_version: ProtocolVersion::new(frame.required_u32(2)?),
        epoch: Epoch::new(frame.required_u64(3)?),
        genesis_digest: decode_digest32(frame.required_field(4)?)?,
        domain: AtomicityDomainId::new(domain_bytes)
            .map_err(|_| ReadinessError::Invalid("readiness domain"))?,
        outgoing_set_digest: decode_digest32(frame.required_field(6)?)?,
        cut_digest: decode_digest32(frame.required_field(7)?)?,
        next_epoch: Epoch::new(frame.required_u64(8)?),
        next_set_digest: decode_digest32(frame.required_field(9)?)?,
        schedule_digest: decode_digest32(frame.required_field(10)?)?,
    };
    if encode_readiness_subject(&subject)? != bytes {
        return Err(ReadinessError::Invalid("noncanonical readiness subject"));
    }
    Ok(subject)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadinessVote {
    pub subject: ReadinessSubject,
    pub signer: ValidatorId,
    pub scheme: SignatureSchemeId,
    pub signature: [u8; 64],
}

pub fn encode_readiness_payload(
    subject: &ReadinessSubject,
    signer: ValidatorId,
    scheme: SignatureSchemeId,
) -> Result<Vec<u8>, ReadinessError> {
    if scheme != SignatureSchemeId::Ed25519 {
        return Err(ReadinessError::Invalid("readiness requires Ed25519"));
    }
    let mut frame: CanonicalStruct = CanonicalStruct::new(PAYLOAD, 1);
    frame.field_bytes(1, encode_readiness_subject(subject)?)?;
    frame.field_bytes(2, signer.as_bytes())?;
    frame.field_u16(3, scheme.as_u16())?;
    let bytes: Vec<u8> = frame.finish()?;
    bounded(&bytes, MAX_READINESS_VOTE_BYTES)?;
    Ok(bytes)
}

pub fn readiness_signing_frame(
    subject: &ReadinessSubject,
    signer: ValidatorId,
) -> Result<Vec<u8>, ReadinessError> {
    let domain: SignatureDomain = SignatureDomain {
        chain_id: subject.chain_id.clone(),
        protocol_version: subject.protocol_version,
        epoch: subject.epoch,
        message_type: SignatureMessageType::new("conditional-readiness-v1")?,
        signature_scheme_id: SignatureSchemeId::Ed25519,
    };
    Ok(frame_signature_message(
        &domain,
        &encode_readiness_payload(subject, signer, SignatureSchemeId::Ed25519)?,
    )?)
}

pub fn encode_readiness_vote(vote: &ReadinessVote) -> Result<Vec<u8>, ReadinessError> {
    let mut frame: CanonicalStruct = CanonicalStruct::new(VOTE, 1);
    frame.field_bytes(
        1,
        encode_readiness_payload(&vote.subject, vote.signer, vote.scheme)?,
    )?;
    frame.field_bytes(2, vote.signature)?;
    let bytes: Vec<u8> = frame.finish()?;
    bounded(&bytes, MAX_READINESS_VOTE_BYTES)?;
    Ok(bytes)
}

pub fn decode_readiness_vote(bytes: &[u8]) -> Result<ReadinessVote, ReadinessError> {
    bounded(bytes, MAX_READINESS_VOTE_BYTES)?;
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(VOTE)?;
    frame.require_version(1)?;
    frame.require_only_fields(&[1, 2])?;
    let payload = decode_canonical_frame(frame.required_field(1)?)?;
    payload.require_type(PAYLOAD)?;
    payload.require_version(1)?;
    payload.require_only_fields(&[1, 2, 3])?;
    let signer: [u8; 32] = payload
        .required_field(2)?
        .try_into()
        .map_err(|_| ReadinessError::Invalid("readiness signer length"))?;
    let vote: ReadinessVote = ReadinessVote {
        subject: decode_readiness_subject(payload.required_field(1)?)?,
        signer: ValidatorId::new(signer),
        scheme: SignatureSchemeId::try_from(payload.required_u16(3)?)
            .map_err(|_| ReadinessError::Invalid("readiness signature scheme"))?,
        signature: frame
            .required_field(2)?
            .try_into()
            .map_err(|_| ReadinessError::Invalid("readiness signature length"))?,
    };
    if encode_readiness_vote(&vote)? != bytes {
        return Err(ReadinessError::Invalid("noncanonical readiness vote"));
    }
    Ok(vote)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadinessCertificate {
    pub subject: ReadinessSubject,
    pub next_set: ValidatorSet,
    pub votes: Vec<ReadinessVote>,
}

pub fn encode_readiness_certificate(
    certificate: &ReadinessCertificate,
) -> Result<Vec<u8>, ReadinessError> {
    validate_readiness_set(&certificate.next_set)?;
    if certificate.votes.is_empty() || certificate.votes.len() > MAX_READINESS_MEMBERS {
        return Err(ReadinessError::Invalid("readiness certificate vote bound"));
    }
    let mut frame: CanonicalStruct = CanonicalStruct::new(CERTIFICATE, 1);
    frame.field_bytes(1, encode_readiness_subject(&certificate.subject)?)?;
    frame.field_bytes(2, encode_validator_set(&certificate.next_set)?)?;
    frame.field_u16(
        3,
        u16::try_from(certificate.votes.len())
            .map_err(|_| ReadinessError::Invalid("readiness certificate count"))?,
    )?;
    let mut previous: Option<ValidatorId> = None;
    for (index, vote) in certificate.votes.iter().enumerate() {
        if previous.is_some_and(|signer| signer >= vote.signer)
            || vote.subject != certificate.subject
        {
            return Err(ReadinessError::Invalid(
                "readiness certificate order/subject",
            ));
        }
        previous = Some(vote.signer);
        frame.field_bytes(
            u16::try_from(index + 4)
                .map_err(|_| ReadinessError::Invalid("readiness certificate field"))?,
            encode_readiness_vote(vote)?,
        )?;
    }
    let bytes: Vec<u8> = frame.finish()?;
    bounded(&bytes, MAX_READINESS_CERTIFICATE_BYTES)?;
    Ok(bytes)
}

pub fn decode_readiness_certificate(bytes: &[u8]) -> Result<ReadinessCertificate, ReadinessError> {
    bounded(bytes, MAX_READINESS_CERTIFICATE_BYTES)?;
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(CERTIFICATE)?;
    frame.require_version(1)?;
    let count: usize = usize::from(frame.required_u16(3)?);
    if !(1..=MAX_READINESS_MEMBERS).contains(&count) {
        return Err(ReadinessError::Invalid("readiness certificate vote bound"));
    }
    let fields: Vec<u16> = (1..=count + 3)
        .map(|value: usize| {
            u16::try_from(value).map_err(|_| ReadinessError::Invalid("readiness certificate field"))
        })
        .collect::<Result<Vec<u16>, ReadinessError>>()?;
    frame.require_only_fields(&fields)?;
    let next_bytes: &[u8] = frame.required_field(2)?;
    bounded(next_bytes, MAX_READINESS_SET_BYTES)?;
    let next_set: ValidatorSet = decode_validator_set(next_bytes)?;
    validate_readiness_set(&next_set)?;
    let mut votes: Vec<ReadinessVote> = Vec::with_capacity(count);
    for index in 0..count {
        votes.push(decode_readiness_vote(
            frame.required_field(fields[index + 3])?,
        )?);
    }
    let certificate: ReadinessCertificate = ReadinessCertificate {
        subject: decode_readiness_subject(frame.required_field(1)?)?,
        next_set,
        votes,
    };
    if encode_readiness_certificate(&certificate)? != bytes {
        return Err(ReadinessError::Invalid(
            "noncanonical readiness certificate",
        ));
    }
    Ok(certificate)
}

/// Pure certificate owner bound to the caller's independent expected subject
/// and local configuration. It cannot construct business-readiness authority.
pub struct ReadinessCertifier<'a> {
    resolver: &'a HashSuiteResolver,
    subject: &'a ReadinessSubject,
    next_set: &'a ValidatorSet,
}
impl<'a> ReadinessCertifier<'a> {
    pub fn new(
        resolver: &'a HashSuiteResolver,
        subject: &'a ReadinessSubject,
        next_set: &'a ValidatorSet,
    ) -> Result<Self, ReadinessError> {
        subject.check_configuration(resolver)?;
        validate_readiness_set(next_set)?;
        if next_set.epoch() != subject.next_epoch
            || next_set.digest(resolver)? != subject.next_set_digest
        {
            return Err(ReadinessError::Invalid(
                "readiness successor identity mismatch",
            ));
        }
        Ok(Self {
            resolver,
            subject,
            next_set,
        })
    }
    pub fn verify_vote(&self, vote: &ReadinessVote) -> Result<(), ReadinessError> {
        if &vote.subject != self.subject || vote.scheme != SignatureSchemeId::Ed25519 {
            return Err(ReadinessError::Invalid("readiness vote identity mismatch"));
        }
        let member = self
            .next_set
            .get(vote.signer)
            .ok_or(ReadinessError::Invalid("readiness signer not registered"))?;
        let verifier: Ed25519Verifier =
            Ed25519Verifier::from_verifying_key_bytes(&member.public_key)?;
        if !verifier.verify_framed(
            &readiness_signing_frame(self.subject, vote.signer)?,
            &vote.signature,
        )? {
            return Err(ReadinessError::Invalid("readiness invalid signature"));
        }
        Ok(())
    }
    pub fn form_certificate(
        &self,
        votes: &[ReadinessVote],
    ) -> Result<ReadinessCertificate, ReadinessError> {
        if !(1..=MAX_READINESS_MEMBERS).contains(&votes.len()) {
            return Err(ReadinessError::Invalid("readiness certificate vote bound"));
        }
        let mut certificate: ReadinessCertificate = ReadinessCertificate {
            subject: self.subject.clone(),
            next_set: self.next_set.clone(),
            votes: votes.to_vec(),
        };
        certificate
            .votes
            .sort_by_key(|vote: &ReadinessVote| vote.signer);
        self.verify_certificate(&certificate)?;
        Ok(certificate)
    }
    pub fn verify_certificate(
        &self,
        certificate: &ReadinessCertificate,
    ) -> Result<(), ReadinessError> {
        if &certificate.subject != self.subject || &certificate.next_set != self.next_set {
            return Err(ReadinessError::Invalid(
                "readiness certificate local identity mismatch",
            ));
        }
        bounded(
            &encode_readiness_certificate(certificate)?,
            MAX_READINESS_CERTIFICATE_BYTES,
        )?;
        let mut signers: BTreeSet<ValidatorId> = BTreeSet::new();
        let mut power: u64 = 0;
        for vote in &certificate.votes {
            self.verify_vote(vote)?;
            if !signers.insert(vote.signer) {
                return Err(ReadinessError::Invalid("readiness duplicate signer"));
            }
            let member = self
                .next_set
                .get(vote.signer)
                .ok_or(ReadinessError::Invalid("readiness signer not registered"))?;
            power = power
                .checked_add(member.voting_power)
                .ok_or(ReadinessError::Invalid("readiness voting-power overflow"))?;
        }
        if power < self.next_set.quorum_threshold() {
            return Err(ReadinessError::Invalid(
                "readiness insufficient successor quorum",
            ));
        }
        // The resolver is retained by this owner; do not accept an asserted
        // schedule even if a future caller changes the expected subject.
        self.subject.check_configuration(self.resolver)
    }
}

#[cfg(test)]
mod tests;
