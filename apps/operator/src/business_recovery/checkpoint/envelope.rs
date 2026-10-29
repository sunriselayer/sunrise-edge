//! Closed local v2 framing; v1 saved-business framing remains byte-identical.
use super::*;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};

pub(super) const NAMES: [&str; 2] = ["state.sqlite", "blobs.sqlite"];
pub(super) const MANIFEST: &str = "checkpoint-manifest-v2.bin";
pub(super) const COMPLETE: &str = "checkpoint-complete-v2.bin";
#[derive(Clone, Debug)]
pub(super) struct Manifest {
    pub(super) point: LocalStoreCheckpoint,
    pub(super) bodies: [(u64, [u8; 32]); 2],
    payload: Vec<u8>,
    pub(super) plaintext: u64,
}
impl Manifest {
    pub(super) fn new(
        point: LocalStoreCheckpoint,
        bodies: [(u64, [u8; 32]); 2],
        limits: &RecoveryLimits,
    ) -> Result<Self, RecoveryError> {
        let chain: &[u8] = point.namespace.chain_id().as_str().as_bytes();
        if chain.is_empty() || chain.len() > 128 {
            return Err(RecoveryError::Inventory);
        }
        let mut payload: Vec<u8> = Vec::with_capacity(234 + chain.len());
        payload.extend_from_slice(&(chain.len() as u16).to_be_bytes());
        payload.extend_from_slice(chain);
        payload.extend_from_slice(point.namespace.validator_id().as_bytes());
        payload.extend_from_slice(point.namespace.domain().as_bytes());
        payload.extend_from_slice(&point.source_instance_id);
        payload.extend_from_slice(&point.checkpoint.sequence.to_be_bytes());
        payload.extend_from_slice(&point.checkpoint.state_root);
        payload.extend_from_slice(&point.checkpoint.body_manifest_root);
        for (length, hash) in &bodies {
            if *length == 0 || *length > limits.file_bytes {
                return Err(RecoveryError::Quota);
            }
            payload.extend_from_slice(&length.to_be_bytes());
            payload.extend_from_slice(hash);
        }
        let mut plaintext: u64 = 80 + payload.len() as u64;
        for (length, _) in &bodies {
            plaintext = plaintext.checked_add(*length).ok_or(RecoveryError::Quota)?;
        }
        if plaintext > limits.plaintext_bytes || 80 + payload.len() as u64 > limits.control_bytes {
            return Err(RecoveryError::Quota);
        }
        Ok(Self {
            point,
            bodies,
            payload,
            plaintext,
        })
    }
    pub(super) fn prefix<W: Write>(&self, writer: &mut W) -> Result<(), RecoveryError> {
        writer
            .write_all(super::super::envelope::MAGIC)
            .map_err(|_| RecoveryError::Transport)?;
        writer
            .write_all(&2u16.to_be_bytes())
            .map_err(|_| RecoveryError::Transport)?;
        writer
            .write_all(&[1])
            .map_err(|_| RecoveryError::Transport)?;
        writer
            .write_all(&(self.payload.len() as u32).to_be_bytes())
            .map_err(|_| RecoveryError::Transport)?;
        writer
            .write_all(&self.payload)
            .map_err(|_| RecoveryError::Transport)
    }
    pub(super) fn control(&self) -> &[u8] {
        &self.payload
    }
    pub(super) fn file_header(&self, index: usize) -> Result<[u8; 10], RecoveryError> {
        let (length, _) = self.bodies.get(index).ok_or(RecoveryError::Inventory)?;
        let mut header: [u8; 10] = [0; 10];
        header[0] = 2;
        header[1] = index as u8;
        header[2..].copy_from_slice(&length.to_be_bytes());
        Ok(header)
    }
    pub(super) fn footer(&self) -> [u8; 41] {
        let mut bytes: [u8; 41] = [0; 41];
        bytes[0] = 3;
        bytes[1..9].copy_from_slice(&self.plaintext.to_be_bytes());
        bytes[9..].copy_from_slice(&Sha256::digest(&self.payload));
        bytes
    }
    pub(super) fn read<R: Read>(
        reader: &mut R,
        limits: &RecoveryLimits,
    ) -> Result<Self, RecoveryError> {
        if take::<12, _>(reader)? != *super::super::envelope::MAGIC
            || take::<2, _>(reader)? != 2u16.to_be_bytes()
            || take::<1, _>(reader)? != [1]
        {
            return Err(RecoveryError::Inventory);
        }
        let length: u32 = u32::from_be_bytes(take(reader)?);
        if !(235..=362).contains(&length) || u64::from(length) + 80 > limits.control_bytes {
            return Err(RecoveryError::Quota);
        }
        let mut payload: Vec<u8> = vec![0; length as usize];
        reader
            .read_exact(&mut payload)
            .map_err(|_| RecoveryError::Inventory)?;
        let mut cursor: std::io::Cursor<&[u8]> = std::io::Cursor::new(&payload);
        let chain_length: u16 = u16::from_be_bytes(take(&mut cursor)?);
        if !(1..=128).contains(&chain_length) || length != 234 + u32::from(chain_length) {
            return Err(RecoveryError::Inventory);
        }
        let mut chain: Vec<u8> = vec![0; usize::from(chain_length)];
        cursor
            .read_exact(&mut chain)
            .map_err(|_| RecoveryError::Inventory)?;
        let chain: ChainId =
            ChainId::new(std::str::from_utf8(&chain).map_err(|_| RecoveryError::Inventory)?)
                .map_err(|_| RecoveryError::Inventory)?;
        let validator: ValidatorId = ValidatorId::new(take(&mut cursor)?);
        let domain: AtomicityDomainId =
            AtomicityDomainId::new(take(&mut cursor)?).map_err(|_| RecoveryError::Inventory)?;
        let point = LocalStoreCheckpoint {
            namespace: SqliteNamespace::new(chain, validator, domain),
            source_instance_id: take(&mut cursor)?,
            checkpoint: runtime_sqlite::AnchorCheckpoint {
                sequence: u64::from_be_bytes(take(&mut cursor)?),
                state_root: take(&mut cursor)?,
                body_manifest_root: take(&mut cursor)?,
            },
        };
        let mut bodies: [(u64, [u8; 32]); 2] = [(0, [0; 32]); 2];
        for body in &mut bodies {
            *body = (u64::from_be_bytes(take(&mut cursor)?), take(&mut cursor)?);
        }
        let result: Self = Self::new(point, bodies, limits)?;
        if result.payload != payload {
            return Err(RecoveryError::Inventory);
        }
        Ok(result)
    }
}
fn take<const N: usize, R: Read>(reader: &mut R) -> Result<[u8; N], RecoveryError> {
    let mut value: [u8; N] = [0; N];
    reader
        .read_exact(&mut value)
        .map_err(|_| RecoveryError::Inventory)?;
    Ok(value)
}

pub(super) fn receive<R: Read>(
    reader: &mut R,
    stage: &mut PrivateStage,
    limits: &RecoveryLimits,
) -> Result<Manifest, RecoveryError> {
    let manifest: Manifest = Manifest::read(reader, limits)?;
    for (index, name) in NAMES.into_iter().enumerate() {
        if take::<10, _>(reader)? != manifest.file_header(index)? {
            return Err(RecoveryError::Inventory);
        }
        let (length, hash) = manifest.bodies[index];
        stage.checkpoint_receive(name, reader, length, hash)?;
    }
    if take::<41, _>(reader)? != manifest.footer() {
        return Err(RecoveryError::Inventory);
    }
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn manifest() -> Manifest {
        Manifest::new(
            LocalStoreCheckpoint {
                namespace: SqliteNamespace::new(
                    ChainId::new("x").unwrap(),
                    ValidatorId::new([1; 32]),
                    AtomicityDomainId::new([2; 32]).unwrap(),
                ),
                source_instance_id: [3; 16],
                checkpoint: runtime_sqlite::AnchorCheckpoint {
                    sequence: 4,
                    state_root: [5; 32],
                    body_manifest_root: [6; 32],
                },
            },
            [(7, [8; 32]), (9, [10; 32])],
            &RecoveryLimits::default(),
        )
        .unwrap()
    }
    #[test]
    fn independent_v2_vector_and_closed_version_length_controls() {
        let m: Manifest = manifest();
        let mut expected: Vec<u8> = vec![0, 1, b'x'];
        expected.extend([1; 32]);
        expected.extend([2; 32]);
        expected.extend([3; 16]);
        expected.extend(4u64.to_be_bytes());
        expected.extend([5; 32]);
        expected.extend([6; 32]);
        expected.extend(7u64.to_be_bytes());
        expected.extend([8; 32]);
        expected.extend(9u64.to_be_bytes());
        expected.extend([10; 32]);
        assert_eq!(m.payload, expected);
        assert_eq!(m.payload.len(), 235);
        assert_eq!(m.plaintext, 331);
        // Independently computed from the literal payload above (Python
        // hashlib SHA-256), not this encoder's footer implementation.
        const FOOTER: &str =
            "03000000000000014b52326eb541baadbc0968eb190d9a2c791db309666c7769a818f493dd8f06b67f";
        let expected_footer: Vec<u8> = FOOTER
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        assert_eq!(m.footer().as_slice(), expected_footer);

        let mut prefix: Vec<u8> = b"SE-RECOVERY\0\0\x02\x01\0\0\0\xeb".to_vec();
        prefix.extend(&expected);
        let mut actual: Vec<u8> = Vec::new();
        m.prefix(&mut actual).unwrap();
        assert_eq!(actual, prefix);
        assert_eq!(m.file_header(0).unwrap(), [2, 0, 0, 0, 0, 0, 0, 0, 0, 7]);
        assert_eq!(m.file_header(1).unwrap(), [2, 1, 0, 0, 0, 0, 0, 0, 0, 9]);
        assert_eq!(
            Manifest::read(&mut &actual[..], &RecoveryLimits::default())
                .unwrap()
                .point,
            m.point
        );
        for (index, value) in [(13, 1), (13, 3), (14, 2), (18, 0), (19, 1), (20, 0)] {
            let mut changed: Vec<u8> = actual.clone();
            changed[index] = value;
            assert!(Manifest::read(&mut &changed[..], &RecoveryLimits::default()).is_err());
        }
        for length in [0, 1, 18, actual.len() - 1] {
            assert!(Manifest::read(&mut &actual[..length], &RecoveryLimits::default()).is_err());
        }
    }
}
