//! Private, opt-in client for the designated original serving node's local
//! Coin observation. This is not a chain proof or a currentness reservation.
//! No approval or signing path calls this module yet.

use std::{io, path::PathBuf, time::Duration};

use node_core::ordered_economics::OrderedEconomicsPolicy;
use node_wire::original_bond_currentness::{self as wire, OriginalBondLocalObservationFrame};
use sunrise_edge_client::{
    AtomicityDomainId, ChainId, Digest32, Epoch, ObjectRef, ProtocolVersion, ValidatorId,
    VerifiedGenesisRoot,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};

use super::{bond_policy::BondTrust, client::connect_and_check_peer};
use crate::error::CliError;

const IO_DEADLINE: Duration = Duration::from_secs(15);

fn refused() -> CliError {
    CliError::LocalExecution(Box::new(io::Error::other(
        "designated local bond observation refused",
    )))
}

/// All authority comes from a private role config and an independently
/// authenticated genesis manifest, never from the request or response.
struct Pins {
    socket: PathBuf,
    server_uid: u32,
    validator: ValidatorId,
    namespace: Vec<u8>,
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
    domain: AtomicityDomainId,
    validator_set_digest: Digest32,
    genesis_digest: Digest32,
    anchor: Digest32,
}

impl Pins {
    fn from_trust(trust: &BondTrust) -> Result<Self, CliError> {
        let target = trust.config().currentness().ok_or_else(refused)?;
        let root = trust.currentness_root();
        require_original_validator(root, target.validator)?;
        let expected = trust.config().expected_context().map_err(|_| refused())?;
        let validator_set_digest = root
            .genesis_committee()
            .digest(root.genesis_resolver())
            .map_err(|_| refused())?;
        let anchor = OrderedEconomicsPolicy::from_genesis_root(root, expected.domain())
            .map_err(|_| refused())?
            .anchor();
        Ok(Self {
            socket: target.socket.clone(),
            server_uid: target.uid,
            validator: target.validator,
            namespace: target.namespace.clone(),
            chain_id: expected.chain_id().clone(),
            protocol_version: expected.protocol_version(),
            domain: expected.domain(),
            validator_set_digest,
            genesis_digest: root.digest(),
            anchor,
        })
    }

    fn check(
        &self,
        value: OriginalBondLocalObservationFrame,
        reference: &ObjectRef,
        prior: Option<&LocalBondObservation>,
    ) -> Result<LocalBondObservation, CliError> {
        if value.validator != self.validator
            || value.chain_id != self.chain_id
            || value.protocol_version != self.protocol_version
            || value.token.namespace() != self.namespace
            || value.token.domain() != self.domain
            || value.epoch != Epoch::new(0)
            || value.validator_set_digest != self.validator_set_digest
            || value.genesis_digest != self.genesis_digest
            || value.anchor != self.anchor
            || value.coin != *reference
            || (value.through_height == 0
                && (value.through_view != 0 || value.through_digest != self.anchor))
            || (value.through_height != 0 && value.through_view == 0)
            || prior.is_some_and(|before| before.0 != value)
        {
            return Err(refused());
        }
        Ok(LocalBondObservation(value))
    }
}

fn require_original_validator(
    root: &VerifiedGenesisRoot,
    validator: ValidatorId,
) -> Result<(), CliError> {
    root.genesis_committee()
        .get(validator)
        .ok_or_else(refused)?;
    Ok(())
}

/// A successfully pinned local observation at one token, not a promise that
/// the Coin remains current when an approval or signature is delivered.
#[derive(Clone)]
pub(super) struct LocalBondObservation(OriginalBondLocalObservationFrame);

/// One fresh read from the configured local node. Callers at separate review,
/// approval and signing decisions must requery and bind the complete result.
pub(super) fn observe(
    trust: &BondTrust,
    reference: &ObjectRef,
    coin_body: &[u8],
    prior: Option<&LocalBondObservation>,
) -> Result<LocalBondObservation, CliError> {
    let pins = Pins::from_trust(trust)?;
    let body = wire::encode_request(reference, coin_body).map_err(|_| refused())?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|_| refused())?;
    runtime.block_on(observe_async(&pins, reference, &body, prior))
}

async fn observe_async(
    pins: &Pins,
    reference: &ObjectRef,
    body: &[u8],
    prior: Option<&LocalBondObservation>,
) -> Result<LocalBondObservation, CliError> {
    // Peer credentials are checked before any request byte is sent.
    let mut stream = connect_and_check_peer(&pins.socket, pins.server_uid)
        .await
        .map_err(|_| refused())?;
    let response = timeout(IO_DEADLINE, async {
        let length = u32::try_from(body.len()).map_err(|_| refused())?;
        stream
            .write_all(&length.to_be_bytes())
            .await
            .map_err(|_| refused())?;
        stream.write_all(body).await.map_err(|_| refused())?;
        stream.shutdown().await.map_err(|_| refused())?;

        let response_length = stream.read_u32().await.map_err(|_| refused())? as usize;
        if response_length == 0 || response_length > wire::MAX_RESPONSE_BYTES {
            return Err(refused());
        }
        let mut response = vec![0; response_length];
        stream
            .read_exact(&mut response)
            .await
            .map_err(|_| refused())?;
        let mut trailing = [0];
        if stream.read(&mut trailing).await.map_err(|_| refused())? != 0 {
            return Err(refused());
        }
        Ok(response)
    })
    .await
    .map_err(|_| refused())??;
    pins.check(
        wire::decode_response(&response).map_err(|_| refused())?,
        reference,
        prior,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::custody::fsperm::{current_effective_uid, test_support::TempDir};
    use runtime::{WriterFenceGeneration, portable::PortableSnapshotToken};
    use sunrise_edge_client::{HashAlgorithmId, LocalSigner, ObjectId, PublicationContext};
    use tokio::net::UnixListener;

    fn fixture(path: PathBuf) -> (Pins, ObjectRef, OriginalBondLocalObservationFrame) {
        let digest = |byte| Digest32::new(HashAlgorithmId::Sha2_256, [byte; 32]);
        let reference = ObjectRef {
            id: ObjectId::new([1; 32]),
            version: 2,
            digest: digest(3),
        };
        let frame = OriginalBondLocalObservationFrame {
            validator: ValidatorId::new([4; 32]),
            chain_id: ChainId::new("original-bond-test").unwrap(),
            protocol_version: ProtocolVersion::new(1),
            token: PortableSnapshotToken::new(
                b"fixed-store-instance".to_vec(),
                AtomicityDomainId::new([5; 32]).unwrap(),
                WriterFenceGeneration::new(7).unwrap(),
                8,
            )
            .unwrap(),
            epoch: Epoch::new(0),
            validator_set_digest: digest(6),
            genesis_digest: digest(7),
            anchor: digest(8),
            through_height: 0,
            through_view: 0,
            through_digest: digest(8),
            coin: reference.clone(),
        };
        let pins = Pins {
            socket: path,
            server_uid: current_effective_uid().unwrap(),
            validator: frame.validator,
            namespace: frame.token.namespace().to_vec(),
            chain_id: frame.chain_id.clone(),
            protocol_version: frame.protocol_version,
            domain: frame.token.domain(),
            validator_set_digest: frame.validator_set_digest,
            genesis_digest: frame.genesis_digest,
            anchor: frame.anchor,
        };
        (pins, reference, frame)
    }

    #[test]
    fn pinned_frame_refuses_every_identity_and_changed_token() {
        let (pins, reference, frame) = fixture(PathBuf::from("/unused"));
        let accepted = pins.check(frame.clone(), &reference, None).unwrap();
        let mut changed = frame.clone();
        changed.validator = ValidatorId::new([0x11; 32]);
        assert!(pins.check(changed, &reference, None).is_err());
        let mut changed = frame.clone();
        changed.token = PortableSnapshotToken::new(
            b"other-store".to_vec(),
            pins.domain,
            WriterFenceGeneration::new(7).unwrap(),
            8,
        )
        .unwrap();
        assert!(pins.check(changed, &reference, None).is_err());
        let mut changed = frame.clone();
        changed.token = PortableSnapshotToken::new(
            pins.namespace.clone(),
            pins.domain,
            WriterFenceGeneration::new(8).unwrap(),
            8,
        )
        .unwrap();
        assert!(pins.check(changed, &reference, Some(&accepted)).is_err());
        let mut changed = frame.clone();
        changed.token = PortableSnapshotToken::new(
            pins.namespace.clone(),
            pins.domain,
            WriterFenceGeneration::new(7).unwrap(),
            9,
        )
        .unwrap();
        assert!(pins.check(changed, &reference, Some(&accepted)).is_err());
        let mut changed = frame.clone();
        changed.genesis_digest = Digest32::new(HashAlgorithmId::Sha2_256, [9; 32]);
        assert!(pins.check(changed, &reference, None).is_err());
        let mut changed = frame.clone();
        changed.validator_set_digest = Digest32::new(HashAlgorithmId::Sha2_256, [9; 32]);
        assert!(pins.check(changed, &reference, None).is_err());
        let mut changed = frame.clone();
        changed.anchor = Digest32::new(HashAlgorithmId::Sha2_256, [9; 32]);
        assert!(pins.check(changed, &reference, None).is_err());
        let mut changed = frame.clone();
        changed.coin.version += 1;
        assert!(pins.check(changed, &reference, None).is_err());
        let mut changed = frame.clone();
        changed.through_height = 1;
        changed.through_view = 1;
        assert!(pins.check(changed, &reference, Some(&accepted)).is_err());
        let mut changed = frame;
        changed.through_digest = Digest32::new(HashAlgorithmId::Sha2_256, [9; 32]);
        assert!(pins.check(changed, &reference, None).is_err());
    }

    #[test]
    fn designated_source_host_must_be_original_committee_member() {
        let protocol = sunrise_edge_devnet::build_devnet_protocol_context(
            ChainId::new("bond-node-member-test").unwrap(),
            Epoch::new(0),
        )
        .unwrap();
        let context = PublicationContext::new(
            protocol.chain_id().clone(),
            protocol.resolver().protocol_version(),
            Epoch::new(0),
        )
        .unwrap();
        let owner = LocalSigner::from_seed([0x31; 32]).address();
        let fee_owner = LocalSigner::from_seed([0x32; 32]).address();
        let (manifest, _) = sunrise_edge_devnet::build_paid_genesis_manifest(
            protocol.resolver(),
            &context,
            &[sunrise_edge_devnet::DevOwner::new(*owner.as_bytes())],
            sunrise_edge_devnet::DevOwner::new(*fee_owner.as_bytes()),
        )
        .unwrap();
        let bytes = node_core::genesis::encode_genesis_manifest(&manifest).unwrap();
        let digest =
            node_core::genesis::genesis_manifest_commitment(protocol.resolver(), &manifest)
                .unwrap();
        let root = VerifiedGenesisRoot::verify_bytes(
            protocol.resolver(),
            &bytes,
            digest.bytes(),
            &context,
        )
        .unwrap();
        let member = root.genesis_committee().validators()[0].id;
        require_original_validator(&root, member).unwrap();
        let stranger = ValidatorId::new([0xff; 32]);
        assert_ne!(member, stranger);
        assert!(require_original_validator(&root, stranger).is_err());
    }

    #[tokio::test]
    async fn peer_checked_before_body_and_bounded_exact_round_trip() {
        let dir = TempDir::new(0o700);
        let socket = dir.child("observe.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let (mut pins, reference, frame) = fixture(socket);
        let body = wire::encode_request(&reference, b"reviewed Coin body").unwrap();

        pins.server_uid = pins.server_uid.wrapping_add(1);
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut first = [0];
            assert_eq!(stream.read(&mut first).await.unwrap(), 0);
            listener
        });
        assert!(observe_async(&pins, &reference, &body, None).await.is_err());
        let listener = server.await.unwrap();

        pins.server_uid = current_effective_uid().unwrap();
        let expected_body = body.clone();
        let response = wire::encode_response(&frame).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let length = stream.read_u32().await.unwrap() as usize;
            let mut request = vec![0; length];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(request, expected_body);
            stream.write_u32(response.len() as u32).await.unwrap();
            stream.write_all(&response).await.unwrap();
        });
        let result = observe_async(&pins, &reference, &body, None).await.unwrap();
        assert_eq!(result.0, frame);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn malformed_length_and_trailing_bytes_are_refused() {
        let dir = TempDir::new(0o700);
        let socket = dir.child("observe.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let (pins, reference, frame) = fixture(socket);
        let body = wire::encode_request(&reference, b"Coin").unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let length = stream.read_u32().await.unwrap() as usize;
            let mut request = vec![0; length];
            stream.read_exact(&mut request).await.unwrap();
            stream
                .write_u32((wire::MAX_RESPONSE_BYTES + 1) as u32)
                .await
                .unwrap();
            drop(stream);

            let (mut stream, _) = listener.accept().await.unwrap();
            let length = stream.read_u32().await.unwrap() as usize;
            let mut request = vec![0; length];
            stream.read_exact(&mut request).await.unwrap();
            let response = wire::encode_response(&frame).unwrap();
            stream.write_u32(response.len() as u32).await.unwrap();
            stream.write_all(&response).await.unwrap();
            stream.write_all(b"extra").await.unwrap();
        });
        assert!(observe_async(&pins, &reference, &body, None).await.is_err());
        assert!(observe_async(&pins, &reference, &body, None).await.is_err());
        server.await.unwrap();
    }
}
