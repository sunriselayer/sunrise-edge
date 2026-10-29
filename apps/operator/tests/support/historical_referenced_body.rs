//! DR-0277: one independently fixed historical body for the ACK-loss fixture.
//! This is a typed storage fixture, never a paid Coin or claimed quorum effect.
//! The literal 70 KiB object follows DR-0265's existing BodyOracle without
//! changing or invoking that separate upgrade owner.

use super::{Network, TlsPeer, VALIDATORS, open_store, operation, snapshot};
use node_core::business_reconstruction::SourceBusinessSnapshot;
use node_core::{NodeDedupRecord, NodeResponse, NodeResponseStatus};
use objects::{Address, Object, ObjectId, Owner, decode_object, encode_object};
use protocol_types::{Digest32, HashAlgorithmId, HashPurpose};
use runtime::portable::DurableCollection;
use runtime::{
    BlobStore, DurableCommitOutcome, DurableInvocationTransaction, DurableObjectChanges,
    DurableObjectHead, DurableObjectHeadRead, DurableObjectMutation, DurableObjectMutationEntry,
    DurableObjectOwnerProjection, DurableObjectProvenance, DurableObjectRoutingProjection,
    DurableObjectVersion, DurableObjectVersionRecord, DurableOperationContext, DurableRequestId,
    DurableRequestReceipt, ObjectHeadRevision, StructuredDurableDomainStateStore,
};
use runtime_sqlite::{SqliteBlobStore, SqliteDurableStore};
use std::collections::{BTreeMap, BTreeSet};
use sunrise_edge_client::{HttpObjectQueryResult, RequestId};

pub(super) struct HistoricalReferencedBody {
    object: Object,
    bytes: Vec<u8>,
    digest: Digest32,
    version: DurableObjectVersionRecord,
    head: DurableObjectHead,
    receipt: DurableRequestReceipt,
}

impl HistoricalReferencedBody {
    /// Install before any serving host starts. Publish the canonical body before
    /// its typed Create commit, retaining no SQLite handle in the returned oracle.
    pub(super) fn install(network: &Network) -> Self {
        let object: Object = Object {
            id: ObjectId::new([61; 32]),
            version: 1,
            owner: Owner::Address(Address::new([62; 32])),
            type_hash: Digest32::new(HashAlgorithmId::Sha2_256, [63; 32]),
            schema_version: 1,
            data: vec![64; 70 * 1024],
        };
        let bytes: Vec<u8> = encode_object(&object).unwrap();
        assert!(bytes.len() > 64 * 1024 && bytes.len() <= 80 * 1024);
        assert_eq!(decode_object(&bytes).unwrap(), object);
        let digest: Digest32 = network
            .fixture
            .resolver
            .hash_for_purpose(network.fixture.context.epoch(), HashPurpose::Object, &bytes)
            .unwrap();
        let version: DurableObjectVersionRecord = DurableObjectVersionRecord::from_blob_reference(
            object.id,
            DurableObjectVersion::FIRST,
            digest,
            object.schema_version,
            DurableObjectProvenance::new(
                network.fixture.context.chain_id().clone(),
                network.fixture.context.protocol_version(),
            ),
            7,
            digest,
        );
        let head: DurableObjectHead = DurableObjectHead::Current {
            head_revision: ObjectHeadRevision::FIRST,
            object_version: DurableObjectVersion::FIRST,
            digest,
            owner_projection: DurableObjectOwnerProjection::from_owner(object.owner.clone())
                .unwrap(),
            routing_projection: DurableObjectRoutingProjection::default(),
        };
        let request: RequestId = RequestId::new([81; 32]).unwrap();
        let event: Digest32 = network
            .fixture
            .resolver
            .hash_for_purpose(
                network.fixture.context.epoch(),
                HashPurpose::NodeEvent,
                &bytes,
            )
            .unwrap();
        let response: NodeResponse =
            NodeResponse::new(request, NodeResponseStatus::Accepted, Some(bytes.clone())).unwrap();
        let record: NodeDedupRecord = NodeDedupRecord::new(request, event, vec![response]).unwrap();
        let receipt: DurableRequestReceipt = DurableRequestReceipt::new(
            DurableRequestId::new([81; 32]).unwrap(),
            event,
            record.encode().unwrap(),
        )
        .unwrap();
        for index in 0..VALIDATORS {
            let store: SqliteDurableStore = open_store(network, index);
            let blobs: SqliteBlobStore =
                SqliteBlobStore::open_existing_writable(network.blob_db(index)).unwrap();
            blobs.put_blob(digest, bytes.clone()).unwrap();
            let changes: DurableObjectChanges = DurableObjectChanges::new(
                vec![DurableObjectHeadRead::new(
                    object.id,
                    DurableObjectHead::Absent,
                )],
                vec![DurableObjectMutationEntry::new(
                    object.id,
                    DurableObjectMutation::Create {
                        version: version.clone(),
                        owner_projection: DurableObjectOwnerProjection::from_owner(
                            object.owner.clone(),
                        )
                        .unwrap(),
                        routing_projection: DurableObjectRoutingProjection::default(),
                    },
                )],
            )
            .unwrap();
            let transaction: DurableInvocationTransaction = DurableInvocationTransaction::new(
                network.domain,
                None,
                changes,
                receipt.clone(),
                None,
            )
            .unwrap();
            assert_eq!(
                store.commit_invocation(
                    &operation(store.writer_fence().unwrap(), 0x71),
                    transaction
                ),
                DurableCommitOutcome::Committed
            );
        }
        Self {
            object,
            bytes,
            digest,
            version,
            head,
            receipt,
        }
    }

    /// Require the complete closure, its exact bytes, decoded object and digest.
    /// A nonempty blob table alone cannot satisfy this owning-reference oracle.
    pub(super) fn assert_snapshot(&self, network: &Network, captured: &SourceBusinessSnapshot) {
        captured.validate().unwrap();
        let expected: BTreeMap<Digest32, Vec<u8>> =
            BTreeMap::from([(self.digest, self.bytes.clone())]);
        assert_eq!(captured.referenced_blobs, expected);
        let bytes: &Vec<u8> = captured.referenced_blobs.get(&self.digest).unwrap();
        let decoded: Object = decode_object(bytes).unwrap();
        assert_eq!(decoded, self.object);
        assert_eq!(encode_object(&decoded).unwrap(), self.bytes);
        let digest: Digest32 = network
            .fixture
            .resolver
            .hash_for_purpose(network.fixture.context.epoch(), HashPurpose::Object, bytes)
            .unwrap();
        assert_eq!(digest, self.digest);
        let collections: BTreeSet<DurableCollection> = captured
            .records
            .iter()
            .map(|record| record.descriptor.key().collection())
            .collect();
        assert_eq!(
            collections,
            BTreeSet::from([
                DurableCollection::State,
                DurableCollection::Receipts,
                DurableCollection::ObjectHeads,
                DurableCollection::ObjectVersions
            ])
        );
    }

    /// Verify every replica through fresh typed storage reads, complete portable
    /// capture and the actual TLS query. Expectations never come from paid output.
    pub(super) fn verify<P: TlsPeer>(&self, network: &Network, peers: &[P]) {
        assert_eq!(peers.len(), VALIDATORS);
        for (index, peer) in peers.iter().enumerate() {
            let store: SqliteDurableStore = open_store(network, index);
            let context: DurableOperationContext = operation(store.writer_fence().unwrap(), 0x72);
            assert_eq!(
                store
                    .get_object_head(&context, network.domain, self.object.id)
                    .unwrap(),
                self.head
            );
            assert_eq!(
                store
                    .get_object_version(
                        &context,
                        network.domain,
                        self.object.id,
                        DurableObjectVersion::FIRST
                    )
                    .unwrap(),
                Some(self.version.clone())
            );
            let receipt: DurableRequestReceipt = store
                .get_request_receipt(&context, network.domain, self.receipt.request_id())
                .unwrap()
                .expect("historical fixture receipt remains present");
            assert_eq!(receipt, self.receipt);
            let record: NodeDedupRecord =
                NodeDedupRecord::decode(receipt.canonical_bytes()).unwrap();
            assert_eq!(record.encode().unwrap(), receipt.canonical_bytes());
            drop(store);
            let captured: SourceBusinessSnapshot = snapshot(network, index);
            self.assert_snapshot(network, &captured);
            assert_eq!(
                peer.client().query_object(self.object.id).unwrap(),
                HttpObjectQueryResult::CurrentBlobReference {
                    object_id: self.object.id,
                    head_revision: ObjectHeadRevision::FIRST,
                    object_version: DurableObjectVersion::FIRST,
                    digest: self.digest,
                    blob_digest: self.digest
                }
            );
        }
    }
}
