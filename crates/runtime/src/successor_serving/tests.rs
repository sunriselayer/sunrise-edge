use super::*;
use crate::inactive_import::ImportContext;
use crate::portable::PortableSnapshotToken;
use protocol_types::{ChainId, Epoch, ExecutionGeneration, ProtocolVersion};

fn domain(byte: u8) -> AtomicityDomainId {
    AtomicityDomainId::new([byte; 32]).unwrap()
}

fn binding(byte: u8) -> ImportBinding {
    ImportBinding {
        context: ImportContext {
            chain_id: ChainId::new("sunrise-edge-successor-test").unwrap(),
            protocol_version: ProtocolVersion::new(1),
            epoch: Epoch::new(5),
        },
        domain: domain(byte),
        genesis_digest: Digest32::new(protocol_types::HashAlgorithmId::Sha2_256, [1; 32]),
        validator_set_digest: Digest32::new(protocol_types::HashAlgorithmId::Sha2_256, [2; 32]),
        cut_digest: Digest32::new(protocol_types::HashAlgorithmId::Sha2_256, [3; 32]),
        package_digest: Digest32::new(protocol_types::HashAlgorithmId::Sha2_256, [4; 32]),
        plan_digest: Digest32::new(protocol_types::HashAlgorithmId::Sha2_256, [5; 32]),
        row_count: 1,
        blob_count: 0,
        generation_floor: ExecutionGeneration::new(1),
    }
}

fn progress() -> ImportProgress {
    ImportProgress {
        next_ordinal: 1,
        last_batch_digest: Some(Digest32::new(protocol_types::HashAlgorithmId::Sha2_256, [6; 32])),
        accumulator: Digest32::new(protocol_types::HashAlgorithmId::Sha2_256, [7; 32]),
    }
}

fn token(byte: u8) -> PortableSnapshotToken {
    PortableSnapshotToken::new(
        b"ns".to_vec(),
        domain(byte),
        WriterFenceGeneration::new(1).unwrap(),
        3,
    )
    .unwrap()
}

fn record(byte: u8) -> SuccessorServingRecord {
    SuccessorServingRecord {
        subject: Digest32::new(protocol_types::HashAlgorithmId::Sha2_256, [8; 32]),
        manifest: Digest32::new(protocol_types::HashAlgorithmId::Sha2_256, [9; 32]),
        binding: binding(byte),
        progress: progress(),
        activation_token: token(byte),
        anchor: Digest32::new(protocol_types::HashAlgorithmId::Sha2_256, [10; 32]),
        validator: ValidatorId::new([11; 32]),
        public_key: [12; 32],
    }
}

#[test]
fn record_round_trips_and_rejects_tamper() {
    let value = record(1);
    let bytes = encode_successor_serving_record(&value).unwrap();
    assert_eq!(decode_successor_serving_record(&bytes).unwrap(), value);

    let mut tampered = bytes.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert!(decode_successor_serving_record(&tampered).is_err());
}

#[test]
fn record_stays_within_bound() {
    let bytes = encode_successor_serving_record(&record(1)).unwrap();
    assert!(bytes.len() <= MAX_SUCCESSOR_SERVING_RECORD_BYTES);
}

#[test]
fn slot_inactive_round_trips_and_rejects_nonempty_record() {
    let bytes = encode_successor_serving_slot(&SuccessorServingSlot::Inactive).unwrap();
    assert_eq!(decode_successor_serving_slot(&bytes).unwrap(), SuccessorServingSlot::Inactive);

    let frame_bytes: Vec<u8> = {
        let mut frame = canonical_encoding::CanonicalStruct::new(0x64D6, 1);
        frame.field_u16(1, 1).unwrap();
        frame.field_bytes(2, vec![0xAA]).unwrap();
        frame.finish().unwrap()
    };
    assert!(decode_successor_serving_slot(&frame_bytes).is_err());
}

#[test]
fn slot_serving_round_trips_and_rejects_mismatched_observation() {
    let value = record(2);
    let record_bytes = encode_successor_serving_record(&value).unwrap();
    let slot = SuccessorServingSlot::Serving(SuccessorServingObservation {
        record: record_bytes.clone(),
        binding: value.binding.clone(),
        progress: value.progress.clone(),
    });
    let bytes = encode_successor_serving_slot(&slot).unwrap();
    assert_eq!(decode_successor_serving_slot(&bytes).unwrap(), slot);

    let mismatched = SuccessorServingSlot::Serving(SuccessorServingObservation {
        record: record_bytes,
        binding: binding(9),
        progress: value.progress,
    });
    assert!(encode_successor_serving_slot(&mismatched).is_err());
}

#[test]
fn decode_rejects_unknown_phase_and_oversized_frame() {
    let unknown_phase: Vec<u8> = {
        let mut frame = canonical_encoding::CanonicalStruct::new(0x64D6, 1);
        frame.field_u16(1, 3).unwrap();
        frame.field_bytes(2, Vec::new()).unwrap();
        frame.finish().unwrap()
    };
    assert!(decode_successor_serving_slot(&unknown_phase).is_err());

    let oversized = vec![0u8; MAX_SUCCESSOR_SERVING_SLOT_BYTES + 1];
    assert!(decode_successor_serving_slot(&oversized).is_err());
    let oversized_record = vec![0u8; MAX_SUCCESSOR_SERVING_RECORD_BYTES + 1];
    assert!(decode_successor_serving_record(&oversized_record).is_err());
}
