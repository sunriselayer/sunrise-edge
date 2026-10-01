use super::*;
use crate::fast_path::tests::transfer_bundle_bytes;
use crate::paid_execution::tests::{FIRST_PAID_NONCE, protocol};
use canonical_encoding::{decode_canonical_frame, encode_chain_id};
use execution::local_execution::encode_object_authority;
use execution::paid_execution::decode_paid_execution_result;
use objects::encode_object;
use protocol_types::{ChainId, HashAlgorithmId};

const REQUEST: u8 = 0xE4;
const NONCE: u64 = FIRST_PAID_NONCE;

fn lp(out: &mut Vec<u8>, bytes: &[u8]) {
    let length: u32 = u32::try_from(bytes.len()).expect("test operand length");
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(bytes);
}

fn list<T>(items: &[T], encode: impl Fn(&T) -> Vec<u8>) -> Vec<u8> {
    let count: u32 = u32::try_from(items.len()).expect("test list length");
    let mut out: Vec<u8> = count.to_be_bytes().to_vec();
    for item in items {
        lp(&mut out, &encode(item));
    }
    out
}

fn optional(out: &mut Vec<u8>, bytes: Option<&[u8]>) {
    match bytes {
        None => out.push(0),
        Some(bytes) => {
            out.push(1);
            lp(out, bytes);
        }
    }
}

fn encode_typed_operands(decoded: &DecodedLogicalWitness) -> [Vec<u8>; 10] {
    let authorities: Vec<u8> = list(&decoded.created_authorities, |item| {
        let mut out: Vec<u8> = item.creation_ordinal.to_be_bytes().to_vec();
        lp(
            &mut out,
            &encode_object_authority(&item.authority).expect("authority encoding"),
        );
        out
    });
    let heads: Vec<u8> = list(&decoded.head_reads, |item| {
        let mut out: Vec<u8> = item.object_id.as_bytes().to_vec();
        match &item.observation {
            DecodedObjectHeadObservation::Absent => out.push(0),
            DecodedObjectHeadObservation::Tombstoned {
                last_object_version,
            } => {
                out.push(1);
                out.extend_from_slice(&last_object_version.to_be_bytes());
            }
            DecodedObjectHeadObservation::Current {
                object_version,
                digest,
                owner_projection,
                routing_projection,
            } => {
                out.push(2);
                out.extend_from_slice(&object_version.to_be_bytes());
                out.extend_from_slice(digest);
                optional(&mut out, owner_projection.bytes());
                optional(&mut out, routing_projection.bytes());
            }
        }
        out
    });
    let object_mutations: Vec<u8> = list(&decoded.object_mutations, |item| {
        let mut out: Vec<u8> = item.object_id.as_bytes().to_vec();
        match &item.mutation {
            DecodedObjectMutationKind::Delete => out.push(0),
            DecodedObjectMutationKind::Create {
                version,
                owner_projection,
                routing_projection,
            }
            | DecodedObjectMutationKind::Update {
                version,
                owner_projection,
                routing_projection,
            } => {
                out.push(
                    if matches!(&item.mutation, DecodedObjectMutationKind::Create { .. }) {
                        1
                    } else {
                        2
                    },
                );
                let mut record: Vec<u8> = version.object_id.as_bytes().to_vec();
                record.extend_from_slice(&version.object_version.to_be_bytes());
                record.extend_from_slice(&version.digest);
                record.extend_from_slice(&version.schema_version.to_be_bytes());
                lp(
                    &mut record,
                    &encode_chain_id(&version.chain_id).expect("chain id encoding"),
                );
                record.extend_from_slice(&version.protocol_version.get().to_be_bytes());
                match &version.payload {
                    DecodedObjectPayload::InlineCanonicalObject(bytes) => {
                        record.push(0);
                        lp(&mut record, bytes);
                    }
                    DecodedObjectPayload::BlobReference(digest) => {
                        record.push(1);
                        record.extend_from_slice(digest);
                    }
                }
                lp(&mut out, &record);
                optional(&mut out, owner_projection.bytes());
                optional(&mut out, routing_projection.bytes());
            }
        }
        out
    });
    let state_reads: Vec<u8> = list(&decoded.state_reads, |item| {
        let mut out: Vec<u8> = Vec::new();
        lp(&mut out, &item.key);
        let observation: Vec<u8> = match item.observation {
            DecodedStateObservation::NeverWritten => vec![0],
            DecodedStateObservation::Present { content_digest } => {
                [1u16.to_be_bytes().as_slice(), content_digest.as_slice()].concat()
            }
            DecodedStateObservation::Deleted => 2u16.to_be_bytes().to_vec(),
        };
        lp(&mut out, &observation);
        match item.generation {
            None => out.push(0),
            Some(generation) => {
                out.push(1);
                out.extend_from_slice(&generation.get().to_be_bytes());
            }
        }
        out
    });
    let state_mutations: Vec<u8> = list(&decoded.state_mutations, |item| {
        let mut out: Vec<u8> = Vec::new();
        lp(&mut out, &item.key);
        match &item.mutation {
            StateMutation::Assert => out.push(0),
            StateMutation::Put(value) => {
                out.push(1);
                lp(&mut out, value);
            }
            StateMutation::Delete => out.push(2),
        }
        out
    });
    let dependencies: Vec<u8> = list(&decoded.dependencies, |item| {
        let mut subject: Vec<u8> = Vec::new();
        match &item.subject {
            LogicalSubject::StateKey(key) => {
                subject.push(1);
                lp(&mut subject, key);
            }
            LogicalSubject::Object(object_id) => {
                subject.push(2);
                subject.extend_from_slice(object_id.as_bytes());
            }
            LogicalSubject::SenderNonce { sender, epoch } => {
                subject.push(3);
                subject.extend_from_slice(sender);
                subject.extend_from_slice(&epoch.get().to_be_bytes());
            }
        }
        let mut out: Vec<u8> = Vec::new();
        lp(&mut out, &subject);
        out.extend_from_slice(&item.generation.get().to_be_bytes());
        out
    });
    [
        authorities,
        heads,
        object_mutations,
        state_reads,
        state_mutations,
        decoded.nonce.key.clone(),
        decoded.nonce.canonical_value.clone(),
        decoded.generation.get().to_le_bytes().to_vec(),
        dependencies,
        decoded.paid_execution_result_bytes.clone(),
    ]
}

#[test]
fn decodes_and_reencodes_every_v2_operand_from_a_real_prepare_bundle() {
    let (bundle, certificate) = transfer_bundle_bytes(REQUEST, NONCE);
    let decoded: DecodedLogicalWitness = decode_logical_witness(&bundle.witness).unwrap();
    let frame = decode_canonical_frame(&bundle.witness).unwrap();

    assert_eq!(decoded.event_digest, certificate.tx_hash);
    assert_eq!(
        decoded.paid_execution_result_bytes,
        frame.required_field(2).unwrap()
    );
    assert_eq!(
        decoded.paid_execution_result,
        decode_paid_execution_result(&decoded.paid_execution_result_bytes).unwrap()
    );
    let encoded: [Vec<u8>; 10] = encode_typed_operands(&decoded);
    for (index, field) in [3u16, 4, 5, 6, 7, 8, 10, 11, 12, 2].into_iter().enumerate() {
        assert_eq!(
            encoded[index],
            frame.required_field(field).unwrap(),
            "typed v2 operand field {field} must equal the original production bytes"
        );
    }
    assert_eq!(decoded.nonce.next_nonce, NONCE + 1);
    assert!(decoded.generation.get() > 0);
    assert!(
        decoded
            .state_reads
            .iter()
            .any(|read| { matches!(read.observation, DecodedStateObservation::Present { .. }) })
    );
    assert!(!decoded.dependencies.is_empty());
}

fn one_item_list(item: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = 1u32.to_be_bytes().to_vec();
    lp(&mut out, item);
    out
}

#[test]
fn preserves_all_state_observation_and_optional_generation_shapes() {
    let mut pristine: Vec<u8> = Vec::new();
    lp(&mut pristine, b"a");
    lp(&mut pristine, &[0]);
    pristine.push(0);
    assert_eq!(
        decode_state_reads(&one_item_list(&pristine)).unwrap()[0],
        DecodedStateRead {
            key: b"a".to_vec(),
            observation: DecodedStateObservation::NeverWritten,
            generation: None,
        }
    );

    for observation in [
        DecodedStateObservation::Present {
            content_digest: [9; 32],
        },
        DecodedStateObservation::Deleted,
    ] {
        let bytes: Vec<u8> = match observation {
            DecodedStateObservation::Present { content_digest } => {
                [1u16.to_be_bytes().as_slice(), content_digest.as_slice()].concat()
            }
            DecodedStateObservation::Deleted => 2u16.to_be_bytes().to_vec(),
            DecodedStateObservation::NeverWritten => unreachable!(),
        };
        let mut read: Vec<u8> = Vec::new();
        lp(&mut read, b"b");
        lp(&mut read, &bytes);
        read.push(1);
        read.extend_from_slice(&4u64.to_be_bytes());
        let decoded: DecodedStateRead =
            decode_state_reads(&one_item_list(&read)).unwrap()[0].clone();
        assert_eq!(decoded.observation, observation);
        assert_eq!(decoded.generation, Some(ExecutionGeneration::new(4)));
    }

    let mut invalid: Vec<u8> = Vec::new();
    lp(&mut invalid, b"a");
    lp(&mut invalid, &[0]);
    invalid.push(1);
    invalid.extend_from_slice(&1u64.to_be_bytes());
    assert!(decode_state_reads(&one_item_list(&invalid)).is_err());

    let mut unknown_generation: Vec<u8> = Vec::new();
    lp(&mut unknown_generation, b"b");
    lp(&mut unknown_generation, &2u16.to_be_bytes());
    unknown_generation.push(2);
    assert!(decode_state_reads(&one_item_list(&unknown_generation)).is_err());

    assert!(decode_state_observation(&[0, 0]).is_err());
    assert!(decode_state_observation(&[0, 3]).is_err());
    assert!(decode_state_observation(&[0, 2, 0]).is_err());
}

#[test]
fn rejects_unknown_tags_trailing_bytes_duplicate_keys_and_oversized_counts() {
    let unknown_head_item: Vec<u8> = [[1u8; 32].as_slice(), &[0xFF]].concat();
    let unknown_head: Vec<u8> = one_item_list(&unknown_head_item);
    assert!(decode_head_reads(&unknown_head).is_err());

    let duplicate_read: Vec<u8> = {
        let mut item: Vec<u8> = Vec::new();
        lp(&mut item, b"duplicate");
        lp(&mut item, &[0]);
        item.push(0);
        let mut out: Vec<u8> = 2u32.to_be_bytes().to_vec();
        lp(&mut out, &item);
        lp(&mut out, &item);
        out
    };
    assert!(decode_state_reads(&duplicate_read).is_err());

    let oversized: Vec<u8> = u32::try_from(commitment::MAX_WITNESS_LIST_ITEMS + 1)
        .unwrap()
        .to_be_bytes()
        .to_vec();
    assert!(decode_state_mutations(&oversized).is_err());

    let mut trailing_subject: Vec<u8> = vec![2];
    trailing_subject.extend_from_slice(&[7; 32]);
    trailing_subject.push(0);
    assert!(decode_subject(&trailing_subject).is_err());

    let mut trailing_mutation: Vec<u8> = Vec::new();
    lp(&mut trailing_mutation, b"key");
    trailing_mutation.extend_from_slice(&[2, 0]);
    assert!(decode_state_mutations(&one_item_list(&trailing_mutation)).is_err());
}

#[test]
fn parser_accepts_every_head_mutation_and_dependency_tag() {
    let absent: Vec<u8> = [[1u8; 32].as_slice(), &[0]].concat();
    let mut tombstone: Vec<u8> = [[2u8; 32].as_slice(), &[1]].concat();
    tombstone.extend_from_slice(&3u64.to_be_bytes());
    let mut current: Vec<u8> = [[3u8; 32].as_slice(), &[2]].concat();
    current.extend_from_slice(&4u64.to_be_bytes());
    current.extend_from_slice(&[5; 32]);
    optional(&mut current, None);
    optional(&mut current, Some(&[]));
    let heads: Vec<u8> =
        [absent, tombstone, current]
            .iter()
            .fold(3u32.to_be_bytes().to_vec(), |mut out, item| {
                lp(&mut out, item);
                out
            });
    assert_eq!(decode_head_reads(&heads).unwrap().len(), 3);

    let inline_id: [u8; 32] = [4; 32];
    let inline_object: objects::Object = objects::Object {
        id: ObjectId::new(inline_id),
        version: 1,
        owner: objects::Owner::Shared,
        type_hash: Digest32::new(HashAlgorithmId::Sha2_256, [5; 32]),
        schema_version: 2,
        data: vec![9, 8, 7],
    };
    let inline_bytes: Vec<u8> = encode_object(&inline_object).unwrap();
    let deleted: Vec<u8> = [[5u8; 32].as_slice(), &[0]].concat();
    assert!(decode_object_mutations(&one_item_list(&deleted)).is_ok());
    for (mutation_tag, payload_tag) in [(1u8, 0u8), (2, 1)] {
        let id: [u8; 32] = if payload_tag == 0 { inline_id } else { [6; 32] };
        let mut record: Vec<u8> = id.to_vec();
        record.extend_from_slice(&1u64.to_be_bytes());
        record.extend_from_slice(&[7; 32]);
        record.extend_from_slice(&2u32.to_be_bytes());
        lp(
            &mut record,
            &encode_chain_id(&ChainId::new("witness-test").unwrap()).unwrap(),
        );
        record.extend_from_slice(&3u32.to_be_bytes());
        if payload_tag == 0 {
            record.push(0);
            lp(&mut record, &inline_bytes);
        } else {
            record.push(1);
            record.extend_from_slice(&[7; 32]);
        }
        let mut mutation: Vec<u8> = id.to_vec();
        mutation.push(mutation_tag);
        lp(&mut mutation, &record);
        optional(&mut mutation, None);
        optional(&mut mutation, None);
        assert!(decode_object_mutations(&one_item_list(&mutation)).is_ok());
    }

    let asserted_mutation: Vec<u8> = {
        let mut item: Vec<u8> = Vec::new();
        lp(&mut item, b"assert-key");
        item.push(0);
        item
    };
    assert_eq!(
        decode_state_mutations(&one_item_list(&asserted_mutation)).unwrap()[0].mutation,
        StateMutation::Assert
    );
    for mutation in [StateMutation::Put(b"value".to_vec()), StateMutation::Delete] {
        let mut item: Vec<u8> = Vec::new();
        lp(&mut item, b"mutation-key");
        match &mutation {
            StateMutation::Put(value) => {
                item.push(1);
                lp(&mut item, value);
            }
            StateMutation::Delete => item.push(2),
            StateMutation::Assert => item.push(0),
        }
        assert_eq!(
            decode_state_mutations(&one_item_list(&item)).unwrap()[0].mutation,
            mutation
        );
    }

    for subject in [
        {
            let mut bytes: Vec<u8> = vec![1];
            lp(&mut bytes, b"key");
            bytes
        },
        [[2u8].as_slice(), &[2; 32]].concat(),
        [[3u8].as_slice(), &[3; 32], &8u64.to_be_bytes()].concat(),
    ] {
        assert!(decode_subject(&subject).is_ok());
    }
}

#[test]
fn decodes_created_authority_operands_as_untrusted_typed_data() {
    let publication_context = protocol();
    let origin: abi::package_types::PackageOrigin = abi::package_types::PackageOrigin::unverified(
        publication_context.chain_id().clone(),
        [0x10; 32],
        [0x11; 32],
    )
    .unwrap();
    let code: execution::publication::UnverifiedDependencyRef =
        execution::publication::UnverifiedDependencyRef::new(
            origin.clone(),
            1,
            publication_context.clone(),
            Digest32::new(HashAlgorithmId::Sha2_256, [0x12; 32]),
        )
        .unwrap();
    let authority: execution::local_execution::ObjectAuthority =
        execution::local_execution::ObjectAuthority {
            object_id: ObjectId::new([0x20; 32]),
            instance_context: publication_context,
            instance: execution::call::InstanceTarget {
                creator: [0x13; 32],
                seed: [0x14; 32],
                revision: 1,
                record_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x15; 32]),
            },
            code,
            ty: abi::package_types::ScopedTypeTag::new(
                origin,
                2,
                vec![abi::package_types::ScopedTypeArg::Opaque {
                    domain: 7,
                    value: [0x30; 32],
                }],
            )
            .unwrap(),
        };
    let authority_bytes: Vec<u8> = encode_object_authority(&authority).unwrap();
    let mut item: Vec<u8> = 0u32.to_be_bytes().to_vec();
    lp(&mut item, &authority_bytes);
    let decoded: Vec<CreatedObjectAuthority> =
        decode_created_authorities(&one_item_list(&item)).unwrap();
    assert_eq!(decoded[0].creation_ordinal, 0);
    assert_eq!(decoded[0].authority, authority);
}
