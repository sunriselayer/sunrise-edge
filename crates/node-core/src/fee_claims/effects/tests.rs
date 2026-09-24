use super::*;
use crate::genesis::tests::{build_fixture, protocol, resolver};
use abi::call_values::{CallValue, encode_call_value};
use ed25519_zebra::SigningKey;
use execution::EventRecord;
use objects::Address;
use protocol_types::{HashAlgorithmId, HashPurpose};
use runtime::{
    DurableObjectHead, DurableObjectOwnerProjection, DurableObjectProvenance,
    DurableObjectRoutingProjection, DurableObjectVersion, ObjectHeadRevision,
};

struct Fixture {
    interface: VerifiedPublicationInterface,
    authority: ObjectAuthority,
    snapshot: object_snapshots::ObjectSnapshot,
    scope: ProtocolCustodyScope,
    recipient: Address,
}

fn fixture() -> Fixture {
    let (manifest, _origin, _instance, _definition_id, _coin_id) = build_fixture();
    let candidate = execution::publication::authenticate_publication_submission(
        &resolver(),
        &protocol(),
        &execution::local_execution::generic_object_result_semantics(&resolver(), &protocol())
            .unwrap(),
        manifest.publication.clone(),
    )
    .unwrap();
    let interface: VerifiedPublicationInterface =
        execution::publication::verify_publication_interface(candidate, Vec::new()).unwrap();
    let mut object: Object = manifest.objects[1].object.clone();
    let scope: ProtocolCustodyScope = fee_escrow_scope(
        &protocol(),
        [0x71; 32],
        manifest.economics_policy.resources[0].resource_id,
    );
    object.owner = Owner::ProtocolCustody(scope.clone());
    let bytes: Vec<u8> = objects::encode_object(&object).unwrap();
    let digest: Digest32 = resolver()
        .hash_for_purpose(protocol().epoch(), HashPurpose::Object, &bytes)
        .unwrap();
    let snapshot = object_snapshots::ObjectSnapshot {
        head: DurableObjectHead::Current {
            head_revision: ObjectHeadRevision::FIRST,
            object_version: DurableObjectVersion::new(object.version).unwrap(),
            digest,
            owner_projection: DurableObjectOwnerProjection::from_owner(object.owner.clone())
                .unwrap(),
            routing_projection: DurableObjectRoutingProjection::default(),
        },
        object,
        created_checkpoint: 4,
        provenance: DurableObjectProvenance::new(
            protocol().chain_id().clone(),
            protocol().protocol_version(),
        ),
    };
    let recipient: Address =
        Address::new(ed25519_zebra::VerificationKey::from(&SigningKey::from([0x72; 32])).into());
    Fixture {
        interface,
        authority: manifest.objects[1].authority.clone(),
        snapshot,
        scope,
        recipient,
    }
}

fn data(value: u64) -> Vec<u8> {
    encode_call_value(
        &public_standard_asset::coin_body_layout(),
        &CallValue::U64(value),
    )
    .unwrap()
}

fn effects(object_effects: Vec<ObjectEffect>) -> ExecutionEffects {
    ExecutionEffects {
        tx_hash: Digest32::new(HashAlgorithmId::Sha2_256, [0; 32]),
        status: ExecutionStatus::Success,
        object_effects,
        events: Vec::new(),
        gas_used: 0,
    }
}

fn mutation(f: &Fixture, object: Object) -> ObjectEffect {
    ObjectEffect::Mutated {
        previous_version: f.snapshot.object.version,
        new_object: object,
    }
}

fn expected(f: &Fixture, amount: u64) -> ExpectedFeeClaim<'_> {
    ExpectedFeeClaim {
        escrow_id: f.snapshot.object.id,
        escrow_scope: &f.scope,
        resource_authority: &f.authority,
        recipient: f.recipient,
        unclaimed_before: 1_000_000,
        claim_amount: amount,
    }
}

fn final_effect(f: &Fixture) -> ExecutionEffects {
    let mut transferred: Object = f.snapshot.object.clone();
    transferred.version += 1;
    transferred.owner = Owner::Address(f.recipient);
    effects(vec![mutation(f, transferred)])
}

fn split_effect(f: &Fixture) -> (ExecutionEffects, Vec<CreatedObjectAuthority>) {
    let mut retained: Object = f.snapshot.object.clone();
    retained.version += 1;
    retained.data = data(600_000);
    let mut released: Object = f.snapshot.object.clone();
    released.id = ObjectId::new([0x73; 32]);
    released.version = 1;
    released.owner = Owner::Address(f.recipient);
    released.data = data(400_000);
    let mut authority: ObjectAuthority = f.authority.clone();
    authority.object_id = released.id;
    (
        effects(vec![mutation(f, retained), ObjectEffect::Created(released)]),
        vec![CreatedObjectAuthority {
            creation_ordinal: 0,
            authority,
        }],
    )
}

fn accepted(
    f: &Fixture,
    output: &ExecutionEffects,
    authorities: &[CreatedObjectAuthority],
    amount: u64,
    is_final: bool,
) -> bool {
    validate(
        &f.interface,
        authorities,
        &expected(f, amount),
        4,
        &f.snapshot,
        output,
        is_final,
    )
    .is_ok()
}

#[test]
fn final_effect_rejects_adversarial_shapes() {
    let f: Fixture = fixture();
    let baseline: ExecutionEffects = final_effect(&f);
    assert!(accepted(&f, &baseline, &[], 1_000_000, true));

    let mut cases: Vec<(&str, ExecutionEffects)> = Vec::new();
    let mut trapped: ExecutionEffects = baseline.clone();
    trapped.status = ExecutionStatus::Failure {
        reason: "trap".to_owned(),
    };
    cases.push(("trap", trapped));
    let mut event: ExecutionEffects = baseline.clone();
    event.events.push(EventRecord {
        type_tag: vec![1],
        data: vec![2],
    });
    cases.push(("event", event));
    cases.push(("no mutation", effects(Vec::new())));
    cases.push((
        "duplicate mutation",
        effects(vec![baseline.object_effects[0].clone(); 2]),
    ));
    let ObjectEffect::Mutated { new_object, .. } = &baseline.object_effects[0] else {
        unreachable!()
    };
    cases.push((
        "creation",
        effects(vec![ObjectEffect::Created(new_object.clone())]),
    ));

    for (name, change) in [
        (
            "wrong id",
            Box::new(|object: &mut Object| object.id = ObjectId::new([0x74; 32]))
                as Box<dyn Fn(&mut Object)>,
        ),
        (
            "wrong version",
            Box::new(|object: &mut Object| object.version += 1),
        ),
        (
            "wrong owner",
            Box::new(|object: &mut Object| object.owner = Owner::Address(Address::new([0x75; 32]))),
        ),
        (
            "wrong type",
            Box::new(|object: &mut Object| {
                object.type_hash = Digest32::new(HashAlgorithmId::Sha2_256, [0x76; 32])
            }),
        ),
        (
            "wrong schema",
            Box::new(|object: &mut Object| object.schema_version += 1),
        ),
        (
            "wrong value",
            Box::new(|object: &mut Object| object.data = data(999_999)),
        ),
    ] {
        let mut altered: Object = new_object.clone();
        change(&mut altered);
        cases.push((name, effects(vec![mutation(&f, altered)])));
    }
    for (name, output) in cases {
        assert!(!accepted(&f, &output, &[], 1_000_000, true), "{name}");
    }
    assert!(!accepted(&f, &baseline, &[], 400_000, true));
    let (split, authorities) = split_effect(&f);
    assert!(!accepted(&f, &split, &authorities, 1_000_000, true));
    assert!(!accepted(&f, &baseline, &authorities, 1_000_000, true));
}

#[test]
fn split_effect_rejects_adversarial_shapes() {
    let f: Fixture = fixture();
    let (baseline, authorities): (ExecutionEffects, Vec<CreatedObjectAuthority>) = split_effect(&f);
    assert!(accepted(&f, &baseline, &authorities, 400_000, false));
    let mut reversed: ExecutionEffects = baseline.clone();
    reversed.object_effects.reverse();
    assert!(accepted(&f, &reversed, &authorities, 400_000, false));
    assert!(!accepted(&f, &baseline, &[], 400_000, false));
    assert!(!accepted(
        &f,
        &baseline,
        &vec![authorities[0].clone(); 2],
        400_000,
        false
    ));
    assert!(!accepted(&f, &baseline, &authorities, 500_000, false));
    assert!(!accepted(&f, &final_effect(&f), &[], 400_000, false));

    let mut altered: ExecutionEffects = baseline.clone();
    let ObjectEffect::Mutated {
        new_object: retained,
        ..
    } = &mut altered.object_effects[0]
    else {
        unreachable!()
    };
    retained.owner = Owner::Address(f.recipient);
    assert!(!accepted(&f, &altered, &authorities, 400_000, false));
    let mut altered: ExecutionEffects = baseline.clone();
    let ObjectEffect::Mutated {
        new_object: retained,
        ..
    } = &mut altered.object_effects[0]
    else {
        unreachable!()
    };
    retained.data = data(600_001);
    assert!(!accepted(&f, &altered, &authorities, 400_000, false));
    let mut altered: ExecutionEffects = baseline.clone();
    let ObjectEffect::Created(released) = &mut altered.object_effects[1] else {
        unreachable!()
    };
    released.owner = Owner::Address(Address::new([0x77; 32]));
    assert!(!accepted(&f, &altered, &authorities, 400_000, false));
    let mut altered: ExecutionEffects = baseline.clone();
    let ObjectEffect::Created(released) = &mut altered.object_effects[1] else {
        unreachable!()
    };
    released.data = data(0);
    assert!(!accepted(&f, &altered, &authorities, 400_000, false));
    let mut altered: ExecutionEffects = baseline.clone();
    let ObjectEffect::Created(released) = &mut altered.object_effects[1] else {
        unreachable!()
    };
    released.schema_version += 1;
    assert!(!accepted(&f, &altered, &authorities, 400_000, false));
    let mut wrong_authority: Vec<CreatedObjectAuthority> = authorities.clone();
    wrong_authority[0].authority.object_id = ObjectId::new([0x78; 32]);
    assert!(!accepted(&f, &baseline, &wrong_authority, 400_000, false));
    let mut wrong_authority: Vec<CreatedObjectAuthority> = authorities.clone();
    wrong_authority[0].authority.ty = crate::genesis::tests::build_fixture().0.objects[0]
        .authority
        .ty
        .clone();
    assert!(!accepted(&f, &baseline, &wrong_authority, 400_000, false));
}
