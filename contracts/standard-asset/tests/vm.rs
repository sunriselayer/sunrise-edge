use abi::call_values::{CallValue, encode_call_value};
use abi::package_types::PackageOrigin;
use abi::package_types::ScopedTypeArg;
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::call::CallIntent;
use execution::call_authorization::*;
use execution::local_execution::*;
use execution::publication::*;
use execution::{ExecutionStatus, LocalWasmExecutionEngine, ObjectEffect, ResolvedObject};
use hashing::HashSuiteResolver;
use objects::{AccessMode, ObjectId, ObjectRef};
use protocol_types::{
    ChainId, Digest32, Epoch, HashAlgorithmId, HashPurpose, HashSuite, HashSuiteSchedule,
    ProtocolVersion,
};
use public_standard_asset::*;
fn key() -> SigningKey {
    SigningKey::from([7; 32])
}
fn sender() -> [u8; 32] {
    VerificationKey::from(&key()).into()
}
fn other_recipient() -> [u8; 32] {
    VerificationKey::from(&SigningKey::from([9; 32])).into()
}
fn context() -> PublicationContext {
    PublicationContext::new(
        ChainId::new("general-vm").unwrap(),
        ProtocolVersion::new(3),
        Epoch::new(0),
    )
    .unwrap()
}
fn resolver() -> HashSuiteResolver {
    HashSuiteResolver::new(
        context().chain_id().clone(),
        context().protocol_version(),
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .unwrap()
}
fn origin(seed: u8) -> PackageOrigin {
    PackageOrigin::unverified(context().chain_id().clone(), sender(), [seed; 32]).unwrap()
}
fn reference(candidate: &AuthenticatedPublicationCandidate) -> UnverifiedDependencyRef {
    let artifact = candidate.request().artifact();
    UnverifiedDependencyRef::new(
        artifact.origin().clone(),
        1,
        context(),
        *candidate.request().artifact_digest(),
    )
    .unwrap()
}
fn publish() -> AuthenticatedPublicationCandidate {
    let package: StandardAssetPackage = build_package(&origin(1)).unwrap();
    let semantics = generic_object_result_semantics(&resolver(), &context()).unwrap();
    let artifact = CodeArtifact::new(ArtifactParts {
        context: context(),
        origin: origin(1),
        revision: 1,
        wasm_profile: 4,
        semantics,
        wasm: package.wasm,
        unverified_abi: package.encoded_abi,
        exports: package.exports,
        unverified_dependencies: vec![],
    })
    .unwrap();
    let digest = artifact_commitment(&resolver(), &context(), &artifact).unwrap();
    let frame =
        publication_submission_signing_frame(&resolver(), &context(), &artifact, 0, [1; 32])
            .unwrap();
    authenticate_publication_submission(
        &resolver(),
        &context(),
        &semantics,
        PublicationSubmission::new(
            [1; 32],
            PublicationRequest::new(artifact, 0, digest, key().sign(&frame).into()),
        )
        .unwrap(),
    )
    .unwrap()
}
fn scope(
    candidate: AuthenticatedPublicationCandidate,
    dependencies: Vec<AuthenticatedPublicationCandidate>,
    seed: u8,
    initializer: &str,
) -> ResolvedExecutionScope {
    let instance = InstanceRecord {
        context: context(),
        creator: sender(),
        seed: [seed; 32],
        code: reference(&candidate),
        revision: 1,
        initializer: initializer.into(),
    };
    ResolvedExecutionScope {
        target: instance_target(&resolver(), &instance).unwrap(),
        instance,
        interface: verify_publication_interface(candidate, dependencies).unwrap(),
    }
}
fn run(
    scopes: Vec<ResolvedExecutionScope>,
    entry: &str,
    args: Vec<u8>,
    inputs: &[ScopedResolvedObject],
    authorizations: Vec<CallAuthorization>,
    gas: u64,
    type_arguments: Vec<ScopedTypeArg>,
) -> Result<LocalExecutionOutcome, LocalExecutionError> {
    let resolver = resolver();
    let policy = LocalExecutionPolicy::generic_object_results(context());
    let root = &scopes[0];
    let access = abi::AccessManifest {
        entries: inputs
            .iter()
            .map(|input| abi::AccessEntry {
                mode: input.resolved.mode,
                object_ref: ObjectRef {
                    id: input.resolved.object.id,
                    version: input.resolved.object.version,
                    digest: resolver
                        .hash_for_purpose(
                            Epoch::new(0),
                            HashPurpose::Object,
                            &objects::encode_object(&input.resolved.object).unwrap(),
                        )
                        .unwrap(),
                },
            })
            .collect(),
    };
    let call = CallIntent {
        context: context(),
        request_id: [5; 32],
        sender: sender(),
        nonce: 0,
        code: root.instance.code.clone(),
        instance: root.target.clone(),
        entrypoint: entry.into(),
        type_arguments,
        access,
        arguments: args,
        gas_limit: gas,
    };
    let intent = LocalExecutionIntent {
        mode: if entry == root.instance.initializer {
            LocalExecutionMode::Instantiate
        } else {
            LocalExecutionMode::Call
        },
        policy_digest: policy.digest(&resolver).unwrap(),
        call,
        authorizations,
    };
    let signature = key()
        .sign(&local_execution_signing_frame(&context(), &intent)?)
        .into();
    let signed = SignedLocalExecutionIntent { intent, signature };
    let authenticated =
        authenticate_local_execution(&resolver, &policy, &encode_signed_local_execution(&signed)?)?;
    LocalWasmExecutionEngine::new().execute(LocalExecutionRequest {
        scopes: &scopes,
        intent: &authenticated,
        resolver: &resolver,
        policy: &policy,
        event_digest: local_execution_event_digest(&resolver, &signed)?,
        inputs,
    })
}
fn created(
    outcome: &LocalExecutionOutcome,
    index: usize,
    mode: AccessMode,
) -> ScopedResolvedObject {
    let object = outcome
        .effects
        .object_effects
        .iter()
        .filter_map(|effect| match effect {
            ObjectEffect::Created(object) => Some(object),
            _ => None,
        })
        .nth(index)
        .unwrap()
        .clone();
    let authority = outcome
        .created_authorities
        .iter()
        .find(|created| created.authority.object_id == object.id)
        .unwrap()
        .authority
        .clone();
    ScopedResolvedObject {
        resolved: ResolvedObject { object, mode },
        authority,
    }
}
fn mutated(outcome: &LocalExecutionOutcome, prior: &ScopedResolvedObject) -> ScopedResolvedObject {
    let mut next: ScopedResolvedObject = prior.clone();
    next.resolved.object = outcome
        .effects
        .object_effects
        .iter()
        .find_map(|effect| match effect {
            ObjectEffect::Mutated { new_object, .. }
                if new_object.id == prior.resolved.object.id =>
            {
                Some(new_object.clone())
            }
            _ => None,
        })
        .unwrap();
    next
}
fn try_call(
    root: &ResolvedExecutionScope,
    name: &str,
    args: Vec<u8>,
    inputs: &[ScopedResolvedObject],
    asset: Option<ObjectId>,
) -> Result<LocalExecutionOutcome, LocalExecutionError> {
    let types: Vec<ScopedTypeArg> = asset
        .map(|id| vec![asset_type_argument(&id)])
        .unwrap_or_default();
    run(
        vec![root.clone()],
        name,
        args,
        inputs,
        vec![],
        MAX_LOCAL_EXECUTION_GAS,
        types,
    )
}
fn call(
    root: &ResolvedExecutionScope,
    name: &str,
    args: Vec<u8>,
    inputs: &[ScopedResolvedObject],
    asset: Option<ObjectId>,
) -> LocalExecutionOutcome {
    try_call(root, name, args, inputs, asset).unwrap()
}
#[track_caller]
fn success(outcome: &LocalExecutionOutcome) {
    assert_eq!(outcome.effects.status, ExecutionStatus::Success);
}
#[track_caller]
fn trapped(outcome: &LocalExecutionOutcome) {
    assert!(
        matches!(outcome.effects.status, ExecutionStatus::Failure { .. }),
        "expected a trapped execution, got {:?}",
        outcome.effects.status
    );
    assert!(outcome.effects.object_effects.is_empty());
    assert!(outcome.effects.events.is_empty());
}
fn created_count(outcome: &LocalExecutionOutcome) -> usize {
    outcome
        .effects
        .object_effects
        .iter()
        .filter(|effect| matches!(effect, ObjectEffect::Created(_)))
        .count()
}
/// Publishes and initializes a fresh instance, returning its scope, asset
/// identity, and zero-supply `TreasuryCap`.
fn init_asset(instance_seed: u8) -> (ResolvedExecutionScope, ObjectId, ScopedResolvedObject) {
    let root: ResolvedExecutionScope = scope(publish(), vec![], instance_seed, "init");
    let init: LocalExecutionOutcome = call(&root, "init", no_arguments().unwrap(), &[], None);
    success(&init);
    let definition: ScopedResolvedObject = created(&init, 0, AccessMode::Read);
    let asset: ObjectId = definition.resolved.object.id;
    let cap: ScopedResolvedObject = created(&init, 1, AccessMode::Write);
    assert_eq!(treasury_supply(&cap.resolved.object.data).unwrap(), 0);
    (root, asset, cap)
}
fn invocation_digest() -> Digest32 {
    resolver()
        .hash_for_purpose(Epoch::new(0), HashPurpose::Object, b"invocation")
        .unwrap()
}
fn policy_digest() -> Digest32 {
    resolver()
        .hash_for_purpose(Epoch::new(0), HashPurpose::Object, b"policy")
        .unwrap()
}
/// The expected `type_hash` of a `Coin<asset>` object, computed independently
/// of the guest so tests can assert created objects carry the exact nominal
/// type rather than merely decoding as a `u64` body.
fn coin_type_hash(asset: &ObjectId) -> Digest32 {
    let tag = coin_type_tag(&origin(1), asset).unwrap();
    abi::package_types::derive_scoped_type_id(&resolver(), Epoch::new(0), &tag).unwrap()
}
fn deleted_ids(outcome: &LocalExecutionOutcome) -> Vec<ObjectId> {
    outcome
        .effects
        .object_effects
        .iter()
        .filter_map(|effect| match effect {
            ObjectEffect::Deleted { id, .. } => Some(*id),
            _ => None,
        })
        .collect()
}
/// Encodes one raw field header (id, length) followed by its raw bytes,
/// independent of `CanonicalStruct`, which always sorts fields by id and so
/// cannot itself produce a non-canonically ordered frame for testing.
fn raw_field(id: u16, len: u32, bytes: &[u8]) -> Vec<u8> {
    let mut field = Vec::new();
    field.extend_from_slice(&id.to_le_bytes());
    field.extend_from_slice(&len.to_le_bytes());
    field.extend_from_slice(bytes);
    field
}
/// Builds a raw `0x0103`/v1 canonical frame byte-for-byte, so tests can
/// exercise shapes `canonical_encoding::encode_digest32` can never produce:
/// an unknown algorithm id, a mismatched declared field count, physically
/// reordered fields, or mismatched field lengths.
fn digest_frame(
    field_count: u16,
    reversed: bool,
    algorithm_len: u32,
    algorithm_bytes: &[u8],
    digest_len: u32,
    digest_bytes: &[u8],
) -> Vec<u8> {
    let field1 = raw_field(1, algorithm_len, algorithm_bytes);
    let field2 = raw_field(2, digest_len, digest_bytes);
    let mut frame = Vec::new();
    frame.extend_from_slice(b"SNRE");
    frame.extend_from_slice(&0x0103u16.to_le_bytes());
    frame.extend_from_slice(&1u16.to_le_bytes());
    frame.extend_from_slice(&field_count.to_le_bytes());
    if reversed {
        frame.extend_from_slice(&field2);
        frame.extend_from_slice(&field1);
    } else {
        frame.extend_from_slice(&field1);
        frame.extend_from_slice(&field2);
    }
    frame
}
/// Malformed 56-byte digest frames that must be rejected by every layer
/// that decodes an attested digest: the guest's fixed-offset `$digest`
/// walker, and the native `canonical_encoding::decode_digest32` call in
/// `arguments::digest_field`. Every variant is exactly 56 bytes, matching
/// the `ENCODED_DIGEST32_BYTES` argument/body layout, so only the framing
/// itself is under test, not the outer length bound.
fn malformed_digest_variants() -> Vec<(&'static str, Vec<u8>)> {
    let variants: Vec<(&'static str, Vec<u8>)> = vec![
        (
            "unknown_algorithm_id",
            digest_frame(2, false, 2, &4u16.to_le_bytes(), 32, &[0xCD; 32]),
        ),
        (
            "non_canonical_field_count",
            digest_frame(1, false, 2, &1u16.to_le_bytes(), 32, &[0xCD; 32]),
        ),
        (
            "reversed_field_order",
            digest_frame(2, true, 2, &1u16.to_le_bytes(), 32, &[0xCD; 32]),
        ),
        (
            "mismatched_field_lengths",
            digest_frame(2, false, 1, &[0x01], 33, &[0xCD; 33]),
        ),
    ];
    for (name, bytes) in &variants {
        assert_eq!(bytes.len(), 56, "{name}: variant must stay 56 bytes");
    }
    variants
}
#[test]
fn guest_asset_lifecycle_and_reservation_conserve_supply() {
    let root: ResolvedExecutionScope = scope(publish(), vec![], 3, "init");
    let init: LocalExecutionOutcome = call(&root, "init", no_arguments().unwrap(), &[], None);
    success(&init);
    let definition: ScopedResolvedObject = created(&init, 0, AccessMode::Read);
    let asset: objects::ObjectId = definition.resolved.object.id;
    let cap: ScopedResolvedObject = created(&init, 1, AccessMode::Write);
    assert_eq!(treasury_supply(&cap.resolved.object.data).unwrap(), 0);
    let mint: LocalExecutionOutcome = call(
        &root,
        "mint",
        mint_arguments(100, &sender()).unwrap(),
        std::slice::from_ref(&cap),
        Some(asset),
    );
    success(&mint);
    let cap: ScopedResolvedObject = mutated(&mint, &cap);
    assert_eq!(treasury_supply(&cap.resolved.object.data).unwrap(), 100);
    let coin: ScopedResolvedObject = created(&mint, 0, AccessMode::Write);
    assert_eq!(coin_amount(&coin.resolved.object.data).unwrap(), 100);
    let invocation = resolver()
        .hash_for_purpose(Epoch::new(0), HashPurpose::Object, b"invocation")
        .unwrap();
    let policy = resolver()
        .hash_for_purpose(Epoch::new(0), HashPurpose::Object, b"policy")
        .unwrap();
    let reserve: LocalExecutionOutcome = call(
        &root,
        "reserve",
        reserve_arguments(40, &invocation, &policy, &sender(), &sender()).unwrap(),
        std::slice::from_ref(&coin),
        Some(asset),
    );
    success(&reserve);
    let remainder: ScopedResolvedObject = mutated(&reserve, &coin);
    assert_eq!(coin_amount(&remainder.resolved.object.data).unwrap(), 60);
    let reservation: ScopedResolvedObject = created(&reserve, 0, AccessMode::Consume);
    assert_eq!(
        reservation_body(&reservation.resolved.object.data)
            .unwrap()
            .reserved,
        40
    );
    let reservation_id: objects::ObjectId = reservation.resolved.object.id;
    let settled: LocalExecutionOutcome = call(
        &root,
        "settle",
        settle_arguments(15, &invocation, &policy).unwrap(),
        &[reservation],
        Some(asset),
    );
    success(&settled);
    // The consumed Reservation must appear as Deleted, not merely absent
    // from the created list: no surviving reservation remains.
    assert_eq!(deleted_ids(&settled), vec![reservation_id]);
    let fee: ScopedResolvedObject = created(&settled, 0, AccessMode::Read);
    let refund: ScopedResolvedObject = created(&settled, 1, AccessMode::Read);
    assert_eq!(coin_amount(&fee.resolved.object.data).unwrap(), 15);
    assert_eq!(coin_amount(&refund.resolved.object.data).unwrap(), 25);
    // Both the fee and refund coins are owned by the pinned recipients and
    // carry the exact Coin<asset> nominal type, not merely a u64 body.
    let sender_owner = objects::Owner::Address(objects::Address::new(sender()));
    assert_eq!(fee.resolved.object.owner, sender_owner);
    assert_eq!(refund.resolved.object.owner, sender_owner);
    let expected_type = coin_type_hash(&asset);
    assert_eq!(fee.resolved.object.type_hash, expected_type);
    assert_eq!(refund.resolved.object.type_hash, expected_type);
}

#[test]
fn all_nine_exports_conserve_supply_across_split_merge_transfer_and_burn() {
    let (root, asset, cap) = init_asset(10);
    let mint: LocalExecutionOutcome = call(
        &root,
        "mint",
        mint_arguments(100, &sender()).unwrap(),
        std::slice::from_ref(&cap),
        Some(asset),
    );
    success(&mint);
    let cap: ScopedResolvedObject = mutated(&mint, &cap);
    assert_eq!(treasury_supply(&cap.resolved.object.data).unwrap(), 100);
    let coin: ScopedResolvedObject = created(&mint, 0, AccessMode::Write);

    // split: 100 -> remainder 70, new coin 30.
    let split: LocalExecutionOutcome = call(
        &root,
        "split",
        split_arguments(30, &sender()).unwrap(),
        std::slice::from_ref(&coin),
        Some(asset),
    );
    success(&split);
    let remainder: ScopedResolvedObject = mutated(&split, &coin);
    assert_eq!(coin_amount(&remainder.resolved.object.data).unwrap(), 70);
    let piece: ScopedResolvedObject = created(&split, 0, AccessMode::Write);
    assert_eq!(coin_amount(&piece.resolved.object.data).unwrap(), 30);

    // merge: piece back into remainder -> 100 again, piece consumed.
    let mut piece: ScopedResolvedObject = piece;
    piece.resolved.mode = AccessMode::Consume;
    let merge: LocalExecutionOutcome = call(
        &root,
        "merge",
        no_arguments().unwrap(),
        &[remainder.clone(), piece],
        Some(asset),
    );
    success(&merge);
    let coin: ScopedResolvedObject = mutated(&merge, &remainder);
    assert_eq!(coin_amount(&coin.resolved.object.data).unwrap(), 100);

    // transfer: ownership changes, amount is conserved.
    let transfer: LocalExecutionOutcome = call(
        &root,
        "transfer",
        transfer_arguments(&other_recipient()).unwrap(),
        std::slice::from_ref(&coin),
        Some(asset),
    );
    success(&transfer);
    let transferred: ScopedResolvedObject = mutated(&transfer, &coin);
    assert_eq!(coin_amount(&transferred.resolved.object.data).unwrap(), 100);
    assert_eq!(
        transferred.resolved.object.owner,
        objects::Owner::Address(objects::Address::new(other_recipient()))
    );

    // mint a second coin, burn it entirely, and verify supply conservation.
    let mint2: LocalExecutionOutcome = call(
        &root,
        "mint",
        mint_arguments(40, &sender()).unwrap(),
        std::slice::from_ref(&cap),
        Some(asset),
    );
    success(&mint2);
    let cap: ScopedResolvedObject = mutated(&mint2, &cap);
    assert_eq!(treasury_supply(&cap.resolved.object.data).unwrap(), 140);
    let burn_coin: ScopedResolvedObject = created(&mint2, 0, AccessMode::Write);
    let mut burn_coin: ScopedResolvedObject = burn_coin;
    burn_coin.resolved.mode = AccessMode::Consume;
    let burn: LocalExecutionOutcome = call(
        &root,
        "burn",
        no_arguments().unwrap(),
        &[cap.clone(), burn_coin],
        Some(asset),
    );
    success(&burn);
    let cap: ScopedResolvedObject = mutated(&burn, &cap);
    assert_eq!(treasury_supply(&cap.resolved.object.data).unwrap(), 100);
}

#[test]
fn exact_full_reserve_via_reserve_all_settles_with_no_refund() {
    let (root, asset, cap) = init_asset(11);
    let mint: LocalExecutionOutcome = call(
        &root,
        "mint",
        mint_arguments(50, &sender()).unwrap(),
        &[cap],
        Some(asset),
    );
    success(&mint);
    let coin: ScopedResolvedObject = created(&mint, 0, AccessMode::Write);
    let invocation = invocation_digest();
    let policy = policy_digest();
    let coin_id: objects::ObjectId = coin.resolved.object.id;
    let reserve_all: LocalExecutionOutcome = call(
        &root,
        "reserve_all",
        reserve_arguments(50, &invocation, &policy, &sender(), &sender()).unwrap(),
        &[ScopedResolvedObject {
            resolved: ResolvedObject {
                mode: AccessMode::Consume,
                ..coin.resolved
            },
            authority: coin.authority,
        }],
        Some(asset),
    );
    success(&reserve_all);
    // The source Coin is consumed, not mutated: no mutation effect for it.
    assert_eq!(deleted_ids(&reserve_all), vec![coin_id]);
    let reservation: ScopedResolvedObject = created(&reserve_all, 0, AccessMode::Consume);
    assert_eq!(
        reservation_body(&reservation.resolved.object.data)
            .unwrap()
            .reserved,
        50
    );
    let reservation_id: objects::ObjectId = reservation.resolved.object.id;
    let settle: LocalExecutionOutcome = call(
        &root,
        "settle",
        settle_arguments(50, &invocation, &policy).unwrap(),
        &[reservation],
        Some(asset),
    );
    success(&settle);
    // The consumed Reservation must appear as Deleted: no surviving
    // reservation remains after settlement.
    assert_eq!(deleted_ids(&settle), vec![reservation_id]);
    // Exactly one created object (the fee coin); no refund slot is filled.
    assert_eq!(created_count(&settle), 1);
    let fee: ScopedResolvedObject = created(&settle, 0, AccessMode::Read);
    assert_eq!(coin_amount(&fee.resolved.object.data).unwrap(), 50);
    assert_eq!(
        fee.resolved.object.owner,
        objects::Owner::Address(objects::Address::new(sender()))
    );
    assert_eq!(fee.resolved.object.type_hash, coin_type_hash(&asset));
}

#[test]
fn zero_and_overflow_amounts_trap_and_leave_no_effects() {
    let (root, asset, cap) = init_asset(12);

    // mint(0) bypasses the client helper's positivity guard directly.
    let zero_mint_args = encode_call_value(
        &mint_argument_layout(),
        &CallValue::Tuple(vec![CallValue::U64(0), CallValue::Bytes(sender().to_vec())]),
    )
    .unwrap();
    let outcome = call(
        &root,
        "mint",
        zero_mint_args,
        std::slice::from_ref(&cap),
        Some(asset),
    );
    trapped(&outcome);

    // mint(u64::MAX) succeeds once, then a second mint overflows checked u64 addition.
    let mint_max: LocalExecutionOutcome = call(
        &root,
        "mint",
        mint_arguments(u64::MAX, &sender()).unwrap(),
        std::slice::from_ref(&cap),
        Some(asset),
    );
    success(&mint_max);
    let cap: ScopedResolvedObject = mutated(&mint_max, &cap);
    assert_eq!(
        treasury_supply(&cap.resolved.object.data).unwrap(),
        u64::MAX
    );
    let overflow_mint: LocalExecutionOutcome = call(
        &root,
        "mint",
        mint_arguments(1, &sender()).unwrap(),
        std::slice::from_ref(&cap),
        Some(asset),
    );
    trapped(&overflow_mint);

    // split requires a strict partial amount: amount == held must trap.
    let full_coin: ScopedResolvedObject = created(&mint_max, 0, AccessMode::Write);
    let non_partial_split: LocalExecutionOutcome = call(
        &root,
        "split",
        split_arguments(u64::MAX, &sender()).unwrap(),
        std::slice::from_ref(&full_coin),
        Some(asset),
    );
    trapped(&non_partial_split);

    // split(0) bypasses the client helper directly.
    let zero_split_args = encode_call_value(
        &split_argument_layout(),
        &CallValue::Tuple(vec![CallValue::U64(0), CallValue::Bytes(sender().to_vec())]),
    )
    .unwrap();
    let zero_split: LocalExecutionOutcome = call(
        &root,
        "split",
        zero_split_args,
        std::slice::from_ref(&full_coin),
        Some(asset),
    );
    trapped(&zero_split);

    // reserve requires 0 < reserved < balance: reserved == balance must trap.
    let invocation = invocation_digest();
    let policy = policy_digest();
    let non_strict_reserve: LocalExecutionOutcome = call(
        &root,
        "reserve",
        reserve_arguments(u64::MAX, &invocation, &policy, &sender(), &sender()).unwrap(),
        std::slice::from_ref(&full_coin),
        Some(asset),
    );
    trapped(&non_strict_reserve);

    // reserve(0) bypasses the client helper directly.
    let zero_reserve_args = encode_call_value(
        &reserve_argument_layout(),
        &CallValue::Tuple(vec![
            CallValue::U64(0),
            CallValue::Bytes(canonical_encoding::encode_digest32(&invocation).unwrap()),
            CallValue::Bytes(canonical_encoding::encode_digest32(&policy).unwrap()),
            CallValue::Bytes(sender().to_vec()),
            CallValue::Bytes(sender().to_vec()),
        ]),
    )
    .unwrap();
    let zero_reserve: LocalExecutionOutcome = call(
        &root,
        "reserve",
        zero_reserve_args,
        std::slice::from_ref(&full_coin),
        Some(asset),
    );
    trapped(&zero_reserve);

    // reserve_all requires reserved == balance: a smaller claim must trap.
    let mismatched_reserve_all: LocalExecutionOutcome = call(
        &root,
        "reserve_all",
        reserve_arguments(1, &invocation, &policy, &sender(), &sender()).unwrap(),
        &[ScopedResolvedObject {
            resolved: ResolvedObject {
                mode: AccessMode::Consume,
                ..full_coin.resolved.clone()
            },
            authority: full_coin.authority.clone(),
        }],
        Some(asset),
    );
    trapped(&mismatched_reserve_all);

    // A valid reservation, then adversarial settlements against it.
    let reserve: LocalExecutionOutcome = call(
        &root,
        "reserve",
        reserve_arguments(10, &invocation, &policy, &sender(), &sender()).unwrap(),
        &[full_coin],
        Some(asset),
    );
    success(&reserve);
    let reservation: ScopedResolvedObject = created(&reserve, 0, AccessMode::Consume);

    // settle(0) bypasses the client helper directly.
    let zero_settle_args = encode_call_value(
        &settle_argument_layout(),
        &CallValue::Tuple(vec![
            CallValue::U64(0),
            CallValue::Bytes(canonical_encoding::encode_digest32(&invocation).unwrap()),
            CallValue::Bytes(canonical_encoding::encode_digest32(&policy).unwrap()),
        ]),
    )
    .unwrap();
    let zero_settle: LocalExecutionOutcome = call(
        &root,
        "settle",
        zero_settle_args,
        std::slice::from_ref(&reservation),
        Some(asset),
    );
    trapped(&zero_settle);

    // settle(actual > reserved) must trap.
    let over_settle: LocalExecutionOutcome = call(
        &root,
        "settle",
        settle_arguments(11, &invocation, &policy).unwrap(),
        &[reservation],
        Some(asset),
    );
    trapped(&over_settle);
}

#[test]
fn malformed_digest_bytes_are_rejected_as_reservation_commitments() {
    let (root, asset, cap) = init_asset(13);
    let mint: LocalExecutionOutcome = call(
        &root,
        "mint",
        mint_arguments(100, &sender()).unwrap(),
        &[cap],
        Some(asset),
    );
    success(&mint);
    let coin: ScopedResolvedObject = created(&mint, 0, AccessMode::Write);

    // Bypasses `reserve_arguments`: the digest fields are 56 bytes of the
    // right *length* but not a canonical self-describing Digest32 frame
    // (no "SNRE" magic, no 0x0103 header). The guest must reject this
    // shape, not accept any 56-byte blob as an attested commitment.
    let garbage_reserve_args = encode_call_value(
        &reserve_argument_layout(),
        &CallValue::Tuple(vec![
            CallValue::U64(40),
            CallValue::Bytes(vec![0u8; 56]),
            CallValue::Bytes(vec![0u8; 56]),
            CallValue::Bytes(sender().to_vec()),
            CallValue::Bytes(sender().to_vec()),
        ]),
    )
    .unwrap();
    let outcome = call(&root, "reserve", garbage_reserve_args, &[coin], Some(asset));
    trapped(&outcome);
}

#[test]
fn settle_commitment_mismatch_traps() {
    let (root, asset, cap) = init_asset(14);
    let mint: LocalExecutionOutcome = call(
        &root,
        "mint",
        mint_arguments(100, &sender()).unwrap(),
        &[cap],
        Some(asset),
    );
    success(&mint);
    let coin: ScopedResolvedObject = created(&mint, 0, AccessMode::Write);
    let invocation = invocation_digest();
    let policy = policy_digest();
    let reserve: LocalExecutionOutcome = call(
        &root,
        "reserve",
        reserve_arguments(40, &invocation, &policy, &sender(), &sender()).unwrap(),
        &[coin],
        Some(asset),
    );
    success(&reserve);
    let reservation: ScopedResolvedObject = created(&reserve, 0, AccessMode::Consume);

    let wrong_invocation = resolver()
        .hash_for_purpose(Epoch::new(0), HashPurpose::Object, b"different-invocation")
        .unwrap();
    let outcome = call(
        &root,
        "settle",
        settle_arguments(15, &wrong_invocation, &policy).unwrap(),
        &[reservation],
        Some(asset),
    );
    trapped(&outcome);
}

#[test]
fn malformed_call_arguments_are_rejected_before_execution() {
    let (root, asset, cap) = init_asset(15);
    let mint: LocalExecutionOutcome = call(
        &root,
        "mint",
        mint_arguments(100, &sender()).unwrap(),
        &[cap],
        Some(asset),
    );
    success(&mint);
    let coin: ScopedResolvedObject = created(&mint, 0, AccessMode::Write);

    // Trailing bytes after a validly encoded argument tuple must be
    // rejected before the guest ever runs, not merely ignored.
    let mut malformed = transfer_arguments(&sender()).unwrap();
    malformed.push(0);
    let root2 = root.clone();
    let result = try_call(&root2, "transfer", malformed, &[coin], Some(asset));
    assert!(result.is_err());
}

#[test]
fn wrong_asset_type_argument_is_rejected_before_execution() {
    let (root_a, asset_a, cap_a) = init_asset(16);
    let (_root_b, asset_b, _cap_b) = init_asset(17);
    let mint: LocalExecutionOutcome = call(
        &root_a,
        "mint",
        mint_arguments(100, &sender()).unwrap(),
        &[cap_a],
        Some(asset_a),
    );
    success(&mint);
    let coin: ScopedResolvedObject = created(&mint, 0, AccessMode::Write);

    // The Coin<asset_a> object is bound against asset_b's type argument.
    let result = try_call(
        &root_a,
        "transfer",
        transfer_arguments(&sender()).unwrap(),
        &[coin],
        Some(asset_b),
    );
    assert!(result.is_err());
}

#[test]
fn wrong_object_type_is_rejected_before_execution() {
    let (root, asset, cap) = init_asset(18);
    let mint: LocalExecutionOutcome = call(
        &root,
        "mint",
        mint_arguments(100, &sender()).unwrap(),
        std::slice::from_ref(&cap),
        Some(asset),
    );
    success(&mint);
    let coin: ScopedResolvedObject = created(&mint, 0, AccessMode::Write);

    // `transfer` declares a Coin parameter; supplying the TreasuryCap
    // itself (a different constructor of the same asset) must not bind.
    let result = try_call(
        &root,
        "transfer",
        transfer_arguments(&sender()).unwrap(),
        &[cap],
        Some(asset),
    );
    assert!(result.is_err());

    // `merge` declares two Coin parameters; supplying a Reservation as the
    // consumed source must not bind either, keeping Reservation private
    // to `settle`.
    let invocation = invocation_digest();
    let policy = policy_digest();
    let reserve: LocalExecutionOutcome = call(
        &root,
        "reserve",
        reserve_arguments(40, &invocation, &policy, &sender(), &sender()).unwrap(),
        std::slice::from_ref(&coin),
        Some(asset),
    );
    success(&reserve);
    let remainder: ScopedResolvedObject = mutated(&reserve, &coin);
    let reservation: ScopedResolvedObject = created(&reserve, 0, AccessMode::Consume);
    let result = try_call(
        &root,
        "merge",
        no_arguments().unwrap(),
        &[remainder, reservation],
        Some(asset),
    );
    assert!(result.is_err());
}

#[test]
fn wrong_access_mode_is_rejected_before_execution() {
    let (root, asset, cap) = init_asset(19);
    // `mint` declares TreasuryCap Write; supplying only Read must not bind.
    let mut read_only_cap: ScopedResolvedObject = cap;
    read_only_cap.resolved.mode = AccessMode::Read;
    let result = try_call(
        &root,
        "mint",
        mint_arguments(1, &sender()).unwrap(),
        &[read_only_cap],
        Some(asset),
    );
    assert!(result.is_err());
}

#[test]
fn malformed_digest_frames_are_rejected_by_reserve_and_reserve_all() {
    let (root, asset, cap) = init_asset(20);
    let mint: LocalExecutionOutcome = call(
        &root,
        "mint",
        mint_arguments(100, &sender()).unwrap(),
        &[cap],
        Some(asset),
    );
    success(&mint);
    let coin: ScopedResolvedObject = created(&mint, 0, AccessMode::Write);
    let policy = policy_digest();

    for (name, malformed) in malformed_digest_variants() {
        let args = encode_call_value(
            &reserve_argument_layout(),
            &CallValue::Tuple(vec![
                CallValue::U64(40),
                CallValue::Bytes(malformed),
                CallValue::Bytes(canonical_encoding::encode_digest32(&policy).unwrap()),
                CallValue::Bytes(sender().to_vec()),
                CallValue::Bytes(sender().to_vec()),
            ]),
        )
        .unwrap();
        let outcome = call(
            &root,
            "reserve",
            args,
            std::slice::from_ref(&coin),
            Some(asset),
        );
        assert!(
            matches!(outcome.effects.status, ExecutionStatus::Failure { .. }),
            "reserve: variant {name} should have trapped"
        );
        trapped(&outcome);
    }

    // The same malformed frames must also be rejected by `reserve_all`,
    // which consumes rather than mutates its source Coin.
    for (name, malformed) in malformed_digest_variants() {
        let args = encode_call_value(
            &reserve_argument_layout(),
            &CallValue::Tuple(vec![
                CallValue::U64(100),
                CallValue::Bytes(malformed),
                CallValue::Bytes(canonical_encoding::encode_digest32(&policy).unwrap()),
                CallValue::Bytes(sender().to_vec()),
                CallValue::Bytes(sender().to_vec()),
            ]),
        )
        .unwrap();
        let outcome = call(
            &root,
            "reserve_all",
            args,
            &[ScopedResolvedObject {
                resolved: ResolvedObject {
                    mode: AccessMode::Consume,
                    ..coin.resolved.clone()
                },
                authority: coin.authority.clone(),
            }],
            Some(asset),
        );
        assert!(
            matches!(outcome.effects.status, ExecutionStatus::Failure { .. }),
            "reserve_all: variant {name} should have trapped"
        );
        trapped(&outcome);
    }

    // The Coin was never actually consumed by any trapped attempt: a
    // genuine reserve now succeeds against the same, untouched object.
    let invocation = invocation_digest();
    let reserve = call(
        &root,
        "reserve",
        reserve_arguments(40, &invocation, &policy, &sender(), &sender()).unwrap(),
        std::slice::from_ref(&coin),
        Some(asset),
    );
    success(&reserve);
}

#[test]
fn malformed_digest_frames_are_rejected_by_settle() {
    let (root, asset, cap) = init_asset(21);
    let mint: LocalExecutionOutcome = call(
        &root,
        "mint",
        mint_arguments(100, &sender()).unwrap(),
        &[cap],
        Some(asset),
    );
    success(&mint);
    let coin: ScopedResolvedObject = created(&mint, 0, AccessMode::Write);
    let invocation = invocation_digest();
    let policy = policy_digest();
    let reserve: LocalExecutionOutcome = call(
        &root,
        "reserve",
        reserve_arguments(40, &invocation, &policy, &sender(), &sender()).unwrap(),
        std::slice::from_ref(&coin),
        Some(asset),
    );
    success(&reserve);
    let reservation: ScopedResolvedObject = created(&reserve, 0, AccessMode::Consume);

    for (name, malformed) in malformed_digest_variants() {
        let args = encode_call_value(
            &settle_argument_layout(),
            &CallValue::Tuple(vec![
                CallValue::U64(15),
                CallValue::Bytes(malformed),
                CallValue::Bytes(canonical_encoding::encode_digest32(&policy).unwrap()),
            ]),
        )
        .unwrap();
        let outcome = call(
            &root,
            "settle",
            args,
            std::slice::from_ref(&reservation),
            Some(asset),
        );
        assert!(
            matches!(outcome.effects.status, ExecutionStatus::Failure { .. }),
            "settle: variant {name} should have trapped"
        );
        trapped(&outcome);
    }

    // The Reservation was never actually consumed by any trapped attempt:
    // a genuine settle now succeeds against the same, untouched object.
    let settle: LocalExecutionOutcome = call(
        &root,
        "settle",
        settle_arguments(15, &invocation, &policy).unwrap(),
        &[reservation],
        Some(asset),
    );
    success(&settle);
}

#[test]
fn accepted_hash_algorithm_ids_one_two_three_are_admitted_by_reserve_and_settle() {
    for (seed, algorithm) in [
        (22u8, HashAlgorithmId::Sha2_256),
        (23u8, HashAlgorithmId::Sha3_256),
        (24u8, HashAlgorithmId::Blake3_256),
    ] {
        let (root, asset, cap) = init_asset(seed);
        let mint: LocalExecutionOutcome = call(
            &root,
            "mint",
            mint_arguments(100, &sender()).unwrap(),
            &[cap],
            Some(asset),
        );
        success(&mint);
        let coin: ScopedResolvedObject = created(&mint, 0, AccessMode::Write);
        let invocation = Digest32::new(algorithm, [0xAB; 32]);
        let policy = Digest32::new(algorithm, [0xCD; 32]);
        let reserve: LocalExecutionOutcome = call(
            &root,
            "reserve",
            reserve_arguments(40, &invocation, &policy, &sender(), &sender()).unwrap(),
            std::slice::from_ref(&coin),
            Some(asset),
        );
        success(&reserve);
        let reservation: ScopedResolvedObject = created(&reserve, 0, AccessMode::Consume);
        let settle: LocalExecutionOutcome = call(
            &root,
            "settle",
            settle_arguments(15, &invocation, &policy).unwrap(),
            &[reservation],
            Some(asset),
        );
        success(&settle);
    }
}

#[test]
fn reservation_body_decoder_rejects_malformed_digest_fields() {
    let policy = policy_digest();
    let malformed_body = encode_call_value(
        &reservation_body_layout(),
        &CallValue::Tuple(vec![
            CallValue::U64(10),
            CallValue::Bytes(digest_frame(
                2,
                false,
                2,
                &4u16.to_le_bytes(),
                32,
                &[0xCD; 32],
            )),
            CallValue::Bytes(canonical_encoding::encode_digest32(&policy).unwrap()),
            CallValue::Bytes(sender().to_vec()),
            CallValue::Bytes(sender().to_vec()),
        ]),
    )
    .unwrap();
    assert!(reservation_body(&malformed_body).is_err());
}

#[test]
fn late_host_create_failure_after_cap_write_rolls_back_all_effects() {
    let (root, asset, cap) = init_asset(25);
    // The all-zero recipient is not a decodable Ed25519 owner: `create`
    // must fail at the host boundary only *after* the guest has already
    // performed its checked supply update and issued the write to the
    // TreasuryCap. The whole call must still roll back with no effects.
    let outcome = call(
        &root,
        "mint",
        mint_arguments(50, &[0u8; 32]).unwrap(),
        std::slice::from_ref(&cap),
        Some(asset),
    );
    trapped(&outcome);
}
