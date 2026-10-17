//! ADR0271 selected actual certified multi-UID component fixture for DR0268. Ignored by ordinary
//! validation: only the bounded reviewed Docker controller supplies its inputs.
//! No release executable, signing service, authority token or host setup.
#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]
#[path = "support/compiled_source_host_process.rs"]
mod compiled_source_host_process;
#[allow(dead_code)]
#[path = "support/https_relay.rs"]
mod https_relay;
#[path = "support/offline_genesis_fixture.rs"]
mod offline_genesis_fixture;
#[path = "support/sqlite_durable_image.rs"]
mod sqlite_durable_image;

use abi::{AccessEntry, AccessManifest};
use canonical_encoding::decode_canonical_frame;
use consensus::bundle::{PublicationBundle, decode_publication_bundle, encode_publication_bundle};
use consensus::{
    AvailabilityCertificate, AvailabilityCertifier, AvailabilityIdentity, AvailabilityVote,
    Ed25519ConsensusVerifier, FastCertificate, FastVote, FrozenFrontierCertifier,
    FrozenFrontierPage, FrozenFrontierPageVerifier, FrozenFrontierVote,
    UnsupportedSignatureSchemeResponse,
};
use execution::ObjectEffect;
use execution::call::CallIntent;
use execution::paid_execution::{
    FeeSourceConsent, PaidApplication, PaidExecutionResult, PaidExecutionStatus,
    ReservationAccessKind, SignedPaidIntent, authenticate_paid_intent,
    decode_paid_execution_result, decode_signed_paid_intent, encode_paid_execution_result,
    encode_signed_paid_intent, paid_invocation_digest,
};
use execution::publication::PublicationContext;
use hashing::HashSuiteResolver;
use node_core::ordered_economics::{
    FreezeIntent, OrderedCandidate, OrderedEconomicsPolicy, OrderedOperationKind, OrderedOutcome,
    decode_ordered_outcome, encode_freeze_intent, encode_ordered_candidate, encode_ordered_outcome,
};
use node_wire::*;
use objects::{Address, Object, ObjectId, ObjectRef, Owner};
use offline_genesis_fixture::{Fixture, hex};
use protocol_types::{
    AtomicityDomainId, ChainId, Digest32, Epoch, HashSuiteId, ProtocolVersion, ValidatorId,
};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use sqlite_durable_image::{AnchorImage, Image};
use std::{
    collections::BTreeMap,
    env,
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Write},
    net::SocketAddr,
    num::NonZeroUsize,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use sunrise_edge_client::ordered_economics_client::{
    ArtifactSink, OrderedEconomicsEndpoint, PeerPhaseOutcome, submit_candidate,
};
use sunrise_edge_client::{
    Client, DrainDriveBounds, DrainDriveOutcome, ExpectedDrainFreeze, ExpectedProtocolContext,
    FastVoteEndpoint, LocalSigner, Method, RemoteTlsHttpTransport, Transport,
    TrustedFastVoteGenesis, WireRequest, WireResponse, collect_fastvote_availability_certificate,
    collect_fastvote_certificate, drive_drain_to_local_ready,
    load_trusted_fastvote_genesis_with_profile,
};
use sunrise_edge_operator::common::{parse_hash_suite, parse_hex_32};

const COUNT: usize = 4;
const PUBLIC: &str = "/work/public";
const ARTIFACTS: &str = "/work/artifacts";
const MAX_FILE: usize = 1024 * 1024;
const DOMAIN: [u8; 32] = [0x61; 32];
fn path(tree: &str, index: usize, name: &str) -> PathBuf {
    PathBuf::from(format!("/work/{tree}/v{index}/{name}"))
}
fn read(path: impl AsRef<Path>, cap: usize) -> Vec<u8> {
    let file: File = File::open(path).unwrap();
    assert!(usize::try_from(file.metadata().unwrap().len()).unwrap() <= cap);
    let mut bytes: Vec<u8> = Vec::new();
    file.take(u64::try_from(cap + 1).unwrap())
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= cap);
    bytes
}
fn write_new(path: impl AsRef<Path>, bytes: &[u8], mode: u32) {
    assert!(bytes.len() <= MAX_FILE);
    let mut file: File = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .unwrap();
    // The controller's role umask is077. Only selected public fixture bytes
    // receive0644 explicitly; authority/key/config destinations remain0600.
    file.set_permissions(fs::Permissions::from_mode(mode))
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}
fn pins() -> BTreeMap<String, String> {
    let text: String = String::from_utf8(read(format!("{PUBLIC}/pins"), 16 * 1024)).unwrap();
    let mut pins: BTreeMap<String, String> = BTreeMap::new();
    for line in text.lines() {
        let (key, value): (&str, &str) = line.split_once('=').unwrap();
        assert!(pins.insert(key.into(), value.into()).is_none());
    }
    assert_eq!(pins.len(), 8);
    pins
}
fn policy() -> OrderedEconomicsPolicy {
    let pins: BTreeMap<String, String> = pins();
    let chain: ChainId = ChainId::new(pins["chain-id"].clone()).unwrap();
    let context: PublicationContext =
        PublicationContext::new(chain.clone(), ProtocolVersion::new(7), Epoch::new(0)).unwrap();
    let resolver: HashSuiteResolver = HashSuiteResolver::new(
        chain,
        ProtocolVersion::new(7),
        vec![parse_hash_suite("0:1:1:1:1:1:1:1").unwrap()],
    )
    .unwrap();
    let digest_text: String = String::from_utf8(read(format!("{PUBLIC}/digest"), 64)).unwrap();
    let digest: [u8; 32] = parse_hex_32(&digest_text, "fixture public digest").unwrap();
    let root = sunrise_edge_client::load_verified_genesis_root(
        &PathBuf::from(format!("{PUBLIC}/genesis.bin")),
        &resolver,
        digest,
        &context,
    )
    .unwrap();
    assert!(root.admission_profile().is_causal());
    let policy: OrderedEconomicsPolicy =
        OrderedEconomicsPolicy::from_genesis_root(&root, AtomicityDomainId::new(DOMAIN).unwrap())
            .unwrap();
    assert_eq!(policy.engine().validator_set().validators().len(), COUNT);
    policy
}
fn verifier() -> Ed25519ConsensusVerifier {
    Ed25519ConsensusVerifier::new(UnsupportedSignatureSchemeResponse::InvalidSignature)
}
fn prepare_inputs() {
    let fixture: Fixture = Fixture::with_chain("certified-multiuid-1017");
    let setup: PathBuf = PathBuf::from("/work/worker/setup");
    let mut args = fixture.args.clone();
    for name in ["authority.key", "validators.txt", "allocations.txt"] {
        write_new(
            setup.join(name),
            &read(fixture.directory.join(name), MAX_FILE),
            0o600,
        );
    }
    for (flag, name) in [
        ("--genesis-key-file", "authority.key"),
        ("--validators-file", "validators.txt"),
        ("--allocations-file", "allocations.txt"),
        ("--output", "genesis.bin"),
    ] {
        offline_genesis_fixture::replace(&mut args, flag, setup.join(name).into_os_string());
    }
    let mut arguments: String = String::new();
    for value in args {
        let value = value.into_string().unwrap();
        assert!(
            !value
                .bytes()
                .any(|byte: u8| matches!(byte, b'\n' | b'\r' | 0))
        );
        arguments.push_str(&value);
        arguments.push('\n');
    }
    write_new(
        format!("{PUBLIC}/author-arguments"),
        arguments.as_bytes(),
        0o644,
    );
    let mut text: String = format!(
        "chain-id={}\nauthority={}\ndomain={}\nsuite=0:1:1:1:1:1:1:1\n",
        fixture.context.chain_id().as_str(),
        hex(&fixture.authority),
        hex(&DOMAIN)
    );
    for (index, public) in fixture.validators.iter().enumerate() {
        text.push_str(&format!("validator-{index}={}\n", hex(public)));
        let seed: [u8; 32] = [0x51 + u8::try_from(index).unwrap(); 32];
        write_new(path("worker", index, "validator.key"), &seed, 0o600);
    }
    write_new(format!("{PUBLIC}/pins"), text.as_bytes(), 0o644);
    // Fixture Drop removes the original private author directory. No validator
    // key bytes are handed to the root controller or frontend process.
}
fn publish_genesis() {
    let bytes: Vec<u8> = read("/work/worker/setup/genesis.bin", MAX_FILE);
    write_new(format!("{PUBLIC}/genesis.bin"), &bytes, 0o644);
    for index in 0..COUNT {
        write_new(path("worker", index, "genesis.bin"), &bytes, 0o600);
    }
    let _verified: OrderedEconomicsPolicy = policy();
    for name in [
        "authority.key",
        "validators.txt",
        "allocations.txt",
        "genesis.bin",
    ] {
        fs::remove_file(PathBuf::from("/work/worker/setup").join(name)).unwrap();
    }
}
fn frontend_inputs() {
    for index in 0..COUNT {
        let name: String = format!("validator-{index}.certified-custody.sunrise-edge.invalid");
        let ca: https_relay::FixtureCa =
            https_relay::FixtureCa::new(&format!("certified-custody-{index}-issuer"));
        let leaf: https_relay::FixtureLeaf = ca.issue_leaf(&name);
        for (file, bytes) in [
            ("ca.der", ca.der.as_slice()),
            ("leaf.der", leaf.der.as_slice()),
            ("tls.key", leaf.key_pkcs8_der.as_slice()),
            ("spki.der", leaf.public_key_der.as_slice()),
            ("name", name.as_bytes()),
        ] {
            write_new(path("front", index, file), bytes, 0o600);
        }
        write_new(
            path("front", index, "genesis.bin"),
            &read(format!("{PUBLIC}/genesis.bin"), MAX_FILE),
            0o600,
        );
    }
}
fn endpoints() -> Vec<FastVoteEndpoint<CountedTls>> {
    let pins: BTreeMap<String, String> = pins();
    (0..COUNT)
        .map(|index: usize| {
            let address: SocketAddr =
                String::from_utf8(read(format!("{PUBLIC}/address-{index}"), 128))
                    .unwrap()
                    .parse()
                    .unwrap();
            let name: String = String::from_utf8(read(path("front", index, "name"), 256)).unwrap();
            let ca: Vec<u8> = read(path("front", index, "ca.der"), 16 * 1024);
            let received: Vec<u8> = https_relay::authenticated_leaf(address, &name, &ca);
            assert_eq!(received, read(path("front", index, "leaf.der"), 16 * 1024));
            let transport: RemoteTlsHttpTransport = RemoteTlsHttpTransport::new(
                address,
                &name,
                &ca,
                Duration::from_secs(2),
                Duration::from_secs(2),
                Duration::from_secs(2),
                Duration::from_secs(5),
                Duration::from_secs(2),
                NonZeroUsize::new(16 * 1024).unwrap(),
                NonZeroUsize::new(MAX_FILE).unwrap(),
            )
            .unwrap();
            FastVoteEndpoint {
                validator_id: ValidatorId::new(
                    parse_hex_32(&pins[&format!("validator-{index}")], "validator").unwrap(),
                ),
                endpoint_label: address.to_string(),
                client: Client::new(CountedTls {
                    inner: transport,
                    index,
                }),
            }
        })
        .collect()
}
fn send(
    endpoint: &FastVoteEndpoint<CountedTls>,
    method: Method,
    path: &str,
    media: Option<&'static str>,
    body: Vec<u8>,
) -> WireResponse {
    endpoint
        .client
        .transport()
        .send(&WireRequest {
            method,
            path: path.into(),
            content_type: media,
            body,
            deadline: Some(Instant::now().checked_add(Duration::from_secs(2)).unwrap()),
        })
        .unwrap()
}
fn success(response: WireResponse, media: &str) -> Vec<u8> {
    assert_eq!(response.status, 200);
    assert_eq!(response.content_type.as_deref(), Some(media));
    response.body
}
fn save(name: &str, bytes: &[u8]) {
    assert!(!name.contains('/') && name.len() <= 64);
    write_new(format!("{ARTIFACTS}/{name}"), bytes, 0o600);
    // Canonical wire artifacts are public; only this selected copy is readable
    // by the independent worker-UID row oracle. Never publish key/config bytes.
    write_new(format!("{PUBLIC}/wire/{name}"), bytes, 0o644);
}
fn saved(name: &str) -> Vec<u8> {
    read(format!("{PUBLIC}/wire/{name}"), MAX_FILE)
}
const A: &str = "a";
const B: &str = "b";
const C: &str = "c";
const FREEZE: [u8; 32] = [0xb8; 32];
fn request(tag: &str) -> [u8; 32] {
    match tag {
        A => [0x2a; 32],
        B => [0x2b; 32],
        C => [0x2c; 32],
        _ => panic!("closed paid tag"),
    }
}
fn context() -> PublicationContext {
    PublicationContext::new(
        ChainId::new(pins()["chain-id"].clone()).unwrap(),
        ProtocolVersion::new(7),
        Epoch::new(0),
    )
    .unwrap()
}
fn resolver() -> HashSuiteResolver {
    HashSuiteResolver::new(
        context().chain_id().clone(),
        ProtocolVersion::new(7),
        vec![parse_hash_suite("0:1:1:1:1:1:1:1").unwrap()],
    )
    .unwrap()
}
fn domain() -> AtomicityDomainId {
    AtomicityDomainId::new(DOMAIN).unwrap()
}
fn trusted() -> TrustedFastVoteGenesis {
    let digest: String = String::from_utf8(read(format!("{PUBLIC}/digest"), 64)).unwrap();
    let trusted: TrustedFastVoteGenesis = load_trusted_fastvote_genesis_with_profile(
        &PathBuf::from(format!("{PUBLIC}/genesis.bin")),
        &resolver(),
        parse_hex_32(&digest, "digest").unwrap(),
        &context(),
    )
    .unwrap();
    assert!(trusted.admission_profile().is_causal());
    assert_eq!(
        trusted.certifier().validator_set().validators().len(),
        COUNT
    );
    trusted
}
fn expected() -> ExpectedProtocolContext {
    ExpectedProtocolContext::new(
        context().chain_id().clone(),
        ProtocolVersion::new(7),
        Epoch::new(0),
        HashSuiteId::new(1),
        1,
        1,
        1,
        domain(),
    )
    .unwrap()
}
fn owner() -> LocalSigner {
    LocalSigner::from_seed([0x56; 32])
}
fn recipient() -> Address {
    LocalSigner::from_seed([0x57; 32]).address()
}
fn signed(tag: &str) -> SignedPaidIntent {
    decode_signed_paid_intent(&saved(&format!("{tag}.intent"))).unwrap()
}
fn certificate(tag: &str) -> FastCertificate {
    consensus::decode_fast_certificate(&saved(&format!("{tag}.certificate"))).unwrap()
}
fn availability(tag: &str) -> AvailabilityCertificate {
    consensus::decode_availability_certificate(&saved(&format!("{tag}.availability"))).unwrap()
}
fn bundle(tag: &str) -> PublicationBundle {
    decode_publication_bundle(&saved(&format!("{tag}.bundle"))).unwrap()
}
fn result(tag: &str) -> PaidExecutionResult {
    decode_paid_execution_result(&saved(&format!("{tag}.result"))).unwrap()
}
fn current(client: &Client<CountedTls>, id: ObjectId) -> (ObjectRef, Object) {
    let observed: HttpObjectQueryResult = client.query_object(id).unwrap();
    let HttpObjectQueryResult::CurrentInline {
        object_version,
        digest,
        canonical_object_bytes,
        ..
    } = observed
    else {
        panic!("actual current inline object")
    };
    let object: Object = objects::decode_object(&canonical_object_bytes).unwrap();
    assert_eq!(
        objects::encode_object(&object).unwrap(),
        canonical_object_bytes
    );
    assert_eq!(object.id, id);
    assert_eq!(object.version, object_version.get());
    (
        ObjectRef {
            id,
            version: object_version.get(),
            digest,
        },
        object,
    )
}
fn build(tag: &str) {
    let trusted: TrustedFastVoteGenesis = trusted();
    let manifest = trusted.genesis_root().manifest();
    let endpoints: Vec<FastVoteEndpoint<CountedTls>> = endpoints();
    let client = &endpoints[0].client;
    client.query_verified_context(&expected()).unwrap();
    let fee_policy = client
        .query_paid_fee_policy(&resolver(), &expected())
        .unwrap();
    assert_eq!(fee_policy, manifest.fee_policy);
    let app_id: ObjectId = match tag {
        A => ObjectId::new([0x21; 32]),
        B => result(A).charged.unwrap().refund_output.unwrap().id,
        C => result(B).charged.unwrap().refund_output.unwrap().id,
        _ => panic!("paid tag"),
    };
    let (application, object): (ObjectRef, Object) = current(client, app_id);
    assert_eq!(object.owner, Owner::Address(owner().address()));
    let (fee, fee_object): (ObjectRef, Object) = current(client, ObjectId::new([0x22; 32]));
    save(
        &format!("{tag}.input"),
        &objects::encode_object(&object).unwrap(),
    );
    save(
        &format!("{tag}.fee-input"),
        &objects::encode_object(&fee_object).unwrap(),
    );
    if tag == A {
        save(
            "reply.context",
            &success(
                send(
                    &endpoints[0],
                    Method::Get,
                    QUERY_CONTEXT_PATH,
                    None,
                    Vec::new(),
                ),
                QUERY_RESULT_MEDIA_TYPE,
            ),
        );
    }
    let nonce: u64 = match tag {
        A => 0,
        B => 1,
        C => 2,
        _ => unreachable!(),
    };
    assert_eq!(
        client
            .query_next_nonce(owner().address())
            .unwrap()
            .next_nonce(),
        nonce
    );
    let original: &CallIntent = &manifest.initialization.intent.call;
    let consent: FeeSourceConsent = FeeSourceConsent {
        source: fee,
        access: ReservationAccessKind::Write,
        max_fee: fees::Amount::new(1_000_000),
        refund_recipient: *owner().address().as_bytes(),
    };
    client
        .validate_paid_fee_source(&owner(), &resolver(), &expected(), &fee_policy, &consent)
        .unwrap();
    client
        .query_paid_executable_interface(&original.code, &resolver(), &expected())
        .unwrap();
    let recipient: [u8; 32] = *recipient().as_bytes();
    // Existing fixture's ordinary sender-owned transfer; application and fee refs are independently queried.
    let call: CallIntent = CallIntent {
        context: context(),
        request_id: request(tag),
        sender: *owner().address().as_bytes(),
        nonce,
        code: original.code.clone(),
        instance: original.instance.clone(),
        entrypoint: "transfer".into(),
        type_arguments: fee_policy.type_arguments.clone(),
        access: AccessManifest {
            entries: vec![AccessEntry {
                object_ref: application,
                mode: objects::AccessMode::Write,
            }],
        },
        arguments: public_standard_asset::transfer_arguments(&recipient).unwrap(),
        gas_limit: 200_000,
    };
    let signed: SignedPaidIntent =
        sunrise_edge_client::paid_execution_client::build_signed_paid_execution(
            &owner(),
            &resolver(),
            &expected(),
            &fee_policy,
            consent,
            PaidApplication::Call(call),
            node_core::RequestId::new(request(tag)).unwrap(),
            nonce,
            200_000,
            Vec::new(),
        )
        .unwrap();
    let bytes: Vec<u8> = encode_signed_paid_intent(&signed).unwrap();
    authenticate_paid_intent(&resolver(), &context(), &bytes).unwrap();
    save(&format!("{tag}.intent"), &bytes);
}
fn prepare_votes(tag: &str) {
    build(tag);
    let endpoints: Vec<FastVoteEndpoint<CountedTls>> = endpoints();
    let trusted: TrustedFastVoteGenesis = trusted();
    let (certificate, attempts) = collect_fastvote_certificate(
        &endpoints,
        trusted.certifier(),
        &resolver(),
        &signed(tag),
        Instant::now() + Duration::from_secs(20),
        Duration::from_secs(2),
    )
    .unwrap();
    assert_eq!(attempts.len(), COUNT);
    for (index, attempt) in attempts.into_iter().enumerate() {
        assert_eq!(attempt.validator_id, endpoints[index].validator_id);
        let vote: FastVote = attempt.result.unwrap();
        trusted.certifier().verify_vote(&vote, &verifier()).unwrap();
        assert_eq!(vote.validator, endpoints[index].validator_id);
        assert_eq!(
            vote.tx_hash,
            paid_invocation_digest(&resolver(), &signed(tag)).unwrap()
        );
        save(
            &format!("{tag}.vote-{index}"),
            &consensus::encode_fast_vote(&vote).unwrap(),
        );
    }
    assert_eq!(certificate.votes.len(), 3);
    save(
        &format!("{tag}.certificate"),
        &consensus::encode_fast_certificate(&certificate).unwrap(),
    );
}
fn retain(tag: &str) {
    let endpoints: Vec<FastVoteEndpoint<CountedTls>> = endpoints();
    let trusted: TrustedFastVoteGenesis = trusted();
    let certificate: FastCertificate = certificate(tag);
    if tag == C {
        let (bundle, identity) = endpoints[0]
            .client
            .source_fastvote_publication(
                &signed(tag),
                &certificate,
                trusted.certifier(),
                &resolver(),
                &[],
                domain(),
                Some(Instant::now() + Duration::from_secs(2)),
            )
            .unwrap();
        let bytes: Vec<u8> = encode_publication_bundle(&bundle).unwrap();
        let ack: AvailabilityVote = endpoints[0]
            .client
            .retain_fastvote_publication(&bytes, Some(Instant::now() + Duration::from_secs(2)))
            .unwrap();
        assert_eq!(ack.identity, identity);
        assert_eq!(ack.validator, endpoints[0].validator_id);
        AvailabilityCertifier::new(
            context().chain_id().clone(),
            ProtocolVersion::new(7),
            Epoch::new(0),
            trusted.certifier().validator_set().clone(),
        )
        .unwrap()
        .verify_vote(&ack, &verifier())
        .unwrap();
        save(&format!("{tag}.bundle"), &bytes);
        save(
            &format!("{tag}.ack-0"),
            &consensus::encode_availability_vote(&ack).unwrap(),
        );
    } else {
        let round = collect_fastvote_availability_certificate(
            &endpoints,
            trusted.certifier(),
            &resolver(),
            &[],
            domain(),
            &signed(tag),
            &certificate,
            Instant::now() + Duration::from_secs(20),
            Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(round.attempts.len(), COUNT);
        for (index, attempt) in round.attempts.into_iter().enumerate() {
            let vote: AvailabilityVote = attempt.result.unwrap();
            assert_eq!(attempt.validator_id, endpoints[index].validator_id);
            assert_eq!(vote.validator, endpoints[index].validator_id);
            assert_eq!(vote.identity, round.availability_certificate.identity);
            save(
                &format!("{tag}.ack-{index}"),
                &consensus::encode_availability_vote(&vote).unwrap(),
            );
        }
        assert_eq!(round.availability_certificate.votes.len(), 3);
        save(
            &format!("{tag}.availability"),
            &consensus::encode_availability_certificate(&round.availability_certificate).unwrap(),
        );
        save(
            &format!("{tag}.bundle"),
            &encode_publication_bundle(&round.bundle).unwrap(),
        );
    }
    for endpoint in &endpoints {
        assert!(matches!(
            endpoint
                .client
                .query_receipt(node_core::RequestId::new(request(tag)).unwrap())
                .unwrap(),
            HttpReceiptQueryResult::Absent { .. }
        ));
    }
}
fn prepared(tag: &str) {
    prepare_votes(tag);
    retain(tag);
}
fn unapplied_a() {
    let signed: SignedPaidIntent = signed(A);
    let PaidApplication::Call(call) = &signed.intent.application else {
        panic!("Call")
    };
    for endpoint in endpoints() {
        assert_eq!(
            endpoint
                .client
                .query_next_nonce(owner().address())
                .unwrap()
                .next_nonce(),
            0
        );
        assert!(matches!(
            endpoint
                .client
                .query_receipt(node_core::RequestId::new(request(A)).unwrap())
                .unwrap(),
            HttpReceiptQueryResult::Absent { .. }
        ));
        for (reference, artifact) in [
            (&call.access.entries[0].object_ref, "a.input"),
            (&signed.intent.consent.source, "a.fee-input"),
        ] {
            let (observed, object): (ObjectRef, Object) = current(&endpoint.client, reference.id);
            assert_eq!(&observed, reference);
            assert_eq!(objects::encode_object(&object).unwrap(), saved(artifact));
        }
    }
}

fn replay_prepared(tag: &str) {
    let endpoints: Vec<FastVoteEndpoint<CountedTls>> = endpoints();
    for (index, endpoint) in endpoints.iter().enumerate() {
        let response: Vec<u8> = success(
            send(
                endpoint,
                Method::Post,
                FASTVOTE_PREPARE_PATH,
                Some(NODE_EVENT_MEDIA_TYPE),
                saved(&format!("{tag}.intent")),
            ),
            NODE_RESULT_MEDIA_TYPE,
        );
        assert_eq!(response, saved(&format!("{tag}.vote-{index}")));
        let response: Vec<u8> = success(
            send(
                endpoint,
                Method::Post,
                FASTVOTE_PUBLICATION_RETAIN_PATH,
                Some(NODE_EVENT_MEDIA_TYPE),
                saved(&format!("{tag}.bundle")),
            ),
            NODE_RESULT_MEDIA_TYPE,
        );
        assert_eq!(response, saved(&format!("{tag}.ack-{index}")));
    }
}
fn paid_response(bytes: &[u8], signed: &SignedPaidIntent) -> PaidExecutionResult {
    let outer: HttpNodeResult = HttpNodeResult::decode(bytes).unwrap();
    assert_eq!(outer.encode().unwrap(), bytes);
    let bound = outer
        .bind_request(node_core::RequestId::new(signed.intent.request_id).unwrap())
        .unwrap();
    let ack = bound.single_acknowledgement().unwrap();
    assert_eq!(ack.status(), node_core::NodeResponseStatus::Accepted);
    let result: PaidExecutionResult = decode_paid_execution_result(ack.payload()).unwrap();
    assert_eq!(result.request_id, signed.intent.request_id);
    assert_eq!(result.status, PaidExecutionStatus::Success);
    assert_eq!(
        result.effects.tx_hash,
        paid_invocation_digest(&resolver(), signed).unwrap()
    );
    let PaidApplication::Call(call) = &signed.intent.application else {
        panic!("ordinary Call")
    };
    let execution::paid_execution::PaidResultTarget::Instance(record) = &result.target else {
        panic!("exact instance")
    };
    assert_eq!(
        execution::local_execution::instance_target(&resolver(), record).unwrap(),
        call.instance
    );
    result
}
fn apply(tag: &str, replay: bool) {
    let signed: SignedPaidIntent = signed(tag);
    let trusted: TrustedFastVoteGenesis = trusted();
    let endpoints: Vec<FastVoteEndpoint<CountedTls>> = endpoints();
    // SDK independently verifies both real quorum authorities before any POST.
    let attempts = sunrise_edge_client::apply_published_fastvote_to_all(
        &endpoints,
        trusted.certifier(),
        &resolver(),
        domain(),
        &signed,
        &certificate(tag),
        &availability(tag),
        Instant::now() + Duration::from_secs(20),
        Duration::from_secs(2),
    )
    .unwrap();
    assert_eq!(attempts.len(), COUNT);
    let mut common: Option<Vec<u8>> = None;
    for (index, attempt) in attempts.into_iter().enumerate() {
        assert_eq!(attempt.validator_id, endpoints[index].validator_id);
        let result: PaidExecutionResult = attempt.result.unwrap();
        let canonical: Vec<u8> = encode_paid_execution_result(&result).unwrap();
        if let Some(bytes) = &common {
            assert_eq!(&canonical, bytes);
        } else {
            common = Some(canonical.clone());
        }
        let body: Vec<u8> = FastVotePublishedApplyRequest {
            signed_paid_intent: encode_signed_paid_intent(&signed).unwrap(),
            certificate: consensus::encode_fast_certificate(&certificate(tag)).unwrap(),
            availability_certificate: consensus::encode_availability_certificate(&availability(
                tag,
            ))
            .unwrap(),
        }
        .encode()
        .unwrap();
        let bytes: Vec<u8> = success(
            send(
                &endpoints[index],
                Method::Post,
                FASTVOTE_PUBLISHED_APPLY_PATH,
                Some(NODE_EVENT_MEDIA_TYPE),
                body,
            ),
            NODE_RESULT_MEDIA_TYPE,
        );
        assert_eq!(paid_response(&bytes, &signed), result);
        if replay {
            assert_eq!(bytes, saved(&format!("{tag}.wire-{index}")));
        } else {
            save(&format!("{tag}.wire-{index}"), &bytes);
        }
    }
    if replay {
        assert_eq!(common.unwrap(), saved(&format!("{tag}.result")));
    } else {
        save(&format!("{tag}.result"), &common.unwrap());
    }
    if !replay {
        verify_business(tag);
    }
}
fn verify_business(tag: &str) {
    let signed: SignedPaidIntent = signed(tag);
    let result: PaidExecutionResult = result(tag);
    let charged = result.charged.as_ref().unwrap();
    assert!(charged.reserved.get() > 0 && charged.actual.get() > 0 && charged.refund.get() > 0);
    assert_eq!(
        charged
            .actual
            .get()
            .checked_add(charged.refund.get())
            .unwrap(),
        charged.reserved.get()
    );
    let PaidApplication::Call(call) = &signed.intent.application else {
        panic!("Call")
    };
    let [input] = call.access.entries.as_slice() else {
        panic!("one input")
    };
    let expected_recipient: Address = recipient();
    let mutated: Vec<&Object> = result
        .effects
        .object_effects
        .iter()
        .filter_map(|effect| match effect {
            ObjectEffect::Mutated {
                previous_version,
                new_object,
            } if new_object.id == input.object_ref.id => {
                assert_eq!(*previous_version, input.object_ref.version);
                Some(new_object)
            }
            _ => None,
        })
        .collect();
    assert_eq!(mutated.len(), 1);
    let mutation: &Object = mutated[0];
    assert_eq!(
        mutation.version,
        input.object_ref.version.checked_add(1).unwrap()
    );
    assert_eq!(mutation.owner, Owner::Address(expected_recipient));
    let original: Object = objects::decode_object(&saved(&format!("{tag}.input"))).unwrap();
    assert_eq!(mutation.type_hash, original.type_hash);
    assert_eq!(mutation.schema_version, original.schema_version);
    assert_eq!(mutation.data, original.data);
    assert_eq!(
        public_standard_asset::coin_amount(&mutation.data).unwrap(),
        public_standard_asset::coin_amount(&original.data).unwrap()
    );
    let authenticated =
        authenticate_paid_intent(&resolver(), &context(), &saved(&format!("{tag}.intent")))
            .unwrap();
    let base_policy =
        execution::local_execution::LocalExecutionPolicy::generic_object_results(context());
    let root: TrustedFastVoteGenesis = trusted();
    let admission = execution::paid_execution::quote_paid_intent(
        &authenticated,
        &resolver(),
        &base_policy,
        &root.genesis_root().manifest().fee_policy,
    )
    .unwrap();
    let settlement = admission.settle(charged.application_gas_units).unwrap();
    assert_eq!(charged.reserved, admission.reserved());
    assert_eq!(charged.actual, settlement.actual);
    assert_eq!(charged.refund, settlement.refund);
    assert!(charged.reserved.get() <= signed.intent.consent.max_fee.get());
    let fee_created: Vec<&Object> = result
        .effects
        .object_effects
        .iter()
        .filter_map(|effect| match effect {
            ObjectEffect::Created(object) if object.id == charged.fee_output.id => Some(object),
            _ => None,
        })
        .collect();
    assert_eq!(fee_created.len(), 1);
    assert_eq!(fee_created[0].type_hash, original.type_hash);
    assert_eq!(fee_created[0].schema_version, original.schema_version);
    assert_eq!(fee_created[0].version, charged.fee_output.version);
    assert_eq!(
        public_standard_asset::coin_amount(&fee_created[0].data).unwrap(),
        charged.actual.get()
    );
    assert!(
        matches!(&fee_created[0].owner, Owner::ProtocolCustody(scope) if scope.purpose == objects::ProtocolCustodyPurpose::FeeEscrow && &scope.chain_id == context().chain_id())
    );
    let refund: &ObjectRef = charged.refund_output.as_ref().unwrap();
    let refund_created: Vec<&Object> = result
        .effects
        .object_effects
        .iter()
        .filter_map(|effect| match effect {
            ObjectEffect::Created(object) if object.id == refund.id => Some(object),
            _ => None,
        })
        .collect();
    assert_eq!(refund_created.len(), 1);
    assert_eq!(refund_created[0].owner, Owner::Address(owner().address()));
    assert_eq!(refund_created[0].version, refund.version);
    assert_eq!(refund_created[0].type_hash, original.type_hash);
    assert_eq!(refund_created[0].schema_version, original.schema_version);
    assert_eq!(
        public_standard_asset::coin_amount(&refund_created[0].data).unwrap(),
        charged.refund.get()
    );
    for endpoint in endpoints() {
        let (_, observed): (ObjectRef, Object) = current(&endpoint.client, mutation.id);
        assert_eq!(&observed, mutation);
        let (_, observed): (ObjectRef, Object) = current(&endpoint.client, refund.id);
        assert_eq!(&observed, refund_created[0]);
        let (_, observed): (ObjectRef, Object) = current(&endpoint.client, charged.fee_output.id);
        assert_eq!(&observed, fee_created[0]);
        assert!(matches!(
            endpoint.client.query_object(charged.reservation).unwrap(),
            HttpObjectQueryResult::Absent { .. } | HttpObjectQueryResult::Tombstoned { .. }
        ));
        assert_eq!(
            endpoint
                .client
                .query_next_nonce(owner().address())
                .unwrap()
                .next_nonce(),
            signed.intent.nonce.checked_add(1).unwrap()
        );
        let HttpReceiptQueryResult::Present {
            event_digest,
            dedup_record_bytes,
            ..
        } = endpoint
            .client
            .query_receipt(node_core::RequestId::new(request(tag)).unwrap())
            .unwrap()
        else {
            panic!("original receipt")
        };
        let receipt: node_core::NodeDedupRecord =
            node_core::NodeDedupRecord::decode(&dedup_record_bytes).unwrap();
        assert_eq!(event_digest, result.effects.tx_hash);
        assert_eq!(receipt.event_digest(), event_digest);
        let [response] = receipt.responses() else {
            panic!("one response")
        };
        assert_eq!(
            response.payload(),
            Some(saved(&format!("{tag}.result")).as_slice())
        );
        assert_eq!(response.status(), node_core::NodeResponseStatus::Accepted);
    }
}

struct Sink {
    directory: PathBuf,
    count: usize,
    bytes: usize,
}
impl ArtifactSink for Sink {
    fn persist(&mut self, name: &str, bytes: &[u8]) -> io::Result<()> {
        if name.len() > 128 || name.contains('/') || self.count >= 32 || bytes.len() > MAX_FILE {
            return Err(io::Error::other("fixture artifact bound"));
        }
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("fixture artifact overflow"))?;
        if self.bytes > 8 * MAX_FILE {
            return Err(io::Error::other("fixture artifact total bound"));
        }
        self.count += 1;
        let mut file: File = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.directory.join(name))?;
        file.write_all(bytes)?;
        file.sync_all()
    }
}
fn sink(name: &str) -> Sink {
    let directory: PathBuf = PathBuf::from(ARTIFACTS).join(name);
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    Sink {
        directory,
        count: 0,
        bytes: 0,
    }
}
// Test-only measurement, not protocol state or an authority source.
static CALLS: std::sync::Mutex<[u64; COUNT]> = std::sync::Mutex::new([0; COUNT]);
struct CountedTls {
    inner: RemoteTlsHttpTransport,
    index: usize,
}
impl Transport for CountedTls {
    fn send(
        &self,
        request: &WireRequest,
    ) -> Result<WireResponse, sunrise_edge_client::transport::TransportError> {
        let mut counts = CALLS.lock().unwrap();
        counts[self.index] = counts[self.index].checked_add(1).unwrap();
        assert!(
            counts[self.index] <= 96,
            "closed phase endpoint request budget"
        );
        drop(counts);
        let cap: Instant = Instant::now() + Duration::from_secs(2);
        let bounded: WireRequest = WireRequest {
            method: request.method,
            path: request.path.clone(),
            content_type: request.content_type,
            body: request.body.clone(),
            deadline: Some(request.deadline.map_or(cap, |deadline| deadline.min(cap))),
        };
        self.inner.send(&bounded)
    }
}
fn freeze() {
    let root: TrustedFastVoteGenesis = trusted();
    let mut next_set = root.genesis_root().manifest().validator_set.clone();
    next_set.context = PublicationContext::new(
        context().chain_id().clone(),
        ProtocolVersion::new(7),
        Epoch::new(1),
    )
    .unwrap();
    let intent: FreezeIntent = FreezeIntent {
        context: context(),
        request_id: FREEZE,
        advisory_next_set: next_set,
    };
    let candidate: OrderedCandidate = OrderedCandidate {
        context: context(),
        request_id: FREEZE,
        kind: OrderedOperationKind::Freeze,
        intent: encode_freeze_intent(&intent).unwrap(),
        created_checkpoint: 11,
    };
    let peers: Vec<OrderedEconomicsEndpoint<CountedTls>> = endpoints()
        .into_iter()
        .map(|endpoint| OrderedEconomicsEndpoint {
            validator_id: endpoint.validator_id,
            endpoint_label: endpoint.endpoint_label,
            client: endpoint.client,
        })
        .collect();
    let outcome = submit_candidate(
        &peers,
        &policy(),
        &encode_ordered_candidate(&candidate).unwrap(),
        None,
        Instant::now() + Duration::from_secs(20),
        Duration::from_secs(2),
        &mut sink("freeze"),
    )
    .unwrap();
    assert_eq!(outcome.rounds.len(), 3);
    assert_eq!(outcome.committed_outcome.request_id, FREEZE);
    assert_eq!(outcome.committed_outcome.block_height, 1);
    assert_eq!(
        outcome.committed_outcome.candidate_digest,
        policy().candidate_digest(&candidate).unwrap()
    );
    assert_eq!(outcome.committed_outcome.output.responses().len(), 1);
    assert_eq!(
        outcome.committed_outcome.output.responses()[0].status(),
        node_core::NodeResponseStatus::Accepted
    );
    for (index, round) in outcome.rounds.into_iter().enumerate() {
        assert_eq!(round.height, u64::try_from(index + 1).unwrap());
        assert_eq!(round.peers.len(), COUNT);
        assert_eq!(round.qc_formed_from.len(), 3);
        for peer in round.peers {
            assert!(matches!(peer.vote_phase, PeerPhaseOutcome::Applied(_)));
            assert!(matches!(
                peer.certificate_phase,
                PeerPhaseOutcome::Applied(_)
            ));
        }
        save(
            &format!("freeze.round{}.proposal", index + 1),
            &round.proposal_bytes,
        );
        save(
            &format!("freeze.round{}.certificate", index + 1),
            &round.certificate_bytes,
        );
    }
    save(
        "freeze.outcome",
        &encode_ordered_outcome(&outcome.committed_outcome).unwrap(),
    );
}
fn frozen() -> ExpectedDrainFreeze {
    let outcome: OrderedOutcome = decode_ordered_outcome(&saved("freeze.outcome")).unwrap();
    assert_eq!(outcome.request_id, FREEZE);
    assert_eq!(outcome.block_height, 1);
    ExpectedDrainFreeze {
        domain: domain(),
        closure_request_id: FREEZE,
        closure_height: outcome.block_height,
    }
}
fn frontier_certifier() -> FrozenFrontierCertifier {
    FrozenFrontierCertifier::new(
        context().chain_id().clone(),
        ProtocolVersion::new(7),
        Epoch::new(0),
        trusted().certifier().validator_set().clone(),
    )
    .unwrap()
}
fn frontier_vote(index: usize) -> FrozenFrontierVote {
    consensus::decode_frozen_frontier_vote(&saved(&format!("frontier-{index}.vote"))).unwrap()
}
fn frontier(replay: bool) {
    let certifier: FrozenFrontierCertifier = frontier_certifier();
    let frozen: ExpectedDrainFreeze = frozen();
    for (index, endpoint) in endpoints().iter().enumerate() {
        let mut vote: Option<FrozenFrontierVote> = None;
        for _ in 0..5 {
            if let Some(value) = endpoint
                .client
                .advance_frozen_frontier(
                    &certifier,
                    endpoint.validator_id,
                    Some(Instant::now() + Duration::from_secs(2)),
                )
                .unwrap()
            {
                vote = Some(value);
                break;
            }
        }
        let vote: FrozenFrontierVote = vote.unwrap();
        assert_eq!(vote.identity.closure_request_id, frozen.closure_request_id);
        assert_eq!(vote.identity.closure_height, frozen.closure_height);
        assert_eq!(vote.identity.entry_count, if index == 0 { 3 } else { 2 });
        let encoded: Vec<u8> = consensus::encode_frozen_frontier_vote(&vote).unwrap();
        if replay {
            assert_eq!(encoded, saved(&format!("frontier-{index}.vote")));
        } else {
            save(&format!("frontier-{index}.vote"), &encoded);
        }
        let mut verifier: FrozenFrontierPageVerifier = FrozenFrontierPageVerifier::new(
            &resolver(),
            &certifier,
            vote.clone(),
            &self::verifier(),
        )
        .unwrap();
        let mut after: Option<[u8; 32]> = None;
        let mut observed: Vec<[u8; 32]> = Vec::new();
        for page_index in 0..4 {
            let request: FrozenFrontierPageRequest = FrozenFrontierPageRequest {
                epoch: Epoch::new(0),
                after_request_id: after,
                limit: 1,
            };
            let (same, page): (FrozenFrontierVote, FrozenFrontierPage) = endpoint
                .client
                .fetch_signed_frozen_frontier_page(
                    &request,
                    &certifier,
                    endpoint.validator_id,
                    Some(Instant::now() + Duration::from_secs(2)),
                )
                .unwrap();
            assert_eq!(same, vote);
            verifier.push_page(&resolver(), &page).unwrap();
            observed.extend(page.entries.iter().map(|entry| entry.request_id));
            let bytes: Vec<u8> = success(
                send(
                    endpoint,
                    Method::Post,
                    FASTVOTE_FROZEN_FRONTIER_PAGE_PATH,
                    Some(NODE_EVENT_MEDIA_TYPE),
                    request.encode().unwrap(),
                ),
                NODE_RESULT_MEDIA_TYPE,
            );
            assert_eq!(
                bytes,
                FrozenFrontierPageResponse {
                    vote: encoded.clone(),
                    page: consensus::encode_frozen_frontier_page(&page).unwrap()
                }
                .encode()
                .unwrap()
            );
            let name: String = format!("frontier-{index}.page-{page_index}");
            if replay {
                assert_eq!(bytes, saved(&name));
            } else {
                save(&name, &bytes);
            }
            if page.terminal {
                break;
            }
            after = Some(page.entries.last().unwrap().request_id);
        }
        assert!(verifier.is_terminal());
        assert_eq!(
            observed,
            if index == 0 {
                vec![request(A), request(B), request(C)]
            } else {
                vec![request(A), request(B)]
            }
        );
    }
}
fn selected_frontier_votes() -> Vec<FrozenFrontierVote> {
    // Public saved votes/pins only: the read-only worker-UID oracle must not
    // open frontend-private TLS files or issue requests while comparing rows.
    let zero: ValidatorId =
        ValidatorId::new(parse_hex_32(&pins()["validator-0"], "validator").unwrap());
    let mut votes: Vec<FrozenFrontierVote> = (0..COUNT).map(frontier_vote).collect();
    votes.sort_by_key(|vote| vote.validator);
    let remove: usize = votes
        .iter()
        .rposition(|vote| vote.validator != zero)
        .unwrap();
    votes.remove(remove);
    assert_eq!(votes.len(), 3);
    assert!(votes.iter().any(|vote| vote.validator == zero));
    votes
}

fn drain(replay: bool) {
    let endpoints: Vec<FastVoteEndpoint<CountedTls>> = endpoints();
    let trusted: TrustedFastVoteGenesis = trusted();
    let certifier: FrozenFrontierCertifier = frontier_certifier();
    let selected: Vec<FrozenFrontierVote> = selected_frontier_votes();
    let client = &endpoints[1].client;
    if !replay {
        // Explicitly stage worker0's C-containing frontier and import real missing proof on worker1.
        let (_, page) = endpoints[0]
            .client
            .fetch_signed_frozen_frontier_page(
                &FrozenFrontierPageRequest {
                    epoch: Epoch::new(0),
                    after_request_id: None,
                    limit: 3,
                },
                &certifier,
                endpoints[0].validator_id,
                Some(Instant::now() + Duration::from_secs(2)),
            )
            .unwrap();
        assert_eq!(page.entries.len(), 3);
        assert!(page.terminal);
        client
            .stage_drain_signer_page(
                &certifier,
                endpoints[0].validator_id,
                frozen(),
                &frontier_vote(0),
                &page,
                Some(Instant::now() + Duration::from_secs(2)),
            )
            .unwrap();
        for entry in &page.entries {
            if entry.request_id == request(C) {
                let missing = client.confirm_drain_member(
                    Epoch::new(0),
                    endpoints[0].validator_id,
                    request(C),
                    Some(Instant::now() + Duration::from_secs(2)),
                );
                assert!(
                    matches!(missing, Err(sunrise_edge_client::error::ClientError::UnexpectedStatus { status: 409, ref body }) if body == "drain-proof-not-retained")
                );
                let bundle: PublicationBundle = endpoints[0]
                    .client
                    .source_retained_fastvote_publication(
                        trusted.certifier(),
                        &resolver(),
                        &[],
                        entry,
                        Some(Instant::now() + Duration::from_secs(2)),
                    )
                    .unwrap();
                client
                    .import_staged_drain_publication(
                        endpoints[0].validator_id,
                        &bundle,
                        entry,
                        trusted.certifier(),
                        &resolver(),
                        &[],
                        Some(Instant::now() + Duration::from_secs(2)),
                    )
                    .unwrap();
            }
            client
                .confirm_drain_member(
                    Epoch::new(0),
                    endpoints[0].validator_id,
                    entry.request_id,
                    Some(Instant::now() + Duration::from_secs(2)),
                )
                .unwrap();
        }
    }
    let sources: Vec<FastVoteEndpoint<CountedTls>> = self::endpoints()
        .into_iter()
        .filter(|endpoint| {
            selected
                .iter()
                .any(|vote| vote.validator == endpoint.validator_id)
        })
        .collect();
    let outcome: DrainDriveOutcome = drive_drain_to_local_ready(
        client,
        &sources,
        &endpoints,
        &selected,
        trusted.certifier(),
        &resolver(),
        &[],
        frozen(),
        DrainDriveBounds {
            overall_deadline: Instant::now() + Duration::from_secs(20),
            per_request_cap: Duration::from_secs(2),
            page_limit: 1,
            max_mutation_attempts: 32,
        },
    )
    .unwrap();
    let DrainDriveOutcome::LocallyReady {
        identity,
        mutation_attempts,
    } = outcome
    else {
        panic!("real local readiness")
    };
    assert!(mutation_attempts <= 32);
    assert_eq!(identity.member_count, 3);
    let encoded: Vec<u8> = consensus::encode_drain_union_identity(&identity).unwrap();
    if replay {
        assert_eq!(encoded, saved("drain.union"));
    } else {
        save("drain.union", &encoded);
    }
    for vote in selected {
        let response: Vec<u8> = success(
            send(
                &endpoints[1],
                Method::Post,
                FASTVOTE_DRAIN_SIGNER_PROGRESS_PATH,
                Some(NODE_EVENT_MEDIA_TYPE),
                DrainSignerProgressRequest {
                    epoch: Epoch::new(0),
                    signer: vote.validator,
                }
                .encode()
                .unwrap(),
            ),
            NODE_RESULT_MEDIA_TYPE,
        );
        let progress = client
            .read_drain_signer_progress(
                &certifier,
                vote.validator,
                frozen(),
                &resolver(),
                Some(Instant::now() + Duration::from_secs(2)),
            )
            .unwrap()
            .unwrap();
        assert!(progress.complete);
        assert_eq!(progress.vote, vote);
        assert!(progress.staged_page.is_none());
        // Use bounded short artifact names, not full validator IDs in filenames.
        let index: usize = endpoints
            .iter()
            .position(|endpoint| endpoint.validator_id == vote.validator)
            .unwrap();
        let name: String = format!("drain.progress-{index}");
        if replay {
            assert_eq!(response, saved(&name));
        } else {
            save(&name, &response);
        }
    }
}
fn unsigned_queries() {
    let root: TrustedFastVoteGenesis = trusted();
    let manifest = root.genesis_root().manifest();
    let original: &CallIntent = &manifest.initialization.intent.call;
    let record: execution::local_execution::InstanceRecord =
        execution::local_execution::InstanceRecord {
            context: original.context.clone(),
            creator: original.sender,
            seed: [0x32; 32],
            code: original.code.clone(),
            revision: 1,
            initializer: "init".into(),
        };
    for endpoint in endpoints() {
        endpoint.client.query_verified_context(&expected()).unwrap();
        assert_eq!(
            endpoint
                .client
                .query_paid_fee_policy(&resolver(), &expected())
                .unwrap(),
            manifest.fee_policy
        );
        assert_eq!(
            endpoint
                .client
                .query_instance(record.creator, record.seed, &resolver(), &expected())
                .unwrap()
                .unwrap(),
            record
        );
        assert!(
            endpoint
                .client
                .query_publication(
                    original.code.origin(),
                    &resolver(),
                    &expected(),
                    &execution::local_execution::generic_object_result_semantics(
                        &resolver(),
                        &context()
                    )
                    .unwrap()
                )
                .unwrap()
                .is_some()
        );
        let response: WireResponse = send(&endpoint, Method::Get, "/health/live", None, vec![1, 2]);
        assert_eq!(response.status, 204);
        assert!(response.body.is_empty());
        let nonce: u64 = endpoint
            .client
            .query_next_nonce(owner().address())
            .unwrap()
            .next_nonce();
        assert_eq!(nonce, 2);
        assert!(matches!(
            endpoint
                .client
                .query_receipt(node_core::RequestId::new(request(C)).unwrap())
                .unwrap(),
            HttpReceiptQueryResult::Absent { .. }
        ));
        for tag in [A, B] {
            let HttpReceiptQueryResult::Present {
                event_digest,
                dedup_record_bytes,
                ..
            } = endpoint
                .client
                .query_receipt(node_core::RequestId::new(request(tag)).unwrap())
                .unwrap()
            else {
                panic!("actual historical paid receipt")
            };
            let record: node_core::NodeDedupRecord =
                node_core::NodeDedupRecord::decode(&dedup_record_bytes).unwrap();
            assert_eq!(record.request_id().as_bytes(), &request(tag));
            assert_eq!(
                event_digest,
                paid_invocation_digest(&resolver(), &signed(tag)).unwrap()
            );
            assert_eq!(record.event_digest(), event_digest);
            let [response] = record.responses() else {
                panic!("one original paid response")
            };
            assert_eq!(response.status(), node_core::NodeResponseStatus::Accepted);
            assert_eq!(
                response.payload(),
                Some(saved(&format!("{tag}.result")).as_slice())
            );
        }
        current(&endpoint.client, ObjectId::new([0x22; 32]));
    }
}
fn bad_input() {
    let mut bad: SignedPaidIntent = signed(A);
    bad.signature[0] ^= 1;
    let bad: Vec<u8> = encode_signed_paid_intent(&bad).unwrap();
    let mut changed: PublicationBundle = bundle(A);
    changed.contents[0][0] ^= 1;
    for endpoint in endpoints() {
        let refused: WireResponse = send(
            &endpoint,
            Method::Post,
            FASTVOTE_PREPARE_PATH,
            Some(NODE_EVENT_MEDIA_TYPE),
            bad.clone(),
        );
        assert_eq!(refused.status, 400);
        assert_eq!(
            send(
                &endpoint,
                Method::Post,
                FASTVOTE_PUBLICATION_RETAIN_PATH,
                Some(NODE_EVENT_MEDIA_TYPE),
                encode_publication_bundle(&changed).unwrap()
            )
            .status,
            400
        );
        let original: Vec<u8> = FastVoteApplyRequest {
            signed_paid_intent: saved("a.intent"),
            certificate: saved("a.certificate"),
        }
        .encode()
        .unwrap();
        // Real fresh causal work cannot use the historical path without publication authority.
        assert_eq!(
            send(
                &endpoint,
                Method::Post,
                FASTVOTE_CERTIFICATES_PATH,
                Some(NODE_EVENT_MEDIA_TYPE),
                original
            )
            .status,
            400
        );
        let mut conflict: SignedPaidIntent = signed(A);
        conflict.intent.nonce = 1;
        let PaidApplication::Call(call) = &mut conflict.intent.application else {
            panic!("Call")
        };
        call.nonce = 1;
        let framed: Vec<u8> =
            execution::paid_execution::paid_intent_signing_frame(&context(), &conflict.intent)
                .unwrap();
        conflict.signature = ed25519_zebra::SigningKey::from([0x56; 32])
            .sign(&framed)
            .into();
        assert_eq!(
            send(
                &endpoint,
                Method::Post,
                FASTVOTE_PREPARE_PATH,
                Some(NODE_EVENT_MEDIA_TYPE),
                encode_signed_paid_intent(&conflict).unwrap()
            )
            .status,
            400
        );
        let mut wrong: AvailabilityCertificate = availability(A);
        wrong.votes[0].signature[0] ^= 1;
        let body: Vec<u8> = FastVotePublishedApplyRequest {
            signed_paid_intent: saved("a.intent"),
            certificate: saved("a.certificate"),
            availability_certificate: consensus::encode_availability_certificate(&wrong).unwrap(),
        }
        .encode()
        .unwrap();
        assert_eq!(
            send(
                &endpoint,
                Method::Post,
                FASTVOTE_PUBLISHED_APPLY_PATH,
                Some(NODE_EVENT_MEDIA_TYPE),
                body
            )
            .status,
            400
        );
        for route in [
            "/sign",
            "/v1/conditional-readiness",
            "/tmp/validator.key",
            "/v1/ordered-economics/propose",
        ] {
            assert_eq!(
                send(&endpoint, Method::Post, route, None, Vec::new()).status,
                404
            );
        }
    }
}
fn no_drain_set() {
    let body: Vec<u8> = DrainMemberApplyRequest {
        epoch: Epoch::new(0),
        member_request_id: request(C),
    }
    .encode()
    .unwrap();
    for endpoint in endpoints() {
        let response: WireResponse = send(
            &endpoint,
            Method::Post,
            FASTVOTE_DRAIN_APPLY_PATH,
            Some(NODE_EVENT_MEDIA_TYPE),
            body.clone(),
        );
        assert_eq!(response.status, 409);
        assert_eq!(response.body, b"drain-member-not-ready");
        assert!(matches!(
            endpoint
                .client
                .query_receipt(node_core::RequestId::new(request(C)).unwrap())
                .unwrap(),
            HttpReceiptQueryResult::Absent { .. }
        ));
        assert_eq!(
            endpoint
                .client
                .query_next_nonce(owner().address())
                .unwrap()
                .next_nonce(),
            2
        );
    }
}
fn worker_down() {
    for endpoint in endpoints() {
        let response: WireResponse = send(
            &endpoint,
            Method::Post,
            FASTVOTE_PREPARE_PATH,
            Some(NODE_EVENT_MEDIA_TYPE),
            saved("a.intent"),
        );
        assert_eq!(response.status, 503);
        assert_eq!(response.body, b"certified-custody-unavailable");
        let live: WireResponse = send(&endpoint, Method::Get, "/health/live", None, Vec::new());
        assert_eq!(live.status, 204);
        assert!(live.body.is_empty());
    }
}
fn closed_after_freeze() {
    let mut fresh: SignedPaidIntent = signed(C);
    fresh.intent.request_id = [0x2d; 32];
    let PaidApplication::Call(call) = &mut fresh.intent.application else {
        panic!("Call")
    };
    call.request_id = [0x2d; 32];
    fresh.signature = ed25519_zebra::SigningKey::from([0x56; 32])
        .sign(
            &execution::paid_execution::paid_intent_signing_frame(&context(), &fresh.intent)
                .unwrap(),
        )
        .into();
    let bytes: Vec<u8> = encode_signed_paid_intent(&fresh).unwrap();
    for endpoint in endpoints() {
        assert_eq!(
            send(
                &endpoint,
                Method::Post,
                FASTVOTE_PREPARE_PATH,
                Some(NODE_EVENT_MEDIA_TYPE),
                bytes.clone()
            )
            .status,
            400
        );
        let ack: Vec<u8> = success(
            send(
                &endpoint,
                Method::Post,
                FASTVOTE_PUBLICATION_RETAIN_PATH,
                Some(NODE_EVENT_MEDIA_TYPE),
                saved("a.bundle"),
            ),
            NODE_RESULT_MEDIA_TYPE,
        );
        let index: usize = pins()
            .iter()
            .find_map(|(key, value)| {
                if key.starts_with("validator-") && value == &hex(endpoint.validator_id.as_bytes())
                {
                    Some(key.trim_start_matches("validator-").parse().unwrap())
                } else {
                    None
                }
            })
            .unwrap();
        assert_eq!(ack, saved(&format!("a.ack-{index}")));
    }
}
fn tls_refusals() {
    let endpoint = endpoints().remove(0);
    let address: SocketAddr = String::from_utf8(read(format!("{PUBLIC}/address-0"), 128))
        .unwrap()
        .parse()
        .unwrap();
    let ca: Vec<u8> = read(path("front", 0, "ca.der"), 16 * 1024);
    let wrong_ca: Vec<u8> = read(path("front", 1, "ca.der"), 16 * 1024);
    let name: String = String::from_utf8(read(path("front", 0, "name"), 256)).unwrap();
    for (name, ca) in [
        ("unconfigured.sunrise-edge.invalid", ca.as_slice()),
        (name.as_str(), wrong_ca.as_slice()),
    ] {
        let transport: RemoteTlsHttpTransport = RemoteTlsHttpTransport::new(
            address,
            name,
            ca,
            Duration::from_secs(2),
            Duration::from_secs(2),
            Duration::from_secs(2),
            Duration::from_secs(2),
            Duration::from_secs(2),
            NonZeroUsize::new(16 * 1024).unwrap(),
            NonZeroUsize::new(MAX_FILE).unwrap(),
        )
        .unwrap();
        assert!(
            transport
                .send(&WireRequest {
                    method: Method::Get,
                    path: QUERY_CONTEXT_PATH.into(),
                    content_type: None,
                    body: Vec::new(),
                    deadline: Some(Instant::now() + Duration::from_secs(2))
                })
                .is_err()
        );
    }
    assert_eq!(
        endpoint.validator_id.as_bytes(),
        &parse_hex_32(&pins()["validator-0"], "validator").unwrap()
    );
}
fn connection(index: usize) -> Connection {
    let connection: Connection = Connection::open_with_flags(
        path("source", index, "state.sqlite"),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap();
    connection.busy_timeout(Duration::from_secs(1)).unwrap();
    connection
}
// Match the closed full-image oracle's per-cell admission before copying.
fn sql_blob(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<Vec<u8>> {
    let bytes: &[u8] = row.get_ref(index)?.as_blob()?;
    assert!(bytes.len() <= 512 * 1024, "SQL cell admission before copy");
    Ok(bytes.to_vec())
}
fn row(connection: &Connection, key: &[u8]) -> Option<Vec<u8>> {
    connection
        .query_row(
            "SELECT value FROM durable_state WHERE key=?1",
            [key],
            |row| {
                if matches!(row.get_ref(0)?, rusqlite::types::ValueRef::Null) {
                    Ok(None)
                } else {
                    sql_blob(row, 0).map(Some)
                }
            },
        )
        .optional()
        .unwrap()
        .flatten()
}
fn receipt(connection: &Connection, id: [u8; 32]) -> Option<Vec<u8>> {
    connection
        .query_row(
            "SELECT canonical_bytes FROM durable_receipts WHERE request_id=?1",
            [id.as_slice()],
            |row| sql_blob(row, 0),
        )
        .optional()
        .unwrap()
}

fn material(connection: &Connection, tag: &str, index: usize, imported: bool) {
    use node_core::fast_path::{drain_publication, publication};
    let trusted: TrustedFastVoteGenesis = trusted();
    let original: PublicationBundle = bundle(tag);
    let identity: AvailabilityIdentity =
        drain_publication::verify_drain_publication_bundle_with_profile(
            &resolver(),
            &[],
            &context(),
            trusted.admission_profile(),
            domain(),
            trusted.certifier(),
            &original,
        )
        .unwrap();
    let key: Vec<u8> = if imported {
        drain_publication::drain_publication_key(context().chain_id(), Epoch::new(0), &request(tag))
            .unwrap()
    } else {
        publication::fastpath_publication_key(context().chain_id(), &request(tag)).unwrap()
    };
    let stored: publication::FastPathPublicationRecord =
        publication::decode_fastpath_publication_record(&row(connection, &key).unwrap()).unwrap();
    assert_eq!(stored.request_id, request(tag));
    assert_eq!(stored.context, context());
    assert_eq!(
        stored.identity,
        consensus::encode_availability_identity(&identity).unwrap()
    );
    assert_eq!(stored.signed_intent, original.signed_intent);
    assert_eq!(
        stored.certificate,
        consensus::encode_fast_certificate(&original.certificate).unwrap()
    );
    assert_eq!(stored.witness, original.witness);
    assert_eq!(
        stored.manifest,
        consensus::bundle::encode_artifact_manifest(&original.manifest).unwrap()
    );
    for (entry, bytes) in original.manifest.entries.iter().zip(&original.contents) {
        let key: Vec<u8> = if imported {
            drain_publication::drain_publication_artifact_key(
                context().chain_id(),
                Epoch::new(0),
                &request(tag),
                entry,
            )
            .unwrap()
        } else {
            publication::fastpath_publication_artifact_key(
                context().chain_id(),
                &request(tag),
                entry.kind,
                &entry.content_digest.bytes(),
            )
            .unwrap()
        };
        assert_eq!(row(connection, &key).as_ref(), Some(bytes));
    }
    let ack_key: Vec<u8> =
        publication::fastpath_availability_ack_key(context().chain_id(), &request(tag)).unwrap();
    if imported {
        assert!(row(connection, &ack_key).is_none());
        assert!(
            row(
                connection,
                &publication::fastpath_publication_key(context().chain_id(), &request(tag))
                    .unwrap()
            )
            .is_none()
        );
    } else {
        let ack = publication::decode_fastpath_availability_ack_record(
            &row(connection, &ack_key).unwrap(),
        )
        .unwrap();
        assert_eq!(ack.vote, saved(&format!("{tag}.ack-{index}")));
        assert_eq!(ack.identity, stored.identity);
        let vote: AvailabilityVote = consensus::decode_availability_vote(&ack.vote).unwrap();
        assert_eq!(
            hex(vote.validator.as_bytes()),
            pins()[&format!("validator-{index}")]
        );
        AvailabilityCertifier::new(
            context().chain_id().clone(),
            ProtocolVersion::new(7),
            Epoch::new(0),
            trusted.certifier().validator_set().clone(),
        )
        .unwrap()
        .verify_vote(&vote, &verifier())
        .unwrap();
    }
}
fn prepared_row(connection: &Connection, tag: &str, index: usize, locked: bool) {
    use node_core::{fast_path::records, local_instance_state as state};
    let signed: SignedPaidIntent = signed(tag);
    let key: Vec<u8> =
        state::fastpath_prepared_record_key(context().chain_id(), &request(tag)).unwrap();
    let prepared: records::FastPathPreparedRecord =
        records::decode_fastpath_prepared_record(&row(connection, &key).unwrap()).unwrap();
    assert_eq!(prepared.vote, saved(&format!("{tag}.vote-{index}")));
    assert_eq!(
        prepared.signed_intent_digest,
        paid_invocation_digest(&resolver(), &signed).unwrap()
    );
    assert_eq!(prepared.context, context());
    assert_eq!(prepared.request_id, request(tag));
    let PaidApplication::Call(call) = &signed.intent.application else {
        panic!("Call")
    };
    let mut expected_locks: Vec<ObjectRef> = vec![signed.intent.consent.source.clone()];
    expected_locks.extend(
        call.access
            .entries
            .iter()
            .map(|entry| entry.object_ref.clone()),
    );
    assert_eq!(prepared.locked_objects, expected_locks);
    assert_eq!(prepared.pending_nonce, signed.intent.nonce);
    assert_eq!(prepared.created_checkpoint, 10);
    assert!(prepared.prepared_generation.is_some());
    let vote: FastVote = consensus::decode_fast_vote(&prepared.vote).unwrap();
    assert_eq!(vote.execution_effects_hash, prepared.commitment);
    assert_eq!(
        hex(vote.validator.as_bytes()),
        pins()[&format!("validator-{index}")]
    );
    trusted()
        .certifier()
        .verify_vote(&vote, &verifier())
        .unwrap();
    if locked {
        let key: Vec<u8> = state::fastpath_nonce_lock_key(
            context().chain_id(),
            &signed.intent.sender,
            Epoch::new(0),
        )
        .unwrap();
        let nonce =
            state::decode_fastpath_nonce_lock_record(&row(connection, &key).unwrap()).unwrap();
        assert_eq!(nonce.request_id, request(tag));
        assert_eq!(nonce.nonce, signed.intent.nonce);
        for reference in &prepared.locked_objects {
            let lock = state::decode_fastpath_lock_record(
                &row(
                    connection,
                    &state::fastpath_lock_key(context().chain_id(), reference.id).unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
            assert_eq!(lock.request_id, request(tag));
            assert_eq!(&lock.object, reference);
        }
    }
}
fn applied_row(connection: &Connection, tag: &str) {
    use node_core::{fast_path::records, local_instance_state as state};
    let signed: SignedPaidIntent = signed(tag);
    let result: PaidExecutionResult = result(tag);
    let cert: records::FastPathCertificateRecord = records::decode_fastpath_certificate_record(
        &row(
            connection,
            &state::fastpath_certificate_key(context().chain_id(), &request(tag)).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(cert.request_id, request(tag));
    assert_eq!(cert.certificate, saved(&format!("{tag}.certificate")));
    let available = records::decode_fastpath_availability_certificate_record(
        &row(
            connection,
            &records::fastpath_availability_certificate_key(context().chain_id(), &request(tag))
                .unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(available.request_id, request(tag));
    assert_eq!(available.certificate, saved(&format!("{tag}.availability")));
    let settlement: records::FastPathSettlementRecord = records::decode_fastpath_settlement_record(
        &row(
            connection,
            &state::fastpath_settlement_key(context().chain_id(), &request(tag)).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(settlement.context, context());
    assert_eq!(settlement.request_id, request(tag));
    let charged = result.charged.as_ref().unwrap();
    assert_eq!(settlement.fee_output.as_ref(), Some(&charged.fee_output));
    assert_eq!(settlement.total_amount, Some(charged.actual.get()));
    let original: Vec<u8> = receipt(connection, request(tag)).unwrap();
    let receipt: node_core::NodeDedupRecord =
        node_core::NodeDedupRecord::decode(&original).unwrap();
    assert_eq!(receipt.request_id().as_bytes(), &request(tag));
    assert_eq!(
        receipt.event_digest(),
        paid_invocation_digest(&resolver(), &signed).unwrap()
    );
    let [response] = receipt.responses() else {
        panic!("one original response")
    };
    assert_eq!(response.status(), node_core::NodeResponseStatus::Accepted);
    assert_eq!(
        response.payload(),
        Some(saved(&format!("{tag}.result")).as_slice())
    );
    for effect in &result.effects.object_effects {
        if let ObjectEffect::Created(object)
        | ObjectEffect::Mutated {
            new_object: object, ..
        } = effect
        {
            let bytes: Vec<u8> = connection.query_row("SELECT inline_canonical_bytes FROM durable_object_versions WHERE object_id=?1 AND object_version=?2", (object.id.as_bytes().as_slice(), object.version), |row| sql_blob(row, 0)).unwrap();
            assert_eq!(bytes, objects::encode_object(object).unwrap());
        }
    }
}
fn drain_rows(connection: &Connection) {
    use consensus::{DrainUnionAccumulator, FrozenFrontierIdentity};
    use node_core::ordered_economics::{
        drain_signer_entry_key, drain_signer_progress_key, drain_union_progress_key,
        drain_union_ready_key,
    };
    let selected: Vec<FrozenFrontierVote> = selected_frontier_votes();
    let pairs: Vec<(ValidatorId, FrozenFrontierIdentity)> = selected
        .iter()
        .map(|vote| (vote.validator, vote.identity.clone()))
        .collect();
    let seed: DrainUnionAccumulator = DrainUnionAccumulator::new(
        &resolver(),
        context().chain_id().clone(),
        ProtocolVersion::new(7),
        Epoch::new(0),
        domain(),
        FREEZE,
        1,
        &pairs,
    )
    .unwrap();
    let selection_digest: Digest32 = seed.identity().entries_digest;
    let mut complete: DrainUnionAccumulator = seed;
    for tag in [A, B, C] {
        let ack: AvailabilityVote =
            consensus::decode_availability_vote(&saved(&format!("{tag}.ack-0"))).unwrap();
        complete.push_member(&resolver(), &ack.identity).unwrap();
    }
    let identity: Vec<u8> = consensus::encode_drain_union_identity(complete.identity()).unwrap();
    assert_eq!(identity, saved("drain.union"));
    for (kind, key) in [
        (
            0x645C,
            drain_union_progress_key(context().chain_id(), Epoch::new(0), &selection_digest)
                .unwrap(),
        ),
        (
            0x645D,
            drain_union_ready_key(context().chain_id(), Epoch::new(0), &selection_digest).unwrap(),
        ),
    ] {
        let bytes: Vec<u8> = row(connection, &key).unwrap();
        let frame = decode_canonical_frame(&bytes).unwrap();
        frame.require_type(kind).unwrap();
        frame.require_version(1).unwrap();
        assert_eq!(frame.required_field(1).unwrap(), identity);
        let base: u16 = if kind == 0x645C {
            assert_eq!(frame.required_field(2).unwrap(), request(C));
            assert_eq!(
                frame.required_field(3).unwrap(),
                canonical_encoding::encode_digest32(&selection_digest).unwrap()
            );
            4
        } else {
            assert_eq!(
                frame.required_field(2).unwrap(),
                canonical_encoding::encode_digest32(&selection_digest).unwrap()
            );
            3
        };
        assert_eq!(frame.field_count(), usize::from(base) + selected.len());
        assert_eq!(
            usize::from(frame.required_u16(base).unwrap()),
            selected.len()
        );
        for (index, vote) in selected.iter().enumerate() {
            assert_eq!(
                frame
                    .required_field(base + u16::try_from(index + 1).unwrap())
                    .unwrap(),
                consensus::encode_frozen_frontier_vote(vote).unwrap()
            );
        }
    }
    for vote in selected {
        let index: usize = (0..COUNT)
            .position(|index| frontier_vote(index).validator == vote.validator)
            .unwrap();
        let response: DrainSignerProgressResponse =
            DrainSignerProgressResponse::decode(&saved(&format!("drain.progress-{index}")))
                .unwrap();
        let key: Vec<u8> =
            drain_signer_progress_key(context().chain_id(), Epoch::new(0), vote.validator).unwrap();
        let bytes: Vec<u8> = row(connection, &key).unwrap();
        let frame = decode_canonical_frame(&bytes).unwrap();
        frame.require_type(0x645B).unwrap();
        frame.require_version(1).unwrap();
        frame.require_only_fields(&[1, 2, 3, 4, 5]).unwrap();
        assert_eq!(
            frame.required_field(1).unwrap(),
            consensus::encode_frozen_frontier_vote(&vote).unwrap()
        );
        assert_eq!(frame.required_field(1).unwrap(), response.vote);
        assert_eq!(
            frame.required_field(2).unwrap(),
            consensus::encode_frozen_frontier_identity(&vote.identity).unwrap()
        );
        assert_eq!(
            frame.required_field(2).unwrap(),
            response.confirmed_identity
        );
        let last: [u8; 32] = request(if index == 0 { C } else { B });
        assert_eq!(frame.required_field(3).unwrap(), last);
        assert_eq!(response.cursor, Some(last));
        assert!(frame.required_field(4).unwrap().is_empty());
        assert!(response.staged_page.is_none());
        assert_eq!(frame.required_u16(5).unwrap(), 1);
        assert!(response.complete);
        assert_eq!(response.chain_id, context().chain_id().as_str());
        assert_eq!(response.epoch, Epoch::new(0));
        assert_eq!(response.signer, vote.validator);
        for tag in if index == 0 {
            &[A, B, C][..]
        } else {
            &[A, B][..]
        } {
            let key: Vec<u8> = drain_signer_entry_key(
                context().chain_id(),
                Epoch::new(0),
                vote.validator,
                &request(tag),
            )
            .unwrap();
            let ack: AvailabilityVote =
                consensus::decode_availability_vote(&saved(&format!("{tag}.ack-0"))).unwrap();
            assert_eq!(
                row(connection, &key).unwrap(),
                consensus::encode_availability_identity(&ack.identity).unwrap()
            );
        }
    }
}

fn oracle_records(stage: &str) {
    for index in 0..COUNT {
        let connection: Connection = connection(index);
        let have_a: bool = !matches!(stage, "initial");
        let have_b: bool = matches!(
            stage,
            "b-applied" | "c-retained" | "frozen" | "frontier" | "drained"
        );
        let have_c: bool = matches!(stage, "c-retained" | "frozen" | "frontier" | "drained");
        let applied_a: bool = !matches!(stage, "initial" | "a-prepared" | "a-retained");
        if have_a {
            prepared_row(
                &connection,
                A,
                index,
                matches!(stage, "a-prepared" | "a-retained"),
            );
            if stage == "a-prepared" {
                assert!(
                    row(
                        &connection,
                        &node_core::fast_path::publication::fastpath_publication_key(
                            context().chain_id(),
                            &request(A)
                        )
                        .unwrap()
                    )
                    .is_none()
                );
                assert!(
                    row(
                        &connection,
                        &node_core::fast_path::publication::fastpath_availability_ack_key(
                            context().chain_id(),
                            &request(A)
                        )
                        .unwrap()
                    )
                    .is_none()
                );
            } else {
                material(&connection, A, index, false);
            }
        }
        if have_a && applied_a {
            applied_row(&connection, A);
        }
        if have_b {
            prepared_row(&connection, B, index, false);
            material(&connection, B, index, false);
            applied_row(&connection, B);
        }
        if have_c {
            prepared_row(&connection, C, index, true);
            assert!(receipt(&connection, request(C)).is_none());
            if index == 0 {
                material(&connection, C, index, false);
            } else if stage == "drained" && index == 1 {
                material(&connection, C, index, true);
            } else {
                assert!(
                    row(
                        &connection,
                        &node_core::fast_path::publication::fastpath_publication_key(
                            context().chain_id(),
                            &request(C)
                        )
                        .unwrap()
                    )
                    .is_none()
                );
            }
        }
        if !applied_a {
            assert!(receipt(&connection, request(A)).is_none());
        }
        let nonce_key: Vec<u8> =
            runtime::PersistenceLayout::new(context().chain_id().clone(), ProtocolVersion::new(7))
                .sender_nonce_key(*owner().address().as_bytes(), Epoch::new(0));
        let expected_nonce: u64 = if have_b {
            2
        } else {
            u64::from(have_a && applied_a)
        };
        match row(&connection, &nonce_key) {
            None => assert_eq!(expected_nonce, 0),
            Some(bytes) => {
                let frame = decode_canonical_frame(&bytes).unwrap();
                frame.require_type(0xE006).unwrap();
                frame.require_version(1).unwrap();
                frame.require_only_fields(&[1, 2, 3]).unwrap();
                assert_eq!(
                    frame.required_field(1).unwrap(),
                    owner().address().as_bytes()
                );
                assert_eq!(frame.required_u64(2).unwrap(), 0);
                assert_eq!(frame.required_u64(3).unwrap(), expected_nonce);
            }
        }
        if matches!(stage, "frozen" | "frontier" | "drained") {
            let outcome: OrderedOutcome = decode_ordered_outcome(&saved("freeze.outcome")).unwrap();
            let original: Vec<u8> = receipt(&connection, FREEZE).unwrap();
            let receipt: node_core::NodeDedupRecord =
                node_core::NodeDedupRecord::decode(&original).unwrap();
            assert_eq!(receipt.responses(), outcome.output.responses());
        }
        if matches!(stage, "frontier" | "drained") {
            let mut statement = connection
                .prepare("SELECT value FROM durable_state WHERE value IS NOT NULL ORDER BY key")
                .unwrap();
            let mut cursor: rusqlite::Rows<'_> = statement.query([]).unwrap();
            let mut values: Vec<Vec<u8>> = Vec::new();
            let mut total: usize = 0;
            while let Some(row) = cursor.next().unwrap() {
                assert!(values.len() < 1024, "complete SQL row admission");
                let bytes: &[u8] = row.get_ref(0).unwrap().as_blob().unwrap();
                assert!(bytes.len() <= 512 * 1024, "SQL cell admission before copy");
                total = total.checked_add(bytes.len()).unwrap();
                assert!(
                    total <= 16 * 1024 * 1024,
                    "SQL scan byte admission before copy"
                );
                values.push(bytes.to_vec());
            }
            drop(cursor);
            let mut found: usize = 0;
            for value in values {
                if let Ok(frame) = decode_canonical_frame(&value)
                    && frame.type_id() == 0x645A
                {
                    frame.require_version(2).unwrap();
                    frame.require_only_fields(&[1, 2]).unwrap();
                    assert_eq!(
                        frame.required_field(2).unwrap(),
                        saved(&format!("frontier-{index}.vote"))
                    );
                    let vote: FrozenFrontierVote =
                        consensus::decode_frozen_frontier_vote(frame.required_field(2).unwrap())
                            .unwrap();
                    frontier_certifier()
                        .verify_vote(&vote, &verifier())
                        .unwrap();
                    assert_eq!(
                        consensus::decode_frozen_frontier_identity(
                            frame.required_field(1).unwrap()
                        )
                        .unwrap(),
                        vote.identity
                    );
                    found += 1;
                }
            }
            assert_eq!(found, 1);
            drop(statement);
        }
        if stage == "drained" && index == 1 {
            drain_rows(&connection);
        }
        connection.close().unwrap();
    }
}

fn images() -> (Vec<Image>, Vec<AnchorImage>) {
    let source: Vec<Image> = (0..COUNT)
        .map(|index| {
            sqlite_durable_image::capture(
                &path("source", index, "state.sqlite"),
                &path("source", index, "body.sqlite"),
            )
        })
        .collect();
    let anchors: Vec<AnchorImage> = (0..COUNT)
        .map(|index| {
            sqlite_durable_image::capture_anchor(&path("authority", index, "anchor.sqlite"))
        })
        .collect();
    for fd in fs::read_dir("/proc/self/fd").unwrap() {
        if let Ok(target) = fs::read_link(fd.unwrap().path()) {
            assert!(
                !target.starts_with("/work/source") && !target.starts_with("/work/authority"),
                "oracle retained DB/lease FD"
            );
        }
    }
    (source, anchors)
}
fn oracle() {
    let stream = std::os::unix::net::UnixStream::connect("/work/oracle/control.sock").unwrap();
    let end: Instant = Instant::now() + Duration::from_secs(210);
    let mut stream: BufReader<std::os::unix::net::UnixStream> = BufReader::new(stream);
    let mut baseline: Option<(Vec<Image>, Vec<AnchorImage>)> = None;
    for _ in 0..64 {
        let remaining: Duration = end.checked_duration_since(Instant::now()).unwrap();
        stream
            .get_ref()
            .set_read_timeout(Some(remaining.min(Duration::from_secs(30))))
            .unwrap();
        stream
            .get_ref()
            .set_write_timeout(Some(remaining.min(Duration::from_secs(2))))
            .unwrap();
        let mut phase: String = String::new();
        let count: usize = stream.by_ref().take(65).read_line(&mut phase).unwrap();
        assert!(count > 0 && count <= 64 && phase.ends_with('\n'));
        let phase: &str = phase.trim_end_matches('\n');
        match phase {
            "baseline" => baseline = Some(images()),
            "unchanged" | "finish" => assert_eq!(&images(), baseline.as_ref().unwrap()),
            "fence-2" | "fence-3" | "fence-4" | "fence-5" | "fence-6" => {
                let next = images();
                let previous = baseline.as_ref().unwrap();
                let to: u64 = phase.strip_prefix("fence-").unwrap().parse().unwrap();
                sqlite_durable_image::assert_only_fence_changed(&previous.0, &next.0, to - 1, to);
                assert_ne!(previous.1, next.1);
                baseline = Some(next);
            }
            "initial" | "a-prepared" | "a-retained" | "a-applied" | "b-applied" | "c-retained"
            | "frozen" | "frontier" | "drained" => {
                oracle_records(phase);
                baseline = Some(images());
            }
            _ => panic!("closed certified oracle phase"),
        }
        stream
            .get_mut()
            .write_all(format!("ok {phase}\n").as_bytes())
            .unwrap();
        if phase == "finish" {
            return;
        }
    }
    panic!("oracle phase bound exhausted");
}
#[test]
#[ignore = "requires reviewed bounded Docker multi-UID controller and exact five compiled inputs"]
fn fixture_certified_fastvote_role_probe() {
    let phase: String = env::var("SUNRISE_CERTIFIED_FIXTURE_PHASE").unwrap();
    match phase.as_str() {
        "prepare-inputs" => prepare_inputs(),
        "publish-genesis" => publish_genesis(),
        "frontend-inputs" => frontend_inputs(),
        "tls-refusals" => tls_refusals(),
        "a-prepare" => {
            prepare_votes(A);
            unapplied_a();
        }
        "a-retain" => {
            retain(A);
            unapplied_a();
        }
        "a-repeat" => replay_prepared(A),
        "a-apply" => apply(A, false),
        "a-apply-replay" => apply(A, true),
        "b-fresh" => {
            prepared(B);
            apply(B, false);
        }
        "c-retained" => prepared(C),
        "bad-input" => bad_input(),
        "worker-down" => worker_down(),
        "freeze" => freeze(),
        "frontier-first" => frontier(false),
        "frontier-replay" => frontier(true),
        "drain-first" => drain(false),
        "drain-replay" => drain(true),
        "no-drain-set" => no_drain_set(),
        "closed-after-freeze" => closed_after_freeze(),
        "queries" => unsigned_queries(),
        "wrong-output" => wrong_output(),
        "oracle" => oracle(),
        _ => panic!("closed certified fixture phase"),
    }
    println!(
        "certified_phase={} endpoint_requests={:?}",
        phase,
        *CALLS.lock().unwrap()
    );
}
fn wrong_output() {
    let address: SocketAddr =
        String::from_utf8(read(format!("{PUBLIC}/wrong-output-address"), 128))
            .unwrap()
            .parse()
            .unwrap();
    let name: String = String::from_utf8(read(path("front", 0, "name"), 256)).unwrap();
    let ca: Vec<u8> = read(path("front", 0, "ca.der"), 16 * 1024);
    assert_eq!(
        https_relay::authenticated_leaf(address, &name, &ca),
        read(path("front", 0, "leaf.der"), 16 * 1024)
    );
    let transport: RemoteTlsHttpTransport = RemoteTlsHttpTransport::new(
        address,
        &name,
        &ca,
        Duration::from_secs(2),
        Duration::from_secs(2),
        Duration::from_secs(2),
        Duration::from_secs(2),
        Duration::from_secs(2),
        NonZeroUsize::new(16 * 1024).unwrap(),
        NonZeroUsize::new(MAX_FILE).unwrap(),
    )
    .unwrap();
    let endpoint: FastVoteEndpoint<CountedTls> = FastVoteEndpoint {
        validator_id: ValidatorId::new(parse_hex_32(&pins()["validator-0"], "validator").unwrap()),
        endpoint_label: address.to_string(),
        client: Client::new(CountedTls {
            inner: transport,
            index: 0,
        }),
    };
    for route in [
        FASTVOTE_PREPARE_PATH,
        FASTVOTE_PUBLICATION_RETAIN_PATH,
        FASTVOTE_PREPARE_PATH,
        FASTVOTE_PREPARE_PATH,
        FASTVOTE_PREPARE_PATH,
    ] {
        let body: Vec<u8> = if route == FASTVOTE_PUBLICATION_RETAIN_PATH {
            saved("a.bundle")
        } else {
            saved("a.intent")
        };
        let response: WireResponse = send(
            &endpoint,
            Method::Post,
            route,
            Some(NODE_EVENT_MEDIA_TYPE),
            body,
        );
        assert_eq!(response.status, 503);
        assert_eq!(response.body, b"certified-custody-unavailable");
    }
}
