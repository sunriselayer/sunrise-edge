//! Actual offline executable plus existing ordered ingress. A predicted row
//! below is only a caller claim: these tests do not certify VM execution or E
//! registration. The genuine committed-execution tests belong to node-core.

use std::{
    fs::{self, File},
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use abi::{AccessEntry, AccessManifest};
use crypto::SignatureSigner;
use execution::{
    call::CallIntent,
    local_execution::{
        LocalExecutionIntent, LocalExecutionMode, LocalExecutionPolicy, SignedLocalExecutionIntent,
        encode_signed_local_execution, local_execution_signing_frame,
    },
    protocol_custody::derive_deposit_owner_token,
};
use node_core::{
    fast_path::records::FastPathBondState,
    genesis::{
        GenesisManifest, encode_genesis_manifest, genesis_manifest_commitment,
        genesis_manifest_signing_frame,
    },
};
use objects::{Object, ObjectRef, Owner, ProtocolCustodyPurpose, ProtocolCustodyScope};
use protocol_types::HashPurpose;
use runtime::{DurableObjectVersion, ObjectHeadRevision};
use sunrise_edge_client::{
    AccessMode, AtomicityDomainId, ChainId, CommitmentProfile, Digest32,
    ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_BINDING_ID,
    ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID, Epoch, HashAlgorithmId,
    HashSuite, HashSuiteId, HashSuiteResolver, HashSuiteSchedule, HttpContextQueryResult,
    HttpObjectQueryResult, LocalSigner, ProtocolVersion, PublicationContext,
    QUERY_RESULT_MEDIA_TYPE, SignatureSchemeId, ValidatorId, VerifiedGenesisRoot,
    bond_registration::{
        BondRegistrationContext, FastPathBondRecord, LocalBondRegistrationError,
        MAX_BOND_REGISTRATION_ROW_BYTES, MAX_LOCAL_EXECUTION_INTENT_BYTES,
        PreparedLocalBondRegistration, decode_signed_bond_registration_intent,
        encode_fastpath_bond_record, verify_signed_bond_registration,
    },
    ordered_economics::{
        ORDERED_ECONOMICS_OUTCOME_PATH_PREFIX, ORDERED_ECONOMICS_PROPOSE_PATH,
        ORDERED_ECONOMICS_STATUS_PATH, ORDERED_STATUS_MEDIA_TYPE, OrderedProposeRequest,
    },
    ordered_economics_client::load_trusted_ordered_policy,
    ordered_economics_core::{
        OrderedCandidate, OrderedOperationKind, OrderedStatus, decode_ordered_candidate,
        encode_ordered_status,
    },
};
use sunrise_edge_devnet::{
    DEVNET_PAID_GENESIS_SEED, DevOwner, PaidGenesisActivationMetadata, build_paid_genesis_manifest,
};

const NEW_SEED: [u8; 32] = [0x65; 32];
const SOURCE_SEED: [u8; 32] = [0x67; 32];

#[path = "../../../clients/rust/tests/support/external_signer.rs"]
mod external_signer;
const REQUEST_ID: [u8; 32] = [0x86; 32];
const SUITE: &str = "0:23:2:2:2:2:2:2";
static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte: &u8| format!("{byte:02x}"))
        .collect()
}

fn write_seed(path: &Path, seed: [u8; 32]) {
    fs::write(path, hex(&seed)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

struct Fixture {
    directory: PathBuf,
    context: PublicationContext,
    resolver: HashSuiteResolver,
    domain: AtomicityDomainId,
    manifest: GenesisManifest,
    digest: Digest32,
    row: FastPathBondRecord,
    leg: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        let directory: PathBuf = std::env::temp_dir().join(format!(
            "sunrise-cli-bond-registration-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&directory).unwrap();
        let context: PublicationContext = PublicationContext::new(
            ChainId::new("cli-bond-registration").unwrap(),
            ProtocolVersion::new(7),
            Epoch::new(0),
        )
        .unwrap();
        let resolver: HashSuiteResolver = HashSuiteResolver::new(
            context.chain_id().clone(),
            context.protocol_version(),
            vec![HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: HashSuite {
                    id: HashSuiteId::new(23),
                    transaction_hash: HashAlgorithmId::Sha3_256,
                    object_digest: HashAlgorithmId::Sha3_256,
                    effects_hash: HashAlgorithmId::Sha3_256,
                    code_hash: HashAlgorithmId::Sha3_256,
                    config_hash: HashAlgorithmId::Sha3_256,
                    certificate_hash: HashAlgorithmId::Sha3_256,
                },
            }],
        )
        .unwrap();
        let signer: LocalSigner = LocalSigner::from_seed(NEW_SEED);
        let source_signer: LocalSigner = LocalSigner::from_seed(SOURCE_SEED);
        let owner: DevOwner = DevOwner::new(*source_signer.address().as_bytes());
        let (mut manifest, metadata): (GenesisManifest, PaidGenesisActivationMetadata) =
            build_paid_genesis_manifest(&resolver, &context, &[owner], owner).unwrap();
        manifest.commitment_profile = CommitmentProfile::CausalAdmission;
        manifest.minimum_freeze_block_height = 1;
        let genesis_signer: LocalSigner = LocalSigner::from_seed(DEVNET_PAID_GENESIS_SEED);
        manifest.signature = genesis_signer
            .sign_framed(&genesis_manifest_signing_frame(&manifest).unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let digest: Digest32 = genesis_manifest_commitment(&resolver, &manifest).unwrap();
        let resource = &manifest.economics_policy.resources[0];
        let source = manifest
            .objects
            .iter()
            .find(|entry| entry.object.id == metadata.owner_coins[0].spend_coin)
            .unwrap();
        assert_eq!(source.object.owner, Owner::Address(source_signer.address()));
        let source_ref: ObjectRef = object_ref(&resolver, &source.object, context.epoch());
        let scope: ProtocolCustodyScope = ProtocolCustodyScope {
            purpose: ProtocolCustodyPurpose::BondCollateral,
            chain_id: context.chain_id().clone(),
            subject: *signer.address().as_bytes(),
            resource: *resource.resource_id.value(),
        };
        let token: [u8; 32] =
            derive_deposit_owner_token(&resolver, &context, source.object.id, &scope).unwrap();
        let intent: LocalExecutionIntent = LocalExecutionIntent {
            mode: LocalExecutionMode::Call,
            policy_digest: LocalExecutionPolicy::generic_object_results(context.clone())
                .digest(&resolver)
                .unwrap(),
            call: CallIntent {
                context: context.clone(),
                request_id: REQUEST_ID,
                sender: *source_signer.address().as_bytes(),
                nonce: 0,
                code: resource.code.clone(),
                instance: resource.instance.clone(),
                entrypoint: resource.transfer_entrypoint.clone(),
                type_arguments: vec![public_standard_asset::asset_type_argument(
                    &metadata.definition_id,
                )],
                access: AccessManifest {
                    entries: vec![AccessEntry {
                        object_ref: source_ref,
                        mode: AccessMode::Write,
                    }],
                },
                arguments: public_standard_asset::transfer_arguments(&token).unwrap(),
                gas_limit: 500_000,
            },
            authorizations: Vec::new(),
        };
        let signed_leg: SignedLocalExecutionIntent = SignedLocalExecutionIntent {
            signature: source_signer
                .sign_framed(&local_execution_signing_frame(&context, &intent).unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
            intent,
        };
        let leg: Vec<u8> = encode_signed_local_execution(&signed_leg).unwrap();
        // Prediction only. No object is installed or executed in this fixture.
        let predicted_object: Object = Object {
            version: source.object.version.checked_add(1).unwrap(),
            owner: Owner::ProtocolCustody(scope),
            ..source.object.clone()
        };
        let row: FastPathBondRecord = FastPathBondRecord {
            context: resource.context.clone(),
            validator_id: ValidatorId::new(*signer.address().as_bytes()),
            resource_domain: resource.resource_id.domain(),
            resource: *resource.resource_id.value(),
            custody_object: object_ref(&resolver, &predicted_object, context.epoch()),
            custody_object_epoch: context.epoch(),
            authority: source.authority.clone(),
            amount: public_standard_asset::coin_amount(&source.object.data).unwrap(),
            committed_at_checkpoint: 0,
            generation: 1,
            lifecycle_epoch: context.epoch(),
            slashable_from_epoch: Epoch::new(1),
            required_minimum: resource.bond.as_ref().unwrap().min_bond.get(),
            state: FastPathBondState::Active,
            authorization_scheme: SignatureSchemeId::Ed25519,
            authorization_key: *signer.address().as_bytes(),
        };
        fs::write(
            directory.join("genesis"),
            encode_genesis_manifest(&manifest).unwrap(),
        )
        .unwrap();
        fs::write(
            directory.join("source-coin"),
            objects::encode_object(&source.object).unwrap(),
        )
        .unwrap();
        fs::write(directory.join("leg"), &leg).unwrap();
        fs::write(
            directory.join("row"),
            encode_fastpath_bond_record(&row).unwrap(),
        )
        .unwrap();
        write_seed(&directory.join("seed"), NEW_SEED);
        Self {
            directory,
            context,
            resolver,
            domain: AtomicityDomainId::new([0x44; 32]).unwrap(),
            manifest,
            digest,
            row,
            leg,
        }
    }

    fn path(&self, name: &str) -> String {
        self.directory.join(name).to_str().unwrap().to_string()
    }

    fn pins(&self) -> Vec<String> {
        vec![
            "--ordered-genesis-manifest".into(),
            self.path("genesis"),
            "--ordered-expected-genesis-digest".into(),
            hex(&self.digest.bytes()),
            "--expected-chain-id".into(),
            self.context.chain_id().as_str().into(),
            "--expected-protocol-version".into(),
            self.context.protocol_version().get().to_string(),
            "--expected-epoch".into(),
            self.context.epoch().get().to_string(),
            "--domain".into(),
            hex(self.domain.as_bytes()),
            "--suite".into(),
            SUITE.into(),
        ]
    }

    fn prepare_args(&self, output: &str) -> Vec<String> {
        let mut args: Vec<String> = vec!["economics".into(), "bond-registration-prepare".into()];
        args.extend(self.pins());
        args.extend([
            "--request-id".into(),
            hex(&REQUEST_ID),
            "--signed-leg".into(),
            self.path("leg"),
            "--expected-bond-row".into(),
            self.path("row"),
            "--seed-file".into(),
            self.path("seed"),
            "--out".into(),
            self.path(output),
        ]);
        args
    }

    fn preview_args(&self, authorization_key: [u8; 32]) -> Vec<String> {
        let mut args: Vec<String> = vec!["economics".into(), "bond-registration-preview".into()];
        args.extend(self.pins());
        args.extend([
            "--request-id".into(),
            hex(&REQUEST_ID),
            "--signed-leg".into(),
            self.path("leg"),
            "--expected-bond-row".into(),
            self.path("row"),
            "--expected-authorization-key".into(),
            hex(&authorization_key),
        ]);
        args
    }

    fn inner_preview_args(&self) -> Vec<String> {
        let resource = &self.manifest.economics_policy.resources[0].resource_id;
        let source_key = LocalSigner::from_seed(SOURCE_SEED);
        let validator_key = LocalSigner::from_seed(NEW_SEED);
        let mut args = vec!["economics".into(), "bond-inner-preview".into()];
        args.extend(self.pins());
        args.extend([
            "--source-coin".into(),
            self.path("source-coin"),
            "--source-key".into(),
            hex(source_key.address().as_bytes()),
            "--validator-key".into(),
            hex(validator_key.address().as_bytes()),
            "--resource-domain".into(),
            resource.domain().to_string(),
            "--resource-id".into(),
            hex(resource.value()),
            "--nonce".into(),
            "0".into(),
            "--request-id".into(),
            hex(&REQUEST_ID),
            "--gas-limit".into(),
            "500000".into(),
        ]);
        args
    }

    fn wrap_args(&self, intent: &str, output: &str) -> Vec<String> {
        let mut args: Vec<String> = vec!["economics".into(), "candidate-wrap".into()];
        args.extend(self.pins());
        args.extend([
            "--kind".into(),
            "bond-registration".into(),
            "--intent".into(),
            self.path(intent),
            "--request-id".into(),
            hex(&REQUEST_ID),
            "--created-checkpoint".into(),
            "0".into(),
            "--out".into(),
            self.path(output),
        ]);
        args
    }

    fn input_inventory(&self) -> Vec<Vec<u8>> {
        ["genesis", "source-coin", "leg", "row", "seed"]
            .map(|name: &str| fs::read(self.path(name)).unwrap())
            .to_vec()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if !thread::panicking() {
            let _ignored: std::io::Result<()> = fs::remove_dir_all(&self.directory);
        }
    }
}

fn object_ref(resolver: &HashSuiteResolver, object: &Object, epoch: Epoch) -> ObjectRef {
    ObjectRef {
        id: object.id,
        version: object.version,
        digest: resolver
            .hash_for_purpose(
                epoch,
                HashPurpose::Object,
                &objects::encode_object(object).unwrap(),
            )
            .unwrap(),
    }
}

fn run(args: &[String]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sunrise-edge-cli"))
        .args(args)
        .output()
        .unwrap()
}

fn replace(args: &mut [String], flag: &str, value: String) {
    let index: usize = args
        .iter()
        .position(|argument: &String| argument == flag)
        .unwrap();
    args[index + 1] = value;
}

fn refuse(output: &Output) {
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).starts_with("error="));
}

#[test]
fn executable_prepares_exact_claim_wraps_kind7_and_preserves_inputs() {
    let fixture: Fixture = Fixture::new();
    let inputs: Vec<Vec<u8>> = fixture.input_inventory();
    let output: Output = run(&fixture.prepare_args("signed"));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout: String = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("preparation=structural_registration_claim\nexecuted=false\n"));
    assert!(!stdout.contains("ready=true"));
    let bytes: Vec<u8> = fs::read(fixture.path("signed")).unwrap();
    let genesis_bytes: Vec<u8> = encode_genesis_manifest(&fixture.manifest).unwrap();
    let root: VerifiedGenesisRoot = VerifiedGenesisRoot::verify_bytes(
        &fixture.resolver,
        &genesis_bytes,
        fixture.digest.bytes(),
        &fixture.context,
    )
    .unwrap();
    let signed = verify_signed_bond_registration(&root, &bytes).unwrap();
    assert_eq!(signed.intent.validator_id, fixture.row.validator_id);
    assert_eq!(
        signed.intent.authorization_key,
        fixture.row.authorization_key
    );
    assert_eq!(signed.intent.leg, fixture.leg);
    assert_eq!(signed.intent.request_id, REQUEST_ID);
    let wrapped: Output = run(&fixture.wrap_args("signed", "candidate"));
    assert!(
        wrapped.status.success(),
        "{}",
        String::from_utf8_lossy(&wrapped.stderr)
    );
    let candidate: OrderedCandidate =
        decode_ordered_candidate(&fs::read(fixture.path("candidate")).unwrap()).unwrap();
    assert_eq!(candidate.kind, OrderedOperationKind::BondRegistration);
    assert_eq!(candidate.intent, bytes);
    assert_eq!(candidate.request_id, REQUEST_ID);
    assert_eq!(candidate.context, fixture.context);
    assert_eq!(fixture.input_inventory(), inputs);
}

#[test]
fn original_inner_preview_rebuilds_the_existing_whole_coin_leg_without_signing() {
    let fixture = Fixture::new();
    fs::remove_file(fixture.path("seed")).unwrap();
    let mut before: Vec<String> = fs::read_dir(&fixture.directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    before.sort();
    let output = run(&fixture.inner_preview_args());
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let leg = execution::local_execution::decode_signed_local_execution(&fixture.leg).unwrap();
    let frame = local_execution_signing_frame(&fixture.context, &leg.intent).unwrap();
    let source_bytes = fs::read(fixture.path("source-coin")).unwrap();
    let source_object = objects::decode_object(&source_bytes).unwrap();
    let scope = ProtocolCustodyScope {
        purpose: ProtocolCustodyPurpose::BondCollateral,
        chain_id: fixture.context.chain_id().clone(),
        subject: *fixture.row.validator_id.as_bytes(),
        resource: fixture.row.resource,
    };
    let token = derive_deposit_owner_token(
        &fixture.resolver,
        &fixture.context,
        source_object.id,
        &scope,
    )
    .unwrap();
    let mut predicted_object = source_object.clone();
    predicted_object.version += 1;
    predicted_object.owner = Owner::ProtocolCustody(scope);
    assert!(stdout.starts_with(
        "profile=original-genesis-standard-asset-bond-inner\nauthorizing=false\nsigned=false\nexecuted=false\n"
    ));
    assert!(stdout.contains("source_snapshot_unverified=true\n"));
    assert!(stdout.contains("source_endpoint_current_inline_checked=false\n"));
    assert!(stdout.contains("source_current_query_chain_proof=false\n"));
    assert!(stdout.contains("code_revision=1\n"));
    assert!(stdout.contains("code_dependencies=none\nentrypoint=transfer\n"));
    assert!(stdout.contains(&format!("amount={}\n", fixture.row.amount)));
    assert!(stdout.contains(&format!(
        "source_id={}\n",
        leg.intent.call.access.entries[0].object_ref.id
    )));
    assert!(stdout.contains(&format!(
        "predicted_digest={}\n",
        fixture.row.custody_object.digest
    )));
    assert!(stdout.contains(&format!("unsigned_frame_hex={}\n", hex(&frame))));
    assert!(stdout.contains(&format!("source_object_hex={}\n", hex(&source_bytes))));
    assert!(stdout.contains(&format!(
        "predicted_object_hex={}\n",
        hex(&objects::encode_object(&predicted_object).unwrap())
    )));
    assert!(stdout.contains(&format!("deposit_token={}\n", hex(&token))));
    assert!(stdout.contains(&format!("policy_digest={}\n", leg.intent.policy_digest)));
    assert!(stdout.contains(&format!(
        "unsigned_intent_hex={}\n",
        hex(&execution::local_execution::encode_local_execution_intent(&leg.intent).unwrap())
    )));
    assert_eq!(
        leg.intent.call.sender,
        *LocalSigner::from_seed(SOURCE_SEED).address().as_bytes()
    );
    assert_eq!(
        fixture.row.authorization_key,
        *LocalSigner::from_seed(NEW_SEED).address().as_bytes()
    );
    assert_ne!(leg.intent.call.sender, fixture.row.authorization_key);
    let mut after: Vec<String> = fs::read_dir(&fixture.directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    after.sort();
    assert_eq!(before, after);
    assert!(!Path::new(&fixture.path("signed")).exists());
}

fn bond_query_context(fixture: &Fixture) -> Vec<u8> {
    HttpContextQueryResult::new(
        fixture.context.chain_id().clone(),
        fixture.context.protocol_version(),
        fixture.context.epoch(),
        HashSuiteId::new(23),
        ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID,
        SignatureSchemeId::Ed25519.as_u16(),
        ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_BINDING_ID,
        fixture.domain,
        vec![1],
    )
    .unwrap()
    .encode()
    .unwrap()
}

fn bond_query_source(fixture: &Fixture) -> Vec<u8> {
    let bytes = fs::read(fixture.path("source-coin")).unwrap();
    let object = objects::decode_object(&bytes).unwrap();
    HttpObjectQueryResult::CurrentInline {
        object_id: object.id,
        head_revision: ObjectHeadRevision::new(1).unwrap(),
        object_version: DurableObjectVersion::new(object.version).unwrap(),
        digest: object_ref(&fixture.resolver, &object, fixture.context.epoch()).digest,
        creating_chain_id: fixture.context.chain_id().clone(),
        creating_protocol_version: fixture.context.protocol_version(),
        canonical_object_bytes: bytes,
    }
    .encode()
    .unwrap()
}

fn source_query_probe(
    responses: Vec<Vec<u8>>,
) -> (SocketAddr, JoinHandle<Result<Vec<ObservedRequest>, String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let worker = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut requests = Vec::new();
        for response in responses {
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(pair) => break pair,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => return Err(format!("query accept: {error}")),
                }
            };
            requests.push(read_request(&mut stream)?);
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {QUERY_RESULT_MEDIA_TYPE}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response.len()
            );
            stream
                .write_all(header.as_bytes())
                .and_then(|()| stream.write_all(&response))
                .map_err(|error| error.to_string())?;
        }
        Ok(requests)
    });
    (address, worker)
}

#[test]
fn original_inner_preview_checks_endpoint_reported_current_source_without_authority() {
    let fixture = Fixture::new();
    fs::remove_file(fixture.path("seed")).unwrap();
    let source = objects::decode_object(&fs::read(fixture.path("source-coin")).unwrap()).unwrap();
    let (endpoint, worker) = source_query_probe(vec![
        bond_query_context(&fixture),
        bond_query_source(&fixture),
    ]);
    let mut args = fixture.inner_preview_args();
    args.extend([
        "--endpoint".into(),
        endpoint.to_string(),
        "--source-object-id".into(),
        hex(source.id.as_bytes()),
    ]);
    let output = run(&args);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("source_endpoint_current_inline_checked=true\n"));
    assert!(stdout.contains("source_snapshot_unverified=true\n"));
    assert!(stdout.contains("source_current_query_chain_proof=false\n"));
    assert!(stdout.contains("authorizing=false\nsigned=false\nexecuted=false\n"));
    assert!(!Path::new(&fixture.path("signed")).exists());
    let requests = worker.join().unwrap().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        (requests[0].method.as_str(), requests[0].path.as_str()),
        ("GET", "/v1/context")
    );
    assert_eq!(requests[1].method, "GET");
    assert_eq!(
        requests[1].path,
        format!("/v1/objects/{}", hex(source.id.as_bytes()))
    );
}

#[test]
fn original_inner_preview_refuses_changed_or_unverifiable_current_source() {
    let fixture = Fixture::new();
    let original = fs::read(fixture.path("source-coin")).unwrap();
    let source = objects::decode_object(&original).unwrap();
    let base_args = {
        let mut args = fixture.inner_preview_args();
        args.extend([
            "--endpoint".into(),
            "127.0.0.1:1".into(),
            "--source-object-id".into(),
            hex(source.id.as_bytes()),
        ]);
        args
    };
    let (endpoint, worker) = source_query_probe(vec![
        bond_query_context(&fixture),
        HttpObjectQueryResult::Absent {
            object_id: source.id,
        }
        .encode()
        .unwrap(),
    ]);
    let mut args = base_args.clone();
    replace(&mut args, "--endpoint", endpoint.to_string());
    refuse(&run(&args));
    worker.join().unwrap().unwrap();

    let invalid_context = HttpContextQueryResult::new(
        ChainId::new("another-chain").unwrap(),
        fixture.context.protocol_version(),
        fixture.context.epoch(),
        HashSuiteId::new(23),
        ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID,
        SignatureSchemeId::Ed25519.as_u16(),
        ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_BINDING_ID,
        fixture.domain,
        vec![1],
    )
    .unwrap()
    .encode()
    .unwrap();
    let (endpoint, worker) = source_query_probe(vec![invalid_context]);
    let mut args = base_args.clone();
    replace(&mut args, "--endpoint", endpoint.to_string());
    refuse(&run(&args));
    assert_eq!(worker.join().unwrap().unwrap().len(), 1);

    let wrong_digest = HttpObjectQueryResult::CurrentInline {
        object_id: source.id,
        head_revision: ObjectHeadRevision::new(1).unwrap(),
        object_version: DurableObjectVersion::new(source.version).unwrap(),
        digest: Digest32::new(HashAlgorithmId::Sha3_256, [0xAA; 32]),
        creating_chain_id: fixture.context.chain_id().clone(),
        creating_protocol_version: fixture.context.protocol_version(),
        canonical_object_bytes: original.clone(),
    }
    .encode()
    .unwrap();
    let (endpoint, worker) = source_query_probe(vec![bond_query_context(&fixture), wrong_digest]);
    let mut args = base_args.clone();
    replace(&mut args, "--endpoint", endpoint.to_string());
    refuse(&run(&args));
    worker.join().unwrap().unwrap();

    // A self-consistent body digest for another chain still cannot become
    // this original-genesis bond source's reviewed access reference.
    let foreign_chain = ChainId::new("another-chain").unwrap();
    let foreign_resolver = HashSuiteResolver::new(
        foreign_chain.clone(),
        fixture.context.protocol_version(),
        vec![HashSuiteSchedule {
            activation_epoch: fixture.context.epoch(),
            suite: fixture
                .resolver
                .suite_for_epoch(fixture.context.epoch())
                .unwrap()
                .clone(),
        }],
    )
    .unwrap();
    let foreign_provenance = HttpObjectQueryResult::CurrentInline {
        object_id: source.id,
        head_revision: ObjectHeadRevision::new(1).unwrap(),
        object_version: DurableObjectVersion::new(source.version).unwrap(),
        digest: foreign_resolver
            .hash_for_purpose(fixture.context.epoch(), HashPurpose::Object, &original)
            .unwrap(),
        creating_chain_id: foreign_chain,
        creating_protocol_version: fixture.context.protocol_version(),
        canonical_object_bytes: original.clone(),
    }
    .encode()
    .unwrap();
    let (endpoint, worker) =
        source_query_probe(vec![bond_query_context(&fixture), foreign_provenance]);
    let mut args = base_args.clone();
    replace(&mut args, "--endpoint", endpoint.to_string());
    refuse(&run(&args));
    worker.join().unwrap().unwrap();

    let mut changed = source.clone();
    changed.version += 1;
    fs::write(
        fixture.path("source-coin"),
        objects::encode_object(&changed).unwrap(),
    )
    .unwrap();
    let (endpoint, worker) = source_query_probe(vec![bond_query_context(&fixture), {
        // The endpoint still reports the original source snapshot.
        HttpObjectQueryResult::CurrentInline {
            object_id: source.id,
            head_revision: ObjectHeadRevision::new(1).unwrap(),
            object_version: DurableObjectVersion::new(source.version).unwrap(),
            digest: object_ref(&fixture.resolver, &source, fixture.context.epoch()).digest,
            creating_chain_id: fixture.context.chain_id().clone(),
            creating_protocol_version: fixture.context.protocol_version(),
            canonical_object_bytes: original.clone(),
        }
        .encode()
        .unwrap()
    }]);
    let mut args = base_args.clone();
    replace(&mut args, "--endpoint", endpoint.to_string());
    refuse(&run(&args));
    worker.join().unwrap().unwrap();
    for incomplete in [
        vec!["--endpoint".into(), "127.0.0.1:1".into()],
        vec!["--source-object-id".into(), hex(source.id.as_bytes())],
        vec!["--tls-server-name".into(), "example.invalid".into()],
    ] {
        let mut args = fixture.inner_preview_args();
        args.extend(incomplete);
        refuse(&run(&args));
    }
}

#[test]
fn original_inner_preview_refuses_untrusted_scope_source_and_entrypoint() {
    let fixture = Fixture::new();
    let args = fixture.inner_preview_args();
    for (flag, value) in [
        (
            "--source-key",
            hex(LocalSigner::from_seed([0x68; 32]).address().as_bytes()),
        ),
        ("--resource-id", hex(&[0xAA; 32])),
        ("--expected-epoch", "1".into()),
        ("--ordered-expected-genesis-digest", hex(&[0xBB; 32])),
    ] {
        let mut case = args.clone();
        replace(&mut case, flag, value);
        refuse(&run(&case));
    }
    for extra in [
        vec!["--out".into(), fixture.path("signed")],
        vec!["--successor-max-links".into(), "1".into()],
        vec!["--seed-file".into(), fixture.path("seed")],
    ] {
        let mut case = args.clone();
        case.extend(extra);
        refuse(&run(&case));
    }
    let original = fs::read(fixture.path("source-coin")).unwrap();
    fs::write(fixture.path("source-coin"), [0_u8; 3]).unwrap();
    refuse(&run(&args));
    let mut wrong_owner = objects::decode_object(&original).unwrap();
    wrong_owner.owner = Owner::Address(LocalSigner::from_seed([0x68; 32]).address());
    fs::write(
        fixture.path("source-coin"),
        objects::encode_object(&wrong_owner).unwrap(),
    )
    .unwrap();
    refuse(&run(&args));
    let mut overflowing = objects::decode_object(&original).unwrap();
    overflowing.version = u64::MAX;
    fs::write(
        fixture.path("source-coin"),
        objects::encode_object(&overflowing).unwrap(),
    )
    .unwrap();
    refuse(&run(&args));
    fs::write(fixture.path("source-coin"), original).unwrap();

    let genesis_signer = LocalSigner::from_seed(DEVNET_PAID_GENESIS_SEED);
    for case in 0..5 {
        let mut changed = fixture.manifest.clone();
        let replacement_ty = changed.fee_policy.reservation_type.clone();
        let resource = &mut changed.economics_policy.resources[0];
        match case {
            0 => std::mem::swap(
                &mut resource.split_entrypoint,
                &mut resource.transfer_entrypoint,
            ),
            1 => {
                resource.code = execution::publication::UnverifiedDependencyRef::new(
                    resource.code.origin().clone(),
                    2,
                    resource.context.clone(),
                    *resource.code.artifact_digest(),
                )
                .unwrap()
            }
            2 => resource.instance.seed[0] ^= 1,
            3 => resource.ty = replacement_ty,
            4 => resource.schema += 1,
            _ => unreachable!(),
        }
        changed.signature = genesis_signer
            .sign_framed(&genesis_manifest_signing_frame(&changed).unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let changed_digest = genesis_manifest_commitment(&fixture.resolver, &changed).unwrap();
        fs::write(
            fixture.path("genesis"),
            encode_genesis_manifest(&changed).unwrap(),
        )
        .unwrap();
        let mut changed_args = args.clone();
        replace(
            &mut changed_args,
            "--ordered-expected-genesis-digest",
            hex(&changed_digest.bytes()),
        );
        refuse(&run(&changed_args));
    }
    assert!(!Path::new(&fixture.path("signed")).exists());
}

#[test]
fn seed_free_preview_recomputes_exact_original_content_without_output() {
    let fixture: Fixture = Fixture::new();
    let signer: LocalSigner = LocalSigner::from_seed(NEW_SEED);
    let key: [u8; 32] = *signer.address().as_bytes();
    fs::remove_file(fixture.path("seed")).unwrap();
    let mut before: Vec<String> = fs::read_dir(&fixture.directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    before.sort();
    let output: Output = run(&fixture.preview_args(key));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let stdout: String = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.starts_with(
        "preview=structural_bond_registration\napproved=false\nsigned=false\nexecuted=false\nleg_semantics=unreviewed\nscope=original\n"
    ));
    assert!(stdout.contains(&format!("chain_id={}\n", fixture.context.chain_id())));
    assert!(stdout.contains(&format!(
        "ordered_domain={}\n",
        hex(fixture.domain.as_bytes())
    )));
    assert!(stdout.contains("protocol_version=7\nepoch=0\n"));
    assert!(stdout.contains(&format!("validator_id={}\n", hex(&key))));
    assert!(stdout.contains(&format!("predicted_amount={}\n", fixture.row.amount)));
    assert!(stdout.contains(&format!("signed_leg_hex={}\n", hex(&fixture.leg))));
    assert!(stdout.contains(&format!(
        "predicted_row_hex={}\n",
        hex(&encode_fastpath_bond_record(&fixture.row).unwrap())
    )));
    let trusted: BondRegistrationContext = BondRegistrationContext::load(
        Path::new(&fixture.path("genesis")),
        &fixture.resolver,
        fixture.digest.bytes(),
        &fixture.context,
        fixture.domain,
    )
    .unwrap();
    let prepared: PreparedLocalBondRegistration = trusted
        .prepare_for_public_key(key, REQUEST_ID, fixture.leg.clone(), fixture.row.clone())
        .unwrap();
    assert!(stdout.contains(&format!(
        "outer_intent_hex={}\n",
        hex(&node_core::bond_lifecycle::registration::encode_bond_registration_intent(
            prepared.intent()
        )
        .unwrap())
    )));
    assert!(stdout.contains(&format!(
        "outer_frame_hex={}\n",
        hex(prepared.signable_frame())
    )));
    let mut after: Vec<String> = fs::read_dir(&fixture.directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    after.sort();
    assert_eq!(before, after);
    assert!(!Path::new(&fixture.path("signed")).exists());
}

#[test]
fn original_registration_preview_recognizes_only_the_exact_pinned_inner_leg() {
    let fixture = Fixture::new();
    fs::remove_file(fixture.path("seed")).unwrap();
    let validator_key = *LocalSigner::from_seed(NEW_SEED).address().as_bytes();
    let source_key = *LocalSigner::from_seed(SOURCE_SEED).address().as_bytes();
    let mut args = fixture.preview_args(validator_key);
    args.extend([
        "--inner-source-coin".into(),
        fixture.path("source-coin"),
        "--inner-source-key".into(),
        hex(&source_key),
    ]);
    let original_source = fs::read(fixture.path("source-coin")).unwrap();
    let output = run(&args);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("leg_semantics=manifest-pinned-original-standard-asset-whole-transfer\n")
    );
    assert!(stdout.contains("source_snapshot_unverified=true\n"));
    assert!(stdout.contains("approved=false\nsigned=false\nexecuted=false\n"));
    assert_eq!(
        fs::read(fixture.path("source-coin")).unwrap(),
        original_source
    );
    assert!(!Path::new(&fixture.path("signed")).exists());

    let mut wrong_key = args.clone();
    replace(
        &mut wrong_key,
        "--inner-source-key",
        hex(LocalSigner::from_seed([0x68; 32]).address().as_bytes()),
    );
    refuse(&run(&wrong_key));
    let mut changed_source = objects::decode_object(&original_source).unwrap();
    changed_source.version += 1;
    fs::write(
        fixture.path("source-coin"),
        objects::encode_object(&changed_source).unwrap(),
    )
    .unwrap();
    refuse(&run(&args));
    fs::write(fixture.path("source-coin"), &original_source).unwrap();

    for missing in ["--inner-source-coin", "--inner-source-key"] {
        let mut incomplete = args.clone();
        let index = incomplete.iter().position(|arg| arg == missing).unwrap();
        incomplete.drain(index..=index + 1);
        refuse(&run(&incomplete));
    }
    assert!(!Path::new(&fixture.path("signed")).exists());
}

#[test]
fn seed_free_preview_refuses_changed_leg_row_and_key_without_output() {
    let fixture: Fixture = Fixture::new();
    let signer: LocalSigner = LocalSigner::from_seed(NEW_SEED);
    let key: [u8; 32] = *signer.address().as_bytes();
    fs::remove_file(fixture.path("seed")).unwrap();
    let wrong_key: [u8; 32] = *LocalSigner::from_seed([0x66; 32]).address().as_bytes();
    let output: Output = run(&fixture.preview_args(wrong_key));
    refuse(&output);
    assert!(!Path::new(&fixture.path("signed")).exists());

    let mut forbidden_signing_flags: Vec<String> = fixture.preview_args(key);
    forbidden_signing_flags.extend(["--seed-file".into(), fixture.path("missing-seed")]);
    refuse(&run(&forbidden_signing_flags));
    let mut forbidden_output_flags: Vec<String> = fixture.preview_args(key);
    forbidden_output_flags.extend(["--out".into(), fixture.path("signed")]);
    refuse(&run(&forbidden_output_flags));
    let mut forbidden_successor_flags: Vec<String> = fixture.preview_args(key);
    forbidden_successor_flags.extend(["--successor-max-links".into(), "1".into()]);
    let successor_output: Output = run(&forbidden_successor_flags);
    refuse(&successor_output);
    let mut complete_successor_flags: Vec<String> = fixture.preview_args(key);
    complete_successor_flags.extend([
        "--successor-genesis-epoch".into(),
        "0".into(),
        "--successor-max-links".into(),
        "1".into(),
        "--successor-plan-history-dir".into(),
        fixture.path("missing-plan-history"),
        "--successor-cut-dir".into(),
        fixture.path("missing-cut"),
        "--successor-manifest-history-dir".into(),
        fixture.path("missing-manifest-history"),
        "--successor-certificate-dir".into(),
        fixture.path("missing-certificate"),
    ]);
    let successor_output: Output = run(&complete_successor_flags);
    refuse(&successor_output);
    assert!(
        String::from_utf8_lossy(&successor_output.stderr)
            .contains("successor authority refused: successor artifact could not be read")
    );
    assert!(!Path::new(&fixture.path("signed")).exists());

    let mut altered_leg: SignedLocalExecutionIntent =
        execution::local_execution::decode_signed_local_execution(&fixture.leg).unwrap();
    altered_leg.intent.call.request_id = [0x87; 32];
    fs::write(
        fixture.path("leg"),
        encode_signed_local_execution(&altered_leg).unwrap(),
    )
    .unwrap();
    let output: Output = run(&fixture.preview_args(key));
    refuse(&output);
    fs::write(fixture.path("leg"), &fixture.leg).unwrap();

    fs::write(fixture.path("row"), [0x00_u8, 0x01]).unwrap();
    refuse(&run(&fixture.preview_args(key)));
    fs::write(
        fixture.path("row"),
        encode_fastpath_bond_record(&fixture.row).unwrap(),
    )
    .unwrap();

    let mut altered_row: FastPathBondRecord = fixture.row.clone();
    altered_row.generation = 2;
    fs::write(
        fixture.path("row"),
        encode_fastpath_bond_record(&altered_row).unwrap(),
    )
    .unwrap();
    let output: Output = run(&fixture.preview_args(key));
    refuse(&output);
    assert!(!Path::new(&fixture.path("signed")).exists());
}

#[test]
fn executable_rejects_invalid_pins_keys_claims_and_unused_flags_before_output() {
    let fixture: Fixture = Fixture::new();
    let mut cases: Vec<Vec<String>> = Vec::new();
    for (flag, value) in [
        ("--ordered-expected-genesis-digest", hex(&[0x22; 32])),
        ("--expected-protocol-version", "4294967296".into()),
        ("--expected-epoch", "1".into()),
        ("--request-id", hex(&[0; 32])),
        ("--request-id", hex(&[0x01; 32])),
        ("--suite", "0:1:1:1:1:1:1:1".into()),
    ] {
        let mut args: Vec<String> = fixture.prepare_args("refused");
        replace(&mut args, flag, value);
        cases.push(args);
    }
    for flag in [
        "--endpoint",
        "--ledger-hid-path",
        "--tls-server-name",
        "--validator-id",
    ] {
        let mut args: Vec<String> = fixture.prepare_args("refused");
        args.extend([flag.into(), "unused".into()]);
        cases.push(args);
    }
    let mut without_suite: Vec<String> = fixture.prepare_args("refused");
    let suite_index: usize = without_suite
        .iter()
        .position(|value| value == "--suite")
        .unwrap();
    without_suite.drain(suite_index..=suite_index + 1);
    cases.push(without_suite);
    let input_bytes: Vec<Vec<u8>> = fixture.input_inventory();
    for args in cases {
        refuse(&run(&args));
        assert!(!Path::new(&fixture.path("refused")).exists());
        assert_eq!(fixture.input_inventory(), input_bytes);
    }
    write_seed(Path::new(&fixture.path("other-seed")), [0x66; 32]);
    let mut wrong_key: Vec<String> = fixture.prepare_args("refused");
    replace(&mut wrong_key, "--seed-file", fixture.path("other-seed"));
    refuse(&run(&wrong_key));
    assert!(!Path::new(&fixture.path("refused")).exists());
    write_seed(
        Path::new(&fixture.path("genesis-seed")),
        DEVNET_PAID_GENESIS_SEED,
    );
    replace(&mut wrong_key, "--seed-file", fixture.path("genesis-seed"));
    refuse(&run(&wrong_key));
    assert!(!Path::new(&fixture.path("refused")).exists());
    let mut row: FastPathBondRecord = fixture.row.clone();
    row.generation = 2;
    fs::write(
        fixture.path("wrong-row"),
        encode_fastpath_bond_record(&row).unwrap(),
    )
    .unwrap();
    let mut wrong_row: Vec<String> = fixture.prepare_args("refused");
    replace(
        &mut wrong_row,
        "--expected-bond-row",
        fixture.path("wrong-row"),
    );
    refuse(&run(&wrong_row));
    assert!(!Path::new(&fixture.path("refused")).exists());
}

#[test]
fn executable_output_is_fresh_never_aliases_inputs_and_bounds_original_material() {
    let fixture: Fixture = Fixture::new();
    let inputs: Vec<Vec<u8>> = fixture.input_inventory();
    fs::write(fixture.path("existing"), b"keep exact original").unwrap();
    refuse(&run(&fixture.prepare_args("existing")));
    assert_eq!(
        fs::read(fixture.path("existing")).unwrap(),
        b"keep exact original"
    );
    for input in ["genesis", "leg", "row", "seed"] {
        refuse(&run(&fixture.prepare_args(input)));
        assert_eq!(fixture.input_inventory(), inputs);
    }
    for (flag, maximum) in [
        ("--signed-leg", MAX_LOCAL_EXECUTION_INTENT_BYTES),
        ("--expected-bond-row", MAX_BOND_REGISTRATION_ROW_BYTES),
    ] {
        let path: String = fixture.path("oversized");
        let file: File = File::create(&path).unwrap();
        file.set_len(u64::try_from(maximum + 1).unwrap()).unwrap();
        let mut args: Vec<String> = fixture.prepare_args("refused");
        replace(&mut args, flag, path);
        refuse(&run(&args));
        assert!(!Path::new(&fixture.path("refused")).exists());
    }
    assert_eq!(fixture.input_inventory(), inputs);
}

#[cfg(unix)]
#[test]
fn executable_keeps_original_input_symlink_behavior_but_refuses_output_and_seed_links() {
    let fixture: Fixture = Fixture::new();
    let mut args: Vec<String> = fixture.prepare_args("signed");
    for (flag, name) in [
        ("--ordered-genesis-manifest", "genesis"),
        ("--signed-leg", "leg"),
        ("--expected-bond-row", "row"),
    ] {
        let link: String = fixture.path(&format!("{name}-link"));
        std::os::unix::fs::symlink(fixture.path(name), &link).unwrap();
        replace(&mut args, flag, link);
    }
    let output: Output = run(&args);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let original: Vec<u8> = fs::read(fixture.path("signed")).unwrap();
    std::os::unix::fs::symlink(fixture.path("signed"), fixture.path("output-link")).unwrap();
    refuse(&run(&fixture.prepare_args("output-link")));
    assert_eq!(fs::read(fixture.path("signed")).unwrap(), original);
    std::os::unix::fs::symlink(fixture.path("seed"), fixture.path("seed-link")).unwrap();
    let mut seed_args: Vec<String> = fixture.prepare_args("refused");
    replace(&mut seed_args, "--seed-file", fixture.path("seed-link"));
    refuse(&run(&seed_args));
    assert!(!Path::new(&fixture.path("refused")).exists());
}

#[test]
fn sdk_preparation_is_immutable_and_refuses_an_independent_signer() {
    let fixture: Fixture = Fixture::new();
    let trusted: BondRegistrationContext = BondRegistrationContext::load(
        Path::new(&fixture.path("genesis")),
        &fixture.resolver,
        fixture.digest.bytes(),
        &fixture.context,
        fixture.domain,
    )
    .unwrap();
    let signer: LocalSigner = LocalSigner::from_seed(NEW_SEED);
    let prepared = trusted
        .prepare(
            &signer,
            REQUEST_ID,
            fixture.leg.clone(),
            fixture.row.clone(),
        )
        .unwrap();
    assert!(matches!(
        prepared.sign(&LocalSigner::from_seed([0x66; 32])),
        Err(LocalBondRegistrationError::SignerMismatch)
    ));
    let first: Vec<u8> = prepared.sign(&signer).unwrap();
    let second: Vec<u8> = prepared.sign(&signer).unwrap();
    assert_eq!(first, second);
    assert_eq!(
        decode_signed_bond_registration_intent(&first)
            .unwrap()
            .intent,
        *prepared.intent()
    );
}

#[test]
fn public_key_registration_preserves_original_raw_and_executable_bytes() {
    use external_signer::{Behavior, TestSigner};
    use node_core::bond_lifecycle::registration::{
        BondRegistrationPreparationRequest, BondResourceId, prepare_bond_registration,
    };
    use sunrise_edge_client::bond_registration::{
        SignedBondRegistrationIntent, encode_signed_bond_registration_intent,
    };
    let fixture: Fixture = Fixture::new();
    let root: VerifiedGenesisRoot = VerifiedGenesisRoot::verify_bytes(
        &fixture.resolver,
        &encode_genesis_manifest(&fixture.manifest).unwrap(),
        fixture.digest.bytes(),
        &fixture.context,
    )
    .unwrap();
    let signer: LocalSigner = LocalSigner::from_seed(NEW_SEED);
    // Core preparation and the original raw sign/encode sequence independently
    // pin the envelope, not a second call into the migrated SDK wrapper.
    let raw = prepare_bond_registration(
        &root,
        BondRegistrationPreparationRequest {
            context: fixture.context.clone(),
            request_id: REQUEST_ID,
            authorization_key: *signer.address().as_bytes(),
            resource_context: fixture.row.context.clone(),
            resource: BondResourceId::new(fixture.row.resource_domain, fixture.row.resource)
                .unwrap(),
            leg: fixture.leg.clone(),
            predicted_initial_row: fixture.row.clone(),
        },
    )
    .unwrap();
    let signature: [u8; 64] = signer
        .sign_framed(&raw.signing_frame)
        .unwrap()
        .try_into()
        .unwrap();
    let original: Vec<u8> = encode_signed_bond_registration_intent(&SignedBondRegistrationIntent {
        intent: raw.intent,
        signature,
    })
    .unwrap();
    let trusted: BondRegistrationContext = BondRegistrationContext::load(
        Path::new(&fixture.path("genesis")),
        &fixture.resolver,
        fixture.digest.bytes(),
        &fixture.context,
        fixture.domain,
    )
    .unwrap();
    let prepared = trusted
        .prepare_for_public_key(
            *signer.address().as_bytes(),
            REQUEST_ID,
            fixture.leg.clone(),
            fixture.row.clone(),
        )
        .unwrap();
    assert_eq!(prepared.signable_frame(), raw.signing_frame);
    assert_eq!(prepared.predicted_initial_row(), &fixture.row);
    let external: TestSigner = TestSigner::new(NEW_SEED, Behavior::Valid);
    assert_eq!(
        prepared.sign_and_finalize_external(&external).unwrap(),
        original
    );
    assert_eq!(external.calls(), 1);
    assert_eq!(
        trusted
            .prepare(
                &signer,
                REQUEST_ID,
                fixture.leg.clone(),
                fixture.row.clone()
            )
            .unwrap()
            .sign(&signer)
            .unwrap(),
        original
    );
    let output: Output = run(&fixture.prepare_args("prepared-vector"));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(fixture.path("prepared-vector")).unwrap(), original);
}

#[test]
fn registration_refuses_external_failures_changed_row_and_presign_mutations() {
    use external_signer::{Behavior, REFUSALS, TestSigner, expected_calls};
    let fixture: Fixture = Fixture::new();
    let signer: LocalSigner = LocalSigner::from_seed(NEW_SEED);
    let trusted: BondRegistrationContext = BondRegistrationContext::load(
        Path::new(&fixture.path("genesis")),
        &fixture.resolver,
        fixture.digest.bytes(),
        &fixture.context,
        fixture.domain,
    )
    .unwrap();
    for behavior in REFUSALS {
        let external: TestSigner = TestSigner::new(NEW_SEED, behavior);
        let prepared = trusted
            .prepare_for_public_key(
                *signer.address().as_bytes(),
                REQUEST_ID,
                fixture.leg.clone(),
                fixture.row.clone(),
            )
            .unwrap();
        let error = prepared.sign_and_finalize_external(&external).unwrap_err();
        assert!(!error.to_string().contains("secret-provider-failure-marker"));
        assert!(!format!("{error:?}").contains("secret-provider-failure-marker"));
        assert_eq!(external.calls(), expected_calls(behavior));
    }
    for case in 0..8 {
        let external: TestSigner = TestSigner::new(NEW_SEED, Behavior::Valid);
        let mut row = fixture.row.clone();
        let mut leg = fixture.leg.clone();
        let mut request_id: [u8; 32] = REQUEST_ID;
        let mut key: [u8; 32] = *signer.address().as_bytes();
        match case {
            0 => row.generation += 1,
            1 => row.authorization_key = [0; 32],
            2 => row.validator_id = ValidatorId::new([9; 32]),
            3 => row.custody_object.version += 1,
            4 => {
                let last: usize = leg.len() - 1;
                leg[last] ^= 1;
            }
            5 => request_id = [0; 32],
            6 => {
                key = *LocalSigner::from_seed(DEVNET_PAID_GENESIS_SEED)
                    .address()
                    .as_bytes()
            }
            7 => row.lifecycle_epoch = Epoch::new(1),
            _ => unreachable!(),
        }
        let result: Result<Vec<u8>, LocalBondRegistrationError> =
            match trusted.prepare_for_public_key(key, request_id, leg, row) {
                Ok(prepared) => prepared.sign_and_finalize_external(&external),
                Err(error) => Err(error),
            };
        assert!(result.is_err(), "case {case}");
        assert_eq!(external.calls(), 0, "case {case}");
    }
    let original = trusted
        .prepare_for_public_key(
            *signer.address().as_bytes(),
            REQUEST_ID,
            fixture.leg.clone(),
            fixture.row.clone(),
        )
        .unwrap();
    let signature: Vec<u8> = signer.sign_framed(original.signable_frame()).unwrap();
    let mut changed = fixture.row.clone();
    // Checkpoint is a caller prediction and can be different while still
    // structurally valid; its digest must remain bound to the outer signature.
    changed.committed_at_checkpoint += 1;
    let changed = trusted
        .prepare_for_public_key(
            *signer.address().as_bytes(),
            REQUEST_ID,
            fixture.leg.clone(),
            changed,
        )
        .unwrap();
    assert!(changed.finalize(signature).is_err());
}

struct ObservedRequest {
    method: String,
    path: String,
    body: Vec<u8>,
}

fn read_request(stream: &mut TcpStream) -> Result<ObservedRequest, String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| error.to_string())?;
    let mut bytes: Vec<u8> = Vec::new();
    let mut buffer: [u8; 4096] = [0; 4096];
    let header_end: usize = loop {
        let count: usize = stream
            .read(&mut buffer)
            .map_err(|error| error.to_string())?;
        if count == 0 {
            return Err("truncated request headers".into());
        }
        bytes.extend_from_slice(&buffer[..count]);
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
        if bytes.len() > 8192 {
            return Err("request headers exceed bound".into());
        }
    };
    let header: &str =
        std::str::from_utf8(&bytes[..header_end]).map_err(|error| error.to_string())?;
    let mut lines = header.lines();
    let first: Vec<&str> = lines
        .next()
        .ok_or("missing request line")?
        .split_whitespace()
        .collect();
    if first.len() != 3 {
        return Err("invalid request line".into());
    }
    let method: String = first[0].to_string();
    let path: String = first[1].to_string();
    let mut length: usize = 0;
    for line in lines {
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            length = value
                .trim()
                .parse::<usize>()
                .map_err(|error| error.to_string())?;
        }
    }
    if length > sunrise_edge_client::ordered_economics::MAX_ORDERED_CANDIDATE_BYTES + 1024 {
        return Err("request body exceeds bound".into());
    }
    while bytes.len().saturating_sub(header_end) < length {
        let remaining: usize = length - (bytes.len() - header_end);
        let count: usize = stream
            .read(&mut buffer[..remaining.min(4096)])
            .map_err(|error| error.to_string())?;
        if count == 0 {
            return Err("truncated request body".into());
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    if bytes.len() - header_end != length {
        return Err("surplus request bytes".into());
    }
    Ok(ObservedRequest {
        method,
        path,
        body: bytes[header_end..].to_vec(),
    })
}

// Receipt reconciliation, initial empty-alignment routing, round routing,
// then the original candidate POST deliberately answered with 409.
const INGRESS_PROBE_REQUESTS: usize = 4;

fn ingress_probe(
    status: Vec<u8>,
) -> (SocketAddr, JoinHandle<Result<Vec<ObservedRequest>, String>>) {
    let listener: TcpListener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address: SocketAddr = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let worker = thread::spawn(move || {
        let deadline: Instant = Instant::now() + Duration::from_secs(10);
        let mut requests: Vec<ObservedRequest> = Vec::new();
        while requests.len() < INGRESS_PROBE_REQUESTS && Instant::now() < deadline {
            let (mut stream, _) = match listener.accept() {
                Ok(pair) => pair,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Err(error) => return Err(error.to_string()),
            };
            let request: ObservedRequest = read_request(&mut stream)?;
            if request
                .path
                .starts_with(ORDERED_ECONOMICS_OUTCOME_PATH_PREFIX)
            {
                stream
                    .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                    .map_err(|error| error.to_string())?;
            } else if request.path == ORDERED_ECONOMICS_STATUS_PATH {
                let header: String = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {ORDERED_STATUS_MEDIA_TYPE}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    status.len()
                );
                stream
                    .write_all(header.as_bytes())
                    .map_err(|error| error.to_string())?;
                stream
                    .write_all(&status)
                    .map_err(|error| error.to_string())?;
            } else if request.path == ORDERED_ECONOMICS_PROPOSE_PATH {
                // Do not forge execution/finality. Confirm exact normal-route
                // delivery, then deliberately refuse this probe's proposal.
                stream
                    .write_all(
                        b"HTTP/1.1 409 Conflict\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .map_err(|error| error.to_string())?;
            } else {
                return Err(format!("unexpected route {}", request.path));
            }
            requests.push(request);
        }
        if requests.len() != INGRESS_PROBE_REQUESTS {
            return Err(format!(
                "ingress probe expected {INGRESS_PROBE_REQUESTS} requests, received {}",
                requests.len(),
            ));
        }
        Ok(requests)
    });
    (address, worker)
}

#[test]
fn compiled_preparation_wrap_and_nondefault_suite_submission_delivers_exact_ordered_propose_request()
 {
    let fixture: Fixture = Fixture::new();
    let inputs: Vec<Vec<u8>> = fixture.input_inventory();
    for args in [
        fixture.prepare_args("signed"),
        fixture.wrap_args("signed", "candidate"),
    ] {
        let output: Output = run(&args);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let signed_bytes: Vec<u8> = fs::read(fixture.path("signed")).unwrap();
    let candidate_bytes: Vec<u8> = fs::read(fixture.path("candidate")).unwrap();
    let policy = load_trusted_ordered_policy(
        Path::new(&fixture.path("genesis")),
        &fixture.resolver,
        fixture.digest.bytes(),
        &fixture.context,
        fixture.domain,
    )
    .unwrap();
    // This real genesis profile has one registered voting identity; its
    // distinct configured endpoint supplies the pinned routing quorum.
    assert_eq!(fixture.manifest.validator_set.validators.len(), 1);
    assert!(
        fixture.manifest.validator_set.validators[0].voting_power
            >= policy.engine().validator_set().quorum_threshold()
    );
    let status: Vec<u8> = encode_ordered_status(&OrderedStatus {
        current_view: 1,
        high_qc: policy.engine().genesis_state(0).high_qc,
        committed_height: 0,
    })
    .unwrap();
    let (address, worker) = ingress_probe(status);
    fs::write(
        fixture.path("network"),
        format!(
            "{} {address} - -\n",
            hex(fixture.manifest.validator_set.validators[0].id.as_bytes()),
        ),
    )
    .unwrap();
    let mut args: Vec<String> = vec!["economics".into(), "network-submit".into()];
    args.extend(fixture.pins());
    args.extend([
        "--ordered-network".into(),
        fixture.path("network"),
        "--candidate".into(),
        fixture.path("candidate"),
        "--out".into(),
        fixture.path("submission"),
        "--deadline-seconds".into(),
        "2".into(),
        "--per-request-cap-seconds".into(),
        "1".into(),
    ]);
    let output: Output = run(&args);
    refuse(&output);
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("request identity conflict or explicit recovery required"),
        "{}",
        String::from_utf8_lossy(&output.stderr),
    );
    let requests: Vec<ObservedRequest> = worker.join().unwrap().unwrap();
    assert_eq!(requests.len(), INGRESS_PROBE_REQUESTS);
    assert_eq!(
        requests[0].path,
        format!(
            "{ORDERED_ECONOMICS_OUTCOME_PATH_PREFIX}{}",
            hex(&REQUEST_ID)
        ),
    );
    for request in &requests[..3] {
        assert_eq!(request.method, "GET");
        assert!(request.body.is_empty());
    }
    for request in &requests[1..3] {
        assert_eq!(request.path, ORDERED_ECONOMICS_STATUS_PATH);
    }
    assert_eq!(requests[3].path, ORDERED_ECONOMICS_PROPOSE_PATH);
    let delivered = requests
        .iter()
        .find(|request| request.path == ORDERED_ECONOMICS_PROPOSE_PATH)
        .unwrap();
    assert_eq!(delivered.method, "POST");
    let proposed: OrderedProposeRequest = OrderedProposeRequest::decode(&delivered.body).unwrap();
    assert_eq!(proposed.candidate, Some(candidate_bytes.clone()));
    assert_eq!(
        decode_ordered_candidate(&proposed.candidate.unwrap())
            .unwrap()
            .kind,
        OrderedOperationKind::BondRegistration
    );
    assert_eq!(fixture.input_inventory(), inputs);
    assert_eq!(fs::read(fixture.path("signed")).unwrap(), signed_bytes);
    assert_eq!(
        fs::read(fixture.path("candidate")).unwrap(),
        candidate_bytes
    );
}
