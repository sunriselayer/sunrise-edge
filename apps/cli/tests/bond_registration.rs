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

#[cfg(target_os = "linux")]
use std::{
    os::unix::fs::PermissionsExt,
    process::{Child, Stdio},
    time::{SystemTime, UNIX_EPOCH},
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
#[cfg(target_os = "linux")]
// The original registration owner requires the signed leg and outer claim to
// carry one operation request ID; the two approval records remain phase keyed.
const PROTECTED_OUTER_REQUEST_ID: [u8; 32] = REQUEST_ID;
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

#[cfg(target_os = "linux")]
struct BondServiceChild(Option<Child>);

#[cfg(target_os = "linux")]
impl BondServiceChild {
    fn wait(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.0.as_mut().unwrap().try_wait().unwrap() {
                assert!(status.success(), "bond service exited with {status}");
                self.0.take();
                return;
            }
            assert!(
                Instant::now() < deadline,
                "bond service did not reach its bounded end"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for BondServiceChild {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[cfg(target_os = "linux")]
fn namespace_ids() -> Option<(u32, u32)> {
    let user = std::env::var("USER").ok()?;
    let parse = |path: &str| -> Option<u32> {
        fs::read_to_string(path).ok()?.lines().find_map(|line| {
            let mut fields = line.split(':');
            let name = fields.next()?;
            let start = fields.next()?.parse::<u32>().ok()?;
            let count = fields.next()?.parse::<u32>().ok()?;
            (name == user && count >= 100).then_some(start)
        })
    };
    Some((parse("/etc/subuid")?, parse("/etc/subgid")?))
}

#[cfg(target_os = "linux")]
fn namespace_id(flag: &str) -> u32 {
    let output = Command::new("id").arg(flag).output().unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout)
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

#[cfg(target_os = "linux")]
fn set_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

#[cfg(target_os = "linux")]
fn fixture_chown(path: &Path, uid: u32, gid: u32) {
    let output = Command::new("chown")
        .args(["-R", &format!("{uid}:{gid}")])
        .arg(path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(target_os = "linux")]
fn role_command(binary: &Path, uid: u32, gid: u32, args: &[String]) -> Command {
    let mut command = Command::new("setpriv");
    command.args([
        "--bounding-set=-all",
        "--inh-caps=-all",
        "--ambient-caps=-all",
        "--no-new-privs",
    ]);
    command.arg(format!("--reuid={uid}"));
    command.arg(format!("--regid={gid}"));
    command.arg(format!("--groups={gid}"));
    command.arg(binary).args(args);
    command
}

#[cfg(target_os = "linux")]
fn run_role(binary: &Path, uid: u32, gid: u32, args: &[String]) -> Output {
    role_command(binary, uid, gid, args).output().unwrap()
}

#[cfg(target_os = "linux")]
fn shell_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\"'\"'"))
}

#[cfg(target_os = "linux")]
fn command_on_path(name: &str) -> PathBuf {
    std::env::split_paths(&std::env::var_os("PATH").unwrap())
        .map(|directory| directory.join(name))
        .find(|path| path.is_file())
        .unwrap_or_else(|| panic!("required original bond test command is unavailable: {name}"))
}

#[cfg(target_os = "linux")]
fn approve_on_test_pty(
    binary: &Path,
    uid: u32,
    gid: u32,
    args: &[String],
    confirmation: &str,
) -> Output {
    let command_text = std::iter::once(binary.to_str().unwrap())
        .chain(args.iter().map(String::as_str))
        .map(shell_quote)
        .collect::<Vec<_>>()
        .join(" ");
    let mut command = role_command(
        &command_on_path("script"),
        uid,
        gid,
        &[
            "-q".into(),
            "-e".into(),
            "-c".into(),
            command_text,
            "/dev/null".into(),
        ],
    );
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{confirmation}\n").as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[cfg(target_os = "linux")]
fn start_bond_service(
    binary: &Path,
    uid: u32,
    gid: u32,
    args: &[String],
    socket: &Path,
) -> BondServiceChild {
    let child = role_command(binary, uid, gid, args)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut child = BondServiceChild(Some(child));
    let deadline = Instant::now() + Duration::from_secs(5);
    while !socket.exists() && Instant::now() < deadline {
        if let Some(status) = child.0.as_mut().unwrap().try_wait().unwrap() {
            let mut stderr = String::new();
            child
                .0
                .as_mut()
                .unwrap()
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut stderr)
                .unwrap();
            panic!("bond service exited with {status}: {stderr}");
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(socket.exists(), "bond service did not bind its socket");
    child
}

#[cfg(target_os = "linux")]
fn blocked_bond_worker_run() {
    use std::os::unix::net::UnixListener;

    let socket = PathBuf::from(std::env::var_os("SUNRISE_BOND_BLOCKED_SOCKET").unwrap());
    let marker = PathBuf::from(std::env::var_os("SUNRISE_BOND_BLOCKED_MARKER").unwrap());
    let release = PathBuf::from(std::env::var_os("SUNRISE_BOND_BLOCKED_RELEASE").unwrap());
    let config = fs::read(std::env::var_os("SUNRISE_BOND_BLOCKED_CONFIG").unwrap()).unwrap();
    let signature_hex = std::env::var("SUNRISE_BOND_BLOCKED_SIGNATURE").unwrap();
    let signature = signature_hex
        .as_bytes()
        .chunks_exact(2)
        .map(|digits| u8::from_str_radix(std::str::from_utf8(digits).unwrap(), 16).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(signature.len(), 64);
    let listener = UnixListener::bind(&socket).unwrap();
    set_mode(&socket, 0o770);
    let (mut stream, _) = listener.accept().unwrap();
    let mut length = [0_u8; 4];
    stream.read_exact(&mut length).unwrap();
    let length = u32::from_be_bytes(length) as usize;
    assert!(length <= 1_048_576);
    let mut request = vec![0_u8; length];
    stream.read_exact(&mut request).unwrap();
    fs::write(&marker, b"worker received typed request").unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !release.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(release.exists(), "blocked worker was not released");
    let mut check = vec![1_u8, 2_u8];
    check.extend_from_slice(&(request.len() as u32).to_be_bytes());
    check.extend_from_slice(&request);
    check.extend_from_slice(&(config.len() as u32).to_be_bytes());
    check.extend_from_slice(&config);
    stream
        .write_all(&(check.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(&check).unwrap();
    let mut approval = [0_u8; 2];
    stream.read_exact(&mut approval).unwrap();
    assert_eq!(approval, [1, 1]);
    stream.write_all(&[1, 3]).unwrap();
    stream.write_all(&signature).unwrap();
    drop(stream);
    drop(listener);
    fs::remove_file(&socket).unwrap();
}

#[cfg(target_os = "linux")]
fn protected_bond_namespace_run() {
    const BROKER: u32 = 2001;
    const INNER_WORKER: u32 = 2002;
    const OUTER_WORKER: u32 = 2003;
    const INNER_APPROVER: u32 = 2004;
    const OUTER_APPROVER: u32 = 2005;

    let fixture = Fixture::new();
    let cli_uid = namespace_id("-u");
    let gid = namespace_id("-g");
    assert!(
        ![
            BROKER,
            INNER_WORKER,
            OUTER_WORKER,
            INNER_APPROVER,
            OUTER_APPROVER
        ]
        .contains(&cli_uid)
    );
    set_mode(&fixture.directory, 0o755);
    let binary = fixture.directory.join("protected-bond-cli");
    fs::copy(env!("CARGO_BIN_EXE_sunrise-edge-cli"), &binary).unwrap();
    set_mode(&binary, 0o755);

    let resource = &fixture.manifest.economics_policy.resources[0].resource_id;
    let source_key = LocalSigner::from_seed(SOURCE_SEED).address();
    let validator_key = LocalSigner::from_seed(NEW_SEED).address();
    let config = format!(
        "chain_id={}\nprotocol_version={}\nsuite={SUITE}\ndomain={}\ngenesis_digest={}\nsource_key={}\nvalidator_key={}\nresource_domain={}\nresource_id={}\ncli_uid={cli_uid}\nbroker_uid={BROKER}\ninner_worker_uid={INNER_WORKER}\nouter_worker_uid={OUTER_WORKER}\ninner_approver_uid={INNER_APPROVER}\nouter_approver_uid={OUTER_APPROVER}\n",
        fixture.context.chain_id(),
        fixture.context.protocol_version().get(),
        hex(fixture.domain.as_bytes()),
        hex(&fixture.digest.bytes()),
        hex(source_key.as_bytes()),
        hex(validator_key.as_bytes()),
        resource.domain(),
        hex(resource.value()),
    );
    let private = |uid: u32| fixture.directory.join(format!("private-{uid}"));
    for uid in [
        cli_uid,
        BROKER,
        INNER_WORKER,
        OUTER_WORKER,
        INNER_APPROVER,
        OUTER_APPROVER,
    ] {
        let dir = private(uid);
        fs::create_dir(&dir).unwrap();
        set_mode(&dir, 0o700);
        fs::write(dir.join("config"), &config).unwrap();
        set_mode(&dir.join("config"), 0o600);
    }
    let cli_dir = private(cli_uid);
    for (source, destination) in [
        ("source-coin", "source-coin"),
        ("row", "row"),
        ("leg", "signed-leg-initial"),
    ] {
        fs::copy(fixture.path(source), cli_dir.join(destination)).unwrap();
        set_mode(&cli_dir.join(destination), 0o600);
    }
    write_seed(&private(INNER_WORKER).join("key"), SOURCE_SEED);
    write_seed(&private(INNER_WORKER).join("wrong-key"), [0x68; 32]);
    write_seed(&private(OUTER_WORKER).join("key"), NEW_SEED);
    fs::create_dir(private(BROKER).join("approvals")).unwrap();
    set_mode(&private(BROKER).join("approvals"), 0o700);
    for uid in [
        BROKER,
        INNER_WORKER,
        OUTER_WORKER,
        INNER_APPROVER,
        OUTER_APPROVER,
    ] {
        fixture_chown(&private(uid), uid, gid);
    }
    let socket_dir = |role: &str| fixture.directory.join(format!("socket-{role}"));
    for (role, uid) in [
        ("broker", BROKER),
        ("inner", INNER_WORKER),
        ("outer", OUTER_WORKER),
    ] {
        let dir = socket_dir(role);
        fs::create_dir(&dir).unwrap();
        set_mode(&dir, 0o750);
        fixture_chown(&dir, uid, gid);
    }
    let broker_socket = socket_dir("broker").join("bond.sock");
    let inner_socket = socket_dir("inner").join("bond.sock");
    let outer_socket = socket_dir("outer").join("bond.sock");
    let cli_args = |action: &str| {
        vec![
            "custody".into(),
            action.into(),
            "--config".into(),
            cli_dir.join("config").to_str().unwrap().into(),
            "--genesis-manifest".into(),
            fixture.path("genesis"),
        ]
    };
    let role_args = |uid: u32, action: &str| {
        vec![
            "custody".into(),
            action.into(),
            "--config".into(),
            private(uid).join("config").to_str().unwrap().into(),
            "--genesis-manifest".into(),
            fixture.path("genesis"),
        ]
    };
    let mut prepare_inner = cli_args("prepare-bond-inner");
    prepare_inner.extend([
        "--source-coin".into(),
        cli_dir.join("source-coin").to_str().unwrap().into(),
        "--nonce".into(),
        "0".into(),
        "--request-id".into(),
        hex(&REQUEST_ID),
        "--gas-limit".into(),
        "500000".into(),
        "--out".into(),
        cli_dir.join("inner-request").to_str().unwrap().into(),
    ]);
    let prepared = run_role(&binary, cli_uid, gid, &prepare_inner);
    assert!(
        prepared.status.success(),
        "{}",
        String::from_utf8_lossy(&prepared.stderr)
    );
    assert!(String::from_utf8_lossy(&prepared.stdout).contains("source_snapshot_unverified=true"));
    fs::copy(
        cli_dir.join("inner-request"),
        private(INNER_APPROVER).join("request"),
    )
    .unwrap();
    set_mode(&private(INNER_APPROVER).join("request"), 0o600);
    fixture_chown(
        &private(INNER_APPROVER).join("request"),
        INNER_APPROVER,
        gid,
    );

    let mut prepare_outer = cli_args("prepare-bond-outer");
    prepare_outer.extend([
        "--inner-request".into(),
        cli_dir.join("inner-request").to_str().unwrap().into(),
        "--signed-leg".into(),
        cli_dir.join("signed-leg-initial").to_str().unwrap().into(),
        "--predicted-row".into(),
        cli_dir.join("row").to_str().unwrap().into(),
        "--request-id".into(),
        hex(&PROTECTED_OUTER_REQUEST_ID),
        "--out".into(),
        cli_dir
            .join("outer-request-initial")
            .to_str()
            .unwrap()
            .into(),
    ]);
    let prepared = run_role(&binary, cli_uid, gid, &prepare_outer);
    assert!(
        prepared.status.success(),
        "{}",
        String::from_utf8_lossy(&prepared.stderr)
    );
    fs::copy(
        cli_dir.join("outer-request-initial"),
        private(OUTER_APPROVER).join("request"),
    )
    .unwrap();
    set_mode(&private(OUTER_APPROVER).join("request"), 0o600);
    fixture_chown(
        &private(OUTER_APPROVER).join("request"),
        OUTER_APPROVER,
        gid,
    );

    let expires = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 180;
    let leg = execution::local_execution::decode_signed_local_execution(&fixture.leg).unwrap();
    let inner_frame = local_execution_signing_frame(&fixture.context, &leg.intent).unwrap();
    let inner_digest = fixture
        .resolver
        .hash_for_purpose(Epoch::new(0), HashPurpose::Transaction, &inner_frame)
        .unwrap();
    let inner_confirmation = format!(
        "APPROVE-ORIGINAL-BOND phase=Inner request={} key={} frame_digest={} not_after={expires}",
        hex(&REQUEST_ID),
        source_key,
        inner_digest,
    );
    let root = VerifiedGenesisRoot::verify_bytes(
        &fixture.resolver,
        &encode_genesis_manifest(&fixture.manifest).unwrap(),
        fixture.digest.bytes(),
        &fixture.context,
    )
    .unwrap();
    let outer_prepared = BondRegistrationContext::load(
        Path::new(&fixture.path("genesis")),
        &fixture.resolver,
        fixture.digest.bytes(),
        &fixture.context,
        fixture.domain,
    )
    .unwrap()
    .prepare_for_public_key(
        *validator_key.as_bytes(),
        PROTECTED_OUTER_REQUEST_ID,
        fixture.leg.clone(),
        fixture.row.clone(),
    )
    .unwrap();
    assert_eq!(outer_prepared.genesis_root().digest(), root.digest());
    let outer_digest = fixture
        .resolver
        .hash_for_purpose(
            Epoch::new(0),
            HashPurpose::Transaction,
            outer_prepared.signable_frame(),
        )
        .unwrap();
    let outer_confirmation = format!(
        "APPROVE-ORIGINAL-BOND phase=Outer request={} key={} frame_digest={} not_after={expires}",
        hex(&PROTECTED_OUTER_REQUEST_ID),
        validator_key,
        outer_digest,
    );
    let approve_args = |uid: u32, phase: &str| {
        let mut args = role_args(uid, &format!("approve-bond-{phase}"));
        args.extend([
            "--request".into(),
            private(uid).join("request").to_str().unwrap().into(),
            "--broker-socket".into(),
            broker_socket.to_str().unwrap().into(),
            "--not-after-unix-seconds".into(),
            expires.to_string(),
        ]);
        args
    };
    let service_args = |uid: u32, action: &str, socket: &Path, count: &str| {
        let mut args = role_args(uid, action);
        args.extend([
            "--socket".into(),
            socket.to_str().unwrap().into(),
            "--max-connections".into(),
            count.into(),
            "--max-requests".into(),
            count.into(),
            "--total-deadline-secs".into(),
            "90".into(),
        ]);
        args
    };
    let mut broker_args = service_args(BROKER, "serve-bond-approvals", &broker_socket, "2");
    broker_args.extend([
        "--approvals-dir".into(),
        private(BROKER).join("approvals").to_str().unwrap().into(),
        "--inner-worker-socket".into(),
        inner_socket.to_str().unwrap().into(),
        "--outer-worker-socket".into(),
        outer_socket.to_str().unwrap().into(),
    ]);
    let mut broker = start_bond_service(&binary, BROKER, gid, &broker_args, &broker_socket);
    let second_broker_dir = socket_dir("broker-second");
    fs::create_dir(&second_broker_dir).unwrap();
    set_mode(&second_broker_dir, 0o750);
    fixture_chown(&second_broker_dir, BROKER, gid);
    let second_broker_socket = second_broker_dir.join("bond.sock");
    let mut duplicate_broker = broker_args.clone();
    replace(
        &mut duplicate_broker,
        "--socket",
        second_broker_socket.to_str().unwrap().into(),
    );
    let duplicate = run_role(&binary, BROKER, gid, &duplicate_broker);
    assert!(
        !duplicate.status.success(),
        "a second broker served the same approval store"
    );
    assert!(
        !second_broker_socket.exists(),
        "duplicate broker bound a socket before refusing the store lock"
    );
    let outer_too_early = approve_on_test_pty(
        &binary,
        OUTER_APPROVER,
        gid,
        &approve_args(OUTER_APPROVER, "outer"),
        &outer_confirmation,
    );
    assert!(
        !outer_too_early.status.success(),
        "outer approved before inner approval"
    );
    let inner_approved = approve_on_test_pty(
        &binary,
        INNER_APPROVER,
        gid,
        &approve_args(INNER_APPROVER, "inner"),
        &inner_confirmation,
    );
    assert!(
        inner_approved.status.success(),
        "{} {}",
        String::from_utf8_lossy(&inner_approved.stdout),
        String::from_utf8_lossy(&inner_approved.stderr)
    );
    broker.wait();
    assert!(
        !broker_socket.exists(),
        "bounded broker did not unlink its own socket"
    );

    let mut broker_args = service_args(BROKER, "serve-bond-approvals", &broker_socket, "7");
    broker_args.extend([
        "--approvals-dir".into(),
        private(BROKER).join("approvals").to_str().unwrap().into(),
        "--inner-worker-socket".into(),
        inner_socket.to_str().unwrap().into(),
        "--outer-worker-socket".into(),
        outer_socket.to_str().unwrap().into(),
    ]);
    let mut broker = start_bond_service(&binary, BROKER, gid, &broker_args, &broker_socket);
    let mut inner_args = service_args(INNER_WORKER, "serve-bond-inner", &inner_socket, "1");
    replace(&mut inner_args, "--max-connections", "2".into());
    inner_args.extend([
        "--key-file".into(),
        private(INNER_WORKER).join("key").to_str().unwrap().into(),
    ]);
    let mut wrong_key_args = inner_args.clone();
    replace(
        &mut wrong_key_args,
        "--key-file",
        private(INNER_WORKER)
            .join("wrong-key")
            .to_str()
            .unwrap()
            .into(),
    );
    let wrong_key = run_role(&binary, INNER_WORKER, gid, &wrong_key_args);
    assert!(
        !wrong_key.status.success(),
        "wrong protected key was accepted"
    );
    assert!(!inner_socket.exists());
    let mut inner_worker =
        start_bond_service(&binary, INNER_WORKER, gid, &inner_args, &inner_socket);
    // The CLI can reach the socket through its group, but the worker must
    // close this connection before waiting for any request body.
    let mut wrong_peer = std::os::unix::net::UnixStream::connect(&inner_socket).unwrap();
    wrong_peer
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut byte = [0_u8; 1];
    assert_eq!(wrong_peer.read(&mut byte).unwrap(), 0);
    drop(wrong_peer);
    let mut sign_inner = cli_args("sign-bond-inner");
    sign_inner.extend([
        "--request".into(),
        cli_dir.join("inner-request").to_str().unwrap().into(),
        "--broker-socket".into(),
        broker_socket.to_str().unwrap().into(),
        "--out".into(),
        cli_dir.join("signed-leg").to_str().unwrap().into(),
    ]);
    let output = run_role(&binary, cli_uid, gid, &sign_inner);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(cli_dir.join("signed-leg")).unwrap(), fixture.leg);
    // The actual protected inner output, rather than the independently
    // prebuilt fixture leg used by the early-refusal probe, now becomes the
    // outer request's only signed-leg input.
    let mut prepare_protected_outer = prepare_outer.clone();
    replace(
        &mut prepare_protected_outer,
        "--signed-leg",
        cli_dir.join("signed-leg").to_str().unwrap().into(),
    );
    replace(
        &mut prepare_protected_outer,
        "--out",
        cli_dir.join("outer-request").to_str().unwrap().into(),
    );
    let prepared_protected_outer = run_role(&binary, cli_uid, gid, &prepare_protected_outer);
    assert!(
        prepared_protected_outer.status.success(),
        "{}",
        String::from_utf8_lossy(&prepared_protected_outer.stderr)
    );
    assert_eq!(
        fs::read(cli_dir.join("outer-request")).unwrap(),
        fs::read(cli_dir.join("outer-request-initial")).unwrap(),
        "the protected inner signed leg changed the outer prepared bytes"
    );
    fs::copy(
        cli_dir.join("outer-request"),
        private(OUTER_APPROVER).join("request-protected"),
    )
    .unwrap();
    set_mode(&private(OUTER_APPROVER).join("request-protected"), 0o600);
    fixture_chown(
        &private(OUTER_APPROVER).join("request-protected"),
        OUTER_APPROVER,
        gid,
    );
    let mut changed_inner = prepare_inner.clone();
    replace(&mut changed_inner, "--nonce", "1".into());
    replace(
        &mut changed_inner,
        "--out",
        cli_dir
            .join("changed-inner-request")
            .to_str()
            .unwrap()
            .into(),
    );
    let changed_prepared = run_role(&binary, cli_uid, gid, &changed_inner);
    assert!(changed_prepared.status.success());
    let mut changed_sign = sign_inner.clone();
    replace(
        &mut changed_sign,
        "--request",
        cli_dir
            .join("changed-inner-request")
            .to_str()
            .unwrap()
            .into(),
    );
    replace(
        &mut changed_sign,
        "--out",
        cli_dir
            .join("changed-inner-signed")
            .to_str()
            .unwrap()
            .into(),
    );
    let changed = run_role(&binary, cli_uid, gid, &changed_sign);
    assert!(
        !changed.status.success(),
        "changed inner content was signed"
    );
    assert!(!cli_dir.join("changed-inner-signed").exists());
    inner_worker.wait();

    let mut approve_protected_outer = approve_args(OUTER_APPROVER, "outer");
    replace(
        &mut approve_protected_outer,
        "--request",
        private(OUTER_APPROVER)
            .join("request-protected")
            .to_str()
            .unwrap()
            .into(),
    );
    let outer_approved = approve_on_test_pty(
        &binary,
        OUTER_APPROVER,
        gid,
        &approve_protected_outer,
        &outer_confirmation,
    );
    assert!(
        outer_approved.status.success(),
        "{} {}",
        String::from_utf8_lossy(&outer_approved.stdout),
        String::from_utf8_lossy(&outer_approved.stderr)
    );
    let mut outer_args = service_args(OUTER_WORKER, "serve-bond-outer", &outer_socket, "1");
    outer_args.extend([
        "--key-file".into(),
        private(OUTER_WORKER).join("key").to_str().unwrap().into(),
    ]);
    let mut outer_worker =
        start_bond_service(&binary, OUTER_WORKER, gid, &outer_args, &outer_socket);
    let mut sign_outer = cli_args("sign-bond-outer");
    sign_outer.extend([
        "--request".into(),
        cli_dir.join("outer-request").to_str().unwrap().into(),
        "--broker-socket".into(),
        broker_socket.to_str().unwrap().into(),
        "--out".into(),
        cli_dir.join("signed-registration").to_str().unwrap().into(),
    ]);
    let output = run_role(&binary, cli_uid, gid, &sign_outer);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let signed_registration = fs::read(cli_dir.join("signed-registration")).unwrap();
    let expected_intent = outer_prepared.intent().clone();
    assert_eq!(
        signed_registration,
        outer_prepared
            .sign_and_finalize_with(&LocalSigner::from_seed(NEW_SEED))
            .unwrap()
    );
    let verified = verify_signed_bond_registration(&root, &signed_registration).unwrap();
    assert_eq!(verified.intent.leg, fixture.leg);
    assert_eq!(
        verified.intent.leg,
        fs::read(cli_dir.join("signed-leg")).unwrap()
    );
    assert_eq!(verified.intent.request_id, PROTECTED_OUTER_REQUEST_ID);
    assert_eq!(verified.intent, expected_intent);

    // Hold a worker connection after it has received the broker's typed
    // request. A revoke queued during this interval must not complete before
    // the broker finishes the in-flight sign response. This exercises the
    // broker's serialized release/revoke linearization without timing guesses
    // about which request entered the accept queue first.
    outer_worker.wait();
    let marker = socket_dir("outer").join("received");
    let release = socket_dir("outer").join("release");
    let mut blocked = role_command(
        &std::env::current_exe().unwrap(),
        OUTER_WORKER,
        gid,
        &[
            "--exact".into(),
            "protected_original_bond_uses_two_distinct_approvers_and_workers".into(),
            "--nocapture".into(),
        ],
    );
    blocked.env("SUNRISE_BOND_BLOCKED_SOCKET", &outer_socket);
    blocked.env("SUNRISE_BOND_BLOCKED_MARKER", &marker);
    blocked.env("SUNRISE_BOND_BLOCKED_RELEASE", &release);
    blocked.env(
        "SUNRISE_BOND_BLOCKED_CONFIG",
        private(OUTER_WORKER).join("config"),
    );
    blocked.env(
        "SUNRISE_BOND_BLOCKED_SIGNATURE",
        hex(
            &decode_signed_bond_registration_intent(&signed_registration)
                .unwrap()
                .signature,
        ),
    );
    let mut blocked = blocked
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !outer_socket.exists() && Instant::now() < deadline {
        assert!(blocked.try_wait().unwrap().is_none());
        thread::sleep(Duration::from_millis(10));
    }
    assert!(outer_socket.exists());
    let mut racing_sign = sign_outer.clone();
    replace(
        &mut racing_sign,
        "--out",
        cli_dir.join("racing-registration").to_str().unwrap().into(),
    );
    let mut racing_sign_child = role_command(&binary, cli_uid, gid, &racing_sign)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    while !marker.exists() && Instant::now() < deadline {
        if let Some(status) = racing_sign_child.try_wait().unwrap() {
            let mut stderr = String::new();
            racing_sign_child
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut stderr)
                .unwrap();
            let worker_status = blocked.try_wait().unwrap();
            let broker_status = broker.0.as_mut().unwrap().try_wait().unwrap();
            let mut worker_stderr = String::new();
            if worker_status.is_some() {
                blocked
                    .stderr
                    .take()
                    .unwrap()
                    .read_to_string(&mut worker_stderr)
                    .unwrap();
            }
            panic!(
                "racing sign exited with {status}: {stderr}; blocked worker={worker_status:?}: {worker_stderr}; broker={broker_status:?}"
            );
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        marker.exists(),
        "broker did not connect to the blocked worker"
    );

    let mut revoke = vec![
        "custody".into(),
        "revoke-bond-inner".into(),
        "--config".into(),
        private(INNER_APPROVER)
            .join("config")
            .to_str()
            .unwrap()
            .into(),
    ];
    revoke.extend([
        "--broker-socket".into(),
        broker_socket.to_str().unwrap().into(),
        "--request-id".into(),
        hex(&REQUEST_ID),
    ]);
    let mut revoke_child = role_command(&binary, INNER_APPROVER, gid, &revoke)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    thread::sleep(Duration::from_millis(100));
    assert!(
        revoke_child.try_wait().unwrap().is_none(),
        "revoke completed while an earlier sign was in flight"
    );
    fs::write(&release, b"release").unwrap();
    let racing_result = racing_sign_child.wait_with_output().unwrap();
    assert!(
        racing_result.status.success(),
        "{}",
        String::from_utf8_lossy(&racing_result.stderr)
    );
    assert_eq!(
        fs::read(cli_dir.join("racing-registration")).unwrap(),
        signed_registration
    );
    let blocked_result = blocked.wait_with_output().unwrap();
    assert!(
        blocked_result.status.success(),
        "{}",
        String::from_utf8_lossy(&blocked_result.stderr)
    );
    let revoked = revoke_child.wait_with_output().unwrap();
    assert!(
        revoked.status.success(),
        "{}",
        String::from_utf8_lossy(&revoked.stderr)
    );
    replace(
        &mut sign_outer,
        "--out",
        cli_dir
            .join("refused-registration")
            .to_str()
            .unwrap()
            .into(),
    );
    let refused = run_role(&binary, cli_uid, gid, &sign_outer);
    assert!(
        !refused.status.success(),
        "outer signed after inner revocation"
    );
    assert!(!cli_dir.join("refused-registration").exists());
    broker.wait();
}

/// A user namespace supplies five disposable OS principals without creating
/// host users or changing any host policy. This test fails rather than
/// silently passing when that boundary cannot be exercised.
#[cfg(target_os = "linux")]
#[test]
fn protected_original_bond_uses_two_distinct_approvers_and_workers() {
    if std::env::var_os("SUNRISE_BOND_BLOCKED_SOCKET").is_some() {
        blocked_bond_worker_run();
        return;
    }
    if std::env::var_os("SUNRISE_BOND_UID_NAMESPACE_CHILD").is_some() {
        protected_bond_namespace_run();
        return;
    }
    let (subuid, subgid) =
        namespace_ids().expect("original bond test requires subordinate UID/GID ranges");
    let test_binary = std::env::current_exe().unwrap();
    let output = Command::new("unshare")
        // The fixture controller needs effective namespace CAP_CHOWN after
        // exec; retaining a nonzero namespace UID does not guarantee it on
        // hosted runners. This maps only the current host user to namespace
        // root, while the role processes below still drop all capabilities.
        .args(["--map-root-user", "--map-users"])
        .arg(format!("2000:{subuid}:100"))
        .arg("--map-groups")
        .arg(format!("2000:{subgid}:100"))
        .arg("--keep-caps")
        .arg(test_binary)
        .args([
            "--exact",
            "protected_original_bond_uses_two_distinct_approvers_and_workers",
            "--nocapture",
        ])
        .env("SUNRISE_BOND_UID_NAMESPACE_CHILD", "1")
        .output();
    match output {
        Ok(output) if output.status.success() => {}
        Ok(output) => panic!(
            "original bond namespace failed: status={} stdout={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        ),
        Err(error) => panic!("original bond namespace could not start: {error}"),
    }
}
