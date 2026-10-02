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
use sunrise_edge_client::{
    AccessMode, AtomicityDomainId, ChainId, CommitmentProfile, Digest32, Epoch, HashAlgorithmId,
    HashSuite, HashSuiteId, HashSuiteResolver, HashSuiteSchedule, LocalSigner, ProtocolVersion,
    PublicationContext, SignatureSchemeId, ValidatorId,
    bond_registration::{
        BondRegistrationContext, FastPathBondRecord, LocalBondRegistrationError,
        MAX_BOND_REGISTRATION_ROW_BYTES, MAX_LOCAL_EXECUTION_INTENT_BYTES,
        decode_signed_bond_registration_intent, encode_fastpath_bond_record,
        verify_signed_bond_registration,
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
        let owner: DevOwner = DevOwner::new(*signer.address().as_bytes());
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
        assert_eq!(
            source.object.owner,
            Owner::Address(*signer.address().as_bytes())
        );
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
                sender: *signer.address().as_bytes(),
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
            signature: signer
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
        ["genesis", "leg", "row", "seed"]
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
    let signed = verify_signed_bond_registration(
        &fixture.resolver,
        &fixture.manifest,
        fixture.digest,
        &bytes,
    )
    .unwrap();
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
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                length = value
                    .trim()
                    .parse::<usize>()
                    .map_err(|error| error.to_string())?;
            }
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

fn ingress_probe(
    status: Vec<u8>,
) -> (SocketAddr, JoinHandle<Result<Vec<ObservedRequest>, String>>) {
    let listener: TcpListener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address: SocketAddr = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let worker = thread::spawn(move || {
        let deadline: Instant = Instant::now() + Duration::from_secs(10);
        let mut requests: Vec<ObservedRequest> = Vec::new();
        while requests.len() < 3 && Instant::now() < deadline {
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
        Ok(requests)
    });
    (address, worker)
}

#[test]
fn compiled_preparation_wrap_and_nondefault_suite_submission_delivers_exact_ordered_propose_request()
 {
    let fixture: Fixture = Fixture::new();
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
    let policy = load_trusted_ordered_policy(
        Path::new(&fixture.path("genesis")),
        &fixture.resolver,
        fixture.digest.bytes(),
        &fixture.context,
        fixture.domain,
    )
    .unwrap();
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
            .contains("request identity conflict or explicit recovery required")
    );
    let requests: Vec<ObservedRequest> = worker.join().unwrap().unwrap();
    assert_eq!(requests.len(), 3);
    let delivered = requests
        .iter()
        .find(|request| request.path == ORDERED_ECONOMICS_PROPOSE_PATH)
        .unwrap();
    assert_eq!(delivered.method, "POST");
    let proposed: OrderedProposeRequest = OrderedProposeRequest::decode(&delivered.body).unwrap();
    assert_eq!(
        proposed.candidate,
        Some(fs::read(fixture.path("candidate")).unwrap())
    );
    assert_eq!(
        decode_ordered_candidate(&proposed.candidate.unwrap())
            .unwrap()
            .kind,
        OrderedOperationKind::BondRegistration
    );
}
