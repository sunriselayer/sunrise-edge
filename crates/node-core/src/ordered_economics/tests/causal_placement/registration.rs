//! Genuine non-genesis E producer and initial registration. Test-only reuse
//! supplies no positive bond/receipt/object rows and exports no live permit.
use super::business_reconstruction::{complete_history, reconstruction_plan, snapshot};
use super::*;
use crate::bond_lifecycle::registration::{
    BondRegistrationPreparationRequest, SignedBondRegistrationIntent, bond_registration_anchor_key,
    decode_signed_bond_registration_intent, encode_signed_bond_registration_intent,
    prepare_bond_registration, verify_registered_bond_chain, verify_signed_bond_registration,
};
use crate::business_reconstruction::cut::{SavedBusinessCut, derive_source_business_cut};
use crate::business_reconstruction::inactive_import::verify_saved_business_import;
use crate::business_reconstruction::{
    BusinessReconstructionOverlay, BusinessReconstructionPlan, owned_material_from_source_snapshot,
};
use crate::epoch_transition::{NextSetEligibilityError, check_next_set_eligibility};
use crate::fast_path::records::{FastPathValidatorEntry, FastPathValidatorSetRecord};
use consensus::{DrainUnionIdentity, FrozenFrontierPage, FrozenFrontierVote};
use std::cell::Cell;
use std::num::NonZeroUsize;
#[cfg(target_os = "linux")]
use std::{
    fs,
    path::Path,
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
};

const FUND: [u8; 32] = [0x66; 32];
const REGISTER: [u8; 32] = [0xe6; 32];
const FREEZE: [u8; 32] = [0xe7; 32];
const DRAIN: [u8; 32] = [0xe8; 32];
const CHECKPOINT: u64 = 20;
#[cfg(target_os = "linux")]
static NEXT_BOND_HANDOFF: AtomicU64 = AtomicU64::new(1);

#[cfg(target_os = "linux")]
fn bond_handoff_sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(target_os = "linux")]
fn bond_handoff_decode_hex(value: &str, max: usize) -> Vec<u8> {
    assert!(value.len() % 2 == 0 && value.len() <= max * 2);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[cfg(target_os = "linux")]
struct BondHandoffDirectory(std::path::PathBuf);

#[cfg(target_os = "linux")]
impl Drop for BondHandoffDirectory {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
}

#[cfg(target_os = "linux")]
fn protected_bond_ordered_bytes(
    fixture: &CausalFixture,
    source: &Object,
    row: &FastPathBondRecord,
    baseline_leg: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    use std::os::unix::fs::PermissionsExt;
    let harness = std::env::var("SUNRISE_BOND_ORDERED_HARNESS").unwrap();
    let harness_sha = std::env::var("SUNRISE_BOND_ORDERED_HARNESS_SHA256").unwrap();
    let cli = std::env::var("SUNRISE_BOND_ORDERED_CLI").unwrap();
    let cli_sha = std::env::var("SUNRISE_BOND_ORDERED_CLI_SHA256").unwrap();
    for (path, digest) in [(&harness, &harness_sha), (&cli, &cli_sha)] {
        let path = Path::new(path);
        assert!(path.is_absolute() && !path.is_symlink() && path.is_file());
        assert_eq!(bond_handoff_sha256(&fs::read(path).unwrap()), *digest);
    }
    let input = BondHandoffDirectory(std::env::temp_dir().join(format!(
        "sunrise-bond-ordered-handoff-{}-{}",
        std::process::id(),
        NEXT_BOND_HANDOFF.fetch_add(1, Ordering::Relaxed),
    )));
    fs::create_dir(&input.0).unwrap();
    fs::set_permissions(&input.0, fs::Permissions::from_mode(0o700)).unwrap();
    let inputs = [
        (
            "genesis",
            encode_genesis_manifest(&fixture.manifest).unwrap(),
        ),
        ("source-coin", objects::encode_object(source).unwrap()),
        ("row", encode_fastpath_bond_record(row).unwrap()),
        ("leg", baseline_leg.to_vec()),
    ];
    let mut metadata = String::from("profile=genesis-test-bond-v1\n");
    for (name, bytes) in inputs {
        assert!(bytes.len() <= 1_048_576);
        fs::write(input.0.join(name), &bytes).unwrap();
        metadata.push_str(&format!(
            "{name}_len={}\n{name}_sha256={}\n",
            bytes.len(),
            bond_handoff_sha256(&bytes),
        ));
    }
    fs::write(input.0.join("manifest"), metadata).unwrap();
    let stdout_path = input.0.join("harness.stdout");
    let stderr_path = input.0.join("harness.stderr");
    let stdout_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&stdout_path)
        .unwrap();
    let stderr_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&stderr_path)
        .unwrap();
    for path in [&stdout_path, &stderr_path] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let status = Command::new("/usr/bin/timeout")
        .args(["--signal=TERM", "--kill-after=5s", "300s", &harness])
        .args([
            "--exact",
            "protected_original_bond_uses_two_distinct_approvers_and_workers",
            "--nocapture",
        ])
        .env("SUNRISE_BOND_ORDERED_HANDOFF", &input.0)
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file))
        .status()
        .unwrap();
    assert!(
        fs::metadata(&stdout_path).unwrap().len() <= 1_048_576
            && fs::metadata(&stderr_path).unwrap().len() <= 1_048_576,
        "protected harness output exceeded its bound"
    );
    let stdout_bytes = fs::read(&stdout_path).unwrap();
    let stderr_bytes = fs::read(&stderr_path).unwrap();
    assert!(
        status.success(),
        "protected bond handoff failed: status={} stdout={} stderr={}",
        status,
        String::from_utf8_lossy(&stdout_bytes),
        String::from_utf8_lossy(&stderr_bytes),
    );
    assert_eq!(
        bond_handoff_sha256(&fs::read(&harness).unwrap()),
        harness_sha
    );
    assert_eq!(bond_handoff_sha256(&fs::read(&cli).unwrap()), cli_sha);
    let stdout = String::from_utf8(stdout_bytes).unwrap();
    let markers: Vec<&str> = stdout
        .lines()
        .filter(|line| line.starts_with("SUNRISE_BOND_ORDERED_RESULT_V1 "))
        .collect();
    assert_eq!(markers.len(), 1, "exactly one protected result");
    let parts: Vec<&str> = markers[0].split_ascii_whitespace().collect();
    assert_eq!(parts.len(), 7);
    assert_eq!(parts[0], "SUNRISE_BOND_ORDERED_RESULT_V1");
    let read_part = |index: usize, name: &str| parts[index].strip_prefix(name).unwrap();
    let inner = bond_handoff_decode_hex(read_part(3, "inner="), 1_048_576);
    let outer = bond_handoff_decode_hex(read_part(6, "outer="), 1_048_576);
    assert_eq!(
        inner.len(),
        read_part(1, "inner_len=").parse::<usize>().unwrap()
    );
    assert_eq!(
        outer.len(),
        read_part(4, "outer_len=").parse::<usize>().unwrap()
    );
    assert_eq!(bond_handoff_sha256(&inner), read_part(2, "inner_sha256="));
    assert_eq!(bond_handoff_sha256(&outer), read_part(5, "outer_sha256="));
    (inner, outer)
}

#[path = "registration/generic.rs"]
mod generic;
#[path = "registration/preparation.rs"]
mod preparation;
#[path = "registration/sqlite.rs"]
mod sqlite;

fn e_key() -> SigningKey {
    SigningKey::from([0xe5; 32])
}
fn e_id() -> ValidatorId {
    ValidatorId::new(VerificationKey::from(&e_key()).into())
}

fn next_set(network: &Network) -> FastPathValidatorSetRecord {
    let mut entries: Vec<FastPathValidatorEntry> = network.signers[..3]
        .iter()
        .map(|signer| FastPathValidatorEntry {
            id: signer.id,
            voting_power: 1,
            signature_scheme: SignatureSchemeId::Ed25519,
            public_key: signer.id.as_bytes().to_vec(),
        })
        .collect();
    entries.push(FastPathValidatorEntry {
        id: e_id(),
        voting_power: 1,
        signature_scheme: SignatureSchemeId::Ed25519,
        public_key: e_id().as_bytes().to_vec(),
    });
    entries.sort_by_key(|entry| entry.id);
    FastPathValidatorSetRecord {
        context: PublicationContext::new(
            fixture::chain(),
            fixture::protocol().protocol_version(),
            Epoch::new(fixture::protocol().epoch().get().checked_add(1).unwrap()),
        )
        .unwrap(),
        validators: entries,
    }
}

fn fund_e(fixture: &CausalFixture, nonce: u64) -> CertifiedPaidMaterial {
    fund_e_for(fixture, nonce, FUND, 10_000)
}

fn fund_e_for(
    fixture: &CausalFixture,
    nonce: u64,
    request: [u8; 32],
    amount: u64,
) -> CertifiedPaidMaterial {
    fund_for_recipient(fixture, nonce, request, amount, *e_id().as_bytes())
}

fn fund_for_recipient(
    fixture: &CausalFixture,
    nonce: u64,
    request: [u8; 32],
    amount: u64,
    recipient: [u8; 32],
) -> CertifiedPaidMaterial {
    let source: Object = current_object(&fixture.network, 0, fixture.manifest.objects[1].object.id);
    let template: Vec<u8> = paid_transfer_to(fixture, 0, &source, request, nonce, &recipient);
    let mut signed: SignedPaidIntent =
        execution::paid_execution::decode_signed_paid_intent(&template).unwrap();
    let PaidApplication::Call(call) = &mut signed.intent.application else {
        panic!("genuine call template");
    };
    call.entrypoint = "split".into();
    call.arguments = public_standard_asset::split_arguments(amount, &recipient).unwrap();
    signed.signature = fixture.network.signers[0]
        .key
        .sign(&paid_intent_signing_frame(&fixture::protocol(), &signed.intent).unwrap())
        .into();
    let bytes: Vec<u8> = encode_signed_paid_intent(&signed).unwrap();
    let material: CertifiedPaidMaterial = certify_and_apply_paid(fixture, &bytes, 16);
    let created: Vec<&Object> = material
        .result
        .effects
        .object_effects
        .iter()
        .filter_map(|effect| match effect {
            execution::ObjectEffect::Created(object)
                if object.owner == Owner::Address(Address::new(recipient)) =>
            {
                Some(object)
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        created.len(),
        1,
        "the actual paid generic producer creates E collateral"
    );
    assert!(
        fixture
            .manifest
            .objects
            .iter()
            .all(|entry| entry.object.id != created[0].id)
    );
    for replica in 0..REPLICAS {
        assert_eq!(
            current_object(&fixture.network, replica, created[0].id).owner,
            Owner::Address(Address::new(recipient))
        );
    }
    material
}

fn funded_object(fixture: &CausalFixture) -> Object {
    funded_object_for(fixture, FUND)
}

fn funded_object_for(fixture: &CausalFixture, request: [u8; 32]) -> Object {
    funded_object_for_recipient(fixture, request, *e_id().as_bytes())
}

fn funded_object_for_recipient(
    fixture: &CausalFixture,
    request: [u8; 32],
    recipient: [u8; 32],
) -> Object {
    let record: NodeDedupRecord = NodeDedupRecord::decode(
        receipt(&fixture.network, 0, request)
            .unwrap()
            .canonical_bytes(),
    )
    .unwrap();
    let result: PaidExecutionResult = execution::paid_execution::decode_paid_execution_result(
        record.responses()[0].payload().unwrap(),
    )
    .unwrap();
    let id: ObjectId = result
        .effects
        .object_effects
        .iter()
        .find_map(|effect| match effect {
            execution::ObjectEffect::Created(object)
                if object.owner == Owner::Address(Address::new(recipient)) =>
            {
                Some(object.id)
            }
            _ => None,
        })
        .unwrap();
    current_object(&fixture.network, 0, id)
}

fn leg(
    fixture: &CausalFixture,
    source: &Object,
    request: [u8; 32],
    nonce: u64,
    recipient: &[u8; 32],
    gas: u64,
    source_signer: &SigningKey,
) -> Vec<u8> {
    let network: &Network = &fixture.network;
    let source_key: [u8; 32] = VerificationKey::from(source_signer).into();
    let intent: LocalExecutionIntent = LocalExecutionIntent {
        mode: LocalExecutionMode::Call,
        policy_digest: network.leg_policy.digest(&network.resolver).unwrap(),
        call: CallIntent {
            context: fixture::protocol(),
            request_id: request,
            sender: source_key,
            nonce,
            code: fixture.instance.code.clone(),
            instance: instance_target(&network.resolver, &fixture.instance).unwrap(),
            entrypoint: "transfer".into(),
            type_arguments: fixture.manifest.fee_policy.type_arguments.clone(),
            access: abi::AccessManifest {
                entries: vec![abi::AccessEntry {
                    object_ref: object_ref(network, source),
                    mode: AccessMode::Write,
                }],
            },
            arguments: public_standard_asset::transfer_arguments(recipient).unwrap(),
            gas_limit: gas,
        },
        authorizations: Vec::new(),
    };
    let framed: Vec<u8> = local_execution_signing_frame(&fixture::protocol(), &intent).unwrap();
    encode_signed_local_execution(&SignedLocalExecutionIntent {
        signature: source_signer.sign(&framed).into(),
        intent,
    })
    .unwrap()
}

fn registration(
    fixture: &CausalFixture,
    request: [u8; 32],
    nonce: u64,
) -> (OrderedCandidate, FastPathBondRecord) {
    registration_for_object(fixture, funded_object(fixture), request, nonce)
}

fn registration_for_object(
    fixture: &CausalFixture,
    source: Object,
    request: [u8; 32],
    nonce: u64,
) -> (OrderedCandidate, FastPathBondRecord) {
    registration_claim_for_object(fixture, source, request, nonce, None)
}

/// A deliberately wrong amount is only an authenticated caller claim. The
/// actual paid producer/body is left untouched and the ordered VM must refuse.
fn registration_claim_for_object(
    fixture: &CausalFixture,
    source: Object,
    request: [u8; 32],
    nonce: u64,
    claimed_amount: Option<u64>,
) -> (OrderedCandidate, FastPathBondRecord) {
    registration_claim_for_object_signed_by(
        fixture,
        source,
        request,
        nonce,
        claimed_amount,
        &e_key(),
    )
}

fn registration_claim_for_object_signed_by(
    fixture: &CausalFixture,
    source: Object,
    request: [u8; 32],
    nonce: u64,
    claimed_amount: Option<u64>,
    source_signer: &SigningKey,
) -> (OrderedCandidate, FastPathBondRecord) {
    let (row, token) = registration_expected_row(fixture, &source, claimed_amount);
    let network: &Network = &fixture.network;
    let resource = &fixture.manifest.economics_policy.resources[0];
    let signed_leg: Vec<u8> = leg(
        fixture,
        &source,
        request,
        nonce,
        &token,
        500_000,
        source_signer,
    );
    let prepared = prepare_bond_registration(
        &network.root,
        BondRegistrationPreparationRequest {
            context: fixture::protocol(),
            request_id: request,
            authorization_key: *e_id().as_bytes(),
            resource_context: resource.context.clone(),
            resource: resource.resource_id,
            leg: signed_leg,
            predicted_initial_row: row.clone(),
        },
    )
    .unwrap();
    let signed: SignedBondRegistrationIntent = SignedBondRegistrationIntent {
        intent: prepared.intent,
        signature: e_key().sign(&prepared.signing_frame).into(),
    };
    let bytes: Vec<u8> = encode_signed_bond_registration_intent(&signed).unwrap();
    assert_eq!(
        verify_signed_bond_registration(&network.root, &bytes).unwrap(),
        signed
    );
    (
        OrderedCandidate {
            context: fixture::protocol(),
            request_id: request,
            kind: OrderedOperationKind::BondRegistration,
            intent: bytes,
            created_checkpoint: CHECKPOINT,
        },
        row,
    )
}

fn registration_expected_row(
    fixture: &CausalFixture,
    source: &Object,
    claimed_amount: Option<u64>,
) -> (FastPathBondRecord, [u8; 32]) {
    let network: &Network = &fixture.network;
    let resource = &fixture.manifest.economics_policy.resources[0];
    let scope: objects::ProtocolCustodyScope = objects::ProtocolCustodyScope {
        purpose: objects::ProtocolCustodyPurpose::BondCollateral,
        chain_id: fixture::chain(),
        subject: *e_id().as_bytes(),
        resource: *resource.resource_id.value(),
    };
    let token: [u8; 32] = execution::protocol_custody::derive_deposit_owner_token(
        &network.resolver,
        &fixture::protocol(),
        source.id,
        &scope,
    )
    .unwrap();
    let authority_observed = network.stores[0]
        .get_versioned_durable(
            &network.context,
            network.domain(),
            &crate::local_instance_state::object_authority_key(source.id),
        )
        .unwrap();
    let authority =
        execution::local_execution::decode_object_authority(authority_observed.value().unwrap())
            .unwrap();
    let amount: u64 = match abi::call_values::decode_call_value(
        &public_standard_asset::coin_body_layout(),
        &source.data,
    )
    .unwrap()
    {
        abi::call_values::CallValue::U64(amount) => amount,
        other => panic!("genuine collateral body: {other:?}"),
    };
    let mut predicted_object: Object = source.clone();
    predicted_object.version = predicted_object.version.checked_add(1).unwrap();
    predicted_object.owner = Owner::ProtocolCustody(scope);
    let row: FastPathBondRecord = FastPathBondRecord {
        context: resource.context.clone(),
        validator_id: e_id(),
        resource_domain: resource.resource_id.domain(),
        resource: *resource.resource_id.value(),
        custody_object: object_ref(network, &predicted_object),
        custody_object_epoch: fixture::protocol().epoch(),
        authority,
        amount: claimed_amount.unwrap_or(amount),
        committed_at_checkpoint: CHECKPOINT,
        generation: 1,
        lifecycle_epoch: fixture::protocol().epoch(),
        slashable_from_epoch: Epoch::new(fixture::protocol().epoch().get().checked_add(1).unwrap()),
        required_minimum: resource.bond.as_ref().unwrap().min_bond.get(),
        state: crate::fast_path::records::FastPathBondState::Active,
        authorization_scheme: SignatureSchemeId::Ed25519,
        authorization_key: *e_id().as_bytes(),
    };
    (row, token)
}

fn sign_changed(
    candidate: &mut OrderedCandidate,
    change: impl FnOnce(&mut SignedBondRegistrationIntent),
) {
    let mut signed = decode_signed_bond_registration_intent(&candidate.intent).unwrap();
    change(&mut signed);
    let digest = crate::bond_lifecycle::registration::bond_registration_intent_digest(
        &fixture::resolver(),
        &signed.intent,
    )
    .unwrap();
    let frame = crate::bond_lifecycle::registration::bond_registration_signing_frame(
        &signed.intent.context,
        digest,
    )
    .unwrap();
    signed.signature = e_key().sign(&frame).into();
    candidate.intent = encode_signed_bond_registration_intent(&signed).unwrap();
}

fn commit_registration(
    network: &Network,
    candidate: &OrderedCandidate,
    first_view: u64,
) -> QuorumCertificate {
    let mut terminal: Option<QuorumCertificate> = None;
    for view in first_view..first_view.checked_add(3).unwrap() {
        let (outputs, certificate, _) =
            network.round(view, (view == first_view).then_some(candidate));
        if view == first_view.checked_add(2).unwrap() {
            assert_eq!(outputs.len(), REPLICAS);
            for output in outputs {
                assert_eq!(output.committed.len(), 1);
            }
            terminal = Some(certificate);
        }
    }
    terminal.unwrap()
}

fn assert_registered(fixture: &CausalFixture, expected: &FastPathBondRecord) {
    assert_registered_from(fixture, expected, *e_id().as_bytes());
}

fn assert_registered_from(
    fixture: &CausalFixture,
    expected: &FastPathBondRecord,
    source_key: [u8; 32],
) {
    let network: &Network = &fixture.network;
    for replica in 0..REPLICAS {
        let actual = verify_registered_bond_chain(
            &network.stores[replica],
            &network.context,
            network.domain(),
            &network.root,
            &network.history,
            e_id(),
        )
        .unwrap();
        assert_eq!(&actual, expected);
        assert_eq!(
            query_sender_next_nonce(
                &network.stores[replica],
                &network.context,
                network.domain(),
                fixture::chain(),
                fixture::protocol().protocol_version(),
                fixture::protocol().epoch(),
                source_key
            )
            .unwrap(),
            1
        );
        let initial_transition = network.stores[replica]
            .get_versioned_durable(
                &network.context,
                network.domain(),
                &crate::local_instance_state::fastpath_bond_transition_key(
                    &fixture::chain(),
                    &e_id(),
                    1,
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(initial_transition.revision(), StateRevision::INITIAL);
        assert!(initial_transition.value().is_none());
        check_next_set_eligibility(
            &network.stores[replica],
            &network.context,
            network.domain(),
            &fixture::chain(),
            fixture::protocol().epoch(),
            &next_set(network).validators,
        )
        .unwrap();
        assert!(
            network
                .policy
                .engine()
                .validator_set()
                .get(e_id())
                .is_none()
        );
        assert_eq!(
            network.policy.engine().validator_set().validators().len(),
            REPLICAS
        );
    }
}

/// Opaque test-only fixture for the separate conditional-readiness owner.
/// The source is genuine and no incoming membership/activation is installed.
pub(crate) struct RegisteredCutFixture {
    source: CausalFixture,
    saved: SavedBusinessCut,
    next: FastPathValidatorSetRecord,
    keys: Vec<(ValidatorId, SigningKey)>,
    registration: OrderedCandidate,
}
impl RegisteredCutFixture {
    pub(crate) fn saved(&self) -> &SavedBusinessCut {
        &self.saved
    }
    pub(crate) fn manifest(&self) -> &GenesisManifest {
        &self.source.manifest
    }
    pub(crate) fn resolver(&self) -> &HashSuiteResolver {
        &self.source.network.resolver
    }
    pub(crate) fn policy(&self) -> &OrderedEconomicsPolicy {
        &self.source.network.policy
    }
    pub(crate) fn next_set(&self) -> &FastPathValidatorSetRecord {
        &self.next
    }
    pub(crate) fn signing_key(&self, id: ValidatorId) -> &SigningKey {
        &self
            .keys
            .iter()
            .find(|(validator, _)| *validator == id)
            .unwrap()
            .1
    }
    pub(crate) fn plan(
        &self,
        operation_context: DurableOperationContext,
    ) -> BusinessReconstructionPlan<'_> {
        let mut plan = reconstruction_plan(&self.source, &self.saved.identity.ordered_history);
        plan.operation_context = operation_context;
        plan
    }
    /// The genuine outgoing ABCD source, for the successor Seal producer.
    pub(super) fn source(&self) -> &CausalFixture {
        &self.source
    }
    /// The original epoch-e kind7 registration, for successor replay refusal.
    pub(super) fn registration(&self) -> &OrderedCandidate {
        &self.registration
    }
    /// The certified A->E paid request whose drained escrow the cut imports.
    pub(super) fn funded_escrow(&self) -> [u8; 32] {
        FUND
    }
}

/// ABCD real signed-v4 genesis, generic Publish/Instantiate/Call, certified
/// A->E owned producer, kind7 registration, ABC/E Freeze, complete DrainSet
/// and empty terminal candidate. Raw inactive plan exceeds one 128-row batch.
pub(crate) fn registered_cut_fixture() -> RegisteredCutFixture {
    registered_cut_fixture_configure(|_| {})
}

/// Test-only signed-genesis variation. All registration, execution and cut
/// evidence below still runs through the same genuine owning paths.
pub(super) fn registered_cut_fixture_configure(
    configure: impl FnOnce(&mut GenesisManifest),
) -> RegisteredCutFixture {
    let source: CausalFixture = setup_fixture_configure(
        crate::logical_generation::CommitmentProfile::CausalAdmission,
        configure,
    );
    let mut materials: Vec<CertifiedPaidMaterial> =
        control_reconstruction::registration_generic_prefix(&source);
    materials.push(fund_e(&source, u64::try_from(materials.len()).unwrap()));
    let (candidate, expected) = registration(&source, REGISTER, 0);
    commit_registration(&source.network, &candidate, 1);
    assert_registered(&source, &expected);
    let next: FastPathValidatorSetRecord = next_set(&source.network);
    let freeze: OrderedCandidate = OrderedCandidate {
        context: fixture::protocol(),
        request_id: FREEZE,
        kind: OrderedOperationKind::Freeze,
        intent: encode_freeze_intent(&FreezeIntent {
            context: fixture::protocol(),
            request_id: FREEZE,
            advisory_next_set: next.clone(),
        })
        .unwrap(),
        created_checkpoint: 21,
    };
    for view in 4..=6 {
        source.network.round(view, (view == 4).then_some(&freeze));
    }
    let network: &Network = &source.network;
    let mut selected: Vec<(FrozenFrontierVote, FrozenFrontierPage)> = Vec::new();
    for replica in 0..3 {
        let mut finalized: bool = false;
        for _ in 0..=materials.len() {
            if matches!(
                advance_frozen_frontier(
                    &network.stores[replica],
                    &network.context,
                    network.domain(),
                    &network.resolver,
                    &network.history,
                    &fixture::protocol(),
                    &network.signers[replica]
                )
                .unwrap(),
                FrozenFrontierStep::Finalized(_)
            ) {
                finalized = true;
                break;
            }
        }
        assert!(finalized);
        let pair = read_frozen_frontier_page(
            &network.stores[replica],
            &network.context,
            network.domain(),
            &network.resolver,
            &network.history,
            &fixture::protocol(),
            network.signers[replica].id,
            None,
            NonZeroUsize::new(materials.len() + 1).unwrap(),
        )
        .unwrap();
        assert!(pair.1.terminal);
        assert_eq!(pair.1.entries.len(), materials.len());
        selected.push(pair);
    }
    selected.sort_by_key(|(vote, _)| vote.validator);
    let bundles: Vec<&[u8]> = materials
        .iter()
        .map(|material| material.bundle.as_slice())
        .collect();
    let mut union: Option<DrainUnionIdentity> = None;
    for replica in 0..REPLICAS {
        let actual = control_reconstruction::derive_ready(network, replica, &selected, &bundles);
        if let Some(expected) = &union {
            assert_eq!(&actual, expected);
        } else {
            union = Some(actual);
        }
    }
    let drain: OrderedCandidate = OrderedCandidate {
        context: fixture::protocol(),
        request_id: DRAIN,
        kind: OrderedOperationKind::DrainSet,
        intent: encode_drain_set_intent(&DrainSetIntent {
            context: fixture::protocol(),
            request_id: DRAIN,
            selected_votes: selected.iter().map(|(vote, _)| vote.clone()).collect(),
            drain_union_identity: union.unwrap(),
        })
        .unwrap(),
        created_checkpoint: 22,
    };
    for view in 7..=9 {
        network.round(view, (view == 7).then_some(&drain));
    }
    for view in 10..=12 {
        network.round(view, None);
    }
    let (identity, history) = complete_history(network);
    let cut = derive_source_business_cut(
        reconstruction_plan(&source, &identity),
        &network.stores[0],
        &network.blobs,
        &history,
    )
    .unwrap();
    let saved = control_reconstruction::registration_transfer_cut(&cut, &network.resolver);
    let keys: Vec<(ValidatorId, SigningKey)> = network.signers[..3]
        .iter()
        .map(|signer| (signer.id, signer.key))
        .chain(std::iter::once((e_id(), e_key())))
        .collect();
    RegisteredCutFixture {
        source,
        saved,
        next,
        keys,
        registration: candidate,
    }
}

/// Exercise the existing ordered owner with a source Coin key distinct from
/// the registering validator. The required gate supplies the protected CLI
/// harness and submits its actual worker output. A direct cargo test retains
/// the original local-signature baseline when no pinned harness is supplied.
#[test]
fn initial_registration_distinct_source_and_validator_keys_order_effects() {
    let pin_names = [
        "SUNRISE_BOND_ORDERED_CLI",
        "SUNRISE_BOND_ORDERED_CLI_SHA256",
        "SUNRISE_BOND_ORDERED_HARNESS",
        "SUNRISE_BOND_ORDERED_HARNESS_SHA256",
    ];
    let supplied = pin_names
        .iter()
        .filter(|name| std::env::var_os(name).is_some())
        .count();
    assert!(
        supplied == 0 || supplied == pin_names.len(),
        "partial protected bond artifact pins"
    );
    let protected = supplied == pin_names.len();
    let fixture: CausalFixture = if protected {
        // This one test's signed genesis uses the canonical empty Standard
        // Asset initializer arguments required by the original-genesis CLI
        // profile. Other causal fixtures and their selectors are unchanged.
        setup_fixture_configure(
            crate::logical_generation::CommitmentProfile::CausalAdmission,
            |manifest| {
                manifest.initialization.intent.call.arguments =
                    public_standard_asset::no_arguments().unwrap();
                let frame = local_execution_signing_frame(
                    &fixture::protocol(),
                    &manifest.initialization.intent,
                )
                .unwrap();
                manifest.initialization.signature = fixture::key().sign(&frame).into();
            },
        )
    } else {
        fresh_fixture()
    };
    let source_signer = SigningKey::from([0x67; 32]);
    let source_key: [u8; 32] = VerificationKey::from(&source_signer).into();
    assert_ne!(source_key, *e_id().as_bytes());

    fund_for_recipient(&fixture, 0, FUND, 10_000, source_key);
    let source = funded_object_for_recipient(&fixture, FUND, source_key);
    let (candidate, expected) = if protected {
        #[cfg(target_os = "linux")]
        {
            for replica in 0..REPLICAS {
                assert_eq!(current_object(&fixture.network, replica, source.id), source);
            }
            let (row, token) = registration_expected_row(&fixture, &source, None);
            let baseline_leg = leg(
                &fixture,
                &source,
                REGISTER,
                0,
                &token,
                500_000,
                &source_signer,
            );
            let (protected_leg, protected_claim) =
                protected_bond_ordered_bytes(&fixture, &source, &row, &baseline_leg);
            assert_eq!(
                protected_leg, baseline_leg,
                "protected worker changed inner bytes"
            );
            execution::local_execution::authenticate_local_execution(
                &fixture.network.resolver,
                &fixture.network.leg_policy,
                &protected_leg,
            )
            .unwrap();
            let signed =
                verify_signed_bond_registration(&fixture.network.root, &protected_claim).unwrap();
            assert_eq!(
                signed.intent.leg, protected_leg,
                "outer claim changed inner bytes"
            );
            assert_eq!(signed.intent.context, fixture::protocol());
            assert_eq!(signed.intent.request_id, REGISTER);
            assert_eq!(signed.intent.authorization_key, *e_id().as_bytes());
            let resource = &fixture.manifest.economics_policy.resources[0];
            let prepared = prepare_bond_registration(
                &fixture.network.root,
                BondRegistrationPreparationRequest {
                    context: fixture::protocol(),
                    request_id: REGISTER,
                    authorization_key: *e_id().as_bytes(),
                    resource_context: resource.context.clone(),
                    resource: resource.resource_id,
                    leg: protected_leg,
                    predicted_initial_row: row.clone(),
                },
            )
            .unwrap();
            assert_eq!(signed.intent, prepared.intent);
            (
                OrderedCandidate {
                    context: fixture::protocol(),
                    request_id: REGISTER,
                    kind: OrderedOperationKind::BondRegistration,
                    intent: protected_claim,
                    created_checkpoint: CHECKPOINT,
                },
                row,
            )
        }
        #[cfg(not(target_os = "linux"))]
        panic!("protected bond ordered handoff requires Linux")
    } else {
        registration_claim_for_object_signed_by(
            &fixture,
            source.clone(),
            REGISTER,
            0,
            None,
            &source_signer,
        )
    };
    let signed = verify_signed_bond_registration(&fixture.network.root, &candidate.intent).unwrap();
    let signed_leg =
        execution::local_execution::decode_signed_local_execution(&signed.intent.leg).unwrap();
    assert_eq!(signed_leg.intent.call.sender, source_key);
    assert_eq!(signed.intent.authorization_key, *e_id().as_bytes());
    assert_eq!(signed.intent.request_id, candidate.request_id);
    assert_eq!(signed_leg.intent.call.request_id, candidate.request_id);
    commit_registration(&fixture.network, &candidate, 1);
    assert_registered_from(&fixture, &expected, source_key);
    for replica in 0..REPLICAS {
        let actual = current_object(&fixture.network, replica, source.id);
        assert_eq!(actual.version, source.version.checked_add(1).unwrap());
        assert_eq!(
            object_ref(&fixture.network, &actual),
            expected.custody_object
        );
        let outcome = query_ordered_outcome(
            &fixture.network.stores[replica],
            &fixture.network.context,
            &fixture.network.env(),
            &candidate.request_id,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            outcome.output.responses()[0].status(),
            NodeResponseStatus::Accepted
        );
    }
}

#[test]
fn initial_registration_genuine_paid_producer_orders_replays_and_reconstructs() {
    let fixture: CausalFixture = fresh_fixture();
    let _material = fund_e(&fixture, 0);
    let second_request: [u8; 32] = [0x67; 32];
    let _second: CertifiedPaidMaterial = fund_e_for(&fixture, 1, second_request, 10_000);
    let next = next_set(&fixture.network);
    assert!(matches!(
        check_next_set_eligibility(
            &fixture.network.stores[0],
            &fixture.network.context,
            fixture.network.domain(),
            &fixture::chain(),
            fixture::protocol().epoch(),
            &next.validators
        ),
        Err(NextSetEligibilityError::Prerequisite)
    ));
    let (candidate, expected) = registration(&fixture, REGISTER, 0);
    let terminal = commit_registration(&fixture.network, &candidate, 1);
    assert_registered(&fixture, &expected);
    let network: &Network = &fixture.network;
    let before = snapshot(network);
    for replica in 0..REPLICAS {
        let outcome = query_ordered_outcome(
            &network.stores[replica],
            &network.context,
            &network.env(),
            &candidate.request_id,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            outcome.output.responses()[0].status(),
            NodeResponseStatus::Accepted
        );
        assert!(
            process_certificate(
                &network.stores[replica],
                &network.context,
                &network.env(),
                &terminal
            )
            .unwrap()
            .committed
            .is_empty()
        );
    }
    assert_eq!(snapshot(network), before);
    let original_receipt: DurableRequestReceipt = receipt(network, 0, REGISTER).unwrap();
    let second_source: Object = funded_object_for(&fixture, second_request);
    let duplicate_request: [u8; 32] = [0xec; 32];
    let (duplicate, _) =
        registration_for_object(&fixture, second_source.clone(), duplicate_request, 1);
    commit_registration(network, &duplicate, 4);
    assert_registered(&fixture, &expected);
    for replica in 0..REPLICAS {
        let outcome = query_ordered_outcome(
            &network.stores[replica],
            &network.context,
            &network.env(),
            &duplicate_request,
        )
        .unwrap()
        .unwrap();
        assert_eq!(refusal_of(&outcome), OrderedRefusal::AlreadyRegistered);
        assert_eq!(
            current_object(network, replica, second_source.id),
            second_source
        );
        assert_eq!(
            receipt(network, replica, REGISTER).unwrap(),
            original_receipt
        );
    }
    let before = snapshot(network);
    let (identity, history) = complete_history(network);
    let plan = reconstruction_plan(&fixture, &identity);
    let owned = owned_material_from_source_snapshot(&before, &plan).unwrap();
    let mut overlay = BusinessReconstructionOverlay::new(plan).unwrap();
    let report = overlay.reconstruct(&owned, &history).unwrap();
    assert_eq!(report.ordered_originals_replayed, 2);
    overlay.compare_source(&before).unwrap();
    let mut corrupt = before.clone();
    let key = bond_registration_anchor_key(&fixture::chain(), &e_id()).unwrap();
    let bytes: &mut Vec<u8> = corrupt
        .records
        .iter_mut()
        .find(|record| {
            record.descriptor.key() == &runtime::portable::DurableRecordKey::State(key.clone())
        })
        .unwrap()
        .value
        .as_mut()
        .unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    assert!(overlay.compare_source(&corrupt).is_err());
}

#[test]
fn initial_registration_genuine_future_nonce_and_tombstone_stop_without_metadata() {
    let fixture = fresh_fixture();
    let _material = fund_e(&fixture, 0);
    let network = &fixture.network;
    let (future, _) = registration(&fixture, REGISTER, 1);
    let leader = network.leader_index(1);
    let before = snapshot(network);
    assert!(matches!(
        propose(
            &network.stores[leader],
            &network.context,
            &network.env(),
            Some(&future),
            &network.signers[leader]
        ),
        Err(OrderedEconomicsError::Prerequisite(_))
    ));
    assert_eq!(snapshot(network), before);
    let (valid, _) = registration(&fixture, REGISTER, 0);
    let mut invalid: Vec<OrderedCandidate> = Vec::new();
    let mut outer: OrderedCandidate = valid.clone();
    let mut signed = decode_signed_bond_registration_intent(&outer.intent).unwrap();
    signed.signature[0] ^= 1;
    outer.intent = encode_signed_bond_registration_intent(&signed).unwrap();
    invalid.push(outer);
    let mut inner: OrderedCandidate = valid.clone();
    sign_changed(&mut inner, |signed| {
        let mut leg =
            execution::local_execution::decode_signed_local_execution(&signed.intent.leg).unwrap();
        leg.signature[0] ^= 1;
        signed.intent.leg = encode_signed_local_execution(&leg).unwrap();
    });
    invalid.push(inner);
    // Noncanonical encoding, identity and canonical torsion point. No invalid
    // key is claimed to authenticate a positive registration.
    let mut identity: [u8; 32] = [0; 32];
    identity[0] = 1;
    for key in [
        [0xff; 32],
        identity,
        [0; 32],
        *network.signers[0].id.as_bytes(),
    ] {
        let mut candidate: OrderedCandidate = valid.clone();
        sign_changed(&mut candidate, |signed| {
            signed.intent.authorization_key = key;
            signed.intent.validator_id = ValidatorId::new(key);
        });
        let reason: &str = if key == *network.signers[0].id.as_bytes() {
            "registration reuses a signed genesis identity or key"
        } else {
            "registration requires canonical prime-order key"
        };
        assert!(matches!(
            verify_signed_bond_registration(&network.root, &candidate.intent),
            Err(crate::bond_lifecycle::registration::BondRegistrationError::Invalid(message))
                if message == reason
        ));
        invalid.push(candidate);
    }
    let mut wrong_lane: OrderedCandidate = valid.clone();
    wrong_lane.request_id = [0x46; 32];
    sign_changed(&mut wrong_lane, |signed| {
        signed.intent.request_id = [0x46; 32];
    });
    invalid.push(wrong_lane);
    for candidate in invalid {
        assert!(authenticate_candidate(&network.env(), &candidate).is_err());
        let signer = CountingConsensusSigner {
            signer: &network.signers[leader],
            calls: Cell::new(0),
        };
        assert!(
            propose(
                &network.stores[leader],
                &network.context,
                &network.env(),
                Some(&candidate),
                &signer
            )
            .is_err()
        );
        assert_eq!(signer.calls.get(), 0);
        assert_eq!(snapshot(network), before);
    }
    let mut reserved = decode_signed_bond_registration_intent(&valid.intent).unwrap();
    reserved.intent.request_id[..8]
        .copy_from_slice(&crate::local_instance_state::FASTPATH_SYNTHETIC_REQUEST_ID_TAG);
    assert!(encode_signed_bond_registration_intent(&reserved).is_err());
    let key = bond_registration_anchor_key(&fixture::chain(), &e_id()).unwrap();
    network.put(leader, key.clone(), StateMutation::Delete);
    let (candidate, _) = registration(&fixture, REGISTER, 0);
    let before = network.snapshot(leader, &[REGISTER], 3);
    assert!(matches!(
        propose(
            &network.stores[leader],
            &network.context,
            &network.env(),
            Some(&candidate),
            &network.signers[leader]
        ),
        Err(OrderedEconomicsError::Prerequisite(_))
    ));
    assert_eq!(network.snapshot(leader, &[REGISTER], 3), before);
    // Deliberate corruption replaces the local tombstone only in this negative
    // fixture; production registration never repairs/overwrites either slot.
    network.put(
        leader,
        key,
        StateMutation::Put(b"corrupt partial anchor".to_vec()),
    );
    let before = network.snapshot(leader, &[REGISTER], 3);
    let signer = CountingConsensusSigner {
        signer: &network.signers[leader],
        calls: Cell::new(0),
    };
    assert!(matches!(
        propose(
            &network.stores[leader],
            &network.context,
            &network.env(),
            Some(&candidate),
            &signer
        ),
        Err(OrderedEconomicsError::Prerequisite(_))
    ));
    assert_eq!(signer.calls.get(), 0);
    assert_eq!(network.snapshot(leader, &[REGISTER], 3), before);
}

#[test]
fn initial_registration_genuine_caller_invalid_results_refuse_then_valid_progress() {
    let fixture: CausalFixture = setup_fixture_configure(
        crate::logical_generation::CommitmentProfile::CausalAdmission,
        |manifest| {
            generic::event_on_collateral(manifest);
            manifest.economics_policy.resources[0]
                .bond
                .as_mut()
                .unwrap()
                .max_validator_exposure = Some(fees::Amount::new(25_000));
            for entry in &mut manifest.objects {
                if matches!(entry.object.owner, Owner::ProtocolCustody(_)) {
                    entry.object.data = abi::call_values::encode_call_value(
                        &public_standard_asset::coin_body_layout(),
                        &abi::call_values::CallValue::U64(10_000),
                    )
                    .unwrap();
                }
            }
        },
    );
    let _material = fund_e(&fixture, 0);
    let event_request: [u8; 32] = [0x67; 32];
    let _second_material: CertifiedPaidMaterial = fund_e_for(&fixture, 1, event_request, 20_000);
    let minimum_request: [u8; 32] = [0x68; 32];
    let maximum_request: [u8; 32] = [0x69; 32];
    let _minimum: CertifiedPaidMaterial = fund_e_for(&fixture, 2, minimum_request, 50);
    let _maximum: CertifiedPaidMaterial = fund_e_for(&fixture, 3, maximum_request, 30_000);
    let network = &fixture.network;
    let original: Object = funded_object(&fixture);
    for (index, refusal) in [
        OrderedRefusal::SignedRowMismatch,
        OrderedRefusal::RegistrationTrapped,
        OrderedRefusal::RegistrationEffects,
        OrderedRefusal::RegistrationMinimum,
        OrderedRefusal::RegistrationExposure,
    ]
    .into_iter()
    .enumerate()
    {
        let request: [u8; 32] = [0xe9 + u8::try_from(index).unwrap(); 32];
        let source: Object = match index {
            2 => funded_object_for(&fixture, event_request),
            3 => funded_object_for(&fixture, minimum_request),
            4 => funded_object_for(&fixture, maximum_request),
            _ => original.clone(),
        };
        let (mut candidate, _) = registration_claim_for_object(
            &fixture,
            source.clone(),
            request,
            0,
            (index >= 3).then_some(10_000),
        );
        match index {
            0 => sign_changed(&mut candidate, |signed| {
                signed.intent.expected_initial_row_digest =
                    Digest32::new(protocol_types::HashAlgorithmId::Sha2_256, [0x11; 32])
            }),
            1 => sign_changed(&mut candidate, |signed| {
                let mut leg =
                    execution::local_execution::decode_signed_local_execution(&signed.intent.leg)
                        .unwrap();
                leg.intent.call.gas_limit = 1;
                leg.signature = e_key()
                    .sign(
                        &local_execution_signing_frame(&fixture::protocol(), &leg.intent).unwrap(),
                    )
                    .into();
                signed.intent.leg = encode_signed_local_execution(&leg).unwrap();
            }),
            _ => {}
        }
        authenticate_candidate(&network.env(), &candidate).unwrap();
        let first_view = u64::try_from(index)
            .unwrap()
            .checked_mul(3)
            .unwrap()
            .checked_add(1)
            .unwrap();
        let terminal = commit_registration(network, &candidate, first_view);
        for replica in 0..REPLICAS {
            let outcome = query_ordered_outcome(
                &network.stores[replica],
                &network.context,
                &network.env(),
                &candidate.request_id,
            )
            .unwrap()
            .unwrap();
            assert_eq!(refusal_of(&outcome), refusal);
            assert_eq!(current_object(network, replica, original.id), original);
            assert_eq!(current_object(network, replica, source.id), source);
            assert_eq!(
                query_sender_next_nonce(
                    &network.stores[replica],
                    &network.context,
                    network.domain(),
                    fixture::chain(),
                    fixture::protocol().protocol_version(),
                    fixture::protocol().epoch(),
                    *e_id().as_bytes()
                )
                .unwrap(),
                0
            );
            for key in [
                fastpath_bond_record_key(&fixture::chain(), &e_id()).unwrap(),
                bond_registration_anchor_key(&fixture::chain(), &e_id()).unwrap(),
            ] {
                let observed = network.stores[replica]
                    .get_versioned_durable(&network.context, network.domain(), &key)
                    .unwrap();
                assert_eq!(observed.revision(), StateRevision::INITIAL);
                assert!(observed.value().is_none());
            }
            let original_receipt = receipt(network, replica, request).unwrap();
            assert_eq!(
                original_receipt.event_digest(),
                network.policy.candidate_digest(&candidate).unwrap()
            );
            let before = network.snapshot(replica, &[request], 3);
            assert!(
                process_certificate(
                    &network.stores[replica],
                    &network.context,
                    &network.env(),
                    &terminal
                )
                .unwrap()
                .committed
                .is_empty()
            );
            assert_eq!(network.snapshot(replica, &[request], 3), before);
            assert_eq!(
                receipt(network, replica, request).unwrap(),
                original_receipt
            );
        }
    }
    let (candidate, expected) = registration(&fixture, REGISTER, 0);
    commit_registration(network, &candidate, 16);
    assert_registered(&fixture, &expected);
    let source = snapshot(network);
    let (identity, history) = complete_history(network);
    let plan = reconstruction_plan(&fixture, &identity);
    let owned = owned_material_from_source_snapshot(&source, &plan).unwrap();
    let mut overlay = BusinessReconstructionOverlay::new(plan).unwrap();
    assert_eq!(
        overlay
            .reconstruct(&owned, &history)
            .unwrap()
            .ordered_originals_replayed,
        6
    );
    overlay.compare_source(&source).unwrap();
}

#[test]
fn initial_registration_genuine_abce_complete_cut_independent_import_exceeds128() {
    let source: crate::ordered_economics::RegisteredCutFixture =
        crate::ordered_economics::registered_cut_fixture();
    let operation = fixture::context(1);
    assert_eq!(
        source.manifest().commitment_profile,
        crate::logical_generation::CommitmentProfile::CausalAdmission
    );
    assert_eq!(
        source.policy().genesis_digest(),
        genesis::genesis_manifest_commitment(source.resolver(), source.manifest()).unwrap()
    );
    let plan = verify_saved_business_import(source.plan(operation), source.saved()).unwrap();
    assert!(
        plan.binding().row_count > 128,
        "genuine raw plan must span multiple row batches"
    );
    assert_eq!(source.next_set().validators.len(), 4);
    assert!(
        source
            .next_set()
            .validators
            .iter()
            .any(|entry| entry.id == e_id())
    );
    let actual: [u8; 64] = source.signing_key(e_id()).sign(b"actual key").into();
    let expected: [u8; 64] = e_key().sign(b"actual key").into();
    assert_eq!(actual, expected);
    sqlite::assert_registration_restart_replay_and_fence(&source, &plan);
}
