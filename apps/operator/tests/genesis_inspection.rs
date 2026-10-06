//! Real author/inspector processes: independently pinned, no raw row seeding,
//! no inspection key, and no durable side effects or activation claim.

#[path = "support/compiled_source_host_process.rs"]
mod compiled_source_host_process;
#[path = "support/offline_genesis_fixture.rs"]
mod offline_genesis_fixture;

use compiled_source_host_process::spawn_bounded_output;
use ed25519_zebra::{SigningKey, VerificationKey};
use node_core::genesis::{
    GenesisManifest, MAX_GENESIS_MANIFEST_BYTES, VerifiedGenesisRoot, decode_genesis_manifest,
    encode_genesis_manifest, genesis_manifest_commitment, genesis_manifest_signing_frame,
};
use node_core::logical_generation::CommitmentProfile;
use offline_genesis_fixture::{Fixture, field, hex, refused, replace, success};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::Duration,
};
use sunrise_edge_operator::common::parse_hex_32;

struct Inspection {
    fixture: Fixture,
    path: PathBuf,
    digest: [u8; 32],
}

impl Inspection {
    fn authored() -> Self {
        Self::from_fixture(Fixture::new())
    }

    fn from_fixture(fixture: Fixture) -> Self {
        let output: String = success(fixture.author(&fixture.args));
        let digest: [u8; 32] = parse_hex_32(field(&output, "manifest_digest="), "digest").unwrap();
        let path: PathBuf = fixture.directory.join("genesis.bin");
        Self {
            fixture,
            path,
            digest,
        }
    }

    fn args(&self) -> Vec<OsString> {
        let mut args: Vec<OsString> = vec!["inspect".into()];
        for (flag, value) in [
            (
                "--chain-id",
                self.fixture.context.chain_id().as_str().to_owned(),
            ),
            (
                "--protocol-version",
                self.fixture.context.protocol_version().get().to_string(),
            ),
            ("--epoch", self.fixture.context.epoch().get().to_string()),
            ("--suite", "0:1:1:1:1:1:1:1".to_owned()),
            ("--expected-genesis-authority", hex(&self.fixture.authority)),
            ("--expected-manifest-digest", hex(&self.digest)),
            ("--validation-domain", hex(&[0x41; 32])),
            ("--validation-checkpoint", "10".to_owned()),
            ("--timeout-seconds", "30".to_owned()),
        ] {
            args.push(flag.into());
            args.push(value.into());
        }
        args.push("--genesis-manifest".into());
        args.push(self.path.as_os_str().into());
        args
    }

    fn inspect(&self, args: &[OsString]) -> Output {
        let mut command: Command = Command::new(env!("CARGO_BIN_EXE_genesis_inspect"));
        command.args(args);
        spawn_bounded_output(command, Duration::from_secs(30))
    }

    fn manifest(&self) -> GenesisManifest {
        decode_genesis_manifest(&fs::read(&self.path).unwrap()).unwrap()
    }

    fn resign(&mut self, mut manifest: GenesisManifest) -> VerifiedGenesisRoot {
        // Only disposable known fixture material, never a production key.
        manifest.signature = SigningKey::from([0x55; 32])
            .sign(&genesis_manifest_signing_frame(&manifest).unwrap())
            .into();
        let bytes: Vec<u8> = encode_genesis_manifest(&manifest).unwrap();
        self.digest = genesis_manifest_commitment(&self.fixture.resolver, &manifest)
            .unwrap()
            .bytes();
        let root: VerifiedGenesisRoot = VerifiedGenesisRoot::verify_bytes(
            &self.fixture.resolver,
            &bytes,
            self.digest,
            &self.fixture.context,
        )
        .unwrap();
        fs::write(&self.path, bytes).unwrap();
        root
    }
}

fn inventory(directory: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut files: BTreeMap<PathBuf, Vec<u8>> = BTreeMap::new();
    for entry in fs::read_dir(directory).unwrap() {
        let entry: fs::DirEntry = entry.unwrap();
        assert!(
            entry.file_type().unwrap().is_file(),
            "unexpected new directory or sidecar owner"
        );
        files.insert(entry.file_name().into(), fs::read(entry.path()).unwrap());
    }
    files
}

fn inspected(output: Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: String = String::from_utf8(output.stdout).unwrap();
    assert!(summary.ends_with("complete=true mode=inspect evidence=none\n"));
    assert_eq!(summary.matches("complete=true").count(), 1);
    summary
}

fn fields(summary: &str) -> BTreeMap<&str, &str> {
    let mut values: BTreeMap<&str, &str> = BTreeMap::new();
    for line in summary.lines() {
        if line == "complete=true mode=inspect evidence=none" {
            continue;
        }
        let (key, value): (&str, &str) = line.split_once('=').unwrap();
        assert!(!value.contains('='), "unescaped value delimiter");
        assert!(
            values.insert(key, value).is_none(),
            "duplicate diagnostic field"
        );
    }
    values
}

#[test]
fn real_inspection_needs_no_secret_and_is_deterministic_without_durable_side_effects() {
    let inspection: Inspection = Inspection::authored();
    fs::remove_file(inspection.fixture.directory.join("authority.key")).unwrap();
    let before: BTreeMap<PathBuf, Vec<u8>> = inventory(&inspection.fixture.directory);
    let summary: String = inspected(inspection.inspect(&inspection.args()));
    let root: VerifiedGenesisRoot = VerifiedGenesisRoot::verify_bytes(
        &inspection.fixture.resolver,
        &fs::read(&inspection.path).unwrap(),
        inspection.digest,
        &inspection.fixture.context,
    )
    .unwrap();
    let manifest: &GenesisManifest = root.manifest();
    let values: BTreeMap<&str, &str> = fields(&summary);
    assert_eq!(values["manifest_digest"], root.digest().to_string());
    assert_eq!(
        values["genesis_authority"],
        hex(&manifest.genesis_authority)
    );
    assert_eq!(
        values["expected_chain_id"],
        inspection.fixture.context.chain_id().as_str()
    );
    assert_eq!(values["expected_protocol_version"], "7");
    assert_eq!(values["expected_epoch"], "0");
    assert_eq!(values["manifest_encoding_version"], "4");
    assert_eq!(
        values["signature_family"],
        manifest.signature_message_type()
    );
    assert_eq!(values["commitment_profile"], "causal_admission");
    assert_eq!(values["minimum_freeze_block_height"], "1");
    assert_eq!(
        values["published_revision"],
        manifest
            .publication
            .request()
            .artifact()
            .revision()
            .to_string()
    );
    assert_eq!(
        values["published_artifact_digest"],
        manifest.publication.request().artifact_digest().to_string()
    );
    assert_eq!(
        values["initializer_entrypoint"],
        manifest.initialization.intent.call.entrypoint
    );
    assert_eq!(values["committee_member_count"], "4");
    for (index, validator) in root.genesis_committee().validators().iter().enumerate() {
        let prefix: String = format!("committee_member_{index}");
        assert_eq!(
            values[format!("{prefix}_id").as_str()],
            hex(validator.id.as_bytes())
        );
        assert_eq!(
            values[format!("{prefix}_public_key").as_str()],
            hex(&validator.public_key)
        );
        assert_eq!(
            values[format!("{prefix}_signature_scheme").as_str()],
            "ed25519"
        );
        assert_eq!(values[format!("{prefix}_voting_power").as_str()], "1");
    }
    let fee: &execution::paid_execution::PaidFeePolicy = &manifest.fee_policy;
    for (label, number) in [
        ("fee_base_price", fee.gas_schedule.base_fee),
        ("fee_execution_price", fee.gas_schedule.execution_price),
        ("fee_read_price", fee.gas_schedule.read_price),
        ("fee_write_price", fee.gas_schedule.write_price),
        ("fee_storage_price", fee.gas_schedule.storage_price),
        (
            "fee_system_module_price",
            fee.gas_schedule.system_module_price,
        ),
        ("fee_conversion_divisor", fee.conversion_divisor),
        ("fee_reserve_allowance", fee.reserve_allowance),
        ("fee_settle_allowance", fee.settle_allowance),
        (
            "fee_publish_artifact_byte_price",
            fee.publish_artifact_byte_price,
        ),
        (
            "fee_publish_closure_node_price",
            fee.publish_closure_node_price,
        ),
        ("fee_cap_calls", u64::from(fee.calls)),
        ("fee_cap_handles", u64::from(fee.handles)),
        ("fee_cap_creations", u64::from(fee.creations)),
        ("fee_cap_events", u64::from(fee.events)),
        ("fee_cap_memory_bytes", fee.memory_bytes),
        ("fee_cap_output_bytes", fee.output_bytes),
    ] {
        assert_eq!(values[label], number.to_string(), "{label}");
    }
    assert_eq!(values["fee_recipient"], hex(&fee.fee_recipient));
    assert_eq!(values["economics_resource_count"], "1");
    let resource: &node_core::economics::FastPathEconomicsResourcePolicy =
        &manifest.economics_policy.resources[0];
    assert_eq!(
        values["economics_resource_0_id"],
        format!(
            "{:04x}:{}",
            resource.resource_id.domain(),
            hex(resource.resource_id.value())
        )
    );
    assert_eq!(
        values["economics_resource_0_schema"],
        resource.schema.to_string()
    );
    assert_eq!(values["economics_resource_0_fee_escrow"], "true");
    assert_eq!(values["economics_resource_0_bond_enabled"], "true");
    assert_eq!(values["economics_resource_0_bond_min"], "100");
    assert_eq!(values["economics_resource_0_bond_unbonding_epochs"], "7");
    assert_eq!(values["economics_resource_0_bond_max_exposure"], "none");
    assert_eq!(values["object_count"], manifest.objects.len().to_string());
    for (index, entry) in manifest.objects.iter().enumerate() {
        let prefix: String = format!("object_{index}");
        assert_eq!(
            values[format!("{prefix}_frame").as_str()],
            hex(&objects::encode_object(&entry.object).unwrap())
        );
        assert_eq!(
            values[format!("{prefix}_authority_frame").as_str()],
            hex(&execution::local_execution::encode_object_authority(&entry.authority).unwrap())
        );
        assert_eq!(
            values[format!("{prefix}_id").as_str()],
            hex(entry.object.id.as_bytes())
        );
        assert_eq!(
            values[format!("{prefix}_version").as_str()],
            entry.object.version.to_string()
        );
        assert_eq!(
            values[format!("{prefix}_schema_version").as_str()],
            entry.object.schema_version.to_string()
        );
        assert_eq!(
            values[format!("{prefix}_type_digest").as_str()],
            entry.object.type_hash.to_string()
        );
        match &entry.object.owner {
            objects::Owner::Address(address) => {
                assert_eq!(values[format!("{prefix}_owner").as_str()], "address");
                assert_eq!(
                    values[format!("{prefix}_owner_address").as_str()],
                    hex(address.as_bytes())
                );
            }
            objects::Owner::ProtocolCustody(scope) => {
                assert_eq!(
                    values[format!("{prefix}_owner").as_str()],
                    "protocol_custody"
                );
                assert_eq!(
                    values[format!("{prefix}_owner_custody_purpose").as_str()],
                    "bond_collateral"
                );
                assert_eq!(
                    values[format!("{prefix}_owner_custody_chain_id").as_str()],
                    scope.chain_id.as_str()
                );
                assert_eq!(
                    values[format!("{prefix}_owner_custody_subject").as_str()],
                    hex(&scope.subject)
                );
                assert_eq!(
                    values[format!("{prefix}_owner_custody_resource").as_str()],
                    hex(&scope.resource)
                );
            }
            other => panic!("unexpected authored owner: {other:?}"),
        }
    }
    for canonical in [
        execution::paid_execution::encode_paid_fee_policy(&manifest.fee_policy).unwrap(),
        node_core::economics::encode_fastpath_economics_policy(&manifest.economics_policy).unwrap(),
        node_core::fast_path::records::encode_fastpath_validator_set_record(
            &manifest.validator_set,
        )
        .unwrap(),
        abi::package_types::encode_package_origin(
            manifest.publication.request().artifact().origin(),
        )
        .unwrap(),
        execution::publication::encode_publication_context(
            manifest.publication.request().artifact().context(),
        )
        .unwrap(),
        execution::publication::encode_dependency_ref(&manifest.initialization.intent.call.code)
            .unwrap(),
        execution::call::encode_instance_target(&manifest.initialization.intent.call.instance)
            .unwrap(),
    ] {
        assert!(
            summary.contains(&hex(&canonical)),
            "missing exact canonical diagnostic record"
        );
    }
    let mut changed_local: Vec<OsString> = inspection.args();
    replace(
        &mut changed_local,
        "--validation-domain",
        hex(&[0x42; 32]).into(),
    );
    replace(&mut changed_local, "--validation-checkpoint", "9876".into());
    std::thread::sleep(Duration::from_millis(2));
    assert_eq!(inspected(inspection.inspect(&changed_local)), summary);
    assert_eq!(inventory(&inspection.fixture.directory), before);
}

#[test]
fn real_inspection_does_not_let_signed_public_text_inject_lines_or_terminal_controls() {
    let chain: &str = "offline=inspect\\\n\u{1b}[31mé\u{009b}\u{202e}";
    let inspection: Inspection = Inspection::from_fixture(Fixture::with_chain(chain));
    let before: BTreeMap<PathBuf, Vec<u8>> = inventory(&inspection.fixture.directory);
    let summary: String = inspected(inspection.inspect(&inspection.args()));
    let values: BTreeMap<&str, &str> = fields(&summary);
    let escaped_chain: &str =
        "offline\\x3dinspect\\\\\\x0a\\x1b[31m\\xc3\\xa9\\xc2\\x9b\\xe2\\x80\\xae";
    assert_eq!(values["expected_chain_id"], escaped_chain);
    let manifest: GenesisManifest = inspection.manifest();
    for (index, entry) in manifest.objects.iter().enumerate() {
        if matches!(entry.object.owner, objects::Owner::ProtocolCustody(_)) {
            assert_eq!(
                values[format!("object_{index}_owner_custody_chain_id").as_str()],
                escaped_chain
            );
        }
    }
    assert!(!summary.contains('\u{1b}'));
    assert!(!summary.contains('é'));
    assert!(!summary.contains('\u{009b}'));
    assert!(!summary.contains('\u{202e}'));
    assert_eq!(inventory(&inspection.fixture.directory), before);
}

#[test]
fn real_inspection_refuses_wrong_independent_pins_before_advertising_any_summary() {
    let inspection: Inspection = Inspection::authored();
    let before: BTreeMap<PathBuf, Vec<u8>> = inventory(&inspection.fixture.directory);
    let foreign_authority: [u8; 32] = VerificationKey::from(&SigningKey::from([0x66; 32])).into();
    for (flag, value) in [
        ("--expected-manifest-digest", hex(&[0; 32])),
        ("--expected-genesis-authority", hex(&foreign_authority)),
        ("--chain-id", "foreign-inspection-chain".to_owned()),
        ("--protocol-version", "8".to_owned()),
        ("--epoch", "1".to_owned()),
        ("--suite", "0:1:2:2:2:2:2:2".to_owned()),
    ] {
        let mut args: Vec<OsString> = inspection.args();
        replace(&mut args, flag, value.into());
        refused(inspection.inspect(&args));
        assert_eq!(inventory(&inspection.fixture.directory), before);
    }
}

#[test]
fn real_inspection_rejects_open_dispatch_secret_or_mutation_flags_and_noncanonical_numbers() {
    let inspection: Inspection = Inspection::authored();
    let before: BTreeMap<PathBuf, Vec<u8>> = inventory(&inspection.fixture.directory);
    for (flag, value) in [
        ("--protocol-version", "07"),
        ("--epoch", "+0"),
        ("--validation-checkpoint", "01"),
        ("--timeout-seconds", "0"),
        ("--timeout-seconds", "31"),
        ("--timeout-seconds", "18446744073709551615"),
        ("--suite", "00:1:1:1:1:1:1:1"),
        ("--suite", "0:+1:1:1:1:1:1:1"),
        ("--suite", "0:1:01:1:1:1:1:1"),
    ] {
        let mut args: Vec<OsString> = inspection.args();
        replace(&mut args, flag, value.into());
        refused(inspection.inspect(&args));
    }
    let mut zero_domain: Vec<OsString> = inspection.args();
    replace(
        &mut zero_domain,
        "--validation-domain",
        hex(&[0; 32]).into(),
    );
    refused(inspection.inspect(&zero_domain));
    for flag in [
        "--genesis-key-file",
        "--output",
        "--state-db",
        "--listen",
        "--url",
        "--unknown",
    ] {
        let mut args: Vec<OsString> = inspection.args();
        args.extend([OsString::from(flag), OsString::from("must-not-be-used")]);
        refused(inspection.inspect(&args));
    }
    let mut duplicate: Vec<OsString> = inspection.args();
    duplicate.extend(["--epoch".into(), "0".into()]);
    refused(inspection.inspect(&duplicate));
    for args in [Vec::new(), vec!["author".into()], vec!["inspect".into()]] {
        refused(inspection.inspect(&args));
    }
    let mut missing: Vec<OsString> = inspection.args();
    let index: usize = missing
        .iter()
        .position(|value: &OsString| value == "--suite")
        .unwrap();
    missing.drain(index..index + 2);
    refused(inspection.inspect(&missing));
    let mut excess: Vec<OsString> = inspection.args();
    for _index in 0..64 {
        excess.extend(["--suite".into(), "0:1:1:1:1:1:1:1".into()]);
    }
    refused(inspection.inspect(&excess));
    assert_eq!(inventory(&inspection.fixture.directory), before);
}

#[test]
fn real_inspection_refuses_missing_truncated_malformed_and_excess_manifest_without_writes() {
    let inspection: Inspection = Inspection::authored();
    let original: Vec<u8> = fs::read(&inspection.path).unwrap();
    for bytes in [
        b"not-a-manifest".to_vec(),
        original[..original.len() / 2].to_vec(),
        vec![0; MAX_GENESIS_MANIFEST_BYTES + 1],
    ] {
        let path: PathBuf = inspection.fixture.directory.join("bad-manifest.bin");
        fs::write(&path, bytes).unwrap();
        let before: BTreeMap<PathBuf, Vec<u8>> = inventory(&inspection.fixture.directory);
        let mut args: Vec<OsString> = inspection.args();
        replace(&mut args, "--genesis-manifest", path.into_os_string());
        refused(inspection.inspect(&args));
        assert_eq!(inventory(&inspection.fixture.directory), before);
    }
    let before: BTreeMap<PathBuf, Vec<u8>> = inventory(&inspection.fixture.directory);
    let mut args: Vec<OsString> = inspection.args();
    replace(
        &mut args,
        "--genesis-manifest",
        inspection.fixture.directory.join("missing.bin").into(),
    );
    refused(inspection.inspect(&args));
    assert_eq!(inventory(&inspection.fixture.directory), before);
}

#[test]
fn valid_outer_signature_cannot_hide_either_invalid_nested_signature_from_the_real_inspector() {
    for publication in [true, false] {
        let mut inspection: Inspection = Inspection::authored();
        let mut manifest: GenesisManifest = inspection.manifest();
        if publication {
            let request: &execution::publication::PublicationRequest =
                manifest.publication.request();
            let altered: execution::publication::PublicationRequest =
                execution::publication::PublicationRequest::new(
                    request.artifact().clone(),
                    request.nonce(),
                    *request.artifact_digest(),
                    [0; 64],
                );
            manifest.publication = execution::publication::PublicationSubmission::new(
                *manifest.publication.request_id(),
                altered,
            )
            .unwrap();
        } else {
            manifest.initialization.signature = [0; 64];
        }
        let _valid_outer: VerifiedGenesisRoot = inspection.resign(manifest);
        let before: BTreeMap<PathBuf, Vec<u8>> = inventory(&inspection.fixture.directory);
        let output: Output = inspection.inspect(&inspection.args());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("signature"),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        refused(output);
        assert_eq!(inventory(&inspection.fixture.directory), before);
    }
}

#[test]
fn real_generic_inspection_accepts_a_defining_installer_supported_noncausal_original_profile() {
    let mut inspection: Inspection = Inspection::authored();
    let mut manifest: GenesisManifest = inspection.manifest();
    manifest.commitment_profile = CommitmentProfile::PhysicalCheckpointV1;
    manifest.minimum_freeze_block_height = 0;
    let root: VerifiedGenesisRoot = inspection.resign(manifest);
    assert!(!root.admission_profile().is_causal());
    assert_eq!(root.manifest().encoding_version(), 1);
    let before: BTreeMap<PathBuf, Vec<u8>> = inventory(&inspection.fixture.directory);
    let summary: String = inspected(inspection.inspect(&inspection.args()));
    assert!(summary.contains(&root.digest().to_string()));
    assert_eq!(inventory(&inspection.fixture.directory), before);
}
