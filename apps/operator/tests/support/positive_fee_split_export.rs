//! Opt-in public export for the original, complete first-successor selector.
//! No key or database material is accepted here (DR-0270).
use sha2::{Digest as _, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    process::{Command, Output},
    time::Duration,
};
use sunrise_edge_client::immutable_archive::ImmutableArchiveReader;
use sunrise_edge_client::{
    FeeClaimIntent, FeeClaimPrepareRequest, HashSuiteResolver, PublicationContext,
    SuccessorArtifactDirectories, SuccessorChainBudget, SuccessorWorkflowAuthority,
    encode_fee_claim_intent, load_successor_chain_workflow_from_directories,
};

const FILE_BYTES: usize = 1024 * 1024;
const TOTAL_BYTES: usize = 16 * 1024 * 1024;
const FILE_COUNT: usize = 256;

pub(super) struct PublicCase {
    pub label: &'static str,
    pub request: FeeClaimPrepareRequest,
    pub intent: FeeClaimIntent,
    pub signed_outer: Vec<u8>,
    pub candidate: Vec<u8>,
}

pub(super) struct Selection {
    root: PathBuf,
    node: PathBuf,
    provenance: PathBuf,
    provenance_sha: String,
    node_sha: String,
}

fn digest(bytes: &[u8]) -> String {
    let hash: [u8; 32] = Sha256::digest(bytes).into();
    super::super::hex(&hash)
}

fn read(path: &Path, maximum: usize) -> Vec<u8> {
    let before: fs::Metadata = fs::symlink_metadata(path).unwrap();
    assert!(before.is_file() && !before.file_type().is_symlink());
    let mut file: File = File::open(path).unwrap();
    let held: fs::Metadata = file.metadata().unwrap();
    assert_eq!((before.dev(), before.ino()), (held.dev(), held.ino()));
    let mut bytes: Vec<u8> = Vec::new();
    Read::by_ref(&mut file)
        .take(u64::try_from(maximum).unwrap() + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= maximum && u64::try_from(bytes.len()).unwrap() == held.len());
    ImmutableArchiveReader::ensure_file_attached(path, &file).unwrap();
    bytes
}

fn private_directory(path: &Path) {
    let metadata: fs::Metadata = fs::symlink_metadata(path).unwrap();
    assert!(metadata.is_dir() && !metadata.file_type().is_symlink());
    assert_eq!(metadata.permissions().mode() & 0o7777, 0o700);
    let mut status: String = String::new();
    File::open("/proc/self/status")
        .unwrap()
        .take(8192)
        .read_to_string(&mut status)
        .unwrap();
    let uid: u32 = status
        .lines()
        .find_map(|line: &str| {
            line.strip_prefix("Uid:")
                .and_then(|v: &str| v.split_whitespace().nth(1))
        })
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(metadata.uid(), uid);
}

pub(super) fn selection() -> Option<Selection> {
    let root: Option<OsString> = std::env::var_os("SUNRISE_EDGE_POSITIVE_SPLIT_EXPORT_ROOT");
    let plan: Option<OsString> = std::env::var_os("SUNRISE_EDGE_POSITIVE_SPLIT_UID_PLAN");
    let (root, plan): (OsString, OsString) = match (root, plan) {
        (None, None) => return None,
        (Some(root), Some(plan)) => (root, plan),
        _ => panic!("positive Split export and inline fixture plan must be selected together"),
    };
    let root: PathBuf = root.into();
    assert!(
        root.is_absolute()
            && root
                .components()
                .all(|c| !matches!(c, Component::ParentDir))
    );
    private_directory(root.parent().unwrap());
    for ancestor in root.parent().unwrap().ancestors() {
        let metadata: fs::Metadata = fs::symlink_metadata(ancestor).unwrap();
        assert!(metadata.is_dir() && !metadata.file_type().is_symlink());
    }
    assert!(!root.exists(), "create-only public export already exists");
    let plan: PathBuf = plan.into();
    assert!(plan.is_absolute());
    let text: String = String::from_utf8(read(&plan, 16384)).unwrap();
    let mut fields: BTreeMap<&str, &str> = BTreeMap::new();
    for line in text.lines() {
        let (key, value): (&str, &str) = line.split_once('=').unwrap();
        assert!(fields.insert(key, value).is_none());
    }
    assert_eq!(fields.len(), 4);
    let node: PathBuf = fields["node"].into();
    let provenance: PathBuf = fields["provenance"].into();
    let node_sha: String = fields["node_sha256"].into();
    let provenance_sha: String = fields["provenance_sha256"].into();
    assert!(node.is_absolute() && provenance.is_absolute());
    assert_eq!(digest(&read(&node, 256 * 1024 * 1024)), node_sha);
    assert_eq!(digest(&read(&provenance, 256 * 1024)), provenance_sha);
    Some(Selection {
        root,
        node,
        provenance,
        provenance_sha,
        node_sha,
    })
}

struct Export {
    root: PathBuf,
    records: BTreeMap<String, (usize, String)>,
    bytes: usize,
}
impl Export {
    fn put(&mut self, relative: &str, bytes: &[u8]) {
        assert!(bytes.len() <= FILE_BYTES && self.records.len() < FILE_COUNT);
        assert!(
            relative.len() <= 251
                && relative.split('/').all(|name| !name.is_empty()
                    && name != "."
                    && name != ".."
                    && !name.contains(['\t', '\n', '\r', '\\']))
        );
        self.bytes = self.bytes.checked_add(bytes.len()).unwrap();
        assert!(self.bytes <= TOTAL_BYTES);
        assert!(!self.records.contains_key(relative));
        let path: PathBuf = self.root.join(relative);
        let parent: &Path = path.parent().unwrap();
        if !parent.exists() {
            fs::create_dir_all(parent).unwrap();
            let mut current: PathBuf = self.root.clone();
            for component in parent.strip_prefix(&self.root).unwrap().components() {
                current.push(component);
                fs::set_permissions(&current, fs::Permissions::from_mode(0o700)).unwrap();
            }
        }
        private_directory(parent);
        let mut file: File = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        File::open(parent).unwrap().sync_all().unwrap();
        assert_eq!(read(&path, FILE_BYTES), bytes);
        self.records
            .insert(relative.into(), (bytes.len(), digest(bytes)));
    }
    fn archive(&mut self, role: &str, original: &Path) {
        let reader: ImmutableArchiveReader = ImmutableArchiveReader::open(original).unwrap();
        if let Some(staging) = reader.staging() {
            assert!(
                fs::read_dir(staging.path()).unwrap().next().is_none(),
                "export refuses pending/orphan staging"
            );
        }
        let names: BTreeSet<String> = reader.names().unwrap();
        for name in &names {
            assert!(
                ![".key", ".seed", ".db"]
                    .iter()
                    .any(|suffix: &&str| name.ends_with(*suffix))
                    && name != "private.key",
                "private/database files cannot be exported"
            );
            let bytes: Vec<u8> = reader.read(name, FILE_BYTES).unwrap();
            self.put(&format!("{role}/{name}"), &bytes);
        }
        assert_eq!(reader.names().unwrap(), names);
        reader.ensure_attached().unwrap();
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn run(
    selected: Selection,
    workflow: &SuccessorWorkflowAuthority,
    resolver: &HashSuiteResolver,
    manifest: &[u8],
    manifest_digest: [u8; 32],
    flags: &[String],
    fee_object: &[u8],
    cases: &[PublicCase],
) -> Vec<u8> {
    assert_eq!(
        cases
            .iter()
            .map(|c: &PublicCase| c.label)
            .collect::<Vec<&str>>(),
        ["A", "B", "C", "D"]
    );
    fs::create_dir(&selected.root).unwrap();
    fs::set_permissions(&selected.root, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        fs::metadata(&selected.root).unwrap().uid(),
        fs::metadata(selected.root.parent().unwrap()).unwrap().uid()
    );
    let mut out: Export = Export {
        root: selected.root.clone(),
        records: BTreeMap::new(),
        bytes: 0,
    };
    out.put("manifest.bin", manifest);
    assert!(flags.len().is_multiple_of(2));
    let mut directories: BTreeMap<&str, &str> = BTreeMap::new();
    let mut suites: Vec<&str> = Vec::new();
    for pair in flags.chunks_exact(2) {
        let role: Option<&str> = match pair[0].as_str() {
            "--successor-plan-history-dir" => Some("plan-history"),
            "--successor-cut-dir" => Some("cut"),
            "--successor-manifest-history-dir" => Some("manifest-history"),
            "--successor-certificate-dir" => Some("certificate"),
            "--suite" => {
                suites.push(&pair[1]);
                None
            }
            _ => None,
        };
        if let Some(role) = role {
            assert!(
                directories.insert(role, &pair[1]).is_none(),
                "first-successor profile requires exactly one complete link"
            );
        }
    }
    assert_eq!(directories.len(), 4);
    for (role, original) in &directories {
        out.archive(role, Path::new(original));
    }
    let current: &PublicationContext = workflow.expected_context();
    let mut pins: String = format!(
        "profile=positive-first-successor-v1\nchain={}\nprotocol={}\ngenesis_epoch={}\nexecution_epoch={}\ngenesis_digest={}\ndomain={}\nclaimant={}\nvalidator={}\ncertificate_epoch={}\nhash_suite_id={}\ncheckpoint={}\n",
        current.chain_id(),
        current.protocol_version().get(),
        workflow.genesis_root().genesis_context().epoch().get(),
        current.epoch().get(),
        super::super::hex(&manifest_digest),
        super::super::hex(workflow.ordered_policy().domain().as_bytes()),
        super::super::hex(&cases[0].request.claimant_public_key),
        cases[0].request.validator_id,
        cases[0].intent.certificate_epoch.get(),
        resolver.suite_for_epoch(current.epoch()).unwrap().id.get(),
        super::HOST_CHECKPOINT
    );
    for suite in &suites {
        assert!(!suite.contains(['\n', '\r', '\t']));
        pins.push_str(&format!("suite={suite}\n"));
    }
    assert!(!suites.is_empty());
    out.put("pins.txt", pins.as_bytes());
    for case in cases {
        let leg: &[u8] = case.request.signed_leg.as_deref().unwrap();
        let decoded: execution::local_execution::SignedLocalExecutionIntent =
            execution::local_execution::decode_signed_local_execution(leg).unwrap();
        let params: String = format!(
            "request={}\nescrow={}\namount={}\nrecipient={}\nnonce={}\ngas={}\nhash_epoch={}\n",
            super::super::hex(&case.request.request_id),
            super::super::hex(&case.request.escrow_request_id),
            case.intent.share_amount,
            case.request.recipient,
            decoded.intent.call.nonce,
            decoded.intent.call.gas_limit,
            current.epoch().get()
        );
        let prefix: String = format!("cases/{}", case.label);
        for (name, bytes) in [
            ("params.txt", params.into_bytes()),
            ("fee-object.bin", fee_object.to_vec()),
            (
                "fee-ref.bin",
                objects::encode_object_ref(&case.intent.expected_fee_output).unwrap(),
            ),
            ("signed-leg.bin", leg.to_vec()),
            ("host-request.bin", case.request.encode().unwrap()),
            (
                "host-intent.bin",
                encode_fee_claim_intent(&case.intent).unwrap(),
            ),
            ("signed-outer.bin", case.signed_outer.clone()),
            ("candidate.bin", case.candidate.clone()),
        ] {
            out.put(&format!("{prefix}/{name}"), &bytes);
        }
    }
    let link: SuccessorArtifactDirectories<'_> = SuccessorArtifactDirectories {
        plan_history: &out.root.join("plan-history"),
        cut: &out.root.join("cut"),
        manifest_history: &out.root.join("manifest-history"),
        certificate: &out.root.join("certificate"),
    };
    let verified: SuccessorWorkflowAuthority = load_successor_chain_workflow_from_directories(
        &out.root.join("manifest.bin"),
        resolver,
        manifest_digest,
        workflow.genesis_root().genesis_context(),
        workflow.ordered_policy().domain(),
        &[link],
        SuccessorChainBudget::new(std::num::NonZeroU32::new(1).unwrap()),
    )
    .unwrap();
    assert_eq!(verified.expected_context(), current);
    assert_eq!(
        verified.genesis_root().digest(),
        workflow.genesis_root().digest()
    );
    assert_eq!(
        verified.ordered_policy().anchor(),
        workflow.ordered_policy().anchor()
    );
    for case in cases {
        sunrise_edge_client::verify_prepared_fee_claim(&verified, &case.request, &case.intent)
            .unwrap();
    }
    let mut inventory: String = String::new();
    for (name, (length, hash)) in &out.records {
        inventory.push_str(&format!("{name}\t{length}\t{hash}\n"));
    }
    assert!(inventory.len() <= 256 * 1024);
    out.put("files.tsv", inventory.as_bytes());
    File::open(&out.root).unwrap().sync_all().unwrap();
    let script: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/check-docker-positive-fee-split-fixture-1017.mjs");
    assert_eq!(
        digest(&read(&selected.node, 256 * 1024 * 1024)),
        selected.node_sha
    );
    assert_eq!(
        digest(&read(&selected.provenance, 256 * 1024)),
        selected.provenance_sha
    );
    let mut command: Command = Command::new(&selected.node);
    command.arg(script).args([
        "--public-index",
        out.root.join("files.tsv").to_str().unwrap(),
        "--public-index-sha256",
        &digest(inventory.as_bytes()),
        "--provenance-index",
        selected.provenance.to_str().unwrap(),
        "--provenance-index-sha256",
        &selected.provenance_sha,
    ]);
    command
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("LANG", "C.UTF-8");
    let output: Output = super::super::compiled_source_host_process::spawn_strict_bounded_output(
        command,
        Duration::from_secs(300),
    );
    assert!(
        output.status.success(),
        "selected positive UID fixture failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text: String = String::from_utf8(output.stdout).unwrap();
    print!("{text}");
    assert!(
        text.lines()
            .any(|line| line == "positive_fee_split_uid_lifecycle=passed")
    );
    let candidates: Vec<&str> = text
        .lines()
        .filter_map(|line| line.strip_prefix("positive_fee_split_candidate="))
        .collect();
    assert_eq!(candidates.len(), 1);
    let encoded: &str = candidates[0];
    assert!(encoded.len() <= 2 * FILE_BYTES && encoded.len().is_multiple_of(2));
    let bytes: Vec<u8> = encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair: &[u8]| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    assert_eq!(bytes, cases[0].candidate);
    for (name, (length, hash)) in &out.records {
        let bytes: Vec<u8> = read(&out.root.join(name), FILE_BYTES);
        assert_eq!(bytes.len(), *length);
        assert_eq!(digest(&bytes), *hash);
    }
    bytes
}
