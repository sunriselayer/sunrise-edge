//! Exercise the actual compiled CLI binary's `contract preview` action: it
//! must never contact a node or signer, never submit, and must refuse
//! outright (with empty stdout) rather than print a partial review.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use abi::call_values::{CallAbi, ValueLayout};
use abi::executable_abi::{ExecutableAbi, encode_executable_abi};
use abi::public_abi::{EntrypointDeclaration, PackageAbi};
use sunrise_edge_client::{
    Address, ArtifactParts, ChainId, CodeArtifact, Digest32, Epoch, ExpectedProtocolContext,
    HashAlgorithmId, HashSuiteResolver, LocalSigner, PackageOrigin, PreparedPublication,
    ProtocolVersion, PublicationContext, PublicationReview, RequestId, UnverifiedDependencyRef,
    local_execution, local_publication_profile_semantics, local_publication_resolver,
};

// Stable core-WASM binary: defined bounded memory and an empty () -> () run.
const VALID_WASM: &[u8] = b"\0asm\x01\0\0\0\x01\x04\x01\x60\0\0\x03\x02\x01\0\x05\x04\x01\x01\x01\x02\x07\x10\x02\x06memory\x02\0\x03run\0\0\x0a\x04\x01\x02\0\x0b";
const BARE_ABI: &[u8] = b"opaque-abi";
static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

fn next_path(suffix: &str) -> PathBuf {
    let sequence: u64 = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "sunrise-contract-preview-{}-{sequence}.{suffix}",
        std::process::id()
    ))
}

struct Fixture {
    wasm: PathBuf,
    abi: PathBuf,
}

impl Fixture {
    fn new(abi: &[u8]) -> Self {
        let wasm: PathBuf = next_path("wasm");
        let abi_path: PathBuf = next_path("abi");
        fs::write(&wasm, VALID_WASM).unwrap();
        fs::write(&abi_path, abi).unwrap();
        Self {
            wasm,
            abi: abi_path,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.wasm);
        let _ = fs::remove_file(&self.abi);
    }
}

fn expected() -> ExpectedProtocolContext {
    ExpectedProtocolContext::new(
        ChainId::new("preview-e2e").unwrap(),
        ProtocolVersion::new(1),
        Epoch::new(0),
        sunrise_edge_client::HashSuiteId::new(1),
        2,
        1,
        2,
        sunrise_edge_client::AtomicityDomainId::new([6; 32]).unwrap(),
    )
    .unwrap()
}

fn origin_seed() -> [u8; 32] {
    [2; 32]
}

/// Minimal valid `ExecutableAbi` bytes for one `run` entrypoint, required by
/// `--executable`/`--general-calls` (the bare profile accepts any opaque
/// non-empty bytes instead).
fn executable_abi_bytes(origin: PackageOrigin) -> Vec<u8> {
    let call = CallAbi {
        objects: PackageAbi {
            origin,
            constructors: vec![],
            entrypoints: vec![EntrypointDeclaration {
                name: "run".into(),
                type_parameters: vec![],
                objects: vec![],
            }],
        },
        arguments: vec![ValueLayout::Tuple(vec![])],
        bodies: vec![],
    };
    encode_executable_abi(&ExecutableAbi {
        call,
        initializer: None,
        transferable_constructors: vec![],
        results: vec![vec![]],
    })
    .unwrap()
}

/// Base flags shared by every invocation in this file.
fn base_flags(publisher: &str) -> Vec<String> {
    vec![
        "--expected-chain-id".into(),
        "preview-e2e".into(),
        "--expected-protocol-version".into(),
        "1".into(),
        "--expected-epoch".into(),
        "0".into(),
        "--expected-hash-suite-id".into(),
        "1".into(),
        "--expected-domain".into(),
        "06".repeat(32),
        "--publisher".into(),
        publisher.to_owned(),
        "--origin-seed".into(),
        hex(&origin_seed()),
    ]
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn run_preview(extra: &[String]) -> Output {
    let mut args: Vec<String> = vec!["contract".into(), "preview".into()];
    args.extend(extra.iter().cloned());
    Command::new(env!("CARGO_BIN_EXE_sunrise-edge-cli"))
        .args(args)
        .output()
        .unwrap()
}

/// Independent oracle: builds the same review through the library directly,
/// in this test process, rather than the spawned binary subprocess.
#[allow(clippy::too_many_arguments)]
fn expected_output(
    publisher: Address,
    wasm_profile: u32,
    wasm: &[u8],
    abi: &[u8],
    exports: Vec<String>,
    dependencies: Vec<UnverifiedDependencyRef>,
    request_id: [u8; 32],
    nonce: u64,
) -> String {
    let expected: ExpectedProtocolContext = expected();
    let resolver: HashSuiteResolver = local_publication_resolver(&expected).unwrap();
    let context: PublicationContext = PublicationContext::new(
        expected.chain_id().clone(),
        expected.protocol_version(),
        expected.epoch(),
    )
    .unwrap();
    let semantics: Digest32 = match wasm_profile {
        2 => local_execution::local_execution_semantics(&resolver, &context).unwrap(),
        3 => local_execution::general_execution_semantics(&resolver, &context).unwrap(),
        _ => local_publication_profile_semantics(&resolver, &context).unwrap(),
    };
    let artifact: CodeArtifact = CodeArtifact::new(ArtifactParts {
        context,
        origin: PackageOrigin::unverified(
            expected.chain_id().clone(),
            *publisher.as_bytes(),
            origin_seed(),
        )
        .unwrap(),
        revision: 1,
        wasm_profile,
        semantics,
        wasm: wasm.to_vec(),
        unverified_abi: abi.to_vec(),
        exports,
        unverified_dependencies: dependencies,
    })
    .unwrap();
    let prepared: PreparedPublication = PreparedPublication::prepare(
        publisher,
        &resolver,
        &expected,
        artifact,
        nonce,
        RequestId::new(request_id).unwrap(),
    )
    .unwrap();
    let review: PublicationReview = PublicationReview::build(&prepared).unwrap();
    format!("preview=true\npublished=false\n{}", review.render())
}

#[test]
fn preview_matches_the_independent_oracle_for_bare_typed_and_general_profiles() {
    let publisher: LocalSigner = LocalSigner::from_seed([7; 32]);
    let origin: PackageOrigin = PackageOrigin::unverified(
        ChainId::new("preview-e2e").unwrap(),
        *publisher.address().as_bytes(),
        origin_seed(),
    )
    .unwrap();
    let executable_abi: Vec<u8> = executable_abi_bytes(origin);
    let cases: [(u32, &[u8], Option<&str>); 3] = [
        (1, BARE_ABI, None),
        (2, executable_abi.as_slice(), Some("--executable")),
        (3, executable_abi.as_slice(), Some("--general-calls")),
    ];
    for (profile, abi_bytes, profile_flag) in cases {
        let fixture = Fixture::new(abi_bytes);
        let mut args = base_flags(&publisher.address().to_string());
        if let Some(flag) = profile_flag {
            args.push(flag.to_owned());
        }
        args.extend([
            "--wasm".into(),
            fixture.wasm.display().to_string(),
            "--abi".into(),
            fixture.abi.display().to_string(),
            "--entrypoints".into(),
            "run".into(),
            "--request-id".into(),
            "09".repeat(32),
            "--nonce".into(),
            "5".into(),
        ]);
        let output = run_preview(&args);
        assert!(
            output.status.success(),
            "profile {profile}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        let stdout = String::from_utf8(output.stdout).unwrap();
        let expected_text = expected_output(
            publisher.address(),
            profile,
            VALID_WASM,
            abi_bytes,
            vec!["run".to_owned()],
            vec![],
            [9; 32],
            5,
        );
        assert_eq!(stdout, expected_text, "profile {profile}");
    }
}

#[test]
fn preview_prints_a_supplied_dependency_reference() {
    let fixture = Fixture::new(BARE_ABI);
    let publisher: LocalSigner = LocalSigner::from_seed([7; 32]);
    let dependency = UnverifiedDependencyRef::new(
        PackageOrigin::unverified(ChainId::new("preview-e2e").unwrap(), [40; 32], [1; 32]).unwrap(),
        1,
        PublicationContext::new(
            expected().chain_id().clone(),
            expected().protocol_version(),
            expected().epoch(),
        )
        .unwrap(),
        Digest32::new(HashAlgorithmId::Sha2_256, [0x55; 32]),
    )
    .unwrap();
    let dependency_path: PathBuf = next_path("dep");
    fs::write(
        &dependency_path,
        sunrise_edge_client::publication::encode_dependency_ref(&dependency).unwrap(),
    )
    .unwrap();

    let mut args = base_flags(&publisher.address().to_string());
    args.extend([
        "--wasm".into(),
        fixture.wasm.display().to_string(),
        "--abi".into(),
        fixture.abi.display().to_string(),
        "--entrypoints".into(),
        "run".into(),
        "--dependencies".into(),
        dependency_path.display().to_string(),
        "--request-id".into(),
        "09".repeat(32),
        "--nonce".into(),
        "5".into(),
    ]);
    let output = run_preview(&args);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let expected_text = expected_output(
        publisher.address(),
        1,
        VALID_WASM,
        BARE_ABI,
        vec!["run".to_owned()],
        vec![dependency],
        [9; 32],
        5,
    );
    assert_eq!(stdout, expected_text);
    assert!(stdout.contains("dependency_count=1"));
    assert!(stdout.contains(&format!("dependency[0].publisher={}", hex(&[40; 32]))));
    let _ = fs::remove_file(&dependency_path);
}

#[test]
fn preview_rejects_network_and_signer_flags_as_unknown() {
    for flag in ["--endpoint", "--seed-file", "--ledger-hid-path"] {
        let output = run_preview(&[flag.to_owned(), "unused".to_owned()]);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("unknown flag")
        );
    }
}

#[test]
fn preview_requires_an_explicit_nonce_and_refuses_with_empty_stdout() {
    let fixture = Fixture::new(BARE_ABI);
    let publisher: LocalSigner = LocalSigner::from_seed([7; 32]);
    let mut args = base_flags(&publisher.address().to_string());
    args.extend([
        "--wasm".into(),
        fixture.wasm.display().to_string(),
        "--abi".into(),
        fixture.abi.display().to_string(),
        "--entrypoints".into(),
        "run".into(),
        "--request-id".into(),
        "09".repeat(32),
    ]);
    let output = run_preview(&args);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .starts_with("error=")
    );
}

#[test]
fn preview_rejects_malformed_nonce_publisher_and_origin_seed_with_empty_stdout() {
    let fixture = Fixture::new(BARE_ABI);
    let publisher: LocalSigner = LocalSigner::from_seed([7; 32]);
    let common = |nonce: &str, publisher_flag: &str, origin_seed_flag: &str| -> Vec<String> {
        vec![
            "--expected-chain-id".into(),
            "preview-e2e".into(),
            "--expected-protocol-version".into(),
            "1".into(),
            "--expected-epoch".into(),
            "0".into(),
            "--expected-hash-suite-id".into(),
            "1".into(),
            "--expected-domain".into(),
            "06".repeat(32),
            "--publisher".into(),
            publisher_flag.to_owned(),
            "--origin-seed".into(),
            origin_seed_flag.to_owned(),
            "--wasm".into(),
            fixture.wasm.display().to_string(),
            "--abi".into(),
            fixture.abi.display().to_string(),
            "--entrypoints".into(),
            "run".into(),
            "--request-id".into(),
            "09".repeat(32),
            "--nonce".into(),
            nonce.to_owned(),
        ]
    };
    let good_publisher: String = publisher.address().to_string();
    let good_seed: String = hex(&origin_seed());
    let wrong_length_seed: String = "ab".to_owned();
    let wrong_charset_seed: String = "g".repeat(64);
    let cases: [(&str, &str, &str); 4] = [
        ("not-a-number", &good_publisher, &good_seed),
        ("5", "zz", &good_seed),
        ("5", &good_publisher, &wrong_length_seed),
        ("5", &good_publisher, &wrong_charset_seed),
    ];
    for (nonce, publisher_flag, origin_seed_flag) in cases {
        let output = run_preview(&common(nonce, publisher_flag, origin_seed_flag));
        assert!(
            !output.status.success(),
            "{nonce} {publisher_flag} {origin_seed_flag}"
        );
        assert!(output.stdout.is_empty());
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .starts_with("error=")
        );
    }
}

#[test]
fn preview_refuses_an_export_name_containing_control_bytes_with_empty_stdout() {
    let fixture = Fixture::new(BARE_ABI);
    let publisher: LocalSigner = LocalSigner::from_seed([7; 32]);
    let mut args = base_flags(&publisher.address().to_string());
    args.extend([
        "--wasm".into(),
        fixture.wasm.display().to_string(),
        "--abi".into(),
        fixture.abi.display().to_string(),
        "--entrypoints".into(),
        "evil\u{1b}bad".into(),
        "--request-id".into(),
        "09".repeat(32),
        "--nonce".into(),
        "5".into(),
    ]);
    let output = run_preview(&args);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .starts_with("error=")
    );
}

#[test]
fn preview_requires_explicit_supported_flags() {
    for args in [
        vec!["contract", "preview"],
        vec!["contract", "preview", "--wasm"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_sunrise-edge-cli"))
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn preview_exports_exact_private_preimage_and_refuses_overwrite_or_lax_parent() {
    use std::os::unix::fs::PermissionsExt;
    let fixture: Fixture = Fixture::new(BARE_ABI);
    let publisher: LocalSigner = LocalSigner::from_seed([7; 32]);
    let directory: PathBuf = next_path("private");
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let artifact_path: PathBuf = directory.join("artifact.bin");
    let mut args: Vec<String> = base_flags(&publisher.address().to_string());
    args.extend([
        "--wasm".into(),
        fixture.wasm.display().to_string(),
        "--abi".into(),
        fixture.abi.display().to_string(),
        "--entrypoints".into(),
        "run".into(),
        "--request-id".into(),
        "09".repeat(32),
        "--nonce".into(),
        "5".into(),
        "--artifact-out".into(),
        artifact_path.display().to_string(),
    ]);
    let output: Output = run_preview(&args);
    assert!(output.status.success(), "{:?}", output.stderr);
    let bytes: Vec<u8> = fs::read(&artifact_path).unwrap();
    let artifact: CodeArtifact =
        sunrise_edge_client::publication::decode_code_artifact(&bytes).unwrap();
    assert_eq!(artifact.wasm(), VALID_WASM);
    assert_eq!(artifact.unverified_abi(), BARE_ABI);
    assert_eq!(
        artifact.origin().publisher(),
        publisher.address().as_bytes()
    );
    assert_eq!(
        bytes,
        sunrise_edge_client::publication::encode_code_artifact(&artifact).unwrap()
    );
    assert_eq!(
        fs::metadata(&artifact_path).unwrap().permissions().mode() & 0o7777,
        0o600
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        expected_output(
            publisher.address(),
            1,
            VALID_WASM,
            BARE_ABI,
            vec!["run".into()],
            vec![],
            [9; 32],
            5,
        )
    );
    let overwrite: Output = run_preview(&args);
    assert!(!overwrite.status.success());
    assert!(overwrite.stdout.is_empty());
    assert_eq!(fs::read(&artifact_path).unwrap(), bytes);
    fs::remove_file(&artifact_path).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
    let lax_parent: Output = run_preview(&args);
    assert!(!lax_parent.status.success());
    assert!(lax_parent.stdout.is_empty());
    assert!(!artifact_path.exists());
    fs::remove_dir(&directory).unwrap();
}
