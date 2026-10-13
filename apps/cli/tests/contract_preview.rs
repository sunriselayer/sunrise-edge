//! Exercise the actual compiled CLI binary's `contract preview` action: it
//! must never contact a node or signer, never submit, and must refuse
//! outright (with empty stdout) rather than print a partial review.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use sunrise_edge_client::{
    ArtifactParts, ChainId, CodeArtifact, Digest32, Epoch, ExpectedProtocolContext,
    HashSuiteResolver, LocalSigner, PackageOrigin, PreparedPublication, ProtocolVersion,
    PublicationContext, local_publication_profile_semantics, local_publication_resolver,
};

// Stable core-WASM binary: defined bounded memory and an empty () -> () run.
const VALID_WASM: &[u8] = b"\0asm\x01\0\0\0\x01\x04\x01\x60\0\0\x03\x02\x01\0\x05\x04\x01\x01\x01\x02\x07\x10\x02\x06memory\x02\0\x03run\0\0\x0a\x04\x01\x02\0\x0b";
const VALID_ABI: &[u8] = b"opaque-abi";
static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    wasm: PathBuf,
    abi: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let sequence: u64 = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!(
            "sunrise-contract-preview-{}-{sequence}",
            std::process::id()
        ));
        let wasm = base.with_extension("wasm");
        let abi = base.with_extension("abi");
        fs::write(&wasm, VALID_WASM).unwrap();
        fs::write(&abi, VALID_ABI).unwrap();
        Self { wasm, abi }
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
        "02".repeat(32),
    ]
}

fn run_preview(extra: &[String]) -> Output {
    let mut args: Vec<String> = vec!["contract".into(), "preview".into()];
    args.extend(extra.iter().cloned());
    Command::new(env!("CARGO_BIN_EXE_sunrise-edge-cli"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn preview_prints_every_material_field_without_network_or_signer_flags() {
    let fixture = Fixture::new();
    let publisher: LocalSigner = LocalSigner::from_seed([7; 32]);
    let publisher_hex: String = publisher.address().to_string();
    let mut args = base_flags(&publisher_hex);
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
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).unwrap();

    // Independent oracle: built from the same flags, through the library
    // directly, in this test process rather than the spawned binary.
    let resolver: HashSuiteResolver = local_publication_resolver(&expected()).unwrap();
    let context: PublicationContext = PublicationContext::new(
        expected().chain_id().clone(),
        expected().protocol_version(),
        expected().epoch(),
    )
    .unwrap();
    let semantics: Digest32 = local_publication_profile_semantics(&resolver, &context).unwrap();
    let artifact: CodeArtifact = CodeArtifact::new(ArtifactParts {
        context,
        origin: PackageOrigin::unverified(
            expected().chain_id().clone(),
            *publisher.address().as_bytes(),
            [2; 32],
        )
        .unwrap(),
        revision: 1,
        wasm_profile: 1,
        semantics,
        wasm: VALID_WASM.to_vec(),
        unverified_abi: VALID_ABI.to_vec(),
        exports: vec!["run".to_owned()],
        unverified_dependencies: vec![],
    })
    .unwrap();
    let prepared: PreparedPublication = PreparedPublication::prepare(
        publisher.address(),
        &resolver,
        &expected(),
        artifact,
        5,
        sunrise_edge_client::RequestId::new([9; 32]).unwrap(),
    )
    .unwrap();

    assert_eq!(stdout, format!(
        "preview=true\npublished=false\npublisher={publisher_hex}\nchain_id=preview-e2e\nprotocol_version=1\nepoch=0\nrevision=1\nwasm_profile=1\nwasm_profile_name=publication-only\nwasm_bytes={}\nabi_bytes={}\nsemantics={}\nartifact_digest={}\nexport_count=1\nexport[0]=run\ndependency_count=0\nnonce=5\nrequest_id={}\nsignable_frame_bytes={}\n",
        VALID_WASM.len(),
        VALID_ABI.len(),
        prepared.semantics(),
        prepared.artifact_digest(),
        "09".repeat(32),
        prepared.signable_frame().len(),
    ));
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
    let fixture = Fixture::new();
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
fn preview_refuses_an_export_name_containing_control_bytes_with_empty_stdout() {
    let fixture = Fixture::new();
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
    for args in [vec!["contract", "preview"], vec!["contract", "preview", "--wasm"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_sunrise-edge-cli"))
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
}
