//! Independent-input coverage for the bounded, non-authorizing publication
//! review surface. Every oracle value here is computed independently of
//! `PublicationReview`'s own internals: hex strings are rendered with a
//! local `hex` helper (never `Digest32`/`Address` `Display`), and semantics
//! digests are recomputed by directly calling the same production profile
//! functions `PublicationReview::build` calls, from a separate call site,
//! against artifacts this file constructs on its own.

use execution::{GENERAL_CONTRACT_WASM_PROFILE_VERSION, TYPED_CONTRACT_WASM_PROFILE_VERSION};
use sunrise_edge_client::*;

const WASM_HEX: &str = "0061736d0100000001040160000003020100050401010102071002066d656d6f727902000372756e00000a040102000b";

fn wasm_bytes() -> Vec<u8> {
    (0..WASM_HEX.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&WASM_HEX[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn expected() -> ExpectedProtocolContext {
    ExpectedProtocolContext::new(
        ChainId::new("review-test").unwrap(),
        ProtocolVersion::new(1),
        Epoch::new(0),
        HashSuiteId::new(1),
        2,
        1,
        2,
        AtomicityDomainId::new([9; 32]).unwrap(),
    )
    .unwrap()
}

fn context() -> PublicationContext {
    let expected: ExpectedProtocolContext = expected();
    PublicationContext::new(
        expected.chain_id().clone(),
        expected.protocol_version(),
        expected.epoch(),
    )
    .unwrap()
}

fn resolver() -> HashSuiteResolver {
    local_publication_resolver(&expected()).unwrap()
}

/// Builds an artifact whose `semantics` is the REAL commitment for `profile`,
/// so `PublicationReview::build` succeeds. Exports/dependencies are supplied
/// independently per call to exercise distinct review snapshots.
fn artifact_with_profile(
    publisher: [u8; 32],
    seed: u8,
    profile: u32,
    exports: Vec<String>,
    dependencies: Vec<UnverifiedDependencyRef>,
) -> CodeArtifact {
    let semantics: Digest32 = match profile {
        TYPED_CONTRACT_WASM_PROFILE_VERSION => {
            local_execution::local_execution_semantics(&resolver(), &context()).unwrap()
        }
        GENERAL_CONTRACT_WASM_PROFILE_VERSION => {
            local_execution::general_execution_semantics(&resolver(), &context()).unwrap()
        }
        GENERIC_OBJECT_RESULT_WASM_PROFILE_VERSION => {
            local_execution::generic_object_result_semantics(&resolver(), &context()).unwrap()
        }
        _ => local_publication_profile_semantics(&resolver(), &context()).unwrap(),
    };
    CodeArtifact::new(ArtifactParts {
        context: context(),
        origin: PackageOrigin::unverified(expected().chain_id().clone(), publisher, [seed; 32])
            .unwrap(),
        revision: 1,
        wasm_profile: profile,
        semantics,
        wasm: wasm_bytes(),
        unverified_abi: b"opaque-abi".to_vec(),
        exports,
        unverified_dependencies: dependencies,
    })
    .unwrap()
}

fn dependency(publisher: [u8; 32], seed: u8, digest_byte: u8) -> UnverifiedDependencyRef {
    UnverifiedDependencyRef::new(
        PackageOrigin::unverified(expected().chain_id().clone(), publisher, [seed; 32]).unwrap(),
        1,
        context(),
        Digest32::new(HashAlgorithmId::Sha2_256, [digest_byte; 32]),
    )
    .unwrap()
}

fn prepare(
    publisher: Address,
    artifact: CodeArtifact,
    nonce: u64,
    request_id: [u8; 32],
) -> PreparedPublication {
    PreparedPublication::prepare(
        publisher,
        &resolver(),
        &expected(),
        artifact,
        nonce,
        RequestId::new(request_id).unwrap(),
    )
    .unwrap()
}

#[test]
fn review_matches_independently_recomputed_fields_for_every_known_profile() {
    let publisher: Address = LocalSigner::from_seed([11; 32]).address();
    let dep: UnverifiedDependencyRef = dependency([22; 32], 5, 0xAB);
    let profiles: [(u32, &str); 4] = [
        (CONTRACT_WASM_ADMISSION_PROFILE_VERSION, "publication-only"),
        (TYPED_CONTRACT_WASM_PROFILE_VERSION, "typed-host-execution"),
        (GENERAL_CONTRACT_WASM_PROFILE_VERSION, "general-execution"),
        (
            GENERIC_OBJECT_RESULT_WASM_PROFILE_VERSION,
            "generic-object-result",
        ),
    ];
    for (profile, name) in profiles {
        let artifact: CodeArtifact = artifact_with_profile(
            *publisher.as_bytes(),
            7,
            profile,
            vec!["alpha".to_owned(), "beta".to_owned()],
            vec![dep.clone()],
        );
        let expected_wasm_bytes_len: usize = wasm_bytes().len();
        let expected_semantics: Digest32 = *artifact.semantics();
        let prepared: PreparedPublication = prepare(publisher, artifact, 42, [9; 32]);
        let review: PublicationReview = PublicationReview::build(&prepared).unwrap();

        assert_eq!(review.publisher_hex(), hex(publisher.as_bytes()));
        assert_eq!(review.chain_id(), "review-test");
        assert_eq!(review.protocol_version(), 1);
        assert_eq!(review.epoch(), 0);
        assert_eq!(review.revision(), 1);
        assert_eq!(review.wasm_profile(), profile);
        assert_eq!(review.wasm_profile_name(), name);
        assert_eq!(review.wasm_bytes_len(), expected_wasm_bytes_len);
        assert_eq!(review.unverified_abi_bytes_len(), b"opaque-abi".len());
        assert_eq!(
            review.semantics_hex(),
            format!(
                "{}:{}",
                format_algorithm(expected_semantics.algorithm()),
                hex(&expected_semantics.bytes())
            )
        );
        assert_eq!(
            review.exports().to_vec(),
            vec!["alpha".to_owned(), "beta".to_owned()]
        );
        assert_eq!(review.dependencies().len(), 1);
        assert_eq!(review.dependencies()[0].chain_id(), "review-test");
        assert_eq!(review.dependencies()[0].publisher_hex(), hex(&[22; 32]));
        assert_eq!(review.dependencies()[0].seed_hex(), hex(&[5; 32]));
        assert_eq!(review.dependencies()[0].revision(), 1);
        assert_eq!(review.dependencies()[0].protocol_version(), 1);
        assert_eq!(review.dependencies()[0].epoch(), 0);
        assert_eq!(review.nonce(), 42);
        assert_eq!(review.request_id_hex(), hex(&[9; 32]));
    }
}

/// Independent oracle for `HashAlgorithmId`'s wire label, matching the one
/// `Digest32`'s own `Display` uses, without calling it.
fn format_algorithm(algorithm: HashAlgorithmId) -> &'static str {
    match algorithm {
        HashAlgorithmId::Sha2_256 => "sha2-256",
        HashAlgorithmId::Sha3_256 => "sha3-256",
        HashAlgorithmId::Blake3_256 => "blake3-256",
    }
}

#[test]
fn review_refuses_semantics_that_do_not_match_the_declared_profile() {
    let publisher: Address = LocalSigner::from_seed([11; 32]).address();
    let mut artifact: CodeArtifact = artifact_with_profile(
        *publisher.as_bytes(),
        7,
        CONTRACT_WASM_ADMISSION_PROFILE_VERSION,
        vec!["run".to_owned()],
        vec![],
    );
    // Rebuild with a semantics value that does not match the real profile
    // commitment; `CodeArtifact::new` does not itself authenticate semantics.
    artifact = CodeArtifact::new(ArtifactParts {
        context: context(),
        origin: artifact.origin().clone(),
        revision: artifact.revision(),
        wasm_profile: artifact.wasm_profile(),
        semantics: Digest32::new(HashAlgorithmId::Sha2_256, [0x66; 32]),
        wasm: artifact.wasm().to_vec(),
        unverified_abi: artifact.unverified_abi().to_vec(),
        exports: artifact.exports().to_vec(),
        unverified_dependencies: artifact.unverified_dependencies().to_vec(),
    })
    .unwrap();
    let prepared: PreparedPublication = prepare(publisher, artifact, 1, [3; 32]);
    let error = PublicationReview::build(&prepared).unwrap_err();
    assert!(matches!(error, PublicationReviewError::SemanticsMismatch));
}

#[test]
fn review_refuses_an_export_name_containing_control_bytes() {
    let publisher: Address = LocalSigner::from_seed([11; 32]).address();
    let artifact: CodeArtifact = artifact_with_profile(
        *publisher.as_bytes(),
        7,
        CONTRACT_WASM_ADMISSION_PROFILE_VERSION,
        vec!["evil\u{1b}[31m".to_owned()],
        vec![],
    );
    let prepared: PreparedPublication = prepare(publisher, artifact, 1, [3; 32]);
    let error = PublicationReview::build(&prepared).unwrap_err();
    assert!(matches!(
        error,
        PublicationReviewError::UndisplayableField("export")
    ));
}

#[test]
fn review_refuses_a_context_chain_id_containing_control_bytes() {
    let bad_expected: ExpectedProtocolContext = ExpectedProtocolContext::new(
        ChainId::new("bad\u{7}chain").unwrap(),
        ProtocolVersion::new(1),
        Epoch::new(0),
        HashSuiteId::new(1),
        2,
        1,
        2,
        AtomicityDomainId::new([9; 32]).unwrap(),
    )
    .unwrap();
    let bad_resolver: HashSuiteResolver = local_publication_resolver(&bad_expected).unwrap();
    let bad_context: PublicationContext = PublicationContext::new(
        bad_expected.chain_id().clone(),
        bad_expected.protocol_version(),
        bad_expected.epoch(),
    )
    .unwrap();
    let publisher: Address = LocalSigner::from_seed([11; 32]).address();
    let semantics: Digest32 =
        local_publication_profile_semantics(&bad_resolver, &bad_context).unwrap();
    let artifact: CodeArtifact = CodeArtifact::new(ArtifactParts {
        context: bad_context,
        origin: PackageOrigin::unverified(
            bad_expected.chain_id().clone(),
            *publisher.as_bytes(),
            [7; 32],
        )
        .unwrap(),
        revision: 1,
        wasm_profile: CONTRACT_WASM_ADMISSION_PROFILE_VERSION,
        semantics,
        wasm: wasm_bytes(),
        unverified_abi: b"opaque-abi".to_vec(),
        exports: vec!["run".to_owned()],
        unverified_dependencies: vec![],
    })
    .unwrap();
    let prepared: PreparedPublication = PreparedPublication::prepare(
        publisher,
        &bad_resolver,
        &bad_expected,
        artifact,
        1,
        RequestId::new([3; 32]).unwrap(),
    )
    .unwrap();
    let error = PublicationReview::build(&prepared).unwrap_err();
    assert!(matches!(
        error,
        PublicationReviewError::UndisplayableField("context.chain_id")
    ));
}

#[test]
fn review_never_signs_contacts_a_signer_or_requires_any_signer_type() {
    // A review is built from a `PreparedPublication` alone; nothing here
    // constructs, names, or passes any signer/seed/transport type, and the
    // resulting `PublicationReview` carries no signature or submission API.
    let publisher: Address = LocalSigner::from_seed([11; 32]).address();
    let artifact: CodeArtifact = artifact_with_profile(
        *publisher.as_bytes(),
        7,
        CONTRACT_WASM_ADMISSION_PROFILE_VERSION,
        vec!["run".to_owned()],
        vec![],
    );
    let prepared: PreparedPublication = prepare(publisher, artifact, 1, [3; 32]);
    let review: PublicationReview = PublicationReview::build(&prepared).unwrap();
    assert_eq!(review.nonce(), 1);
}
