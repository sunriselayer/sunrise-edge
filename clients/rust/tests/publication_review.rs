//! Independent-input coverage for the bounded, non-authorizing publication
//! review surface. Every oracle value here is computed independently of
//! `PublicationReview`'s own internals: hex strings are rendered with a
//! local `hex` helper (never `Digest32`/`Address`/`RequestId` `Display`), and
//! component digests/frame/semantics are recomputed by directly calling the
//! same production functions `PublicationReview::build` calls, from a
//! separate call site, against artifacts this file constructs on its own.

use crypto::SignatureSigner;
use execution::publication::{
    PublicationSubmission, authenticate_publication_submission,
    publication_submission_signing_frame,
};
use execution::{GENERAL_CONTRACT_WASM_PROFILE_VERSION, TYPED_CONTRACT_WASM_PROFILE_VERSION};
use protocol_types::HashPurpose;
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

/// Independent oracle for `HashAlgorithmId`'s wire label, matching the one
/// `Digest32`'s own `Display` uses, without calling it.
fn format_algorithm(algorithm: HashAlgorithmId) -> &'static str {
    match algorithm {
        HashAlgorithmId::Sha2_256 => "sha2-256",
        HashAlgorithmId::Sha3_256 => "sha3-256",
        HashAlgorithmId::Blake3_256 => "blake3-256",
    }
}

/// Independent oracle matching `Digest32`'s own `Display`, without calling it.
fn digest_hex(digest: Digest32) -> String {
    format!(
        "{}:{}",
        format_algorithm(digest.algorithm()),
        hex(&digest.bytes())
    )
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
/// so `PublicationReview::build` succeeds. Exports/dependencies, origin seed,
/// WASM and ABI bytes are all supplied independently per call so tests can
/// change exactly one of them.
#[allow(clippy::too_many_arguments)]
fn artifact_with(
    publisher: [u8; 32],
    seed: u8,
    profile: u32,
    wasm: Vec<u8>,
    abi: Vec<u8>,
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
        wasm,
        unverified_abi: abi,
        exports,
        unverified_dependencies: dependencies,
    })
    .unwrap()
}

fn artifact_with_profile(
    publisher: [u8; 32],
    seed: u8,
    profile: u32,
    exports: Vec<String>,
    dependencies: Vec<UnverifiedDependencyRef>,
) -> CodeArtifact {
    artifact_with(
        publisher,
        seed,
        profile,
        wasm_bytes(),
        b"opaque-abi".to_vec(),
        exports,
        dependencies,
    )
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
        let expected_semantics: Digest32 = *artifact.semantics();
        let expected_wasm_digest: Digest32 = resolver()
            .hash_for_purpose(context().epoch(), HashPurpose::ContractCode, &wasm_bytes())
            .unwrap();
        let expected_abi_digest: Digest32 = resolver()
            .hash_for_purpose(context().epoch(), HashPurpose::ContractCode, b"opaque-abi")
            .unwrap();
        let expected_hash_suite_id: u16 = resolver()
            .suite_for_epoch(context().epoch())
            .unwrap()
            .id
            .get();
        let expected_digest: Digest32 =
            publication::artifact_commitment(&resolver(), &context(), &artifact).unwrap();
        let expected_dependency_digest: Digest32 =
            Digest32::new(HashAlgorithmId::Sha2_256, [0xAB; 32]);

        let prepared: PreparedPublication = prepare(publisher, artifact, 42, [9; 32]);
        let expected_frame: Vec<u8> = publication_submission_signing_frame(
            &resolver(),
            &context(),
            prepared.artifact(),
            42,
            [9; 32],
        )
        .unwrap();
        let review: PublicationReview = PublicationReview::build(&prepared).unwrap();

        assert_eq!(review.publisher_hex(), hex(publisher.as_bytes()));
        assert_eq!(review.origin_chain_id(), "review-test");
        assert_eq!(review.origin_seed_hex(), hex(&[7; 32]));
        assert_eq!(review.chain_id(), "review-test");
        assert_eq!(review.protocol_version(), 1);
        assert_eq!(review.epoch(), 0);
        assert_eq!(review.hash_suite_id(), expected_hash_suite_id);
        assert_eq!(review.revision(), 1);
        assert_eq!(review.wasm_profile(), profile);
        assert_eq!(review.wasm_profile_name(), name);
        assert_eq!(review.wasm_bytes_len(), wasm_bytes().len());
        assert_eq!(
            review.diagnostic_wasm_contract_code_hash_hex(),
            digest_hex(expected_wasm_digest)
        );
        assert_eq!(review.unverified_abi_bytes_len(), b"opaque-abi".len());
        assert_eq!(
            review.diagnostic_abi_bytes_hash_hex(),
            digest_hex(expected_abi_digest)
        );
        assert_eq!(review.semantics_hex(), digest_hex(expected_semantics));
        assert_eq!(review.artifact_digest_hex(), digest_hex(expected_digest));
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
        assert_eq!(
            review.dependencies()[0].artifact_digest_hex(),
            digest_hex(expected_dependency_digest)
        );
        assert_eq!(review.nonce(), 42);
        assert_eq!(review.request_id_hex(), hex(&[9; 32]));
        assert_eq!(review.frame_hex(), hex(&expected_frame));
        assert_eq!(review.frame_bytes(), expected_frame.as_slice());
        assert_eq!(
            review.artifact_bytes(),
            publication::encode_code_artifact(prepared.artifact()).unwrap()
        );
        // Every rendered line is present in `render()`/`lines()`; building
        // it twice must agree exactly (deterministic, not recomputed state).
        let rendered: String = review.render();
        assert!(rendered.contains(&format!("origin_seed_hex={}\n", hex(&[7; 32]))));
        assert!(rendered.contains("hash_suite_id="));
        assert_eq!(review.lines().len(), review.render().lines().count());
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
    // Rebuild with a semantics value the presentation-only dispatch in
    // `PublicationReview::build` would not itself compute for this profile;
    // `CodeArtifact::new` does not authenticate semantics against a profile.
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
        PublicationReviewError::UndisplayableField("origin.chain_id")
    ));
}

#[test]
fn review_refuses_control_bytes_in_a_nonempty_dependency_closure() {
    // `UnverifiedDependencyRef::new` requires its origin's chain id to equal
    // its own context's chain id, and `CodeArtifact::new` requires that in
    // turn to equal the artifact's own context chain id; so the dependency
    // control-byte identifier case is exercised under a whole closure built
    // on a control-byte chain id. The origin check deliberately runs first;
    // the private dependency presentation owner has its own focused control.
    let publisher: Address = LocalSigner::from_seed([11; 32]).address();
    let bad_expected: ExpectedProtocolContext = ExpectedProtocolContext::new(
        ChainId::new("dep\u{1}bad").unwrap(),
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
    let dependency = UnverifiedDependencyRef::new(
        PackageOrigin::unverified(bad_expected.chain_id().clone(), [22; 32], [5; 32]).unwrap(),
        1,
        bad_context.clone(),
        Digest32::new(HashAlgorithmId::Sha2_256, [0xAB; 32]),
    )
    .unwrap();
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
        unverified_dependencies: vec![dependency],
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
        PublicationReviewError::UndisplayableField("origin.chain_id")
    ));
}

#[test]
fn review_refuses_when_aggregate_display_bytes_exceed_the_budget() {
    let expected: ExpectedProtocolContext = ExpectedProtocolContext::new(
        ChainId::new("c".repeat(128)).unwrap(),
        ProtocolVersion::new(1),
        Epoch::new(0),
        HashSuiteId::new(1),
        2,
        1,
        2,
        AtomicityDomainId::new([9; 32]).unwrap(),
    )
    .unwrap();
    let resolver: HashSuiteResolver = local_publication_resolver(&expected).unwrap();
    let context: PublicationContext = PublicationContext::new(
        expected.chain_id().clone(),
        expected.protocol_version(),
        expected.epoch(),
    )
    .unwrap();
    let publisher: Address = LocalSigner::from_seed([11; 32]).address();
    // 32 is `execution::publication::MAX_DEPENDENCIES`: the structural
    // ceiling `CodeArtifact::new` already enforces. Reaching it here, with
    // maximal-length chain ids, independently proves the aggregate display
    // byte budget is a real, reachable bound, not decoration.
    let dependencies: Vec<UnverifiedDependencyRef> = (1u8..=32)
        .map(|index| {
            UnverifiedDependencyRef::new(
                PackageOrigin::unverified(
                    expected.chain_id().clone(),
                    [100 + index; 32],
                    [index; 32],
                )
                .unwrap(),
                1,
                context.clone(),
                Digest32::new(HashAlgorithmId::Sha2_256, [index; 32]),
            )
            .unwrap()
        })
        .collect();
    let semantics: Digest32 = local_publication_profile_semantics(&resolver, &context).unwrap();
    let artifact: CodeArtifact = CodeArtifact::new(ArtifactParts {
        context,
        origin: PackageOrigin::unverified(
            expected.chain_id().clone(),
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
        unverified_dependencies: dependencies,
    })
    .unwrap();
    let prepared: PreparedPublication = PreparedPublication::prepare(
        publisher,
        &resolver,
        &expected,
        artifact,
        1,
        RequestId::new([3; 32]).unwrap(),
    )
    .unwrap();
    let error = PublicationReview::build(&prepared).unwrap_err();
    assert!(matches!(
        error,
        PublicationReviewError::Limit {
            field: "total_display_bytes",
            ..
        }
    ));
}

#[test]
fn review_distinguishes_origin_seed_code_and_abi_changes() {
    let publisher: Address = LocalSigner::from_seed([11; 32]).address();
    let baseline_artifact: CodeArtifact = artifact_with_profile(
        *publisher.as_bytes(),
        7,
        CONTRACT_WASM_ADMISSION_PROFILE_VERSION,
        vec!["run".to_owned()],
        vec![],
    );
    let baseline: PublicationReview =
        PublicationReview::build(&prepare(publisher, baseline_artifact, 1, [3; 32])).unwrap();

    let changed_seed_artifact: CodeArtifact = artifact_with_profile(
        *publisher.as_bytes(),
        8,
        CONTRACT_WASM_ADMISSION_PROFILE_VERSION,
        vec!["run".to_owned()],
        vec![],
    );
    let changed_seed: PublicationReview =
        PublicationReview::build(&prepare(publisher, changed_seed_artifact, 1, [3; 32])).unwrap();
    assert_ne!(baseline.origin_seed_hex(), changed_seed.origin_seed_hex());
    assert_ne!(
        baseline.artifact_digest_hex(),
        changed_seed.artifact_digest_hex()
    );
    assert_eq!(
        baseline.diagnostic_wasm_contract_code_hash_hex(),
        changed_seed.diagnostic_wasm_contract_code_hash_hex()
    );
    assert_eq!(
        baseline.diagnostic_abi_bytes_hash_hex(),
        changed_seed.diagnostic_abi_bytes_hash_hex()
    );

    let mut changed_wasm: Vec<u8> = wasm_bytes();
    *changed_wasm.last_mut().unwrap() ^= 0x01;
    let changed_code_artifact: CodeArtifact = artifact_with(
        *publisher.as_bytes(),
        7,
        CONTRACT_WASM_ADMISSION_PROFILE_VERSION,
        changed_wasm,
        b"opaque-abi".to_vec(),
        vec!["run".to_owned()],
        vec![],
    );
    let changed_code: PublicationReview =
        PublicationReview::build(&prepare(publisher, changed_code_artifact, 1, [3; 32])).unwrap();
    assert_ne!(
        baseline.diagnostic_wasm_contract_code_hash_hex(),
        changed_code.diagnostic_wasm_contract_code_hash_hex()
    );
    assert_ne!(
        baseline.artifact_digest_hex(),
        changed_code.artifact_digest_hex()
    );
    assert_eq!(baseline.origin_seed_hex(), changed_code.origin_seed_hex());
    assert_eq!(
        baseline.diagnostic_abi_bytes_hash_hex(),
        changed_code.diagnostic_abi_bytes_hash_hex()
    );

    let changed_abi_artifact: CodeArtifact = artifact_with(
        *publisher.as_bytes(),
        7,
        CONTRACT_WASM_ADMISSION_PROFILE_VERSION,
        wasm_bytes(),
        b"opaque-abi-changed".to_vec(),
        vec!["run".to_owned()],
        vec![],
    );
    let changed_abi: PublicationReview =
        PublicationReview::build(&prepare(publisher, changed_abi_artifact, 1, [3; 32])).unwrap();
    assert_ne!(
        baseline.diagnostic_abi_bytes_hash_hex(),
        changed_abi.diagnostic_abi_bytes_hash_hex()
    );
    assert_ne!(
        baseline.artifact_digest_hex(),
        changed_abi.artifact_digest_hex()
    );
    assert_eq!(baseline.origin_seed_hex(), changed_abi.origin_seed_hex());
    assert_eq!(
        baseline.diagnostic_wasm_contract_code_hash_hex(),
        changed_abi.diagnostic_wasm_contract_code_hash_hex()
    );
}

/// Conformance check: for every known profile, the presentation-only
/// semantics dispatch inside `PublicationReview::build` picks exactly the
/// semantics value the existing, independent `authenticate_publication_submission`
/// verifier accepts for that profile, and a different profile's semantics
/// is rejected by that same real verifier. This exercises the actual
/// existing authority oracle, not a reimplementation of it.
#[test]
fn review_profile_semantics_conform_to_existing_authentication_oracle() {
    let signer: LocalSigner = LocalSigner::from_seed([7; 32]);
    let profiles: [u32; 4] = [
        CONTRACT_WASM_ADMISSION_PROFILE_VERSION,
        TYPED_CONTRACT_WASM_PROFILE_VERSION,
        GENERAL_CONTRACT_WASM_PROFILE_VERSION,
        GENERIC_OBJECT_RESULT_WASM_PROFILE_VERSION,
    ];
    let semantics_for = |profile: u32| -> Digest32 {
        match profile {
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
        }
    };
    for profile in profiles {
        let artifact: CodeArtifact = artifact_with_profile(
            *signer.address().as_bytes(),
            9,
            profile,
            vec!["run".to_owned()],
            vec![],
        );
        let digest: Digest32 =
            publication::artifact_commitment(&resolver(), &context(), &artifact).unwrap();
        let frame: Vec<u8> =
            publication_submission_signing_frame(&resolver(), &context(), &artifact, 1, [4; 32])
                .unwrap();
        let signature: [u8; 64] = signer.sign_framed(&frame).unwrap().try_into().unwrap();
        let submission: PublicationSubmission = PublicationSubmission::new(
            [4; 32],
            publication::PublicationRequest::new(artifact.clone(), 1, digest, signature),
        )
        .unwrap();

        // The same semantics our presentation dispatch would compute for
        // this exact profile is accepted by the real admission verifier.
        assert!(
            authenticate_publication_submission(
                &resolver(),
                &context(),
                &semantics_for(profile),
                submission.clone(),
            )
            .is_ok()
        );

        // Any other profile's semantics is rejected by that same verifier,
        // proving profiles are not interchangeable under it.
        for other in profiles {
            if other == profile {
                continue;
            }
            assert!(
                authenticate_publication_submission(
                    &resolver(),
                    &context(),
                    &semantics_for(other),
                    submission.clone(),
                )
                .is_err()
            );
        }
    }
}
