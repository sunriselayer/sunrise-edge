//! Shared real-binary paid-execution call builders for the DR-0151
//! contract-lifecycle E2Es (`contract_lifecycle_pg_e2e`,
//! `contract_lifecycle_catch_up_pg_e2e`): every paid-publish/paid-instantiate
//! or top-level Standard Asset verb invocation drives the separately
//! compiled `sunrise-edge-cli` binary as a subprocess through
//! [`super::cli::edge_cli_command`], never `sunrise_edge_cli::run` in-process,
//! so both files exercise identical process-boundary and argv-parsing
//! behavior. Factored out here so neither test file re-implements its own
//! copy of this flag/decode/identify plumbing.
#![allow(dead_code)]

use abi::package_types::{PackageOrigin, ScopedTypeTag, verify_scoped_type_id};
use abi::{
    AccessEntry, AccessManifest, encode_access_manifest,
    package_types::encode_scoped_type_arguments,
};
use consensus::{
    AvailabilityCertificate, AvailabilityCertifier, FastCertificate,
    decode_availability_certificate, decode_fast_certificate,
};
use execution::{
    ObjectEffect,
    paid_execution::{
        PaidExecutionResult, SignedPaidIntent, decode_paid_execution_result,
        decode_signed_paid_intent, paid_invocation_digest,
    },
};
use hashing::HashSuiteResolver;
use node_core::fast_path::FastPathEd25519Verifier;
use node_core::{ObjectQueryResult, decode_genesis_manifest, query_object};
use objects::{AccessMode, Object, ObjectId, ObjectRef};
use protocol_types::{AtomicityDomainId, ChainId, Epoch, HashSuite, HashSuiteSchedule};
use public_standard_asset::{
    asset_type_argument, coin_type_tag, definition_type_tag, mint_arguments, treasury_cap_type_tag,
};
use runtime::{DurableOperationContext, StructuredDurableDomainStateStore};
use std::{
    collections::BTreeSet,
    ffi::OsString,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use super::host::temp_file;

pub fn decode_result(path: &Path) -> PaidExecutionResult {
    decode_paid_execution_result(&fs::read(path).unwrap()).unwrap()
}

pub fn verify_saved_availability_certificate(
    call: &NetworkCall<'_>,
    path: &Path,
    signed_path: &Path,
    certificate_path: &Path,
) {
    let bytes: Vec<u8> = fs::read(path).expect("availability certificate file must exist");
    assert!(
        !bytes.is_empty(),
        "availability certificate must not be empty"
    );
    let cert: AvailabilityCertificate =
        decode_availability_certificate(&bytes).expect("availability certificate must decode");
    let manifest_bytes: Vec<u8> = fs::read(call.manifest_path).unwrap();
    let manifest: node_core::GenesisManifest = decode_genesis_manifest(&manifest_bytes).unwrap();
    let resolver: HashSuiteResolver = HashSuiteResolver::new(
        manifest.context().chain_id().clone(),
        manifest.context().protocol_version(),
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .unwrap();
    let manifest_digest: protocol_types::Digest32 =
        node_core::genesis_manifest_commitment(&resolver, &manifest).unwrap();
    assert_eq!(
        super::cli::to_hex(&manifest_digest.bytes()),
        call.digest_hex
    );
    let trusted: sunrise_edge_client::TrustedFastVoteGenesis =
        sunrise_edge_client::load_trusted_fastvote_genesis_with_profile(
            call.manifest_path,
            &resolver,
            manifest_digest.bytes(),
            manifest.context(),
        )
        .unwrap();
    assert!(trusted.commitment_profile().is_logical());
    let certifier: AvailabilityCertifier = AvailabilityCertifier::new(
        manifest.context().chain_id().clone(),
        manifest.context().protocol_version(),
        manifest.context().epoch(),
        trusted.certifier().validator_set().clone(),
    )
    .unwrap();
    certifier
        .verify_certificate(&cert, &FastPathEd25519Verifier)
        .expect("saved availability certificate must verify under genesis validator set");
    let signed: SignedPaidIntent =
        decode_signed_paid_intent(&fs::read(signed_path).unwrap()).unwrap();
    let full: FastCertificate =
        decode_fast_certificate(&fs::read(certificate_path).unwrap()).unwrap();
    trusted
        .certifier()
        .verify_certificate(&full, &FastPathEd25519Verifier)
        .unwrap();
    let signed_digest: protocol_types::Digest32 =
        paid_invocation_digest(&resolver, &signed).unwrap();
    assert_eq!(cert.identity.domain.to_string(), call.domain_hex);
    assert_eq!(cert.identity.request_id, signed.intent.request_id);
    assert_eq!(cert.identity.signed_intent_digest, signed_digest);
    assert_eq!(full.tx_hash, signed_digest);
    assert_eq!(
        cert.identity.execution_commitment,
        full.execution_effects_hash
    );
}

/// Identifies the freshly created `Definition`/`TreasuryCap` pair a
/// successful `paid-instantiate`/`create-asset` left behind, excluding the
/// fee/refund settlement outputs, by re-deriving each type's scoped id from
/// `origin`.
pub fn identify_definition_and_cap(
    result: &PaidExecutionResult,
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    origin: &PackageOrigin,
) -> (ObjectId, ObjectId) {
    let charged = result.charged.as_ref().unwrap();
    let fee_id: ObjectId = charged.fee_output.id;
    let refund_id: Option<ObjectId> = charged.refund_output.as_ref().map(|value| value.id);
    let created: Vec<&Object> = result
        .effects
        .object_effects
        .iter()
        .filter_map(|effect: &ObjectEffect| match effect {
            ObjectEffect::Created(object)
                if object.id != fee_id && Some(object.id) != refund_id =>
            {
                Some(object)
            }
            _ => None,
        })
        .collect();
    let definition_tag: ScopedTypeTag = definition_type_tag(origin).unwrap();
    let definition: &Object = created
        .iter()
        .copied()
        .find(|object: &&Object| {
            verify_scoped_type_id(resolver, &object.type_hash, epoch, &definition_tag)
                .unwrap_or(false)
        })
        .expect("instantiate must create a Definition");
    let cap_tag: ScopedTypeTag = treasury_cap_type_tag(origin, &definition.id).unwrap();
    let cap: &Object = created
        .iter()
        .copied()
        .find(|object: &&Object| {
            verify_scoped_type_id(resolver, &object.type_hash, epoch, &cap_tag).unwrap_or(false)
        })
        .expect("instantiate must create a TreasuryCap");
    (definition.id, cap.id)
}

/// Identifies the single freshly created `Coin` a successful `mint`/`split`
/// verb left behind, excluding the fee/refund settlement outputs.
pub fn identify_coin(
    result: &PaidExecutionResult,
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    origin: &PackageOrigin,
    asset: ObjectId,
) -> ObjectId {
    let charged = result.charged.as_ref().unwrap();
    let fee_id: ObjectId = charged.fee_output.id;
    let refund_id: Option<ObjectId> = charged.refund_output.as_ref().map(|value| value.id);
    let coin_tag: ScopedTypeTag = coin_type_tag(origin, &asset).unwrap();
    result
        .effects
        .object_effects
        .iter()
        .find_map(|effect: &ObjectEffect| match effect {
            ObjectEffect::Created(object)
                if object.id != fee_id && Some(object.id) != refund_id =>
            {
                verify_scoped_type_id(resolver, &object.type_hash, epoch, &coin_tag)
                    .unwrap_or(false)
                    .then_some(object.id)
            }
            _ => None,
        })
        .expect("call must create exactly one Coin")
}

/// Tracks every object a result touched: created, mutated, deleted,
/// fee-output and refund-output ids.
pub fn track(ids: &mut BTreeSet<ObjectId>, result: &PaidExecutionResult) {
    result
        .effects
        .object_effects
        .iter()
        .for_each(|effect: &ObjectEffect| {
            let id: ObjectId = match effect {
                ObjectEffect::Created(object) => object.id,
                ObjectEffect::Mutated { new_object, .. } => new_object.id,
                ObjectEffect::Deleted { id, .. } => *id,
            };
            ids.insert(id);
        });
    if let Some(charged) = &result.charged {
        ids.insert(charged.fee_output.id);
        if let Some(refund) = &charged.refund_output {
            ids.insert(refund.id);
        }
    }
}

/// Every flag shared by a real network paid-publish/paid-instantiate/paid-call
/// or top-level asset-verb invocation of the compiled CLI, factored out so
/// each call site only spells out what actually varies between them: the
/// action, its own object/amount/recipient/code arguments, and its outputs.
/// `--fee-access` is deliberately excluded: it exists only on `contract
/// paid-*`, never on the top-level asset verbs (which always reserve the fee
/// source for Write internally) -- callers of [`Self::contract_flags`] add it
/// themselves.
pub struct NetworkCall<'a> {
    pub endpoint: SocketAddr,
    pub chain_id: &'a str,
    pub domain_hex: &'a str,
    pub seed_path: &'a Path,
    pub network_config_path: &'a Path,
    pub manifest_path: &'a Path,
    pub digest_hex: &'a str,
    pub fee_source: ObjectId,
}

impl NetworkCall<'_> {
    pub fn is_logical(&self) -> bool {
        let bytes: Vec<u8> = fs::read(self.manifest_path).unwrap();
        let manifest: node_core::GenesisManifest = decode_genesis_manifest(&bytes).unwrap();
        manifest.commitment_profile.is_logical()
    }

    pub fn preamble(&self, request_id: [u8; 32], nonce: u64) -> Vec<OsString> {
        [
            "--endpoint",
            &self.endpoint.to_string(),
            "--expected-chain-id",
            self.chain_id,
            "--expected-protocol-version",
            "3",
            "--expected-epoch",
            "0",
            "--expected-hash-suite-id",
            "1",
            "--expected-domain",
            self.domain_hex,
            "--seed-file",
            self.seed_path.to_str().unwrap(),
            "--gas-limit",
            "200000",
            "--request-id",
            &super::cli::to_hex(&request_id),
            "--nonce",
            &nonce.to_string(),
            "--fee-source",
            &self.fee_source.to_string(),
            "--max-fee",
            "1000000",
            "--fastvote-network",
            self.network_config_path.to_str().unwrap(),
            "--fastvote-genesis-manifest",
            self.manifest_path.to_str().unwrap(),
            "--fastvote-expected-genesis-digest",
            self.digest_hex,
            "--fastvote-deadline-seconds",
            "30",
            "--fastvote-per-request-cap-seconds",
            "10",
        ]
        .into_iter()
        .map(OsString::from)
        .collect()
    }
}

/// Runs one real top-level Standard Asset verb (`create-asset`, `transfer`,
/// `split`, `merge`, `mint` or `burn`) through the compiled CLI binary over
/// `--fastvote-network`, asserting the expected process exit status and
/// returning the decoded result.
#[allow(clippy::too_many_arguments)]
pub fn run_asset_verb(
    call: &NetworkCall<'_>,
    action: &str,
    extra: &[(&str, String)],
    data_dir: &Path,
    request_id: [u8; 32],
    nonce: u64,
    label: &str,
    expect_success: bool,
) -> PaidExecutionResult {
    let signed_out = temp_file(data_dir, &format!("{label}.intent"));
    let cert_out = temp_file(data_dir, &format!("{label}.cert"));
    let result_out = temp_file(data_dir, &format!("{label}.result"));
    let avail_out = temp_file(data_dir, &format!("{label}.avail"));
    let mut flags: Vec<OsString> = vec![OsString::from(action)];
    flags.extend(call.preamble(request_id, nonce));
    for (flag, value) in extra {
        flags.push(OsString::from(*flag));
        flags.push(OsString::from(value.as_str()));
    }
    flags.extend(
        [
            "--fastvote-signed-intent-out",
            signed_out.to_str().unwrap(),
            "--fastvote-certificate-out",
            cert_out.to_str().unwrap(),
            "--result-out",
            result_out.to_str().unwrap(),
        ]
        .into_iter()
        .map(OsString::from),
    );
    if call.is_logical() {
        flags.push(OsString::from("--fastvote-availability-certificate-out"));
        flags.push(OsString::from(avail_out.to_str().unwrap()));
    }
    let output = super::cli::edge_cli_command(flags).output().unwrap();
    assert_eq!(
        output.status.success(),
        expect_success,
        "{label} ({action}) exit status mismatch: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if call.is_logical() {
        verify_saved_availability_certificate(call, &avail_out, &signed_out, &cert_out);
    }
    decode_result(&result_out)
}

/// Runs one real top-level Standard Asset verb exactly like
/// [`run_asset_verb`], for a call expected to be rejected by admission
/// before any result is ever committed (e.g. a conflicting request-id
/// reuse): asserts the process exits unsuccessfully and that no result or
/// certificate artifact was left behind, without attempting to decode
/// either -- unlike a charged application trap, a rejected admission never
/// writes `--result-out`/`--fastvote-certificate-out` at all.
#[allow(clippy::too_many_arguments)]
pub fn run_asset_verb_expect_rejected(
    call: &NetworkCall<'_>,
    action: &str,
    extra: &[(&str, String)],
    data_dir: &Path,
    request_id: [u8; 32],
    nonce: u64,
    label: &str,
) {
    let signed_out = temp_file(data_dir, &format!("{label}.intent"));
    let cert_out = temp_file(data_dir, &format!("{label}.cert"));
    let result_out = temp_file(data_dir, &format!("{label}.result"));
    let avail_out = temp_file(data_dir, &format!("{label}.avail"));
    let mut flags: Vec<OsString> = vec![OsString::from(action)];
    flags.extend(call.preamble(request_id, nonce));
    for (flag, value) in extra {
        flags.push(OsString::from(*flag));
        flags.push(OsString::from(value.as_str()));
    }
    flags.extend(
        [
            "--fastvote-signed-intent-out",
            signed_out.to_str().unwrap(),
            "--fastvote-certificate-out",
            cert_out.to_str().unwrap(),
            "--result-out",
            result_out.to_str().unwrap(),
        ]
        .into_iter()
        .map(OsString::from),
    );
    if call.is_logical() {
        flags.push(OsString::from("--fastvote-availability-certificate-out"));
        flags.push(OsString::from(avail_out.to_str().unwrap()));
    }
    let output = super::cli::edge_cli_command(flags).output().unwrap();
    assert!(
        !output.status.success(),
        "{label} ({action}) unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let mut artifacts: Vec<(&PathBuf, &'static str)> =
        vec![(&result_out, "result"), (&cert_out, "certificate")];
    if call.is_logical() {
        artifacts.push((&avail_out, "availability"));
    }
    for (path, artifact) in artifacts {
        let bytes: Vec<u8> = fs::read(path).unwrap_or_default();
        assert!(
            bytes.is_empty(),
            "{label} ({action}) left behind a non-empty {artifact} artifact despite rejection"
        );
    }
}

/// Runs a successful `contract paid-publish`, `paid-instantiate` or `paid-call` over
/// `--fastvote-network` through the compiled CLI binary, asserting success
/// (both are only ever driven as the positive path in these E2Es; a
/// negative/offline replay of their saved artifacts goes through
/// `contract fastvote-catch-up` instead, not through this helper) and
/// returning the decoded result. `--fastvote-signed-intent-out`/
/// `--fastvote-certificate-out` name the exact artifact files a later
/// `fastvote-catch-up` manifest entry can reference.
#[allow(clippy::too_many_arguments)]
pub fn run_contract_paid(
    call: &NetworkCall<'_>,
    action: &str,
    extra: &[(&str, String)],
    data_dir: &Path,
    request_id: [u8; 32],
    nonce: u64,
    label: &str,
) -> (PaidExecutionResult, std::path::PathBuf, std::path::PathBuf) {
    let signed_out = temp_file(data_dir, &format!("{label}.intent"));
    let cert_out = temp_file(data_dir, &format!("{label}.cert"));
    let result_out = temp_file(data_dir, &format!("{label}.result"));
    let avail_out = temp_file(data_dir, &format!("{label}.avail"));
    let mut flags: Vec<OsString> = vec![OsString::from("contract"), OsString::from(action)];
    flags.extend(call.preamble(request_id, nonce));
    flags.push(OsString::from("--fee-access"));
    flags.push(OsString::from("write"));
    for (flag, value) in extra {
        flags.push(OsString::from(*flag));
        flags.push(OsString::from(value.as_str()));
    }
    flags.extend(
        [
            "--fastvote-signed-intent-out",
            signed_out.to_str().unwrap(),
            "--fastvote-certificate-out",
            cert_out.to_str().unwrap(),
            "--result-out",
            result_out.to_str().unwrap(),
        ]
        .into_iter()
        .map(OsString::from),
    );
    if call.is_logical() {
        flags.push(OsString::from("--fastvote-availability-certificate-out"));
        flags.push(OsString::from(avail_out.to_str().unwrap()));
    }
    super::run_expect_success(super::cli::edge_cli_command(flags), label);
    if call.is_logical() {
        verify_saved_availability_certificate(call, &avail_out, &signed_out, &cert_out);
    }
    (decode_result(&result_out), signed_out, cert_out)
}

/// Independently re-queries one object's exact current `ObjectRef` (id, live
/// version, live digest) out of band, the same way [`super::cli::current_fee_coin_ref`]
/// does for the genesis fee coin: an owned object's version/digest advances
/// on every settlement, so a stale reference (e.g. from the moment a
/// `TreasuryCap` was first created) only works for the very first call
/// against it.
pub fn current_object_ref<S>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    chain_id: &ChainId,
    object_id: ObjectId,
) -> ObjectRef
where
    S: StructuredDurableDomainStateStore,
{
    match query_object(store, context, domain, chain_id, object_id).unwrap() {
        ObjectQueryResult::CurrentInline {
            object_id,
            object_version,
            digest,
            ..
        } => ObjectRef {
            id: object_id,
            version: object_version.get(),
            digest,
        },
        other => panic!("expected {object_id:?} to be a current inline object, got {other:?}"),
    }
}

/// Mints against a genuinely independent-origin published package's
/// `TreasuryCap` through the generic `contract paid-call` path -- never a
/// top-level asset verb, which intentionally only binds to the active
/// locally trusted Standard Asset code
/// (`standard_asset::validate_application_instance_pin`). Builds the
/// canonical `mint` arguments/type-arguments/access-manifest (a single
/// `Write` entry on the cap's freshly re-queried `ObjectRef`) and returns
/// the decoded result plus the intent/certificate paths a later catch-up
/// manifest may reference by `label`.
#[allow(clippy::too_many_arguments)]
pub fn run_generic_mint<S>(
    call: &NetworkCall<'_>,
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    chain_id: &ChainId,
    instance_ref_path: &Path,
    definition: ObjectId,
    treasury_cap: ObjectId,
    amount: u64,
    recipient: &[u8; 32],
    data_dir: &Path,
    request_id: [u8; 32],
    nonce: u64,
    label: &str,
) -> (PaidExecutionResult, PathBuf, PathBuf)
where
    S: StructuredDurableDomainStateStore,
{
    let cap_ref: ObjectRef = current_object_ref(store, context, domain, chain_id, treasury_cap);
    let args_path: PathBuf = temp_file(data_dir, &format!("{label}.args"));
    fs::write(&args_path, mint_arguments(amount, recipient).unwrap()).unwrap();
    let type_args_path: PathBuf = temp_file(data_dir, &format!("{label}.type-args"));
    fs::write(
        &type_args_path,
        encode_scoped_type_arguments(chain_id, &[asset_type_argument(&definition)]).unwrap(),
    )
    .unwrap();
    let access_path: PathBuf = temp_file(data_dir, &format!("{label}.access"));
    fs::write(
        &access_path,
        encode_access_manifest(&AccessManifest {
            entries: vec![AccessEntry {
                object_ref: cap_ref,
                mode: AccessMode::Write,
            }],
        })
        .unwrap(),
    )
    .unwrap();
    run_contract_paid(
        call,
        "paid-call",
        &[
            (
                "--instance-ref",
                instance_ref_path.to_str().unwrap().to_owned(),
            ),
            ("--entrypoint", "mint".to_owned()),
            ("--access", access_path.to_str().unwrap().to_owned()),
            ("--args", args_path.to_str().unwrap().to_owned()),
            ("--type-args", type_args_path.to_str().unwrap().to_owned()),
        ],
        data_dir,
        request_id,
        nonce,
        label,
    )
}
