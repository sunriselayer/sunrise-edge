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
use execution::{
    ObjectEffect,
    paid_execution::{PaidExecutionResult, decode_paid_execution_result},
};
use hashing::HashSuiteResolver;
use objects::{Object, ObjectId};
use protocol_types::Epoch;
use public_standard_asset::{coin_type_tag, definition_type_tag, treasury_cap_type_tag};
use std::{collections::BTreeSet, ffi::OsString, fs, net::SocketAddr, path::Path};

use super::host::temp_file;

pub fn decode_result(path: &Path) -> PaidExecutionResult {
    decode_paid_execution_result(&fs::read(path).unwrap()).unwrap()
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
    let output = super::cli::edge_cli_command(flags).output().unwrap();
    assert_eq!(
        output.status.success(),
        expect_success,
        "{label} ({action}) exit status mismatch: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    decode_result(&result_out)
}

/// Runs a real `contract paid-publish` or `contract paid-instantiate` over
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
    super::run_expect_success(super::cli::edge_cli_command(flags), label);
    (decode_result(&result_out), signed_out, cert_out)
}
