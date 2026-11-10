//! Seed-free, non-authorizing original bond inner transfer preview.

use std::{error::Error, ffi::OsString, path::Path};

use sunrise_edge_client::{
    Address, AtomicityDomainId, ChainId, Client,
    ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_BINDING_ID,
    ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID, Epoch, ExpectedProtocolContext,
    HashSuiteResolver, HashSuiteSchedule, HttpObjectQueryResult, ObjectId, ProtocolVersion,
    PublicationContext, RequestId, SignatureSchemeId, Transport, bond_registration::BondResourceId,
    load_verified_genesis_root,
};

use crate::{
    args::{FlagSpec, ParsedArgs, scalar},
    custody::bond_inner::{BondInnerRequest, BondInnerTrust, PreparedBondInner},
    error::CliError,
    hex::decode_hex_32,
    parse::{parse_u16, parse_u32, parse_u64},
};

use super::{hash_suite_pins::parse_pinned_flags, network_artifacts::read_bounded};
use crate::net::{connect, tls_flag_specs};

const HELP: &str = "Seed-free, non-authorizing original-genesis Standard Asset bond inner transfer preview. Rebuilds the exact unsigned local execution frame from the manifest-pinned revision-one transfer and a caller-supplied source Coin snapshot. Optional --endpoint HOST:PORT with --source-object-id HEX checks an endpoint-reported current inline object after the expected protocol context; remote endpoints require the existing paired TLS flags. This checks bytes, digest and provenance but is not chain-state freshness proof. It does not approve, sign, execute or write an artifact. Successor/live-epoch scope is unsupported. Required: --ordered-genesis-manifest FILE --ordered-expected-genesis-digest HEX --expected-chain-id CHAIN --expected-protocol-version N --expected-epoch N --domain HEX --suite epoch:id:transaction:object:effects:code:config:certificate --source-coin FILE --source-key HEX --validator-key HEX --resource-domain N --resource-id HEX --nonce N --request-id HEX --gas-limit N.";

const FLAGS: &[FlagSpec] = &[
    scalar("--ordered-genesis-manifest"),
    scalar("--ordered-expected-genesis-digest"),
    scalar("--expected-chain-id"),
    scalar("--expected-protocol-version"),
    scalar("--expected-epoch"),
    scalar("--domain"),
    scalar("--source-coin"),
    scalar("--source-key"),
    scalar("--validator-key"),
    scalar("--resource-domain"),
    scalar("--resource-id"),
    scalar("--nonce"),
    scalar("--request-id"),
    scalar("--gas-limit"),
];

fn failure(error: impl Error + Send + Sync + 'static) -> CliError {
    CliError::LocalExecution(Box::new(error))
}

fn invalid(message: &'static str) -> CliError {
    failure(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message,
    ))
}

/// A node's current-inline claim is useful for refusing a stale or changed
/// local snapshot, but neither the response nor its recomputed body digest
/// proves freshness against a chain-anchored state root. Never turn this
/// check into signing authority.
fn check_endpoint_reported_source<T: Transport>(
    client: &Client<T>,
    expected: &ExpectedProtocolContext,
    requested_id: ObjectId,
    source_bytes: &[u8],
    preview: &PreparedBondInner,
) -> Result<(), CliError> {
    client.query_verified_context(expected)?;
    let result = client.query_object(requested_id)?;
    let HttpObjectQueryResult::CurrentInline {
        object_id,
        object_version,
        digest,
        creating_chain_id,
        creating_protocol_version,
        canonical_object_bytes,
        ..
    } = result
    else {
        return Err(invalid(
            "bond source query must report a current inline object",
        ));
    };
    let expected_ref = &preview.prepared.intent().call.access.entries[0].object_ref;
    if object_id != requested_id
        || object_id != expected_ref.id
        || object_version.get() != expected_ref.version
        || digest != expected_ref.digest
        || creating_chain_id != *expected.chain_id()
        || creating_protocol_version != expected.protocol_version()
        || canonical_object_bytes != source_bytes
    {
        return Err(invalid(
            "bond source query differs from the reviewed source, access reference or protocol provenance",
        ));
    }
    Ok(())
}

pub(super) fn run<I: IntoIterator<Item = OsString>>(args: I) -> Result<(), CliError> {
    let args: Vec<OsString> = args.into_iter().collect();
    if args.len() == 1 && args[0] == "--help" {
        println!("{HELP}");
        return Ok(());
    }
    let mut flags: Vec<FlagSpec> = FLAGS.to_vec();
    flags.extend([scalar("--endpoint"), scalar("--source-object-id")]);
    let tls_flags = tls_flag_specs();
    flags.extend(tls_flags.iter().copied());
    let (parsed, schedules): (ParsedArgs, Vec<HashSuiteSchedule>) =
        parse_pinned_flags(args, &flags)?;
    if schedules.is_empty() {
        return Err(invalid("one to 64 explicit --suite entries are required"));
    }
    // Parse required local context pins before loading the source Coin.
    let manifest_path = parsed.require("--ordered-genesis-manifest")?;
    let expected_digest = decode_hex_32(
        "--ordered-expected-genesis-digest",
        parsed.require("--ordered-expected-genesis-digest")?,
    )?;
    let chain =
        ChainId::new(parsed.require("--expected-chain-id")?.to_string()).map_err(failure)?;
    let version = ProtocolVersion::new(parse_u32(
        "--expected-protocol-version",
        parsed.require("--expected-protocol-version")?,
    )?);
    let epoch = Epoch::new(parse_u64(
        "--expected-epoch",
        parsed.require("--expected-epoch")?,
    )?);
    let domain = AtomicityDomainId::new(decode_hex_32("--domain", parsed.require("--domain")?)?)
        .map_err(failure)?;
    let context = PublicationContext::new(chain.clone(), version, epoch).map_err(failure)?;
    let resolver = HashSuiteResolver::new(chain.clone(), version, schedules).map_err(failure)?;
    let expected = ExpectedProtocolContext::new(
        chain,
        version,
        epoch,
        resolver.suite_for_epoch(epoch).map_err(failure)?.id,
        ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID,
        SignatureSchemeId::Ed25519.as_u16(),
        ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_BINDING_ID,
        domain,
    )
    .map_err(failure)?;
    let source_key = Address::new(decode_hex_32(
        "--source-key",
        parsed.require("--source-key")?,
    )?);
    let current_query = match (parsed.get("--endpoint"), parsed.get("--source-object-id")) {
        (None, None) if tls_flags.iter().all(|flag| parsed.get(flag.name).is_none()) => None,
        (Some(endpoint), Some(id)) => Some((
            endpoint,
            ObjectId::new(decode_hex_32("--source-object-id", id)?),
        )),
        _ => {
            return Err(invalid(
                "bond source query requires both --endpoint and --source-object-id; TLS flags require the endpoint",
            ));
        }
    };
    let resource = BondResourceId::new(
        parse_u16("--resource-domain", parsed.require("--resource-domain")?)?,
        decode_hex_32("--resource-id", parsed.require("--resource-id")?)?,
    )
    .map_err(failure)?;
    let request = BondInnerRequest {
        source_coin_bytes: read_bounded(
            parsed.require("--source-coin")?,
            sunrise_edge_client::MAX_AUTHENTICATED_OBJECT_BODY_BYTES,
        )?,
        validator_key: decode_hex_32("--validator-key", parsed.require("--validator-key")?)?,
        resource,
        nonce: parse_u64("--nonce", parsed.require("--nonce")?)?,
        request_id: RequestId::new(decode_hex_32(
            "--request-id",
            parsed.require("--request-id")?,
        )?)
        .map_err(failure)?,
        gas_limit: parse_u64("--gas-limit", parsed.require("--gas-limit")?)?,
        local_observation: None,
    };
    let root = load_verified_genesis_root(
        Path::new(manifest_path),
        &resolver,
        expected_digest,
        &context,
    )
    .map_err(failure)?;
    let trust = BondInnerTrust::new(expected.clone(), source_key, root)?;
    let preview: PreparedBondInner = trust.prepare(&request)?;
    if let Some((endpoint, object_id)) = current_query {
        let client = connect(endpoint, &parsed)?;
        check_endpoint_reported_source(
            &client,
            &expected,
            object_id,
            &request.source_coin_bytes,
            &preview,
        )?;
    }
    print!("{}", preview.review);
    println!(
        "source_endpoint_current_inline_checked={}",
        current_query.is_some()
    );
    println!("source_current_query_chain_proof=false");
    println!(
        "unsigned_frame_bytes={}",
        preview.prepared.signable_frame().len()
    );
    Ok(())
}
