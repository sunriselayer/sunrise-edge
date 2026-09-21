//! Human-facing Standard Asset operations over the ordinary paid Call path.

use super::paid_execution::{MAX_INSTANCE_RECORD_BYTES, validate_remote_instance};
use crate::{
    args::{FlagSpec, ParsedArgs, parse_flags, scalar},
    error::CliError,
    hex::{decode_hex_32, encode_hex},
    net::{CliTransport, connect_paid_execution, tls_flag_specs},
    parse::{parse_u16, parse_u32, parse_u64},
    seed::load_dev_seed,
    signer::{SignerSelection, parse_signer_selection, signer_flag_specs},
};
use public_standard_asset::{
    ASSET_OPAQUE_DOMAIN, INITIALIZER, SCHEMA_VERSION, asset_type_argument, coin_type_tag,
    definition_body, definition_type_tag, executable_abi, mint_arguments, no_arguments,
    split_arguments, transfer_arguments, treasury_cap_type_tag, treasury_supply,
};
use std::{error::Error, ffi::OsString, path::Path};
use sunrise_edge_client::{
    AccessEntry, AccessManifest, AccessMode, Address, Amount, AtomicityDomainId, ChainId, Client,
    Digest32, ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_BINDING_ID,
    ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID, Epoch, ExpectedProtocolContext,
    FeeSourceConsent, HashSuiteId, HashSuiteResolver, HttpObjectQueryResult, LocalSigner, Object,
    ObjectEffect, ObjectId, ObjectRef, Owner, PaidApplication, PaidExecutionResult,
    PaidExecutionStatus, ProtocolVersion, RequestId, ReservationAccessKind, SignatureSchemeId,
    Transport,
    call::{CallIntent, InstanceTarget},
    decode_object, encode_signed_paid_intent,
    local_execution::{
        InstanceRecord, decode_instance_record, encode_instance_record, instance_target,
    },
    local_publication_resolver,
    package_types::{ScopedTypeArg, ScopedTypeTag, derive_scoped_type_id, verify_scoped_type_id},
    paid_execution_client::build_signed_paid_execution,
    publication::{PublicationContext, UnverifiedDependencyRef},
};

const ENDPOINT: &str = "--endpoint";
const EXPECTED_CHAIN_ID: &str = "--expected-chain-id";
const EXPECTED_PROTOCOL_VERSION: &str = "--expected-protocol-version";
const EXPECTED_EPOCH: &str = "--expected-epoch";
const EXPECTED_HASH_SUITE_ID: &str = "--expected-hash-suite-id";
const EXPECTED_DOMAIN: &str = "--expected-domain";
const FEE_SOURCE: &str = "--fee-source";
const MAX_FEE: &str = "--max-fee";
const REFUND_RECIPIENT: &str = "--refund-recipient";
const GAS_LIMIT: &str = "--gas-limit";
const REQUEST_ID: &str = "--request-id";
const NONCE: &str = "--nonce";
const SUBMISSION_OUT: &str = "--submission-out";
const RESULT_OUT: &str = "--result-out";
const COIN: &str = "--coin";
const RECIPIENT: &str = "--recipient";
const AMOUNT: &str = "--amount";
const INTO: &str = "--into";
const FROM: &str = "--from";
const TREASURY_CAP: &str = "--treasury-cap";
const ASSET: &str = "--asset";
const INSTANCE_REF: &str = "--instance-ref";
const INSTANCE_SEED: &str = "--instance-seed";
const INSTANCE_REF_OUT: &str = "--instance-ref-out";

fn failure(error: impl Error + Send + Sync + 'static) -> CliError {
    CliError::LocalExecution(Box::new(error))
}

fn invalid(message: &'static str) -> CliError {
    failure(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message,
    ))
}

fn common_specs() -> Vec<FlagSpec> {
    let mut specs: Vec<FlagSpec> = vec![
        scalar(ENDPOINT),
        scalar(EXPECTED_CHAIN_ID),
        scalar(EXPECTED_PROTOCOL_VERSION),
        scalar(EXPECTED_EPOCH),
        scalar(EXPECTED_HASH_SUITE_ID),
        scalar(EXPECTED_DOMAIN),
        scalar(FEE_SOURCE),
        scalar(MAX_FEE),
        scalar(REFUND_RECIPIENT),
        scalar(GAS_LIMIT),
        scalar(REQUEST_ID),
        scalar(NONCE),
        scalar(SUBMISSION_OUT),
        scalar(RESULT_OUT),
    ];
    specs.extend(tls_flag_specs());
    specs.extend(signer_flag_specs());
    specs
}

/// Parses the independently configured protocol context used before signing.
pub(crate) fn parse_expected_context(
    parsed: &ParsedArgs,
) -> Result<ExpectedProtocolContext, CliError> {
    let chain_id: ChainId = ChainId::new(parsed.require(EXPECTED_CHAIN_ID)?)?;
    let protocol_version: ProtocolVersion = ProtocolVersion::new(parse_u32(
        EXPECTED_PROTOCOL_VERSION,
        parsed.require(EXPECTED_PROTOCOL_VERSION)?,
    )?);
    let epoch: Epoch = Epoch::new(parse_u64(EXPECTED_EPOCH, parsed.require(EXPECTED_EPOCH)?)?);
    let hash_suite_id: HashSuiteId = HashSuiteId::new(parse_u16(
        EXPECTED_HASH_SUITE_ID,
        parsed.require(EXPECTED_HASH_SUITE_ID)?,
    )?);
    let domain: AtomicityDomainId = AtomicityDomainId::new(decode_hex_32(
        EXPECTED_DOMAIN,
        parsed.require(EXPECTED_DOMAIN)?,
    )?)?;
    Ok(ExpectedProtocolContext::new(
        chain_id,
        protocol_version,
        epoch,
        hash_suite_id,
        ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID,
        SignatureSchemeId::Ed25519.as_u16(),
        ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_BINDING_ID,
        domain,
    )?)
}

#[derive(Clone, Copy)]
enum ObjectKind {
    Coin,
    TreasuryCap,
}

struct AssetOperation {
    entrypoint: &'static str,
    inputs: Vec<(ObjectId, AccessMode, ObjectKind, &'static str)>,
    arguments: Vec<u8>,
}

struct ApplicationTarget {
    code: UnverifiedDependencyRef,
    instance: InstanceTarget,
    type_arguments: Vec<ScopedTypeArg>,
    asset: ObjectId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CreatedAsset {
    definition: ObjectId,
    treasury_cap: ObjectId,
}

fn object_id(parsed: &ParsedArgs, flag: &'static str) -> Result<ObjectId, CliError> {
    Ok(ObjectId::new(decode_hex_32(flag, parsed.require(flag)?)?))
}

fn application_selection(parsed: &ParsedArgs) -> Result<Option<(ObjectId, &str)>, CliError> {
    match (parsed.get(ASSET), parsed.get(INSTANCE_REF)) {
        (None, None) => Ok(None),
        (Some(asset), Some(instance)) => Ok(Some((
            ObjectId::new(decode_hex_32(ASSET, asset)?),
            instance,
        ))),
        _ => Err(invalid(
            "--asset and --instance-ref must be provided together",
        )),
    }
}

fn policy_asset(policy: &sunrise_edge_client::PaidFeePolicy) -> Result<ObjectId, CliError> {
    let asset: ObjectId = match policy.type_arguments.as_slice() {
        [ScopedTypeArg::Opaque { domain, value }] if *domain == ASSET_OPAQUE_DOMAIN => {
            ObjectId::new(*value)
        }
        _ => {
            return Err(invalid(
                "installed fee policy is not the Standard Asset profile",
            ));
        }
    };
    if policy.asset_type != coin_type_tag(policy.code.origin(), &asset).map_err(failure)?
        || policy.schema != SCHEMA_VERSION
    {
        return Err(invalid(
            "installed fee policy Standard Asset identity mismatch",
        ));
    }
    Ok(asset)
}

fn operation(action: &str, parsed: &ParsedArgs) -> Result<AssetOperation, CliError> {
    let recipient = || -> Result<[u8; 32], CliError> {
        decode_hex_32(RECIPIENT, parsed.require(RECIPIENT)?).map_err(CliError::from)
    };
    match action {
        "transfer" => Ok(AssetOperation {
            entrypoint: "transfer",
            inputs: vec![(
                object_id(parsed, COIN)?,
                AccessMode::Write,
                ObjectKind::Coin,
                COIN,
            )],
            arguments: transfer_arguments(&recipient()?).map_err(failure)?,
        }),
        "split" => {
            let amount: u64 = parse_u64(AMOUNT, parsed.require(AMOUNT)?)?;
            Ok(AssetOperation {
                entrypoint: "split",
                inputs: vec![(
                    object_id(parsed, COIN)?,
                    AccessMode::Write,
                    ObjectKind::Coin,
                    COIN,
                )],
                arguments: split_arguments(amount, &recipient()?).map_err(failure)?,
            })
        }
        "merge" => {
            let into: ObjectId = object_id(parsed, INTO)?;
            let from: ObjectId = object_id(parsed, FROM)?;
            if into == from {
                return Err(invalid("merge inputs must be distinct"));
            }
            Ok(AssetOperation {
                entrypoint: "merge",
                inputs: vec![
                    (into, AccessMode::Write, ObjectKind::Coin, INTO),
                    (from, AccessMode::Consume, ObjectKind::Coin, FROM),
                ],
                arguments: no_arguments().map_err(failure)?,
            })
        }
        "mint" => {
            let amount: u64 = parse_u64(AMOUNT, parsed.require(AMOUNT)?)?;
            Ok(AssetOperation {
                entrypoint: "mint",
                inputs: vec![(
                    object_id(parsed, TREASURY_CAP)?,
                    AccessMode::Write,
                    ObjectKind::TreasuryCap,
                    TREASURY_CAP,
                )],
                arguments: mint_arguments(amount, &recipient()?).map_err(failure)?,
            })
        }
        "burn" => Ok(AssetOperation {
            entrypoint: "burn",
            inputs: vec![
                (
                    object_id(parsed, TREASURY_CAP)?,
                    AccessMode::Write,
                    ObjectKind::TreasuryCap,
                    TREASURY_CAP,
                ),
                (
                    object_id(parsed, COIN)?,
                    AccessMode::Consume,
                    ObjectKind::Coin,
                    COIN,
                ),
            ],
            arguments: no_arguments().map_err(failure)?,
        }),
        _ => Err(invalid("unknown Standard Asset operation")),
    }
}

fn expected_tag(
    kind: ObjectKind,
    origin: &sunrise_edge_client::PackageOrigin,
    asset: &ObjectId,
) -> Result<ScopedTypeTag, CliError> {
    match kind {
        ObjectKind::Coin => coin_type_tag(origin, asset).map_err(failure),
        ObjectKind::TreasuryCap => treasury_cap_type_tag(origin, asset).map_err(failure),
    }
}

fn validate_definition(
    result: &HttpObjectQueryResult,
    resolver: &HashSuiteResolver,
    expected: &ExpectedProtocolContext,
    object_id: ObjectId,
    tag: &ScopedTypeTag,
) -> Result<(), CliError> {
    let HttpObjectQueryResult::CurrentInline {
        object_id: queried_id,
        object_version,
        creating_chain_id,
        creating_protocol_version,
        canonical_object_bytes,
        ..
    } = result
    else {
        return Err(invalid("asset Definition must be a current inline object"));
    };
    if *queried_id != object_id
        || *creating_chain_id != *expected.chain_id()
        || *creating_protocol_version != expected.protocol_version()
    {
        return Err(invalid("asset Definition protocol provenance mismatch"));
    }
    let object: Object = decode_object(canonical_object_bytes).map_err(failure)?;
    let type_matches: bool =
        verify_scoped_type_id(resolver, &object.type_hash, expected.epoch(), tag)
            .map_err(failure)?;
    if object.id != object_id
        || object.version != object_version.get()
        || !matches!(object.owner, Owner::Address(_))
        || object.schema_version != SCHEMA_VERSION
        || object.data != definition_body().map_err(failure)?
        || !type_matches
    {
        return Err(invalid("asset Definition schema or nominal type mismatch"));
    }
    Ok(())
}

fn validate_application_instance_pin(
    record: &InstanceRecord,
    expected_context: &PublicationContext,
    expected_code: &UnverifiedDependencyRef,
) -> Result<(), CliError> {
    if &record.context != expected_context
        || &record.code != expected_code
        || record.initializer != INITIALIZER
    {
        return Err(invalid(
            "application instance is not the active public Standard Asset code",
        ));
    }
    Ok(())
}

fn select_application_target<T: Transport>(
    parsed: &ParsedArgs,
    client: &Client<T>,
    resolver: &HashSuiteResolver,
    expected: &ExpectedProtocolContext,
    policy: &sunrise_edge_client::PaidFeePolicy,
    genesis_asset: ObjectId,
) -> Result<ApplicationTarget, CliError> {
    let Some((asset, path)) = application_selection(parsed)? else {
        return Ok(ApplicationTarget {
            code: policy.code.clone(),
            instance: policy.instance.clone(),
            type_arguments: policy.type_arguments.clone(),
            asset: genesis_asset,
        });
    };
    let record: InstanceRecord = decode_instance_record(&super::paid_execution::read(
        path,
        MAX_INSTANCE_RECORD_BYTES,
    )?)
    .map_err(failure)?;
    validate_application_instance_pin(&record, &policy.context, &policy.code)?;
    let remote: Option<InstanceRecord> =
        client.query_instance(record.creator, record.seed, resolver, expected)?;
    validate_remote_instance(&record, remote.as_ref())?;
    let definition_tag: ScopedTypeTag =
        definition_type_tag(record.code.origin()).map_err(failure)?;
    validate_definition(
        &client.query_object(asset)?,
        resolver,
        expected,
        asset,
        &definition_tag,
    )?;
    Ok(ApplicationTarget {
        code: record.code.clone(),
        instance: instance_target(resolver, &record).map_err(failure)?,
        type_arguments: vec![asset_type_argument(&asset)],
        asset,
    })
}

#[allow(clippy::too_many_arguments)]
fn owned_input(
    client: &Client<CliTransport>,
    resolver: &HashSuiteResolver,
    expected: &ExpectedProtocolContext,
    owner: Address,
    object_id: ObjectId,
    tag: &ScopedTypeTag,
    flag: &'static str,
) -> Result<ObjectRef, CliError> {
    let result: HttpObjectQueryResult = client.query_object(object_id)?;
    validate_owned_input(&result, resolver, expected, owner, object_id, tag, flag)
}

#[allow(clippy::too_many_arguments)]
fn validate_owned_input(
    result: &HttpObjectQueryResult,
    resolver: &HashSuiteResolver,
    expected: &ExpectedProtocolContext,
    owner: Address,
    object_id: ObjectId,
    tag: &ScopedTypeTag,
    flag: &'static str,
) -> Result<ObjectRef, CliError> {
    let HttpObjectQueryResult::CurrentInline {
        object_id: queried_id,
        object_version,
        digest,
        creating_chain_id,
        creating_protocol_version,
        canonical_object_bytes,
        ..
    } = result
    else {
        return Err(invalid("application input must be a current inline object"));
    };
    if *queried_id != object_id
        || *creating_chain_id != *expected.chain_id()
        || *creating_protocol_version != expected.protocol_version()
    {
        return Err(invalid("application input protocol provenance mismatch"));
    }
    let object: Object = decode_object(canonical_object_bytes).map_err(failure)?;
    let type_matches: bool =
        verify_scoped_type_id(resolver, &object.type_hash, expected.epoch(), tag)
            .map_err(failure)?;
    if object.id != object_id
        || object.version != object_version.get()
        || object.owner != Owner::Address(owner)
        || object.schema_version != SCHEMA_VERSION
        || !type_matches
    {
        return Err(failure(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{flag} owner, schema, or nominal type mismatch"),
        )));
    }
    Ok(ObjectRef {
        id: object_id,
        version: object_version.get(),
        digest: *digest,
    })
}

fn print_result(result: &PaidExecutionResult) {
    println!("paid_status={:?}", result.status);
    println!("gas_used={}", result.effects.gas_used);
    if let Some(charged) = &result.charged {
        println!("reserved_fee={}", charged.reserved.get());
        println!("actual_fee={}", charged.actual.get());
        println!("refund_fee={}", charged.refund.get());
        println!("fee_coin={}", charged.fee_output.id);
        if let Some(refund) = &charged.refund_output {
            println!("refund_coin={}", refund.id);
        }
    }
    for (index, effect) in result.effects.object_effects.iter().enumerate() {
        match effect {
            ObjectEffect::Created(object) => {
                println!("effect[{index}].kind=created");
                println!("effect[{index}].object={}", object.id);
            }
            ObjectEffect::Mutated { new_object, .. } => {
                println!("effect[{index}].kind=mutated");
                println!("effect[{index}].object={}", new_object.id);
            }
            ObjectEffect::Deleted { id, .. } => {
                println!("effect[{index}].kind=deleted");
                println!("effect[{index}].object={id}");
            }
        }
    }
}

fn validate_created_asset(
    result: &PaidExecutionResult,
    resolver: &HashSuiteResolver,
    expected: &ExpectedProtocolContext,
    owner: Address,
    origin: &sunrise_edge_client::PackageOrigin,
) -> Result<CreatedAsset, CliError> {
    if result.status != PaidExecutionStatus::Success {
        return Err(invalid("asset creation did not succeed"));
    }
    let charged = result
        .charged
        .as_ref()
        .ok_or_else(|| invalid("successful asset creation must be charged"))?;
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
    if created.len() != 2 {
        return Err(invalid(
            "asset initializer must create exactly Definition and TreasuryCap",
        ));
    }
    let definition_tag: ScopedTypeTag = definition_type_tag(origin).map_err(failure)?;
    let definition_type: Digest32 =
        derive_scoped_type_id(resolver, expected.epoch(), &definition_tag).map_err(failure)?;
    let definition: &Object = created
        .iter()
        .copied()
        .find(|object: &&Object| object.type_hash == definition_type)
        .ok_or_else(|| invalid("asset initializer omitted Definition"))?;
    let asset: ObjectId = definition.id;
    let cap_tag: ScopedTypeTag = treasury_cap_type_tag(origin, &asset).map_err(failure)?;
    let cap_type: Digest32 =
        derive_scoped_type_id(resolver, expected.epoch(), &cap_tag).map_err(failure)?;
    let cap: &Object = created
        .iter()
        .copied()
        .find(|object: &&Object| object.type_hash == cap_type)
        .ok_or_else(|| invalid("asset initializer omitted TreasuryCap"))?;
    let expected_owner: Owner = Owner::Address(owner);
    if definition.id == cap.id
        || definition.version != 1
        || cap.version != 1
        || definition.owner != expected_owner
        || cap.owner != expected_owner
        || definition.schema_version != SCHEMA_VERSION
        || cap.schema_version != SCHEMA_VERSION
        || definition.data != definition_body().map_err(failure)?
        || treasury_supply(&cap.data).map_err(failure)? != 0
    {
        return Err(invalid("invalid Standard Asset initializer effects"));
    }
    Ok(CreatedAsset {
        definition: asset,
        treasury_cap: cap.id,
    })
}

/// Runs Standard Asset creation or one of the five asset verbs through public
/// paid execution.
pub fn run<I>(action: &str, args: I) -> Result<(), CliError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut specs: Vec<FlagSpec> = common_specs();
    match action {
        "create-asset" => specs.extend([scalar(INSTANCE_SEED), scalar(INSTANCE_REF_OUT)]),
        "transfer" => specs.extend([
            scalar(COIN),
            scalar(RECIPIENT),
            scalar(ASSET),
            scalar(INSTANCE_REF),
        ]),
        "split" => specs.extend([
            scalar(COIN),
            scalar(AMOUNT),
            scalar(RECIPIENT),
            scalar(ASSET),
            scalar(INSTANCE_REF),
        ]),
        "merge" => specs.extend([
            scalar(INTO),
            scalar(FROM),
            scalar(ASSET),
            scalar(INSTANCE_REF),
        ]),
        "mint" => specs.extend([
            scalar(TREASURY_CAP),
            scalar(AMOUNT),
            scalar(RECIPIENT),
            scalar(ASSET),
            scalar(INSTANCE_REF),
        ]),
        "burn" => specs.extend([
            scalar(TREASURY_CAP),
            scalar(COIN),
            scalar(ASSET),
            scalar(INSTANCE_REF),
        ]),
        _ => return Err(invalid("unknown Standard Asset operation")),
    }
    let parsed: ParsedArgs = parse_flags(args, &specs)?;
    let signer: LocalSigner = match parse_signer_selection(&parsed)? {
        SignerSelection::Local { seed_file } => {
            LocalSigner::from_seed(load_dev_seed(Path::new(&seed_file))?)
        }
        SignerSelection::Ledger { .. } => {
            return Err(invalid(
                "Ledger paid Standard Asset signing is not supported",
            ));
        }
    };
    let create_asset_inputs: Option<([u8; 32], &str)> = if action == "create-asset" {
        Some((
            decode_hex_32(INSTANCE_SEED, parsed.require(INSTANCE_SEED)?)?,
            parsed.require(INSTANCE_REF_OUT)?,
        ))
    } else {
        None
    };
    let expected: ExpectedProtocolContext = parse_expected_context(&parsed)?;
    let resolver: HashSuiteResolver = local_publication_resolver(&expected)?;
    let client: Client<CliTransport> = connect_paid_execution(parsed.require(ENDPOINT)?, &parsed)?;
    let policy = client.query_paid_fee_policy(&resolver, &expected)?;
    let genesis_asset: ObjectId = policy_asset(&policy)?;

    let fee_source_id: ObjectId = object_id(&parsed, FEE_SOURCE)?;
    let queried_fee = client.query_object(fee_source_id)?;
    let fee_source: ObjectRef = sunrise_edge_client::current_inline_object_ref(&queried_fee)
        .ok_or_else(|| invalid("fee source must be a current inline object"))?;
    let refund_recipient: [u8; 32] = match parsed.get(REFUND_RECIPIENT) {
        Some(value) => decode_hex_32(REFUND_RECIPIENT, value)?,
        None => *signer.address().as_bytes(),
    };
    let consent = FeeSourceConsent {
        source: fee_source.clone(),
        access: ReservationAccessKind::Write,
        max_fee: Amount::new(parse_u64(MAX_FEE, parsed.require(MAX_FEE)?)?),
        refund_recipient,
    };
    client.validate_paid_fee_source(&signer, &resolver, &expected, &policy, &consent)?;

    let request_id: RequestId =
        RequestId::new(decode_hex_32(REQUEST_ID, parsed.require(REQUEST_ID)?)?)?;
    let nonce: u64 = match parsed.get(NONCE) {
        Some(value) => parse_u64(NONCE, value)?,
        None => {
            let value = client.query_next_nonce(signer.address())?;
            if value.epoch() != expected.epoch() {
                return Err(invalid("nonce epoch differs from expected context"));
            }
            value.next_nonce()
        }
    };
    let gas_limit: u64 = parse_u64(GAS_LIMIT, parsed.require(GAS_LIMIT)?)?;

    if let Some((instance_seed, instance_ref_out)) = create_asset_inputs {
        let interface =
            client.query_paid_executable_interface(&policy.code, &resolver, &expected)?;
        let expected_abi = executable_abi(policy.code.origin()).map_err(failure)?;
        if interface.executable_abi(policy.code.origin()) != Some(&expected_abi) {
            return Err(invalid(
                "installed fee code is not the exact public Standard Asset package",
            ));
        }
        let context: PublicationContext = policy.context.clone();
        let record: InstanceRecord = InstanceRecord {
            context: context.clone(),
            creator: *signer.address().as_bytes(),
            seed: instance_seed,
            code: policy.code.clone(),
            revision: 1,
            initializer: INITIALIZER.to_owned(),
        };
        let target: InstanceTarget = instance_target(&resolver, &record).map_err(failure)?;
        if target == policy.instance {
            return Err(invalid("asset instance collides with the fee instance"));
        }
        let call: CallIntent = CallIntent {
            context,
            request_id: *request_id.as_bytes(),
            sender: *signer.address().as_bytes(),
            nonce,
            code: record.code.clone(),
            instance: target,
            entrypoint: INITIALIZER.to_owned(),
            type_arguments: Vec::new(),
            access: AccessManifest::new(),
            arguments: no_arguments().map_err(failure)?,
            gas_limit,
        };
        let signed = build_signed_paid_execution(
            &signer,
            &resolver,
            &expected,
            &policy,
            consent,
            PaidApplication::Instantiate(call),
            request_id,
            nonce,
            gas_limit,
            Vec::new(),
        )?;
        let signed_bytes: Vec<u8> = encode_signed_paid_intent(&signed).map_err(failure)?;
        let record_bytes: Vec<u8> = encode_instance_record(&record).map_err(failure)?;
        let result: PaidExecutionResult = super::paid_execution::submit_with_outputs(
            parsed.get(RESULT_OUT),
            parsed.get(SUBMISSION_OUT),
            Some(instance_ref_out),
            &signed_bytes,
            Some(&record_bytes),
            request_id,
            nonce,
            || {
                client
                    .submit_paid_execution(&signed, &resolver)
                    .map_err(CliError::from)
            },
        )?;
        print_result(&result);
        if result.status != PaidExecutionStatus::Success {
            return Err(invalid(
                "paid Standard Asset creation rejected; replay identical signed bytes",
            ));
        }
        let created: CreatedAsset = validate_created_asset(
            &result,
            &resolver,
            &expected,
            signer.address(),
            policy.code.origin(),
        )
        .map_err(|error: CliError| {
            failure(std::io::Error::other(format!(
                "paid Standard Asset outcome and recovery files were persisted but result validation failed: {error}; request_id={request_id} nonce={nonce}; replay identical signed bytes with the same request ID and nonce; do not retry with a fresh nonce"
            )))
        })?;
        println!("asset={}", created.definition);
        println!("definition={}", created.definition);
        println!("treasury_cap={}", created.treasury_cap);
        println!("instance_creator={}", signer.address());
        println!("instance_seed={}", encode_hex(&record.seed));
        return Ok(());
    }

    let target: ApplicationTarget = select_application_target(
        &parsed,
        &client,
        &resolver,
        &expected,
        &policy,
        genesis_asset,
    )?;
    let operation: AssetOperation = operation(action, &parsed)?;
    let mut access: AccessManifest = AccessManifest::new();
    for (id, mode, kind, flag) in &operation.inputs {
        let tag: ScopedTypeTag = expected_tag(*kind, target.code.origin(), &target.asset)?;
        let reference: ObjectRef = if *id == fee_source.id {
            validate_owned_input(
                &queried_fee,
                &resolver,
                &expected,
                signer.address(),
                *id,
                &tag,
                flag,
            )?
        } else {
            owned_input(
                &client,
                &resolver,
                &expected,
                signer.address(),
                *id,
                &tag,
                flag,
            )?
        };
        access.entries.push(AccessEntry {
            object_ref: reference,
            mode: *mode,
        });
    }
    let call = CallIntent {
        context: policy.context.clone(),
        request_id: *request_id.as_bytes(),
        sender: *signer.address().as_bytes(),
        nonce,
        code: target.code,
        instance: target.instance,
        entrypoint: operation.entrypoint.to_owned(),
        type_arguments: target.type_arguments,
        access,
        arguments: operation.arguments,
        gas_limit,
    };
    let signed = build_signed_paid_execution(
        &signer,
        &resolver,
        &expected,
        &policy,
        consent,
        PaidApplication::Call(call),
        request_id,
        nonce,
        gas_limit,
        Vec::new(),
    )?;
    let signed_bytes: Vec<u8> = encode_signed_paid_intent(&signed).map_err(failure)?;
    let result: PaidExecutionResult = super::paid_execution::submit_with_outputs(
        parsed.get(RESULT_OUT),
        parsed.get(SUBMISSION_OUT),
        None,
        &signed_bytes,
        None,
        request_id,
        nonce,
        || {
            client
                .submit_paid_execution(&signed, &resolver)
                .map_err(CliError::from)
        },
    )?;
    print_result(&result);
    if result.status != PaidExecutionStatus::Success {
        return Err(invalid(
            "paid Standard Asset execution rejected; replay identical signed bytes",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::{
        call_values::{CallValue, encode_call_value},
        package_types::{PackageOrigin, derive_scoped_type_id},
    };
    use execution::{
        ExecutionEffects, ExecutionStatus,
        paid_execution::{PaidChargedOutcome, PaidResultKind, PaidResultTarget},
    };
    use objects::encode_object;
    use protocol_types::{Digest32, HashAlgorithmId};
    use runtime::{DurableObjectVersion, ObjectHeadRevision};

    struct ValidationFixture {
        object: Object,
        resolver: HashSuiteResolver,
        expected: ExpectedProtocolContext,
        owner: Address,
        object_id: ObjectId,
        tag: ScopedTypeTag,
    }

    struct CreatedAssetFixture {
        result: PaidExecutionResult,
        resolver: HashSuiteResolver,
        expected: ExpectedProtocolContext,
        owner: Address,
        origin: PackageOrigin,
        definition: ObjectId,
        treasury_cap: ObjectId,
    }

    fn validation_fixture() -> ValidationFixture {
        let chain_id: ChainId = ChainId::new("standard-asset-validation-test").unwrap();
        let expected: ExpectedProtocolContext = ExpectedProtocolContext::new(
            chain_id.clone(),
            ProtocolVersion::new(7),
            Epoch::new(9),
            HashSuiteId::new(1),
            ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID,
            SignatureSchemeId::Ed25519.as_u16(),
            ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_BINDING_ID,
            AtomicityDomainId::new([0x44; 32]).unwrap(),
        )
        .unwrap();
        let resolver: HashSuiteResolver = local_publication_resolver(&expected).unwrap();
        let origin: PackageOrigin =
            PackageOrigin::unverified(chain_id, [0x11; 32], [0x12; 32]).unwrap();
        let asset: ObjectId = ObjectId::new([0x13; 32]);
        let tag: ScopedTypeTag = coin_type_tag(&origin, &asset).unwrap();
        let object_id: ObjectId = ObjectId::new([0x14; 32]);
        let owner: Address = Address::new([0x15; 32]);
        let object: Object = Object {
            id: object_id,
            version: 3,
            owner: Owner::Address(owner),
            type_hash: derive_scoped_type_id(&resolver, expected.epoch(), &tag).unwrap(),
            schema_version: SCHEMA_VERSION,
            data: vec![0x16],
        };
        ValidationFixture {
            object,
            resolver,
            expected,
            owner,
            object_id,
            tag,
        }
    }

    fn inline_result(
        object: &Object,
        queried_id: ObjectId,
        object_version: u64,
        creating_chain_id: ChainId,
        creating_protocol_version: ProtocolVersion,
    ) -> HttpObjectQueryResult {
        HttpObjectQueryResult::CurrentInline {
            object_id: queried_id,
            head_revision: ObjectHeadRevision::new(1).unwrap(),
            object_version: DurableObjectVersion::new(object_version).unwrap(),
            digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x17; 32]),
            creating_chain_id,
            creating_protocol_version,
            canonical_object_bytes: encode_object(object).unwrap(),
        }
    }

    fn valid_result(fixture: &ValidationFixture) -> HttpObjectQueryResult {
        inline_result(
            &fixture.object,
            fixture.object_id,
            fixture.object.version,
            fixture.expected.chain_id().clone(),
            fixture.expected.protocol_version(),
        )
    }

    fn digest(byte: u8) -> Digest32 {
        Digest32::new(HashAlgorithmId::Sha2_256, [byte; 32])
    }

    fn created_asset_fixture() -> CreatedAssetFixture {
        let expected: ExpectedProtocolContext = validation_fixture().expected;
        let resolver: HashSuiteResolver = local_publication_resolver(&expected).unwrap();
        let owner: Address = LocalSigner::from_seed([0x31; 32]).address();
        let context: PublicationContext = PublicationContext::new(
            expected.chain_id().clone(),
            expected.protocol_version(),
            expected.epoch(),
        )
        .unwrap();
        let origin: PackageOrigin =
            PackageOrigin::unverified(expected.chain_id().clone(), [0x32; 32], [0x33; 32]).unwrap();
        let code: UnverifiedDependencyRef =
            UnverifiedDependencyRef::new(origin.clone(), 1, context.clone(), digest(0x34)).unwrap();
        let record: InstanceRecord = InstanceRecord {
            context,
            creator: *owner.as_bytes(),
            seed: [0x35; 32],
            code,
            revision: 1,
            initializer: INITIALIZER.to_owned(),
        };
        let definition: ObjectId = ObjectId::new([0x36; 32]);
        let treasury_cap: ObjectId = ObjectId::new([0x37; 32]);
        let fee_output: ObjectId = ObjectId::new([0x38; 32]);
        let definition_object: Object = Object {
            id: definition,
            version: 1,
            owner: Owner::Address(owner),
            type_hash: derive_scoped_type_id(
                &resolver,
                expected.epoch(),
                &definition_type_tag(&origin).unwrap(),
            )
            .unwrap(),
            schema_version: SCHEMA_VERSION,
            data: definition_body().unwrap(),
        };
        let cap_object: Object = Object {
            id: treasury_cap,
            version: 1,
            owner: Owner::Address(owner),
            type_hash: derive_scoped_type_id(
                &resolver,
                expected.epoch(),
                &treasury_cap_type_tag(&origin, &definition).unwrap(),
            )
            .unwrap(),
            schema_version: SCHEMA_VERSION,
            data: encode_call_value(
                &public_standard_asset::treasury_cap_body_layout(),
                &CallValue::U64(0),
            )
            .unwrap(),
        };
        let fee_object: Object = Object {
            id: fee_output,
            version: 1,
            owner: Owner::Address(owner),
            type_hash: digest(0x39),
            schema_version: SCHEMA_VERSION,
            data: vec![0x01],
        };
        let result: PaidExecutionResult = PaidExecutionResult {
            request_id: [0x3a; 32],
            kind: PaidResultKind::Instantiate,
            target: PaidResultTarget::Instance(record),
            status: PaidExecutionStatus::Success,
            effects: ExecutionEffects {
                tx_hash: digest(0x3b),
                status: ExecutionStatus::Success,
                object_effects: vec![
                    ObjectEffect::Created(fee_object),
                    ObjectEffect::Created(definition_object),
                    ObjectEffect::Created(cap_object),
                ],
                events: Vec::new(),
                gas_used: 1,
            },
            charged: Some(PaidChargedOutcome {
                reserved: Amount::new(1),
                actual: Amount::new(1),
                refund: Amount::new(0),
                fee_output: ObjectRef {
                    id: fee_output,
                    version: 1,
                    digest: digest(0x3c),
                },
                refund_output: None,
                reservation: ObjectId::new([0x3d; 32]),
                application_gas_units: 1,
            }),
        };
        CreatedAssetFixture {
            result,
            resolver,
            expected,
            owner,
            origin,
            definition,
            treasury_cap,
        }
    }

    fn created_object_mut(result: &mut PaidExecutionResult, id: ObjectId) -> &mut Object {
        result
            .effects
            .object_effects
            .iter_mut()
            .find_map(|effect: &mut ObjectEffect| match effect {
                ObjectEffect::Created(object) if object.id == id => Some(object),
                _ => None,
            })
            .unwrap()
    }

    fn parsed(values: &[&str], specs: &[FlagSpec]) -> ParsedArgs {
        parse_flags(values.iter().map(OsString::from), specs).unwrap()
    }

    #[test]
    fn owned_input_validation_accepts_exact_current_object() {
        let fixture: ValidationFixture = validation_fixture();
        let reference: ObjectRef = validate_owned_input(
            &valid_result(&fixture),
            &fixture.resolver,
            &fixture.expected,
            fixture.owner,
            fixture.object_id,
            &fixture.tag,
            COIN,
        )
        .unwrap();
        assert_eq!(reference.id, fixture.object_id);
        assert_eq!(reference.version, fixture.object.version);
    }

    #[test]
    fn owned_input_validation_rejects_non_current_and_wrong_provenance() {
        let fixture: ValidationFixture = validation_fixture();
        let check = |result: &HttpObjectQueryResult| {
            validate_owned_input(
                result,
                &fixture.resolver,
                &fixture.expected,
                fixture.owner,
                fixture.object_id,
                &fixture.tag,
                COIN,
            )
            .is_err()
        };
        assert!(check(&HttpObjectQueryResult::Absent {
            object_id: fixture.object_id,
        }));
        assert!(check(&inline_result(
            &fixture.object,
            ObjectId::new([0x18; 32]),
            fixture.object.version,
            fixture.expected.chain_id().clone(),
            fixture.expected.protocol_version(),
        )));
        assert!(check(&inline_result(
            &fixture.object,
            fixture.object_id,
            fixture.object.version,
            ChainId::new("wrong-chain").unwrap(),
            fixture.expected.protocol_version(),
        )));
        assert!(check(&inline_result(
            &fixture.object,
            fixture.object_id,
            fixture.object.version,
            fixture.expected.chain_id().clone(),
            ProtocolVersion::new(6),
        )));
    }

    #[test]
    fn owned_input_validation_rejects_wrong_version_owner_schema_and_type() {
        let fixture: ValidationFixture = validation_fixture();
        let check = |object: &Object, queried_version: u64| {
            validate_owned_input(
                &inline_result(
                    object,
                    fixture.object_id,
                    queried_version,
                    fixture.expected.chain_id().clone(),
                    fixture.expected.protocol_version(),
                ),
                &fixture.resolver,
                &fixture.expected,
                fixture.owner,
                fixture.object_id,
                &fixture.tag,
                COIN,
            )
            .is_err()
        };
        assert!(check(&fixture.object, fixture.object.version + 1));

        let mut wrong_owner: Object = fixture.object.clone();
        wrong_owner.owner = Owner::Address(Address::new([0x19; 32]));
        assert!(check(&wrong_owner, wrong_owner.version));

        let mut wrong_schema: Object = fixture.object.clone();
        wrong_schema.schema_version = SCHEMA_VERSION + 1;
        assert!(check(&wrong_schema, wrong_schema.version));

        let mut wrong_type: Object = fixture.object.clone();
        wrong_type.type_hash = Digest32::new(HashAlgorithmId::Sha2_256, [0x20; 32]);
        assert!(check(&wrong_type, wrong_type.version));
    }

    #[test]
    fn application_instance_validation_pins_canonical_context_code_and_remote_record() {
        let fixture: CreatedAssetFixture = created_asset_fixture();
        let record: InstanceRecord = match &fixture.result.target {
            PaidResultTarget::Instance(record) => record.clone(),
            PaidResultTarget::Package(_) => unreachable!(),
        };
        let encoded: Vec<u8> = encode_instance_record(&record).unwrap();
        assert_eq!(decode_instance_record(&encoded).unwrap(), record);
        let mut trailing: Vec<u8> = encoded;
        trailing.push(0);
        assert!(decode_instance_record(&trailing).is_err());
        assert!(validate_application_instance_pin(&record, &record.context, &record.code).is_ok());

        let mut wrong_context: InstanceRecord = record.clone();
        wrong_context.context = PublicationContext::new(
            fixture.expected.chain_id().clone(),
            ProtocolVersion::new(fixture.expected.protocol_version().get() + 1),
            fixture.expected.epoch(),
        )
        .unwrap();
        assert!(
            validate_application_instance_pin(&wrong_context, &record.context, &record.code,)
                .is_err()
        );

        let mut wrong_code: InstanceRecord = record.clone();
        wrong_code.code = UnverifiedDependencyRef::new(
            record.code.origin().clone(),
            record.code.revision(),
            record.code.context().clone(),
            digest(0x3e),
        )
        .unwrap();
        assert!(
            validate_application_instance_pin(&wrong_code, &record.context, &record.code,).is_err()
        );

        let mut wrong_initializer: InstanceRecord = record.clone();
        wrong_initializer.initializer = "other".to_owned();
        assert!(
            validate_application_instance_pin(&wrong_initializer, &record.context, &record.code,)
                .is_err()
        );
        assert!(validate_remote_instance(&record, None).is_err());
        let mut different_remote: InstanceRecord = record.clone();
        different_remote.seed = [0x3f; 32];
        assert!(validate_remote_instance(&record, Some(&different_remote)).is_err());
    }

    #[test]
    fn definition_validation_rejects_non_current_provenance_owner_schema_body_and_type() {
        let fixture: CreatedAssetFixture = created_asset_fixture();
        let definition: Object =
            created_object_mut(&mut fixture.result.clone(), fixture.definition).clone();
        let tag: ScopedTypeTag = definition_type_tag(&fixture.origin).unwrap();
        let valid: HttpObjectQueryResult = inline_result(
            &definition,
            fixture.definition,
            1,
            fixture.expected.chain_id().clone(),
            fixture.expected.protocol_version(),
        );
        assert!(
            validate_definition(
                &valid,
                &fixture.resolver,
                &fixture.expected,
                fixture.definition,
                &tag,
            )
            .is_ok()
        );
        assert!(
            validate_definition(
                &HttpObjectQueryResult::Absent {
                    object_id: fixture.definition,
                },
                &fixture.resolver,
                &fixture.expected,
                fixture.definition,
                &tag,
            )
            .is_err()
        );

        let check = |object: &Object,
                     queried_id: ObjectId,
                     version: u64,
                     chain: ChainId,
                     protocol: ProtocolVersion| {
            validate_definition(
                &inline_result(object, queried_id, version, chain, protocol),
                &fixture.resolver,
                &fixture.expected,
                fixture.definition,
                &tag,
            )
            .is_err()
        };
        assert!(check(
            &definition,
            ObjectId::new([0x40; 32]),
            1,
            fixture.expected.chain_id().clone(),
            fixture.expected.protocol_version(),
        ));
        assert!(check(
            &definition,
            fixture.definition,
            1,
            ChainId::new("wrong-chain").unwrap(),
            fixture.expected.protocol_version(),
        ));
        assert!(check(
            &definition,
            fixture.definition,
            1,
            fixture.expected.chain_id().clone(),
            ProtocolVersion::new(8),
        ));
        assert!(check(
            &definition,
            fixture.definition,
            2,
            fixture.expected.chain_id().clone(),
            fixture.expected.protocol_version(),
        ));

        let mut wrong_owner: Object = definition.clone();
        wrong_owner.owner = Owner::Immutable;
        assert!(check(
            &wrong_owner,
            fixture.definition,
            1,
            fixture.expected.chain_id().clone(),
            fixture.expected.protocol_version(),
        ));
        let mut wrong_schema: Object = definition.clone();
        wrong_schema.schema_version += 1;
        assert!(check(
            &wrong_schema,
            fixture.definition,
            1,
            fixture.expected.chain_id().clone(),
            fixture.expected.protocol_version(),
        ));
        let mut wrong_body: Object = definition.clone();
        wrong_body.data.push(0);
        assert!(check(
            &wrong_body,
            fixture.definition,
            1,
            fixture.expected.chain_id().clone(),
            fixture.expected.protocol_version(),
        ));
        let mut wrong_type: Object = definition;
        wrong_type.type_hash = digest(0x41);
        assert!(check(
            &wrong_type,
            fixture.definition,
            1,
            fixture.expected.chain_id().clone(),
            fixture.expected.protocol_version(),
        ));
    }

    #[test]
    fn created_asset_validation_pins_exact_effect_shape_and_initial_state() {
        let fixture: CreatedAssetFixture = created_asset_fixture();
        assert_eq!(
            validate_created_asset(
                &fixture.result,
                &fixture.resolver,
                &fixture.expected,
                fixture.owner,
                &fixture.origin,
            )
            .unwrap(),
            CreatedAsset {
                definition: fixture.definition,
                treasury_cap: fixture.treasury_cap,
            }
        );

        let check = |result: &PaidExecutionResult| {
            validate_created_asset(
                result,
                &fixture.resolver,
                &fixture.expected,
                fixture.owner,
                &fixture.origin,
            )
            .is_err()
        };
        let mut failed: PaidExecutionResult = fixture.result.clone();
        failed.status = PaidExecutionStatus::ApplicationFailed;
        assert!(check(&failed));
        let mut uncharged: PaidExecutionResult = fixture.result.clone();
        uncharged.charged = None;
        assert!(check(&uncharged));
        let mut missing_cap: PaidExecutionResult = fixture.result.clone();
        missing_cap.effects.object_effects.pop();
        assert!(check(&missing_cap));
        let mut extra: PaidExecutionResult = fixture.result.clone();
        extra
            .effects
            .object_effects
            .push(ObjectEffect::Created(Object {
                id: ObjectId::new([0x42; 32]),
                version: 1,
                owner: Owner::Address(fixture.owner),
                type_hash: digest(0x42),
                schema_version: SCHEMA_VERSION,
                data: Vec::new(),
            }));
        assert!(check(&extra));
        let mut missing_definition: PaidExecutionResult = fixture.result.clone();
        created_object_mut(&mut missing_definition, fixture.definition).type_hash = digest(0x43);
        assert!(check(&missing_definition));
        let mut wrong_cap_type: PaidExecutionResult = fixture.result.clone();
        created_object_mut(&mut wrong_cap_type, fixture.treasury_cap).type_hash = digest(0x44);
        assert!(check(&wrong_cap_type));

        for mutate in [
            |object: &mut Object| object.version = 2,
            |object: &mut Object| object.owner = Owner::Address(Address::new([0x45; 32])),
            |object: &mut Object| object.schema_version = SCHEMA_VERSION + 1,
            |object: &mut Object| object.data.push(0),
        ] {
            let mut changed: PaidExecutionResult = fixture.result.clone();
            mutate(created_object_mut(&mut changed, fixture.definition));
            assert!(check(&changed));
        }
        let mut nonzero_supply: PaidExecutionResult = fixture.result.clone();
        created_object_mut(&mut nonzero_supply, fixture.treasury_cap).data = encode_call_value(
            &public_standard_asset::treasury_cap_body_layout(),
            &CallValue::U64(1),
        )
        .unwrap();
        assert!(check(&nonzero_supply));
        let mut wrong_cap_owner: PaidExecutionResult = fixture.result.clone();
        created_object_mut(&mut wrong_cap_owner, fixture.treasury_cap).owner = Owner::Immutable;
        assert!(check(&wrong_cap_owner));
    }

    #[test]
    fn operation_builders_pin_order_modes_and_public_arguments() {
        let coin_a: String = "11".repeat(32);
        let coin_b: String = "22".repeat(32);
        let cap: String = "33".repeat(32);
        let recipient: String = "44".repeat(32);

        let transfer = parsed(
            &[COIN, &coin_a, RECIPIENT, &recipient],
            &[scalar(COIN), scalar(RECIPIENT)],
        );
        let transfer_op: AssetOperation = operation("transfer", &transfer).unwrap();
        assert_eq!(transfer_op.entrypoint, "transfer");
        assert_eq!(transfer_op.inputs.len(), 1);
        assert_eq!(transfer_op.inputs[0].1, AccessMode::Write);
        assert_eq!(
            transfer_op.arguments,
            transfer_arguments(&[0x44; 32]).unwrap()
        );

        let split = parsed(
            &[COIN, &coin_a, AMOUNT, "7", RECIPIENT, &recipient],
            &[scalar(COIN), scalar(AMOUNT), scalar(RECIPIENT)],
        );
        let split_op: AssetOperation = operation("split", &split).unwrap();
        assert_eq!(split_op.entrypoint, "split");
        assert_eq!(split_op.inputs[0].1, AccessMode::Write);
        assert_eq!(split_op.arguments, split_arguments(7, &[0x44; 32]).unwrap());

        let merge = parsed(
            &[INTO, &coin_a, FROM, &coin_b],
            &[scalar(INTO), scalar(FROM)],
        );
        let merge_op: AssetOperation = operation("merge", &merge).unwrap();
        assert_eq!(merge_op.entrypoint, "merge");
        assert_eq!(merge_op.inputs[0].1, AccessMode::Write);
        assert_eq!(merge_op.inputs[1].1, AccessMode::Consume);
        assert_eq!(merge_op.arguments, no_arguments().unwrap());

        let mint = parsed(
            &[TREASURY_CAP, &cap, AMOUNT, "9", RECIPIENT, &recipient],
            &[scalar(TREASURY_CAP), scalar(AMOUNT), scalar(RECIPIENT)],
        );
        let mint_op: AssetOperation = operation("mint", &mint).unwrap();
        assert_eq!(mint_op.entrypoint, "mint");
        assert_eq!(mint_op.inputs[0].1, AccessMode::Write);
        assert_eq!(mint_op.arguments, mint_arguments(9, &[0x44; 32]).unwrap());

        let burn = parsed(
            &[TREASURY_CAP, &cap, COIN, &coin_a],
            &[scalar(TREASURY_CAP), scalar(COIN)],
        );
        let burn_op: AssetOperation = operation("burn", &burn).unwrap();
        assert_eq!(burn_op.entrypoint, "burn");
        assert_eq!(burn_op.inputs[0].1, AccessMode::Write);
        assert_eq!(burn_op.inputs[1].1, AccessMode::Consume);
        assert_eq!(burn_op.arguments, no_arguments().unwrap());
    }

    #[test]
    fn merge_rejects_one_object_in_both_roles() {
        let coin: String = "11".repeat(32);
        let parsed = parsed(&[INTO, &coin, FROM, &coin], &[scalar(INTO), scalar(FROM)]);
        assert!(operation("merge", &parsed).is_err());
    }

    #[test]
    fn public_asset_commands_reject_legacy_module_flags() {
        let specs: Vec<FlagSpec> = common_specs();
        let error = parse_flags(
            [OsString::from("--module-id"), OsString::from("00")],
            &specs,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            crate::args::ArgsError::UnknownFlag(flag) if flag == "--module-id"
        ));
    }

    #[test]
    fn application_asset_and_instance_selection_are_all_or_none() {
        let asset: String = "31".repeat(32);
        let both: ParsedArgs = parsed(
            &[ASSET, &asset, INSTANCE_REF, "/tmp/instance.ref"],
            &[scalar(ASSET), scalar(INSTANCE_REF)],
        );
        assert_eq!(
            application_selection(&both).unwrap(),
            Some((ObjectId::new([0x31; 32]), "/tmp/instance.ref"))
        );

        let only_asset: ParsedArgs =
            parsed(&[ASSET, &asset], &[scalar(ASSET), scalar(INSTANCE_REF)]);
        assert!(application_selection(&only_asset).is_err());
        let only_instance: ParsedArgs = parsed(
            &[INSTANCE_REF, "/tmp/instance.ref"],
            &[scalar(ASSET), scalar(INSTANCE_REF)],
        );
        assert!(application_selection(&only_instance).is_err());
    }

    #[test]
    fn ledger_selection_is_rejected_before_endpoint_or_device_access() {
        let error = run(
            "transfer",
            [
                OsString::from("--ledger-hid-path"),
                OsString::from("/definitely/not/a/device"),
                OsString::from("--ledger-account"),
                OsString::from("0"),
                OsString::from("--ledger-expected-firmware-version"),
                OsString::from("1.0.0"),
            ],
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Ledger paid Standard Asset signing is not supported")
        );
    }

    #[test]
    fn create_asset_rejects_ledger_before_endpoint_or_device_access() {
        let error = run(
            "create-asset",
            [
                OsString::from("--ledger-hid-path"),
                OsString::from("/definitely/not/a/device"),
                OsString::from("--ledger-account"),
                OsString::from("0"),
                OsString::from("--ledger-expected-firmware-version"),
                OsString::from("1.0.0"),
            ],
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Ledger paid Standard Asset signing is not supported")
        );
    }
}
