#![forbid(unsafe_code)]

use execution::publication::PublicationContext;
use native_http::{NativeHttpServePolicy, PaidExecutionComposition, serve_with_policy};
use protocol_types::AtomicityDomainId;
use runtime::{Clock, DurableOperationContext, StorageCorrelationId, StorageDeadline, SystemClock};
use std::{error::Error, process::ExitCode, sync::Arc};
use sunrise_edge_devnet::{
    DEVNET_BLOB_DATABASE_FILE, DEVNET_DATABASE_FILE, DEVNET_STARTUP_LIMITATIONS_BANNER,
    DevnetConfig, boot_local_store, build_devnet_protocol_context,
    compose_devnet_router_with_execution_policies, genesis::DEVNET_DOMAIN_BYTES,
    install_paid_contracts, verify_or_seed_protocol_context,
};

const SEED_OPERATION_TIMEOUT_MILLIS: u64 = 30_000;

async fn run() -> Result<(), Box<dyn Error>> {
    let config: DevnetConfig = DevnetConfig::parse_from(std::env::args_os().skip(1))?;
    let boot = boot_local_store(&config)?;
    let boot_generation = boot.boot_generation();
    let database_path = boot.database_path().to_path_buf();
    let blob_database_path = boot.blob_database_path().to_path_buf();
    let protocol_context =
        build_devnet_protocol_context(config.chain_id().clone(), config.epoch())?;

    let operation_context_for = |sequence: u64| -> Result<DurableOperationContext, Box<dyn Error>> {
        let now_unix_millis: u64 = SystemClock.now_unix_millis()?;
        let seed_deadline_unix_millis: u64 = now_unix_millis
            .checked_add(SEED_OPERATION_TIMEOUT_MILLIS)
            .ok_or("seed deadline overflow")?;
        let seed_deadline =
            StorageDeadline::new(seed_deadline_unix_millis).ok_or("invalid seed deadline")?;
        let mut correlation_bytes: [u8; 16] = [0; 16];
        correlation_bytes[..8].copy_from_slice(&boot_generation.get().to_be_bytes());
        correlation_bytes[8..].copy_from_slice(&sequence.to_be_bytes());
        let correlation_id = StorageCorrelationId::new(correlation_bytes)
            .ok_or("invalid seed correlation identity")?;
        Ok(DurableOperationContext::new(
            boot_generation,
            seed_deadline,
            correlation_id,
        ))
    };

    // The fixed, protocol-version-independent marker makes reuse of an old
    // development database fail closed before any v7 genesis state is added.
    let object_store_was_empty: bool = boot.store().object_store_is_empty()?;
    let mut next_sequence: u64 = 0;
    verify_or_seed_protocol_context(
        boot.store(),
        protocol_context.resolver(),
        config.epoch(),
        boot_generation,
        &operation_context_for(next_sequence)?,
        object_store_was_empty,
    )?;
    next_sequence = next_sequence
        .checked_add(1)
        .ok_or("protocol context correlation overflow")?;

    // Paid contract genesis is mandatory and is installed or verified on
    // every boot immediately after the durable protocol marker (DR-0127).
    let domain = AtomicityDomainId::new(DEVNET_DOMAIN_BYTES)?;
    let publication_context = PublicationContext::new(
        config.chain_id().clone(),
        protocol_context.resolver().protocol_version(),
        config.epoch(),
    )?;
    let activation = install_paid_contracts(
        boot.store(),
        &operation_context_for(next_sequence)?,
        domain,
        protocol_context.resolver(),
        &publication_context,
        config.dev_owners(),
        config.fee_recipient(),
    )?;
    next_sequence = next_sequence
        .checked_add(1)
        .ok_or("paid genesis correlation overflow")?;
    let paid_genesis_status: &str = match activation.outcome {
        node_core::genesis::GenesisInstallOutcome::FreshInstall { .. } => "created",
        node_core::genesis::GenesisInstallOutcome::VerifiedExisting { .. } => "verified-existing",
    };

    let publication = if config.local_publication() {
        let policy = sunrise_edge_devnet::publication::seed_local_publication_policy(
            boot.store(),
            &operation_context_for(next_sequence)?,
            domain,
            protocol_context.resolver(),
            config.epoch(),
        )?;
        next_sequence = next_sequence
            .checked_add(1)
            .ok_or("publication seed correlation overflow")?;
        println!(
            "local_publication=true publication_fees=false local_execution={}",
            config.local_execution()
        );
        Some(policy)
    } else {
        None
    };

    let mut local_execution = if config.local_execution() {
        let policies = sunrise_edge_devnet::local_execution::seed_local_execution_policies(
            boot.store(),
            &operation_context_for(next_sequence)?,
            domain,
            protocol_context.resolver(),
            config.epoch(),
        )?;
        next_sequence = next_sequence
            .checked_add(1)
            .ok_or("execution seed correlation overflow")?;
        println!("local_execution=true execution_fees=false publication_profiles=1,2");
        Some(native_http::LocalExecutionComposition::new(
            policies.0, policies.1,
        ))
    } else {
        None
    };

    if config.general_calls() {
        let (publication, policy) =
            sunrise_edge_devnet::local_execution::seed_general_execution_policies(
                boot.store(),
                &operation_context_for(next_sequence)?,
                domain,
                protocol_context.resolver(),
                config.epoch(),
            )?;
        next_sequence = next_sequence
            .checked_add(1)
            .ok_or("general execution seed correlation overflow")?;
        local_execution = Some(
            local_execution
                .ok_or("general calls require local execution")?
                .with_policy(publication, policy),
        );
        println!("general_calls=true execution_fees=false publication_profiles=1,2,3");
    }

    let paid_execution: PaidExecutionComposition =
        PaidExecutionComposition::new(activation.base_policy, activation.fee_policy);

    let (store, blob_store) = boot.into_parts();
    let store = Arc::new(store);
    let blob_store = Arc::new(blob_store);
    let reserved_correlation_sequences = usize::try_from(next_sequence)?;
    let router = compose_devnet_router_with_execution_policies(
        store,
        blob_store,
        protocol_context,
        boot_generation,
        config.max_concurrent(),
        reserved_correlation_sequences,
        publication,
        local_execution,
        paid_execution,
    )?;
    let listener = tokio::net::TcpListener::bind(config.listen()).await?;

    println!("Sunrise Edge local devnet initialized.");
    println!("chain_id={}", config.chain_id());
    println!("epoch={}", config.epoch().get());
    println!("listen={}", listener.local_addr()?);
    println!("database={}", database_path.display());
    println!("database_file={DEVNET_DATABASE_FILE}");
    println!("blob_database={}", blob_database_path.display());
    println!("blob_database_file={DEVNET_BLOB_DATABASE_FILE}");
    println!("boot_generation={}", boot_generation.get());
    println!("dev_owners={}", config.dev_owners().len());
    println!("fee_recipient={}", config.fee_recipient());
    println!("mint_authority={}", activation.metadata.mint_authority);
    println!("paid_genesis_status={paid_genesis_status}");
    println!("paid_manifest_digest={}", activation.manifest_digest);
    println!(
        "standard_asset_definition={} standard_asset_treasury_cap={}",
        activation.metadata.definition_id, activation.metadata.treasury_cap_id
    );
    println!(
        "standard_asset_instance={} standard_asset_code={}",
        activation.metadata.instance.record_digest,
        activation.metadata.code.artifact_digest()
    );
    for owner_coins in &activation.metadata.owner_coins {
        println!(
            "owner={} fee_coin={} spend_coin={}",
            owner_coins.owner, owner_coins.fee_coin, owner_coins.spend_coin
        );
    }
    println!("max_concurrent={}", config.max_concurrent());
    println!("limitations={DEVNET_STARTUP_LIMITATIONS_BANNER}");
    println!("Press Ctrl-C to stop.");

    let serve_policy = NativeHttpServePolicy::default()
        .with_local_publication(config.local_publication())
        .with_local_execution(config.local_execution());
    serve_with_policy(listener, router, serve_policy, async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            eprintln!("failed to install Ctrl-C handler: {error}");
        }
    })
    .await?;
    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("sunrise-edge-devnet failed: {error}");
            ExitCode::FAILURE
        }
    }
}
