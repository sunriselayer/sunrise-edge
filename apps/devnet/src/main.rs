#![forbid(unsafe_code)]

use native_http::serve;
use objects::ObjectId;
use runtime::{Clock, DurableOperationContext, StorageCorrelationId, StorageDeadline, SystemClock};
use std::{error::Error, process::ExitCode, sync::Arc};
use sunrise_edge_devnet::{
    DEVNET_BLOB_DATABASE_FILE, DEVNET_DATABASE_FILE, DEVNET_STARTUP_LIMITATIONS_BANNER,
    DevnetConfig, STANDARD_ASSET_MODULE_WASM, SeedAssetAuthorityObjectsOutcome,
    SeedDevOwnerCoinsOutcome, boot_local_store, build_devnet_protocol_context,
    build_standard_asset_module, compose_devnet_router, seed_asset_authority_objects,
    seed_dev_owner_coins, seed_treasury_coin, verify_or_seed_protocol_context,
    verify_seeded_asset_supply,
};

const SEED_OPERATION_TIMEOUT_MILLIS: u64 = 30_000;

/// The highest operational correlation sequence assigned while seeding one
/// boot: `0` for the protocol context, `1` for the asset authority,
/// `2..=N+1` for the `N` dev owners, and `N+2` for the treasury. Outbox
/// identities must be reserved strictly past this value, or the treasury
/// seed's correlation ID collides with the first outbox attempt.
fn highest_seed_correlation_sequence(dev_owner_count: usize) -> Result<usize, &'static str> {
    dev_owner_count
        .checked_add(2)
        .ok_or("seed correlation sequence overflow")
}

async fn run() -> Result<(), Box<dyn Error>> {
    let config: DevnetConfig = DevnetConfig::parse_from(std::env::args_os().skip(1))?;
    let boot = boot_local_store(&config)?;
    let boot_generation = boot.boot_generation();
    let database_path = boot.database_path().to_path_buf();
    let blob_database_path = boot.blob_database_path().to_path_buf();
    let protocol_context =
        build_devnet_protocol_context(config.chain_id().clone(), config.epoch())?;
    let asset_id = protocol_context.asset_id();
    let asset_module =
        build_standard_asset_module(protocol_context, STANDARD_ASSET_MODULE_WASM.to_vec())?;
    let module_ref = asset_module.module_ref().clone();

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

    let object_store_was_empty: bool = boot.store().object_store_is_empty()?;
    verify_or_seed_protocol_context(
        boot.store(),
        asset_module.resolver(),
        config.epoch(),
        boot_generation,
        &operation_context_for(0)?,
        object_store_was_empty,
    )?;

    let mint_authority = config
        .dev_owners()
        .first()
        .copied()
        .ok_or("devnet requires at least one configured dev owner")?;
    let asset_authority_outcome = seed_asset_authority_objects(
        boot.store(),
        boot.blob_store(),
        asset_module.resolver(),
        config.epoch(),
        asset_id,
        mint_authority,
        config.dev_owners().len(),
        boot_generation,
        &operation_context_for(1)?,
    )?;
    let asset_authority_status: &str = match &asset_authority_outcome {
        SeedAssetAuthorityObjectsOutcome::Created(_) => "created",
        SeedAssetAuthorityObjectsOutcome::Existing(_) => "verified-existing",
    };
    println!(
        "owner={} role=mint-authority seed_status={} asset_definition={} treasury_cap={}",
        mint_authority,
        asset_authority_status,
        asset_authority_outcome.objects().definition().id,
        asset_authority_outcome.objects().treasury_cap().id
    );

    let mut seed_outcomes: Vec<SeedDevOwnerCoinsOutcome> =
        Vec::with_capacity(config.dev_owners().len());
    for (index, owner) in config.dev_owners().iter().copied().enumerate() {
        let sequence: u64 = u64::try_from(index)?
            .checked_add(2)
            .ok_or("seed correlation sequence overflow")?;
        let outcome = seed_dev_owner_coins(
            boot.store(),
            boot.blob_store(),
            asset_module.resolver(),
            config.epoch(),
            asset_id,
            owner,
            boot_generation,
            &operation_context_for(sequence)?,
        )?;
        let seed_status: &str = match &outcome {
            SeedDevOwnerCoinsOutcome::Created(_) => "created",
            SeedDevOwnerCoinsOutcome::Existing(_) => "verified-existing",
        };
        println!(
            "owner={} role=dev-owner seed_status={} transfer_coin={} fee_coin={}",
            owner,
            seed_status,
            outcome.coins().transfer_coin().id,
            outcome.coins().fee_coin().id
        );
        seed_outcomes.push(outcome);
    }

    let highest_seed_sequence: usize =
        highest_seed_correlation_sequence(config.dev_owners().len())?;
    let treasury_sequence: u64 = u64::try_from(highest_seed_sequence)?;
    let treasury_outcome = seed_treasury_coin(
        boot.store(),
        boot.blob_store(),
        asset_module.resolver(),
        config.epoch(),
        asset_id,
        config.fee_treasury_owner(),
        boot_generation,
        &operation_context_for(treasury_sequence)?,
    )?;
    let treasury_status: &str = match &treasury_outcome {
        sunrise_edge_devnet::SeedTreasuryCoinOutcome::Created(_) => "created",
        sunrise_edge_devnet::SeedTreasuryCoinOutcome::Existing(_) => "verified-existing",
    };
    println!(
        "owner={} role=fee-treasury seed_status={} treasury_coin={}",
        config.fee_treasury_owner(),
        treasury_status,
        treasury_outcome.coin().coin().id
    );

    verify_seeded_asset_supply(&seed_outcomes, &treasury_outcome)?;
    let fee_treasury_object_id: ObjectId = treasury_outcome.coin().coin().id;

    let (store, blob_store) = boot.into_parts();
    let store = Arc::new(store);
    let blob_store = Arc::new(blob_store);
    let router = compose_devnet_router(
        store,
        blob_store,
        asset_module,
        boot_generation,
        config.max_concurrent(),
        highest_seed_sequence,
        fee_treasury_object_id,
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
    println!(
        "asset_id={} module_id={} module_version={} module_digest={}",
        asset_id, module_ref.id, module_ref.version, module_ref.digest
    );
    println!("dev_owners={}", config.dev_owners().len());
    println!("fee_treasury_owner={}", config.fee_treasury_owner());
    println!("fee_treasury_object={fee_treasury_object_id}");
    println!("max_concurrent={}", config.max_concurrent());
    println!("limitations={DEVNET_STARTUP_LIMITATIONS_BANNER}");
    println!("Press Ctrl-C to stop.");

    serve(listener, router, async {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn highest_seed_correlation_sequence_covers_authority_owners_and_treasury() {
        // sequence 0 is the protocol context, 1 is the asset authority,
        // 2..=N+1 are the N dev owners, and N+2 is the treasury: the router's
        // outbox identities must be reserved through that treasury sequence
        // so the first outbox attempt cannot collide with it.
        assert_eq!(highest_seed_correlation_sequence(0).unwrap(), 2);
        assert_eq!(highest_seed_correlation_sequence(1).unwrap(), 3);
        assert_eq!(highest_seed_correlation_sequence(5).unwrap(), 7);
    }

    #[test]
    fn highest_seed_correlation_sequence_rejects_overflow() {
        assert_eq!(
            highest_seed_correlation_sequence(usize::MAX),
            Err("seed correlation sequence overflow")
        );
    }
}
