#![forbid(unsafe_code)]

//! Local-only Developer MVP devnet foundations.
//!
//! This crate owns strict process configuration, fenced SQLite startup,
//! restart-safe outbox attempt identities, the preinstalled Standard Asset
//! v1 whole-coin transfer module/catalog, and idempotent coin seeding. Its
//! binary composes these pieces into the bounded native HTTP router.

pub mod boot;
pub mod catalog;
pub mod composition;
pub mod config;
pub mod fee;
pub mod genesis;
pub mod identities;
pub mod local_execution;
pub mod machine;
pub mod publication;
pub mod seed;
pub mod standard_asset;
pub mod transport;

pub use boot::{
    DEVNET_BLOB_DATABASE_FILE, DEVNET_DATABASE_FILE, DevnetBoot, DevnetBootError, boot_local_store,
};
pub use catalog::{DevnetAssetModule, DevnetCatalogError, build_standard_asset_module};
pub use composition::{
    DevnetCompositionError, compose_devnet_router, compose_devnet_router_with_publication,
};
pub use config::{
    DEVNET_STARTUP_LIMITATIONS_BANNER, DevOwner, DevnetConfig, DevnetConfigError,
    MAX_DEVNET_CONCURRENCY, MAX_DEVNET_OWNERS,
};
pub use fee::StandardAssetCoinFeeComposer;
pub use genesis::{DevnetGenesisError, DevnetProtocolContext, build_devnet_protocol_context};
pub use identities::DevnetOutboxIdentitySource;
pub use machine::DevnetMachine;
pub use seed::{
    DevnetSeedError, SeedAssetAuthorityObjectsOutcome, SeedDevOwnerCoinsOutcome,
    SeedTreasuryCoinOutcome, SeededAssetAuthorityObjects, SeededDevOwnerCoins, SeededTreasuryCoin,
    seed_asset_authority_objects, seed_dev_owner_coins, seed_treasury_coin,
    verify_or_seed_protocol_context, verify_seeded_asset_supply,
};
pub use standard_asset::{
    BURN_ENTRYPOINT, MERGE_ENTRYPOINT, MINT_ENTRYPOINT, SPLIT_ENTRYPOINT,
    STANDARD_ASSET_MODULE_WASM, TRANSFER_ENTRYPOINT, derive_devnet_asset_id,
};
pub use transport::DevnetTransport;
