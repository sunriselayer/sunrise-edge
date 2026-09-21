#![forbid(unsafe_code)]

//! Local-only Developer MVP devnet foundations.
//!
//! This crate owns strict process configuration, fenced SQLite startup,
//! restart-safe outbox attempt identities, the fail-closed protocol-context
//! marker, and the installed public Standard Asset paid-contract genesis
//! (DR-0127). Its binary composes these pieces into the bounded native HTTP
//! router: the installed public Standard Asset package and paid-execution
//! envelope are the only active path for `transfer`, `split`, `merge`,
//! `mint`, and `burn`.

pub mod boot;
pub mod composition;
pub mod config;
pub mod genesis;
pub mod identities;
pub mod local_execution;
pub mod machine;
pub mod paid_contracts;
pub mod publication;
mod seed;
pub mod transport;

pub use boot::{
    DEVNET_BLOB_DATABASE_FILE, DEVNET_DATABASE_FILE, DevnetBoot, DevnetBootError, boot_local_store,
};
pub use composition::{
    DevnetCompositionError, compose_devnet_router, compose_devnet_router_with_execution_policies,
    compose_devnet_router_with_local_execution, compose_devnet_router_with_publication,
};
pub use config::{
    DEVNET_STARTUP_LIMITATIONS_BANNER, DevOwner, DevnetConfig, DevnetConfigError,
    MAX_DEVNET_CONCURRENCY, MAX_DEVNET_OWNERS,
};
pub use genesis::{DevnetGenesisError, DevnetProtocolContext, build_devnet_protocol_context};
pub use identities::DevnetOutboxIdentitySource;
pub use machine::DevnetMachine;
pub use paid_contracts::{
    DEVNET_PAID_FEE_COIN_BALANCE, DEVNET_PAID_GENESIS_SEED, DEVNET_PAID_SPEND_COIN_BALANCE,
    PaidContractActivation, PaidContractGenesisError, PaidGenesisActivationMetadata,
    PaidOwnerCoins, build_paid_genesis_manifest, install_paid_contracts, paid_genesis_authority,
};
pub use seed::{DevnetSeedError, verify_or_seed_protocol_context};
pub use transport::DevnetTransport;
