//! Real-WASM integration test for `PaidContractEngine` (DR-0124
//! "Authenticated durable integration", 2026-09-08). Runs the actual public
//! Standard Asset WASM through the production store/host/frame validator;
//! no native balance backdoor and no fake authenticated witness.
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::call::CallIntent;
use execution::local_execution::*;
use execution::paid_execution::*;
use execution::publication::*;
use execution::{ExecutionStatus, LocalWasmExecutionEngine, ObjectEffect};
use fees::{Amount, GasSchedule};
use hashing::HashSuiteResolver;
use objects::{AccessMode, Object, ObjectId};
use protocol_types::{
    ChainId, Digest32, Epoch, HashAlgorithmId, HashPurpose, HashSuite, HashSuiteId,
    HashSuiteSchedule, ProtocolVersion,
};
use public_standard_asset::{StandardAssetPackage, build_package};

include!("paid_execution_engine/fixture.rs");
include!("paid_execution_engine/call.rs");
include!("paid_execution_engine/publish.rs");
include!("paid_execution_engine/verify.rs");
include!("paid_execution_engine/codec.rs");
