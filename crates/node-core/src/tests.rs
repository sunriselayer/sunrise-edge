mod bound_snapshots;

include!("tests/core_and_nonce.rs");
include!("tests/durable_object_support.rs");
include!("tests/authenticated_objects.rs");
include!("tests/preinstalled_support.rs");
include!("tests/preinstalled_execution.rs");
include!("tests/durable_handlers.rs");
#[path = "tests/declared_state_durable_contract.rs"]
mod declared_state_durable_contract;
include!("tests/queries.rs");
include!("tests/fees.rs");
#[path = "tests/envelope_contract.rs"]
mod envelope_contract;
#[path = "tests/envelope_vectors.rs"]
mod envelope_vectors;
