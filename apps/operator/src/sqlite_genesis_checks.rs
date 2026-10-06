//! Private original-SQLite startup-check owner (DR-0195): one shared
//! definition of committed root/fee/committee/key/status agreement, called
//! by `sqlite_genesis` preflight. This owns no fence acquisition, genesis
//! initialization or successor authorization; a caller holds its own
//! context and already decided whether a fence claim precedes this check.
//! Built only from already-public `host_runtime`/`common` primitives, the
//! exact same primitives the existing `sqlite_source_host` serving path
//! calls after its own fence claim, so this is the same check, reused.
#![forbid(unsafe_code)]
use crate::common::require_live_fastvote_pin;
use crate::host_runtime::{
    fast_path_committee_matches, require_committed_genesis_fee_policy, require_registered_signer,
};
use execution::publication::PublicationContext;
use hashing::HashSuiteResolver;
use node_core::fast_path::FastPathValidatorSetRecord;
use node_core::fast_path::records::decode_fastpath_validator_set_record;
use node_core::genesis::VerifiedGenesisRoot;
use protocol_types::{AtomicityDomainId, ValidatorId};
use runtime::{DurableDomainStateStore, DurableOperationContext, VersionedStateValue};
use std::error::Error;

const COMMITTEE_MISMATCH: &str = "committed fast-path validator set does not match the trusted verified root's original signed committee/context";

/// One definition of committed root/fee/committee/key/status agreement.
pub(crate) fn verify_original_host_pins<S: DurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    expected_context: &PublicationContext,
    root: &VerifiedGenesisRoot,
    resolver: &HashSuiteResolver,
    validator: ValidatorId,
    public_key: &[u8; 32],
) -> Result<(), Box<dyn Error>> {
    require_committed_genesis_fee_policy(store, context, domain, expected_context, root)?;
    let validator_set_key: Vec<u8> =
        node_core::local_instance_state::fastpath_validator_set_key(expected_context)?;
    let observed: VersionedStateValue = store
        .get_versioned_durable(context, domain, &validator_set_key)
        .map_err(|error| format!("failed to read committed fast-path validator set: {error:?}"))?;
    let record_bytes: &[u8] = observed
        .value()
        .ok_or("no committed fast-path validator set for the expected genesis context")?;
    let record: FastPathValidatorSetRecord = decode_fastpath_validator_set_record(record_bytes)?;
    require_live_fastvote_pin(store, context, domain, expected_context, &record, resolver)?;
    require_registered_signer(&record, validator, public_key)?;
    let matches_committee = fast_path_committee_matches(&record, &root.manifest().validator_set);
    if !matches_committee {
        return Err(COMMITTEE_MISMATCH.into());
    }
    Ok(())
}
