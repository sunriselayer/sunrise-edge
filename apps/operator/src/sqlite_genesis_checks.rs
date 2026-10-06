//! Private original-SQLite startup-check owner (DR-0195): one shared
//! definition of committed root/fee/committee/key agreement, called by both
//! original serving and advisory preflight. This owns no fence acquisition, genesis
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
use execution::paid_execution::PaidFeePolicy;
use execution::publication::PublicationContext;
use hashing::HashSuiteResolver;
use node_core::fast_path::FastPathValidatorSetRecord;
use node_core::fast_path::records::decode_fastpath_validator_set_record;
use node_core::genesis::VerifiedGenesisRoot;
use protocol_types::{AtomicityDomainId, ValidatorId};
use runtime::portable::{DurablePortableSnapshotRepository, PortableSnapshotToken};
use runtime::{DurableDomainStateStore, DurableOperationContext, VersionedStateValue};
use std::error::Error;

pub(crate) struct OriginalHostPins<'a> {
    pub domain: AtomicityDomainId,
    pub expected_context: &'a PublicationContext,
    pub root: &'a VerifiedGenesisRoot,
    pub resolver: &'a HashSuiteResolver,
}

/// One definition of committed root/fee/committee/key/status agreement.
pub(crate) fn read_original_host_state<S: DurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    pins: &OriginalHostPins<'_>,
) -> Result<(PaidFeePolicy, FastPathValidatorSetRecord), Box<dyn Error>> {
    let domain: AtomicityDomainId = pins.domain;
    let expected_context: &PublicationContext = pins.expected_context;
    node_core::require_ordinary_namespace(store, context, domain)?;
    let fee: PaidFeePolicy =
        require_committed_genesis_fee_policy(store, context, domain, expected_context, pins.root)?;
    let validator_set_key: Vec<u8> =
        node_core::local_instance_state::fastpath_validator_set_key(expected_context)?;
    let observed: VersionedStateValue = store
        .get_versioned_durable(context, domain, &validator_set_key)
        .map_err(|error| format!("failed to read fast-path validator set: {error:?}"))?;
    let record_bytes: &[u8] = observed
        .value()
        .ok_or("no committed fast-path validator set for the expected genesis context")?;
    let record: FastPathValidatorSetRecord = decode_fastpath_validator_set_record(record_bytes)?;
    require_live_fastvote_pin(
        store,
        context,
        domain,
        expected_context,
        &record,
        pins.resolver,
    )?;
    Ok((fee, record))
}

pub(crate) fn verify_original_signer(
    record: &FastPathValidatorSetRecord,
    root: &VerifiedGenesisRoot,
    validator: ValidatorId,
    public_key: &[u8; 32],
) -> Result<(), Box<dyn Error>> {
    require_registered_signer(record, validator, public_key)?;
    require_committed_record_matches_root_committee(record, &root.manifest().validator_set)?;
    Ok(())
}

pub(crate) fn require_committed_record_matches_root_committee(
    record: &FastPathValidatorSetRecord,
    root_committee: &FastPathValidatorSetRecord,
) -> Result<(), String> {
    if !fast_path_committee_matches(record, root_committee) {
        return Err("committed fast-path validator set does not match the trusted verified root's original signed committee/context; refusing to bind the ordered Seal composition".into());
    }
    Ok(())
}

/// All deciding durable reads belong between the two observations. A token
/// includes the bound namespace, domain, active fence and mutation sequence.
/// This is advisory consistency, not an activation credential or a lease.
pub(crate) fn read_stable_advisory<S, T>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    read: impl FnOnce() -> Result<T, Box<dyn Error>>,
) -> Result<T, Box<dyn Error>>
where
    S: DurablePortableSnapshotRepository,
{
    let before: PortableSnapshotToken = store
        .begin_portable_snapshot(context, domain)
        .map_err(|error| format!("preflight snapshot observation failed: {error:?}"))?;
    let result: T = read()?;
    let after: PortableSnapshotToken = store
        .begin_portable_snapshot(context, domain)
        .map_err(|error| format!("preflight snapshot observation failed: {error:?}"))?;
    if before != after {
        return Err(
            "source changed during preflight; refusing to report an advisory success".into(),
        );
    }
    Ok(result)
}
