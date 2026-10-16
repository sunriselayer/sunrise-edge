//! Optional, immutable, locally pinned non-genesis Standard Asset
//! application target for the mint/burn family only (DR-0258). Distinct from
//! [`super::asset_trust::PinnedAssetTrust`]'s shared genesis pin: this module
//! never changes what the genesis pin verifies or means for any other
//! family. It lets an operator additionally pin one independently verified
//! application instance (its own `InstanceRecord` file plus the asset's
//! `Definition` object id) created earlier by the separate `create-asset`
//! family (DR-0255), so mint/burn can target it instead of the pinned
//! genesis instance — never from a value or preimage the untrusted peer
//! request supplies.

use sunrise_edge_client::ObjectId;
use sunrise_edge_client::call::InstanceTarget;
use sunrise_edge_client::local_execution::{
    InstanceRecord, decode_instance_record, instance_target,
};
use sunrise_edge_client::package_types::ScopedTypeTag;

use public_standard_asset::{INITIALIZER, coin_type_tag, treasury_cap_type_tag};

use crate::error::CliError;

use super::asset_trust::PinnedAssetTrust;

/// Maximum bytes of one locally pinned application `InstanceRecord` file.
/// Identical to the public CLI's own bound
/// (`commands::paid_execution::MAX_INSTANCE_RECORD_BYTES`); kept as its own
/// constant here since that one is private to the `commands` module.
pub(super) const MAX_APPLICATION_INSTANCE_RECORD_BYTES: usize = 2048;

fn failure(error: impl std::error::Error + Send + Sync + 'static) -> CliError {
    CliError::LocalExecution(Box::new(error))
}

fn invalid(message: &'static str) -> CliError {
    failure(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message,
    ))
}

/// One independently verified, locally pinned, non-genesis Standard Asset
/// application target: a `Definition`/`TreasuryCap` pair created earlier
/// under the exact verified in-tree Standard Asset code, the pinned custody
/// publisher as creator, revision one and the known initializer. Built once
/// from two local inputs an operator supplies directly to a mint/burn
/// custody command (never from the peer wire request): the asset's
/// `ObjectId` and its own canonical `InstanceRecord` bytes.
pub(super) struct ApplicationAssetPin {
    pub(super) asset: ObjectId,
    pub(super) instance: InstanceTarget,
    pub(super) coin_tag: ScopedTypeTag,
    pub(super) cap_tag: ScopedTypeTag,
}

impl ApplicationAssetPin {
    /// Decodes `instance_ref_bytes` as one bounded, exact-canonical
    /// `InstanceRecord` (`decode_instance_record` itself requires the exact
    /// canonical re-encoding and a bounded size), verifies it against
    /// `trust`'s pinned context, exact genesis-verified in-tree Standard
    /// Asset code, revision one, known initializer and pinned custody
    /// publisher as creator, rejects a derived instance that aliases the
    /// pinned genesis fee instance, and derives `asset`'s own `Coin`/
    /// `TreasuryCap` nominal types from the shared genesis code origin.
    /// Never independently fetches or otherwise confirms that `asset` or
    /// this instance actually exist or are current on chain; that remains
    /// execution-only, exactly like every other family's own preparation.
    pub(super) fn new(
        trust: &PinnedAssetTrust,
        asset: ObjectId,
        instance_ref_bytes: &[u8],
    ) -> Result<Self, CliError> {
        if instance_ref_bytes.len() > MAX_APPLICATION_INSTANCE_RECORD_BYTES {
            return Err(invalid(
                "application instance record exceeds the maximum accepted size",
            ));
        }
        let record: InstanceRecord = decode_instance_record(instance_ref_bytes).map_err(failure)?;
        if record.context != trust.context
            || record.code != trust.fee_policy.code
            || record.revision != 1
            || record.initializer != INITIALIZER
            || record.creator != *trust.publisher.as_bytes()
        {
            return Err(invalid(
                "application instance record does not match the pinned custody context, code, revision, initializer or creator",
            ));
        }
        let instance: InstanceTarget =
            instance_target(&trust.resolver, &record).map_err(failure)?;
        if instance == trust.fee_policy.instance {
            return Err(invalid(
                "application instance must not alias the pinned genesis fee instance",
            ));
        }
        if asset == trust.asset {
            return Err(invalid(
                "application asset must not alias the pinned genesis fee asset",
            ));
        }
        let coin_tag: ScopedTypeTag = coin_type_tag(&trust.origin, &asset).map_err(failure)?;
        let cap_tag: ScopedTypeTag =
            treasury_cap_type_tag(&trust.origin, &asset).map_err(failure)?;
        Ok(Self {
            asset,
            instance,
            coin_tag,
            cap_tag,
        })
    }
}
