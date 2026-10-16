//! Pure Standard Asset `create-asset` (paid `Instantiate`) preparation and
//! review (no network, no signing) for the separate create-asset-only local
//! custody profile (DR-0255/M2). Shares its genesis/code/policy pin with
//! every other Standard Asset custody family via
//! [`super::asset_trust::PinnedAssetTrust`]; this module adds only the
//! Instantiate-specific new-instance derivation and review. The old
//! transfer (DR-0246), split/merge (DR-0249) and mint/burn (DR-0253)
//! families keep targeting the pinned genesis instance exclusively; this is
//! the only family that targets a fresh one.
//!
//! Unlike every other family, `create-asset` has no pre-existing owned
//! `Coin`/`TreasuryCap` application input to validate, and no before/after
//! amount or supply arithmetic: the published initializer always creates a
//! fresh `Definition` and `TreasuryCap` owned by the sender, with initial
//! supply zero, exactly as it does for every other caller (see
//! `commands/standard_asset.rs::validate_created_asset`). What custody adds
//! is an *independent* pre-approval review of the exact
//! [`sunrise_edge_client::call::InstanceTarget`] this intent signs for,
//! rederived from the caller-supplied seed and this trust's own pinned
//! sender/context/code — never from a caller-supplied target, code
//! reference, or digest, and never a guess at the created object
//! identifiers, which cannot be known before execution.

use protocol_types::HashPurpose;

use sunrise_edge_client::call::{CallIntent, InstanceTarget};
use sunrise_edge_client::local_execution::{InstanceRecord, instance_target};
use sunrise_edge_client::{
    AccessManifest, Amount, Digest32, Epoch, FeeSourceConsent, Object, ObjectRef, PaidApplication,
    PreparedPaidExecution, RequestId, ReservationAccessKind, VerifiedGenesisRoot,
};

use public_standard_asset::{INITIALIZER, coin_amount, no_arguments};

use crate::error::CliError;
use crate::hex::encode_hex;

use super::asset_trust::{PinnedAssetTrust, safe_ascii};
use super::config::CustodyConfig;

/// Maximum bytes of the rendered, bounded, display-only review.
const MAX_CREATE_REVIEW_BYTES: usize = 64 * 1024;

fn failure(error: impl std::error::Error + Send + Sync + 'static) -> CliError {
    CliError::LocalExecution(Box::new(error))
}

fn invalid(message: &'static str) -> CliError {
    failure(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message,
    ))
}

/// One caller-supplied `create-asset` request: a creator-scoped logical
/// seed for the new application instance, a distinct owned fee source, and
/// the signed replay/fee fields. There is no amount, recipient, or
/// pre-existing application `Coin`/`TreasuryCap` input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AssetCreateRequest {
    pub(crate) seed: [u8; 32],
    pub(crate) fee_bytes: Vec<u8>,
    pub(crate) nonce: u64,
    pub(crate) request_id: RequestId,
    pub(crate) max_fee: u64,
    pub(crate) gas_limit: u64,
}

/// One immutable prepared `create-asset` paid `Instantiate` plus its
/// bounded review.
pub(super) struct PreparedAssetCreate {
    pub(super) prepared: PreparedPaidExecution,
    pub(super) review: String,
    pub(super) fee_balance: u64,
    pub(super) new_instance: InstanceTarget,
}

/// The create-asset family's own trust: the shared genesis pin plus this
/// operation's own new-instance derivation and review.
pub(super) struct AssetCreateTrust {
    trust: PinnedAssetTrust,
}

impl AssetCreateTrust {
    /// Binds `config` to `root` via the shared [`PinnedAssetTrust`] pin.
    pub(super) fn new(config: CustodyConfig, root: VerifiedGenesisRoot) -> Result<Self, CliError> {
        Ok(Self {
            trust: PinnedAssetTrust::new(config, root)?,
        })
    }

    fn object_digest(&self, bytes: &[u8]) -> Result<Digest32, CliError> {
        let epoch: Epoch = self.trust.expected.epoch();
        self.trust
            .resolver
            .hash_for_purpose(epoch, HashPurpose::Object, bytes)
            .map_err(failure)
    }

    /// Prepares one `create-asset` paid `Instantiate`. Independently
    /// derives the exact new [`InstanceTarget`] from the caller-supplied
    /// seed and this trust's own pinned sender/context/code — never from a
    /// caller-supplied target, code reference, or digest. Rejects a target
    /// that actually collides with the pinned genesis fee instance; it
    /// never rejects merely because the caller reused the same seed bytes
    /// some other creator already used elsewhere, since that collides with
    /// a *different* target under a different creator, not this one.
    pub(super) fn prepare_create(
        &self,
        request: &AssetCreateRequest,
    ) -> Result<PreparedAssetCreate, CliError> {
        let fee_object: Object = self.trust.decode_bounded_object(
            &request.fee_bytes,
            "fee source preimage exceeds the maximum accepted size",
            "fee source preimage is not the exact canonical object encoding",
        )?;
        self.trust.validate_owned_coin(
            &fee_object,
            "fee source is not owned by the pinned custody publisher",
            "fee source schema does not match the genesis Standard Asset schema",
            "fee source is not the genesis Standard Asset Coin type",
        )?;
        if request.gas_limit == 0 {
            return Err(invalid("gas limit must be positive"));
        }
        if request.max_fee == 0 {
            return Err(invalid("max fee must be positive"));
        }
        let fee_balance: u64 = coin_amount(&fee_object.data).map_err(failure)?;
        if request.max_fee >= fee_balance {
            return Err(invalid(
                "max fee must be strictly less than the fee source balance",
            ));
        }

        let record: InstanceRecord = InstanceRecord {
            context: self.trust.context.clone(),
            creator: *self.trust.publisher.as_bytes(),
            seed: request.seed,
            code: self.trust.fee_policy.code.clone(),
            revision: 1,
            initializer: INITIALIZER.to_owned(),
        };
        let new_instance: InstanceTarget =
            instance_target(&self.trust.resolver, &record).map_err(failure)?;
        if new_instance == self.trust.fee_policy.instance {
            return Err(invalid(
                "new asset instance collides with the pinned genesis fee instance",
            ));
        }

        let fee_digest: Digest32 = self.object_digest(&request.fee_bytes)?;
        let fee_ref: ObjectRef = ObjectRef {
            id: fee_object.id,
            version: fee_object.version,
            digest: fee_digest,
        };
        let consent: FeeSourceConsent = FeeSourceConsent {
            source: fee_ref.clone(),
            access: ReservationAccessKind::Write,
            max_fee: Amount::new(request.max_fee),
            refund_recipient: *self.trust.publisher.as_bytes(),
        };
        let call: CallIntent = CallIntent {
            context: self.trust.context.clone(),
            request_id: *request.request_id.as_bytes(),
            sender: *self.trust.publisher.as_bytes(),
            nonce: request.nonce,
            code: self.trust.fee_policy.code.clone(),
            instance: new_instance.clone(),
            entrypoint: INITIALIZER.to_owned(),
            type_arguments: Vec::new(),
            access: AccessManifest::new(),
            arguments: no_arguments().map_err(failure)?,
            gas_limit: request.gas_limit,
        };
        let prepared: PreparedPaidExecution = PreparedPaidExecution::prepare(
            self.trust.publisher,
            &self.trust.resolver,
            &self.trust.expected,
            &self.trust.fee_policy,
            consent,
            PaidApplication::Instantiate(call),
            request.request_id,
            request.nonce,
            request.gas_limit,
            Vec::new(),
        )?;

        let review: String = self.render_review(
            request,
            &record,
            &new_instance,
            &fee_ref,
            fee_balance,
            &prepared,
        )?;
        Ok(PreparedAssetCreate {
            prepared,
            review,
            fee_balance,
            new_instance,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn render_review(
        &self,
        request: &AssetCreateRequest,
        record: &InstanceRecord,
        new_instance: &InstanceTarget,
        fee_ref: &ObjectRef,
        fee_balance: u64,
        prepared: &PreparedPaidExecution,
    ) -> Result<String, CliError> {
        let mut out: String = String::new();
        out.push_str(&format!(
            "chain_id={}\n",
            safe_ascii(self.trust.expected.chain_id().as_str())
        ));
        out.push_str(&format!(
            "protocol_version={}\n",
            self.trust.expected.protocol_version().get()
        ));
        out.push_str(&format!("epoch={}\n", self.trust.expected.epoch().get()));
        out.push_str(&format!("domain={}\n", self.trust.expected.domain()));
        out.push_str(&format!("genesis_digest={}\n", self.trust.genesis_digest));
        out.push_str(&format!(
            "code_origin_publisher={}\n",
            encode_hex(self.trust.origin.publisher())
        ));
        out.push_str(&format!(
            "code_origin_seed={}\n",
            encode_hex(self.trust.origin.seed())
        ));
        out.push_str(&format!(
            "code_revision={}\n",
            self.trust.fee_policy.code.revision()
        ));
        out.push_str(&format!(
            "code_artifact_digest={}\n",
            self.trust.fee_policy.code.artifact_digest()
        ));
        out.push_str(&format!(
            "sender={}\nentrypoint=init\n",
            self.trust.publisher
        ));
        out.push_str(&format!(
            "schema={}\n",
            public_standard_asset::SCHEMA_VERSION
        ));
        out.push_str(&format!("genesis_asset={}\n", self.trust.asset));
        out.push_str(&format!(
            "genesis_instance_creator={}\n",
            encode_hex(&self.trust.fee_policy.instance.creator)
        ));
        out.push_str(&format!(
            "genesis_instance_seed={}\n",
            encode_hex(&self.trust.fee_policy.instance.seed)
        ));
        out.push_str(&format!(
            "genesis_instance_revision={}\n",
            self.trust.fee_policy.instance.revision
        ));
        out.push_str(&format!(
            "genesis_instance_record_digest={}\n",
            self.trust.fee_policy.instance.record_digest
        ));
        out.push_str(&format!("new_instance_seed={}\n", encode_hex(&record.seed)));
        out.push_str(&format!(
            "new_instance_creator={}\n",
            encode_hex(&new_instance.creator)
        ));
        out.push_str(&format!(
            "new_instance_revision={}\n",
            new_instance.revision
        ));
        out.push_str(&format!(
            "new_instance_record_digest={}\n",
            new_instance.record_digest
        ));
        out.push_str("initializer=init\n");
        // `Instantiate` forbids application inputs/type arguments at the
        // protocol level (see `PaidApplicationScopes::Instantiate`); stated
        // explicitly here too, so the review itself says so, not only the
        // opaque signing frame hex.
        out.push_str("type_arguments=none\n");
        out.push_str("access=none\n");
        out.push_str("arguments=none\n");
        // The initializer creates these on-chain, but their identifiers are
        // derived at execution time (see `derive_local_created_object_id`),
        // never predictable from a caller-known seed, context, or code
        // reference alone: this review never claims a precomputed ID.
        out.push_str("created_definition=unknown-until-execution\n");
        out.push_str("created_treasury_cap=unknown-until-execution\n");
        out.push_str("initial_supply=0\n");
        out.push_str(&format!(
            "fee_source_id={} fee_source_version={} fee_source_digest={}\n",
            fee_ref.id, fee_ref.version, fee_ref.digest
        ));
        out.push_str(&format!("fee_balance={fee_balance}\n"));
        out.push_str(&format!("max_fee={}\n", request.max_fee));
        let minimum_fee_source_balance: u64 = fee_balance
            .checked_sub(request.max_fee)
            .ok_or_else(|| invalid("fee balance checked subtraction underflowed"))?;
        out.push_str(&format!(
            "minimum_fee_source_balance={minimum_fee_source_balance}\n"
        ));
        out.push_str(&format!("refund_recipient={}\n", self.trust.publisher));
        out.push_str(&format!(
            "reserve_entrypoint={}\n",
            safe_ascii(&self.trust.fee_policy.reserve_entrypoint)
        ));
        out.push_str(&format!(
            "settle_entrypoint={}\n",
            safe_ascii(&self.trust.fee_policy.settle_entrypoint)
        ));
        out.push_str(&format!(
            "fee_recipient={}\n",
            encode_hex(&self.trust.fee_policy.fee_recipient)
        ));
        out.push_str(&format!(
            "base_policy_digest={}\n",
            self.trust.fee_policy.base_policy_digest
        ));
        out.push_str(&format!(
            "conversion_divisor={}\n",
            self.trust.fee_policy.conversion_divisor
        ));
        out.push_str(&format!(
            "reserve_allowance={}\n",
            self.trust.fee_policy.reserve_allowance
        ));
        out.push_str(&format!(
            "settle_allowance={}\n",
            self.trust.fee_policy.settle_allowance
        ));
        out.push_str(&format!(
            "gas_schedule={:?}\n",
            self.trust.fee_policy.gas_schedule
        ));
        out.push_str(&format!("policy_calls={}\npolicy_handles={}\npolicy_creations={}\npolicy_events={}\npolicy_memory_bytes={}\npolicy_output_bytes={}\npolicy_publish_artifact_byte_price={}\npolicy_publish_closure_node_price={}\n",
            self.trust.fee_policy.calls, self.trust.fee_policy.handles, self.trust.fee_policy.creations, self.trust.fee_policy.events,
            self.trust.fee_policy.memory_bytes, self.trust.fee_policy.output_bytes, self.trust.fee_policy.publish_artifact_byte_price,
            self.trust.fee_policy.publish_closure_node_price));
        out.push_str(&format!("gas_limit={}\n", request.gas_limit));
        out.push_str(&format!("nonce={}\n", request.nonce));
        out.push_str(&format!("request_id={}\n", request.request_id));
        out.push_str("freshness=enforced-at-execution-not-preparation\n");
        // This preparation step never independently authenticates that
        // `request.seed` is unused: a reused seed, or one that now collides
        // with an instance created since this review was rendered, is
        // refused only by execution itself, after this exact reviewed fee
        // ceiling may already have been charged up to `max_fee`.
        out.push_str(
            "seed_reuse_or_existing_instance=refused-only-at-execution-may-still-charge-up-to-max-fee\n",
        );
        out.push_str(&format!(
            "signing_frame={}\n",
            encode_hex(prepared.signable_frame())
        ));
        if out.len() > MAX_CREATE_REVIEW_BYTES {
            return Err(invalid(
                "asset create review exceeds the maximum accepted display size",
            ));
        }
        Ok(out)
    }
}
