//! Pure StandardAsset `transfer` preparation and review (no network, no
//! signing) for the separate transfer-only local custody profile.
//!
//! [`AssetTransferTrust`] wraps one [`super::asset_trust::PinnedAssetTrust`]
//! (the genesis/code/instance/policy pin shared by every Standard Asset
//! custody family) and adds only this family's own argument shape:
//! [`AssetTransferTrust::prepare`] takes two bounded, caller-supplied
//! canonical `Object` preimages (never a peer-reported digest or amount) and
//! builds one [`PreparedPaidExecution`] transferring the whole coin, plus a
//! bounded human-readable review of every signed field.

use protocol_types::HashPurpose;

use sunrise_edge_client::call::CallIntent;
use sunrise_edge_client::{
    AccessEntry, AccessManifest, AccessMode, Amount, Digest32, Epoch, FeeSourceConsent, Object,
    ObjectRef, PaidApplication, PreparedPaidExecution, RequestId, ReservationAccessKind,
    VerifiedGenesisRoot,
};

use public_standard_asset::{asset_type_argument, coin_amount, transfer_arguments};

use crate::error::CliError;
use crate::hex::encode_hex;

use super::asset_trust::{PinnedAssetTrust, safe_ascii};
use super::config::CustodyConfig;

/// Maximum bytes of the rendered, bounded, display-only review.
const MAX_TRANSFER_REVIEW_BYTES: usize = 64 * 1024;

const TRANSFER_ENTRYPOINT: &str = "transfer";

fn failure(error: impl std::error::Error + Send + Sync + 'static) -> CliError {
    CliError::LocalExecution(Box::new(error))
}

fn invalid(message: &'static str) -> CliError {
    failure(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message,
    ))
}

/// One caller-supplied whole-coin transfer request: two bounded canonical
/// `Object` preimages (never a queried digest or amount), the recipient,
/// signed replay fields and the fee ceiling. `coin_bytes` is consumed
/// entirely; this profile never splits or mutates an amount.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AssetTransferRequest {
    pub(crate) coin_bytes: Vec<u8>,
    pub(crate) fee_bytes: Vec<u8>,
    pub(crate) recipient: [u8; 32],
    pub(crate) nonce: u64,
    pub(crate) request_id: RequestId,
    pub(crate) max_fee: u64,
    pub(crate) gas_limit: u64,
}

/// One immutable prepared whole-coin transfer plus its bounded review.
pub(super) struct PreparedAssetTransfer {
    pub(super) prepared: PreparedPaidExecution,
    pub(super) review: String,
    pub(super) amount: u64,
    pub(super) fee_balance: u64,
}

/// The transfer family's own trust: the shared genesis pin plus the
/// `transfer`-specific `prepare`/review logic.
pub(super) struct AssetTransferTrust {
    trust: PinnedAssetTrust,
}

impl AssetTransferTrust {
    /// Binds `config` to `root` via the shared [`PinnedAssetTrust`] pin.
    pub(super) fn new(config: CustodyConfig, root: VerifiedGenesisRoot) -> Result<Self, CliError> {
        Ok(Self {
            trust: PinnedAssetTrust::new(config, root)?,
        })
    }

    /// Prepares one whole-coin `transfer` paid Call. Never mutates, splits
    /// or peeks any amount beyond what `coin_bytes`/`fee_bytes` themselves
    /// canonically decode to, and never trusts a peer-reported digest: the
    /// `ObjectRef` digest is always recomputed locally from the exact
    /// preimage bytes under this trust's own pinned resolver and epoch.
    pub(super) fn prepare(
        &self,
        request: &AssetTransferRequest,
    ) -> Result<PreparedAssetTransfer, CliError> {
        sunrise_edge_client::validate_ed25519_owner_address(
            &request.recipient,
            sunrise_edge_client::Ed25519OwnerAddressPolicy::CanonicalPrimeOrder,
        )
        .map_err(failure)?;
        let coin_object: Object = self.trust.decode_bounded_object(
            &request.coin_bytes,
            "transfer coin preimage exceeds the maximum accepted size",
            "transfer coin preimage is not the exact canonical object encoding",
        )?;
        let fee_object: Object = self.trust.decode_bounded_object(
            &request.fee_bytes,
            "fee source preimage exceeds the maximum accepted size",
            "fee source preimage is not the exact canonical object encoding",
        )?;
        self.trust.validate_owned_coin(
            &coin_object,
            "transfer coin is not owned by the pinned custody publisher",
            "transfer coin schema does not match the genesis Standard Asset schema",
            "transfer coin is not the genesis Standard Asset Coin type",
        )?;
        self.trust.validate_owned_coin(
            &fee_object,
            "fee source is not owned by the pinned custody publisher",
            "fee source schema does not match the genesis Standard Asset schema",
            "fee source is not the genesis Standard Asset Coin type",
        )?;
        if coin_object.id == fee_object.id {
            return Err(invalid(
                "transfer coin and fee source must be distinct objects",
            ));
        }
        if request.recipient == *self.trust.publisher.as_bytes() {
            return Err(invalid(
                "transfer recipient must differ from the pinned custody publisher",
            ));
        }
        if request.gas_limit == 0 {
            return Err(invalid("gas limit must be positive"));
        }
        if request.max_fee == 0 {
            return Err(invalid("max fee must be positive"));
        }

        let amount: u64 = coin_amount(&coin_object.data).map_err(failure)?;
        let fee_balance: u64 = coin_amount(&fee_object.data).map_err(failure)?;
        if request.max_fee >= fee_balance {
            return Err(invalid(
                "max fee must be strictly less than the fee source balance",
            ));
        }

        let epoch: Epoch = self.trust.expected.epoch();
        let coin_digest: Digest32 = self
            .trust
            .resolver
            .hash_for_purpose(epoch, HashPurpose::Object, &request.coin_bytes)
            .map_err(failure)?;
        let fee_digest: Digest32 = self
            .trust
            .resolver
            .hash_for_purpose(epoch, HashPurpose::Object, &request.fee_bytes)
            .map_err(failure)?;
        let coin_ref: ObjectRef = ObjectRef {
            id: coin_object.id,
            version: coin_object.version,
            digest: coin_digest,
        };
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
        let mut access: AccessManifest = AccessManifest::new();
        access.entries.push(AccessEntry {
            object_ref: coin_ref.clone(),
            mode: AccessMode::Write,
        });
        let call: CallIntent = CallIntent {
            context: self.trust.context.clone(),
            request_id: *request.request_id.as_bytes(),
            sender: *self.trust.publisher.as_bytes(),
            nonce: request.nonce,
            code: self.trust.fee_policy.code.clone(),
            instance: self.trust.fee_policy.instance.clone(),
            entrypoint: TRANSFER_ENTRYPOINT.to_owned(),
            type_arguments: vec![asset_type_argument(&self.trust.asset)],
            access,
            arguments: transfer_arguments(&request.recipient).map_err(failure)?,
            gas_limit: request.gas_limit,
        };
        let prepared: PreparedPaidExecution = PreparedPaidExecution::prepare(
            self.trust.publisher,
            &self.trust.resolver,
            &self.trust.expected,
            &self.trust.fee_policy,
            consent,
            PaidApplication::Call(call),
            request.request_id,
            request.nonce,
            request.gas_limit,
            Vec::new(),
        )?;

        let review: String =
            self.render_review(request, &coin_ref, amount, &fee_ref, fee_balance, &prepared)?;
        Ok(PreparedAssetTransfer {
            prepared,
            review,
            amount,
            fee_balance,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn render_review(
        &self,
        request: &AssetTransferRequest,
        coin_ref: &ObjectRef,
        amount: u64,
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
        out.push_str(&format!("asset={}\n", self.trust.asset));
        out.push_str(&format!(
            "sender={}\nentrypoint=transfer\n",
            self.trust.publisher
        ));
        out.push_str(&format!(
            "schema={}\n",
            public_standard_asset::SCHEMA_VERSION
        ));
        out.push_str(&format!(
            "instance_creator={}\n",
            encode_hex(&self.trust.fee_policy.instance.creator)
        ));
        out.push_str(&format!(
            "instance_seed={}\n",
            encode_hex(&self.trust.fee_policy.instance.seed)
        ));
        out.push_str(&format!(
            "instance_revision={}\n",
            self.trust.fee_policy.instance.revision
        ));
        out.push_str(&format!(
            "instance_record_digest={}\n",
            self.trust.fee_policy.instance.record_digest
        ));
        out.push_str(&format!(
            "coin_id={} coin_version={} coin_digest={}\n",
            coin_ref.id, coin_ref.version, coin_ref.digest
        ));
        out.push_str(&format!("amount={amount}\n"));
        out.push_str("transfer=whole-coin-unchanged\n");
        out.push_str(&format!("recipient={}\n", encode_hex(&request.recipient)));
        out.push_str(&format!(
            "fee_source_id={} fee_source_version={} fee_source_digest={}\n",
            fee_ref.id, fee_ref.version, fee_ref.digest
        ));
        out.push_str(&format!("fee_balance={fee_balance}\n"));
        out.push_str(&format!("max_fee={}\n", request.max_fee));
        out.push_str(&format!(
            "minimum_fee_source_balance={}\n",
            fee_balance - request.max_fee
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
        out.push_str(&format!(
            "signing_frame={}\n",
            encode_hex(prepared.signable_frame())
        ));
        if out.len() > MAX_TRANSFER_REVIEW_BYTES {
            return Err(invalid(
                "asset transfer review exceeds the maximum accepted display size",
            ));
        }
        Ok(out)
    }
}
