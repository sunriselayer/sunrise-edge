//! Pure StandardAsset `split`/`merge` preparation and review (no network, no
//! signing) for the separate split/merge-only local custody profile
//! (DR-0249). Shares its genesis/code/instance/policy pin with the transfer
//! family (DR-0246) via [`super::asset_trust::PinnedAssetTrust`]; only this
//! module's own entrypoint/argument/amount/overflow checks differ.
//!
//! `split` owns the whole source coin (`Coin` Write) and never requires the
//! recipient to differ from the pinned publisher: splitting one's own coin
//! into two of one's own coins is a legitimate, ordinary operation, unlike
//! `transfer`'s whole-coin move to a genuinely different owner. `merge`
//! consumes a distinct source coin (`Coin` Consume) into a destination coin
//! (`Coin` Write); both must be owned by the pinned publisher, and the
//! checked sum is rejected on overflow before ever reaching the network.

use protocol_types::HashPurpose;

use sunrise_edge_client::call::CallIntent;
use sunrise_edge_client::{
    AccessEntry, AccessManifest, AccessMode, Amount, Digest32, Epoch, FeeSourceConsent, Object,
    ObjectRef, PaidApplication, PreparedPaidExecution, RequestId, ReservationAccessKind,
    VerifiedGenesisRoot,
};

use public_standard_asset::{asset_type_argument, coin_amount, no_arguments, split_arguments};

use crate::error::CliError;
use crate::hex::encode_hex;

use super::asset_trust::{PinnedAssetTrust, safe_ascii};
use super::config::CustodyConfig;

/// Maximum bytes of either rendered, bounded, display-only review.
const MAX_SPLIT_MERGE_REVIEW_BYTES: usize = 64 * 1024;

const SPLIT_ENTRYPOINT: &str = "split";
const MERGE_ENTRYPOINT: &str = "merge";

fn failure(error: impl std::error::Error + Send + Sync + 'static) -> CliError {
    CliError::LocalExecution(Box::new(error))
}

fn invalid(message: &'static str) -> CliError {
    failure(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message,
    ))
}

/// One caller-supplied `split` request: one owned source `Coin` Write
/// preimage, a distinct owned fee source, the strictly-partial amount, the
/// recipient (which may legitimately equal the pinned publisher — splitting
/// one's own coin is not a transfer), and the signed replay/fee fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AssetSplitRequest {
    pub(crate) coin_bytes: Vec<u8>,
    pub(crate) fee_bytes: Vec<u8>,
    pub(crate) amount: u64,
    pub(crate) recipient: [u8; 32],
    pub(crate) nonce: u64,
    pub(crate) request_id: RequestId,
    pub(crate) max_fee: u64,
    pub(crate) gas_limit: u64,
}

/// One caller-supplied `merge` request: a destination `Coin` Write, a
/// distinct owned source `Coin` Consume, a distinct owned fee source, and
/// the signed replay/fee fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AssetMergeRequest {
    pub(crate) into_bytes: Vec<u8>,
    pub(crate) from_bytes: Vec<u8>,
    pub(crate) fee_bytes: Vec<u8>,
    pub(crate) nonce: u64,
    pub(crate) request_id: RequestId,
    pub(crate) max_fee: u64,
    pub(crate) gas_limit: u64,
}

/// One bounded split or merge request, as carried by the kind-3 wire codec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AssetSplitMergeRequest {
    Split(Box<AssetSplitRequest>),
    Merge(Box<AssetMergeRequest>),
}

/// One immutable prepared `split` plus its bounded review.
pub(super) struct PreparedAssetSplit {
    pub(super) prepared: PreparedPaidExecution,
    pub(super) review: String,
    pub(super) held: u64,
    pub(super) fee_balance: u64,
}

/// One immutable prepared `merge` plus its bounded review.
pub(super) struct PreparedAssetMerge {
    pub(super) prepared: PreparedPaidExecution,
    pub(super) review: String,
    pub(super) into_amount: u64,
    pub(super) from_amount: u64,
    pub(super) checked_total: u64,
    pub(super) fee_balance: u64,
}

/// The split/merge family's own trust: the shared genesis pin plus the
/// `split`/`merge`-specific `prepare`/review logic.
pub(super) struct AssetSplitMergeTrust {
    trust: PinnedAssetTrust,
}

impl AssetSplitMergeTrust {
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

    fn fee_consent(&self, fee_ref: &ObjectRef, max_fee: u64) -> FeeSourceConsent {
        FeeSourceConsent {
            source: fee_ref.clone(),
            access: ReservationAccessKind::Write,
            max_fee: Amount::new(max_fee),
            refund_recipient: *self.trust.publisher.as_bytes(),
        }
    }

    /// Prepares one `split` paid Call. The recipient may equal the pinned
    /// publisher: splitting one's own coin is a legitimate operation, never
    /// refused the way `transfer`'s self-recipient is.
    pub(super) fn prepare_split(
        &self,
        request: &AssetSplitRequest,
    ) -> Result<PreparedAssetSplit, CliError> {
        sunrise_edge_client::validate_ed25519_owner_address(
            &request.recipient,
            sunrise_edge_client::Ed25519OwnerAddressPolicy::CanonicalPrimeOrder,
        )
        .map_err(failure)?;
        let coin_object: Object = self.trust.decode_bounded_object(
            &request.coin_bytes,
            "split coin preimage exceeds the maximum accepted size",
            "split coin preimage is not the exact canonical object encoding",
        )?;
        let fee_object: Object = self.trust.decode_bounded_object(
            &request.fee_bytes,
            "fee source preimage exceeds the maximum accepted size",
            "fee source preimage is not the exact canonical object encoding",
        )?;
        self.trust.validate_owned_coin(
            &coin_object,
            "split coin is not owned by the pinned custody publisher",
            "split coin schema does not match the genesis Standard Asset schema",
            "split coin is not the genesis Standard Asset Coin type",
        )?;
        self.trust.validate_owned_coin(
            &fee_object,
            "fee source is not owned by the pinned custody publisher",
            "fee source schema does not match the genesis Standard Asset schema",
            "fee source is not the genesis Standard Asset Coin type",
        )?;
        if coin_object.id == fee_object.id {
            return Err(invalid(
                "split coin and fee source must be distinct objects",
            ));
        }
        if request.gas_limit == 0 {
            return Err(invalid("gas limit must be positive"));
        }
        if request.max_fee == 0 {
            return Err(invalid("max fee must be positive"));
        }

        let held: u64 = coin_amount(&coin_object.data).map_err(failure)?;
        let fee_balance: u64 = coin_amount(&fee_object.data).map_err(failure)?;
        if request.max_fee >= fee_balance {
            return Err(invalid(
                "max fee must be strictly less than the fee source balance",
            ));
        }
        if request.amount == 0 {
            return Err(invalid("split amount must be positive"));
        }
        if request.amount >= held {
            return Err(invalid(
                "split amount must be strictly less than the held coin balance",
            ));
        }
        let remainder: u64 = held
            .checked_sub(request.amount)
            .ok_or_else(|| invalid("split remainder would underflow"))?;

        let coin_digest: Digest32 = self.object_digest(&request.coin_bytes)?;
        let fee_digest: Digest32 = self.object_digest(&request.fee_bytes)?;
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
            entrypoint: SPLIT_ENTRYPOINT.to_owned(),
            type_arguments: vec![asset_type_argument(&self.trust.asset)],
            access,
            arguments: split_arguments(request.amount, &request.recipient).map_err(failure)?,
            gas_limit: request.gas_limit,
        };
        let prepared: PreparedPaidExecution = PreparedPaidExecution::prepare(
            self.trust.publisher,
            &self.trust.resolver,
            &self.trust.expected,
            &self.trust.fee_policy,
            self.fee_consent(&fee_ref, request.max_fee),
            PaidApplication::Call(call),
            request.request_id,
            request.nonce,
            request.gas_limit,
            Vec::new(),
        )?;

        let review: String = self.render_split_review(
            request,
            &coin_ref,
            held,
            remainder,
            &fee_ref,
            fee_balance,
            &prepared,
        )?;
        Ok(PreparedAssetSplit {
            prepared,
            review,
            held,
            fee_balance,
        })
    }

    /// Prepares one `merge` paid Call: destination `into` (Write) and source
    /// `from` (Consume) must be distinct, both owned, with a checked sum.
    pub(super) fn prepare_merge(
        &self,
        request: &AssetMergeRequest,
    ) -> Result<PreparedAssetMerge, CliError> {
        let into_object: Object = self.trust.decode_bounded_object(
            &request.into_bytes,
            "merge destination preimage exceeds the maximum accepted size",
            "merge destination preimage is not the exact canonical object encoding",
        )?;
        let from_object: Object = self.trust.decode_bounded_object(
            &request.from_bytes,
            "merge source preimage exceeds the maximum accepted size",
            "merge source preimage is not the exact canonical object encoding",
        )?;
        let fee_object: Object = self.trust.decode_bounded_object(
            &request.fee_bytes,
            "fee source preimage exceeds the maximum accepted size",
            "fee source preimage is not the exact canonical object encoding",
        )?;
        self.trust.validate_owned_coin(
            &into_object,
            "merge destination is not owned by the pinned custody publisher",
            "merge destination schema does not match the genesis Standard Asset schema",
            "merge destination is not the genesis Standard Asset Coin type",
        )?;
        self.trust.validate_owned_coin(
            &from_object,
            "merge source is not owned by the pinned custody publisher",
            "merge source schema does not match the genesis Standard Asset schema",
            "merge source is not the genesis Standard Asset Coin type",
        )?;
        self.trust.validate_owned_coin(
            &fee_object,
            "fee source is not owned by the pinned custody publisher",
            "fee source schema does not match the genesis Standard Asset schema",
            "fee source is not the genesis Standard Asset Coin type",
        )?;
        if into_object.id == from_object.id {
            return Err(invalid(
                "merge destination and source must be distinct objects",
            ));
        }
        if fee_object.id == into_object.id || fee_object.id == from_object.id {
            return Err(invalid(
                "fee source must be distinct from every merge application input",
            ));
        }
        if request.gas_limit == 0 {
            return Err(invalid("gas limit must be positive"));
        }
        if request.max_fee == 0 {
            return Err(invalid("max fee must be positive"));
        }

        let into_amount: u64 = coin_amount(&into_object.data).map_err(failure)?;
        let from_amount: u64 = coin_amount(&from_object.data).map_err(failure)?;
        let fee_balance: u64 = coin_amount(&fee_object.data).map_err(failure)?;
        if request.max_fee >= fee_balance {
            return Err(invalid(
                "max fee must be strictly less than the fee source balance",
            ));
        }
        if from_amount == 0 {
            return Err(invalid("merge source amount must be positive"));
        }
        let checked_total: u64 = into_amount
            .checked_add(from_amount)
            .ok_or_else(|| invalid("merge total amount would overflow"))?;

        let into_digest: Digest32 = self.object_digest(&request.into_bytes)?;
        let from_digest: Digest32 = self.object_digest(&request.from_bytes)?;
        let fee_digest: Digest32 = self.object_digest(&request.fee_bytes)?;
        let into_ref: ObjectRef = ObjectRef {
            id: into_object.id,
            version: into_object.version,
            digest: into_digest,
        };
        let from_ref: ObjectRef = ObjectRef {
            id: from_object.id,
            version: from_object.version,
            digest: from_digest,
        };
        let fee_ref: ObjectRef = ObjectRef {
            id: fee_object.id,
            version: fee_object.version,
            digest: fee_digest,
        };

        let mut access: AccessManifest = AccessManifest::new();
        access.entries.push(AccessEntry {
            object_ref: into_ref.clone(),
            mode: AccessMode::Write,
        });
        access.entries.push(AccessEntry {
            object_ref: from_ref.clone(),
            mode: AccessMode::Consume,
        });
        let call: CallIntent = CallIntent {
            context: self.trust.context.clone(),
            request_id: *request.request_id.as_bytes(),
            sender: *self.trust.publisher.as_bytes(),
            nonce: request.nonce,
            code: self.trust.fee_policy.code.clone(),
            instance: self.trust.fee_policy.instance.clone(),
            entrypoint: MERGE_ENTRYPOINT.to_owned(),
            type_arguments: vec![asset_type_argument(&self.trust.asset)],
            access,
            arguments: no_arguments().map_err(failure)?,
            gas_limit: request.gas_limit,
        };
        let prepared: PreparedPaidExecution = PreparedPaidExecution::prepare(
            self.trust.publisher,
            &self.trust.resolver,
            &self.trust.expected,
            &self.trust.fee_policy,
            self.fee_consent(&fee_ref, request.max_fee),
            PaidApplication::Call(call),
            request.request_id,
            request.nonce,
            request.gas_limit,
            Vec::new(),
        )?;

        let review: String = self.render_merge_review(
            request,
            &into_ref,
            into_amount,
            &from_ref,
            from_amount,
            checked_total,
            &fee_ref,
            fee_balance,
            &prepared,
        )?;
        Ok(PreparedAssetMerge {
            prepared,
            review,
            into_amount,
            from_amount,
            checked_total,
            fee_balance,
        })
    }

    fn render_common(&self, out: &mut String) {
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
        out.push_str(&format!("sender={}\n", self.trust.publisher));
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
    }

    #[allow(clippy::too_many_arguments)]
    fn render_fee_and_frame(
        &self,
        out: &mut String,
        fee_ref: &ObjectRef,
        fee_balance: u64,
        max_fee: u64,
        gas_limit: u64,
        nonce: u64,
        request_id: RequestId,
        prepared: &PreparedPaidExecution,
    ) {
        out.push_str(&format!(
            "fee_source_id={} fee_source_version={} fee_source_digest={}\n",
            fee_ref.id, fee_ref.version, fee_ref.digest
        ));
        out.push_str(&format!("fee_balance={fee_balance}\n"));
        out.push_str(&format!("max_fee={max_fee}\n"));
        out.push_str(&format!(
            "minimum_fee_source_balance={}\n",
            fee_balance - max_fee
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
        out.push_str(&format!("gas_limit={gas_limit}\n"));
        out.push_str(&format!("nonce={nonce}\n"));
        out.push_str(&format!("request_id={request_id}\n"));
        out.push_str("freshness=enforced-at-execution-not-preparation\n");
        out.push_str(&format!(
            "signing_frame={}\n",
            encode_hex(prepared.signable_frame())
        ));
    }

    #[allow(clippy::too_many_arguments)]
    fn render_split_review(
        &self,
        request: &AssetSplitRequest,
        coin_ref: &ObjectRef,
        held: u64,
        remainder: u64,
        fee_ref: &ObjectRef,
        fee_balance: u64,
        prepared: &PreparedPaidExecution,
    ) -> Result<String, CliError> {
        let mut out: String = String::new();
        self.render_common(&mut out);
        out.push_str("entrypoint=split\n");
        out.push_str(&format!(
            "coin_id={} coin_version={} coin_digest={} coin_mode=write\n",
            coin_ref.id, coin_ref.version, coin_ref.digest
        ));
        out.push_str(&format!("held={held}\n"));
        out.push_str(&format!("split_amount={}\n", request.amount));
        out.push_str(&format!("remainder={remainder}\n"));
        out.push_str(&format!("recipient={}\n", encode_hex(&request.recipient)));
        out.push_str(&format!(
            "recipient_is_self={}\n",
            request.recipient == *self.trust.publisher.as_bytes()
        ));
        self.render_fee_and_frame(
            &mut out,
            fee_ref,
            fee_balance,
            request.max_fee,
            request.gas_limit,
            request.nonce,
            request.request_id,
            prepared,
        );
        if out.len() > MAX_SPLIT_MERGE_REVIEW_BYTES {
            return Err(invalid(
                "asset split review exceeds the maximum accepted display size",
            ));
        }
        Ok(out)
    }

    #[allow(clippy::too_many_arguments)]
    fn render_merge_review(
        &self,
        request: &AssetMergeRequest,
        into_ref: &ObjectRef,
        into_amount: u64,
        from_ref: &ObjectRef,
        from_amount: u64,
        checked_total: u64,
        fee_ref: &ObjectRef,
        fee_balance: u64,
        prepared: &PreparedPaidExecution,
    ) -> Result<String, CliError> {
        let mut out: String = String::new();
        self.render_common(&mut out);
        out.push_str("entrypoint=merge\n");
        out.push_str(&format!(
            "into_id={} into_version={} into_digest={} into_mode=write\n",
            into_ref.id, into_ref.version, into_ref.digest
        ));
        out.push_str(&format!("into_amount={into_amount}\n"));
        out.push_str(&format!(
            "from_id={} from_version={} from_digest={} from_mode=consume\n",
            from_ref.id, from_ref.version, from_ref.digest
        ));
        out.push_str(&format!("from_amount={from_amount}\n"));
        out.push_str(&format!("checked_total={checked_total}\n"));
        self.render_fee_and_frame(
            &mut out,
            fee_ref,
            fee_balance,
            request.max_fee,
            request.gas_limit,
            request.nonce,
            request.request_id,
            prepared,
        );
        if out.len() > MAX_SPLIT_MERGE_REVIEW_BYTES {
            return Err(invalid(
                "asset merge review exceeds the maximum accepted display size",
            ));
        }
        Ok(out)
    }
}
