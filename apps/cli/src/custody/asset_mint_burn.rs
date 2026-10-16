//! Pure StandardAsset `mint`/`burn` preparation and review (no network, no
//! signing) for the separate mint/burn-only local custody profile
//! (DR-0253). Shares its genesis/code/instance/policy pin with the
//! transfer (DR-0246) and split/merge (DR-0249) families via
//! [`super::asset_trust::PinnedAssetTrust`]; only this module's own
//! entrypoint/argument/supply-arithmetic checks differ.
//!
//! The published WASM remains the sole execution oracle: custody never adds
//! new protocol math and never changes what the contract itself computes or
//! enforces on-chain. What custody adds is an *independent* pre-approval
//! review of the exact same arithmetic the contract performs, computed from
//! the caller-supplied canonical preimages under custody's own pinned
//! trust — never from the caller's claimed amounts or claimed outcome — so
//! a human approver sees the before/after `TreasuryCap` supply for the
//! exact referenced cap/coin preimage versions before ever typing the
//! confirmation line. This is not independently fetched live chain state;
//! currentness is still enforced only at execution (see
//! `freshness=enforced-at-execution-not-preparation` in the rendered
//! review). `mint` owns the `TreasuryCap` (Write)
//! and creates a fresh `Coin` for the reviewed amount/recipient; `burn`
//! consumes a whole owned `Coin` (Consume) together with the `TreasuryCap`
//! (Write) — never a partial amount — and the exact consumed Coin amount
//! reduces supply.

use protocol_types::HashPurpose;

use sunrise_edge_client::call::CallIntent;
use sunrise_edge_client::{
    AccessEntry, AccessManifest, AccessMode, Amount, Digest32, Epoch, FeeSourceConsent, Object,
    ObjectRef, PaidApplication, PreparedPaidExecution, RequestId, ReservationAccessKind,
    VerifiedGenesisRoot,
};

use public_standard_asset::{
    asset_type_argument, coin_amount, mint_arguments, no_arguments, treasury_supply,
};

use crate::error::CliError;
use crate::hex::encode_hex;

use super::asset_trust::{PinnedAssetTrust, safe_ascii};
use super::config::CustodyConfig;

/// Maximum bytes of either rendered, bounded, display-only review.
const MAX_MINT_BURN_REVIEW_BYTES: usize = 64 * 1024;

const MINT_ENTRYPOINT: &str = "mint";
const BURN_ENTRYPOINT: &str = "burn";

fn failure(error: impl std::error::Error + Send + Sync + 'static) -> CliError {
    CliError::LocalExecution(Box::new(error))
}

fn invalid(message: &'static str) -> CliError {
    failure(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message,
    ))
}

/// One caller-supplied `mint` request: one owned `TreasuryCap` Write
/// preimage, a distinct owned fee source, the positive amount, the
/// recipient, and the signed replay/fee fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AssetMintRequest {
    pub(crate) cap_bytes: Vec<u8>,
    pub(crate) fee_bytes: Vec<u8>,
    pub(crate) amount: u64,
    pub(crate) recipient: [u8; 32],
    pub(crate) nonce: u64,
    pub(crate) request_id: RequestId,
    pub(crate) max_fee: u64,
    pub(crate) gas_limit: u64,
}

/// One caller-supplied `burn` request: one owned `TreasuryCap` Write
/// preimage, a distinct owned whole `Coin` Consume preimage, a distinct
/// owned fee source, and the signed replay/fee fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AssetBurnRequest {
    pub(crate) cap_bytes: Vec<u8>,
    pub(crate) coin_bytes: Vec<u8>,
    pub(crate) fee_bytes: Vec<u8>,
    pub(crate) nonce: u64,
    pub(crate) request_id: RequestId,
    pub(crate) max_fee: u64,
    pub(crate) gas_limit: u64,
}

/// One bounded mint or burn request, as carried by the kind-4 wire codec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AssetMintBurnRequest {
    Mint(Box<AssetMintRequest>),
    Burn(Box<AssetBurnRequest>),
}

/// One immutable prepared `mint` plus its bounded review.
pub(super) struct PreparedAssetMint {
    pub(super) prepared: PreparedPaidExecution,
    pub(super) review: String,
    pub(super) supply_before: u64,
    pub(super) supply_after: u64,
    pub(super) fee_balance: u64,
}

/// One immutable prepared `burn` plus its bounded review.
pub(super) struct PreparedAssetBurn {
    pub(super) prepared: PreparedPaidExecution,
    pub(super) review: String,
    pub(super) supply_before: u64,
    pub(super) burn_amount: u64,
    pub(super) supply_after: u64,
    pub(super) fee_balance: u64,
}

/// The mint/burn family's own trust: the shared genesis pin plus the
/// `mint`/`burn`-specific `prepare`/review logic, including the
/// independently rebuilt checked supply arithmetic.
pub(super) struct AssetMintBurnTrust {
    trust: PinnedAssetTrust,
}

impl AssetMintBurnTrust {
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

    /// Prepares one `mint` paid Call. Independently decodes the cap's
    /// current supply from its own verified preimage, rejects a zero
    /// amount, and rejects a supply computation that would overflow —
    /// before any approval or signing step, exactly mirroring the
    /// published contract's own checks.
    pub(super) fn prepare_mint(
        &self,
        request: &AssetMintRequest,
    ) -> Result<PreparedAssetMint, CliError> {
        sunrise_edge_client::validate_ed25519_owner_address(
            &request.recipient,
            sunrise_edge_client::Ed25519OwnerAddressPolicy::CanonicalPrimeOrder,
        )
        .map_err(failure)?;
        let cap_object: Object = self.trust.decode_bounded_object(
            &request.cap_bytes,
            "mint cap preimage exceeds the maximum accepted size",
            "mint cap preimage is not the exact canonical object encoding",
        )?;
        let fee_object: Object = self.trust.decode_bounded_object(
            &request.fee_bytes,
            "fee source preimage exceeds the maximum accepted size",
            "fee source preimage is not the exact canonical object encoding",
        )?;
        self.trust.validate_owned_cap(
            &cap_object,
            "mint cap is not owned by the pinned custody publisher",
            "mint cap schema does not match the genesis Standard Asset schema",
            "mint cap is not the genesis Standard Asset TreasuryCap type",
        )?;
        self.trust.validate_owned_coin(
            &fee_object,
            "fee source is not owned by the pinned custody publisher",
            "fee source schema does not match the genesis Standard Asset schema",
            "fee source is not the genesis Standard Asset Coin type",
        )?;
        if cap_object.id == fee_object.id {
            return Err(invalid("mint cap and fee source must be distinct objects"));
        }
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
        if request.amount == 0 {
            return Err(invalid("mint amount must be positive"));
        }
        let supply_before: u64 = treasury_supply(&cap_object.data).map_err(failure)?;
        let supply_after: u64 = supply_before
            .checked_add(request.amount)
            .ok_or_else(|| invalid("mint supply would overflow"))?;

        let cap_digest: Digest32 = self.object_digest(&request.cap_bytes)?;
        let fee_digest: Digest32 = self.object_digest(&request.fee_bytes)?;
        let cap_ref: ObjectRef = ObjectRef {
            id: cap_object.id,
            version: cap_object.version,
            digest: cap_digest,
        };
        let fee_ref: ObjectRef = ObjectRef {
            id: fee_object.id,
            version: fee_object.version,
            digest: fee_digest,
        };

        let mut access: AccessManifest = AccessManifest::new();
        access.entries.push(AccessEntry {
            object_ref: cap_ref.clone(),
            mode: AccessMode::Write,
        });
        let call: CallIntent = CallIntent {
            context: self.trust.context.clone(),
            request_id: *request.request_id.as_bytes(),
            sender: *self.trust.publisher.as_bytes(),
            nonce: request.nonce,
            code: self.trust.fee_policy.code.clone(),
            instance: self.trust.fee_policy.instance.clone(),
            entrypoint: MINT_ENTRYPOINT.to_owned(),
            type_arguments: vec![asset_type_argument(&self.trust.asset)],
            access,
            arguments: mint_arguments(request.amount, &request.recipient).map_err(failure)?,
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

        let review: String = self.render_mint_review(
            request,
            &cap_ref,
            supply_before,
            supply_after,
            &fee_ref,
            fee_balance,
            &prepared,
        )?;
        Ok(PreparedAssetMint {
            prepared,
            review,
            supply_before,
            supply_after,
            fee_balance,
        })
    }

    /// Prepares one `burn` paid Call. Independently decodes the cap's
    /// current supply and the whole coin's exact amount from their own
    /// verified preimages, rejects a zero-amount coin, and rejects a supply
    /// computation that would underflow — before any approval or signing
    /// step, exactly mirroring the published contract's own checks.
    pub(super) fn prepare_burn(
        &self,
        request: &AssetBurnRequest,
    ) -> Result<PreparedAssetBurn, CliError> {
        let cap_object: Object = self.trust.decode_bounded_object(
            &request.cap_bytes,
            "burn cap preimage exceeds the maximum accepted size",
            "burn cap preimage is not the exact canonical object encoding",
        )?;
        let coin_object: Object = self.trust.decode_bounded_object(
            &request.coin_bytes,
            "burn coin preimage exceeds the maximum accepted size",
            "burn coin preimage is not the exact canonical object encoding",
        )?;
        let fee_object: Object = self.trust.decode_bounded_object(
            &request.fee_bytes,
            "fee source preimage exceeds the maximum accepted size",
            "fee source preimage is not the exact canonical object encoding",
        )?;
        self.trust.validate_owned_cap(
            &cap_object,
            "burn cap is not owned by the pinned custody publisher",
            "burn cap schema does not match the genesis Standard Asset schema",
            "burn cap is not the genesis Standard Asset TreasuryCap type",
        )?;
        self.trust.validate_owned_coin(
            &coin_object,
            "burn coin is not owned by the pinned custody publisher",
            "burn coin schema does not match the genesis Standard Asset schema",
            "burn coin is not the genesis Standard Asset Coin type",
        )?;
        self.trust.validate_owned_coin(
            &fee_object,
            "fee source is not owned by the pinned custody publisher",
            "fee source schema does not match the genesis Standard Asset schema",
            "fee source is not the genesis Standard Asset Coin type",
        )?;
        if cap_object.id == coin_object.id {
            return Err(invalid("burn cap and coin must be distinct objects"));
        }
        if fee_object.id == cap_object.id || fee_object.id == coin_object.id {
            return Err(invalid(
                "fee source must be distinct from every burn application input",
            ));
        }
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
        let burn_amount: u64 = coin_amount(&coin_object.data).map_err(failure)?;
        if burn_amount == 0 {
            return Err(invalid("burn coin amount must be positive"));
        }
        let supply_before: u64 = treasury_supply(&cap_object.data).map_err(failure)?;
        let supply_after: u64 = supply_before
            .checked_sub(burn_amount)
            .ok_or_else(|| invalid("burn amount exceeds the current supply"))?;

        let cap_digest: Digest32 = self.object_digest(&request.cap_bytes)?;
        let coin_digest: Digest32 = self.object_digest(&request.coin_bytes)?;
        let fee_digest: Digest32 = self.object_digest(&request.fee_bytes)?;
        let cap_ref: ObjectRef = ObjectRef {
            id: cap_object.id,
            version: cap_object.version,
            digest: cap_digest,
        };
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
            object_ref: cap_ref.clone(),
            mode: AccessMode::Write,
        });
        access.entries.push(AccessEntry {
            object_ref: coin_ref.clone(),
            mode: AccessMode::Consume,
        });
        let call: CallIntent = CallIntent {
            context: self.trust.context.clone(),
            request_id: *request.request_id.as_bytes(),
            sender: *self.trust.publisher.as_bytes(),
            nonce: request.nonce,
            code: self.trust.fee_policy.code.clone(),
            instance: self.trust.fee_policy.instance.clone(),
            entrypoint: BURN_ENTRYPOINT.to_owned(),
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

        let review: String = self.render_burn_review(
            request,
            &cap_ref,
            supply_before,
            &coin_ref,
            burn_amount,
            supply_after,
            &fee_ref,
            fee_balance,
            &prepared,
        )?;
        Ok(PreparedAssetBurn {
            prepared,
            review,
            supply_before,
            burn_amount,
            supply_after,
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
    fn render_mint_review(
        &self,
        request: &AssetMintRequest,
        cap_ref: &ObjectRef,
        supply_before: u64,
        supply_after: u64,
        fee_ref: &ObjectRef,
        fee_balance: u64,
        prepared: &PreparedPaidExecution,
    ) -> Result<String, CliError> {
        let mut out: String = String::new();
        self.render_common(&mut out);
        out.push_str("entrypoint=mint\n");
        out.push_str(&format!(
            "cap_id={} cap_version={} cap_digest={} cap_mode=write\n",
            cap_ref.id, cap_ref.version, cap_ref.digest
        ));
        out.push_str(&format!("supply_before={supply_before}\n"));
        out.push_str(&format!("mint_amount={}\n", request.amount));
        out.push_str(&format!("supply_after={supply_after}\n"));
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
        if out.len() > MAX_MINT_BURN_REVIEW_BYTES {
            return Err(invalid(
                "asset mint review exceeds the maximum accepted display size",
            ));
        }
        Ok(out)
    }

    #[allow(clippy::too_many_arguments)]
    fn render_burn_review(
        &self,
        request: &AssetBurnRequest,
        cap_ref: &ObjectRef,
        supply_before: u64,
        coin_ref: &ObjectRef,
        burn_amount: u64,
        supply_after: u64,
        fee_ref: &ObjectRef,
        fee_balance: u64,
        prepared: &PreparedPaidExecution,
    ) -> Result<String, CliError> {
        let mut out: String = String::new();
        self.render_common(&mut out);
        out.push_str("entrypoint=burn\n");
        out.push_str(&format!(
            "cap_id={} cap_version={} cap_digest={} cap_mode=write\n",
            cap_ref.id, cap_ref.version, cap_ref.digest
        ));
        out.push_str(&format!("supply_before={supply_before}\n"));
        out.push_str(&format!(
            "coin_id={} coin_version={} coin_digest={} coin_mode=consume\n",
            coin_ref.id, coin_ref.version, coin_ref.digest
        ));
        out.push_str(&format!("burn_amount={burn_amount}\n"));
        out.push_str(&format!("supply_after={supply_after}\n"));
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
        if out.len() > MAX_MINT_BURN_REVIEW_BYTES {
            return Err(invalid(
                "asset burn review exceeds the maximum accepted display size",
            ));
        }
        Ok(out)
    }
}
