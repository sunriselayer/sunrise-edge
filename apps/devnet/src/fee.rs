//! The local devnet's trusted [`node_core::FeeEffectComposer`] implementation.
//!
//! Settles one fee charge over two ordinary
//! [`standard_assets::StandardAssetCoinV1`] bodies using the same strict
//! codec node-core's typed-entrypoint verification relies on. This is
//! trusted node composition, never reachable from request bytes: node-core
//! independently rebuilds identity/version/owner/type/schema for both
//! mutated objects and only asks this composer for the new amounts.

use node_core::{FeeChargeBodies, FeeChargeRequest, FeeCompositionError, FeeEffectComposer};
use standard_assets::{
    StandardAssetCoinV1, decode_standard_asset_coin_v1, encode_standard_asset_coin_v1,
};

/// Settles a fee charge by debiting the payer and crediting the treasury,
/// both ordinary [`StandardAssetCoinV1`] bodies for the same
/// [`standard_assets::AssetId`].
///
/// Unlike a plain checked-subtraction ledger, [`StandardAssetCoinV1::new`]
/// rejects an amount of exactly zero (F3, DR-0107): a fee debit that would
/// leave the payer coin at zero is unencodable and must be explicitly
/// rejected before ever calling `StandardAssetCoinV1::new`, rather than
/// surfacing as a generic encoding failure. A devnet consequence this
/// implies: once a fee coin's amount falls to exactly the current settled
/// fee, it becomes permanently unusable as a fee payer (see
/// `docs/guides/devnet.md`).
#[derive(Debug, Default, Clone, Copy)]
pub struct StandardAssetCoinFeeComposer;

impl FeeEffectComposer for StandardAssetCoinFeeComposer {
    fn compose_fee_charge(
        &self,
        request: &FeeChargeRequest<'_>,
    ) -> Result<FeeChargeBodies, FeeCompositionError> {
        let payer: StandardAssetCoinV1 = decode_standard_asset_coin_v1(request.payer_body)
            .map_err(|_| FeeCompositionError::MalformedBody)?;
        let treasury: StandardAssetCoinV1 = decode_standard_asset_coin_v1(request.treasury_body)
            .map_err(|_| FeeCompositionError::MalformedBody)?;

        if payer.asset_id() != request.asset_id || treasury.asset_id() != request.asset_id {
            return Err(FeeCompositionError::AssetMismatch);
        }

        let amount: u64 = request.amount.get();
        let remaining: u64 = payer
            .amount()
            .checked_sub(amount)
            .ok_or(FeeCompositionError::InsufficientBalance)?;
        // `StandardAssetCoinV1::new` rejects a zero amount outright: an exact
        // full-balance charge must be rejected here, explicitly, rather than
        // silently mapped to a confusing encoding failure (F3).
        if remaining == 0 {
            return Err(FeeCompositionError::InsufficientBalance);
        }
        let new_payer: StandardAssetCoinV1 = StandardAssetCoinV1::new(payer.asset_id(), remaining)
            .map_err(|_| FeeCompositionError::MalformedBody)?;

        let credited: u64 = treasury
            .amount()
            .checked_add(amount)
            .ok_or(FeeCompositionError::Overflow)?;
        let new_treasury: StandardAssetCoinV1 =
            StandardAssetCoinV1::new(treasury.asset_id(), credited)
                .map_err(|_| FeeCompositionError::Overflow)?;

        let payer_body: Vec<u8> = encode_standard_asset_coin_v1(&new_payer)
            .map_err(|_| FeeCompositionError::MalformedBody)?;
        let treasury_body: Vec<u8> = encode_standard_asset_coin_v1(&new_treasury)
            .map_err(|_| FeeCompositionError::MalformedBody)?;

        // Defense-in-depth re-check: decode both outputs back and assert the
        // asset id survived unchanged and both amounts are still non-zero,
        // before ever returning them to node-core.
        let reread_payer: StandardAssetCoinV1 = decode_standard_asset_coin_v1(&payer_body)
            .map_err(|_| FeeCompositionError::MalformedBody)?;
        let reread_treasury: StandardAssetCoinV1 = decode_standard_asset_coin_v1(&treasury_body)
            .map_err(|_| FeeCompositionError::MalformedBody)?;
        if reread_payer.asset_id() != request.asset_id
            || reread_treasury.asset_id() != request.asset_id
            || reread_payer.amount() == 0
            || reread_treasury.amount() == 0
        {
            return Err(FeeCompositionError::MalformedBody);
        }

        Ok(FeeChargeBodies {
            payer_body,
            treasury_body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fees::Amount;
    use standard_assets::AssetId;

    const ASSET: AssetId = AssetId::new([0x64; 32]);

    fn request<'a>(
        amount: u64,
        payer_body: &'a [u8],
        treasury_body: &'a [u8],
    ) -> FeeChargeRequest<'a> {
        FeeChargeRequest {
            asset_id: ASSET,
            amount: Amount::new(amount),
            payer_body,
            treasury_body,
        }
    }

    fn encoded(coin: StandardAssetCoinV1) -> Vec<u8> {
        encode_standard_asset_coin_v1(&coin).expect("valid test coin")
    }

    fn coin(asset_id: AssetId, amount: u64) -> StandardAssetCoinV1 {
        StandardAssetCoinV1::new(asset_id, amount).expect("non-zero test amount")
    }

    #[test]
    fn charges_exact_amount_when_amount_is_fee_plus_one() {
        let payer: Vec<u8> = encoded(coin(ASSET, 1_000));
        let treasury: Vec<u8> = encoded(coin(ASSET, 9));

        let bodies: FeeChargeBodies = StandardAssetCoinFeeComposer
            .compose_fee_charge(&request(40, &payer, &treasury))
            .expect("sufficient balance settles");

        let new_payer: StandardAssetCoinV1 =
            decode_standard_asset_coin_v1(&bodies.payer_body).unwrap();
        let new_treasury: StandardAssetCoinV1 =
            decode_standard_asset_coin_v1(&bodies.treasury_body).unwrap();
        assert_eq!(new_payer, coin(ASSET, 960));
        assert_eq!(new_treasury, coin(ASSET, 49));
    }

    #[test]
    fn charge_conserves_total_amount_across_both_coins() {
        let payer_before = coin(ASSET, 5_000);
        let treasury_before = coin(ASSET, 200);
        let payer: Vec<u8> = encoded(payer_before);
        let treasury: Vec<u8> = encoded(treasury_before);

        let bodies: FeeChargeBodies = StandardAssetCoinFeeComposer
            .compose_fee_charge(&request(75, &payer, &treasury))
            .expect("sufficient balance settles");

        let new_payer: StandardAssetCoinV1 =
            decode_standard_asset_coin_v1(&bodies.payer_body).unwrap();
        let new_treasury: StandardAssetCoinV1 =
            decode_standard_asset_coin_v1(&bodies.treasury_body).unwrap();
        let payer_delta: i128 = i128::from(new_payer.amount()) - i128::from(payer_before.amount());
        let treasury_delta: i128 =
            i128::from(new_treasury.amount()) - i128::from(treasury_before.amount());
        assert_eq!(payer_delta, -treasury_delta);
        assert_eq!(payer_delta, -75);
    }

    #[test]
    fn malformed_payer_body_is_rejected() {
        let treasury: Vec<u8> = encoded(coin(ASSET, 1));
        let malformed: [u8; 4] = [0xFF, 0x00, 0x11, 0x22];

        let error = StandardAssetCoinFeeComposer
            .compose_fee_charge(&request(1, &malformed, &treasury))
            .unwrap_err();
        assert_eq!(error, FeeCompositionError::MalformedBody);
    }

    #[test]
    fn malformed_treasury_body_is_rejected() {
        let payer: Vec<u8> = encoded(coin(ASSET, 1_000));
        let malformed: [u8; 4] = [0xFF, 0x00, 0x11, 0x22];

        let error = StandardAssetCoinFeeComposer
            .compose_fee_charge(&request(1, &payer, &malformed))
            .unwrap_err();
        assert_eq!(error, FeeCompositionError::MalformedBody);
    }

    #[test]
    fn wrong_payer_asset_id_is_rejected() {
        let other_asset: AssetId = AssetId::new([0x42; 32]);
        let payer: Vec<u8> = encoded(coin(other_asset, 1_000));
        let treasury: Vec<u8> = encoded(coin(ASSET, 1));

        let error = StandardAssetCoinFeeComposer
            .compose_fee_charge(&request(1, &payer, &treasury))
            .unwrap_err();
        assert_eq!(error, FeeCompositionError::AssetMismatch);
    }

    #[test]
    fn wrong_treasury_asset_id_is_rejected() {
        let other_asset: AssetId = AssetId::new([0x42; 32]);
        let payer: Vec<u8> = encoded(coin(ASSET, 1_000));
        let treasury: Vec<u8> = encoded(coin(other_asset, 1));

        let error = StandardAssetCoinFeeComposer
            .compose_fee_charge(&request(1, &payer, &treasury))
            .unwrap_err();
        assert_eq!(error, FeeCompositionError::AssetMismatch);
    }

    #[test]
    fn insufficient_balance_is_rejected() {
        let payer: Vec<u8> = encoded(coin(ASSET, 10));
        let treasury: Vec<u8> = encoded(coin(ASSET, 1));

        let error = StandardAssetCoinFeeComposer
            .compose_fee_charge(&request(11, &payer, &treasury))
            .unwrap_err();
        assert_eq!(error, FeeCompositionError::InsufficientBalance);
    }

    /// F3/DR-0107's load-bearing invariant: an exact full-balance charge
    /// would leave the payer coin at zero, which
    /// `StandardAssetCoinV1::new` categorically rejects, so the composer
    /// must reject it explicitly rather than let it surface as a confusing
    /// encoding failure or, worse, silently succeed with an unencodable
    /// coin.
    #[test]
    fn exact_balance_charge_is_rejected_rather_than_producing_a_zero_amount_coin() {
        let payer: Vec<u8> = encoded(coin(ASSET, 10));
        let treasury: Vec<u8> = encoded(coin(ASSET, 1));

        let error = StandardAssetCoinFeeComposer
            .compose_fee_charge(&request(10, &payer, &treasury))
            .unwrap_err();
        assert_eq!(error, FeeCompositionError::InsufficientBalance);
    }

    #[test]
    fn treasury_amount_overflow_is_rejected() {
        let payer: Vec<u8> = encoded(coin(ASSET, u64::MAX));
        let treasury: Vec<u8> = encoded(coin(ASSET, u64::MAX - 1));

        let error = StandardAssetCoinFeeComposer
            .compose_fee_charge(&request(5, &payer, &treasury))
            .unwrap_err();
        assert_eq!(error, FeeCompositionError::Overflow);
    }
}
