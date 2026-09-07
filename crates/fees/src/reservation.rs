//! DR-0124 bounded fee reservation pricing.
//!
//! Deterministic reserve/settle quoting for one paid invocation: converts
//! `base_fee + execution_price * (L + R + S)` into a reserved asset amount
//! at admission and `base_fee + execution_price * (A + R + S)` into an
//! actual asset amount at settlement, both with one ceiling conversion. `L`
//! is the signed application gas limit, `A` is actual metered application
//! gas, and `R`/`S` are the committed fixed reserve/settle fuel allowances.
//! Calibrated values for `R` and `S` are supplied by the caller; this
//! component performs no calibration and decodes no asset or object bytes.

use crate::{Amount, GasSchedule, ceil_div};
use core::fmt;
use std::error::Error;

/// Maximum combined application limit and fixed reserve/settle allowances,
/// per DR-0124 (`L + R + S <= 1_000_000`).
const MAX_TOTAL_GAS_UNITS: u64 = 1_000_000;

/// Errors returned by DR-0124 reservation pricing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservationError {
    /// The gas schedule prices a resource this component does not yet meter.
    ///
    /// Only `base_fee` and `execution_price` are supported until signed
    /// resource maxima for reads/writes/storage/system calls exist.
    UnsupportedResourcePrice,
    /// The asset conversion divisor (fee units per asset unit) must be
    /// non-zero.
    ZeroConversionDivisor,
    /// The fixed reserve (`R`) and settle (`S`) allowances must each be
    /// positive.
    NonPositiveAllowance,
    /// `application_units + reserve_allowance + settle_allowance` exceeds
    /// the DR-0124 bound of 1,000,000.
    TotalGasLimitExceeded {
        application_units: u64,
        reserve_allowance: u64,
        settle_allowance: u64,
    },
    /// Checked arithmetic overflowed.
    ArithmeticOverflow,
    /// Actual application usage exceeded the admitted limit (`A > L`).
    ActualUsageExceedsLimit { actual: u64, limit: u64 },
    /// The signed maximum fee is below the computed reservation.
    MaxFeeExceeded { required: Amount, max_fee: Amount },
}

impl fmt::Display for ReservationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedResourcePrice => write!(
                f,
                "read/write/storage/system prices must be zero until signed resource maxima exist"
            ),
            Self::ZeroConversionDivisor => write!(f, "asset conversion divisor must be non-zero"),
            Self::NonPositiveAllowance => {
                write!(f, "reserve and settle allowances must be positive")
            }
            Self::TotalGasLimitExceeded {
                application_units,
                reserve_allowance,
                settle_allowance,
            } => write!(
                f,
                "application units {application_units} + reserve allowance {reserve_allowance} + settle allowance {settle_allowance} exceeds {MAX_TOTAL_GAS_UNITS}"
            ),
            Self::ArithmeticOverflow => write!(f, "reservation pricing arithmetic overflow"),
            Self::ActualUsageExceedsLimit { actual, limit } => write!(
                f,
                "actual application usage {actual} exceeds admitted limit {limit}"
            ),
            Self::MaxFeeExceeded { required, max_fee } => write!(
                f,
                "required reservation {required} exceeds max fee {max_fee}"
            ),
        }
    }
}

impl Error for ReservationError {}

/// Sums application/reserve/settle gas units with checked arithmetic and
/// enforces the DR-0124 `L + R + S <= 1_000_000` bound.
fn checked_total_gas(
    application_units: u64,
    reserve_allowance: u64,
    settle_allowance: u64,
) -> Result<u64, ReservationError> {
    let total: u64 = application_units
        .checked_add(reserve_allowance)
        .and_then(|value| value.checked_add(settle_allowance))
        .ok_or(ReservationError::ArithmeticOverflow)?;
    if total > MAX_TOTAL_GAS_UNITS {
        return Err(ReservationError::TotalGasLimitExceeded {
            application_units,
            reserve_allowance,
            settle_allowance,
        });
    }
    Ok(total)
}

/// Converts `base_fee + execution_price * total_gas_units` fee units into
/// one ceiling-rounded asset amount, reusing the crate's shared checked
/// ceiling divider.
fn quote_asset_units(
    schedule: &GasSchedule,
    fee_units_per_asset_unit: u64,
    total_gas_units: u64,
) -> Result<Amount, ReservationError> {
    let execution_cost: u64 = schedule
        .execution_price
        .checked_mul(total_gas_units)
        .ok_or(ReservationError::ArithmeticOverflow)?;
    let fee_units: u64 = schedule
        .base_fee
        .checked_add(execution_cost)
        .ok_or(ReservationError::ArithmeticOverflow)?;
    let asset_units: u64 = ceil_div(fee_units, fee_units_per_asset_unit)
        .map_err(|_| ReservationError::ArithmeticOverflow)?;
    Ok(Amount::new(asset_units))
}

/// A validated DR-0124 fixed pricing schedule bound to one committed
/// reserve/settle allowance pair and asset conversion divisor.
///
/// Constructing this type validates every fixed input once. [`Self::admit`]
/// and the resulting [`Admission::settle`] reuse those captured values, so
/// neither the schedule nor the reservation can be silently changed between
/// the reserve and settle phases of one invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReservationPricer {
    schedule: GasSchedule,
    fee_units_per_asset_unit: u64,
    reserve_allowance: u64,
    settle_allowance: u64,
}

impl ReservationPricer {
    /// Validates and captures the fixed schedule, asset conversion divisor,
    /// and the committed reserve (`R`) and settle (`S`) fuel allowances.
    ///
    /// Rejects any nonzero read/write/storage/system price, a zero
    /// conversion divisor, a non-positive `R` or `S`, and an `R + S` that
    /// already exceeds the DR-0124 total gas bound before any application
    /// limit is admitted.
    pub fn new(
        schedule: GasSchedule,
        fee_units_per_asset_unit: u64,
        reserve_allowance: u64,
        settle_allowance: u64,
    ) -> Result<Self, ReservationError> {
        if schedule.read_price != 0
            || schedule.write_price != 0
            || schedule.storage_price != 0
            || schedule.system_module_price != 0
        {
            return Err(ReservationError::UnsupportedResourcePrice);
        }
        if fee_units_per_asset_unit == 0 {
            return Err(ReservationError::ZeroConversionDivisor);
        }
        if reserve_allowance == 0 || settle_allowance == 0 {
            return Err(ReservationError::NonPositiveAllowance);
        }
        checked_total_gas(0, reserve_allowance, settle_allowance)?;

        Ok(Self {
            schedule,
            fee_units_per_asset_unit,
            reserve_allowance,
            settle_allowance,
        })
    }

    /// The committed reserve-phase fixed fuel allowance (`R`).
    #[must_use]
    pub const fn reserve_allowance(&self) -> u64 {
        self.reserve_allowance
    }

    /// The committed settle-phase fixed fuel allowance (`S`).
    #[must_use]
    pub const fn settle_allowance(&self) -> u64 {
        self.settle_allowance
    }

    /// Admits one invocation with application gas limit `L`.
    ///
    /// Computes `base_fee + execution_price * (L + R + S)` and converts it
    /// to asset units with one ceiling rounding. Rejects the admission if
    /// `L + R + S` exceeds the DR-0124 bound or if the reserved amount
    /// exceeds the signed `max_fee`.
    pub fn admit(
        &self,
        application_limit: u64,
        max_fee: Amount,
    ) -> Result<Admission, ReservationError> {
        let total_gas: u64 = checked_total_gas(
            application_limit,
            self.reserve_allowance,
            self.settle_allowance,
        )?;
        let reserved: Amount =
            quote_asset_units(&self.schedule, self.fee_units_per_asset_unit, total_gas)?;
        if reserved > max_fee {
            return Err(ReservationError::MaxFeeExceeded {
                required: reserved,
                max_fee,
            });
        }

        Ok(Admission {
            schedule: self.schedule.clone(),
            fee_units_per_asset_unit: self.fee_units_per_asset_unit,
            reserve_allowance: self.reserve_allowance,
            settle_allowance: self.settle_allowance,
            application_limit,
            reserved,
        })
    }
}

/// One bounded DR-0124 admission.
///
/// Captures the fixed schedule, asset divisor, allowances and the reserved
/// asset amount at admit time. Fields are private: settlement can only
/// proceed through [`Self::settle`], which reuses these captured values
/// rather than accepting a schedule or reservation from the caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admission {
    schedule: GasSchedule,
    fee_units_per_asset_unit: u64,
    reserve_allowance: u64,
    settle_allowance: u64,
    application_limit: u64,
    reserved: Amount,
}

impl Admission {
    /// The admitted application gas limit (`L`).
    #[must_use]
    pub const fn application_limit(&self) -> u64 {
        self.application_limit
    }

    /// The asset units reserved at admission.
    #[must_use]
    pub const fn reserved(&self) -> Amount {
        self.reserved
    }

    /// Settles this admission with actual metered application gas `A`.
    ///
    /// Requires `A <= L`. Computes `base_fee + execution_price * (A + R + S)`
    /// with the schedule and divisor captured at admission and converts it
    /// with one ceiling rounding. Returns the actual charge and the refund
    /// of unused reserved asset units (`refund + actual == reserved`).
    pub fn settle(&self, actual_application_units: u64) -> Result<Settlement, ReservationError> {
        if actual_application_units > self.application_limit {
            return Err(ReservationError::ActualUsageExceedsLimit {
                actual: actual_application_units,
                limit: self.application_limit,
            });
        }

        let total_gas: u64 = checked_total_gas(
            actual_application_units,
            self.reserve_allowance,
            self.settle_allowance,
        )?;
        let actual: Amount =
            quote_asset_units(&self.schedule, self.fee_units_per_asset_unit, total_gas)?;
        let refund: u64 = self
            .reserved
            .get()
            .checked_sub(actual.get())
            .ok_or(ReservationError::ArithmeticOverflow)?;

        Ok(Settlement {
            actual,
            refund: Amount::new(refund),
        })
    }
}

/// The result of settling one [`Admission`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settlement {
    /// Actual asset units charged.
    pub actual: Amount,
    /// Unused reserved asset units, to be returned to the signed refund
    /// recipient.
    pub refund: Amount,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schedule(base_fee: u64, execution_price: u64) -> GasSchedule {
        GasSchedule {
            base_fee,
            execution_price,
            read_price: 0,
            write_price: 0,
            storage_price: 0,
            system_module_price: 0,
        }
    }

    #[test]
    fn constructor_rejects_nonzero_read_write_storage_system_prices() {
        let base = schedule(1, 1);
        for mutate in [
            (|s: &mut GasSchedule| s.read_price = 1) as fn(&mut GasSchedule),
            |s: &mut GasSchedule| s.write_price = 1,
            |s: &mut GasSchedule| s.storage_price = 1,
            |s: &mut GasSchedule| s.system_module_price = 1,
        ] {
            let mut priced = base.clone();
            mutate(&mut priced);
            assert_eq!(
                ReservationPricer::new(priced, 1, 1, 1),
                Err(ReservationError::UnsupportedResourcePrice)
            );
        }
    }

    #[test]
    fn constructor_rejects_zero_conversion_divisor() {
        assert_eq!(
            ReservationPricer::new(schedule(1, 1), 0, 1, 1),
            Err(ReservationError::ZeroConversionDivisor)
        );
    }

    #[test]
    fn constructor_rejects_non_positive_allowances() {
        assert_eq!(
            ReservationPricer::new(schedule(1, 1), 1, 0, 1),
            Err(ReservationError::NonPositiveAllowance)
        );
        assert_eq!(
            ReservationPricer::new(schedule(1, 1), 1, 1, 0),
            Err(ReservationError::NonPositiveAllowance)
        );
    }

    #[test]
    fn constructor_rejects_allowances_that_already_exceed_the_bound() {
        assert_eq!(
            ReservationPricer::new(schedule(1, 1), 1, 600_000, 500_000),
            Err(ReservationError::TotalGasLimitExceeded {
                application_units: 0,
                reserve_allowance: 600_000,
                settle_allowance: 500_000,
            })
        );
    }

    #[test]
    fn constructor_rejects_overflowing_allowance_sum() {
        assert_eq!(
            ReservationPricer::new(schedule(1, 1), 1, u64::MAX, 1),
            Err(ReservationError::ArithmeticOverflow)
        );
    }

    #[test]
    fn admit_computes_ceiling_rounded_reservation() {
        let pricer = ReservationPricer::new(schedule(10, 3), 4, 2, 5).unwrap();
        // base_fee + execution_price * (L + R + S) = 10 + 3 * (1 + 2 + 5) = 34
        // ceil(34 / 4) = 9
        let admission = pricer.admit(1, Amount::new(9)).unwrap();
        assert_eq!(admission.application_limit(), 1);
        assert_eq!(admission.reserved(), Amount::new(9));
    }

    #[test]
    fn admit_rejects_total_gas_above_the_bound() {
        let pricer = ReservationPricer::new(schedule(0, 1), 1, 1, 1).unwrap();
        assert_eq!(
            pricer.admit(MAX_TOTAL_GAS_UNITS, Amount::new(u64::MAX)),
            Err(ReservationError::TotalGasLimitExceeded {
                application_units: MAX_TOTAL_GAS_UNITS,
                reserve_allowance: 1,
                settle_allowance: 1,
            })
        );
    }

    #[test]
    fn admit_rejects_multiplication_overflow() {
        let pricer = ReservationPricer::new(schedule(0, u64::MAX), 1, 1, 1).unwrap();
        assert_eq!(
            pricer.admit(1, Amount::new(u64::MAX)),
            Err(ReservationError::ArithmeticOverflow)
        );
    }

    #[test]
    fn admit_rejects_overflowing_total_gas_sum() {
        let pricer = ReservationPricer::new(schedule(0, 1), 1, 1, 1).unwrap();
        assert_eq!(
            pricer.admit(u64::MAX, Amount::new(u64::MAX)),
            Err(ReservationError::ArithmeticOverflow)
        );
    }

    #[test]
    fn admit_rejects_base_plus_execution_addition_overflow() {
        let pricer = ReservationPricer::new(schedule(u64::MAX, 1), 1, 1, 1).unwrap();
        assert_eq!(
            pricer.admit(0, Amount::new(u64::MAX)),
            Err(ReservationError::ArithmeticOverflow)
        );
    }

    #[test]
    fn admit_rejects_signed_max_fee_below_reserve() {
        let pricer = ReservationPricer::new(schedule(10, 3), 1, 2, 5).unwrap();
        // base_fee + execution_price * (L + R + S) = 10 + 3 * (0 + 2 + 5) = 31
        assert_eq!(
            pricer.admit(0, Amount::new(30)),
            Err(ReservationError::MaxFeeExceeded {
                required: Amount::new(31),
                max_fee: Amount::new(30),
            })
        );
    }

    #[test]
    fn settle_rejects_actual_usage_above_admitted_limit() {
        let pricer = ReservationPricer::new(schedule(0, 1), 1, 1, 1).unwrap();
        let admission = pricer.admit(5, Amount::new(u64::MAX)).unwrap();
        assert_eq!(
            admission.settle(6),
            Err(ReservationError::ActualUsageExceedsLimit {
                actual: 6,
                limit: 5
            })
        );
    }

    #[test]
    fn settle_computes_actual_charge_and_exact_refund() {
        let pricer = ReservationPricer::new(schedule(10, 3), 4, 2, 5).unwrap();
        // reserved: ceil((10 + 3 * (10 + 2 + 5)) / 4) = ceil(61 / 4) = 16
        let admission = pricer.admit(10, Amount::new(16)).unwrap();
        assert_eq!(admission.reserved(), Amount::new(16));

        // actual: ceil((10 + 3 * (4 + 2 + 5)) / 4) = ceil(43 / 4) = 11
        let settlement = admission.settle(4).unwrap();
        assert_eq!(settlement.actual, Amount::new(11));
        assert_eq!(settlement.refund, Amount::new(5));
        assert_eq!(
            settlement.actual.get() + settlement.refund.get(),
            admission.reserved().get()
        );
    }

    #[test]
    fn settle_uses_only_values_captured_at_admit_time() {
        let pricer = ReservationPricer::new(schedule(10, 3), 4, 2, 5).unwrap();
        let admission = pricer.admit(10, Amount::new(16)).unwrap();
        let _ = pricer;

        let settlement = admission.settle(4).unwrap();
        assert_eq!(settlement.actual, Amount::new(11));
        assert_eq!(settlement.refund, Amount::new(5));
    }

    #[test]
    fn zero_priced_schedule_is_arithmetically_supported() {
        let pricer = ReservationPricer::new(schedule(0, 0), 1, 1, 1).unwrap();
        let admission = pricer.admit(1_000, Amount::new(0)).unwrap();
        assert_eq!(admission.reserved(), Amount::new(0));

        let settlement = admission.settle(500).unwrap();
        assert_eq!(settlement.actual, Amount::new(0));
        assert_eq!(settlement.refund, Amount::new(0));
    }

    #[test]
    fn exact_and_rounded_ceiling_boundaries_near_u64_max() {
        // u64::MAX is odd, so u64::MAX / 2 is NOT exact: ceil rounds the
        // remaining 0.5 up to the well-known 1 << 63 boundary.
        let pricer = ReservationPricer::new(schedule(u64::MAX, 0), 2, 1, 1).unwrap();
        let admission = pricer.admit(0, Amount::new(1u64 << 63)).unwrap();
        assert_eq!(admission.reserved(), Amount::new(1u64 << 63));

        // u64::MAX - 1 is even, so this division is exact: no rounding is
        // added on top of the true quotient.
        let pricer = ReservationPricer::new(schedule(u64::MAX - 1, 0), 2, 1, 1).unwrap();
        let admission = pricer.admit(0, Amount::new((u64::MAX - 1) / 2)).unwrap();
        assert_eq!(admission.reserved(), Amount::new((u64::MAX - 1) / 2));

        // Non-exact division rounds up by exactly one unit.
        let pricer = ReservationPricer::new(schedule(u64::MAX, 0), 4, 1, 1).unwrap();
        let admission = pricer.admit(0, Amount::new(u64::MAX)).unwrap();
        let expected = u64::MAX / 4 + 1;
        assert_eq!(admission.reserved(), Amount::new(expected));
    }

    /// Independently computes `ceil((base_fee + execution_price * total_gas) / divisor)`
    /// using `u128` arithmetic, as an oracle independent of the library's
    /// checked `u64` computation path.
    fn ceiling_oracle(base_fee: u64, execution_price: u64, total_gas: u64, divisor: u64) -> u64 {
        let fee_units: u128 =
            u128::from(base_fee) + u128::from(execution_price) * u128::from(total_gas);
        let divisor: u128 = u128::from(divisor);
        let quotient: u128 = fee_units / divisor;
        let remainder: u128 = fee_units % divisor;
        let ceiling: u128 = if remainder == 0 {
            quotient
        } else {
            quotient + 1
        };
        u64::try_from(ceiling).expect("oracle fixture must fit in u64")
    }

    #[test]
    fn actual_never_exceeds_reserved_and_refund_plus_actual_equals_reserved() {
        // Deterministic property-style sweep over L, A <= L, base/execution
        // prices and conversion divisors.
        let reserve_allowance = 11;
        let settle_allowance = 7;
        let limits = [0u64, 1, 10, 999, 500_000, 999_982];
        let base_fees = [0u64, 1, 5, 1_000];
        let execution_prices = [0u64, 1, 3, 17];
        let divisors = [1u64, 2, 3, 7, 1_000];

        for &divisor in &divisors {
            for &base_fee in &base_fees {
                for &execution_price in &execution_prices {
                    let pricer = ReservationPricer::new(
                        schedule(base_fee, execution_price),
                        divisor,
                        reserve_allowance,
                        settle_allowance,
                    )
                    .unwrap();

                    for &limit in &limits {
                        // Every fixture keeps L + R + S <= MAX_TOTAL_GAS_UNITS,
                        // so admission must always succeed here.
                        let admission = pricer.admit(limit, Amount::new(u64::MAX)).unwrap();
                        let expected_reserved: u64 = ceiling_oracle(
                            base_fee,
                            execution_price,
                            limit + reserve_allowance + settle_allowance,
                            divisor,
                        );
                        assert_eq!(admission.reserved(), Amount::new(expected_reserved));

                        for &actual in &[0u64, limit / 2, limit] {
                            let settlement = admission.settle(actual).unwrap();
                            let expected_actual: u64 = ceiling_oracle(
                                base_fee,
                                execution_price,
                                actual + reserve_allowance + settle_allowance,
                                divisor,
                            );
                            assert_eq!(settlement.actual, Amount::new(expected_actual));
                            assert!(settlement.actual <= admission.reserved());
                            assert_eq!(
                                settlement.actual.get() + settlement.refund.get(),
                                admission.reserved().get()
                            );
                        }
                    }
                }
            }
        }
    }
}
