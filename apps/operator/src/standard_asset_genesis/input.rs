//! Closed public configuration for the offline Standard Asset preset.

use crate::common::{FlagSet, parse_hash_suite, parse_hex_32, read_bounded_file};
use crypto::{Ed25519OwnerAddressPolicy, validate_ed25519_owner_address};
use execution::publication::PublicationContext;
use fees::GasSchedule;
use hashing::HashSuiteResolver;
use node_core::genesis::MAX_GENESIS_OBJECTS;
use objects::ObjectId;
use protocol_types::{
    AtomicityDomainId, ChainId, Epoch, HashSuiteSchedule, ProtocolVersion, ValidatorId,
};
use std::{collections::BTreeSet, error::Error, ffi::OsString, path::PathBuf};

const MAX_TABLE_BYTES: usize = 16 * 1024;
const FLAGS: &[&str] = &[
    "--chain-id",
    "--protocol-version",
    "--epoch",
    "--suite",
    "--minimum-freeze-block-height",
    "--expected-genesis-authority",
    "--genesis-key-file",
    "--origin-seed",
    "--instance-seed",
    "--publication-request-id",
    "--initialization-request-id",
    "--definition-id",
    "--treasury-cap-id",
    "--mint-authority",
    "--fee-recipient",
    "--validators-file",
    "--allocations-file",
    "--initialization-gas-limit",
    "--base-fee",
    "--execution-price",
    "--read-price",
    "--write-price",
    "--storage-price",
    "--system-module-price",
    "--conversion-divisor",
    "--reserve-allowance",
    "--settle-allowance",
    "--publish-artifact-byte-price",
    "--publish-closure-node-price",
    "--min-bond",
    "--unbonding-epochs",
    "--max-validator-exposure",
    "--validation-domain",
    "--validation-checkpoint",
    "--timeout-seconds",
    "--output",
];

pub(super) struct Validator {
    pub id: ValidatorId,
    pub public_key: [u8; 32],
    pub voting_power: u64,
    pub bond_amount: u64,
    pub collateral_id: ObjectId,
}

pub(super) struct Allocation {
    pub owner: [u8; 32],
    pub amount: u64,
    pub coin_id: ObjectId,
}

pub(super) struct Economics {
    pub gas: GasSchedule,
    pub conversion_divisor: u64,
    pub reserve_allowance: u64,
    pub settle_allowance: u64,
    pub publish_artifact_byte_price: u64,
    pub publish_closure_node_price: u64,
    pub min_bond: u64,
    pub unbonding_epochs: u64,
    pub max_validator_exposure: Option<u64>,
}

pub(super) struct Config {
    pub resolver: HashSuiteResolver,
    pub context: PublicationContext,
    pub minimum_freeze_block_height: u64,
    pub authority: [u8; 32],
    pub key_file: PathBuf,
    pub origin_seed: [u8; 32],
    pub instance_seed: [u8; 32],
    pub publication_request_id: [u8; 32],
    pub initialization_request_id: [u8; 32],
    pub definition_id: ObjectId,
    pub treasury_cap_id: ObjectId,
    pub mint_authority: [u8; 32],
    pub fee_recipient: [u8; 32],
    pub validators_file: PathBuf,
    pub allocations_file: PathBuf,
    pub initialization_gas_limit: u64,
    pub economics: Economics,
    pub validation_domain: AtomicityDomainId,
    pub validation_checkpoint: u64,
    pub timeout_millis: u64,
    pub output: PathBuf,
}

fn decimal(value: &str, field: &str) -> Result<u64, Box<dyn Error>> {
    let number: u64 = value.parse().map_err(|_| format!("invalid {field}"))?;
    if number.to_string() != value {
        return Err(format!("{field} must be canonical unsigned decimal").into());
    }
    Ok(number)
}

fn number(flags: &mut FlagSet, field: &str) -> Result<u64, Box<dyn Error>> {
    decimal(&flags.one(field)?, field)
}

fn positive(flags: &mut FlagSet, field: &str) -> Result<u64, Box<dyn Error>> {
    let value: u64 = number(flags, field)?;
    if value == 0 {
        return Err(format!("{field} must be positive").into());
    }
    Ok(value)
}

fn bytes(flags: &mut FlagSet, field: &str) -> Result<[u8; 32], Box<dyn Error>> {
    Ok(parse_hex_32(&flags.one(field)?, field)?)
}

fn public_key(value: [u8; 32]) -> Result<[u8; 32], Box<dyn Error>> {
    validate_ed25519_owner_address(&value, Ed25519OwnerAddressPolicy::CanonicalPrimeOrder)?;
    Ok(value)
}

impl Config {
    pub(super) fn parse(tokens: impl Iterator<Item = OsString>) -> Result<Self, Box<dyn Error>> {
        let mut flags: FlagSet = FlagSet::parse(tokens, FLAGS, &[])?;
        let chain: ChainId =
            ChainId::new(flags.one("--chain-id")?).map_err(|_| "invalid --chain-id")?;
        let protocol: u32 = u32::try_from(positive(&mut flags, "--protocol-version")?)
            .map_err(|_| "protocol version exceeds u32")?;
        let version: ProtocolVersion = ProtocolVersion::new(protocol);
        let epoch: Epoch = Epoch::new(number(&mut flags, "--epoch")?);
        let suites: Vec<String> = flags.many("--suite");
        if suites.is_empty() || suites.len() > 64 {
            return Err("one to 64 explicit --suite entries required".into());
        }
        let schedule: Vec<HashSuiteSchedule> = suites
            .iter()
            .map(|value: &String| parse_hash_suite(value))
            .collect::<Result<Vec<HashSuiteSchedule>, String>>()?;
        let resolver: HashSuiteResolver = HashSuiteResolver::new(chain.clone(), version, schedule)?;
        let context: PublicationContext = PublicationContext::new(chain, version, epoch)?;
        let gas: GasSchedule = GasSchedule {
            base_fee: number(&mut flags, "--base-fee")?,
            execution_price: number(&mut flags, "--execution-price")?,
            read_price: number(&mut flags, "--read-price")?,
            write_price: number(&mut flags, "--write-price")?,
            storage_price: number(&mut flags, "--storage-price")?,
            system_module_price: number(&mut flags, "--system-module-price")?,
        };
        let exposure: String = flags.one("--max-validator-exposure")?;
        let max_validator_exposure: Option<u64> = if exposure == "none" {
            None
        } else {
            Some(decimal(&exposure, "--max-validator-exposure")?)
        };
        let economics: Economics = Economics {
            gas,
            conversion_divisor: positive(&mut flags, "--conversion-divisor")?,
            reserve_allowance: positive(&mut flags, "--reserve-allowance")?,
            settle_allowance: positive(&mut flags, "--settle-allowance")?,
            publish_artifact_byte_price: positive(&mut flags, "--publish-artifact-byte-price")?,
            publish_closure_node_price: positive(&mut flags, "--publish-closure-node-price")?,
            min_bond: positive(&mut flags, "--min-bond")?,
            unbonding_epochs: positive(&mut flags, "--unbonding-epochs")?,
            max_validator_exposure,
        };
        if economics
            .max_validator_exposure
            .is_some_and(|value: u64| value < economics.min_bond)
        {
            return Err("maximum exposure is below minimum bond".into());
        }
        let timeout_seconds: u64 = positive(&mut flags, "--timeout-seconds")?;
        let timeout_millis: u64 = timeout_seconds
            .checked_mul(1000)
            .ok_or("timeout overflow")?;
        if timeout_millis > native_http::MAX_INDEXED_OUTBOX_OPERATION_MILLIS {
            return Err("timeout exceeds the operator storage-operation bound".into());
        }
        let config: Self = Self {
            resolver,
            context,
            economics,
            timeout_millis,
            minimum_freeze_block_height: positive(&mut flags, "--minimum-freeze-block-height")?,
            authority: public_key(bytes(&mut flags, "--expected-genesis-authority")?)?,
            key_file: PathBuf::from(flags.one("--genesis-key-file")?),
            origin_seed: bytes(&mut flags, "--origin-seed")?,
            instance_seed: bytes(&mut flags, "--instance-seed")?,
            publication_request_id: bytes(&mut flags, "--publication-request-id")?,
            initialization_request_id: bytes(&mut flags, "--initialization-request-id")?,
            definition_id: ObjectId::new(bytes(&mut flags, "--definition-id")?),
            treasury_cap_id: ObjectId::new(bytes(&mut flags, "--treasury-cap-id")?),
            mint_authority: public_key(bytes(&mut flags, "--mint-authority")?)?,
            fee_recipient: public_key(bytes(&mut flags, "--fee-recipient")?)?,
            validators_file: PathBuf::from(flags.one("--validators-file")?),
            allocations_file: PathBuf::from(flags.one("--allocations-file")?),
            initialization_gas_limit: positive(&mut flags, "--initialization-gas-limit")?,
            validation_domain: AtomicityDomainId::new(bytes(&mut flags, "--validation-domain")?)
                .map_err(|_| "zero validation domain")?,
            validation_checkpoint: number(&mut flags, "--validation-checkpoint")?,
            output: PathBuf::from(flags.one("--output")?),
        };
        flags.finish()?;
        Ok(config)
    }

    pub(super) fn tables(&self) -> Result<(Vec<Validator>, Vec<Allocation>), Box<dyn Error>> {
        let validator_bytes: Vec<u8> =
            read_bounded_file(&self.validators_file, MAX_TABLE_BYTES, "validators table")?;
        let allocation_bytes: Vec<u8> =
            read_bounded_file(&self.allocations_file, MAX_TABLE_BYTES, "allocations table")?;
        let validator_text: &str = std::str::from_utf8(&validator_bytes)?;
        let allocation_text: &str = std::str::from_utf8(&allocation_bytes)?;
        let mut validators: Vec<Validator> = Vec::new();
        let mut allocations: Vec<Allocation> = Vec::new();
        let mut ids: BTreeSet<ValidatorId> = BTreeSet::new();
        let mut keys: BTreeSet<[u8; 32]> = BTreeSet::new();
        let mut objects: BTreeSet<ObjectId> = BTreeSet::new();
        if !objects.insert(self.definition_id) || !objects.insert(self.treasury_cap_id) {
            return Err("definition and TreasuryCap IDs alias".into());
        }
        for line in validator_text.lines() {
            if validators.len() >= MAX_GENESIS_OBJECTS - 2 {
                return Err("too many validators for genesis object limit".into());
            }
            let fields: Vec<&str> = line.split_ascii_whitespace().collect();
            if fields.len() != 5 {
                return Err(
                    "validator row needs id public-key power bond-amount collateral-id".into(),
                );
            }
            let validator: Validator = Validator {
                id: ValidatorId::new(parse_hex_32(fields[0], "validator ID")?),
                public_key: public_key(parse_hex_32(fields[1], "validator public key")?)?,
                voting_power: decimal(fields[2], "voting power")?,
                bond_amount: decimal(fields[3], "bond amount")?,
                collateral_id: ObjectId::new(parse_hex_32(fields[4], "collateral ID")?),
            };
            if validator.voting_power == 0
                || validator.bond_amount < self.economics.min_bond
                || self
                    .economics
                    .max_validator_exposure
                    .is_some_and(|limit: u64| validator.bond_amount > limit)
            {
                return Err("validator needs positive power and an eligible bounded bond".into());
            }
            if !ids.insert(validator.id)
                || !keys.insert(validator.public_key)
                || !objects.insert(validator.collateral_id)
            {
                return Err("duplicate validator ID, registered public key or object ID".into());
            }
            validators.push(validator);
        }
        if validators.is_empty() {
            return Err("genesis committee is empty".into());
        }
        for line in allocation_text.lines() {
            if objects.len() >= MAX_GENESIS_OBJECTS {
                return Err("too many genesis objects".into());
            }
            let fields: Vec<&str> = line.split_ascii_whitespace().collect();
            if fields.len() != 3 {
                return Err("allocation row needs owner amount coin-id".into());
            }
            let allocation: Allocation = Allocation {
                owner: public_key(parse_hex_32(fields[0], "allocation owner")?)?,
                amount: decimal(fields[1], "allocation amount")?,
                coin_id: ObjectId::new(parse_hex_32(fields[2], "allocation Coin ID")?),
            };
            if allocation.amount == 0 || !objects.insert(allocation.coin_id) {
                return Err("allocation needs a positive amount and a distinct Coin ID".into());
            }
            allocations.push(allocation);
        }
        validators.sort_by_key(|validator: &Validator| validator.id);
        allocations.sort_by_key(|allocation: &Allocation| allocation.coin_id);
        // Public arithmetic refuses before the authority key is loaded. The
        // package builder independently rechecks its exact encoded bodies.
        let mut supply: u64 = 0;
        for validator in &validators {
            supply = supply
                .checked_add(validator.bond_amount)
                .ok_or("collateral supply overflow")?;
        }
        for allocation in &allocations {
            supply = supply
                .checked_add(allocation.amount)
                .ok_or("allocation supply overflow")?;
        }
        Ok((validators, allocations))
    }
}
