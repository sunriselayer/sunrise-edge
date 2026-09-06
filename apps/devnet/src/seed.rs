//! Idempotent, fail-closed Standard Asset v1 coin seeding for the local
//! devnet.
//!
//! Replaces the removed protocol-3 `AssetAccount` seeding with the
//! protocol-4 Standard Asset v1 model (DR-0107): each configured dev owner
//! receives one transferable [`standard_assets::StandardAssetCoinV1`] and
//! one distinct fee-payer coin; the separate treasury owner receives one
//! ordinary treasury coin. Every coin uses the same fixed devnet
//! [`standard_assets::AssetId`] (see `crate::standard_asset::derive_devnet_asset_id`).

use crate::{
    config::{DevOwner, MAX_DEVNET_OWNERS},
    genesis::DEVNET_DOMAIN_BYTES,
};
use abi::{AbiError, verify_type_id};
use canonical_encoding::{
    CanonicalDecodingError, CanonicalEncodingError, CanonicalFrame, CanonicalStruct,
    decode_canonical_frame,
};
use crypto::{Ed25519OwnerAddressError, Ed25519OwnerAddressPolicy, validate_ed25519_owner_address};
use hashing::{HashSuiteResolver, HashingError, verify_digest};
use objects::{
    Address, Object, ObjectError, ObjectId, ObjectRef, Owner, decode_object, encode_object,
    encode_object_ref,
};
use protocol_types::{AtomicityDomainId, Digest32, Epoch, HashPurpose};
use runtime::{
    BlobStore, DurableCommitOutcome, DurableCommitRejection, DurableInvocationError,
    DurableInvocationTransaction, DurableObjectChanges, DurableObjectHead, DurableObjectHeadRead,
    DurableObjectMutation, DurableObjectMutationEntry, DurableObjectOwnerProjection,
    DurableObjectPayload, DurableObjectProvenance, DurableObjectRoutingProjection,
    DurableObjectVersion, DurableObjectVersionRecord, DurableOperationContext, DurableReadError,
    DurableRequestId, DurableRequestReceipt, IndeterminateCommitReason, IndexedOutboxContractError,
    RuntimeError, StructuredDurableDomainStateStore, WriterFenceGeneration,
};
use standard_assets::{
    AssetId, STANDARD_ASSET_SCHEMA_VERSION_V1, StandardAssetCoinV1, StandardAssetError,
    coin_type_tag, decode_standard_asset_coin_v1, derive_coin_type_id,
    encode_standard_asset_coin_v1,
};
use std::{collections::BTreeSet, error::Error, fmt};

const TRANSFER_COIN_SLOT: u64 = 1;
const FEE_COIN_SLOT: u64 = 2;
const TREASURY_COIN_SLOT: u64 = 1;

/// Initial amount seeded into every dev owner's transferable coin.
const INITIAL_TRANSFER_COIN_AMOUNT: u64 = 1_000_000;
/// Initial amount seeded into every dev owner's fee coin.
///
/// Deliberately generous (see `docs/guides/devnet.md`): once a fee coin's
/// amount falls to exactly the currently settled fee, `StandardAssetCoinFeeComposer`
/// permanently refuses to debit it further (F3, DR-0107).
const INITIAL_FEE_COIN_AMOUNT: u64 = 1_000_000;
/// Initial amount seeded into the treasury coin.
///
/// Must be non-zero: unlike the removed `AssetAccount`, `StandardAssetCoinV1`
/// categorically rejects a zero amount, so the treasury cannot start empty.
const INITIAL_TREASURY_COIN_AMOUNT: u64 = 1;

const PROTOCOL_CONTEXT_MARKER_TYPE_ID: u16 = 0x7A10;
const PROTOCOL_CONTEXT_MARKER_ENCODING_VERSION: u16 = 1;
/// Fixed, protocol-version-independent object identifier for the persisted
/// protocol-context marker. Deliberately **not** derived through
/// [`HashSuiteResolver::hash_for_purpose`] (which mixes in
/// `protocol_version`): a marker whose own identity depended on the value it
/// exists to check could never detect a mismatch.
const PROTOCOL_CONTEXT_MARKER_OBJECT_ID: ObjectId = ObjectId::new([0xFE; 32]);

/// One dev owner's seeded transferable + fee coin pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeededDevOwnerCoins {
    owner: DevOwner,
    transfer_coin: ObjectRef,
    fee_coin: ObjectRef,
    transfer_amount: u64,
    fee_amount: u64,
}

impl SeededDevOwnerCoins {
    /// Returns the configured development owner these coins were seeded for.
    #[must_use]
    pub const fn owner(&self) -> DevOwner {
        self.owner
    }

    /// Returns the transferable coin's current reference.
    #[must_use]
    pub const fn transfer_coin(&self) -> &ObjectRef {
        &self.transfer_coin
    }

    /// Returns the fee-payer coin's current reference.
    #[must_use]
    pub const fn fee_coin(&self) -> &ObjectRef {
        &self.fee_coin
    }

    fn checked_total_amount(&self) -> Option<u64> {
        self.transfer_amount.checked_add(self.fee_amount)
    }
}

/// Whether this boot created or verified one dev owner's seeded coin pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SeedDevOwnerCoinsOutcome {
    /// Both coins and the seed receipt were committed atomically by this call.
    Created(SeededDevOwnerCoins),
    /// Both coins and their immutable seed history already existed and were verified.
    Existing(SeededDevOwnerCoins),
}

impl SeedDevOwnerCoinsOutcome {
    /// Returns the verified coin pair regardless of whether this call created it.
    #[must_use]
    pub const fn coins(&self) -> &SeededDevOwnerCoins {
        match self {
            Self::Created(coins) | Self::Existing(coins) => coins,
        }
    }
}

/// The treasury owner's one seeded ordinary treasury coin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeededTreasuryCoin {
    owner: DevOwner,
    coin: ObjectRef,
    amount: u64,
}

impl SeededTreasuryCoin {
    /// Returns the configured treasury owner.
    #[must_use]
    pub const fn owner(&self) -> DevOwner {
        self.owner
    }

    /// Returns the treasury coin's current reference.
    #[must_use]
    pub const fn coin(&self) -> &ObjectRef {
        &self.coin
    }
}

/// Whether this boot created or verified the treasury's seeded coin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SeedTreasuryCoinOutcome {
    /// The coin and the seed receipt were committed atomically by this call.
    Created(SeededTreasuryCoin),
    /// The coin and its immutable seed history already existed and were verified.
    Existing(SeededTreasuryCoin),
}

impl SeedTreasuryCoinOutcome {
    /// Returns the verified treasury coin regardless of whether this call
    /// created it.
    #[must_use]
    pub const fn coin(&self) -> &SeededTreasuryCoin {
        match self {
            Self::Created(coin) | Self::Existing(coin) => coin,
        }
    }
}

/// Verifies the fixed devnet asset's total seeded supply across every dev
/// owner's coin pair and the treasury coin.
///
/// Redefines the pre-Standard-Asset-v1 uniform two-account check (F10,
/// DR-0107): the expected total is a fixed function of the configured dev-
/// owner count and the fixed treasury seed amount, never of current
/// balances, and the uniqueness set is over **seed** owners and object ids —
/// never current owners, since a transferable coin may legitimately end up
/// owned by an address outside the configured set after a real transfer.
pub fn verify_seeded_asset_supply(
    dev_outcomes: &[SeedDevOwnerCoinsOutcome],
    treasury_outcome: &SeedTreasuryCoinOutcome,
) -> Result<(), DevnetSeedError> {
    if dev_outcomes.is_empty() || dev_outcomes.len() >= MAX_DEVNET_OWNERS {
        return Err(DevnetSeedError::AssetInvariantViolation);
    }
    let mut owners: BTreeSet<DevOwner> = BTreeSet::new();
    let mut object_ids: BTreeSet<ObjectId> = BTreeSet::new();
    let mut actual_supply: u64 = 0;
    for outcome in dev_outcomes {
        let coins: &SeededDevOwnerCoins = outcome.coins();
        if !owners.insert(coins.owner)
            || !object_ids.insert(coins.transfer_coin.id)
            || !object_ids.insert(coins.fee_coin.id)
        {
            return Err(DevnetSeedError::AssetInvariantViolation);
        }
        let owner_total: u64 = coins
            .checked_total_amount()
            .ok_or(DevnetSeedError::AssetInvariantViolation)?;
        actual_supply = actual_supply
            .checked_add(owner_total)
            .ok_or(DevnetSeedError::AssetInvariantViolation)?;
    }
    let treasury: &SeededTreasuryCoin = treasury_outcome.coin();
    if owners.contains(&treasury.owner) || !object_ids.insert(treasury.coin.id) {
        return Err(DevnetSeedError::AssetInvariantViolation);
    }
    actual_supply = actual_supply
        .checked_add(treasury.amount)
        .ok_or(DevnetSeedError::AssetInvariantViolation)?;

    let owner_count: u64 =
        u64::try_from(dev_outcomes.len()).map_err(|_| DevnetSeedError::AssetInvariantViolation)?;
    let per_owner_total: u64 = INITIAL_TRANSFER_COIN_AMOUNT
        .checked_add(INITIAL_FEE_COIN_AMOUNT)
        .ok_or(DevnetSeedError::AssetInvariantViolation)?;
    let expected_supply: u64 = per_owner_total
        .checked_mul(owner_count)
        .and_then(|total| total.checked_add(INITIAL_TREASURY_COIN_AMOUNT))
        .ok_or(DevnetSeedError::AssetInvariantViolation)?;
    if actual_supply != expected_supply {
        return Err(DevnetSeedError::AssetInvariantViolation);
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct ExpectedSeedCoin {
    initial_object: Object,
    initial_digest: Digest32,
}

impl ExpectedSeedCoin {
    fn object_ref(&self) -> ObjectRef {
        ObjectRef {
            id: self.initial_object.id,
            version: self.initial_object.version,
            digest: self.initial_digest,
        }
    }
}

#[derive(Clone, Debug)]
struct ExpectedDevOwnerSeed {
    domain: AtomicityDomainId,
    transfer: ExpectedSeedCoin,
    fee: ExpectedSeedCoin,
    receipt: DurableRequestReceipt,
}

#[derive(Clone, Debug)]
struct ExpectedTreasurySeed {
    domain: AtomicityDomainId,
    treasury: ExpectedSeedCoin,
    receipt: DurableRequestReceipt,
}

/// Seeds one dev owner's transferable coin and distinct fee coin.
///
/// Creation is one all-or-none structured durable transaction. A restart
/// never overwrites existing coins: it verifies both current immutable
/// versions and their version-one seed history before returning. Per F9, a
/// dev owner's two seeded coins are protocol-indistinguishable — same type,
/// schema, asset, and (at seed time) owner — and either may legitimately
/// have been used as the whole-coin transfer source (its owner changes to
/// any admissible `Owner::Address`, DR-0107) or as the fee payer (its
/// amount changes, never its owner) since seeding, independently of which
/// coin was seeded into which slot. Restart verification therefore relaxes
/// both coins' current owner and amount identically: each must still
/// resolve to an admissible `Owner::Address` and a nonzero canonical amount
/// under the exact seeded object identity, type, schema, and asset id, but
/// neither slot is frozen to ownership-only or amount-only movement.
/// Callers seeding every configured owner must finish with
/// [`verify_seeded_asset_supply`].
#[allow(clippy::too_many_arguments)]
pub fn seed_dev_owner_coins<S>(
    store: &S,
    blob_store: &dyn BlobStore,
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    asset_id: AssetId,
    owner: DevOwner,
    boot_generation: WriterFenceGeneration,
    context: &DurableOperationContext,
) -> Result<SeedDevOwnerCoinsOutcome, DevnetSeedError>
where
    S: StructuredDurableDomainStateStore + ?Sized,
{
    validate_ed25519_owner_address(
        owner.as_bytes(),
        Ed25519OwnerAddressPolicy::CanonicalPrimeOrder,
    )
    .map_err(DevnetSeedError::InadmissibleOwner)?;
    if context.writer_fence() != boot_generation {
        return Err(DevnetSeedError::ContextFenceMismatch {
            context: context.writer_fence(),
            boot: boot_generation,
        });
    }

    let expected: ExpectedDevOwnerSeed =
        build_expected_dev_owner_seed(resolver, epoch, asset_id, owner)?;
    let transfer_head: DurableObjectHead = store
        .get_object_head(
            context,
            expected.domain,
            expected.transfer.initial_object.id,
        )
        .map_err(DevnetSeedError::Read)?;
    let fee_head: DurableObjectHead = store
        .get_object_head(context, expected.domain, expected.fee.initial_object.id)
        .map_err(DevnetSeedError::Read)?;

    match (&transfer_head, &fee_head) {
        (DurableObjectHead::Absent, DurableObjectHead::Absent) => create_dev_owner_seed(
            store,
            blob_store,
            resolver,
            epoch,
            asset_id,
            owner,
            boot_generation,
            context,
            expected,
        ),
        (DurableObjectHead::Current { .. }, DurableObjectHead::Current { .. }) => {
            let coins: SeededDevOwnerCoins = verify_existing_dev_owner_seed(
                store,
                blob_store,
                resolver,
                epoch,
                asset_id,
                owner,
                boot_generation,
                context,
                &expected,
                &transfer_head,
                &fee_head,
            )?;
            Ok(SeedDevOwnerCoinsOutcome::Existing(coins))
        }
        _ => Err(DevnetSeedError::UnexpectedHeadPair {
            first: head_kind(&transfer_head),
            second: head_kind(&fee_head),
        }),
    }
}

fn build_expected_dev_owner_seed(
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    asset_id: AssetId,
    owner: DevOwner,
) -> Result<ExpectedDevOwnerSeed, DevnetSeedError> {
    let domain: AtomicityDomainId = AtomicityDomainId::new(DEVNET_DOMAIN_BYTES)
        .map_err(|_| DevnetSeedError::InvalidStaticDomain)?;
    let coin_type_hash: Digest32 = derive_coin_type_id(resolver, epoch, asset_id)?;
    let transfer_coin: StandardAssetCoinV1 =
        StandardAssetCoinV1::new(asset_id, INITIAL_TRANSFER_COIN_AMOUNT)?;
    let fee_coin: StandardAssetCoinV1 =
        StandardAssetCoinV1::new(asset_id, INITIAL_FEE_COIN_AMOUNT)?;
    let transfer: ExpectedSeedCoin = build_expected_coin(
        resolver,
        epoch,
        Address::new(*owner.as_bytes()),
        TRANSFER_COIN_SLOT,
        coin_type_hash,
        transfer_coin,
    )?;
    let fee: ExpectedSeedCoin = build_expected_coin(
        resolver,
        epoch,
        Address::new(*owner.as_bytes()),
        FEE_COIN_SLOT,
        coin_type_hash,
        fee_coin,
    )?;
    if transfer.initial_object.id == fee.initial_object.id {
        return Err(DevnetSeedError::ObjectIdCollision);
    }

    let receipt: DurableRequestReceipt =
        build_seed_receipt(resolver, epoch, &transfer.object_ref())?;

    Ok(ExpectedDevOwnerSeed {
        domain,
        transfer,
        fee,
        receipt,
    })
}

fn build_expected_coin(
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    owner: Address,
    slot: u64,
    coin_type_hash: Digest32,
    coin: StandardAssetCoinV1,
) -> Result<ExpectedSeedCoin, DevnetSeedError> {
    let address_owner: Owner = Owner::Address(owner);
    let body: Vec<u8> = encode_standard_asset_coin_v1(&coin)?;

    // The identifier descriptor reuses the existing canonical Object frame:
    // zero ObjectId is a descriptor namespace marker and `version` is the
    // explicit slot. The actual stored object never uses either descriptor
    // value. This avoids ad-hoc byte concatenation and a new unratified
    // canonical type identifier.
    let descriptor: Object = Object {
        id: ObjectId::new([0; 32]),
        version: slot,
        owner: address_owner.clone(),
        type_hash: coin_type_hash,
        schema_version: STANDARD_ASSET_SCHEMA_VERSION_V1,
        data: body.clone(),
    };
    let descriptor_bytes: Vec<u8> = encode_object(&descriptor)?;
    let object_id_digest: Digest32 =
        resolver.hash_for_purpose(epoch, HashPurpose::Object, &descriptor_bytes)?;
    let object: Object = Object {
        id: ObjectId::new(object_id_digest.bytes()),
        version: DurableObjectVersion::FIRST.get(),
        owner: address_owner,
        type_hash: coin_type_hash,
        schema_version: STANDARD_ASSET_SCHEMA_VERSION_V1,
        data: body,
    };
    let canonical_object: Vec<u8> = encode_object(&object)?;
    let initial_digest: Digest32 =
        resolver.hash_for_purpose(epoch, HashPurpose::Object, &canonical_object)?;
    Ok(ExpectedSeedCoin {
        initial_object: object,
        initial_digest,
    })
}

/// An `ObjectRef` is already a stable canonical record. Using a coin's
/// immutable version-one reference as the seed receipt avoids inventing a
/// new devnet-local wire type purely to name "the first seeded coin".
fn build_seed_receipt(
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    marker: &ObjectRef,
) -> Result<DurableRequestReceipt, DevnetSeedError> {
    let receipt_bytes: Vec<u8> = encode_object_ref(marker)?;
    let request_digest: Digest32 =
        resolver.hash_for_purpose(epoch, HashPurpose::Transaction, &receipt_bytes)?;
    let event_digest: Digest32 =
        resolver.hash_for_purpose(epoch, HashPurpose::NodeEvent, &receipt_bytes)?;
    let request_id: DurableRequestId = DurableRequestId::new(request_digest.bytes())?;
    Ok(DurableRequestReceipt::new(
        request_id,
        event_digest,
        receipt_bytes,
    )?)
}

#[allow(clippy::too_many_arguments)]
fn create_dev_owner_seed<S>(
    store: &S,
    blob_store: &dyn BlobStore,
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    asset_id: AssetId,
    owner: DevOwner,
    boot_generation: WriterFenceGeneration,
    context: &DurableOperationContext,
    expected: ExpectedDevOwnerSeed,
) -> Result<SeedDevOwnerCoinsOutcome, DevnetSeedError>
where
    S: StructuredDurableDomainStateStore + ?Sized,
{
    let provenance: DurableObjectProvenance =
        DurableObjectProvenance::new(resolver.chain_id().clone(), resolver.protocol_version());
    let transfer_record: DurableObjectVersionRecord =
        DurableObjectVersionRecord::from_inline_object(
            expected.transfer.initial_object.clone(),
            expected.transfer.initial_digest,
            provenance.clone(),
            boot_generation.get(),
        )?;
    let fee_record: DurableObjectVersionRecord = DurableObjectVersionRecord::from_inline_object(
        expected.fee.initial_object.clone(),
        expected.fee.initial_digest,
        provenance,
        boot_generation.get(),
    )?;
    let owner_projection: DurableObjectOwnerProjection =
        DurableObjectOwnerProjection::from_owner(Owner::Address(Address::new(*owner.as_bytes())))?;
    let routing_projection: DurableObjectRoutingProjection =
        DurableObjectRoutingProjection::new(None)?;
    let reads: Vec<DurableObjectHeadRead> = vec![
        DurableObjectHeadRead::new(
            expected.transfer.initial_object.id,
            DurableObjectHead::Absent,
        ),
        DurableObjectHeadRead::new(expected.fee.initial_object.id, DurableObjectHead::Absent),
    ];
    let mutations: Vec<DurableObjectMutationEntry> = vec![
        DurableObjectMutationEntry::new(
            expected.transfer.initial_object.id,
            DurableObjectMutation::Create {
                version: transfer_record,
                owner_projection: owner_projection.clone(),
                routing_projection: routing_projection.clone(),
            },
        ),
        DurableObjectMutationEntry::new(
            expected.fee.initial_object.id,
            DurableObjectMutation::Create {
                version: fee_record,
                owner_projection,
                routing_projection,
            },
        ),
    ];
    let objects: DurableObjectChanges = DurableObjectChanges::new(reads, mutations)?;
    let invocation: DurableInvocationTransaction = DurableInvocationTransaction::new(
        expected.domain,
        None,
        objects,
        expected.receipt.clone(),
        None,
    )?;

    match store.commit_invocation(context, invocation) {
        DurableCommitOutcome::Committed => Ok(SeedDevOwnerCoinsOutcome::Created(
            initial_dev_owner_coins(owner, &expected),
        )),
        DurableCommitOutcome::Rejected(
            DurableCommitRejection::ObjectConflict { .. }
            | DurableCommitRejection::RequestAlreadyCommitted,
        ) => reconcile_existing_dev_owner_seed(
            store,
            blob_store,
            resolver,
            epoch,
            asset_id,
            owner,
            boot_generation,
            context,
            &expected,
        ),
        DurableCommitOutcome::Rejected(rejection) => {
            Err(DevnetSeedError::CommitRejected(rejection))
        }
        DurableCommitOutcome::Indeterminate(reason) => {
            let receipt: Option<DurableRequestReceipt> = store
                .get_request_receipt(context, expected.domain, expected.receipt.request_id())
                .map_err(DevnetSeedError::Read)?;
            match receipt {
                Some(receipt) if receipt == expected.receipt => reconcile_existing_dev_owner_seed(
                    store,
                    blob_store,
                    resolver,
                    epoch,
                    asset_id,
                    owner,
                    boot_generation,
                    context,
                    &expected,
                ),
                Some(_) => Err(DevnetSeedError::ReceiptMismatch),
                None => Err(DevnetSeedError::CommitIndeterminate(reason)),
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn reconcile_existing_dev_owner_seed<S>(
    store: &S,
    blob_store: &dyn BlobStore,
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    asset_id: AssetId,
    owner: DevOwner,
    boot_generation: WriterFenceGeneration,
    context: &DurableOperationContext,
    expected: &ExpectedDevOwnerSeed,
) -> Result<SeedDevOwnerCoinsOutcome, DevnetSeedError>
where
    S: StructuredDurableDomainStateStore + ?Sized,
{
    let transfer_head: DurableObjectHead = store
        .get_object_head(
            context,
            expected.domain,
            expected.transfer.initial_object.id,
        )
        .map_err(DevnetSeedError::Read)?;
    let fee_head: DurableObjectHead = store
        .get_object_head(context, expected.domain, expected.fee.initial_object.id)
        .map_err(DevnetSeedError::Read)?;
    let coins: SeededDevOwnerCoins = verify_existing_dev_owner_seed(
        store,
        blob_store,
        resolver,
        epoch,
        asset_id,
        owner,
        boot_generation,
        context,
        expected,
        &transfer_head,
        &fee_head,
    )?;
    Ok(SeedDevOwnerCoinsOutcome::Existing(coins))
}

#[derive(Clone, Copy)]
enum CoinOwnerExpectation {
    /// The current owner must equal exactly this address (the treasury
    /// coin: it is never a valid whole-coin transfer source or destination
    /// for this entrypoint).
    Exact(Address),
    /// The current owner may be any address admissible under the canonical
    /// prime-order Ed25519 policy (F9: both of a dev owner's seeded coins
    /// relax this far after real seeding, since either may have been used
    /// as a whole-coin transfer source; never at creation time).
    AnyAdmissible,
}

#[derive(Debug)]
struct VerifiedCurrentCoin {
    object_ref: ObjectRef,
    coin: StandardAssetCoinV1,
}

#[allow(clippy::too_many_arguments)]
fn verify_current_coin<S>(
    store: &S,
    blob_store: &dyn BlobStore,
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    boot_generation: WriterFenceGeneration,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    head: &DurableObjectHead,
    expected: &ExpectedSeedCoin,
    asset_id: AssetId,
    owner_expectation: CoinOwnerExpectation,
) -> Result<VerifiedCurrentCoin, DevnetSeedError>
where
    S: StructuredDurableDomainStateStore + ?Sized,
{
    let (object_version, head_digest, owner_projection, routing_projection): (
        DurableObjectVersion,
        Digest32,
        &DurableObjectOwnerProjection,
        &DurableObjectRoutingProjection,
    ) = match head {
        DurableObjectHead::Current {
            object_version,
            digest,
            owner_projection,
            routing_projection,
            ..
        } => (
            *object_version,
            *digest,
            owner_projection,
            routing_projection,
        ),
        DurableObjectHead::Absent | DurableObjectHead::Tombstoned { .. } => {
            return Err(DevnetSeedError::StoredObjectMismatch {
                object_id: expected.initial_object.id,
                detail: "object head is not current",
            });
        }
    };

    let expected_routing_projection: DurableObjectRoutingProjection =
        DurableObjectRoutingProjection::new(None)?;
    if routing_projection != &expected_routing_projection {
        return Err(DevnetSeedError::StoredObjectMismatch {
            object_id: expected.initial_object.id,
            detail: "head routing projection differs",
        });
    }

    let current_owner_address: Address = match owner_expectation {
        CoinOwnerExpectation::Exact(address) => match owner_projection.owner() {
            Some(Owner::Address(actual)) if *actual == address => address,
            _ => {
                return Err(DevnetSeedError::StoredObjectMismatch {
                    object_id: expected.initial_object.id,
                    detail: "head owner projection differs from the expected exact owner",
                });
            }
        },
        CoinOwnerExpectation::AnyAdmissible => match owner_projection.owner() {
            Some(Owner::Address(actual)) => {
                validate_ed25519_owner_address(
                    actual.as_bytes(),
                    Ed25519OwnerAddressPolicy::CanonicalPrimeOrder,
                )
                .map_err(DevnetSeedError::InadmissibleOwner)?;
                *actual
            }
            _ => {
                return Err(DevnetSeedError::StoredObjectMismatch {
                    object_id: expected.initial_object.id,
                    detail: "head owner projection is not an admissible address",
                });
            }
        },
    };
    let expected_owner: Owner = Owner::Address(current_owner_address);

    let record: DurableObjectVersionRecord = store
        .get_object_version(context, domain, expected.initial_object.id, object_version)
        .map_err(DevnetSeedError::Read)?
        .ok_or(DevnetSeedError::MissingObjectVersion {
            object_id: expected.initial_object.id,
            version: object_version,
        })?;
    if record.object_id() != expected.initial_object.id
        || record.object_version() != object_version
        || record.digest() != head_digest
        || record.schema_version() != STANDARD_ASSET_SCHEMA_VERSION_V1
    {
        return Err(DevnetSeedError::StoredObjectMismatch {
            object_id: expected.initial_object.id,
            detail: "head and immutable metadata differ",
        });
    }
    verify_record_context(&record, resolver, boot_generation)?;

    let canonical_bytes: Vec<u8> = match record.payload() {
        DurableObjectPayload::Inline(inline) => inline.canonical_bytes().to_vec(),
        DurableObjectPayload::BlobReference(blob_digest) => {
            let bytes: Vec<u8> = blob_store
                .get_blob(blob_digest)
                .map_err(DevnetSeedError::BlobStore)?
                .ok_or(DevnetSeedError::MissingBlob {
                    object_id: expected.initial_object.id,
                    blob_digest: *blob_digest,
                })?;
            let blob_digest_valid: bool = verify_digest(
                blob_digest,
                HashPurpose::Object,
                record.provenance().protocol_version(),
                record.provenance().chain_id(),
                &bytes,
            )?;
            if !blob_digest_valid {
                return Err(DevnetSeedError::StoredObjectMismatch {
                    object_id: expected.initial_object.id,
                    detail: "fetched blob bytes do not hash to their own blob digest",
                });
            }
            bytes
        }
    };
    let object: Object = decode_object(&canonical_bytes)?;
    if object.id != expected.initial_object.id
        || object.version != object_version.get()
        || object.owner != expected_owner
        || object.schema_version != STANDARD_ASSET_SCHEMA_VERSION_V1
    {
        return Err(DevnetSeedError::StoredObjectMismatch {
            object_id: expected.initial_object.id,
            detail: "typed object identity, owner, or schema differs",
        });
    }
    // F4: the object's nominal Coin<A> type is verified through
    // `abi::verify_type_id`, never by raw `Digest32` equality against a
    // recomputed-under-the-current-suite value: an object committed under an
    // algorithm trusted at an earlier epoch must remain valid across a later
    // hash-suite rotation.
    let type_ok: bool =
        verify_type_id(resolver, &object.type_hash, epoch, &coin_type_tag(asset_id))
            .map_err(DevnetSeedError::TypedAbi)?;
    if !type_ok {
        return Err(DevnetSeedError::StoredObjectMismatch {
            object_id: expected.initial_object.id,
            detail: "coin nominal type failed verify_type_id",
        });
    }
    let canonical_object: Vec<u8> = encode_object(&object)?;
    if canonical_bytes != canonical_object {
        return Err(DevnetSeedError::StoredObjectMismatch {
            object_id: expected.initial_object.id,
            detail: "stored object bytes are not the exact canonical encoding",
        });
    }
    let digest_valid: bool = verify_digest(
        &record.digest(),
        HashPurpose::Object,
        record.provenance().protocol_version(),
        record.provenance().chain_id(),
        &canonical_bytes,
    )?;
    if !digest_valid {
        return Err(DevnetSeedError::StoredObjectMismatch {
            object_id: expected.initial_object.id,
            detail: "stored object digest does not verify",
        });
    }
    let coin: StandardAssetCoinV1 = decode_standard_asset_coin_v1(&object.data)?;
    if coin.asset_id() != asset_id || encode_standard_asset_coin_v1(&coin)? != object.data {
        return Err(DevnetSeedError::StoredObjectMismatch {
            object_id: expected.initial_object.id,
            detail: "coin body or asset identifier differs",
        });
    }
    Ok(VerifiedCurrentCoin {
        object_ref: ObjectRef {
            id: object.id,
            version: object.version,
            digest: record.digest(),
        },
        coin,
    })
}

fn verify_initial_record<S>(
    store: &S,
    resolver: &HashSuiteResolver,
    boot_generation: WriterFenceGeneration,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    expected: &ExpectedSeedCoin,
) -> Result<(), DevnetSeedError>
where
    S: StructuredDurableDomainStateStore + ?Sized,
{
    let record: DurableObjectVersionRecord = store
        .get_object_version(
            context,
            domain,
            expected.initial_object.id,
            DurableObjectVersion::FIRST,
        )
        .map_err(DevnetSeedError::Read)?
        .ok_or(DevnetSeedError::MissingObjectVersion {
            object_id: expected.initial_object.id,
            version: DurableObjectVersion::FIRST,
        })?;
    verify_record_context(&record, resolver, boot_generation)?;
    let inline = match record.payload() {
        DurableObjectPayload::Inline(inline) => inline,
        DurableObjectPayload::BlobReference(_) => {
            return Err(DevnetSeedError::BlobBackedSeedObject(
                expected.initial_object.id,
            ));
        }
    };
    let canonical_expected: Vec<u8> = encode_object(&expected.initial_object)?;
    if record.object_id() != expected.initial_object.id
        || record.object_version() != DurableObjectVersion::FIRST
        || record.digest() != expected.initial_digest
        || record.schema_version() != STANDARD_ASSET_SCHEMA_VERSION_V1
        || inline.object() != &expected.initial_object
        || inline.canonical_bytes() != canonical_expected
    {
        return Err(DevnetSeedError::StoredObjectMismatch {
            object_id: expected.initial_object.id,
            detail: "immutable version-one seed record differs",
        });
    }
    let digest_valid: bool = verify_digest(
        &record.digest(),
        HashPurpose::Object,
        record.provenance().protocol_version(),
        record.provenance().chain_id(),
        inline.canonical_bytes(),
    )?;
    if !digest_valid {
        return Err(DevnetSeedError::StoredObjectMismatch {
            object_id: expected.initial_object.id,
            detail: "immutable version-one seed digest does not verify",
        });
    }
    Ok(())
}

fn verify_record_context(
    record: &DurableObjectVersionRecord,
    resolver: &HashSuiteResolver,
    boot_generation: WriterFenceGeneration,
) -> Result<(), DevnetSeedError> {
    if record.provenance().chain_id() != resolver.chain_id()
        || record.provenance().protocol_version() != resolver.protocol_version()
    {
        return Err(DevnetSeedError::StoredObjectMismatch {
            object_id: record.object_id(),
            detail: "creating chain or protocol-version provenance differs",
        });
    }
    let checkpoint: u64 = record.created_checkpoint();
    if checkpoint == 0 || checkpoint > boot_generation.get() {
        return Err(DevnetSeedError::StoredObjectMismatch {
            object_id: record.object_id(),
            detail: "created checkpoint is zero or from a future boot generation",
        });
    }
    Ok(())
}

fn verify_seed_receipt<S>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    expected: &DurableRequestReceipt,
) -> Result<(), DevnetSeedError>
where
    S: StructuredDurableDomainStateStore + ?Sized,
{
    let receipt: DurableRequestReceipt = store
        .get_request_receipt(context, domain, expected.request_id())
        .map_err(DevnetSeedError::Read)?
        .ok_or(DevnetSeedError::MissingSeedReceipt)?;
    if &receipt != expected {
        return Err(DevnetSeedError::ReceiptMismatch);
    }
    Ok(())
}

fn initial_dev_owner_coins(
    owner: DevOwner,
    expected: &ExpectedDevOwnerSeed,
) -> SeededDevOwnerCoins {
    SeededDevOwnerCoins {
        owner,
        transfer_coin: expected.transfer.object_ref(),
        fee_coin: expected.fee.object_ref(),
        transfer_amount: INITIAL_TRANSFER_COIN_AMOUNT,
        fee_amount: INITIAL_FEE_COIN_AMOUNT,
    }
}

fn head_kind(head: &DurableObjectHead) -> &'static str {
    match head {
        DurableObjectHead::Absent => "absent",
        DurableObjectHead::Tombstoned { .. } => "tombstoned",
        DurableObjectHead::Current { .. } => "current",
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_existing_dev_owner_seed<S>(
    store: &S,
    blob_store: &dyn BlobStore,
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    asset_id: AssetId,
    owner: DevOwner,
    boot_generation: WriterFenceGeneration,
    context: &DurableOperationContext,
    expected: &ExpectedDevOwnerSeed,
    transfer_head: &DurableObjectHead,
    fee_head: &DurableObjectHead,
) -> Result<SeededDevOwnerCoins, DevnetSeedError>
where
    S: StructuredDurableDomainStateStore + ?Sized,
{
    if !matches!(transfer_head, DurableObjectHead::Current { .. })
        || !matches!(fee_head, DurableObjectHead::Current { .. })
    {
        return Err(DevnetSeedError::UnexpectedHeadPair {
            first: head_kind(transfer_head),
            second: head_kind(fee_head),
        });
    }

    // Both seeded coins are protocol-indistinguishable: either may have been
    // used as the whole-coin transfer source (owner moves) or as the fee
    // payer (amount moves) since seeding, so both are verified under the
    // identical relaxed expectation (see `seed_dev_owner_coins`'s docs, F9).
    let transfer: VerifiedCurrentCoin = verify_current_coin(
        store,
        blob_store,
        resolver,
        epoch,
        boot_generation,
        context,
        expected.domain,
        transfer_head,
        &expected.transfer,
        asset_id,
        CoinOwnerExpectation::AnyAdmissible,
    )?;
    let fee: VerifiedCurrentCoin = verify_current_coin(
        store,
        blob_store,
        resolver,
        epoch,
        boot_generation,
        context,
        expected.domain,
        fee_head,
        &expected.fee,
        asset_id,
        CoinOwnerExpectation::AnyAdmissible,
    )?;

    verify_initial_record(
        store,
        resolver,
        boot_generation,
        context,
        expected.domain,
        &expected.transfer,
    )?;
    verify_initial_record(
        store,
        resolver,
        boot_generation,
        context,
        expected.domain,
        &expected.fee,
    )?;
    verify_seed_receipt(store, context, expected.domain, &expected.receipt)?;

    Ok(SeededDevOwnerCoins {
        owner,
        transfer_coin: transfer.object_ref,
        fee_coin: fee.object_ref,
        transfer_amount: transfer.coin.amount(),
        fee_amount: fee.coin.amount(),
    })
}

// ── Treasury coin seeding ─────────────────────────────────────────────────

/// Seeds the distinct treasury owner's one ordinary treasury coin.
#[allow(clippy::too_many_arguments)]
pub fn seed_treasury_coin<S>(
    store: &S,
    blob_store: &dyn BlobStore,
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    asset_id: AssetId,
    treasury_owner: DevOwner,
    boot_generation: WriterFenceGeneration,
    context: &DurableOperationContext,
) -> Result<SeedTreasuryCoinOutcome, DevnetSeedError>
where
    S: StructuredDurableDomainStateStore + ?Sized,
{
    validate_ed25519_owner_address(
        treasury_owner.as_bytes(),
        Ed25519OwnerAddressPolicy::CanonicalPrimeOrder,
    )
    .map_err(DevnetSeedError::InadmissibleOwner)?;
    if context.writer_fence() != boot_generation {
        return Err(DevnetSeedError::ContextFenceMismatch {
            context: context.writer_fence(),
            boot: boot_generation,
        });
    }

    let expected: ExpectedTreasurySeed =
        build_expected_treasury_seed(resolver, epoch, asset_id, treasury_owner)?;
    let head: DurableObjectHead = store
        .get_object_head(
            context,
            expected.domain,
            expected.treasury.initial_object.id,
        )
        .map_err(DevnetSeedError::Read)?;

    match &head {
        DurableObjectHead::Absent => create_treasury_seed(
            store,
            blob_store,
            resolver,
            epoch,
            asset_id,
            treasury_owner,
            boot_generation,
            context,
            expected,
        ),
        DurableObjectHead::Current { .. } => {
            let coin: SeededTreasuryCoin = verify_existing_treasury_seed(
                store,
                blob_store,
                resolver,
                epoch,
                asset_id,
                treasury_owner,
                boot_generation,
                context,
                &expected,
                &head,
            )?;
            Ok(SeedTreasuryCoinOutcome::Existing(coin))
        }
        DurableObjectHead::Tombstoned { .. } => Err(DevnetSeedError::UnexpectedHead {
            object_id: expected.treasury.initial_object.id,
            kind: head_kind(&head),
        }),
    }
}

fn build_expected_treasury_seed(
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    asset_id: AssetId,
    treasury_owner: DevOwner,
) -> Result<ExpectedTreasurySeed, DevnetSeedError> {
    let domain: AtomicityDomainId = AtomicityDomainId::new(DEVNET_DOMAIN_BYTES)
        .map_err(|_| DevnetSeedError::InvalidStaticDomain)?;
    let coin_type_hash: Digest32 = derive_coin_type_id(resolver, epoch, asset_id)?;
    let treasury_coin: StandardAssetCoinV1 =
        StandardAssetCoinV1::new(asset_id, INITIAL_TREASURY_COIN_AMOUNT)?;
    let treasury: ExpectedSeedCoin = build_expected_coin(
        resolver,
        epoch,
        Address::new(*treasury_owner.as_bytes()),
        TREASURY_COIN_SLOT,
        coin_type_hash,
        treasury_coin,
    )?;
    let receipt: DurableRequestReceipt =
        build_seed_receipt(resolver, epoch, &treasury.object_ref())?;
    Ok(ExpectedTreasurySeed {
        domain,
        treasury,
        receipt,
    })
}

#[allow(clippy::too_many_arguments)]
fn create_treasury_seed<S>(
    store: &S,
    blob_store: &dyn BlobStore,
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    asset_id: AssetId,
    treasury_owner: DevOwner,
    boot_generation: WriterFenceGeneration,
    context: &DurableOperationContext,
    expected: ExpectedTreasurySeed,
) -> Result<SeedTreasuryCoinOutcome, DevnetSeedError>
where
    S: StructuredDurableDomainStateStore + ?Sized,
{
    let provenance: DurableObjectProvenance =
        DurableObjectProvenance::new(resolver.chain_id().clone(), resolver.protocol_version());
    let treasury_record: DurableObjectVersionRecord =
        DurableObjectVersionRecord::from_inline_object(
            expected.treasury.initial_object.clone(),
            expected.treasury.initial_digest,
            provenance,
            boot_generation.get(),
        )?;
    let owner_projection: DurableObjectOwnerProjection = DurableObjectOwnerProjection::from_owner(
        Owner::Address(Address::new(*treasury_owner.as_bytes())),
    )?;
    let routing_projection: DurableObjectRoutingProjection =
        DurableObjectRoutingProjection::new(None)?;
    let reads: Vec<DurableObjectHeadRead> = vec![DurableObjectHeadRead::new(
        expected.treasury.initial_object.id,
        DurableObjectHead::Absent,
    )];
    let mutations: Vec<DurableObjectMutationEntry> = vec![DurableObjectMutationEntry::new(
        expected.treasury.initial_object.id,
        DurableObjectMutation::Create {
            version: treasury_record,
            owner_projection,
            routing_projection,
        },
    )];
    let objects: DurableObjectChanges = DurableObjectChanges::new(reads, mutations)?;
    let invocation: DurableInvocationTransaction = DurableInvocationTransaction::new(
        expected.domain,
        None,
        objects,
        expected.receipt.clone(),
        None,
    )?;

    match store.commit_invocation(context, invocation) {
        DurableCommitOutcome::Committed => {
            Ok(SeedTreasuryCoinOutcome::Created(SeededTreasuryCoin {
                owner: treasury_owner,
                coin: expected.treasury.object_ref(),
                amount: INITIAL_TREASURY_COIN_AMOUNT,
            }))
        }
        DurableCommitOutcome::Rejected(
            DurableCommitRejection::ObjectConflict { .. }
            | DurableCommitRejection::RequestAlreadyCommitted,
        ) => {
            let head: DurableObjectHead = store
                .get_object_head(
                    context,
                    expected.domain,
                    expected.treasury.initial_object.id,
                )
                .map_err(DevnetSeedError::Read)?;
            let coin: SeededTreasuryCoin = verify_existing_treasury_seed(
                store,
                blob_store,
                resolver,
                epoch,
                asset_id,
                treasury_owner,
                boot_generation,
                context,
                &expected,
                &head,
            )?;
            Ok(SeedTreasuryCoinOutcome::Existing(coin))
        }
        DurableCommitOutcome::Rejected(rejection) => {
            Err(DevnetSeedError::CommitRejected(rejection))
        }
        DurableCommitOutcome::Indeterminate(reason) => {
            let receipt: Option<DurableRequestReceipt> = store
                .get_request_receipt(context, expected.domain, expected.receipt.request_id())
                .map_err(DevnetSeedError::Read)?;
            match receipt {
                Some(receipt) if receipt == expected.receipt => {
                    let head: DurableObjectHead = store
                        .get_object_head(
                            context,
                            expected.domain,
                            expected.treasury.initial_object.id,
                        )
                        .map_err(DevnetSeedError::Read)?;
                    let coin: SeededTreasuryCoin = verify_existing_treasury_seed(
                        store,
                        blob_store,
                        resolver,
                        epoch,
                        asset_id,
                        treasury_owner,
                        boot_generation,
                        context,
                        &expected,
                        &head,
                    )?;
                    Ok(SeedTreasuryCoinOutcome::Existing(coin))
                }
                Some(_) => Err(DevnetSeedError::ReceiptMismatch),
                None => Err(DevnetSeedError::CommitIndeterminate(reason)),
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_existing_treasury_seed<S>(
    store: &S,
    blob_store: &dyn BlobStore,
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    asset_id: AssetId,
    treasury_owner: DevOwner,
    boot_generation: WriterFenceGeneration,
    context: &DurableOperationContext,
    expected: &ExpectedTreasurySeed,
    head: &DurableObjectHead,
) -> Result<SeededTreasuryCoin, DevnetSeedError>
where
    S: StructuredDurableDomainStateStore + ?Sized,
{
    if !matches!(head, DurableObjectHead::Current { .. }) {
        return Err(DevnetSeedError::UnexpectedHead {
            object_id: expected.treasury.initial_object.id,
            kind: head_kind(head),
        });
    }
    let verified: VerifiedCurrentCoin = verify_current_coin(
        store,
        blob_store,
        resolver,
        epoch,
        boot_generation,
        context,
        expected.domain,
        head,
        &expected.treasury,
        asset_id,
        CoinOwnerExpectation::Exact(Address::new(*treasury_owner.as_bytes())),
    )?;
    verify_initial_record(
        store,
        resolver,
        boot_generation,
        context,
        expected.domain,
        &expected.treasury,
    )?;
    verify_seed_receipt(store, context, expected.domain, &expected.receipt)?;

    Ok(SeededTreasuryCoin {
        owner: treasury_owner,
        coin: verified.object_ref,
        amount: verified.coin.amount(),
    })
}

// ── Protocol-version marker ──────────────────────────────────────────────

fn protocol_context_marker_type_hash() -> Digest32 {
    Digest32::new(protocol_types::HashAlgorithmId::Sha2_256, [0xFE; 32])
}

fn encode_protocol_context_marker(
    protocol_version: u32,
    epoch: Epoch,
) -> Result<Vec<u8>, CanonicalEncodingError> {
    let mut frame: CanonicalStruct = CanonicalStruct::new(
        PROTOCOL_CONTEXT_MARKER_TYPE_ID,
        PROTOCOL_CONTEXT_MARKER_ENCODING_VERSION,
    );
    frame.field_u32(1, protocol_version)?;
    frame.field_u64(2, epoch.get())?;
    frame.finish()
}

fn decode_protocol_context_marker(input: &[u8]) -> Result<(u32, u64), DevnetSeedError> {
    let frame: CanonicalFrame<'_> =
        decode_canonical_frame(input).map_err(DevnetSeedError::CanonicalDecoding)?;
    frame
        .require_type(PROTOCOL_CONTEXT_MARKER_TYPE_ID)
        .map_err(DevnetSeedError::CanonicalDecoding)?;
    frame
        .require_version(PROTOCOL_CONTEXT_MARKER_ENCODING_VERSION)
        .map_err(DevnetSeedError::CanonicalDecoding)?;
    frame
        .require_only_fields(&[1, 2])
        .map_err(DevnetSeedError::CanonicalDecoding)?;
    let protocol_version: u32 = frame
        .required_u32(1)
        .map_err(DevnetSeedError::CanonicalDecoding)?;
    let epoch: u64 = frame
        .required_u64(2)
        .map_err(DevnetSeedError::CanonicalDecoding)?;
    Ok((protocol_version, epoch))
}

/// Verifies (or, on first boot, seeds) a persisted marker recording the
/// exact protocol version and epoch this data directory was created under.
///
/// A protocol-3 data directory reused under this protocol-4 binary would
/// otherwise never fail: every derived `AssetId` and seed object id changes
/// with `protocol_version` (see `derive_devnet_asset_id`/`build_expected_coin`),
/// so a stale v3 data directory would simply seed a *disjoint* fresh v4
/// object set into the same SQLite file rather than refusing to boot. This
/// marker is deliberately keyed by a fixed, protocol-version-independent
/// `ObjectId` so it can actually detect that mismatch instead of silently
/// deriving a different identity for itself too.
///
/// Like its sibling seed functions, this rejects a `context` whose writer
/// fence disagrees with `boot_generation` before any storage work.
pub fn verify_or_seed_protocol_context<S>(
    store: &S,
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    boot_generation: WriterFenceGeneration,
    context: &DurableOperationContext,
    object_store_was_empty: bool,
) -> Result<(), DevnetSeedError>
where
    S: StructuredDurableDomainStateStore + ?Sized,
{
    if context.writer_fence() != boot_generation {
        return Err(DevnetSeedError::ContextFenceMismatch {
            context: context.writer_fence(),
            boot: boot_generation,
        });
    }
    let domain: AtomicityDomainId = AtomicityDomainId::new(DEVNET_DOMAIN_BYTES)
        .map_err(|_| DevnetSeedError::InvalidStaticDomain)?;
    let head: DurableObjectHead = store
        .get_object_head(context, domain, PROTOCOL_CONTEXT_MARKER_OBJECT_ID)
        .map_err(DevnetSeedError::Read)?;
    match head {
        DurableObjectHead::Absent => {
            if !object_store_was_empty {
                return Err(DevnetSeedError::UnmarkedExistingObjectState);
            }
            match create_protocol_context_marker(
                store,
                resolver,
                epoch,
                boot_generation,
                context,
                domain,
            ) {
                Ok(()) => Ok(()),
                Err(DevnetSeedError::CommitRejected(
                    DurableCommitRejection::ObjectConflict { .. }
                    | DurableCommitRejection::RequestAlreadyCommitted,
                )) => verify_protocol_context_marker_current(
                    store,
                    resolver,
                    epoch,
                    boot_generation,
                    context,
                    domain,
                ),
                Err(error) => Err(error),
            }
        }
        DurableObjectHead::Current { .. } => verify_protocol_context_marker_current(
            store,
            resolver,
            epoch,
            boot_generation,
            context,
            domain,
        ),
        DurableObjectHead::Tombstoned { .. } => Err(DevnetSeedError::UnexpectedHead {
            object_id: PROTOCOL_CONTEXT_MARKER_OBJECT_ID,
            kind: "tombstoned",
        }),
    }
}

fn verify_protocol_context_marker_current<S>(
    store: &S,
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    boot_generation: WriterFenceGeneration,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
) -> Result<(), DevnetSeedError>
where
    S: StructuredDurableDomainStateStore + ?Sized,
{
    let head: DurableObjectHead = store
        .get_object_head(context, domain, PROTOCOL_CONTEXT_MARKER_OBJECT_ID)
        .map_err(DevnetSeedError::Read)?;
    let DurableObjectHead::Current {
        object_version,
        digest: head_digest,
        owner_projection,
        routing_projection,
        ..
    } = head
    else {
        return Err(DevnetSeedError::UnexpectedHead {
            object_id: PROTOCOL_CONTEXT_MARKER_OBJECT_ID,
            kind: head_kind(&head),
        });
    };
    let expected_owner_projection: DurableObjectOwnerProjection =
        DurableObjectOwnerProjection::from_owner(Owner::Immutable)?;
    let expected_routing_projection: DurableObjectRoutingProjection =
        DurableObjectRoutingProjection::new(None)?;
    if object_version != DurableObjectVersion::FIRST
        || owner_projection != expected_owner_projection
        || routing_projection != expected_routing_projection
    {
        return Err(DevnetSeedError::StoredObjectMismatch {
            object_id: PROTOCOL_CONTEXT_MARKER_OBJECT_ID,
            detail: "protocol-context marker head metadata differs",
        });
    }
    let record: DurableObjectVersionRecord = store
        .get_object_version(
            context,
            domain,
            PROTOCOL_CONTEXT_MARKER_OBJECT_ID,
            object_version,
        )
        .map_err(DevnetSeedError::Read)?
        .ok_or(DevnetSeedError::MissingObjectVersion {
            object_id: PROTOCOL_CONTEXT_MARKER_OBJECT_ID,
            version: object_version,
        })?;
    if record.object_id() != PROTOCOL_CONTEXT_MARKER_OBJECT_ID
        || record.object_version() != DurableObjectVersion::FIRST
        || record.digest() != head_digest
        || record.schema_version() != 1
    {
        return Err(DevnetSeedError::StoredObjectMismatch {
            object_id: PROTOCOL_CONTEXT_MARKER_OBJECT_ID,
            detail: "protocol-context marker head and immutable metadata differ",
        });
    }
    if record.provenance().chain_id() != resolver.chain_id() {
        return Err(DevnetSeedError::StoredObjectMismatch {
            object_id: PROTOCOL_CONTEXT_MARKER_OBJECT_ID,
            detail: "protocol-context marker creating chain differs",
        });
    }
    let created_checkpoint: u64 = record.created_checkpoint();
    if created_checkpoint == 0 || created_checkpoint > boot_generation.get() {
        return Err(DevnetSeedError::StoredObjectMismatch {
            object_id: PROTOCOL_CONTEXT_MARKER_OBJECT_ID,
            detail: "protocol-context marker checkpoint is zero or from a future boot generation",
        });
    }
    let inline = match record.payload() {
        DurableObjectPayload::Inline(inline) => inline,
        DurableObjectPayload::BlobReference(_) => {
            return Err(DevnetSeedError::BlobBackedSeedObject(
                PROTOCOL_CONTEXT_MARKER_OBJECT_ID,
            ));
        }
    };
    let object: Object = decode_object(inline.canonical_bytes())?;
    if object.id != PROTOCOL_CONTEXT_MARKER_OBJECT_ID
        || object.version != DurableObjectVersion::FIRST.get()
        || object.owner != Owner::Immutable
        || object.type_hash != protocol_context_marker_type_hash()
        || object.schema_version != 1
    {
        return Err(DevnetSeedError::StoredObjectMismatch {
            object_id: PROTOCOL_CONTEXT_MARKER_OBJECT_ID,
            detail: "protocol-context marker typed object differs",
        });
    }
    let canonical_object: Vec<u8> = encode_object(&object)?;
    if canonical_object != inline.canonical_bytes() {
        return Err(DevnetSeedError::StoredObjectMismatch {
            object_id: PROTOCOL_CONTEXT_MARKER_OBJECT_ID,
            detail: "protocol-context marker bytes are not canonical",
        });
    }
    let digest_valid: bool = verify_digest(
        &record.digest(),
        HashPurpose::Object,
        record.provenance().protocol_version(),
        record.provenance().chain_id(),
        &canonical_object,
    )?;
    if !digest_valid {
        return Err(DevnetSeedError::StoredObjectMismatch {
            object_id: PROTOCOL_CONTEXT_MARKER_OBJECT_ID,
            detail: "protocol-context marker digest does not verify",
        });
    }
    let (stored_version, stored_epoch): (u32, u64) = decode_protocol_context_marker(&object.data)?;
    let canonical_body: Vec<u8> =
        encode_protocol_context_marker(stored_version, Epoch::new(stored_epoch))
            .map_err(DevnetSeedError::CanonicalEncoding)?;
    if canonical_body != object.data {
        return Err(DevnetSeedError::StoredObjectMismatch {
            object_id: PROTOCOL_CONTEXT_MARKER_OBJECT_ID,
            detail: "protocol-context marker body is not canonical",
        });
    }
    if record.provenance().protocol_version().get() != stored_version {
        return Err(DevnetSeedError::StoredObjectMismatch {
            object_id: PROTOCOL_CONTEXT_MARKER_OBJECT_ID,
            detail: "protocol-context marker body and provenance differ",
        });
    }
    let expected: u32 = resolver.protocol_version().get();
    if stored_version != expected {
        return Err(DevnetSeedError::ProtocolVersionMismatch {
            expected,
            actual: stored_version,
        });
    }
    if stored_epoch != epoch.get() {
        return Err(DevnetSeedError::EpochMismatch {
            expected: epoch.get(),
            actual: stored_epoch,
        });
    }
    let object_ref: ObjectRef = ObjectRef {
        id: PROTOCOL_CONTEXT_MARKER_OBJECT_ID,
        version: object.version,
        digest: record.digest(),
    };
    let expected_receipt: DurableRequestReceipt = build_seed_receipt(resolver, epoch, &object_ref)?;
    verify_seed_receipt(store, context, domain, &expected_receipt)?;
    Ok(())
}

fn create_protocol_context_marker<S>(
    store: &S,
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    boot_generation: WriterFenceGeneration,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
) -> Result<(), DevnetSeedError>
where
    S: StructuredDurableDomainStateStore + ?Sized,
{
    let body: Vec<u8> = encode_protocol_context_marker(resolver.protocol_version().get(), epoch)
        .map_err(DevnetSeedError::CanonicalEncoding)?;
    let object: Object = Object {
        id: PROTOCOL_CONTEXT_MARKER_OBJECT_ID,
        version: DurableObjectVersion::FIRST.get(),
        owner: Owner::Immutable,
        type_hash: protocol_context_marker_type_hash(),
        schema_version: 1,
        data: body,
    };
    let canonical_object: Vec<u8> = encode_object(&object)?;
    let digest: Digest32 =
        resolver.hash_for_purpose(epoch, HashPurpose::Object, &canonical_object)?;
    let provenance: DurableObjectProvenance =
        DurableObjectProvenance::new(resolver.chain_id().clone(), resolver.protocol_version());
    let record: DurableObjectVersionRecord = DurableObjectVersionRecord::from_inline_object(
        object,
        digest,
        provenance,
        boot_generation.get(),
    )?;
    let owner_projection: DurableObjectOwnerProjection =
        DurableObjectOwnerProjection::from_owner(Owner::Immutable)?;
    let routing_projection: DurableObjectRoutingProjection =
        DurableObjectRoutingProjection::new(None)?;
    let reads: Vec<DurableObjectHeadRead> = vec![DurableObjectHeadRead::new(
        PROTOCOL_CONTEXT_MARKER_OBJECT_ID,
        DurableObjectHead::Absent,
    )];
    let mutations: Vec<DurableObjectMutationEntry> = vec![DurableObjectMutationEntry::new(
        PROTOCOL_CONTEXT_MARKER_OBJECT_ID,
        DurableObjectMutation::Create {
            version: record,
            owner_projection,
            routing_projection,
        },
    )];
    let objects: DurableObjectChanges = DurableObjectChanges::new(reads, mutations)?;
    let object_ref: ObjectRef = ObjectRef {
        id: PROTOCOL_CONTEXT_MARKER_OBJECT_ID,
        version: DurableObjectVersion::FIRST.get(),
        digest,
    };
    let receipt: DurableRequestReceipt = build_seed_receipt(resolver, epoch, &object_ref)?;
    let invocation: DurableInvocationTransaction =
        DurableInvocationTransaction::new(domain, None, objects, receipt, None)?;

    match store.commit_invocation(context, invocation) {
        DurableCommitOutcome::Committed => Ok(()),
        DurableCommitOutcome::Rejected(rejection) => {
            Err(DevnetSeedError::CommitRejected(rejection))
        }
        DurableCommitOutcome::Indeterminate(reason) => {
            Err(DevnetSeedError::CommitIndeterminate(reason))
        }
    }
}

/// Fail-closed errors while deriving, creating, or verifying devnet seed
/// objects.
#[derive(Debug)]
pub enum DevnetSeedError {
    /// The owner was not a canonical, non-identity, prime-order Ed25519
    /// public key and therefore cannot safely receive or hold seeded value.
    InadmissibleOwner(Ed25519OwnerAddressError),
    /// The hard-coded devnet atomicity domain unexpectedly violated its invariant.
    InvalidStaticDomain,
    /// The supplied operation context does not carry this boot's writer fence.
    ContextFenceMismatch {
        /// Fence carried by the operation context.
        context: WriterFenceGeneration,
        /// Fence exclusively claimed by this boot.
        boot: WriterFenceGeneration,
    },
    /// Hash derivation produced the same identifier for both explicit slots.
    ObjectIdCollision,
    /// A Standard Asset v1 codec or derivation call failed.
    StandardAsset(StandardAssetError),
    /// Existing object framing failed.
    Object(ObjectError),
    /// Domain-separated hash derivation or verification failed.
    Hashing(HashingError),
    /// A typed-ABI type-identity verification call failed.
    TypedAbi(AbiError),
    /// A dev-local canonical marker failed to encode.
    CanonicalEncoding(CanonicalEncodingError),
    /// A dev-local canonical marker failed to decode.
    CanonicalDecoding(CanonicalDecodingError),
    /// The bounded durable envelope was invalid.
    Invocation(DurableInvocationError),
    /// A deterministic non-zero durable request identity could not be built.
    RequestIdentity(IndexedOutboxContractError),
    /// A structured read failed.
    Read(DurableReadError),
    /// A dev owner's transfer/fee coin pair was not exactly both absent or
    /// both current.
    UnexpectedHeadPair {
        /// First coin's head kind.
        first: &'static str,
        /// Second coin's head kind.
        second: &'static str,
    },
    /// A single-object seed (treasury coin or protocol-context marker) had
    /// an unexpected head kind.
    UnexpectedHead {
        /// The object identifier.
        object_id: ObjectId,
        /// The unexpected head kind.
        kind: &'static str,
    },
    /// An exact immutable version referenced by a current or seed head was missing.
    MissingObjectVersion {
        /// Missing object's identity.
        object_id: ObjectId,
        /// Missing immutable version.
        version: DurableObjectVersion,
    },
    /// The genesis (version-one) seed record was blob-backed. Seeding always
    /// creates version one inline, and nothing ever republishes an existing
    /// immutable version under a different representation, so this is
    /// persisted corruption, not a currently-reachable case.
    BlobBackedSeedObject(ObjectId),
    /// A `BlobStore` operation failed while verifying a blob-backed current
    /// version (published by a real transaction since seeding, DR-0096).
    BlobStore(RuntimeError),
    /// A current version's payload named a digest absent from the supplied
    /// `BlobStore`.
    MissingBlob {
        /// Object identifier.
        object_id: ObjectId,
        /// Content digest that could not be found.
        blob_digest: Digest32,
    },
    /// Stored object metadata, bytes, digest, or provenance did not match.
    StoredObjectMismatch {
        /// Mismatched object's identity.
        object_id: ObjectId,
        /// Stable operator-facing mismatch category.
        detail: &'static str,
    },
    /// The bounded configured-owner set violated the fixed global seeded supply.
    AssetInvariantViolation,
    /// The deterministic original seed receipt was absent.
    MissingSeedReceipt,
    /// The deterministic seed request identity resolved to different receipt bytes.
    ReceiptMismatch,
    /// The store proved that seed creation did not commit.
    CommitRejected(DurableCommitRejection),
    /// The store could not determine whether seed creation committed.
    CommitIndeterminate(IndeterminateCommitReason),
    /// The persisted protocol-context marker disagrees with the configured
    /// protocol version: this data directory was created under a different,
    /// incompatible protocol version and must not be reused.
    ProtocolVersionMismatch {
        /// The currently configured protocol version.
        expected: u32,
        /// The protocol version this data directory was created under.
        actual: u32,
    },
    /// The persisted marker's creation epoch disagrees with the configured
    /// epoch. Because the devnet AssetId is epoch-bound, the data directory
    /// must not be reused under another epoch.
    EpochMismatch {
        /// The currently configured epoch.
        expected: u64,
        /// The epoch this data directory was created under.
        actual: u64,
    },
    /// Object state already existed before the first protocol-context marker
    /// could be installed. This is an unsupported pre-v4 data directory and
    /// must not be mixed with newly derived v4 objects.
    UnmarkedExistingObjectState,
}

impl fmt::Display for DevnetSeedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InadmissibleOwner(error) => {
                write!(f, "devnet seed owner is not admissible: {error}")
            }
            Self::InvalidStaticDomain => f.write_str("devnet's fixed atomicity domain is invalid"),
            Self::ContextFenceMismatch { context, boot } => write!(
                f,
                "seed context fence {} differs from boot generation {}",
                context.get(),
                boot.get()
            ),
            Self::ObjectIdCollision => {
                f.write_str("devnet transfer and fee coin object identifiers collided")
            }
            Self::StandardAsset(error) => write!(f, "seed standard-asset codec failed: {error}"),
            Self::Object(error) => write!(f, "seed object framing failed: {error}"),
            Self::Hashing(error) => write!(f, "seed hash derivation failed: {error}"),
            Self::TypedAbi(error) => write!(f, "seed typed-ABI verification failed: {error}"),
            Self::CanonicalEncoding(error) => {
                write!(f, "seed marker encoding failed: {error}")
            }
            Self::CanonicalDecoding(error) => {
                write!(f, "seed marker decoding failed: {error}")
            }
            Self::Invocation(error) => write!(f, "seed durable envelope is invalid: {error}"),
            Self::RequestIdentity(error) => {
                write!(f, "seed request identity is invalid: {error}")
            }
            Self::Read(error) => write!(f, "seed structured read failed: {error:?}"),
            Self::UnexpectedHeadPair { first, second } => write!(
                f,
                "seed coin heads must be both absent or both current, got first={first}, second={second}"
            ),
            Self::UnexpectedHead { object_id, kind } => write!(
                f,
                "seed object {object_id} has an unexpected head kind: {kind}"
            ),
            Self::MissingObjectVersion { object_id, version } => write!(
                f,
                "seed object {object_id} immutable version {} is missing",
                version.get()
            ),
            Self::BlobBackedSeedObject(object_id) => write!(
                f,
                "seed object {object_id} genesis version is blob-backed, expected inline"
            ),
            Self::BlobStore(error) => write!(f, "seed blob-store read failed: {error}"),
            Self::MissingBlob {
                object_id,
                blob_digest,
            } => write!(
                f,
                "seed object {object_id} blob payload {blob_digest} is absent from blob storage"
            ),
            Self::StoredObjectMismatch { object_id, detail } => {
                write!(f, "seed object {object_id} failed verification: {detail}")
            }
            Self::AssetInvariantViolation => {
                f.write_str("seed coins violate unique identity or global supply invariants")
            }
            Self::MissingSeedReceipt => f.write_str("deterministic seed receipt is missing"),
            Self::ReceiptMismatch => f.write_str("deterministic seed receipt differs"),
            Self::CommitRejected(rejection) => {
                write!(f, "seed commit was rejected: {rejection:?}")
            }
            Self::CommitIndeterminate(reason) => {
                write!(f, "seed commit is indeterminate: {reason:?}")
            }
            Self::ProtocolVersionMismatch { expected, actual } => write!(
                f,
                "data directory was seeded under protocol version {actual}, current configuration is protocol version {expected}; use a fresh --data-dir"
            ),
            Self::EpochMismatch { expected, actual } => write!(
                f,
                "data directory was seeded under epoch {actual}, current configuration is epoch {expected}; use a fresh --data-dir"
            ),
            Self::UnmarkedExistingObjectState => f.write_str(
                "data directory contains object state but no protocol-context marker; it predates protocol version 4 and must be replaced with a fresh --data-dir",
            ),
        }
    }
}

impl Error for DevnetSeedError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InadmissibleOwner(error) => Some(error),
            Self::StandardAsset(error) => Some(error),
            Self::Object(error) => Some(error),
            Self::Hashing(error) => Some(error),
            Self::TypedAbi(error) => Some(error),
            Self::CanonicalEncoding(error) => Some(error),
            Self::CanonicalDecoding(error) => Some(error),
            Self::Invocation(error) => Some(error),
            Self::RequestIdentity(error) => Some(error),
            Self::BlobStore(error) => Some(error),
            _ => None,
        }
    }
}

impl From<StandardAssetError> for DevnetSeedError {
    fn from(value: StandardAssetError) -> Self {
        Self::StandardAsset(value)
    }
}

impl From<ObjectError> for DevnetSeedError {
    fn from(value: ObjectError) -> Self {
        Self::Object(value)
    }
}

impl From<HashingError> for DevnetSeedError {
    fn from(value: HashingError) -> Self {
        Self::Hashing(value)
    }
}

impl From<DurableInvocationError> for DevnetSeedError {
    fn from(value: DurableInvocationError) -> Self {
        Self::Invocation(value)
    }
}

impl From<IndexedOutboxContractError> for DevnetSeedError {
    fn from(value: IndexedOutboxContractError) -> Self {
        Self::RequestIdentity(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_zebra::{SigningKey, VerificationKey};
    use protocol_types::{ChainId, HashAlgorithmId, HashSuite, HashSuiteSchedule, ProtocolVersion};
    use runtime::{
        MemoryBlobStore, MemoryDurableStateStore, StorageCorrelationId, StorageDeadline,
    };
    use standard_assets::{STANDARD_ASSET_COIN_V1_TYPE_ID, encode_asset_id};

    const ASSET: AssetId = AssetId::new([0x64; 32]);

    fn resolver(protocol_version: u32) -> HashSuiteResolver {
        HashSuiteResolver::new(
            ChainId::new("seed-test-chain").unwrap(),
            ProtocolVersion::new(protocol_version),
            vec![HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: HashSuite::genesis(),
            }],
        )
        .unwrap()
    }

    fn dev_owner(seed: u8) -> DevOwner {
        let signing_key: SigningKey = SigningKey::from([seed; 32]);
        let verification_key: VerificationKey = VerificationKey::from(&signing_key);
        let mut bytes: [u8; 32] = [0; 32];
        bytes.copy_from_slice(verification_key.as_ref());
        DevOwner::new(bytes)
    }

    fn generation() -> WriterFenceGeneration {
        WriterFenceGeneration::new(2).unwrap()
    }

    fn context() -> DurableOperationContext {
        DurableOperationContext::new(
            generation(),
            StorageDeadline::new(1_000).unwrap(),
            StorageCorrelationId::new([0x51; 16]).unwrap(),
        )
    }

    fn domain() -> AtomicityDomainId {
        AtomicityDomainId::new(DEVNET_DOMAIN_BYTES).unwrap()
    }

    fn store() -> MemoryDurableStateStore {
        let store = MemoryDurableStateStore::new_bound(domain(), generation());
        store.set_time(0);
        store
    }

    #[test]
    fn dev_owner_seed_is_atomic_distinct_and_idempotent() {
        let store = store();
        let blob_store = MemoryBlobStore::default();
        let resolver = resolver(4);
        let owner = dev_owner(0x61);

        let created = seed_dev_owner_coins(
            &store,
            &blob_store,
            &resolver,
            Epoch::new(0),
            ASSET,
            owner,
            generation(),
            &context(),
        )
        .unwrap();
        assert!(matches!(created, SeedDevOwnerCoinsOutcome::Created(_)));
        assert_ne!(
            created.coins().transfer_coin().id,
            created.coins().fee_coin().id
        );

        let existing = seed_dev_owner_coins(
            &store,
            &blob_store,
            &resolver,
            Epoch::new(0),
            ASSET,
            owner,
            generation(),
            &context(),
        )
        .unwrap();
        assert!(matches!(existing, SeedDevOwnerCoinsOutcome::Existing(_)));
        assert_eq!(created.coins(), existing.coins());
    }

    #[test]
    fn dev_owner_seed_rejects_universal_zip215_owner_before_storage_work() {
        let store = store();
        let mut bytes: [u8; 32] = [0; 32];
        bytes[0] = 1;
        bytes[31] = 0x80;
        let result = seed_dev_owner_coins(
            &store,
            &MemoryBlobStore::default(),
            &resolver(4),
            Epoch::new(0),
            ASSET,
            DevOwner::new(bytes),
            generation(),
            &context(),
        );

        assert!(matches!(
            result,
            Err(DevnetSeedError::InadmissibleOwner(
                Ed25519OwnerAddressError::NonCanonicalPoint
            ))
        ));
    }

    #[test]
    fn deterministic_ids_are_owner_and_asset_scoped() {
        let resolver = resolver(4);
        let first = build_expected_dev_owner_seed(
            &resolver,
            Epoch::new(0),
            ASSET,
            DevOwner::new([0x71; 32]),
        )
        .unwrap();
        let second = build_expected_dev_owner_seed(
            &resolver,
            Epoch::new(0),
            ASSET,
            DevOwner::new([0x72; 32]),
        )
        .unwrap();
        let other_asset = build_expected_dev_owner_seed(
            &resolver,
            Epoch::new(0),
            AssetId::new([0x65; 32]),
            DevOwner::new([0x71; 32]),
        )
        .unwrap();

        assert_ne!(
            first.transfer.initial_object.id,
            first.fee.initial_object.id
        );
        assert_ne!(
            first.transfer.initial_object.id,
            second.transfer.initial_object.id
        );
        assert_ne!(
            first.transfer.initial_object.id,
            other_asset.transfer.initial_object.id
        );
    }

    #[test]
    fn seeded_asset_supply_accepts_cross_owner_movement_of_the_transferable_coin() {
        let resolver = resolver(4);
        let first = build_expected_dev_owner_seed(
            &resolver,
            Epoch::new(0),
            ASSET,
            DevOwner::new([0x81; 32]),
        )
        .unwrap();
        let second = build_expected_dev_owner_seed(
            &resolver,
            Epoch::new(0),
            ASSET,
            DevOwner::new([0x82; 32]),
        )
        .unwrap();
        let treasury_expected = build_expected_treasury_seed(
            &resolver,
            Epoch::new(0),
            ASSET,
            DevOwner::new([0x90; 32]),
        )
        .unwrap();

        // Simulate the first owner's transferable coin having moved to some
        // address outside the configured set (a legitimate real transfer):
        // the total amount is unaffected, only which coin holds it.
        let outcomes = vec![
            SeedDevOwnerCoinsOutcome::Existing(initial_dev_owner_coins(
                DevOwner::new([0x81; 32]),
                &first,
            )),
            SeedDevOwnerCoinsOutcome::Existing(initial_dev_owner_coins(
                DevOwner::new([0x82; 32]),
                &second,
            )),
        ];
        let treasury = SeedTreasuryCoinOutcome::Existing(SeededTreasuryCoin {
            owner: DevOwner::new([0x90; 32]),
            coin: treasury_expected.treasury.object_ref(),
            amount: INITIAL_TREASURY_COIN_AMOUNT,
        });

        verify_seeded_asset_supply(&outcomes, &treasury).unwrap();
    }

    #[test]
    fn seeded_asset_supply_rejects_a_duplicate_object_id() {
        let resolver = resolver(4);
        let first = build_expected_dev_owner_seed(
            &resolver,
            Epoch::new(0),
            ASSET,
            DevOwner::new([0x81; 32]),
        )
        .unwrap();
        let treasury_expected = build_expected_treasury_seed(
            &resolver,
            Epoch::new(0),
            ASSET,
            DevOwner::new([0x90; 32]),
        )
        .unwrap();
        let outcomes = vec![
            SeedDevOwnerCoinsOutcome::Existing(initial_dev_owner_coins(
                DevOwner::new([0x81; 32]),
                &first,
            )),
            SeedDevOwnerCoinsOutcome::Existing(initial_dev_owner_coins(
                DevOwner::new([0x81; 32]),
                &first,
            )),
        ];
        let treasury = SeedTreasuryCoinOutcome::Existing(SeededTreasuryCoin {
            owner: DevOwner::new([0x90; 32]),
            coin: treasury_expected.treasury.object_ref(),
            amount: INITIAL_TREASURY_COIN_AMOUNT,
        });

        assert!(matches!(
            verify_seeded_asset_supply(&outcomes, &treasury),
            Err(DevnetSeedError::AssetInvariantViolation)
        ));
    }

    #[test]
    fn seeded_asset_supply_rejects_wrong_total() {
        let resolver = resolver(4);
        let first = build_expected_dev_owner_seed(
            &resolver,
            Epoch::new(0),
            ASSET,
            DevOwner::new([0x81; 32]),
        )
        .unwrap();
        let treasury_expected = build_expected_treasury_seed(
            &resolver,
            Epoch::new(0),
            ASSET,
            DevOwner::new([0x90; 32]),
        )
        .unwrap();
        let mut coins = initial_dev_owner_coins(DevOwner::new([0x81; 32]), &first);
        coins.transfer_amount += 1;
        let outcomes = vec![SeedDevOwnerCoinsOutcome::Existing(coins)];
        let treasury = SeedTreasuryCoinOutcome::Existing(SeededTreasuryCoin {
            owner: DevOwner::new([0x90; 32]),
            coin: treasury_expected.treasury.object_ref(),
            amount: INITIAL_TREASURY_COIN_AMOUNT,
        });

        assert!(matches!(
            verify_seeded_asset_supply(&outcomes, &treasury),
            Err(DevnetSeedError::AssetInvariantViolation)
        ));
    }

    fn commit_owner_only_transfer(
        store: &MemoryDurableStateStore,
        resolver: &HashSuiteResolver,
        seeded: &ExpectedSeedCoin,
        new_owner: Address,
        request_tag: u8,
    ) {
        let head = store
            .get_object_head(&context(), domain(), seeded.initial_object.id)
            .unwrap();
        let DurableObjectHead::Current { object_version, .. } = head else {
            panic!("expected a current head before simulating a transfer");
        };
        let mut object = seeded.initial_object.clone();
        object.version = object_version.get() + 1;
        object.owner = Owner::Address(new_owner);
        let canonical_object = encode_object(&object).unwrap();
        let digest = resolver
            .hash_for_purpose(Epoch::new(0), HashPurpose::Object, &canonical_object)
            .unwrap();
        let record = DurableObjectVersionRecord::from_inline_object(
            object.clone(),
            digest,
            DurableObjectProvenance::new(resolver.chain_id().clone(), resolver.protocol_version()),
            generation().get(),
        )
        .unwrap();
        let owner_projection = DurableObjectOwnerProjection::from_owner(object.owner).unwrap();
        let routing_projection = DurableObjectRoutingProjection::new(None).unwrap();
        let changes = DurableObjectChanges::new(
            vec![DurableObjectHeadRead::new(seeded.initial_object.id, head)],
            vec![DurableObjectMutationEntry::new(
                seeded.initial_object.id,
                DurableObjectMutation::Update {
                    version: record,
                    owner_projection,
                    routing_projection,
                },
            )],
        )
        .unwrap();
        let receipt = DurableRequestReceipt::new(
            DurableRequestId::new([request_tag; 32]).unwrap(),
            Digest32::new(HashAlgorithmId::Sha2_256, [request_tag.wrapping_add(1); 32]),
            vec![request_tag],
        )
        .unwrap();
        let invocation =
            DurableInvocationTransaction::new(domain(), None, changes, receipt, None).unwrap();
        assert_eq!(
            store.commit_invocation(&context(), invocation),
            DurableCommitOutcome::Committed
        );
    }

    fn commit_amount_change(
        store: &MemoryDurableStateStore,
        resolver: &HashSuiteResolver,
        seeded: &ExpectedSeedCoin,
        asset_id: AssetId,
        new_amount: u64,
        request_tag: u8,
    ) {
        let head = store
            .get_object_head(&context(), domain(), seeded.initial_object.id)
            .unwrap();
        let DurableObjectHead::Current { object_version, .. } = head else {
            panic!("expected a current head before simulating a fee debit");
        };
        let mut object = seeded.initial_object.clone();
        object.version = object_version.get() + 1;
        object.data =
            encode_standard_asset_coin_v1(&StandardAssetCoinV1::new(asset_id, new_amount).unwrap())
                .unwrap();
        let canonical_object = encode_object(&object).unwrap();
        let digest = resolver
            .hash_for_purpose(Epoch::new(0), HashPurpose::Object, &canonical_object)
            .unwrap();
        let record = DurableObjectVersionRecord::from_inline_object(
            object.clone(),
            digest,
            DurableObjectProvenance::new(resolver.chain_id().clone(), resolver.protocol_version()),
            generation().get(),
        )
        .unwrap();
        let owner_projection = DurableObjectOwnerProjection::from_owner(object.owner).unwrap();
        let routing_projection = DurableObjectRoutingProjection::new(None).unwrap();
        let changes = DurableObjectChanges::new(
            vec![DurableObjectHeadRead::new(seeded.initial_object.id, head)],
            vec![DurableObjectMutationEntry::new(
                seeded.initial_object.id,
                DurableObjectMutation::Update {
                    version: record,
                    owner_projection,
                    routing_projection,
                },
            )],
        )
        .unwrap();
        let receipt = DurableRequestReceipt::new(
            DurableRequestId::new([request_tag; 32]).unwrap(),
            Digest32::new(HashAlgorithmId::Sha2_256, [request_tag.wrapping_add(1); 32]),
            vec![request_tag],
        )
        .unwrap();
        let invocation =
            DurableInvocationTransaction::new(domain(), None, changes, receipt, None).unwrap();
        assert_eq!(
            store.commit_invocation(&context(), invocation),
            DurableCommitOutcome::Committed
        );
    }

    #[test]
    fn restart_accepts_either_seeded_coin_moved_to_a_new_admissible_owner() {
        for (index, moved_slot) in ["transfer", "fee"].into_iter().enumerate() {
            let store = store();
            let blob_store = MemoryBlobStore::default();
            let resolver = resolver(4);
            let owner = dev_owner(u8::try_from(0x91 + index).unwrap());
            seed_dev_owner_coins(
                &store,
                &blob_store,
                &resolver,
                Epoch::new(0),
                ASSET,
                owner,
                generation(),
                &context(),
            )
            .unwrap();

            let expected =
                build_expected_dev_owner_seed(&resolver, Epoch::new(0), ASSET, owner).unwrap();
            let new_owner = dev_owner(u8::try_from(0x95 + index).unwrap());
            let moved = if moved_slot == "transfer" {
                &expected.transfer
            } else {
                &expected.fee
            };
            commit_owner_only_transfer(
                &store,
                &resolver,
                moved,
                Address::new(*new_owner.as_bytes()),
                u8::try_from(0xB0 + index).unwrap(),
            );

            let existing = seed_dev_owner_coins(
                &store,
                &blob_store,
                &resolver,
                Epoch::new(0),
                ASSET,
                owner,
                generation(),
                &context(),
            );
            assert!(
                matches!(existing, Ok(SeedDevOwnerCoinsOutcome::Existing(_))),
                "moving the {moved_slot} coin's owner unexpectedly failed restart: {existing:?}"
            );
        }
    }

    #[test]
    fn restart_accepts_either_seeded_coin_debited_to_a_new_nonzero_amount() {
        for (index, debited_slot) in ["transfer", "fee"].into_iter().enumerate() {
            let store = store();
            let blob_store = MemoryBlobStore::default();
            let resolver = resolver(4);
            let owner = dev_owner(u8::try_from(0x97 + index).unwrap());
            seed_dev_owner_coins(
                &store,
                &blob_store,
                &resolver,
                Epoch::new(0),
                ASSET,
                owner,
                generation(),
                &context(),
            )
            .unwrap();

            let expected =
                build_expected_dev_owner_seed(&resolver, Epoch::new(0), ASSET, owner).unwrap();
            let debited = if debited_slot == "transfer" {
                &expected.transfer
            } else {
                &expected.fee
            };
            commit_amount_change(
                &store,
                &resolver,
                debited,
                ASSET,
                1,
                u8::try_from(0xB8 + index).unwrap(),
            );

            let existing = seed_dev_owner_coins(
                &store,
                &blob_store,
                &resolver,
                Epoch::new(0),
                ASSET,
                owner,
                generation(),
                &context(),
            );
            assert!(
                matches!(existing, Ok(SeedDevOwnerCoinsOutcome::Existing(_))),
                "debiting the {debited_slot} coin's amount unexpectedly failed restart: {existing:?}"
            );
        }
    }

    /// F9: the two seeded coins are protocol-indistinguishable, so a real
    /// devnet run may use either as the whole-coin transfer source and the
    /// other as the fee payer. This pins the arrangement opposite the seed
    /// slots — the fee coin (slot 2) moves owner, the transfer coin (slot 1)
    /// is debited — which the pre-fix verification rejected outright.
    #[test]
    fn restart_accepts_swapped_source_and_fee_roles() {
        let store = store();
        let blob_store = MemoryBlobStore::default();
        let resolver = resolver(4);
        let owner = dev_owner(0x9A);
        seed_dev_owner_coins(
            &store,
            &blob_store,
            &resolver,
            Epoch::new(0),
            ASSET,
            owner,
            generation(),
            &context(),
        )
        .unwrap();
        let expected =
            build_expected_dev_owner_seed(&resolver, Epoch::new(0), ASSET, owner).unwrap();
        let new_owner = dev_owner(0x9B);

        commit_owner_only_transfer(
            &store,
            &resolver,
            &expected.fee,
            Address::new(*new_owner.as_bytes()),
            0xB4,
        );
        commit_amount_change(
            &store,
            &resolver,
            &expected.transfer,
            ASSET,
            INITIAL_TRANSFER_COIN_AMOUNT - 500,
            0xB5,
        );

        let existing = seed_dev_owner_coins(
            &store,
            &blob_store,
            &resolver,
            Epoch::new(0),
            ASSET,
            owner,
            generation(),
            &context(),
        )
        .unwrap();
        assert!(matches!(existing, SeedDevOwnerCoinsOutcome::Existing(_)));
        assert_eq!(
            existing.coins().transfer_coin().id,
            expected.transfer.initial_object.id
        );
        assert_eq!(
            existing.coins().fee_coin().id,
            expected.fee.initial_object.id
        );
    }

    #[test]
    fn restart_rejects_either_seeded_coin_moved_to_an_inadmissible_owner() {
        for (index, moved_slot) in ["transfer", "fee"].into_iter().enumerate() {
            let store = store();
            let blob_store = MemoryBlobStore::default();
            let resolver = resolver(4);
            let owner = dev_owner(u8::try_from(0x93 + index).unwrap());
            seed_dev_owner_coins(
                &store,
                &blob_store,
                &resolver,
                Epoch::new(0),
                ASSET,
                owner,
                generation(),
                &context(),
            )
            .unwrap();
            let expected =
                build_expected_dev_owner_seed(&resolver, Epoch::new(0), ASSET, owner).unwrap();
            let mut universal_owner_bytes: [u8; 32] = [0; 32];
            universal_owner_bytes[0] = 1;
            universal_owner_bytes[31] = 0x80;
            let moved = if moved_slot == "transfer" {
                &expected.transfer
            } else {
                &expected.fee
            };
            commit_owner_only_transfer(
                &store,
                &resolver,
                moved,
                Address::new(universal_owner_bytes),
                u8::try_from(0xB2 + index).unwrap(),
            );

            let result = seed_dev_owner_coins(
                &store,
                &blob_store,
                &resolver,
                Epoch::new(0),
                ASSET,
                owner,
                generation(),
                &context(),
            );
            assert!(
                matches!(
                    result,
                    Err(DevnetSeedError::InadmissibleOwner(
                        Ed25519OwnerAddressError::NonCanonicalPoint
                    ))
                ),
                "moving the {moved_slot} coin to an inadmissible owner unexpectedly verified: {result:?}"
            );
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum CoinTamper {
        Type,
        Schema,
        Asset,
        MalformedBody,
        ZeroAmount,
    }

    fn commit_tampered_coin(
        store: &MemoryDurableStateStore,
        resolver: &HashSuiteResolver,
        seeded: &ExpectedSeedCoin,
        asset_id: AssetId,
        tamper: CoinTamper,
        request_tag: u8,
    ) {
        let head = store
            .get_object_head(&context(), domain(), seeded.initial_object.id)
            .unwrap();
        let DurableObjectHead::Current { object_version, .. } = head else {
            panic!("expected a current head before tampering");
        };
        let mut object = seeded.initial_object.clone();
        object.version = object_version.get() + 1;
        match tamper {
            CoinTamper::Type => {
                object.type_hash = Digest32::new(HashAlgorithmId::Sha2_256, [0xA2; 32]);
            }
            CoinTamper::Schema => {
                object.schema_version = 2;
            }
            CoinTamper::Asset => {
                object.data = encode_standard_asset_coin_v1(
                    &StandardAssetCoinV1::new(AssetId::new([0xA3; 32]), 1).unwrap(),
                )
                .unwrap();
            }
            CoinTamper::MalformedBody => {
                object.data = vec![0xA4];
            }
            CoinTamper::ZeroAmount => {
                // Bypasses `StandardAssetCoinV1::new`'s own zero-amount
                // rejection to prove restart verification independently
                // rejects a decoded-but-invalid zero amount, not just a
                // malformed frame.
                let mut canonical = CanonicalStruct::new(STANDARD_ASSET_COIN_V1_TYPE_ID, 1);
                canonical
                    .field_bytes(1, encode_asset_id(&asset_id).unwrap())
                    .unwrap();
                canonical.field_u64(2, 0).unwrap();
                object.data = canonical.finish().unwrap();
            }
        }
        let canonical_object = encode_object(&object).unwrap();
        let digest = resolver
            .hash_for_purpose(Epoch::new(0), HashPurpose::Object, &canonical_object)
            .unwrap();
        let record = DurableObjectVersionRecord::from_inline_object(
            object.clone(),
            digest,
            DurableObjectProvenance::new(resolver.chain_id().clone(), resolver.protocol_version()),
            generation().get(),
        )
        .unwrap();
        let owner_projection = DurableObjectOwnerProjection::from_owner(object.owner).unwrap();
        let routing_projection = DurableObjectRoutingProjection::new(None).unwrap();
        let changes = DurableObjectChanges::new(
            vec![DurableObjectHeadRead::new(seeded.initial_object.id, head)],
            vec![DurableObjectMutationEntry::new(
                seeded.initial_object.id,
                DurableObjectMutation::Update {
                    version: record,
                    owner_projection,
                    routing_projection,
                },
            )],
        )
        .unwrap();
        let receipt = DurableRequestReceipt::new(
            DurableRequestId::new([request_tag; 32]).unwrap(),
            Digest32::new(HashAlgorithmId::Sha2_256, [request_tag.wrapping_add(1); 32]),
            vec![request_tag],
        )
        .unwrap();
        let invocation =
            DurableInvocationTransaction::new(domain(), None, changes, receipt, None).unwrap();
        assert_eq!(
            store.commit_invocation(&context(), invocation),
            DurableCommitOutcome::Committed
        );
    }

    #[test]
    fn restart_verification_rejects_semantically_tampered_current_coins() {
        let tampers = [
            CoinTamper::Type,
            CoinTamper::Schema,
            CoinTamper::Asset,
            CoinTamper::MalformedBody,
            CoinTamper::ZeroAmount,
        ];
        let cases = tampers.into_iter().flat_map(|tamper| {
            ["transfer", "fee"]
                .into_iter()
                .map(move |slot| (slot, tamper))
        });
        for (index, (tampered_slot, tamper)) in cases.enumerate() {
            let store = store();
            let blob_store = MemoryBlobStore::default();
            let resolver = resolver(4);
            let owner = dev_owner(u8::try_from(0xA0 + index).unwrap());
            seed_dev_owner_coins(
                &store,
                &blob_store,
                &resolver,
                Epoch::new(0),
                ASSET,
                owner,
                generation(),
                &context(),
            )
            .unwrap();
            let expected =
                build_expected_dev_owner_seed(&resolver, Epoch::new(0), ASSET, owner).unwrap();
            let tampered = if tampered_slot == "transfer" {
                &expected.transfer
            } else {
                &expected.fee
            };
            let request_tag: u8 = u8::try_from(index).unwrap() + 0xC0;
            commit_tampered_coin(&store, &resolver, tampered, ASSET, tamper, request_tag);

            let result = seed_dev_owner_coins(
                &store,
                &blob_store,
                &resolver,
                Epoch::new(0),
                ASSET,
                owner,
                generation(),
                &context(),
            );
            assert!(
                matches!(
                    result,
                    Err(DevnetSeedError::StoredObjectMismatch { .. })
                        | Err(DevnetSeedError::StandardAsset(_))
                ),
                "tamper case {tampered_slot}/{tamper:?} unexpectedly verified: {result:?}"
            );
        }
    }

    #[test]
    fn restart_rejects_a_current_coin_committed_under_mismatched_provenance() {
        let store = store();
        let blob_store = MemoryBlobStore::default();
        let resolver = resolver(4);
        let owner = dev_owner(0xE0);
        seed_dev_owner_coins(
            &store,
            &blob_store,
            &resolver,
            Epoch::new(0),
            ASSET,
            owner,
            generation(),
            &context(),
        )
        .unwrap();
        let expected =
            build_expected_dev_owner_seed(&resolver, Epoch::new(0), ASSET, owner).unwrap();

        let head = store
            .get_object_head(&context(), domain(), expected.transfer.initial_object.id)
            .unwrap();
        let DurableObjectHead::Current { object_version, .. } = head else {
            panic!("expected a current head before simulating a provenance mismatch");
        };
        let mut object = expected.transfer.initial_object.clone();
        object.version = object_version.get() + 1;
        let canonical_object = encode_object(&object).unwrap();
        let digest = resolver
            .hash_for_purpose(Epoch::new(0), HashPurpose::Object, &canonical_object)
            .unwrap();
        let wrong_provenance = DurableObjectProvenance::new(
            ChainId::new("a-different-chain").unwrap(),
            resolver.protocol_version(),
        );
        let record = DurableObjectVersionRecord::from_inline_object(
            object.clone(),
            digest,
            wrong_provenance,
            generation().get(),
        )
        .unwrap();
        let owner_projection = DurableObjectOwnerProjection::from_owner(object.owner).unwrap();
        let routing_projection = DurableObjectRoutingProjection::new(None).unwrap();
        let changes = DurableObjectChanges::new(
            vec![DurableObjectHeadRead::new(
                expected.transfer.initial_object.id,
                head,
            )],
            vec![DurableObjectMutationEntry::new(
                expected.transfer.initial_object.id,
                DurableObjectMutation::Update {
                    version: record,
                    owner_projection,
                    routing_projection,
                },
            )],
        )
        .unwrap();
        let receipt = DurableRequestReceipt::new(
            DurableRequestId::new([0xE1; 32]).unwrap(),
            Digest32::new(HashAlgorithmId::Sha2_256, [0xE2; 32]),
            vec![0xE1],
        )
        .unwrap();
        let invocation =
            DurableInvocationTransaction::new(domain(), None, changes, receipt, None).unwrap();
        assert_eq!(
            store.commit_invocation(&context(), invocation),
            DurableCommitOutcome::Committed
        );

        let result = seed_dev_owner_coins(
            &store,
            &blob_store,
            &resolver,
            Epoch::new(0),
            ASSET,
            owner,
            generation(),
            &context(),
        );
        assert!(matches!(
            result,
            Err(DevnetSeedError::StoredObjectMismatch { .. })
        ));
    }

    #[test]
    fn treasury_seed_is_atomic_and_idempotent() {
        let store = store();
        let blob_store = MemoryBlobStore::default();
        let resolver = resolver(4);
        let treasury_owner = dev_owner(0xD0);

        let created = seed_treasury_coin(
            &store,
            &blob_store,
            &resolver,
            Epoch::new(0),
            ASSET,
            treasury_owner,
            generation(),
            &context(),
        )
        .unwrap();
        assert!(matches!(created, SeedTreasuryCoinOutcome::Created(_)));

        let existing = seed_treasury_coin(
            &store,
            &blob_store,
            &resolver,
            Epoch::new(0),
            ASSET,
            treasury_owner,
            generation(),
            &context(),
        )
        .unwrap();
        assert!(matches!(existing, SeedTreasuryCoinOutcome::Existing(_)));
        assert_eq!(created.coin(), existing.coin());
    }

    #[test]
    fn treasury_seed_rejects_a_current_owner_change() {
        let store = store();
        let blob_store = MemoryBlobStore::default();
        let resolver = resolver(4);
        let treasury_owner = dev_owner(0xD1);
        seed_treasury_coin(
            &store,
            &blob_store,
            &resolver,
            Epoch::new(0),
            ASSET,
            treasury_owner,
            generation(),
            &context(),
        )
        .unwrap();
        let expected =
            build_expected_treasury_seed(&resolver, Epoch::new(0), ASSET, treasury_owner).unwrap();
        let other_owner = dev_owner(0xD2);
        commit_owner_only_transfer(
            &store,
            &resolver,
            &expected.treasury,
            Address::new(*other_owner.as_bytes()),
            0xD3,
        );

        let result = seed_treasury_coin(
            &store,
            &blob_store,
            &resolver,
            Epoch::new(0),
            ASSET,
            treasury_owner,
            generation(),
            &context(),
        );
        assert!(matches!(
            result,
            Err(DevnetSeedError::StoredObjectMismatch { .. })
        ));
    }

    #[test]
    fn protocol_context_marker_is_seeded_once_and_reverified_on_restart() {
        let store = store();
        let resolver = resolver(4);

        verify_or_seed_protocol_context(
            &store,
            &resolver,
            Epoch::new(0),
            generation(),
            &context(),
            true,
        )
        .unwrap();
        // Idempotent: a second call under the same protocol version succeeds.
        verify_or_seed_protocol_context(
            &store,
            &resolver,
            Epoch::new(0),
            generation(),
            &context(),
            false,
        )
        .unwrap();
    }

    #[test]
    fn verify_or_seed_protocol_context_rejects_a_context_fence_mismatch() {
        let store = store();
        let resolver = resolver(4);
        let mismatched_context = DurableOperationContext::new(
            WriterFenceGeneration::new(3).unwrap(),
            StorageDeadline::new(1_000).unwrap(),
            StorageCorrelationId::new([0x52; 16]).unwrap(),
        );

        let result = verify_or_seed_protocol_context(
            &store,
            &resolver,
            Epoch::new(0),
            generation(),
            &mismatched_context,
            true,
        );
        assert!(matches!(
            result,
            Err(DevnetSeedError::ContextFenceMismatch { .. })
        ));
    }

    #[test]
    fn protocol_context_marker_rejects_a_mismatched_reused_data_directory() {
        let store = store();
        let v4_resolver = resolver(4);
        verify_or_seed_protocol_context(
            &store,
            &v4_resolver,
            Epoch::new(0),
            generation(),
            &context(),
            true,
        )
        .unwrap();

        let v5_resolver = resolver(5);
        let result = verify_or_seed_protocol_context(
            &store,
            &v5_resolver,
            Epoch::new(0),
            generation(),
            &context(),
            false,
        );
        assert!(matches!(
            result,
            Err(DevnetSeedError::ProtocolVersionMismatch {
                expected: 5,
                actual: 4,
            })
        ));
    }

    #[test]
    fn protocol_context_marker_rejects_a_mismatched_epoch() {
        let store = store();
        let resolver = resolver(4);
        verify_or_seed_protocol_context(
            &store,
            &resolver,
            Epoch::new(0),
            generation(),
            &context(),
            true,
        )
        .unwrap();

        let result = verify_or_seed_protocol_context(
            &store,
            &resolver,
            Epoch::new(1),
            generation(),
            &context(),
            false,
        );
        assert!(matches!(
            result,
            Err(DevnetSeedError::EpochMismatch {
                expected: 1,
                actual: 0,
            })
        ));
    }

    #[test]
    fn protocol_context_marker_rejects_unmarked_existing_object_state() {
        let store = store();
        let resolver = resolver(4);

        let result = verify_or_seed_protocol_context(
            &store,
            &resolver,
            Epoch::new(0),
            generation(),
            &context(),
            false,
        );
        assert!(matches!(
            result,
            Err(DevnetSeedError::UnmarkedExistingObjectState)
        ));
    }
}
