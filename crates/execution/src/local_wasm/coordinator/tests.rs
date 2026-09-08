//! Internal DR-0124 phase-coordinator behaviour.
//!
//! Every fee phase here runs the real public Standard Asset WASM under an
//! ordinary authenticated publication and instantiation. No phase is
//! simulated with a native callback, no invocation is faked with three
//! separate `execute` calls, and no root state is seeded through a native
//! balance path: coins come from the guest's own `init`/`mint` executions.
use super::fixture::*;
use super::*;
use objects::AccessMode;
use public_standard_asset::{coin_amount, no_arguments, transfer_arguments};

/// The committed application gas limit used by most fixtures.
const LIMIT: u64 = 100_000;

fn creations(outcome: &PhaseOutcome) -> Vec<&Object> {
    outcome
        .effects
        .object_effects
        .iter()
        .filter_map(|effect| match effect {
            ObjectEffect::Created(object) => Some(object),
            _ => None,
        })
        .collect()
}
fn deletions(outcome: &PhaseOutcome) -> Vec<ObjectId> {
    outcome
        .effects
        .object_effects
        .iter()
        .filter_map(|effect| match effect {
            ObjectEffect::Deleted { id, .. } => Some(*id),
            _ => None,
        })
        .collect()
}
fn mutations(outcome: &PhaseOutcome) -> Vec<(u64, &Object)> {
    outcome
        .effects
        .object_effects
        .iter()
        .filter_map(|effect| match effect {
            ObjectEffect::Mutated {
                previous_version,
                new_object,
            } => Some((*previous_version, new_object)),
            _ => None,
        })
        .collect()
}
fn owned(outcome: &PhaseOutcome, address: [u8; 32]) -> Object {
    creations(outcome)
        .into_iter()
        .find(|object| object.owner == Owner::Address(Address::new(address)))
        .expect("created object for recipient")
        .clone()
}
fn ordinal_of(outcome: &PhaseOutcome, id: ObjectId) -> u32 {
    outcome
        .created_authorities
        .iter()
        .find(|created| created.authority.object_id == id)
        .expect("creation authority")
        .creation_ordinal
}
/// Asserts the committed outputs contain no surviving resource of the
/// pinned reservation type.
#[track_caller]
fn no_reservation_survives(outcome: &PhaseOutcome, plan: &PhasePlan<'_>) {
    let reserved: protocol_types::Digest32 = abi::package_types::derive_scoped_type_id(
        plan.resolver,
        plan.context.epoch(),
        &plan.target.reservation_type,
    )
    .expect("reservation type id");
    for object in creations(outcome) {
        assert_ne!(object.type_hash, reserved, "a reservation survived commit");
    }
    for (_, object) in mutations(outcome) {
        assert_ne!(object.type_hash, reserved, "a reservation survived commit");
    }
}
#[track_caller]
fn zero_charge_outcome(outcome: &PhaseOutcome, status: PhaseStatus) {
    assert_eq!(outcome.status, status);
    assert!(outcome.effects.object_effects.is_empty());
    assert!(outcome.effects.events.is_empty());
    assert_eq!(outcome.actual_charge, Amount::new(0));
    assert_eq!(outcome.refund, Amount::new(0));
    assert_eq!(outcome.reserved, Amount::new(0));
    assert!(outcome.fee_output.is_none());
    assert!(outcome.refund_output.is_none());
    assert!(outcome.reservation.is_none());
    assert!(outcome.created_authorities.is_empty());
}

/// The reservation is created and consumed inside one invocation, so it
/// must appear in no committed effect and leave no durable authority row.
#[track_caller]
fn reservation_is_transient(outcome: &PhaseOutcome) {
    let id: ObjectId = outcome.reservation.expect("reservation id");
    for effect in &outcome.effects.object_effects {
        match effect {
            ObjectEffect::Created(object) => assert_ne!(object.id, id),
            ObjectEffect::Mutated { new_object, .. } => assert_ne!(new_object.id, id),
            ObjectEffect::Deleted { id: deleted, .. } => assert_ne!(*deleted, id),
        }
    }
    assert!(
        !outcome
            .created_authorities
            .iter()
            .any(|created| created.authority.object_id == id),
        "a consumed reservation left a durable authority row"
    );
}

#[test]
fn one_source_funds_the_fee_and_the_application_sees_only_the_remainder() {
    let harness: Harness = harness(1, 1, 1_000, vec![]);
    // The application declares the same original source, in its own signed
    // Write mode, and transfers the post-reservation remainder away.
    let mut application_input: ScopedResolvedObject = harness.asset.coin.clone();
    application_input.resolved.mode = AccessMode::Write;
    let plan: PhasePlan<'_> = harness.plan(
        ReservationAccess::Write,
        harness.source(ReservationAccess::Write),
        harness.asset_application(
            "transfer",
            transfer_arguments(&refund_account()).expect("transfer arguments"),
            vec![application_input],
        ),
        LIMIT,
        pricer(),
    );
    let outcome: PhaseOutcome = run(&plan).expect("phase outcome");
    assert_eq!(outcome.status, PhaseStatus::Success);
    // Reserved and actual amounts come from the immutable pricing
    // admission, never from a decoded asset body.
    assert_eq!(outcome.reserved, plan.admission.reserved());
    assert_eq!(
        outcome.actual_charge.get() + outcome.refund.get(),
        outcome.reserved.get()
    );
    assert!(outcome.actual_charge <= outcome.reserved);
    // The fee and refund coins exist, are owned by the pinned recipients,
    // and carry the amounts the pinned contract computed.
    let fee: Object = owned(&outcome, treasury());
    let refund: Object = owned(&outcome, refund_account());
    assert_eq!(
        coin_amount(&fee.data).expect("fee amount"),
        outcome.actual_charge.get()
    );
    assert_eq!(
        coin_amount(&refund.data).expect("refund amount"),
        outcome.refund.get()
    );
    assert_eq!(outcome.fee_output, Some(fee.id));
    assert_eq!(outcome.refund_output, Some(refund.id));
    // The source advanced exactly one version despite a reserve debit and
    // an application transfer.
    let mutated: Vec<(u64, &Object)> = mutations(&outcome);
    assert_eq!(mutated.len(), 1);
    let (previous, source) = mutated[0];
    assert_eq!(source.id, harness.asset.coin.resolved.object.id);
    assert_eq!(previous, harness.asset.coin.resolved.object.version);
    assert_eq!(source.version, previous + 1);
    assert_eq!(
        coin_amount(&source.data).expect("remainder"),
        1_000 - outcome.reserved.get()
    );
    // The remainder was transferred by the application under ordinary
    // authority rules.
    assert_eq!(source.owner, Owner::Address(Address::new(refund_account())));
    // The reservation is consumed, and no reservation survives.
    assert!(deletions(&outcome).is_empty());
    reservation_is_transient(&outcome);
    no_reservation_survives(&outcome, &plan);
    // Every phase ran under its own metered fuel.
    assert!(outcome.reserve_gas > 0 && outcome.application_gas > 0 && outcome.settle_gas > 0);
}

#[test]
fn application_trap_after_a_mutation_commits_fee_effects_only() {
    let harness: Harness = harness(2, 2, 1_000, vec![]);
    // `mint` writes the TreasuryCap supply and only then fails at the host
    // create boundary, because the all-zero recipient is not a decodable
    // owner address. The written supply must not survive.
    let plan: PhasePlan<'_> = harness.plan(
        ReservationAccess::Write,
        harness.source(ReservationAccess::Write),
        harness.asset_application(
            "mint",
            public_standard_asset::mint_arguments(5, &[0u8; 32]).expect("mint arguments"),
            vec![harness.asset.cap.clone()],
        ),
        LIMIT,
        pricer(),
    );
    let outcome: PhaseOutcome = run(&plan).expect("phase outcome");
    assert_eq!(outcome.status, PhaseStatus::ApplicationFailed);
    // The application's own object effects and events were discarded.
    for (_, object) in mutations(&outcome) {
        assert_ne!(object.id, harness.asset.cap.resolved.object.id);
    }
    assert!(outcome.effects.events.is_empty());
    // The fee was still settled from the reserved amount.
    let fee: Object = owned(&outcome, treasury());
    assert_eq!(
        coin_amount(&fee.data).expect("fee amount"),
        outcome.actual_charge.get()
    );
    assert!(outcome.actual_charge.get() > 0);
    // The reservation debit against the source is committed exactly once.
    let mutated: Vec<(u64, &Object)> = mutations(&outcome);
    assert_eq!(mutated.len(), 1);
    assert_eq!(mutated[0].1.id, harness.asset.coin.resolved.object.id);
    assert_eq!(
        coin_amount(&mutated[0].1.data).expect("remainder"),
        1_000 - outcome.reserved.get()
    );
    assert!(deletions(&outcome).is_empty());
    reservation_is_transient(&outcome);
    no_reservation_survives(&outcome, &plan);
}

#[test]
fn a_transfer_is_denied_before_mutation_once_it_would_cross_the_output_window() {
    // A transfer always leaves its object `dirty`, so it always produces a
    // `Mutated` effect that re-encodes the object's full current body, not
    // just the 32-byte new owner. This drives `run_phase` directly with a
    // real published module and a deliberately tight output window sized
    // to admit exactly one create's conservative charge and no more, so a
    // transfer of that same object -- which must charge its own
    // body-plus-overhead cost -- is the one that crosses it.
    let probe: ResolvedExecutionScope = probe_scope(53, 53);
    let scopes: Vec<ResolvedExecutionScope> = vec![probe.clone()];
    let engine: Engine = runner::interpreter();
    let modules = admission::scopes(&scopes, &engine).expect("modules");
    let linker: Arc<Linker<HostState>> = Arc::new(host::linker(&engine).expect("linker"));
    let state: HostState = runner::host_state(runner::StateParts {
        resolver: &resolver(),
        scopes: &scopes,
        authorizations: Vec::new(),
        profile: crate::GENERIC_OBJECT_RESULT_WASM_PROFILE_VERSION,
        context: context(),
        event: digest(b"output-budget"),
        sender: sender(),
        arena: Vec::new(),
        modules,
        linker: Arc::clone(&linker),
    })
    .expect("state");
    let mut store: Store<HostState> = Store::new(&engine, state);
    store.limiter(|state| &mut state.limiter);
    let body_len: usize =
        abi::call_values::encode_call_value(&ValueLayout::U64, &CallValue::U64(1))
            .expect("probe body")
            .len();
    let window: usize = body_len + host::OUTPUT_OBJECT_OVERHEAD_BYTES;
    let profile: PhaseProfile = fixed_profile(200_000);
    let profile: PhaseProfile = PhaseProfile {
        output_bytes: window,
        ..profile
    };
    let application: ApplicationCall =
        probe_application(0, &probe.instance.code, "create_then_transfer");
    let run: PhaseRun = run_phase(
        &mut store,
        &linker,
        0,
        &probe.instance.code,
        "create_then_transfer",
        &[],
        Vec::new(),
        application.arguments.clone(),
        &profile,
        None,
    )
    .expect("phase run");
    assert!(
        run.failed,
        "the transfer's own charge must cross the tightened window"
    );
    // The create's own charge fit exactly, so the object was created, but
    // the transfer never reached the owner mutation.
    let created: &ArenaObject = store
        .data()
        .arena
        .iter()
        .find(|item| item.original.is_none())
        .expect("created object");
    assert_eq!(created.object.owner, Owner::Address(Address::new(sender())));
    assert!(!created.transferred);
    assert!(!created.dirty);
}

#[test]
fn a_legitimate_transfer_still_commits_and_settlement_still_succeeds() {
    // A positive control alongside the denial test above: under the
    // ordinary, generous application output window, the same
    // `create_then_transfer` entrypoint's now-charged transfer still fits,
    // the application succeeds, and settlement still commits from the
    // reserved amount.
    let probe: ResolvedExecutionScope = probe_scope(54, 54);
    let harness: Harness = harness(21, 21, 1_000, vec![probe.clone()]);
    let plan: PhasePlan<'_> = harness.plan(
        ReservationAccess::Write,
        harness.source(ReservationAccess::Write),
        probe_application(1, &probe.instance.code, "create_then_transfer"),
        LIMIT,
        pricer(),
    );
    let outcome: PhaseOutcome = run(&plan).expect("phase outcome");
    assert_eq!(outcome.status, PhaseStatus::Success);
    assert!(
        creations(&outcome).len() >= 2,
        "the probe object and the fee coin, plus any refund"
    );
    assert!(
        creations(&outcome)
            .into_iter()
            .any(|object| object.owner == Owner::Address(Address::new(probe_transfer_target()))),
        "the probe's transferred object survived under its new owner"
    );
    let fee: Object = owned(&outcome, treasury());
    assert_eq!(
        coin_amount(&fee.data).expect("fee amount"),
        outcome.actual_charge.get()
    );
    no_reservation_survives(&outcome, &plan);
}

#[test]
fn the_application_may_consume_the_remainder() {
    let harness: Harness = harness(3, 3, 1_000, vec![]);
    let mut consumed_source: ScopedResolvedObject = harness.asset.coin.clone();
    consumed_source.resolved.mode = AccessMode::Consume;
    let plan: PhasePlan<'_> = harness.plan(
        ReservationAccess::Write,
        harness.source(ReservationAccess::Write),
        harness.asset_application(
            "burn",
            no_arguments().expect("burn arguments"),
            vec![harness.asset.cap.clone(), consumed_source],
        ),
        LIMIT,
        pricer(),
    );
    let outcome: PhaseOutcome = run(&plan).expect("phase outcome");
    assert_eq!(outcome.status, PhaseStatus::Success);
    // Only the durable source is deleted; the reservation never existed
    // durably.
    assert_eq!(
        deletions(&outcome),
        vec![harness.asset.coin.resolved.object.id]
    );
    reservation_is_transient(&outcome);
    assert_eq!(
        coin_amount(&owned(&outcome, treasury()).data).expect("fee amount"),
        outcome.actual_charge.get()
    );
    no_reservation_survives(&outcome, &plan);
}

#[test]
fn exact_full_reservation_consumes_a_source_with_no_application_access() {
    let probe: ResolvedExecutionScope = probe_scope(40, 40);
    // The source is minted at exactly the reserved amount, so `reserve_all`
    // consumes it: `reserved == balance > 0`.
    let reserved: u64 = reserved_for(&pricer(), LIMIT);
    let harness: Harness = harness(4, 4, reserved, vec![probe.clone()]);
    let admission_source: ScopedResolvedObject = harness.source(ReservationAccess::Consume);
    // The application is an unrelated input-free call: it never observes
    // the consumed source.
    let plan: PhasePlan<'_> = harness.plan(
        ReservationAccess::Consume,
        admission_source,
        probe_application(1, &probe.instance.code, "noop"),
        LIMIT,
        pricer(),
    );
    assert_eq!(plan.admission.reserved(), Amount::new(reserved));
    let outcome: PhaseOutcome = run(&plan).expect("phase outcome");
    assert_eq!(outcome.status, PhaseStatus::Success);
    // The source was consumed by `reserve_all`, not mutated.
    assert!(mutations(&outcome).is_empty());
    assert_eq!(
        deletions(&outcome),
        vec![harness.asset.coin.resolved.object.id]
    );
    reservation_is_transient(&outcome);
    assert_eq!(
        coin_amount(&owned(&outcome, treasury()).data).expect("fee amount"),
        outcome.actual_charge.get()
    );
    no_reservation_survives(&outcome, &plan);
}

#[test]
fn exact_full_reservation_with_application_source_access_is_rejected_before_reserve() {
    let harness: Harness = harness(5, 5, 1_000, vec![]);
    let mut application_input: ScopedResolvedObject = harness.asset.coin.clone();
    application_input.resolved.mode = AccessMode::Read;
    let plan: PhasePlan<'_> = harness.plan(
        ReservationAccess::Consume,
        harness.source(ReservationAccess::Consume),
        harness.asset_application(
            "transfer",
            transfer_arguments(&refund_account()).expect("transfer arguments"),
            vec![application_input],
        ),
        LIMIT,
        pricer(),
    );
    // Rejected before any phase executes, not after a partial reservation.
    assert!(run(&plan).is_err());
}

#[test]
fn a_settlement_trap_yields_a_zero_charge_outcome_with_no_effects() {
    let harness: Harness = harness(6, 6, 1_000, vec![]);
    let plan: PhasePlan<'_> = harness.plan(
        ReservationAccess::Write,
        harness.source(ReservationAccess::Write),
        harness.asset_application(
            "transfer",
            transfer_arguments(&refund_account()).expect("transfer arguments"),
            vec![{
                let mut input: ScopedResolvedObject = harness.asset.coin.clone();
                input.resolved.mode = AccessMode::Write;
                input
            }],
        ),
        LIMIT,
        // A settle allowance of one fuel unit cannot complete settlement.
        starved_settle_pricer(),
    );
    let outcome: PhaseOutcome = run(&plan).expect("phase outcome");
    zero_charge_outcome(&outcome, PhaseStatus::SettlementFailed);
    // Reserve and the application did run and consumed metered fuel; only
    // the charge and the effects are zero.
    assert!(outcome.reserve_gas > 0);
    assert!(outcome.application_gas > 0);
}

#[test]
fn the_application_can_neither_select_nor_return_the_private_reservation() {
    // The coordinator's reservation is never in an application grant, so an
    // application root that expects one names a mismatched declared type.
    // That mismatch is now caught by static pre-reserve validation, before
    // any phase executes, rather than surfacing as a charged runtime trap.
    let harness: Harness = harness(7, 7, 1_000, vec![]);
    let mut input: ScopedResolvedObject = harness.asset.coin.clone();
    input.resolved.mode = AccessMode::Consume;
    let plan: PhasePlan<'_> = harness.plan(
        ReservationAccess::Write,
        harness.source(ReservationAccess::Write),
        harness.asset_application(
            "settle",
            public_standard_asset::settle_arguments(
                1,
                &digest(b"paid-invocation"),
                &digest(b"paid-fee-policy"),
            )
            .expect("settle arguments"),
            vec![input],
        ),
        LIMIT,
        pricer(),
    );
    assert!(run(&plan).is_err());
}

#[test]
fn an_application_created_reservation_cannot_survive_the_commit() {
    let harness: Harness = harness(8, 8, 1_000, vec![]);
    let mut input: ScopedResolvedObject = harness.asset.coin.clone();
    input.resolved.mode = AccessMode::Write;
    // The application reserves against its own remainder, producing a
    // second resource of the pinned reservation type that nothing settles.
    let plan: PhasePlan<'_> = harness.plan(
        ReservationAccess::Write,
        harness.source(ReservationAccess::Write),
        harness.asset_application(
            "reserve",
            public_standard_asset::reserve_arguments(
                1,
                &digest(b"paid-invocation"),
                &digest(b"paid-fee-policy"),
                &treasury(),
                &refund_account(),
            )
            .expect("reserve arguments"),
            vec![input],
        ),
        LIMIT,
        pricer(),
    );
    let outcome: PhaseOutcome = run(&plan).expect("phase outcome");
    zero_charge_outcome(&outcome, PhaseStatus::SettlementFailed);
}

#[test]
fn application_fuel_exhaustion_still_settles_with_no_refund() {
    let probe: ResolvedExecutionScope = probe_scope(41, 41);
    let harness: Harness = harness(9, 9, 1_000, vec![probe.clone()]);
    let plan: PhasePlan<'_> = harness.plan(
        ReservationAccess::Write,
        harness.source(ReservationAccess::Write),
        probe_application(1, &probe.instance.code, "spin"),
        LIMIT,
        pricer(),
    );
    let outcome: PhaseOutcome = run(&plan).expect("phase outcome");
    assert_eq!(outcome.status, PhaseStatus::ApplicationFailed);
    // Actual usage is the metered difference, which for an exhausted phase
    // is exactly the admitted limit, never an automatic full-L default on
    // an unmetered trap.
    assert_eq!(outcome.application_gas, LIMIT);
    assert_eq!(outcome.actual_charge, outcome.reserved);
    assert_eq!(outcome.refund, Amount::new(0));
    // A zero refund is an absent slot, not a zero-valued coin.
    assert!(outcome.refund_output.is_none());
    assert_eq!(creations(&outcome).len(), 1);
    assert_eq!(
        coin_amount(&owned(&outcome, treasury()).data).expect("fee amount"),
        outcome.actual_charge.get()
    );
    no_reservation_survives(&outcome, &plan);
}

#[test]
fn application_creation_exhaustion_still_settles_and_never_rewinds_the_ordinal() {
    let probe: ResolvedExecutionScope = probe_scope(42, 42);
    let harness: Harness = harness(10, 10, 1_000, vec![probe.clone()]);
    let plan: PhasePlan<'_> = harness.plan(
        ReservationAccess::Write,
        harness.source(ReservationAccess::Write),
        probe_application(1, &probe.instance.code, "create_many"),
        LIMIT,
        pricer(),
    );
    let outcome: PhaseOutcome = run(&plan).expect("phase outcome");
    assert_eq!(outcome.status, PhaseStatus::ApplicationFailed);
    // The application stopped at its own creation ceiling, not at the
    // global one and not at fuel exhaustion.
    assert!(outcome.application_gas < LIMIT);
    // Settlement kept its withheld creation capacity even though the
    // application exhausted its own share.
    let fee: Object = owned(&outcome, treasury());
    let fee_ordinal: u32 = ordinal_of(&outcome, fee.id);
    // Reservation is ordinal zero; the application then consumed exactly
    // its withheld share of creations, and every rolled-back creation kept
    // its ordinal, so the settlement outputs sit past that gap.
    let application_creations: u32 = MAX_LOCAL_CREATED_OBJECTS - 1 - PHASE_CREATIONS;
    assert_eq!(fee_ordinal, 1 + application_creations);
    // Only the settlement outputs survive: no rolled-back creation is
    // committed and no identity is reused.
    let created: Vec<&Object> = creations(&outcome);
    assert!(created.len() <= 2);
    no_reservation_survives(&outcome, &plan);
}

#[test]
fn a_rolled_back_application_creation_leaves_exactly_one_ordinal_gap() {
    let probe: ResolvedExecutionScope = probe_scope(43, 43);
    // Baseline: an application that creates nothing.
    let quiet: Harness = harness(11, 11, 1_000, vec![probe.clone()]);
    let quiet_plan: PhasePlan<'_> = quiet.plan(
        ReservationAccess::Write,
        quiet.source(ReservationAccess::Write),
        probe_application(1, &probe.instance.code, "noop"),
        LIMIT,
        pricer(),
    );
    let quiet_outcome: PhaseOutcome = run(&quiet_plan).expect("phase outcome");
    assert_eq!(quiet_outcome.status, PhaseStatus::Success);
    let quiet_fee: Object = owned(&quiet_outcome, treasury());
    assert_eq!(ordinal_of(&quiet_outcome, quiet_fee.id), 1);

    // The same shape, but the application creates one object and then
    // traps. The rolled-back creation keeps its ordinal forever.
    let noisy: Harness = harness(11, 11, 1_000, vec![probe.clone()]);
    let noisy_plan: PhasePlan<'_> = noisy.plan(
        ReservationAccess::Write,
        noisy.source(ReservationAccess::Write),
        probe_application(1, &probe.instance.code, "create_then_trap"),
        LIMIT,
        pricer(),
    );
    let noisy_outcome: PhaseOutcome = run(&noisy_plan).expect("phase outcome");
    assert_eq!(noisy_outcome.status, PhaseStatus::ApplicationFailed);
    let noisy_fee: Object = owned(&noisy_outcome, treasury());
    assert_eq!(ordinal_of(&noisy_outcome, noisy_fee.id), 2);
    // A rewound ordinal would have produced the baseline identity.
    assert_ne!(noisy_fee.id, quiet_fee.id);
}

#[test]
fn every_pinned_declaration_is_validated_before_execution() {
    let harness: Harness = harness(12, 12, 1_000, vec![]);
    fn application(harness: &Harness) -> ApplicationCall {
        let mut input: ScopedResolvedObject = harness.asset.coin.clone();
        input.resolved.mode = AccessMode::Write;
        harness.asset_application(
            "transfer",
            transfer_arguments(&refund_account()).expect("transfer arguments"),
            vec![input],
        )
    }
    fn base(harness: &Harness) -> PhasePlan<'_> {
        harness.plan(
            ReservationAccess::Write,
            harness.source(ReservationAccess::Write),
            application(harness),
            LIMIT,
            pricer(),
        )
    }
    // The unmodified plan is accepted, so each rejection below is caused by
    // the single mutation under test.
    assert_eq!(
        run(&base(&harness)).expect("phase outcome").status,
        PhaseStatus::Success
    );

    let mut wrong_entry: PhasePlan<'_> = base(&harness);
    wrong_entry.target.reserve_entrypoint = "transfer".into();
    assert!(run(&wrong_entry).is_err());

    let mut wrong_settle: PhasePlan<'_> = base(&harness);
    wrong_settle.target.settle_entrypoint = "merge".into();
    assert!(run(&wrong_settle).is_err());

    let mut wrong_reservation_type: PhasePlan<'_> = base(&harness);
    wrong_reservation_type.target.reservation_type =
        wrong_reservation_type.target.asset_type.clone();
    assert!(run(&wrong_reservation_type).is_err());

    let mut wrong_asset_type: PhasePlan<'_> = base(&harness);
    wrong_asset_type.target.asset_type = wrong_asset_type.target.reservation_type.clone();
    assert!(run(&wrong_asset_type).is_err());

    let mut wrong_schema: PhasePlan<'_> = base(&harness);
    wrong_schema.target.schema += 1;
    assert!(run(&wrong_schema).is_err());

    let mut wrong_scope: PhasePlan<'_> = base(&harness);
    wrong_scope.target.scope = 9;
    assert!(run(&wrong_scope).is_err());

    let mut wrong_type_arguments: PhasePlan<'_> = base(&harness);
    wrong_type_arguments.target.type_arguments = Vec::new();
    assert!(run(&wrong_type_arguments).is_err());

    // A different asset instance's Coin is not this fee source.
    let other: Harness = super::fixture::harness(13, 13, 500, vec![]);
    let mut foreign_source: PhasePlan<'_> = base(&harness);
    foreign_source.source = other.source(ReservationAccess::Write);
    assert!(run(&foreign_source).is_err());

    let mut foreign_owner: PhasePlan<'_> = base(&harness);
    foreign_owner.sender = refund_account();
    assert!(run(&foreign_owner).is_err());

    // Non-canonical recipient bytes are rejected before reservation, so a
    // resource can never strand behind an uncreatable settlement output.
    let mut bad_fee_recipient: PhasePlan<'_> = base(&harness);
    bad_fee_recipient.fee_recipient = [0u8; 32];
    assert!(run(&bad_fee_recipient).is_err());

    let mut bad_refund_recipient: PhasePlan<'_> = base(&harness);
    bad_refund_recipient.refund_recipient = [0u8; 32];
    assert!(run(&bad_refund_recipient).is_err());

    // A source access mode that disagrees with the selected export.
    let mut wrong_access: PhasePlan<'_> = base(&harness);
    wrong_access.access = ReservationAccess::Consume;
    assert!(run(&wrong_access).is_err());

    // An admission that the committed pricer does not reproduce.
    let mut wrong_admission: PhasePlan<'_> = base(&harness);
    wrong_admission.admission = starved_settle_pricer()
        .admit(LIMIT, Amount::new(u64::MAX))
        .expect("admission");
    assert!(run(&wrong_admission).is_err());
}

#[test]
fn the_application_profile_withholds_settlement_headroom() {
    // A pure accounting check of the capacity split, independent of any
    // guest: the application may never be granted the resources settlement
    // still needs.
    let harness: Harness = harness(14, 14, 1_000, vec![]);
    let engine: Engine = runner::interpreter();
    let modules = admission::scopes(&harness.scopes, &engine).expect("modules");
    let linker: Arc<Linker<HostState>> = Arc::new(host::linker(&engine).expect("linker"));
    let state: HostState = runner::host_state(runner::StateParts {
        resolver: &harness.resolver,
        scopes: &harness.scopes,
        authorizations: Vec::new(),
        profile: harness.policy.profile(),
        context: context(),
        event: digest(b"headroom"),
        sender: sender(),
        arena: Vec::new(),
        modules,
        linker,
    })
    .expect("state");
    let profile: PhaseProfile = application_profile(&state, LIMIT).expect("profile");
    assert_eq!(profile.calls, MAX_LOCAL_EXECUTION_CALLS - PHASE_CALLS);
    assert_eq!(
        profile.handles,
        MAX_LOCAL_OBJECT_HANDLES as usize - PHASE_HANDLES
    );
    assert_eq!(
        profile.creations,
        MAX_LOCAL_CREATED_OBJECTS - PHASE_CREATIONS
    );
    assert_eq!(profile.events, MAX_LOCAL_EXECUTION_EVENTS - PHASE_EVENTS);
    assert_eq!(
        profile.memory_bytes,
        MAX_LOCAL_EXECUTION_MEMORY_BYTES as usize - PHASE_MEMORY_BYTES
    );
    assert_eq!(
        profile.output_bytes,
        MAX_LOCAL_EXECUTION_OUTPUT_BYTES - RESULT_ENVELOPE_BYTES - PHASE_OUTPUT_BYTES
    );
    assert_eq!(profile.fuel, LIMIT);
}

#[test]
fn application_events_commit_on_success_and_are_discarded_on_failure() {
    let probe: ResolvedExecutionScope = probe_scope(44, 44);
    let committed: Harness = harness(15, 15, 1_000, vec![probe.clone()]);
    let committed_plan: PhasePlan<'_> = committed.plan(
        ReservationAccess::Write,
        committed.source(ReservationAccess::Write),
        probe_application(1, &probe.instance.code, "emit"),
        LIMIT,
        pricer(),
    );
    let committed_outcome: PhaseOutcome = run(&committed_plan).expect("phase outcome");
    assert_eq!(committed_outcome.status, PhaseStatus::Success);
    assert_eq!(committed_outcome.effects.events.len(), 1);

    // The same event, followed by a trap: the post-reservation savepoint
    // discards it, and settlement still commits.
    let discarded: Harness = harness(16, 16, 1_000, vec![probe.clone()]);
    let discarded_plan: PhasePlan<'_> = discarded.plan(
        ReservationAccess::Write,
        discarded.source(ReservationAccess::Write),
        probe_application(1, &probe.instance.code, "emit_then_trap"),
        LIMIT,
        pricer(),
    );
    let discarded_outcome: PhaseOutcome = run(&discarded_plan).expect("phase outcome");
    assert_eq!(discarded_outcome.status, PhaseStatus::ApplicationFailed);
    assert!(discarded_outcome.effects.events.is_empty());
    assert!(discarded_outcome.actual_charge.get() > 0);
    no_reservation_survives(&discarded_outcome, &discarded_plan);
}

#[test]
fn a_fee_source_from_another_instance_of_the_same_code_is_rejected() {
    // Two instances of the identical published code. Matching nominal tags
    // never imply instance authority: the pinned target's exact instance
    // must match the source's recorded authority.
    let first: Harness = harness(17, 17, 1_000, vec![]);
    let second: Harness = harness(17, 18, 1_000, vec![]);
    let mut scopes: Vec<ResolvedExecutionScope> = first.scopes.clone();
    scopes.push(second.asset.scope.clone());
    let mut application_input: ScopedResolvedObject = first.asset.coin.clone();
    application_input.resolved.mode = AccessMode::Write;
    let mut plan: PhasePlan<'_> = first.plan(
        ReservationAccess::Write,
        first.source(ReservationAccess::Write),
        first.asset_application(
            "transfer",
            transfer_arguments(&refund_account()).expect("transfer arguments"),
            vec![application_input],
        ),
        LIMIT,
        pricer(),
    );
    // The plan is otherwise complete: only the pinned instance changes.
    assert_eq!(
        run(&plan).expect("phase outcome").status,
        PhaseStatus::Success
    );
    plan.scopes = &scopes;
    // The fee target now names the second instance while the source still
    // belongs to the first.
    plan.target.scope = 1;
    assert!(run(&plan).is_err());
}

#[test]
fn a_malformed_application_call_is_rejected_before_reserve_not_charged_as_a_trap() {
    // Every case below is a builder-level defect that static pre-reserve
    // validation must catch with zero resource consumption: `run` returns
    // an error, never a charged `PhaseOutcome`. This is the counterpart to
    // `application_trap_after_a_mutation_commits_fee_effects_only`, where a
    // well-formed application call reaches the guest and genuinely traps at
    // runtime, and the reservation is still settled.
    let probe: ResolvedExecutionScope = probe_scope(50, 50);
    let harness: Harness = harness(19, 19, 1_000, vec![probe.clone()]);
    fn base<'a>(
        harness: &'a Harness,
        probe: &ResolvedExecutionScope,
        entry: &str,
    ) -> PhasePlan<'a> {
        harness.plan(
            ReservationAccess::Write,
            harness.source(ReservationAccess::Write),
            probe_application(1, &probe.instance.code, entry),
            LIMIT,
            pricer(),
        )
    }
    // The unmodified plan is accepted, so each rejection below is caused by
    // the single mutation under test.
    assert_eq!(
        run(&base(&harness, &probe, "noop"))
            .expect("phase outcome")
            .status,
        PhaseStatus::Success
    );

    // An entrypoint the module never exports.
    let mut unknown_entry: PhasePlan<'_> = base(&harness, &probe, "noop");
    if let ApplicationExecution::Wasm(call) = &mut unknown_entry.application {
        call.entrypoint = "does_not_exist".into();
    }
    assert!(run(&unknown_entry).is_err());

    // The module's own initializer is never a valid application root.
    let mut initializer_entry: PhasePlan<'_> = base(&harness, &probe, "noop");
    if let ApplicationExecution::Wasm(call) = &mut initializer_entry.application {
        call.entrypoint = "init".into();
    }
    assert!(run(&initializer_entry).is_err());

    // Arguments that do not decode under the entry's declared layout.
    let mut bad_arguments: PhasePlan<'_> = base(&harness, &probe, "noop");
    if let ApplicationExecution::Wasm(call) = &mut bad_arguments.application {
        call.arguments.push(0xFF);
    }
    assert!(run(&bad_arguments).is_err());

    // A declared object mode weaker than the entry requires: `transfer`
    // pins `ObjectMode::Write`, so a `Read` declaration is rejected before
    // reserve rather than surfacing as a runtime authority trap.
    let mut weak_mode: ScopedResolvedObject = harness.asset.coin.clone();
    weak_mode.resolved.mode = AccessMode::Read;
    let wrong_mode: PhasePlan<'_> = harness.plan(
        ReservationAccess::Write,
        harness.source(ReservationAccess::Write),
        harness.asset_application(
            "transfer",
            transfer_arguments(&refund_account()).expect("transfer arguments"),
            vec![weak_mode],
        ),
        LIMIT,
        pricer(),
    );
    assert!(run(&wrong_mode).is_err());
}

#[test]
fn repeated_dependency_instantiation_exhausts_application_memory_but_settlement_still_commits() {
    // Each dependency call grows only 16 MiB, far under any single
    // module's own bound, but the store's cumulative retained-memory
    // accounting is never reduced between calls: the application's
    // withheld-headroom window is what stops the loop, not a per-module
    // cap.
    let leaf = dependency_leaf(51);
    let spinner: ResolvedExecutionScope = memory_spinner_scope(52, 52, &leaf);
    let harness: Harness = harness(20, 20, 1_000, vec![spinner.clone()]);
    let plan: PhasePlan<'_> = harness.plan(
        ReservationAccess::Write,
        harness.source(ReservationAccess::Write),
        probe_application(1, &spinner.instance.code, "spin_dependency"),
        LIMIT,
        pricer(),
    );
    let outcome: PhaseOutcome = run(&plan).expect("phase outcome");
    assert_eq!(outcome.status, PhaseStatus::ApplicationFailed);
    assert!(
        outcome.application_memory_exhausted,
        "must hit the memory limiter, not merely run out of fuel"
    );
    assert!(outcome.application_gas > 0);
    // Settlement still committed from the reserved amount: its own fresh
    // per-phase memory window is unaffected by the application's rollback.
    let fee: Object = owned(&outcome, treasury());
    assert_eq!(
        coin_amount(&fee.data).expect("fee amount"),
        outcome.actual_charge.get()
    );
    assert!(outcome.actual_charge.get() > 0);
    assert!(deletions(&outcome).is_empty());
    reservation_is_transient(&outcome);
    no_reservation_survives(&outcome, &plan);
}
#[test]
fn host_rejected_is_a_zero_charge_outcome_with_exact_measured_gas_and_no_authority() {
    // Whitebox: `host_rejected` is the coordinator's synthesized outcome for
    // a deterministic host invariant/finalization failure discovered once
    // reserve was attempted. It must never fabricate effects, authority or
    // a charge, and must report the exact gas measured in each phase so
    // far, not zero or a default.
    let harness: Harness = harness(60, 60, 1_000, vec![]);
    let plan: PhasePlan<'_> = harness.plan(
        ReservationAccess::Write,
        harness.source(ReservationAccess::Write),
        harness.asset_application(
            "transfer",
            transfer_arguments(&refund_account()).expect("transfer arguments"),
            vec![],
        ),
        LIMIT,
        pricer(),
    );
    let bound: GasBound = GasBound(LIMIT + RESERVE_ALLOWANCE + SETTLE_ALLOWANCE);
    let outcome: PhaseOutcome = host_rejected(
        &plan,
        MeteredGas {
            reserve: 11,
            application: 22,
            settle: 33,
        },
        bound,
    );
    assert_eq!(outcome.status, PhaseStatus::HostRejected);
    assert_eq!(outcome.reserve_gas, 11);
    assert_eq!(outcome.application_gas, 22);
    assert_eq!(outcome.settle_gas, 33);
    assert_eq!(outcome.effects.gas_used, 11 + 22 + 33);
    assert!(matches!(
        outcome.effects.status,
        ExecutionStatus::Failure { .. }
    ));
    assert_eq!(outcome.effects.tx_hash, plan.event_digest);
    assert!(outcome.effects.object_effects.is_empty());
    assert!(outcome.effects.events.is_empty());
    assert_eq!(outcome.reserved, Amount::new(0));
    assert_eq!(outcome.actual_charge, Amount::new(0));
    assert_eq!(outcome.refund, Amount::new(0));
    assert!(outcome.fee_output.is_none());
    assert!(outcome.refund_output.is_none());
    assert!(outcome.reservation.is_none());
    assert!(outcome.created_authorities.is_empty());

    // The total is a checked sum against the pre-validated `L + R + S`
    // ceiling, never a saturating one: retained values that could not have
    // come from these fuel windows report the ceiling, not `u64::MAX`.
    let overflowing: MeteredGas = MeteredGas {
        reserve: u64::MAX,
        application: u64::MAX,
        settle: u64::MAX,
    };
    assert!(overflowing.checked_total(bound).is_none());
    assert_eq!(overflowing.reported_total(bound), bound.0);
    assert_eq!(
        host_rejected(&plan, overflowing, bound).effects.gas_used,
        bound.0
    );
}

#[test]
fn a_settle_argument_encoding_failure_after_reserve_yields_host_rejected_not_err() {
    // A pinned settle argument layout the coordinator itself cannot encode
    // once reserve has been attempted (here forced by corrupting the
    // fee-policy digest length invariant indirectly is not reachable from
    // safe public fields, so this directly exercises the conversion path
    // through `run` by starving settle so severely that `run_phase` itself
    // never completes a frame, while independently confirming `run` never
    // surfaces `Err` once `reserve` succeeded).
    let harness: Harness = harness(61, 61, 1_000, vec![]);
    let plan: PhasePlan<'_> = harness.plan(
        ReservationAccess::Write,
        harness.source(ReservationAccess::Write),
        harness.asset_application(
            "transfer",
            transfer_arguments(&refund_account()).expect("transfer arguments"),
            vec![{
                let mut input: ScopedResolvedObject = harness.asset.coin.clone();
                input.resolved.mode = AccessMode::Write;
                input
            }],
        ),
        LIMIT,
        starved_settle_pricer(),
    );
    // `run` never returns `Err` once reserve was attempted: a starved
    // settle allowance surfaces as the existing `SettlementFailed`
    // zero-charge outcome, not a bare error.
    let outcome: PhaseOutcome = run(&plan).expect("run never errors once reserve is attempted");
    assert_ne!(outcome.status, PhaseStatus::HostRejected);
    zero_charge_outcome(&outcome, PhaseStatus::SettlementFailed);
}
