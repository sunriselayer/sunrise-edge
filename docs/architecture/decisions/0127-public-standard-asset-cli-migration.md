# DR-0127: public Standard Asset CLI migration

Accepted design, 2026-09-21 (Asia/Singapore).

## Decision

Make the installed public Standard Asset package and signed paid-execution
envelope the only active devnet path for `transfer`, `split`, `merge`, `mint`,
and `burn`. The five existing top-level CLI verbs remain as the human-facing
interface, but they become thin builders for an ordinary `PaidApplication::Call`.
They receive no native entrypoint, type, ownership, amount, fee, or settlement
privilege.

This repository is unreleased. Existing development databases using the
preinstalled Standard Asset catalog are incompatible and are not migrated.
Startup fails closed on their committed protocol context; operators create a
fresh devnet data directory. No compatibility selector or dual execution path
is retained.

## Public package selection

The CLI fetches and validates the installed `PaidFeePolicy` after validating
the separately configured expected protocol context. For this devnet profile,
that policy pins the public Standard Asset code, instance, `Coin<A>` type,
schema, fee recipient, and the single type argument `A`. The five asset
commands target that exact code and instance and reuse that exact type argument.
They do not accept a caller-selected module ID, module version, module digest,
fee asset ID, fee treasury object, code reference, instance reference, or type
argument.

This one-package selection is a devnet product profile, not a generic
node-core rule. Node core continues to validate only signed paid intent,
published ABI, instance/code authority, typed object authority, ownership,
resource bounds, fee consent, and durable state. It contains no comparison to
a Standard Asset package, entrypoint name, constructor, AssetId, or body
layout.

## CLI construction

Every command:

1. rejects Ledger selection before device or network access until paid-intent
   clear signing is separately specified;
2. validates TLS endpoint configuration separately from the expected protocol
   context;
3. fetches the installed fee policy and current object snapshots before
   signing;
4. requires every application input to be a current inline object owned by the
   signer and to match the exact published nominal type and schema;
5. signs one paid envelope containing the application call, fee consent,
   request ID, nonce, gas limit, maximum fee, and optional refund recipient;
6. submits through the existing paid HTTP route and independently verifies the
   returned paid result; and
7. writes requested recovery artifacts before reporting success.

The application access and argument shapes are:

| Command | Entrypoint | Application access, in order | Arguments |
| --- | --- | --- | --- |
| `transfer` | `transfer` | source `Coin<A>` Write | recipient |
| `split` | `split` | source `Coin<A>` Write | positive amount, recipient |
| `merge` | `merge` | primary `Coin<A>` Write, secondary `Coin<A>` Consume | empty tuple |
| `mint` | `mint` | `TreasuryCap<A>` Write | positive amount, recipient |
| `burn` | `burn` | `TreasuryCap<A>` Write, `Coin<A>` Consume | empty tuple |

Fee consent is separate from application access and is fixed to Write
reservation for these five commands. The fee source may be the same object as
any application input, including an application Consume input; the signed
reference must then be identical and the application sees only the
post-reservation remainder. Only a fee consent using `reserve_all`/Consume is
forbidden from overlapping application access. `mint` necessarily uses a Coin
separate from its TreasuryCap input; the other four operations may use one of
their Coin inputs for both roles.

The CLI derives arguments with the public package helpers and uses the
policy-pinned type argument. It does not decode or predict application balance
transitions as authority. Local decoding is limited to presenting and
pre-validating host-authenticated current object bodies; the WASM package
performs the state transition.

## Devnet boot and configuration

Paid contract genesis is mandatory and is installed or verified on every
boot. The opt-in `--enable-paid-contracts` flag is removed. The fee recipient
is an address selected by `--fee-recipient`; there is no seeded native treasury
object and the recipient need not be distinct from a development owner.

Genesis installs one public Standard Asset instance, its Definition and
TreasuryCap, and two initial `Coin<A>` objects per configured development owner:
one named as the initial fee source and one named as the initial spend source.
The first development owner is the devnet mint authority and owns the
TreasuryCap so the `mint` and `burn` CLI workflows are usable without the public
genesis signing key. Total supply is derived from both initial Coin sets and is
asserted against the TreasuryCap body during manifest construction, because the
generic installer intentionally knows nothing about asset supply. Startup
prints the instance, Definition, TreasuryCap, initial Coin IDs, and fee policy
commitment needed for an operator to exercise the network.

The active devnet composes an empty preinstalled module catalog and no native
fee composer. The legacy devnet catalog, asset seeding, embedded native module,
and native Standard Asset fee composer are deleted. Generic preinstalled
transaction machinery may remain as inactive protocol infrastructure in this
slice only where non-asset unit tests still exercise it; the devnet exposes no
registered module or fee-composition capability through it. Retention of that
generic code is not a Standard Asset compatibility path and does not permit
reactivating the removed devnet fixture without a new reviewed composition.

The committed devnet protocol version advances and removes the legacy fee
asset registry and legacy transaction gas schedule. Paid pricing is carried
only by the installed `PaidFeePolicy`.

## Verification gate

One real file-backed SQLite CLI-to-HTTP test covers all five top-level commands
against the production router. It proves successful state transitions,
signer/type/owner checks before signing, separate-source fee behavior for
Consume inputs, valid same-Coin application/fee-source composition, rejection
of a fee Coin aliased as a `TreasuryCap<A>` before submission, and exact fee
settlement. It also
closes and reopens the stores, proves exact replay does not reapply state or
fees, proves request-ID reuse with different signed bytes leaves every queried
object, receipt, and nonce unchanged, and proves stale writer-generation
fencing.

Unit coverage pins each command's ordered access manifest, public argument
bytes, current-object/provenance/version/owner/schema/nominal-type checks,
rejection of legacy module flags, and Ledger rejection before I/O.
Policy-derived code/instance/type selection is exercised only by the real
devnet E2E above rather than duplicated in a fake-policy unit test. The full
repository gate and a fresh independent tech-lead review are required before
merge.

## Consequences

- Standard Asset becomes evidence for the same public contract architecture
  available to user code, not a privileged protocol feature.
- Fees remain ordinary Standard Asset contract state; node core never reads or
  writes balances.
- Old local databases and old CLI flag sets intentionally stop working.
- Arbitrary Standard Asset creation remains the next asset feature after this
  migration; FastVote follows the generic-contract gate.
