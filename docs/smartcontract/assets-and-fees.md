# Standard Asset and fees

This is the normative **To-Be** contract-facing asset and fee design. It uses the
generic authority model in
[`../architecture/generic-contracts.md`](../architecture/generic-contracts.md) and the
contract lifecycle in [`lifecycle.md`](lifecycle.md). Current implementation status
and activation gates belong only in [`TODO.md`](../../TODO.md).

Standard Asset defines its asset identity, Coin, TreasuryCap, and mint, burn,
split, merge, and transfer behavior using the public contract facilities.
Amount arithmetic, supply accounting, and asset-specific state encoding stay
in that contract. The host protects generic type authority, ownership,
consumption, deterministic execution, and atomicity; it does not implement
Coin-specific conservation arithmetic or privileged mint operations.
The public package uses the initializer's host-created Definition ObjectId as
asset type argument A; individual Coin<A> objects retain their separate IDs.
Identity belongs to the nominal type, not a duplicated amount-body field.
Exact instance/defining-code authority is still required for every mutation;
type equality alone is not provenance evidence.

Fee admission, accepted fee assets, gas pricing, and settlement authorization
remain explicit protocol policy. Actual asset-state settlement uses a pinned,
committed contract revision with a bounded interface, rather than an arbitrary
node-local Rust callback that rewrites Coin bodies. The request cannot choose
an unapproved fee implementation or redirect the treasury. The protocol must
specify settlement resources and failure behavior without recursive fee
charging, and govern changes to the pinned settlement revision.

[DR-0124](../architecture/decisions/0124-contract-fee-reservations.md) uses one
reserve/application/settle invocation. The same sender-owned Coin may fund fees
and application work: an ordinary contract reserves the computed worst-case
charge first, and the application sees only the spendable remainder. Reservation
and application access are separately signed; reservation never strengthens the
application's grants. Generic typed frame results carry the protected reservation
to settlement without exposing it to application code. Settlement consumes it,
creates an ordinary fee Coin and returns any unused reserve as a fresh Coin to
the signed refund recipient. A separate fee Coin is optional, not mandatory.

Independent phase resource budgets protect settlement headroom; rollback never
rewinds cumulative gas, memory, handles or creation ordinals. Pricing initially
admits only base plus execution gas, including disclosed fixed bounded reserve
and settle allowances. Paid Call, Instantiate and Publish share the same consent
and coordinator. Bootstrap is a closed, atomic manifest installer, not an
externally callable fee exemption. The host validates output authority and
provenance, while the pinned contract remains responsible for opaque amounts.

The application cannot convert its own reservation-type outputs into a
settlement failure that avoids charging. The initial paid profile rejects
original application inputs of the policy's exact reservation type before
reservation. If application execution leaves another live object of that type,
discard the application effects, retain its measured gas, and settle the private
host reservation normally. This is a policy-type invariant, not a blacklist of
Standard Asset exports or a native decoder of reservation bodies.
Publish receipts must independently reproduce application units from the exact
authenticated artifact and verified dependency closure, including exhaustion;
merely accepting a reported value below the signed limit is insufficient.

Application effects and settlement commit atomically. A normalized execution
trap may discard application effects while committing only authorized fees and
the rejected receipt under the defined fee policy. Pre-execution rejection and
request-ID conflicts must not be confused with such fee-bearing failures.
Exact replay returns the original outcome without executing application or
settlement code again.
An admitted reserve/settlement execution failure instead restores pre-reservation
object state and records a zero-charge rejected receipt plus consumed nonce.
Invalid pre-admission requests still write nothing. Recording failed execution
prevents exact re-execution but does not solve fresh-request economic abuse;
public admission requires that separate analysis.
