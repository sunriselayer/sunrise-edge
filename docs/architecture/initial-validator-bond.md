# Initial validator bond registration

[DR-0179](decisions/0179-initial-validator-bond-registration.md) owns the first
bond of a non-genesis validator. Existing Deposit starts from a real Exited
row; it does not create the first row. Registration does not make a validator
a committee member or authorize readiness, Seal or activation.

## Generic custody, not a native coin

The independently pinned genesis economics policy defines the resource and its
generic public-contract custody capability. A source owner signs an ordinary
local execution leg that transfers one complete owned object into this
validator/resource's BondCollateral scope. The new validator separately signs
the exact registration, resource, leg, pinned genesis and expected generation-1
row digest. Donations are allowed with both signatures. No Standard Asset
special execution path or chain-native balance is introduced.

For first registration the ID is the actual canonical prime-order Ed25519
public key. Neither a genesis ID nor any genesis authorization key can be
reused. Existing genesis identities and lifecycle bytes stay unchanged.

## Ordered execution and reconstruction

`OrderedOperationKind::BondRegistration` is kind 7 on the existing authenticated
ordered route. Pure authentication accepts a self-authenticated incoming key,
not its membership. The outgoing committee still orders and commits normally.
The private dispatcher requires ordinary causal origin, the first outgoing
epoch, exact signed resource authority and pristine bond, registration-anchor
and old generation-1-transition slots.

The generic WASM leg must actually succeed, preserve the complete nominal
amount, type/schema and object identity, and change only the exact permitted
owner/version. The amount must obey enabled minimum/exposure policy. One atomic
invocation commits custody, nonce, generation/provenance, original receipt,
Active generation-1 bond and its immutable signed root. Liability begins at the
adjacent epoch. Bond amount does not choose voting power. Later existing
transitions begin at generation 2; there is no invented predecessor.

An already healthy registered identity or positively classified invalid
execution result becomes an exact ordered refusal without application effects.
Missing/corrupt/unavailable/fenced prerequisites stop, rather than manufacturing
a business refusal. Exact request replay returns the original outcome without
executing again; conflicts do not rebind the root or receipt.

Private business reconstruction executes the original owned producer and
registration, then compares the entire resulting inventory. Structural root
verification alone is not execution proof. Registration anchors have exact
owning codecs and projection; no broad State-prefix exemption is added.

## Capability boundary and surfaces

The preparation SDK/CLI validates a bounded predicted row and signed leg and
signs the resulting claim. Only normal committed execution can establish the
actual row. See [the operator guide](../guides/initial-validator-bond.md).

The initial capability is deliberately limited to the first causal-genesis
epoch. A pre-join incoming key does not gain existing outgoing-member
Unbond/Replace authority. Later registrations require the separate verified
serving authority; ordinary activation/rollover is not supplied by this feature.
Implementation status and remaining Delivery 3 gates belong in
[TODO.md](../../TODO.md).
