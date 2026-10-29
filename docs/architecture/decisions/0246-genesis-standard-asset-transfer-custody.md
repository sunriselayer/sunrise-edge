# DR-0246: Genesis Standard Asset transfer custody

Date: 2026-10-16

Status: Accepted design. Qualification is tracked in TODO.md.

## Decision

Extend the selected trusted-local-OS boundary to one genesis-epoch Standard
Asset whole-coin transfer. The custody process independently pins its context,
sender, operator UID and signed genesis root. It authenticates the nested
publication and requires equality with the in-tree Standard Asset build and
its genesis fee policy. Unknown code, later epochs, user-created assets,
other operations and arbitrary signable frames are refused.

The operator supplies bounded canonical coin and fee-source object preimages,
recipient, nonce, request ID, gas and maximum fee. Custody recomputes both
object references under its pinned genesis context and verifies exact owner,
nominal type, schema and coin body. Only the signed references and actual
known contract semantics establish what the human approves. A preimage is
not proof of current state; execution enforces freshness and availability.

A separate transfer-only server invocation accepts adapter-local message kind
2. Publication remains kind 1 and never gains transfer signing authority.
The bounded UID-checked socket owner and whole-frame approval/revocation store
are shared. Approval uses independently obtained private preimages, a complete
bounded review and an exact terminal confirmation. The operator receives only
a signature and independently finalizes the same prepared paid intent.

## Compatibility and lifecycle

No protocol encodings, cryptographic domains, execution effects, fee quote
ordering or historical vectors change. The local request kind is outside the
protocol namespace. Expiry and revocation gate every signing request; already
issued signatures cannot be erased. Stop the signer before recovery or a
strong revocation fence. Recovery retains revocations; a new sender key needs
independent approval and asset ownership, rather than changing an existing
address identity.

## Limits

This is the same trusted OS/root and separate UID model as DR-0238. At-rest
encryption, compromised-root protection, real key ceremonies, other signing
families and automatic validator signing require their own qualifications.
No real keys, host users, public services or network activation are selected.
