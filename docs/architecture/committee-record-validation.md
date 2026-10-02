# Committee record validation

One core owner converts a `FastPathValidatorSetRecord` into the structurally
valid Ed25519 FastVote committee for an explicitly expected publication context.
The shared primitive is pure validation, not installed-state or serving
authority. [DR-0184](decisions/0184-one-fastvote-committee-record-validator.md)
records the cross-crate boundary. Progress belongs in [TODO](../../TODO.md).

## One defining primitive

`validate_fastvote_validator_set_record(record, expected_context)` returns a
`ValidatorSet` or a typed local committee error. It checks context equality,
rejects non-Ed25519 members and applies the existing `ValidatorSet::new` rules
for membership, power, uniqueness, keys and bounded set size. It does not invent
a hash schedule or change canonical record, committee or signature bytes.

The byte-decoding adapter still performs the existing bounded canonical decode
before calling this primitive. Existing core live and historical read owners
retain their own deciding observations, fences and authenticated digest checks.
They do not reimplement member conversion.

## Structural validity is not authority

| Consumer | Shared validation | Separate owning authority |
| --- | --- | --- |
| Original genesis conversion | Signed record structure and expected genesis context | Local pin/signature, genesis capacity/error order and full bootstrap semantics |
| Live core reads | Decoded current record structure | Fresh epoch/record digest binding and physical deciding observations |
| Historical evidence reads | Decoded historical record structure | Chain-anchored historical digest and history fence |
| Operator startup pin | Configured/loaded record structure | Actual installed live epoch/digest, signer membership and writer/listener order |
| Operator CLI committee use | Explicitly expected record context | Its genuine loaded-row, protocol configuration and invocation checks |

The primitive cannot prove any of those separate authorities. In particular a
`ValidatorSet` produced from arbitrary locally supplied fields is not a verified
genesis root, current serving token, Seal or successor activation.

Genesis retains context-before-capacity-before-member error precedence. Its
capacity rule remains with genesis, not silently imposed on historical/live
records by this shared conversion. The public typed errors map to each owner's
existing diagnostics without matching strings. Preserve current core decode
failure ordering and all externally asserted error messages.

## Actual migration and acceptance

Keep the existing core live/historical decoder owner and delete the operator's
hand-built conversions. Genesis uses the same defining record validation while
retaining its own capacity/authority checks. Do not add another universal live
context or wrapper that preserves a second conversion implementation.

The operator startup path previously omitted the Ed25519-only check while core
admission and the operator CLI enforced it. Add an actual configured-row
negative, including a matching installed digest, proving startup refuses before
claiming a new writer or exposing a listener. This is fail-fast configuration
validation; core already rejects such a committee at real admission, so this
does not establish a signature-verification or consensus exploit.

Retain wrong-context, invalid membership/power/duplicate-key and error-order
negatives. Genuine genesis, historical evidence, live preparation/apply,
startup/compiled CLI, real SQLite and selected PostgreSQL flows remain owning
acceptance. No canonical vectors, replay, receipt, nonce or fencing behavior is
waived by the shared pure primitive.
