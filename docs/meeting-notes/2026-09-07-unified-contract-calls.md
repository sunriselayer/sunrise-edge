# 2026-09-07: unify contract-call authority before extending execution

The user rejected treating calls between instances as a special permission
system: invoking another contract already requires code, ownership and delegated
authority checks, so these checks should generalize rather than fork.

At main `91822a6` (PR #153), library dispatch selects exact dependency code but
keeps one root instance in HostState. Durable admission rejects any non-root
object scope and effect validation assumes the root instance for creations.
These are implementation restrictions, not desired semantic distinctions.

Accepted correction: target = exact code plus exact instance/revision; one
frame-entry and object-operation validator; one object arena, fuel budget, nonce,
receipt and fenced transaction. Same-instance library execution and invocation
of another instance differ only in their selected target and delegated handles.
No separate instance-administrator signature or child transaction is introduced.

The normative design is in `docs/design.md` and DR-0123. Its signed table grants
bounded call capabilities, not a fixed call batch: the WASM caller determines
which authorized calls occur and computes canonically typed arguments. Actual
implementation and remaining evidence belong only in TODO.md.
