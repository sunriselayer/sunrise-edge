# DR-0125: public Standard Asset activation hardening

Accepted: 2026-09-20 (Asia/Singapore).

This decision closes the package-local prerequisites that must be stable before
the public Standard Asset package can be installed by the paid-execution genesis
manifest. It refines [DR-0124](0124-contract-fee-reservations.md) without
activating paid HTTP/CLI admission, installing a fee policy, or removing the
legacy devnet path. Current status and remaining work stay in
[`TODO.md`](../../../TODO.md).

## Decision

Treat the WAT-to-WASM compiler and the generated package bytes as
protocol-relevant build inputs. Pin the workspace `wat` dependency to the exact
version already represented by the accepted lockfile. A dependency update must
therefore be an explicit reviewed change with regenerated artifact evidence,
not an incidental compatible-version resolution.

Make the self-describing `Digest32` frame length a single source of truth for
the executable ABI, native argument/body encoders, and generated WAT. Package
construction must independently encode and decode every admitted digest
algorithm, verify the exact bounded length, and inject that verified length into
every WAT check/copy. A prose comment or a test-only comparison is insufficient:
`build_package` must fail before producing WAT/WASM if canonical framing drifts.

Add VM regressions for the two authority boundaries that activation depends on:

- `mint` and `split` may create ordinary `Coin<A>` objects for a valid foreign
  recipient while preserving supply and leaving the source/capability owner
  unchanged;
- two instances created from identical published code remain distinct authority
  scopes. A Coin, TreasuryCap, or Reservation created under one instance must be
  rejected when supplied to every applicable entrypoint of the other instance,
  even when the caller supplies the first instance's valid nominal asset type.

Cross-instance rejection must occur through the generic host authority model,
not a Standard Asset-specific instance ID comparison in guest code. Rejected
calls produce no object effects or events. This preserves the design rule that
nominal type equality and identical code do not imply shared instance authority.

## Compatibility and scope

No canonical package, ABI, argument, object, or result encoding changes in this
slice. The generated WAT and WASM bytes must remain identical under the pinned
compiler. The new checks make future drift fail closed; they do not introduce a
second package version.

Fee/refund owner validation is not reimplemented here. The existing paid intent
and coordinator boundaries already validate both addresses with the active
canonical prime-order owner policy before reservation. Calibration of reserve
and settle allowances, historical object framing, durable paid coverage, the
closed manifest installer, native HTTP/CLI activation, and removal of the legacy
catalog/native composer remain later DR-0124 activation work.

## Required evidence

- an exact compiler-version pin and a permanent package-WASM digest vector;
- package construction tests proving all admitted `Digest32` algorithms match
  the WAT template length and malformed or drifted framing cannot be emitted;
- successful foreign-recipient mint and split tests with exact owner, amount,
  supply, and unchanged-source assertions;
- a same-code cross-instance rejection matrix covering mint, burn, transfer,
  split, merge, reserve, reserve-all, and settle, with no effects on every
  rejection;
- package tests, workspace format/clippy/tests, stable vectors, and a fresh
  independent review before merge.

## Implementation evidence

The workspace pins `wat` exactly and the package builder validates all three
admitted self-describing digest encodings before producing source. The verified
length is substituted into every guest check; `build_package` parses the same
WAT string it returns instead of regenerating it. A permanent SHA-256 vector
fixes the 3,808-byte package WASM. An independent detached-baseline build
confirmed that this vector also matches the package before the refactor.

The VM suite proves direct foreign-recipient mint and split behavior and fixes
the exact generic `input scope` rejection for mint, burn, transfer, split,
merge, reserve, reserve-all, and settle across two instances of identical code.
These tests exercise generic host authority and introduce no guest-side
instance exception. Repository-gate and review results belong to the pull
request evidence; none of this activates paid admission or closes DR-0124.
