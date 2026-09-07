# DR-0112: Non-executing WASM admission and local contract validation

Accepted: 2026-09-07 (Asia/Singapore).

The first implementation boundary under [DR-0111](0111-generic-contract-design.md)
is a reusable structural WASM verifier in `execution`, exposed through the Rust
client and `contract validate` CLI action. It takes binary module bytes and an
explicit entrypoint set, checks the bounded execution profile, and returns an
immutable validated handle. It does not instantiate or run the module, call
host functions, or use sender authority.

## Separation from authority

Structural validation is necessary but does not authenticate a package lineage,
grant type/object rights, authorize dependencies, or establish instance scope.
In particular, recognizing the existing `env` object-function signatures is
not permission to create or mutate arbitrary objects. Future publication must
combine this verifier with authenticated code/ABI/dependency records and the
host authority checks in [`docs/design.md`](../../design.md).

Do not connect arbitrary validated uploads to the legacy trusted catalog as a
shortcut. The existing preinstalled dispatch is unchanged by this slice; its
replacement and the native fee-callback removal remain acceptance requirements
in TODO. No Standard Asset-specific admission rule is added.

## Structural contract

- Accept binary core modules only, with an explicit bounded entrypoint set.
  Preserve exact WASM bytes; sort entrypoint names and reject duplicates.
- Check byte and metadata bounds before engine translation, including function
  locals whose encoded count can describe far more memory than its byte size.
- Require bounded defined memory and a closed import/export surface matching
  the supported host ABI. Reject start functions without running them.
- Reject floating-point and unsupported WASM features, including unreachable
  code. Pin feature selection instead of inheriting parser defaults.
- Return typed deterministic failures rather than embedding parser/engine
  diagnostic text into protocol-facing outcomes.

Profile 1 limits are 4 MiB of binary bytes; 1–64 entrypoints with names of
1–256 UTF-8 bytes; 4096 function types and 4096 total imported/defined functions;
64 parameters and one result per function type; 4096 declared locals per
function; 1024 globals, data segments, and element segments each. There must
be exactly one defined, exported 32-bit memory with an explicit maximum of
at most 256 standard 64-KiB pages. At most one defined `funcref` table is
allowed, with an explicit maximum of at most 4096 elements.

Only integer MVP instructions, mutable globals, sign extension, and bulk
memory are enabled. Imports are limited to the eleven existing `env` host
functions with exact signatures, without duplicates. Exports must be exactly
`memory` plus the declared defined `() -> ()` entrypoints; compiler-added
global/table exports are not admitted. Custom sections are preserved in the
returned bytes but ignored by engine translation. These are acceptance bounds,
not a guarantee that initialization or execution fits its eventual gas budget.

Profile version 1 identifies these structural rules. It is not a new protocol
version, code identity, lineage revision, or canonical transaction field. A
future publication commitment must bind the selected profile together with
typed ABI and execution semantics. Any future accepted-language change needs
an explicit profile decision. No wire type IDs or hash domains are allocated
in this slice.

## Local tool

`contract validate --wasm <file> --entrypoints <name[,name...]>` reads at most
the module limit plus one byte and invokes the shared verifier. It has no
endpoint or signer flags, creates no instance, and reports structural validation
and `published=false`. It does not claim that a module will initialize
successfully or is safe to publish without the additional authority checks.

The existing node execution and canonical Transaction/Object/receipt bytes
are unchanged. Validation evidence and remaining publication work belong in
[`TODO.md`](../../../TODO.md); the operator syntax is in the
[contract guide](../../guides/contracts.md).
