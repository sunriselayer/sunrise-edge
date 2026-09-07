# Local contract validation

Check an existing compiled WASM artifact before preparing publication:

```bash
cargo run -p sunrise-edge-cli -- contract validate \
  --wasm ./contract.wasm \
  --entrypoints initialize,execute
```

Replace the names with the artifact's exact exported entrypoints. The
comma-separated list is required; duplicates and empty names are rejected.
Names are not whitespace-trimmed. This CLI list syntax cannot represent an
export name containing a comma; the Rust validation API accepts individual
names directly. The artifact must follow the structural admission profile,
including an explicit memory maximum and supported imports/exports.

Success prints line-oriented fields:

```text
validation=structural_wasm
profile_version=1
wasm_bytes=<artifact byte length>
entrypoint_count=<declared entrypoint count>
published=false
```

Failure exits nonzero and prints a sanitized `error=...` line on stderr.
The command does not alter the artifact, request a key, contact a node, publish
code, or execute an initializer. `--endpoint`, `--seed-file`, and Ledger flags
are rejected. A successful result proves structural admission only, not
correct business logic or authority to access another contract's objects.

See [the target design](../design.md) for publication and authority requirements,
[DR-0112](../architecture/decisions/0112-contract-wasm-admission.md) for this
boundary, and [TODO](../../TODO.md) for implemented scope and remaining work.
