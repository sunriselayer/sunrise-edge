# DR-0264: Original ordered protocol custody worker

Date: 2026-10-17, Asia/Singapore

Status: Accepted bounded implementation design. Execution qualification belongs
only in TODO. This is not all-M2 or production key-management qualification.

## Decision

For the selected trusted local OS boundary, place original ordered authority,
validator key use and confirmed retention together in a distinct-UID local
worker. The HTTP/TLS frontend forwards original bounded ordered requests over
authenticated Unix IPC. It owns no validator key, SQLite writer, anchor lease,
writer fence or protocol signing port. The worker reuses the existing original
host startup and complete certified ordered router. No borrowed live warrant,
caller path, raw signing frame or `trusted=true` assertion crosses IPC.

Only original ordered proposal and consensus-vote signing are selected. Keep
certificate/observer/Tick progress and ordered read/history routes with their
existing owners. Other automatic families, successor custody and interactive
approval remain separate. The ordinary combined host and its 13-executable
inventory remain compatible. The new mode is an opt-in ordered-only deployment;
it is never a second concurrent writer beside the ordinary host.

The worker requires an explicitly enrolled independent local anchor, its fixed
source/body paths and original genesis/context pins. It acquires their existing
ownership, requires ordinary namespace, claims one fence, then checks committed
state/committee and the actual key before binding. It never enrolls, repairs,
bootstraps or falls back. Keep real WASM execution and Seal retention.

Canonical protocol encoders, domains, digests, signatures, schemas and core
decision order are unchanged. Existing DR-0215 verification remains before
retention; the frontend also verifies successful proposal/vote outputs against
its independently fixed original policy. Only confirmed complete operation
results cross IPC. Rejected or uncertain commits expose no successful signed
result. Lost post-commit output reconciles through the original exact-request
path, without transport retries or a second signing backend.

Both roles have finite request/connection admission and absolute deadlines.
Both authenticate exact peer UIDs before IPC bytes; the worker authenticates
before operation dispatch/key use. Disconnect and deadline do not imply a
started blocking operation rolled back: close admission and drain its existing
executor before releasing source/authority ownership. Socket cleanup removes
only the exclusively owned attachment.

Trust includes the worker's existing core/execution code and local OS/root.
Keys are isolated from ordinary frontend processes, not from compromised worker
code or root. There is no encryption, hardware or off-host signing-history claim.
The independent source anchor is not a new protocol authority or quorum root.

See [the deployment contract](../local-protocol-custody.md) for configuration,
bounded transport and owning controls. No actual keys, host users/services,
public deployment, stopped audit or stopped fee fixture are authorized here.
