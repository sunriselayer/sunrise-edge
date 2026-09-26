# Recover a missed certified contract lifecycle

This workflow repairs **declared same-epoch certified Publish, Instantiate and
Call requests** on an existing
validator that missed preparation and application. It uses saved signed
artifacts, not a database copy, fresh signature or automatic state reset.
[DR-0150](../architecture/decisions/0150-certified-call-catch-up.md) defines
the original safety boundary; [DR-0151](../architecture/decisions/0151-integrated-network-delivery-and-lightweight-stores.md)
extends it to the generic lifecycle. Current readiness and independent review gates remain
in [`TODO.md`](../../TODO.md). Do not deploy this experimental network publicly
or use real assets.

## Prerequisites

The returning validator must have the same independently trusted signed
genesis, live epoch/set, fee policy and exact predecessor object/nonce state
as the requests need. Required user definitions may already exist exactly, or
be established by an earlier certified Publish in the same manifest. Required
instances similarly precede dependent Calls. Start its already-installed namespace
using [the existing host walkthrough](fastvote-network.md), never reset or
reinstall genesis as recovery. Its configured `--created-checkpoint` must
reproduce the certified staged commitment for a never-prepared request. This
number is creation metadata, not a published checkpoint or state-root anchor.
An already-prepared request always uses its stored checkpoint instead.

Keep ordinary traffic away from the returning host while recovering (for
example, expose only its loopback maintenance endpoint). No command here
silently clears a foreign, stale or orphan lock. Missing definitions, divergent
object heads/nonces or incompatible creation metadata require explicit
investigation; a newer signature or direct database overwrite is not a repair.

Retain the original `--fastvote-signed-intent-out` and
`--fastvote-certificate-out` files produced by
[paid contract and asset commands with `--fastvote-network`](fastvote-network.md).
A quorum
certificate authenticates the exact staged outcome against the full pinned
validator set. Copying the files over an untrusted channel does not authorize
anything until this verification succeeds.

## Prepare an ordered manifest

Create a text file containing one saved signed-intent/certificate pair per
line, in dependency order. Relative paths are relative to this manifest's
directory. Paths containing whitespace are not supported. Each request id
must appear only once. At most 16 pairs and 16 MiB of combined input artifact
bytes are admitted. The manifest itself is limited to 64 KiB and each line to
4096 bytes; existing tighter intent/certificate limits still apply. These are
resource bounds, not throughput targets.

```text
publish.signed.bin publish.certificate.bin
instantiate.signed.bin instantiate.certificate.bin
call.signed.bin call.certificate.bin
```

Do not order by arrival time or filename. Publish dependencies precede their
dependent Publish, Instantiate precedes its Calls, and each operation's
predecessor nonce and objects must be present. A committed charged trap also advances the
nonce and charges its certified fee; it is a valid predecessor, not a reason
to re-sign or omit it.

## Apply exactly the saved bytes

Use a network configuration selecting the returning validator(s). A file
containing only one returning peer is sufficient to **apply an already formed
certificate**; the locally trusted genesis pin still contains the complete
validator authority set and verifies quorum against that full set. It is not
a one-validator certificate or permission to form a new certificate.
Reuse the endpoint identity and per-peer TLS format in
[the network walkthrough](fastvote-network.md#configure-the-network-for-the-cli).
Never replace your expected context/genesis with server response values.

Provide an existing, controlled result directory with unused output filenames:

```sh
cargo run -p sunrise-edge-cli -- contract fastvote-catch-up \
  --expected-chain-id YOUR_CHAIN_ID --expected-protocol-version YOUR_PROTOCOL_VERSION \
  --expected-epoch 0 --expected-hash-suite-id 1 --expected-domain YOUR_DOMAIN_ID \
  --fastvote-network /secure/returning-validator.conf \
  --fastvote-genesis-manifest /secure/genesis.manifest \
  --fastvote-expected-genesis-digest YOUR_64_HEX_DIGIT_MANIFEST_DIGEST \
  --fastvote-deadline-seconds 120 --fastvote-per-request-cap-seconds 10 \
  --manifest /secure/recovery/requests.txt --result-dir /secure/results-first
```

The CLI verifies every pair and all bounds before the first POST. It creates
all output destinations without overwrite before application, synchronizes
the exact input artifacts and uses one whole-operation deadline. It never
queries a new nonce, collects new votes or signs anything. The host independently
re-executes each never-prepared request and compares the complete certified
commitment before atomically applying effects, nonce, receipt and settlement.
An invalid certificate or different outcome creates no speculative locks.

Outputs are indexed from one: `entry-0001.report` records each configured peer's
outcome; `entry-0001-validator-<64-hex-validator-id>.result` contains that peer's
exact canonical result. Keep success and charged-trap results. A charged trap
is a valid committed entry, so the following dependency can still be applied.
An HTTP acknowledgement is not a signed whole-store or network-finality proof.

## Resume after interruption

The batch is **not atomic**. A failure can leave an applied prefix on one or
more peers and empty/partial reserved output files. Do not infer rollback
from a nonzero exit or absent completion line. Investigate the reported entry,
retain all original artifacts and outputs, then replay the same manifest to
a different existing result directory with fresh output paths:

```sh
# Repeat the command above with --result-dir /secure/results-replay.
cmp /secure/results-first/entry-0001-validator-YOUR_VALIDATOR_ID.result \
    /secure/results-replay/entry-0001-validator-YOUR_VALIDATOR_ID.result
```

Already-committed requests return their original receipts without nonce, fee
or application reapplication, including after restart and after later entries.
Do not substitute a fresh nonce or a re-signed request as an ambiguous-commit
retry. Existing files are never truncated. Fix a genuinely invalid artifact
source explicitly; the tool does not fill missing certificates or reorder work.

## What this does not prove

A successful run covers only the manifest's declared requests. It does not
prove that no requests were omitted, import uncertified or arbitrary database definitions,
repair shared fee-claim or bond/evidence state, establish full replica/state
convergence, detect whole-store rollback, or authorize new membership/epoch
activation. Offline DR-0149 claim mutations still require separately reviewed
settlement/state handoff before live re-entry. Keep those independent gates
open; catch-up of a known request list is not their substitute.
