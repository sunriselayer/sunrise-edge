# Own-created Standard Asset transfer, split and merge custody

[DR-0261](decisions/0261-created-standard-asset-coin-custody.md) extends the
existing [transfer](standard-asset-transfer-custody.md) and
[split/merge](standard-asset-split-merge-custody.md) profiles with the same
optional application pin used by
[mint/burn](standard-asset-mint-burn-custody.md). TODO.md owns qualification.

## Local pin for every role

Pass `--asset <definition-object-id> --instance-ref /private/instance.bin`
together to each participating `custody prepare-transfer`, `approve-transfer`,
`sign-transfer`, `serve-transfer`, and the equivalent split/merge commands.
The public Standard Asset `transfer`, `split` or `merge` CLI takes the same
pair along with its ordinary custody signer and business flags. Every
protected invocation independently loads its own trusted pin; the client
request carries only the existing bounded Coin/fee preimages and operation
fields. It cannot reconfigure a serving process.

The canonical InstanceRecord file must be owned by the invoking role, mode
0600 in an owned mode-0700 directory, and at most 2,048 bytes. Pin exactly the
record output by the earlier own-created asset workflow. Its creator must
match the custody publisher, and its context, exact code, initializer and
revision must match the pinned genesis Standard Asset implementation.
Application asset/instance aliases of the genesis fee identity are refused.
A pin is local review input, not independent proof of live state.

For example, append the same pair to the existing bounded serving recipe:

```bash
sunrise-edge-cli custody serve-split-merge \
  --config /private/config --key-file /private/custody.seed \
  --genesis-manifest-file /private/genesis.bin --genesis-digest <64-hex-pin> \
  --asset <64-hex-definition-id> --instance-ref /private/instance.bin \
  --socket /custody-run/application-coins.sock --approvals-dir /private/approvals \
  --max-connections 8 --max-requests 8 --total-deadline-secs 300
```

Use the existing prepare/approve/sign recipes with the same pair and the
application Coin preimages. Omit both flags to retain the genesis-only
behavior. A partial pair is refused. Transfer remains kind 2, split/merge
kind 3; neither server accepts the other family or a generic signing frame.

## Review and fee separation

The application Coin references, nominal type and Call instance are rebuilt
under the local application pin. The fee source remains a separate genesis
Coin, with the original fee policy, positive ceiling below its balance and
sender refund. An application Coin cannot be substituted as the fee source,
and a genesis or another asset's Coin cannot serve as an application input.
Merge requires both application Coins to share the pinned asset type.

The bounded full review retains its genesis fee identity and adds the exact
application asset, creator, seed, revision and record digest. It still shows
whole-transfer amount, split amount/remainder/recipient, or merge values and
checked total, as applicable, plus every signed input and the complete frame.
The existing typed confirmation, whole-frame approval, expiry and durable
revocation rules remain. An approval for another instance is refused even
when the Coin's nominal asset type is identical.

## Contained application sequence

The existing Docker fixture keeps its original families and entire stopped
same-key recovery sequence, then runs a separate follow-on against that same
own-created asset. Protected mint, split-to-self, merge and whole burn return
its supply to zero. A second protected mint and whole transfer go to the
fixture's existing distinct disposable recipient: the final supply is 5M,
TreasuryCap version six and next nonce nine. Transfer to the sender remains
refused; the fixture does not widen policy to use a no-op self transfer.

The independent Rust probe checks each signed frame, actual result, object
identity/type/amount/version/owner, supply, nonce and bound receipt. Saved
request replay compares all observed effect objects and receipt bytes without
advancing nonce; the final stage replays all six new requests. Separate pinned
kind-2/3/4 processes compare offline and actual CLI signatures, then refuse
revoked requests before and after restart without creating output. This adds
no key recovery or generation step and keeps the original resource limits.

## Qualification boundary

Pure source controls use synthetic canonical application preimages and the
existing in-process approval/signing decisions. They do not prove actual
application execution or currentness. Distinct-UID CLI execution, owning/full
validation and release gates remain source-specific acceptance work tracked
in TODO.md. No real-key custody, ownership migration, automatic signing,
public deployment or independent security clearance follows from this slice.

## Historical transfer recovery profile (2026-10-18)

The separate `--profile application-transfer-recovery` invocation runs fresh
contained application setup and then exercises kind-2 same-key recovery. Use
it with the same explicit `--cli-binary` and `--test-binary` inputs as the
existing Docker fixture. `--profile publication-genesis` and its omitted or
`--profile default` aliases select the publication/genesis core. Its 70
completion predicates and this profile's 47 original application setup
predicates retain the original 117-predicate coverage across two invocations,
with common success/cleanup counted once. The complete original create,
recovered-key mint/burn, six-stage Coin and signer-group host checks also run
for this profile; its additional historical transfer recovery stays here.
`--profile genesis-split-handoff` retains its separate 21. Each invocation has
its own allocation and accounting; no counter is reset within an allocation.
The old single-result 117-field shape is not the core result schema.

It retains the application Coin and separate genesis fee preimages from
historical nonce eight, after all original business signers and the native
host have actually stopped. A fresh `a6` request uses the unchanged complete
application definition/InstanceRecord and genesis pins in every custody and
operator role. The real terminal must display the complete prepared review,
including application identity, whole amount, recipient, fee policy and full
signing frame, and the exact `APPROVE-TRANSFER` prefix before confirmation.
The original key signs that same request once; its process is waited, its PID
is absent and its socket is gone before the custody UID makes the existing
private backup/restored-key copies. The restored signer must produce identical
bytes. The old `a5` revocation and new `a6` revocation each refuse with absent
outputs in the same process and after restart. The setup isolation probe checks
the original seed, and the new isolation probe checks the actual restored path;
both also refuse operator edits to their corresponding approval. Public preimages, trust files
and requests must retain their bytes and attachment metadata.

The shared approval helper charges each completed PTY capture exactly once,
after waiting for its child and before checking the review, exit status or
approval record. Callers retain the returned byte length without charging it
again. This includes the default invocation and every separate profile;
phase-local totals still measure the same cumulative counter without resets.
The strict application setup option retains its additional child-closure
checks; accounting no longer depends on that option. Each PTY retains its
16KiB local limit, and actual invocation headroom remains an owning-run result.
The new recovery
adds exactly nine CLI children, one PTY, two custody-private copy children and
three bounded signers, with eight generated private leaves, four absent
refusal outputs, at most 16KiB generated content and 16KiB captured output.
Every invocation retains the global 256KiB captured-output limit, 280/230-second
Node/Python deadlines and original Docker, volume, wire and transport bounds.
Actual output headroom is an owning-run result, not a source-only guarantee.

The fresh recovery request is signed only and is never submitted. It makes no
claim about the historical nonce or fee being usable again, another business
execution, a new owner, creator migration, key rotation or live currentness.
Static source checks do not establish distinct-UID execution; TODO.md owns
actual owning, full-required and hosted validation for the selected source.

## Historical split/merge recovery profile (2026-10-18)

The separate `--profile application-split-merge-recovery` invocation repeats
the strict create, mint/burn, six-stage Coin and create-recovery setup, including
the exact same 47 application setup validations. It then signs two independent
historical kind-3 requests: fresh `a7` uses the retained nonce-four first Coin
and genesis fee preimages, and fresh `a8` uses the retained nonce-five first
Coin, split Coin and fee preimages. The merge preimages are outputs of the
original `a1` split, not outputs of `a7`, which is never submitted.

Every role retains the complete application definition/InstanceRecord and
separate genesis fee pins. Before either terminal confirmation is echoed,
the fixture checks the complete prepare review and exact typed confirmation
prefix. The split review must show the original first Coin at version one,
5M held, 2M split to self and 3M remainder. The merge review must show that
first Coin at version two with 3M, the distinct split Coin at version one with
2M and consume mode, and a checked 5M total. Both reviews include their exact
historical genesis fee identity/version, policy fields and complete frame.

The original key signs those same two frames as references. Its process must
exit, be waited and leave neither PID nor socket before the two custody-UID
backup/restored-key copy children run. Restored-key signatures must match the
reference bytes. Old `a1`/`a2` requests and newly revoked `a7`/`a8` requests
must refuse without outputs, both before and after a signer restart. All
public attachments remain byte- and metadata-identical. Operator probes use
the actual restored-key path and each new approval; together with the setup
probe they record three read refusals, three edit refusals and six waited
children. The two new read probes repeat the same restored-key path; these
counts do not represent three unique keys. They are separate from the
recovery's 25 children.

The recovery adds exactly 18 CLI children, two PTYs, two private-copy children
and three signers. Its fixed allocation has 14 generated private leaves,
eight absent refusal paths, at most 32KiB generated content, 48KiB captured
output and a 4KiB recovery summary. All successful PTY captures are charged
once. The invocation retains the same 256KiB global capture limit, 16KiB
per-PTY limit, deadlines, Docker limits and wire/transport bounds. Core70,
genesis split-handoff21 and application transfer recovery remain independent
profiles with their existing checks. Actual headroom requires an owning run.

These are historical signing-only requests, not a new split-to-merge execution
chain. They establish no reusable nonce/fee freshness, current state, owner
change, creator migration, key rotation or new policy. Qualification remains
source-specific in TODO.md.
