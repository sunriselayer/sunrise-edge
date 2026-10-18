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
existing Docker fixture. The omitted/default profile retains its original
117 checks; `--profile genesis-split-handoff` retains its separate 21. This
profile does not append work to either invocation or reset its accounting.

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
Application split/merge recovery remains separate pending work. Static source
checks do not establish distinct-UID execution; TODO.md owns actual owning,
full-required and hosted validation for the selected source.
