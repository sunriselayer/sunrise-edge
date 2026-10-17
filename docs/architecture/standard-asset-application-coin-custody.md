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

## Qualification boundary

Pure source controls use synthetic canonical application preimages and the
existing in-process approval/signing decisions. They do not prove actual
application execution or currentness. Distinct-UID CLI execution, owning/full
validation and release gates remain source-specific acceptance work tracked
in TODO.md. No real-key custody, ownership migration, automatic signing,
public deployment or independent security clearance follows from this slice.
