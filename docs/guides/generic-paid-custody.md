# Generic paid contract custody handoff

This route accepts generic paid Publish, Instantiate, and Call under the
existing canonical `PaidIntent` signing frame. It uses a saved request file
and a separate custody UID; no contract command reads the custody key.
Approval and signing both query the configured endpoint; they are not offline.
The selected endpoint is checked against explicit protocol pins. Its current
fee-source response is an endpoint observation, and a later state change may
still make admission reject the signed request.

1. Run `contract paid-publish`, `paid-instantiate`, or `paid-call` with its
   normal endpoint, expected-context, fee, and application flags, plus
   `--custody-socket`, `--custody-uid`,
   `--custody-expected-public-key`, and `--unsigned-out` pointing to a fresh
   file under a mode-`0700` operator directory. This mode emits the canonical
   unsigned intent and bounded review, then stops before signing or
   submission. The socket and UID flags satisfy the existing all-or-none
   custody selection grammar; this export does not connect to that socket.
   For a later FastVote replay, also provide `--fastvote-network`, the
   locally pinned `--fastvote-genesis-manifest` and
   `--fastvote-expected-genesis-digest`, and select one configured
   `--endpoint`. The CLI authenticates the genesis/cohort and rejects a
   request ID outside its owned lane before exporting anything. Do not
   provide signed-intent, certificate, result, or derived-output paths during
   unsigned preparation. The signed intent and certificates are created
   separately after approval.
2. Place the exact unsigned file and the independently pinned canonical paid
   fee-policy file in a custody-owned mode-`0700` directory as mode-`0600`
   files. A privileged operator can use `install -o CUSTODY_UID -g CUSTODY_GROUP
   -m 0600` for the file handoff. Do not put the private key in the operator
   directory. The policy file must match the selected endpoint's installed
   policy byte-for-byte.
3. As the custody UID, run `custody approve-paid` with `--config`,
   `--policy-file`, `--request-file`, `--approvals-dir`, `--endpoint`, and
   `--expires-in-seconds` (plus both TLS flags for a remote endpoint, and
   any required `--suite` pins). It rechecks context, installed policy, and
   the current inline fee source, displays the complete bounded review,
   requires a terminal and exact typed confirmation, then stores the whole
   signing frame in a revocable approval. The config, files and approvals
   directory must follow the existing custody ownership/mode rules.
4. As the custody UID, run `custody sign-paid` with the same config, policy,
   request, approvals, endpoint, TLS and suite pins, plus `--key-file` and
   `--out` in a custody-owned mode-`0700` directory. It queries policy and
   source again, rebuilds the same frame, checks the approval expiry and
   revocation, and writes exact canonical `SignedPaidIntent` bytes. It never
   accepts a caller-supplied frame or falls back to a development seed.
5. Move only the signed intent to the submitting operator with a privileged
   `install -o OPERATOR_UID -g OPERATOR_GROUP -m 0600` into the operator's
   mode-`0700` directory. Submit it with `contract paid-submit-signed
   --signed-file ...` plus endpoint and expected-context/TLS/suite pins. This
   command authenticates the signature and rechecks installed policy and
   fee source before the direct POST; the node still performs final admission.
   For Publish, add `--dependency-ref-out`; for Instantiate, add
   `--instance-ref-out`. Both references are independently reconstructed
   from the saved signed intent before the POST and written without
   overwrite. The same recovery flags are supported by FastVote replay.
   For FastVote, pass the **same saved signed file** as `--submission` to
   [`contract fastvote-replay`](fastvote-network.md) with that command's
   pinned network, genesis and deadline flags. Replay can prepare a new
   certificate from the saved signed intent and does not re-sign or change
   request ID or nonce.

Keep the unsigned request, pinned policy, signed intent and any result under
their own request ID. Retry an uncertain submission with the identical signed
bytes; a changed nonce, policy, source, or application needs a new approval.

## Disposable distinct-UID paid-contract check

The [Docker fixture](../../scripts/check-docker-generic-paid-custody.py) reuses
the existing SQLite/native-HTTP paid-contract test server and runs the real
CLI under separate operator and custody Linux UIDs. It runs a protected-signed
Publish, then Instantiate from its saved code reference and Call from the saved
instance reference. Each operation has unsigned export, bounded PTY review and
exact confirmation, protected signature, direct signed submission and focused
approval refusals. The shared fixture also checks operator access to the
custody key and approval store, and revocation before Publish submission. Build the
CLI binary and `devnet_paid_contract_e2e` test binary from the same source,
then pass their absolute paths:

```sh
python3 scripts/check-docker-generic-paid-custody.py \
  --cli-binary /absolute/path/to/sunrise-edge-cli \
  --test-binary /absolute/path/to/devnet_paid_contract_e2e-HASH
```

For the FastVote route, build the `fastvote_network_e2e` test binary from the
same source and use `--fastvote` with that binary in place of
`devnet_paid_contract_e2e`. This runs four real SQLite/native-HTTP validators
with transaction-auth profile 2. It collects and applies a FastVote
certificate for each saved protected-signed Publish, Instantiate, and Call,
then replays each saved certificate and compares exact results. It also rejects
a malformed certificate and mismatched chain pin for Publish, and another
intent's certificate for Instantiate and Call.

The fixture uses a disposable fixed key and an isolated Docker network with
only loopback traffic. It does not cover an enrolled operator key or a public
deployment.
