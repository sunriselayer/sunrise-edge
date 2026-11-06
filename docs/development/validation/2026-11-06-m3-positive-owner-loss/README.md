# M3 referenced body through local owner loss (2026-11-06)

Source base: `add45bb62e451e50091abbca8ec7b06bf102825c`. The new Linux
selector in `apps/operator/tests/local_tls_startup.rs` reuses the fixed 70 KiB
historical-body oracle across four compiled direct-TLS hosts, total SIGKILL and
reap, generation-3 reopen, exact saved replay, fresh paid business and final
stop. Existing empty-closure, ACK-loss and trust-rotation selectors remain.

The initial focused run compiled successfully but failed its explicit
`sunrise-edge-cli` precondition (exit 101). After
`cargo build --locked -p sunrise-edge-cli --bin sunrise-edge-cli` (exit 0),
the following exact commands each exited 0 with one passed test and no failure:

```text
cargo test --locked -p sunrise-edge-operator --test local_tls_startup actual_direct_tls_complete_owner_loss_preserves_historical_referenced_body -- --exact --nocapture
cargo test --locked -p sunrise-edge-operator --test local_tls_startup actual_direct_tls_complete_owner_loss_authorizes_fresh_writer_and_paid_business -- --exact --nocapture
cargo test --locked -p sunrise-edge-operator --test local_tls_startup actual_direct_tls_hosts_replay_once_after_owned_sigkill_and_fresh_fence -- --exact --nocapture
cargo test --locked -p sunrise-edge-operator --test local_tls_startup actual_local_tls_lost_apply_acknowledgements_preserve_historical_body_after_orderly_restart -- --exact --nocapture
cargo test --locked -p sunrise-edge-operator --test local_tls_startup actual_direct_tls_hosts_preserve_paid_state_replay_and_explicit_stopped_trust_rotation -- --exact --nocapture
```

Each run had a 900-second external timeout and a 30-second TERM-to-KILL cleanup
bound. `cargo fmt --all -- --check`, `git diff --check`, and
`cargo clippy --locked -p sunrise-edge-operator --test local_tls_startup -- -D warnings`
also exited 0. The command owner returned EOF/exit for each run; no compiled
CLI, source host, genesis helper or test process remained in this worktree's
process inventory afterward. Complete raw stdout/stderr and exit receipts are
retained outside this source worktree at
`/home/yu/src/github.com/sunriselayer/sunrise-edge-m3-positive-failover-1106-evidence`.
The new-selector success raw SHA-256 is
`9ab12a65476717dbc7821fa423cae56d6fae241e10cd576704f890772ae8983b`.

This is positive historical-body preservation during local process failover.
It does not exercise a blob-write fault, paid-produced blob publication,
cross-host failover, power/media/fsync faults, torn WAL, or the independent
anchor guest. The full required gate and hosted CI remain separate.
