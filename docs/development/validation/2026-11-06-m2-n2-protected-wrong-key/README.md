# Protected successor wrong-key test preparation

Date: 2026-11-06, Asia/Singapore. This is a test-only addition to the
existing M2-N2 owner, not a runtime result or M2 completion claim.

## Exact source and scope

Code commit `04f02cc66dd70aa8b72cc664ae069aafd3d7d983`, tree
`23c6a23a6b7b8d48f946b5cbae90140fdcb5b5d1`, adds one wrong-key startup
refusal to the existing distinct-UID successor branch of
`compiled_registered_replacement_and_recurring_successor_hosts`.
The helper retains the original seven epochs, e8 terminal unlock, two
1832-byte withdrawal candidates, eight links, 35 roles, and process timeout.
The wrong-key process uses the same protected worker command and a separate
disposable 32-byte private key. The new assertions require the actual member
key mismatch, no listening or signed route, exactly one startup writer-fence
claim, and unchanged non-fence durable SQL, receipt and blob rows. The
normal key then starts through the original recurring owner. This observes
the existing startup-fence contract; it does not change authority or add a
new signer route.

During integration review, the non-fence comparison was extended to every
column of `durable_metadata` except `writer_fence`, including
`mutation_sequence` and origin/binding. The state and blob SQL lists now
reuse the existing recurring acceptance capture rather than duplicating that
test oracle. The compile and Clippy results below refer to the earlier code
commit; the integrated source requires its own gate.

## Completed build checks

The dedicated target and raw records are under
`/home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013/m2-n2-wrong-key-1106/`.
The bounded `cargo +1.97.1 test --locked --offline -p sunrise-edge-operator
--test conditional_readiness_sqlite --no-run --message-format=json` finished
with actual exit 0. Its Cargo JSON includes the exact test executable and
all eight operator executables. The terminal receipt is
`operator-build-terminal.json` (SHA-256
`7f71601d61ce98f022b308375b9490c117a6deb0b53464013bd3b4b730e06dd2`);
the Cargo JSON SHA-256 is
`2ad01438b71099c046eca97290acfe561e1e83f7eea361ca087f8e41fa81720d`.
The targeted all-features `cargo +1.97.1 clippy --locked --offline -p
sunrise-edge-operator --all-features --test conditional_readiness_sqlite --
-D warnings` finished with actual exit 0. Its terminal receipt is
`operator-clippy-terminal.json` (SHA-256
`440a838b851339c6a27a07bb6661fa439dc251ffed4c18b51979df7c225f03f3`).
`cargo +1.97.1 fmt --all --check` and `git diff --check` passed.

## Runtime qualification pending

The unchanged selector completed on `17946e42` in the ordinary local required
gate after all seven epochs and e8, with actual exit 0, raw EOF, wait, and
process-group release. That gate does not set
`SUNRISE_SUCCESSOR_MULTIUID_FIXTURE`, so `protected::enabled()` returned
false and the new wrong-key assertion did not run. The expected
`successor_protected_wrong_key_refused=passed` marker is absent from its raw
output. This ordinary result is not the protected branch's verdict.

Run the same original selector in a bounded root-inside-container real-UID
fixture on the final exact source, preserving the full seven epochs, e8,
1832-byte candidates, raw exit, both stream EOFs, wait/reap, and owned
container/PID/cgroup release. Require the wrong-key marker and existing
distinct-UID markers there. The preceding `049dcd59` fixture took about
3 hours 43 minutes and remains historical evidence only. Hosted CI, the
final source's complete required gate, and the applicable release profile
remain separate qualification. Until the protected fixture actually succeeds,
the new wrong-key control and M2-N2 remain open.
