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

## Earlier ordinary gate

The unchanged selector completed on `17946e42` in the ordinary local required
gate after all seven epochs and e8, with actual exit 0, raw EOF, wait, and
process-group release. That gate does not set
`SUNRISE_SUCCESSOR_MULTIUID_FIXTURE`, so `protected::enabled()` returned
false and the new wrong-key assertion did not run. The expected
`successor_protected_wrong_key_refused=passed` marker is absent from its raw
output. This ordinary result is not the protected branch's verdict.

The preceding `049dcd59` fixture took about 3 hours 43 minutes and remains
historical evidence only. The final-source result is below.

## Final source and protected result

PR #348 head `d3c57cbc893b52d32f64251afddf20d9b51071f1`, tree
`e182027210dfa41ebd05598b8fe85a76fa581611`, passed literal npm ci and
the complete required gate with actual exit 0, stream EOF, wait/reap and
source integrity. All seven hosted CI jobs and aggregate `check` passed in
run 42202141140. The ordinary gate and CI do not enable the protected
real-UID branch.

The separate final-head attempt c ran the original ignored selector inside
a bounded, root-inside-container fixture with worker UID 10001 and frontend
UID 10002. It passed once in 13,408.18 seconds with two actual wrong-key
refusals, two distinct-UID starts, recurring epoch ends 1 through 7, epoch-8
terminal unlock, two 1832-byte epoch-8 candidates and acknowledged submissions.
The attached Docker test and outer controller exited 0, both pairs of raw
streams reached EOF and both processes were waited/reaped. The known PIDs,
cgroup and container were released; source, staged executables and libraries
remained exact. An independent terminal audit repeated these checks. The
exact unchanged test asserts eight links; no separate raw 35-role counter was
present, so that count is not claimed as an independent raw observation.
The two earlier attempts failed during executable staging and are retained
separately, not counted as product success. See external terminal receipts
`pr348-n2-protected-final-run-20261106c/terminal.json` and
`pr348-n2-outer-owner-run-20261106c/owner-terminal.json` under the validation
directory. Parent M2, the final RELEASE profile and independent security
review remain open.
