# M2-N1 protected readiness worker validation (2026-11-03)

The code commit `da03f57421fc2e16bf1f38348e35311b282edb06` connects the existing conditional-readiness signer and retained-vote owner to a fixed `vote-worker` / `vote-frontend` Unix-socket exchange. The worker owns the disposable signer key, SQLite state and blob stores. The frontend recomputes the public readiness subject, verifies the returned validator and vote, and publishes the immutable output. The existing `vote-sqlite` path remains available. The socket protocol accepts only the readiness request and authenticates the peer UID. This is the local-OS, separate-process/UID profile selected in DR-0284.

## Actual validation

- `cargo fmt --all -- --check`, `git diff --check`, and Node 24.19.0 `--check` passed at the code commit.
- The existing ignored `compiled_conditional_readiness_real_retention_restart_and_distinct_certificate` owner passed on the host: 1 passed, 0 failed, 21 filtered, 36.20 seconds. [Raw log](raw/ordinary-owner-da03f574.log).
- The same existing owner passed inside the opt-in bounded Docker fixture with actual process UIDs 10001 (worker) and 10002 (frontend): 1 passed, 0 failed, 21 filtered, 31.13 seconds. The controller admitted the clean exact code commit and Cargo JSON artifacts, pinned the local image and ELF closures, used no network, and recorded `code=0`, `signal=null`, `abortReason=null`, `cleanup=already-removed`. [Receipt](raw/da03f574.json), [stdout](raw/da03f574.stdout), [stderr](raw/da03f574.stderr). The controller limits the run to 900 seconds, 6144 MiB memory, 4096 MiB tmpfs and 128 PIDs.
- The retained-vote, wrong-key, wrong-UID, lost-response, restart and distinct-certificate assertions are in the original test owner, not in a second copy of the acceptance flow. The Docker fixture is opt-in; ordinary required CI does not acquire host users or production keys.
- A later build of the native-http unit target exposed two test-only Tokio trait imports omitted by the shared IPC extraction. After restoring those imports, `cargo test --locked --offline -p native-http --lib` passed all 245 tests. [Raw log](raw/native-http-import-fix.log). This later source commit has not yet received the complete required or hosted CI gate.

## Preserved failed attempts

The raw receipt, stdout and stderr for each failed attempt remain in `raw/` under its code-commit prefix. `21c79e6e` exposed a fixture chmod/chown order error; `e77a2010` and `52f94a56` exposed frontend publication permission errors; `364e777e` localized the error to the existing archive staging directory; `b9eedecd` reached the lost-response probe but its test marker was captured by the harness; `774544bc` reached the original successor acceptance but its existing signal helper was absent from the minimal container. The subsequent code and fixture fixes are committed separately. None of these partial/failed runs is counted as success.

This evidence qualifies this readiness consumer only. Full required, hosted CI, other protected M2 families, independent review and parent M2 acceptance remain separate. The original TODO checkbox count is unchanged.
