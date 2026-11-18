# M3 SQLite WAL partial persistent write (2026-11-17)

This is one selected local virtual-device source-COMMIT fault, distinct from
the nine independent-anchor guest boundaries in the [earlier record](../2026-11-16-m3-anchored-qemu11/README.md).
It tests actual SQLite-owned WAL bytes, a split virtual block write, and a
cold receipt-first oracle against the **original authority image**. It does
not qualify physical media or the M3 parent.

## Exact source and run

- Test-only source `cc599a0492d84ec22d3b1ef83bb834716c07ec0d`, tree
  `89b00480b2a25b2c106e6f691fda540e09cce4b1`; owning test ELF SHA-256
  `bc5bce0b8d3cfaf9435e5629ff0401b3038f15c6adb8a514fe8c12cdf73f42ac`.
  The source adds an opt-in WAL warmup/geometry hook to the existing ignored
  anchored guest test. Ordinary tests and product behavior do not enter it.
- [Controller](controller.py) SHA-256
  `449ef14ca574b9c70caab77b6fa7b4e033472c8d9a8621b18d4873a70ff9a9ba`.
  The exact command, inputs and hashes are in [evidence.json](evidence.json)
  (SHA-256 `d222dd6ff3dc366bfb9355a94df93fc6f448b4a9e555cc103815b6f8fb818c29`).
- The bounded `systemd-run` invocation in that manifest returned exit 0 for
  attempt `qga1117f` in 10.12 seconds. `cargo fmt --all -- --check`,
  `cargo test -p runtime-sqlite --lib --no-run`, the focused
  `cargo test -p runtime-sqlite --lib anchored_guest_` (2 passed), and
  `git diff --check` succeeded on that exact test source. The local complete
  profile, nine-case rerun on this source, and hosted CI were not run for the
  diagnostic source.

## Observed bytes and recovery

The warmup made one real WAL frame and completed a `RESTART` checkpoint
(`busy=0, frames=1, checkpointed=1`) while the anchored connection remained
open. Complete source and authority row images and anchor identity still
matched the baseline. At source COMMIT, the live `state.db-wal` was 4,152
bytes with a stable two-block FIEMAP extent at ext4 blocks 15388–15389.
The actual MBR partition start was sector 2048, the logical sector was 512
bytes, and the ext4 block was 4,096 bytes. Thus the first WAL block began at
image offset 64,077,824 and the second at 64,081,920 (sector 125160).

QMP reopened `source-data` through a `blkdebug` node with 4,096-byte alignment
and maximum transfer, targeting the second sector with one write EIO. The
[trace](source-write-fault.trace) shows the 8,192-byte WAL request and the
first 4,096-byte write reaching the original lower `source-file` node; the
second 4,096-byte request did not reach that node. The selected source device
emitted `BLOCK_IO_ERROR`; SQLite reported COMMIT extended error 1034.

Only after the guest was reaped, the controller read the detached original
source image. Its first WAL block changed from SHA-256
`eb277f28262d2df82ac00141c7127f5b8dfa4a360dd24c7fe2da2e91479d6aab`
to `547ac57503f1d6a1a71286c8db4354670a53da25e6db05aa683c1ddaae0fc844`.
All 56 valid bytes of the second WAL block retained their pre-fault SHA-256
`a07726bb16aa80c2f3f02453c82bdc0a5cabce147536152c37af8aebadf1c198`.
The cold boot used a rehashed copy of those source bytes and the **same
original authority**, never a forensic authority copy. Receipt-first recovery
returned `initial=none`, checked all twelve structured and two blob tables,
both authority tables, four collections and two positive bodies, and retained
Pending/old-source fail-stop on repeated attempts.

The retained [terminal](terminal.json), [raw guest log](raw.log) and trace have
SHA-256 `36fe04281b292081f5f16d11a0c06ee40a16c50a4dd870216936f825d5c06aef`,
`3facf5cd20d6360b10fd9e1791863fd063ba0f5aced47707b740eac650999c34`,
and `d54094b8d43f5a9252d8267b6e9739de9e6737f834329e3991f4a902ccbc98d2`.
The owner reaped every child, removed both QMP sockets and its cgroup, held
peak memory to 352,800,768 bytes with zero swap/OOM, and left no host mount.
Failed setup diagnostics `qga1117a`–`d` and the no-fault geometry diagnostic
`qga1117e` remain separately identified in the manifest; none counts as this
fault result.

This result closes the two scoped M3 partial-WAL child checks only. Physical
host/power/media/fsync and separate-host writer failover remain open.
