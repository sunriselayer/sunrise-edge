# M3 independent-anchor guest serial diagnostic (2026-11-16)

This is a boot diagnosis, not a passed M3 fault boundary. The selected
`native-sqlite-qemu-anchored-v1` profile in DR-0266 used Fedora Linux
7.2.9 and QEMU 10.2.2. Its retained `qga1017a` attempt stopped in the first
`ack` boot: the guest kernel reported init exit 76 at about 0.87 seconds,
and the controller recorded an unexpected QMP EOF. No product fault control
passed in that attempt.

The old controller requested `se-s-` plus 16 hexadecimal nonce characters,
which is 21 bytes. Its init and the Rust guest test both require that exact
string; the authority disk uses the equally long `se-a-` prefix. The local
Linux `virtio_blk.h` defines `VIRTIO_BLK_ID_BYTES` as 20. A bounded
diagnostic boot with the retained 7.2.9 guest kernel and current QEMU 11.1.3
observed this actual sysfs value:

```text
SERIAL-DIAG value=<se-s-0123456789abcde> len=20 expected=<se-s-0123456789abcdef> expected_len=21
```

The diagnostic replaced `/init` in a copy of the retained initramfs with a
script that mounted proc/sys/devtmpfs, read `/sys/block/vda/serial`, printed
the line above and exited. It attached one fresh 1 MiB read-only image,
one vCPU, 512 MiB memory and no network. The QEMU invocation had a 15-second
outer timeout and exited 0 after the diagnostic init; its expected kernel
panic followed the init exit. No product test or writable M3 disk was attached.
The command passed to Python `subprocess.run(timeout=15)` was:

```sh
qemu-system-x86_64 -no-user-config -nodefaults -machine q35,accel=kvm \
  -smp 1 -m 512 -nic none -display none -no-reboot -serial stdio \
  -monitor none \
  -kernel /home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013/qga1017a/kernel \
  -initrd /home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013/m3-serial-diag-1116-3dsxo087/initrd.gz \
  -append 'console=ttyS0 rdinit=/init panic=1 loglevel=4' \
  -drive file=/home/yu/src/github.com/sunriselayer/sunrise-edge-validation-1013/m3-serial-diag-1116-3dsxo087/disk.raw,if=none,format=raw,id=src,readonly=on \
  -device virtio-blk-pci,drive=src,serial=se-s-0123456789abcdef
```

The [raw output](qemu.raw) has SHA-256
`7d9dbc6ecc4ddbce0fc162b7bbb38576f8c0a5844cdc6ec09b8e31bc803c727f`.
The original is also retained outside the repository under
`sunrise-edge-validation-1013/m3-serial-diag-1116-3dsxo087/qemu.raw`.
The diagnostic initramfs SHA-256 is
`0b3fd2dca9e60a584d5672c8d13eca0338b4f47eeb21bed06a065c751336e9c3`.
Its local `receipt.json` records the inputs, bounds and unrun checks.

This supports a serial-length mismatch in the old harness. The old QEMU
10.2.2 binary and its Fedora host kernel/config pins are no longer present,
so this later diagnostic does not prove the old boot's sole cause or qualify
the selected profile. The nine actual guest fault boundaries, complete cold
oracles and virtual-device partial persistent write remain unrun on a
re-established exact profile.
The follow-up guest test source now expects distinct 18-byte `s-`/`a-` plus
16-hex serials. The external VM controller was then still unchanged; the follow-up below
updates its task-owned copy. The selected-profile run remains unexecuted.
The same bounded diagnostic was repeated with `serial=s-0123456789abcdef`
and an initramfs that expected that value. It exited 0 and observed exact
18-byte equality; [the second raw output](qemu-short.raw) has SHA-256
`860fe1232a7f3f20d58e55f256a1840d647270f386a41506ee57839660fe1beb`.
Its diagnostic initramfs SHA-256 is
`1788a8127a77a53156b71061e3e64da687cbb978f5386a0e2677bfd981a67d48`.
This checks virtio serial transport only, without an M3 product control.

## Two-device follow-up (2026-11-16)

A task-owned copy of the external controller at
`sunrise-edge-validation-1013/m3-qemu-anchored-owner2-1116-shortserial.py`
changes only the guest `/init` comparison and QEMU `virtio-blk-pci` serial
prefixes from `se-s-`/`se-a-` to `s-`/`a-`. Python compilation passed. The
copy has SHA-256
`60f5fdd8c6bd8fd4b6fa0069942e25eb742be44a9fb38b680ba237bf025e8da2`.
The original controller remains byte-identical (SHA-256
`2eab2934324380bf2204cc179f3435672dba6ebe89f8d92be7930f77ec05033d`).

A bounded boot attached two distinct fresh 1 MiB read-only disks, one vCPU,
512 MiB RAM, no network, the retained Fedora 7.2.9 guest kernel and current
QEMU 11.1.3. Its diagnostic `/init` mounted proc/sys/devtmpfs, read both
`/sys/block/vd{a,b}/serial` values, compared them with the new 18-byte strings
and exited 0. The actual output says:

```text
SERIAL-TWO source=<s-0123456789abcdef> source_len=18 authority=<a-0123456789abcdef> authority_len=18
SERIAL-TWO-PASS
```

QEMU exited 0 in 2.185 seconds without timeout; the expected kernel panic
followed init exit 0. [Raw output](qemu-two.raw) is 1,990 bytes with SHA-256
`dbbd764231b690315c49c1f8bca6bbea15f1f97084eec4b881c95e550dc35eef`.
The private retained `m3-two-serial-diag-1116-94r26bax/receipt.json`
records the exact QEMU argv, kernel/initrd hashes and result; its generated
initrd and `/init` remain available. Both diagnostic disk images and the
extracted duplicate initrd tree were removed after QEMU exited. No QEMU
process remained, and there were no writable product disks or M3 test calls.

This removes the identified serial transport mismatch from the controller
source and checks both device IDs on the current virtual host. It does not
qualify the selected QEMU 10.2.2/Fedora host profile or any of the nine
actual product fault boundaries.
