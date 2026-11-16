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
