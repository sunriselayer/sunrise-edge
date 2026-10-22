# Task-local validation runtimes

The previous full-required attempt completed both product commands, then failed
its immutable-tool postcheck after Homebrew removed its pinned Deno/Python
files. Preserve that failed attempt; a new profile must pass its own before/after
checks.

`prepare-deno.py` downloads the exact
[Deno 2.9.4 release](https://github.com/denoland/deno/releases/tag/v2.9.4)
used by the repository and CI into a new task directory. It verifies the archive
SHA-256, one bounded binary, and the actual version. Limits are 48 MiB network,
256 MiB binary, 300 seconds, and a 5 GiB free-space reserve. The official binary
uses system libraries rather than Homebrew libraries.

`bind-profile.py` only prepares controls. It verifies the preserved control
hashes, binds the private Deno and existing system Python 3.14.8 explicitly,
and records four one-to-one tool-role replacements. All other strict identities,
Node 24.19.0, private Cloudflare closure, archives, source pins, selectors,
resource bounds, and the two literal commands are retained:

```sh
npm ci --prefix adapters/cloudflare-workers
./scripts/check-all.sh
```

After reviewing the generated controls, launch the separate finite owner and
wait for physical command/process closure before reading its bodies. Require
all before/after identities to match. Keep generated runtimes, caches, raw logs,
and machine-specific controls outside Git; these preparation sources are
versioned here. Current results and completion status belong in `TODO.md`.
