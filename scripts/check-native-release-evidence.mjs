#!/usr/bin/env node
// DR-0213: trusted-host, same-host evidence; never release or signing authority.
import { spawn, spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  constants as F, openSync, closeSync, readSync, writeSync, fstatSync, lstatSync,
  readFileSync, readlinkSync, readdirSync, realpathSync, mkdirSync, renameSync,
  unlinkSync, rmdirSync, fchmodSync, fsyncSync, statSync, statfsSync, createReadStream,
} from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createInflateRaw } from "node:zlib";

export const NODE_VERSION = "v22.20.0";
export const RUST_VERSION = "1.97.1";
export const TARGET = "x86_64-unknown-linux-gnu";
export const NAMES = Object.freeze([
  "sqlite_genesis", "standard_asset_genesis", "genesis_inspect", "sqlite_source_host",
  "business_cut", "business_import", "conditional_readiness", "ordered_seal",
  "successor_activation", "successor_host", "sunrise-edge-cli",
]);
const PACKAGES = ["sunrise-edge-operator", "sunrise-edge-cli"];
const SCRIPT = fileURLToPath(import.meta.url);
const GiB = 1024 ** 3;
export const LIMITS = Object.freeze({
  compressed: 128 * 1024 ** 2, expanded: 512 * 1024 ** 2, file: 256 * 1024 ** 2,
  entries: 50_000, path: 4096, closureCompressed: GiB, closureExpanded: 4 * GiB,
  closureEntries: 200_000, line: 1024 ** 2, log: 128 * 1024 ** 2,
  admissionDisk: 10 * GiB, abortDisk: 5 * GiB, admissionMemory: 4 * GiB,
  buildMs: 2 * 60 * 60 * 1000,
});
const utf8 = new TextDecoder("utf-8", { fatal: true });
function requireThat(ok, message) { if (!ok) throw new Error(message); }
function digest(bytes) { return createHash("sha256").update(bytes).digest("hex"); }
function jsonDigest(value) { return digest(Buffer.from(JSON.stringify(value))); }
function within(root, candidate) { return candidate.startsWith(root + path.sep); }
function overlaps(a, b) { return a === b || within(a, b) || within(b, a); }
function exists(p) { try { lstatSync(p); return true; } catch (e) { if (e.code === "ENOENT") return false; throw e; } }
function identity(s) { return { dev: s.dev, ino: s.ino, uid: s.uid, mode: s.mode & 0o7777 }; }
function stamp(s) { return { ...identity(s), size: s.size, mtime: s.mtimeMs, ctime: s.ctimeMs, nlink: s.nlink }; }
function same(a, b) { return JSON.stringify(a) === JSON.stringify(b); }
function absolute(p) {
  requireThat(typeof p === "string" && path.isAbsolute(p) && path.normalize(p) === p &&
    !/[\0\r\n\\]/.test(p), "Noncanonical absolute path");
  return p;
}
export function checkAncestors(p) {
  absolute(p);
  const records = [];
  for (let current = path.parse(p).root; ;) {
    const s = lstatSync(current);
    requireThat(s.isDirectory() && !s.isSymbolicLink(), `Unsafe path ancestor: ${current}`);
    records.push({ path: current, ...identity(s) });
    if (current === p) return records;
    const next = path.relative(current, p).split(path.sep)[0];
    current = path.join(current, next);
  }
}
function assertAncestors(records) {
  for (const r of records) {
    const s = lstatSync(r.path);
    requireThat(s.isDirectory() && !s.isSymbolicLink() && same(identity(s),
      { dev: r.dev, ino: r.ino, uid: r.uid, mode: r.mode }), `Ancestor drift: ${r.path}`);
  }
}
export function heldFile(p, { executable = false, singleLink = false } = {}) {
  const ancestors = checkAncestors(path.dirname(p));
  const before = lstatSync(p);
  requireThat(before.isFile() && !before.isSymbolicLink(), `Not a regular file: ${p}`);
  if (executable) requireThat((before.mode & 0o111) !== 0 && (before.mode & 0o7000) === 0,
    `Not an ordinary executable: ${p}`);
  if (singleLink) requireThat(before.nlink === 1, `Aliased saved file: ${p}`);
  const fd = openSync(p, F.O_RDONLY | F.O_NOFOLLOW | F.O_NONBLOCK);
  const initial = fstatSync(fd);
  try {
    requireThat(same(stamp(initial), stamp(before)), `Changed file attachment: ${p}`);
    return {
      fd, initial, path: p,
      check() {
        assertAncestors(ancestors);
        requireThat(same(stamp(initial), stamp(fstatSync(fd))) &&
          same(stamp(initial), stamp(lstatSync(p))), `File drift: ${p}`);
      },
      close() { closeSync(fd); },
    };
  } catch (e) { closeSync(fd); throw e; }
}
export function hashFile(p, options = {}) {
  const h = heldFile(p, options);
  try {
    const sha = createHash("sha256");
    const blob = createHash("sha1").update(`blob ${h.initial.size}\0`);
    const buffer = Buffer.alloc(64 * 1024);
    for (let offset = 0; offset < h.initial.size;) {
      const n = readSync(h.fd, buffer, 0, Math.min(buffer.length, h.initial.size - offset), offset);
      requireThat(n > 0, `Premature file EOF: ${p}`);
      sha.update(buffer.subarray(0, n)); blob.update(buffer.subarray(0, n)); offset += n;
    }
    h.check();
    return { path: p, ...stamp(h.initial), sha256: sha.digest("hex"), blob: blob.digest("hex") };
  } finally { h.close(); }
}
function smallFile(p, max) {
  const h = heldFile(p);
  try {
    requireThat(h.initial.size <= max, `File byte budget exceeded: ${p}`);
    const b = Buffer.alloc(h.initial.size);
    let n = 0;
    while (n < b.length) { const got = readSync(h.fd, b, n, b.length - n, n); requireThat(got > 0, "Short read"); n += got; }
    h.check(); return b;
  } finally { h.close(); }
}
function writeAll(fd, bytes) {
  for (let offset = 0; offset < bytes.length;) {
    const n = writeSync(fd, bytes, offset, bytes.length - offset);
    requireThat(n > 0, "Short write"); offset += n;
  }
}
function syncDir(p, sync = fsyncSync) {
  const fd = openSync(p, F.O_RDONLY | F.O_DIRECTORY | F.O_NOFOLLOW);
  try { sync(fd, "directory"); } finally { closeSync(fd); }
}
function exclusiveFile(p, bytes, sync = fsyncSync, mode = 0o600) {
  checkAncestors(path.dirname(p));
  const fd = openSync(p, F.O_WRONLY | F.O_CREAT | F.O_EXCL | F.O_NOFOLLOW, mode);
  try { writeAll(fd, bytes); sync(fd, "file"); return identity(fstatSync(fd)); }
  finally { closeSync(fd); }
}

export function validateCallerEnv(env) {
  for (const key of Object.keys(env)) {
    const forbidden = /^(CARGO_(?!HOME$)|RUST(?:C|DOC|FLAGS)|RUSTUP_TOOLCHAIN|CC($|_)|CCACHE|SCCACHE|AR($|_)|CFLAGS|ARFLAGS|CPPFLAGS|CXX|LDFLAGS|LD($|_)|DYLD_|GIT_|NODE_OPTIONS$|NODE_PATH$|GCC_EXEC_PREFIX$|COMPILER_PATH$|LIBRARY_PATH$|CPATH$|C_INCLUDE_PATH$|CPLUS_INCLUDE_PATH$|PKG_CONFIG|VCPKG|SOURCE_DATE_EPOCH$|TMPDIR$|TMP$|TEMP$)/.test(key);
    requireThat(!forbidden, `Forbidden caller variable: ${key}`); // Never expose its value.
  }
}
export function parseCli(argv) {
  const keys = ["source", "expected-sha", "cargo-home", "output-dir", "node", "git", "cargo", "rustc", "rustdoc", "cc", "ar", "ld"];
  const args = {};
  for (let i = 0; i < argv.length; i += 2) {
    const flag = argv[i];
    requireThat(flag.startsWith("--") && keys.includes(flag.slice(2)), "Unknown CLI option");
    const key = flag.slice(2);
    requireThat(!(key in args), `Duplicate CLI option: ${key}`);
    requireThat(typeof argv[i + 1] === "string" && !argv[i + 1].startsWith("--"), `Missing CLI value: ${key}`);
    args[key] = argv[i + 1];
  }
  for (const key of keys) requireThat(key in args, `Missing CLI option: ${key}`);
  requireThat(/^[0-9a-f]{40}$/.test(args["expected-sha"]), "Expected SHA must be 40 lowercase hexadecimal characters");
  for (const key of keys.filter(k => k !== "expected-sha")) absolute(args[key]);
  return args;
}
function baseEnv(args) {
  const dirs = [...new Set(["node", "git", "cargo", "rustc", "rustdoc", "cc", "ar", "ld"]
    .map(k => path.dirname(realpathSync(args[k]))).concat(["/usr/bin", "/bin"]))];
  return { PATH: dirs.join(":"), CARGO_HOME: args["cargo-home"], RUSTC: args.rustc,
    RUSTDOC: args.rustdoc, CARGO_NET_OFFLINE: "true", CARGO_INCREMENTAL: "0",
    CC: args.cc, AR: args.ar, LC_ALL: "C", LANG: "C", TZ: "UTC" };
}
function execute(tool, argv, cwd, env) {
  const r = spawnSync(tool, argv, { cwd, env, encoding: "buffer", timeout: 60_000,
    maxBuffer: 32 * 1024 ** 2, windowsHide: true });
  requireThat(!r.error && r.status === 0 && r.signal === null,
    `Read-only probe failed: ${path.basename(tool)} ${argv[0]}`);
  return r.stdout;
}
function probe(ctx, tool, argv, cwd = ctx.args.source) {
  return ctx.execute(tool, argv, cwd, ctx.env);
}
function textProbe(ctx, tool, argv, cwd) { return utf8.decode(probe(ctx, tool, argv, cwd)).trim(); }

export function checkConfig(args, callerEnv) {
  const dirs = new Set();
  for (let d = args.source; ; d = path.dirname(d)) { dirs.add(d); if (d === path.dirname(d)) break; }
  const homes = [args["cargo-home"]];
  if (callerEnv.CARGO_HOME) homes.push(absolute(callerEnv.CARGO_HOME));
  // Only look for config filenames, never credentials or an environment dump.
  if (callerEnv.HOME) homes.push(path.join(absolute(callerEnv.HOME), ".cargo"));
  for (const d of dirs) for (const name of ["config", "config.toml"]) {
    const cargoDir = path.join(d, ".cargo");
    if (exists(cargoDir)) checkAncestors(cargoDir);
    requireThat(!exists(path.join(cargoDir, name)), `Undeclared Cargo config: ${path.join(cargoDir, name)}`);
  }
  for (const home of new Set(homes)) {
    if (exists(home)) checkAncestors(home);
    for (const name of ["config", "config.toml"]) requireThat(!exists(path.join(home, name)), `Undeclared Cargo config: ${path.join(home, name)}`);
    for (let d = home; ; d = path.dirname(d)) {
      for (const name of ["config", "config.toml"]) {
        const cargoDir = path.join(d, ".cargo");
        if (exists(cargoDir)) checkAncestors(cargoDir);
        requireThat(!exists(path.join(cargoDir, name)), `Undeclared Cargo config: ${path.join(cargoDir, name)}`);
      }
      if (d === path.dirname(d)) break;
    }
  }
  const ancestorPaths = new Set([...dirs, ...homes.filter(exists)]);
  return { policy: "no discovered configuration; only closed command-line configuration", checked: [...dirs],
    homes: [...new Set(homes)], ancestors: [...ancestorPaths].sort().map(p => checkAncestors(p)) };
}
function toolRecord(p) {
  absolute(p);
  const resolved = realpathSync(p);
  const observed = hashFile(resolved, { executable: true });
  const alias = lstatSync(p);
  return { supplied: p, resolved, alias: { ...identity(alias), link: alias.isSymbolicLink() ? readlinkSync(p) : null }, ...observed };
}
export function verifyTools(ctx) {
  const tools = {};
  for (const name of ["node", "git", "cargo", "rustc", "rustdoc", "cc", "ar", "ld"]) tools[name] = toolRecord(ctx.args[name]);
  requireThat(ctx.fixture || (process.version === NODE_VERSION && realpathSync(process.execPath) === tools.node.resolved), "Runner Node executable/version is not the pinned Node");
  if (!ctx.fixture) {
    const image = statSync("/proc/self/exe");
    requireThat(image.dev === tools.node.dev && image.ino === tools.node.ino, "Running Node image differs from recorded executable attachment");
  }
  for (const name of ["cargo", "rustc", "rustdoc", "cc"]) requireThat(!/rustup|ccache|sccache/.test(path.basename(tools[name].resolved)), "Toolchain/compiler/cache wrappers are forbidden");
  tools.node.version = textProbe(ctx, ctx.args.node, ["--version"]);
  requireThat(tools.node.version === NODE_VERSION, "Node version must be 22.20.0");
  tools.git.version = textProbe(ctx, ctx.args.git, ["--version"]);
  tools.cargo.version = textProbe(ctx, ctx.args.cargo, ["-vV"]);
  tools.rustc.version = textProbe(ctx, ctx.args.rustc, ["-vV"]);
  tools.rustdoc.version = textProbe(ctx, ctx.args.rustdoc, ["-vV"]);
  for (const name of ["cargo", "rustc", "rustdoc"]) {
    requireThat(new RegExp(`^${name} ${RUST_VERSION.replaceAll(".", "\\.")}(?: |$)`, "m").test(tools[name].version), `${name} version pin mismatch`);
    requireThat(tools[name].version.split("\n").includes(`host: ${TARGET}`), `${name} host pin mismatch`);
  }
  tools.rustc.sysroot = textProbe(ctx, ctx.args.rustc, ["--print", "sysroot"]);
  checkAncestors(absolute(tools.rustc.sysroot));
  tools.rustc.cfg = textProbe(ctx, ctx.args.rustc, ["--print", "cfg", "--target", TARGET]);
  for (const cfg of ['target_arch="x86_64"', 'target_os="linux"', 'target_env="gnu"', 'target_pointer_width="64"']) {
    requireThat(tools.rustc.cfg.split("\n").includes(cfg), "Rust target ABI mismatch");
  }
  tools.cc.version = textProbe(ctx, ctx.args.cc, ["--version"]);
  tools.cc.machine = textProbe(ctx, ctx.args.cc, ["-dumpmachine"]);
  // GCC vendor components may omit a literal "gnu" (e.g. x86_64-redhat-linux).
  requireThat(/^x86_64-[A-Za-z0-9_.-]*linux(?:-gnu)?$/.test(tools.cc.machine) && !/musl|android|mingw/.test(tools.cc.machine), "Native CC architecture/ABI mismatch");
  tools.cc.macros = textProbe(ctx, ctx.args.cc, ["-dM", "-E", "-x", "c", "/dev/null"]);
  for (const macro of ["__x86_64__ 1", "__linux__ 1", "__LP64__ 1"]) requireThat(tools.cc.macros.includes(`#define ${macro}`), "Native CC ABI macro mismatch");
  requireThat(!tools.cc.macros.includes("__ILP32__"), "Native CC ILP32 mismatch");
  const printedLd = textProbe(ctx, ctx.args.cc, ["-print-prog-name=ld"]);
  const candidates = path.isAbsolute(printedLd) ? [printedLd] : ctx.env.PATH.split(":").map(d => path.join(d, printedLd));
  const found = candidates.find(p => exists(p));
  requireThat(found && realpathSync(found) === tools.ld.resolved, "CC driver does not resolve the supplied linker");
  tools.cc.linker = { printed: printedLd, resolved: realpathSync(found) };
  for (const name of ["ar", "ld"]) tools[name].version = textProbe(ctx, ctx.args[name], ["--version"]);
  requireThat(/^GNU ld(?: |\()/m.test(tools.ld.version) && /^GNU ar(?: |\()/m.test(tools.ar.version), "First evidence profile requires GNU linker/AR");
  const hostCc = ctx.env.PATH.split(":").map(d => path.join(d, "cc")).find(exists);
  requireThat(hostCc && realpathSync(hostCc) === tools.cc.resolved, "Host PATH cc differs from supplied checked CC");
  // Cargo --target isolates target flags from host build scripts/proc macros.
  // Pin only the two relevant default host-linker files, not the whole sysroot.
  const hostBin = path.join(tools.rustc.sysroot, "lib", "rustlib", TARGET, "bin");
  tools.hostLldWrapper = toolRecord(path.join(hostBin, "gcc-ld", "ld.lld"));
  tools.hostLld = toolRecord(path.join(hostBin, "rust-lld"));
  tools.hostLldWrapper.version = textProbe(ctx, tools.hostLldWrapper.supplied, ["--version"]);
  tools.hostLld.version = textProbe(ctx, tools.hostLld.supplied, ["-flavor", "gnu", "--version"]);
  const llvm = /^LLVM version: (\S+)$/m.exec(tools.rustc.version)?.[1];
  requireThat(llvm && tools.hostLld.version.startsWith(`LLD ${llvm} `) &&
    tools.hostLldWrapper.version === tools.hostLld.version, "Bundled host LLD identity/version mismatch");
  tools.linkerRoles = {
    target: { driver: tools.cc.resolved, linker: tools.ld.resolved,
      rustFlags: ["-C", "linker-features=-lld", "-C", "link-self-contained=-linker"] },
    host: { driver: realpathSync(hostCc), wrapper: tools.hostLldWrapper.resolved,
      implementation: tools.hostLld.resolved, features: "+lld/+linker pinned rustc defaults",
      limit: "Cargo host Rust units do not receive target Rust prefix maps" },
  };
  return tools;
}
function git(ctx, argv) {
  const env = { ...ctx.env, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_SYSTEM: "/dev/null", GIT_OPTIONAL_LOCKS: "0" };
  return ctx.execute(ctx.args.git, ["-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", ...argv], ctx.args.source, env);
}
export function verifySource(ctx) {
  checkAncestors(ctx.args.source);
  const output = a => utf8.decode(git(ctx, a)).trim();
  requireThat(output(["rev-parse", "--show-toplevel"]) === ctx.args.source, "Source is not its repository root");
  const head = output(["rev-parse", "HEAD"]);
  requireThat(head === ctx.args["expected-sha"], "Source HEAD mismatch");
  requireThat(output(["rev-parse", "--show-object-format"]) === "sha1", "Unsupported Git object format");
  requireThat(git(ctx, ["status", "--porcelain=v1", "-z", "--untracked-files=normal"]).length === 0, "Dirty source/index");
  // --directory collapses ignored/untracked directories; no traversal of user target contents.
  requireThat(git(ctx, ["ls-files", "--others", "--directory", "--no-empty-directory", "-z"]).length === 0, "Untracked source, including ignored paths");
  const tree = output(["rev-parse", `${head}^{tree}`]);
  const epoch = output(["show", "-s", "--format=%ct", head]);
  requireThat(/^[0-9a-f]{40}$/.test(tree) && /^\d+$/.test(epoch), "Invalid source identity");
  const rows = utf8.decode(git(ctx, ["ls-tree", "-r", "-z", "--full-tree", head])).split("\0");
  requireThat(rows.pop() === "", "Incomplete Git tree records");
  const files = [];
  const seen = new Set();
  for (const row of rows) {
    const match = /^(100644|100755) blob ([0-9a-f]{40})\t(.+)$/.exec(row);
    requireThat(match, "Unsupported Git tree entry");
    const [, mode, oid, name] = match;
    canonicalEntry(name, null, false);
    requireThat(!seen.has(name), "Duplicate tracked path"); seen.add(name);
    const record = hashFile(path.join(ctx.args.source, name));
    requireThat(record.blob === oid && Boolean(record.mode & 0o111) === (mode === "100755"), `Tracked bytes/mode differ from commit: ${name}`);
    files.push({ name, gitMode: mode, oid, ...record });
  }
  const required = ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "scripts/check-native-release-evidence.mjs"];
  for (const name of required) requireThat(seen.has(name), `Missing committed input: ${name}`);
  requireThat(ctx.fixture || realpathSync(SCRIPT) === path.join(ctx.args.source, required[3]), "Runner is not attached to the committed source");
  const toolchain = utf8.decode(smallFile(path.join(ctx.args.source, "rust-toolchain.toml"), 64 * 1024));
  requireThat(/^channel\s*=\s*"1\.97\.1"\s*$/m.test(toolchain), "Committed toolchain pin mismatch");
  const gitDir = output(["rev-parse", "--absolute-git-dir"]);
  const commonDir = output(["rev-parse", "--path-format=absolute", "--git-common-dir"]);
  return { head, tree, epoch, ancestors: checkAncestors(ctx.args.source), gitDir: absolute(gitDir), commonDir: absolute(commonDir), files,
    script: files.find(f => f.name === required[3]).sha256 };
}

function canonicalEntry(name, root, directory) {
  requireThat(Buffer.byteLength(name) <= LIMITS.path && name !== "" && !/[\\\0]/.test(name) && !path.isAbsolute(name), "Illegal archive/source path");
  const effective = directory && name.endsWith("/") ? name.slice(0, -1) : name;
  const parts = effective.split("/");
  requireThat(parts.every(p => p && p !== "." && p !== ".."), "Illegal archive/source path component");
  if (root !== null) requireThat(parts[0] === root && (parts.length > 1 || directory), "Archive package root mismatch or regular root");
  return effective;
}
function octal(bytes) {
  const value = bytes.toString("ascii");
  requireThat(!bytes.some(b => b > 127) && /^[ \0]*[0-7]*[ \0]*$/.test(value), "Invalid tar octal field");
  const digits = value.replace(/[ \0]/g, "");
  const n = digits ? Number.parseInt(digits, 8) : 0;
  requireThat(Number.isSafeInteger(n), "Tar integer overflow"); return n;
}
function tarString(bytes) {
  const end = bytes.indexOf(0);
  if (end >= 0) requireThat(bytes.subarray(end).every(b => b === 0), "Noncanonical tar string padding");
  return utf8.decode(end < 0 ? bytes : bytes.subarray(0, end));
}
const CRC_TABLE = Uint32Array.from({ length: 256 }, (_, i) => {
  let c = i; for (let k = 0; k < 8; k++) c = c & 1 ? (0xedb88320 ^ (c >>> 1)) : c >>> 1; return c >>> 0;
});
function crcUpdate(crc, bytes) { for (const b of bytes) crc = CRC_TABLE[(crc ^ b) & 255] ^ (crc >>> 8); return crc >>> 0; }
function gzipHeader(fd, size) {
  let offset = 0; let crc = 0xffffffff;
  const get = count => {
    requireThat(offset + count <= size && offset + count <= 64 * 1024, "Invalid/budgeted gzip header");
    const b = Buffer.alloc(count); requireThat(readSync(fd, b, 0, count, offset) === count, "Short gzip header");
    offset += count; crc = crcUpdate(crc, b); return b;
  };
  const head = get(10);
  requireThat(head[0] === 0x1f && head[1] === 0x8b && head[2] === 8 && (head[3] & 0xe0) === 0, "Unknown gzip framing");
  const flags = head[3];
  if (flags & 4) { const n = get(2).readUInt16LE(); get(n); }
  for (const flag of [8, 16]) if (flags & flag) { while (get(1)[0] !== 0) { /* bounded header */ } }
  if (flags & 2) {
    const expected = (crc ^ 0xffffffff) & 65535;
    requireThat(get(2).readUInt16LE() === expected, "Gzip header CRC mismatch");
  }
  requireThat(offset + 8 < size, "Missing gzip body/trailer"); return offset;
}

// Narrow, streaming crate reader. It matches existing files, never extracts tar data.
class CrateMatcher {
  constructor(root, expanded, limits) {
    this.root = root; this.expanded = expanded; this.limits = limits;
    this.header = Buffer.alloc(512); this.headerUsed = 0; this.entry = null;
    this.zeroBlocks = 0; this.ended = false; this.longName = null;
    this.records = 0; this.bytes = 0; this.files = new Map(); this.dirs = new Map([[root, null]]); this.explicit = new Set();
  }
  addPath(name, type) {
    requireThat(!this.explicit.has(name), "Duplicate archive entry"); this.explicit.add(name);
    const components = name.split("/");
    for (let i = 1; i < components.length; i++) {
      const parent = components.slice(0, i).join("/");
      requireThat(!this.files.has(parent), "Archive file/parent conflict");
      if (!this.dirs.has(parent)) this.dirs.set(parent, null);
      requireThat(this.dirs.size + this.files.size <= this.limits.entries * 2, "Inferred archive inventory budget exceeded");
    }
    requireThat(type !== "file" || !this.dirs.has(name), "Archive file/directory conflict");
    requireThat(type !== "dir" || !this.files.has(name), "Archive file/directory conflict");
    if (type === "dir") this.dirs.set(name, null);
  }
  begin(header) {
    if (header.every(b => b === 0)) {
      this.zeroBlocks++;
      requireThat(!this.longName, "Orphan GNU L metadata");
      if (this.zeroBlocks >= 2) this.ended = true;
      return;
    }
    requireThat(this.zeroBlocks === 0 && !this.ended, "Tar entry after end framing");
    const magic = header.subarray(257, 263).toString("latin1");
    const version = header.subarray(263, 265).toString("latin1");
    const gnu = magic === "ustar " && version === " \0";
    requireThat(gnu || (magic === "ustar\0" && version === "00"), "Unknown tar magic/version");
    let checksum = 0;
    for (let i = 0; i < 512; i++) checksum += i >= 148 && i < 156 ? 32 : header[i];
    requireThat(octal(header.subarray(148, 156)) === checksum, "Tar checksum mismatch");
    for (const [a, b] of [[100, 108], [108, 116], [116, 124], [136, 148]]) octal(header.subarray(a, b));
    let name = tarString(header.subarray(0, 100));
    if (!gnu) { const prefix = tarString(header.subarray(345, 500)); if (prefix) name = prefix + "/" + name; }
    const type = String.fromCharCode(header[156]);
    const size = octal(header.subarray(124, 136));
    requireThat(tarString(header.subarray(157, 257)) === "", "Tar links are forbidden");
    tarString(header.subarray(265, 297)); tarString(header.subarray(297, 329));
    this.records++; this.bytes += size;
    requireThat(this.records <= this.limits.entries && this.bytes <= this.limits.expanded, "Archive entry/expanded byte budget exceeded");
    if (type === "L") {
      requireThat(!this.longName, "Repeated GNU L metadata");
      requireThat(name === "././@LongLink" && size > 1 && size <= 4097, "Invalid GNU L header/payload budget");
      this.entry = { type: "long", size, used: 0, payload: Buffer.alloc(size), padding: (512 - size % 512) % 512 };
      return;
    }
    requireThat(type === "0" || type === "\0" || type === "5", this.longName ? "GNU L incompatible next entry" : "Unsupported tar entry type");
    if (this.longName) { name = this.longName; this.longName = null; }
    const directory = type === "5";
    name = canonicalEntry(name, this.root, directory);
    requireThat(size <= this.limits.file && (!directory || size === 0), "Archive file/directory size budget exceeded");
    this.addPath(name, directory ? "dir" : "file");
    if (directory) { this.entry = null; return; }
    const disk = path.join(this.expanded, ...name.split("/").slice(1));
    const h = heldFile(disk);
    if (h.initial.size !== size) { h.close(); throw new Error("Expanded file size mismatch"); }
    this.entry = { type: "file", name, h, sha: createHash("sha256"), size, used: 0, padding: (512 - size % 512) % 512 };
    if (size === 0 && this.entry.padding === 0) this.finishEntry();
  }
  finishEntry() {
    const e = this.entry;
    this.entry = null; // Abort must never close the same attachment twice after an error.
    if (e.type === "long") {
      requireThat(e.payload.at(-1) === 0 && !e.payload.subarray(0, -1).includes(0), "GNU L must have exactly one terminal NUL");
      this.longName = utf8.decode(e.payload.subarray(0, -1));
      requireThat(Buffer.byteLength(this.longName) <= this.limits.path && this.longName !== "", "GNU L path budget exceeded");
    } else {
      try { e.h.check(); this.files.set(e.name, { name: e.name, ...stamp(e.h.initial), sha256: e.sha.digest("hex") }); }
      finally { e.h.close(); }
    }
  }
  consume(chunk) {
    let at = 0;
    while (at < chunk.length) {
      if (this.entry) {
        const e = this.entry;
        if (e.used < e.size) {
          const n = Math.min(e.size - e.used, chunk.length - at);
          const piece = chunk.subarray(at, at + n);
          if (e.type === "long") piece.copy(e.payload, e.used);
          else {
            const actual = Buffer.alloc(n);
            requireThat(readSync(e.h.fd, actual, 0, n, e.used) === n && actual.equals(piece), "Archive/expanded source bytes mismatch");
            e.sha.update(piece);
          }
          e.used += n; at += n;
        } else if (e.padding > 0) {
          const n = Math.min(e.padding, chunk.length - at);
          requireThat(chunk.subarray(at, at + n).every(b => b === 0), "Nonzero tar payload padding");
          e.padding -= n; at += n;
        }
        if (e.used === e.size && e.padding === 0) this.finishEntry();
      } else {
        const n = Math.min(512 - this.headerUsed, chunk.length - at);
        chunk.copy(this.header, this.headerUsed, at, at + n); this.headerUsed += n; at += n;
        if (this.headerUsed === 512) { this.begin(this.header); this.headerUsed = 0; }
      }
    }
  }
  finish() {
    requireThat(!this.entry && !this.longName && this.headerUsed === 0 && this.ended && this.zeroBlocks >= 2,
      "Incomplete tar framing or orphan GNU L");
    requireThat(this.files.size > 0, "Empty unexplained crate archive");
  }
  abort() { if (this.entry?.h) { this.entry.h.close(); this.entry = null; } }
}
export function verifyCargoOk(root) {
  const p = path.join(root, ".cargo-ok");
  if (!exists(p)) return { present: false };
  const b = smallFile(p, 128);
  if (b.length) {
    let value;
    try { value = JSON.parse(utf8.decode(b)); } catch { throw new Error("Unknown .cargo-ok content"); }
    requireThat(value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).length === 1 && value.v === 1,
      "Unknown .cargo-ok content");
    // JSON with duplicate properties is not closed metadata.
    requireThat(/^\s*\{\s*"v"\s*:\s*1\s*\}\s*$/.test(utf8.decode(b)), "Noncanonical .cargo-ok metadata");
  }
  return { present: true, bytes: b.toString("base64"), ...hashFile(p) };
}
function expandedInventory(root, matcher) {
  const result = [];
  function visit(p, name) {
    const s = lstatSync(p);
    requireThat(!s.isSymbolicLink(), "Expanded source symlink");
    if (s.isDirectory()) {
      requireThat(matcher.dirs.has(name), "Unexplained expanded directory");
      result.push({ name, kind: "dir", ...identity(s) });
      for (const child of readdirSync(p).sort()) {
        if (name === matcher.root && child === ".cargo-ok") continue;
        canonicalEntry(name + "/" + child, matcher.root, false);
        visit(path.join(p, child), name + "/" + child);
      }
    } else {
      requireThat(s.isFile() && matcher.files.has(name), "Unexplained expanded file/type");
      const record = matcher.files.get(name);
      requireThat(same(stamp(s), { dev: record.dev, ino: record.ino, uid: record.uid, mode: record.mode,
        size: record.size, mtime: record.mtime, ctime: record.ctime, nlink: record.nlink }), "Expanded attachment drift");
      result.push({ kind: "file", ...record });
    }
    requireThat(result.length <= LIMITS.entries * 2 + 1, "Expanded inventory budget exceeded");
  }
  visit(root, matcher.root);
  requireThat(result.filter(r => r.kind === "dir").length === matcher.dirs.size &&
    result.filter(r => r.kind === "file").length === matcher.files.size, "Missing expanded inventory entry");
  return result;
}
export async function verifyRegistryPackage(pkg, limits = LIMITS) {
  const root = `${pkg.name}-${pkg.version}`;
  requireThat(/^[A-Za-z0-9_-]+$/.test(pkg.name) && /^[A-Za-z0-9.+-]+$/.test(pkg.version), "Invalid package identity");
  checkAncestors(pkg.expanded);
  const archive = heldFile(pkg.archive);
  const matcher = new CrateMatcher(root, pkg.expanded, limits);
  let input; let inflater;
  try {
    requireThat(archive.initial.size <= limits.compressed, "Archive compressed budget exceeded");
    const initialHash = hashFile(pkg.archive);
    requireThat(/^[a-f0-9]{64}$/.test(pkg.checksum) && initialHash.sha256 === pkg.checksum, "Locked archive checksum mismatch");
    const start = gzipHeader(archive.fd, archive.initial.size);
    const streamFd = openSync(pkg.archive, F.O_RDONLY | F.O_NOFOLLOW);
    if (!same(stamp(fstatSync(streamFd)), stamp(archive.initial))) { closeSync(streamFd); throw new Error("Archive stream attachment drift"); }
    input = createReadStream(pkg.archive, { fd: streamFd, autoClose: true, start,
      end: archive.initial.size - 1, highWaterMark: 64 * 1024 });
    inflater = createInflateRaw({ chunkSize: 64 * 1024 });
    input.on("error", e => inflater.destroy(e)); input.pipe(inflater);
    let expanded = 0; let crc = 0xffffffff;
    for await (const chunk of inflater) {
      expanded += chunk.length;
      // Framing/padding is also bounded, not just entry payloads.
      requireThat(expanded <= limits.expanded + limits.entries * 1024 + 64 * 1024, "Inflated tar framing budget exceeded");
      crc = crcUpdate(crc, chunk); matcher.consume(chunk);
    }
    input.destroy();
    const trailerAt = start + inflater.bytesWritten;
    requireThat(trailerAt + 8 === archive.initial.size, "Gzip trailing junk/concatenated member or missing trailer");
    const trailer = Buffer.alloc(8);
    requireThat(readSync(archive.fd, trailer, 0, 8, trailerAt) === 8 &&
      trailer.readUInt32LE(0) === ((crc ^ 0xffffffff) >>> 0) &&
      trailer.readUInt32LE(4) === (expanded >>> 0), "Gzip CRC/size framing mismatch");
    matcher.finish();
    const marker = verifyCargoOk(pkg.expanded);
    const inventory = expandedInventory(pkg.expanded, matcher);
    archive.check();
    const afterHash = hashFile(pkg.archive);
    requireThat(same(initialHash, afterHash), "Archive changed while verified");
    return { id: pkg.id, name: pkg.name, version: pkg.version, source: pkg.source,
      manifest: pkg.manifest_path, archive: afterHash, inventory, marker,
      compressed: archive.initial.size, expanded: matcher.bytes, entries: matcher.records };
  } finally { input?.destroy(); inflater?.destroy(); matcher.abort(); archive.close(); }
}

export function parseLock(bytes) {
  const text = utf8.decode(bytes);
  requireThat(/^version = 4\s*$/m.test(text), "Unsupported Cargo.lock format");
  const result = [];
  for (const block of text.split(/^\[\[package\]\]\s*$/m).slice(1)) {
    const field = name => {
      const matches = [...block.matchAll(new RegExp(`^${name} = "([^"\\n]+)"\\s*$`, "gm"))];
      requireThat(matches.length <= 1, "Duplicate lock identity field"); return matches[0]?.[1] ?? null;
    };
    const item = { name: field("name"), version: field("version"), source: field("source"), checksum: field("checksum") };
    requireThat(item.name && /^[A-Za-z0-9_-]+$/.test(item.name) && item.version &&
      /^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)*$/.test(item.version), "Malformed locked package");
    requireThat(!item.source || (item.source === "registry+https://github.com/rust-lang/crates.io-index" && /^[0-9a-f]{64}$/.test(item.checksum)), "Unsupported locked package source/checksum");
    requireThat(!result.some(p => p.name === item.name && p.version === item.version && p.source === item.source), "Duplicate locked package");
    result.push(item);
  }
  requireThat(result.length > 0, "Empty lock graph"); return result;
}
function configArg(value) { return JSON.stringify(value); }
function commonCargo(ctx) {
  return ["--locked", "--offline", "--no-default-features", "--target", TARGET,
    "--config", `target.${TARGET}.linker=${configArg(ctx.args.cc)}`,
    "--config", "net.offline=true", "--color", "never"];
}
export function parseTree(text, metadata) {
  const selected = new Map();
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    const m = /^([A-Za-z0-9_-]+) v([^ |]+)(.*?)\|([^|]*?)(?: \(\*\))?$/.exec(line);
    requireThat(m, "Unknown Cargo tree record");
    const [, name, version, qualifier, featureText] = m;
    const candidates = metadata.packages.filter(p => p.name === name && p.version === version);
    requireThat(candidates.length === 1, "Ambiguous Cargo tree package/source");
    const p = candidates[0];
    const expectedQualifiers = p.source ? ["", " (proc-macro)"] : [` (${path.dirname(p.manifest_path)})`, ` (${path.dirname(p.manifest_path)}) (proc-macro)`];
    requireThat(expectedQualifiers.includes(qualifier), "Cargo tree source qualifier mismatch");
    const features = featureText ? featureText.split(",").sort() : [];
    requireThat(new Set(features).size === features.length && features.every(f => Object.hasOwn(p.features, f)), "Unknown Cargo tree feature");
    if (!selected.has(p.id)) selected.set(p.id, { ...p, featureSets: [] });
    const item = selected.get(p.id);
    if (!item.featureSets.some(f => same(f, features))) item.featureSets.push(features);
  }
  requireThat(selected.size > 0, "Empty selected dependency graph");
  for (const p of selected.values()) p.featureSets.sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
  return [...selected.values()].sort((a, b) => a.id.localeCompare(b.id));
}
export function resolveClosure(ctx) {
  // Refuse implicit extraction before Cargo resolves manifests. This scans only locked
  // names in existing crates.io cache buckets; missing unrelated archives are not required.
  const cacheRoot = path.join(ctx.args["cargo-home"], "registry", "cache");
  const locked = parseLock(smallFile(path.join(ctx.args.source, "Cargo.lock"), 8 * 1024 ** 2));
  if (exists(cacheRoot)) {
    checkAncestors(cacheRoot);
    for (const bucket of readdirSync(cacheRoot).filter(n => /^index\.crates\.io-[0-9a-f]+$/.test(n))) {
      checkAncestors(path.join(cacheRoot, bucket));
      for (const pkg of locked.filter(p => p.source)) {
        const archive = path.join(cacheRoot, bucket, `${pkg.name}-${pkg.version}.crate`);
        if (!exists(archive)) continue;
        const manifest = path.join(ctx.args["cargo-home"], "registry", "src", bucket, `${pkg.name}-${pkg.version}`, "Cargo.toml");
        requireThat(exists(manifest), "Locked cached manifest needs forbidden implicit expansion");
        heldFile(manifest).close();
      }
    }
  }
  const args = commonCargo(ctx);
  const metadataArgs = args.filter((_, i) => args[i] !== "--target" && args[i - 1] !== "--target");
  const raw = probe(ctx, ctx.args.cargo, ["metadata", "--format-version", "1", "--filter-platform", TARGET, ...metadataArgs]);
  let metadata;
  try { metadata = JSON.parse(utf8.decode(raw)); } catch { throw new Error("Malformed Cargo metadata"); }
  requireThat(metadata.version === 1 && metadata.workspace_root === ctx.args.source && Array.isArray(metadata.packages) && metadata.resolve,
    "Unexpected Cargo metadata/workspace");
  const tree = textProbe(ctx, ctx.args.cargo, ["tree", ...args, ...PACKAGES.flatMap(p => ["-p", p]),
    "--edges", "normal,build", "--prefix", "none", "--format", "{p}|{f}"]);
  // Cargo, not a home-grown cfg parser, resolves target-specific normal/build edges and features.
  const selected = parseTree(tree, metadata);
  const lock = locked;
  const shipped = [];
  for (const p of selected) {
    const matches = lock.filter(l => l.name === p.name && l.version === p.version && l.source === p.source);
    requireThat(matches.length === 1, "Metadata/locked graph identity mismatch");
    if (p.source) {
      requireThat(p.source === "registry+https://github.com/rust-lang/crates.io-index", "Unsupported selected registry");
      const srcRoot = path.join(ctx.args["cargo-home"], "registry", "src");
      const rel = path.relative(srcRoot, p.manifest_path).split(path.sep);
      requireThat(rel.length === 3 && /^index\.crates\.io-[0-9a-f]+$/.test(rel[0]) && rel[1] === `${p.name}-${p.version}` && rel[2] === "Cargo.toml", "Metadata cache/source binding mismatch");
      p.expanded = path.join(srcRoot, rel[0], rel[1]);
      p.archive = path.join(ctx.args["cargo-home"], "registry", "cache", rel[0], `${rel[1]}.crate`);
      p.checksum = matches[0].checksum;
      checkAncestors(path.dirname(p.archive)); checkAncestors(p.expanded);
    } else {
      requireThat(metadata.workspace_members.includes(p.id) && within(ctx.args.source, p.manifest_path), "External path dependency");
      requireThat(ctx.source.files.some(f => f.path === p.manifest_path), "Uncommitted path dependency manifest");
    }
    for (const target of p.targets) {
      requireThat(within(p.source ? p.expanded : ctx.args.source, target.src_path), "Target source escapes package/source");
      heldFile(target.src_path).close();
    }
  }
  for (const name of NAMES) {
    const packageName = name === "sunrise-edge-cli" ? PACKAGES[1] : PACKAGES[0];
    const packages = selected.filter(p => p.name === packageName && p.source === null);
    requireThat(packages.length === 1, "Missing/ambiguous selected workspace package");
    const pkg = packages[0];
    requireThat((pkg.features.default ?? []).length === 0 && pkg.featureSets.every(f => f.length === 0), "Selected workspace defaults/features not empty");
    const target = pkg.targets.filter(t => t.name === name && same(t.kind, ["bin"]));
    const expected = path.join(ctx.args.source, name === "sunrise-edge-cli" ? "apps/cli/src/main.rs" : `apps/operator/src/bin/${name}.rs`);
    requireThat(target.length === 1 && target[0].src_path === expected && (target[0]["required-features"] ?? []).length === 0,
      "Shipped target identity/source mismatch");
    shipped.push({ name, packageId: pkg.id, target: target[0] });
  }
  const ledger = selected.find(p => p.name === "sunrise-edge-ledger");
  requireThat(ledger && (ledger.features.default ?? []).length === 0 && ledger.featureSets.every(f => !f.includes("usb-hid")), "Unexpected Ledger USB/default selection");
  requireThat(selected.some(p => p.name === "runtime-postgres") && selected.some(p => p.name === "vcpkg"), "Selected graph lost actual PG/native build dependencies");
  return { selected, shipped, lockedGraph: lock, metadataHash: digest(raw), tree, recipe: args };
}

class RunOwner {
  constructor(root, sync) {
    this.root = root; this.sync = sync; this.records = new Map(); this.manifestId = null;
    this.sequence = 0; this.token = randomUUID(); this.childrenStopped = true;
  }
  initialize() {
    const root = this.root; const sync = this.sync;
    checkAncestors(path.dirname(root));
    requireThat(!exists(root), "Occupied evidence output");
    mkdirSync(root, { mode: 0o700 });
    this.rootAncestors = checkAncestors(root);
    this.rootId = identity(lstatSync(root));
    requireThat(this.rootId.uid === process.getuid() && this.rootId.mode === 0o700, "Unsafe evidence root owner/mode");
    this.lockPath = path.join(root, "owner.json");
    this.lockId = exclusiveFile(this.lockPath, Buffer.from(JSON.stringify({ token: this.token,
      pid: process.pid, root, rootId: this.rootId })), sync);
    syncDir(root, sync);
  }
  check() {
    assertAncestors(this.rootAncestors);
    requireThat(same(identity(lstatSync(this.root)), this.rootId) &&
      same(identity(lstatSync(this.lockPath)), this.lockId) &&
      JSON.parse(utf8.decode(smallFile(this.lockPath, 4096))).token === this.token, "Evidence ownership drift");
  }
  directory(name) {
    this.check(); requireThat(/^(compiler|temp|artifacts)-[ab]$/.test(name), "Illegal owned directory name");
    const p = path.join(this.root, name);
    requireThat(!exists(p) && !this.records.has(p), "Occupied compiler/temp/artifact output");
    mkdirSync(p, { mode: 0o700 });
    const record = { path: p, id: identity(lstatSync(p)), token: this.token, purpose: name,
      created: true, cleaned: false, snapshotsVerified: false };
    this.records.set(p, record); syncDir(this.root, this.sync); return record;
  }
  directoryCheck(record) {
    this.check(); requireThat(this.records.get(record.path) === record && record.created && !record.cleaned &&
      record.token === this.token && within(this.root, record.path) && path.dirname(record.path) === this.root &&
      same(identity(lstatSync(record.path)), record.id), "Owned directory identity mismatch");
  }
  manifest(value) {
    this.check(); const destination = path.join(this.root, "manifest.json");
    if (this.manifestId) requireThat(same(identity(lstatSync(destination)), this.manifestId), "Manifest attachment drift");
    else requireThat(!exists(destination), "Occupied manifest path");
    const temporary = path.join(this.root, `.manifest-${++this.sequence}.tmp`);
    const data = Buffer.from(JSON.stringify(value, null, 2) + "\n");
    exclusiveFile(temporary, data, this.sync);
    this.check();
    if (this.manifestId) requireThat(same(identity(lstatSync(destination)), this.manifestId), "Manifest changed before rename");
    else requireThat(!exists(destination), "Manifest appeared before rename");
    renameSync(temporary, destination);
    this.manifestId = identity(lstatSync(destination));
    syncDir(this.root, this.sync);
  }
  cleanup(record) {
    this.directoryCheck(record);
    requireThat(this.childrenStopped && record.snapshotsVerified && /^(compiler|temp)-[ab]$/.test(record.purpose),
      "Cleanup lacks stopped descendants/verified snapshots/creation purpose");
    // Validate the entire exact created tree first; never follow links/mounts.
    const entries = [];
    const visit = p => {
      const s = lstatSync(p);
      requireThat(!s.isSymbolicLink() && (s.isFile() || s.isDirectory()) && s.dev === record.id.dev &&
        s.uid === process.getuid(), "Unsafe cleanup entry/owner/device");
      requireThat(entries.length < 500_000, "Cleanup inventory budget exceeded");
      entries.push({ path: p, id: stamp(s), directory: s.isDirectory() });
      if (s.isDirectory()) for (const name of readdirSync(p).sort()) visit(path.join(p, name));
    };
    visit(record.path); this.directoryCheck(record);
    // Recheck all attachments before the first removal. Trusted-host freeze still applies.
    for (const entry of entries) requireThat(same(stamp(lstatSync(entry.path)), entry.id), "Cleanup attachment drift");
    for (const entry of entries.reverse()) {
      // Directory timestamps change when its children are removed; identity cannot change.
      const s = lstatSync(entry.path);
      requireThat(same(identity(s), { dev: entry.id.dev, ino: entry.id.ino, uid: entry.id.uid, mode: entry.id.mode }) &&
        (entry.directory || same(stamp(s), entry.id)), "Cleanup attachment changed during removal");
      if (entry.directory) rmdirSync(entry.path); else unlinkSync(entry.path);
    }
    record.cleaned = true; syncDir(this.root, this.sync);
    return { path: record.path, identity: record.id, removed: entries.length, success: true };
  }
}

function sourceLease(source, sync) {
  // Stable across output parents and source commits. No stale-lock scavenging.
  const parent = `/tmp/sunrise-edge-native-evidence-${process.getuid()}`;
  checkAncestors("/tmp");
  if (!exists(parent)) mkdirSync(parent, { mode: 0o700 });
  const ancestors = checkAncestors(parent); const directory = lstatSync(parent);
  requireThat(directory.uid === process.getuid() && (directory.mode & 0o7777) === 0o700, "Unsafe source lease parent");
  const p = path.join(parent, `source-${digest(Buffer.from(source))}.json`);
  const token = randomUUID();
  const id = exclusiveFile(p, Buffer.from(JSON.stringify({ source, token, pid: process.pid })), sync);
  syncDir(parent, sync);
  return {
    path: p, id, token, released: false,
    check() {
      assertAncestors(ancestors);
      requireThat(same(identity(lstatSync(p)), id) && JSON.parse(utf8.decode(smallFile(p, 4096))).token === token,
        "Source lease ownership drift");
    },
    release() { this.check(); unlinkSync(p); syncDir(parent, sync); this.released = true; },
  };
}
function leasePath(source) {
  return `/tmp/sunrise-edge-native-evidence-${process.getuid()}/source-${digest(Buffer.from(source))}.json`;
}
function outputPolicy(ctx) {
  const { source, "cargo-home": cache, "output-dir": output } = ctx.args;
  checkAncestors(source); checkAncestors(cache); checkAncestors(path.dirname(output));
  const gitDir = utf8.decode(git(ctx, ["rev-parse", "--absolute-git-dir"])).trim();
  const commonDir = utf8.decode(git(ctx, ["rev-parse", "--path-format=absolute", "--git-common-dir"])).trim();
  absolute(gitDir); absolute(commonDir);
  // Protect the primary checkout and its shared target without inspecting that target.
  const primary = path.basename(commonDir) === ".git" ? path.dirname(commonDir) : commonDir;
  const prohibited = [source, cache, primary, gitDir, commonDir,
    ...["node", "git", "cargo", "rustc", "rustdoc", "cc", "ar", "ld"].map(k => realpathSync(ctx.args[k])),
    `/tmp/sunrise-edge-native-evidence-${process.getuid()}`];
  for (const p of prohibited) requireThat(!overlaps(output, p), "Output overlaps source/cache/tools/lease/Git metadata");
  requireThat(!["/", "/tmp", "/var", "/home", "/usr", "/opt", ctx.callerEnv.HOME].includes(output), "Broad evidence output root");
  requireThat(!exists(output), "Occupied evidence output");
}
function readings(ctx) {
  if (ctx.fixture && ctx.doubles.resources) return ctx.doubles.resources();
  const fs = statfsSync(ctx.args["output-dir"], { bigint: true });
  const memory = /^MemAvailable:\s+(\d+) kB$/m.exec(readFileSync("/proc/meminfo", "utf8"));
  requireThat(memory, "Missing Linux available-memory reading");
  return { disk: Number(fs.bavail * fs.bsize), memory: Number(memory[1]) * 1024 };
}
function admission(ctx) {
  const r = readings(ctx);
  requireThat(Number.isSafeInteger(r.disk) && Number.isSafeInteger(r.memory) &&
    r.disk >= LIMITS.admissionDisk && r.memory >= LIMITS.admissionMemory, "Resource admission floor failed");
  return r;
}
function diskFloor(ctx) {
  const r = readings(ctx); requireThat(r.disk >= LIMITS.abortDisk, "Free-disk abort floor failed"); return r;
}
async function inputs(ctx) {
  ctx.lease.check(); ctx.owner.check();
  const config = checkConfig(ctx.args, ctx.callerEnv);
  const source = verifySource(ctx);
  const tools = verifyTools(ctx);
  // Resolve afresh; metadata/tree/lock can never be copied from the initial result.
  const closure = resolveClosure({ ...ctx, source });
  const dependencies = [];
  let compressed = 0; let expanded = 0; let entries = 0;
  for (const pkg of closure.selected.filter(p => p.source !== null)) {
    const value = await verifyRegistryPackage(pkg);
    compressed += value.compressed; expanded += value.expanded; entries += value.entries;
    requireThat(compressed <= LIMITS.closureCompressed && expanded <= LIMITS.closureExpanded && entries <= LIMITS.closureEntries,
      "Selected closure byte/entry budget exceeded");
    dependencies.push(value);
  }
  const result = { source, tools, config, closure, dependencies, totals: { compressed, expanded, entries } };
  return { result, sha256: jsonDigest(result) };
}
export function cargoRecipe(ctx, compiler, temp) {
  // No shell, ambient flags, config files, HOME change, or arbitrary Cargo options.
  const rustMaps = [[ctx.args.source, "/sunrise-edge/source"], [ctx.args["cargo-home"], "/sunrise-edge/dependencies"],
    [compiler.path, "/sunrise-edge/compiler-output"], [temp.path, "/sunrise-edge/compiler-temp"]];
  // cc's CFLAGS parser needs unambiguous single tokens. Fail rather than silently splitting.
  for (const [from] of rustMaps) requireThat(!/[\s'"\\]/.test(from), "Unsupported native path-map spelling");
  // Stable rustc 1.97.1 otherwise prefers bundled LLD on this target. Keep the
  // supplied, checked CC/default GNU ld binding explicit and recorded.
  const rustFlags = ["-C", "linker-features=-lld", "-C", "link-self-contained=-linker",
    ...rustMaps.map(([a, b]) => `--remap-path-prefix=${a}=${b}`)];
  const cFlags = rustMaps.flatMap(([a, b]) => [`-ffile-prefix-map=${a}=${b}`, `-fdebug-prefix-map=${a}=${b}`]);
  const argv = ["build", ...commonCargo(ctx), "--release", "--jobs", "1", "--message-format=json-render-diagnostics",
    ...PACKAGES.flatMap(p => ["-p", p]), ...NAMES.flatMap(n => ["--bin", n]), "--target-dir", compiler.path,
    "--config", `build.rustflags=${configArg(rustFlags)}`];
  const env = { ...ctx.env, CFLAGS: cFlags.join(" "), SOURCE_DATE_EPOCH: ctx.source.epoch,
    CARGO_TARGET_DIR: compiler.path, TMPDIR: temp.path, TMP: temp.path, TEMP: temp.path };
  return { argv, env, rustFlags, cFlags };
}
function groupLive(pid) {
  // Inspect only stat identifiers, never process environment or command lines.
  for (const entry of readdirSync("/proc")) {
    if (!/^\d+$/.test(entry)) continue;
    try {
      const stat = readFileSync(`/proc/${entry}/stat`, "utf8");
      const rest = stat.slice(stat.lastIndexOf(")") + 2).split(" ");
      if (Number(rest[2]) === pid && rest[0] !== "Z" && rest[0] !== "X") return true;
    } catch (e) { if (!["ENOENT", "ESRCH", "EACCES"].includes(e.code)) throw e; }
  }
  return false;
}
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
async function stopGroup(pid, force) {
  if (!pid) return true;
  const signal = sig => { try { process.kill(-pid, sig); } catch (e) { if (e.code !== "ESRCH") throw e; } };
  if (force || groupLive(pid)) signal("SIGTERM");
  for (let i = 0; i < 20 && groupLive(pid); i++) await delay(50);
  if (groupLive(pid)) signal("SIGKILL");
  for (let i = 0; i < 40 && groupLive(pid); i++) await delay(50);
  return !groupLive(pid);
}
function normalizedFeatures(value) {
  requireThat(Array.isArray(value) && value.every(f => typeof f === "string") && new Set(value).size === value.length, "Malformed Cargo features");
  return [...value].sort();
}
function validateObservation(message, closure, compiler, observations) {
  requireThat(message && typeof message === "object" && !Array.isArray(message) && typeof message.reason === "string", "Malformed Cargo JSON record");
  const byId = new Map(closure.selected.map(p => [p.id, p]));
  if (message.reason === "build-finished") {
    requireThat(typeof message.success === "boolean" && observations.finished === null, "Duplicate/malformed build-finished");
    observations.finished = message.success; return;
  }
  requireThat(observations.finished === null, "Cargo record after build-finished");
  requireThat(["compiler-artifact", "compiler-message", "build-script-executed"].includes(message.reason), "Unknown Cargo JSON reason");
  const pkg = byId.get(message.package_id);
  requireThat(pkg, "Cargo observation outside selected normal/build closure");
  observations.packages.add(pkg.id);
  if (message.reason === "build-script-executed") {
    requireThat(typeof message.out_dir === "string" && within(compiler.path, message.out_dir), "Build-script output escapes owned compiler");
    observations.dependencies.push(message); return;
  }
  const target = message.target;
  const declared = target && pkg.targets.find(t => t.name === target.name && same(t.kind, target.kind) &&
    same(t.crate_types, target.crate_types) && t.src_path === target.src_path);
  requireThat(declared, "Cargo target identity mismatch");
  if (message.reason === "compiler-message") { observations.diagnostics++; return; }
  requireThat(message.fresh === false && message.profile && message.profile.test === false &&
    message.manifest_path === pkg.manifest_path, "Unexpected reused/nonrelease or wrong-manifest Cargo artifact");
  const features = normalizedFeatures(message.features);
  requireThat(pkg.featureSets.some(f => same(f, features)), "Cargo observed features differ from selected normal/build features");
  if (!observations.features.has(pkg.id)) observations.features.set(pkg.id, new Set());
  for (const f of features) observations.features.get(pkg.id).add(f);
  if (!observations.featureSets.has(pkg.id)) observations.featureSets.set(pkg.id, new Set());
  observations.featureSets.get(pkg.id).add(JSON.stringify(features));
  requireThat(Array.isArray(message.filenames) && message.filenames.length > 0 && message.filenames.every(p =>
    typeof p === "string" && path.isAbsolute(p) && path.normalize(p) === p && within(compiler.path, p)), "Cargo artifact output escapes owned compiler");
  const roles = new Set(message.filenames.map(p => {
    if (within(path.join(compiler.path, TARGET, "release"), p)) return "target";
    if (within(path.join(compiler.path, "release"), p)) return "host";
    throw new Error("Cargo artifact outside owned host/target release roots");
  }));
  requireThat(roles.size === 1, "Mixed Cargo host/target artifact roles");
  const role = [...roles][0];
  requireThat(!(target.kind.includes("custom-build") || target.kind.includes("proc-macro")) || role === "host",
    "Cargo build-script/proc-macro compiler output is not host output");
  message.evidenceRole = role;
  const shipped = closure.shipped.find(s => s.name === target.name && s.packageId === pkg.id && same(target.kind, ["bin"]));
  if (shipped) {
    requireThat(role === "target" && message.executable === path.join(compiler.path, TARGET, "release", shipped.name) &&
      message.filenames.includes(message.executable) && !observations.shipped.has(shipped.name), "Missing/duplicate/illegal shipped executable observation");
    observations.shipped.set(shipped.name, message);
  } else {
    requireThat(!target.kind.includes("bin") && (message.executable === null ||
      (target.kind.includes("custom-build") && typeof message.executable === "string" && within(compiler.path, message.executable))),
      "Unexpected selected executable");
    observations.dependencies.push(message);
  }
}
function finishObservations(closure, observations) {
  requireThat(observations.finished === true && observations.shipped.size === NAMES.length &&
    NAMES.every(n => observations.shipped.has(n)), "Missing shipped artifacts or successful build-finished");
  requireThat(observations.packages.size === closure.selected.length && closure.selected.every(p => observations.packages.has(p.id)),
    "Actual Cargo package closure differs from selected closure");
  for (const pkg of closure.selected) {
    const expected = [...new Set(pkg.featureSets.flat())].sort();
    const actual = [...(observations.features.get(pkg.id) ?? [])].sort();
    requireThat(same(expected, actual) && observations.features.has(pkg.id), "Actual Cargo feature closure incomplete");
    requireThat(same(pkg.featureSets.map(f => JSON.stringify(f)).sort(), [...(observations.featureSets.get(pkg.id) ?? [])].sort()),
      "Actual Cargo feature variants incomplete");
  }
}
function shippedOutputInventory(compiler) {
  const release = path.join(compiler.path, TARGET, "release"); checkAncestors(release);
  for (const name of readdirSync(release)) {
    const p = path.join(release, name); const s = lstatSync(p);
    requireThat(!s.isSymbolicLink() && (s.isDirectory() || s.isFile()), "Illegal target release output");
    if (s.isFile() && (s.mode & 0o111)) requireThat(NAMES.includes(name), "Unexpected target release executable");
  }
}
async function build(ctx, label, compiler, temp, record) {
  ctx.owner.directoryCheck(compiler); ctx.owner.directoryCheck(temp);
  requireThat(readdirSync(compiler.path).length === 0 && readdirSync(temp.path).length === 0, "Fresh compiler/temp output is occupied");
  const recipe = cargoRecipe(ctx, compiler, temp); record.recipe = recipe; record.started = true;
  const observations = { packages: new Set(), features: new Map(), featureSets: new Map(), shipped: new Map(), dependencies: [], diagnostics: 0, finished: null };
  const stdout = path.join(ctx.owner.root, `build-${label}.stdout.log`);
  const stderr = path.join(ctx.owner.root, `build-${label}.stderr.log`);
  record.logs = { stdout, stderr, bytes: 0 }; record.exit = null; record.signal = null;
  let outFd; let errFd;
  try {
    outFd = openSync(stdout, F.O_WRONLY | F.O_CREAT | F.O_EXCL | F.O_NOFOLLOW, 0o600);
    errFd = openSync(stderr, F.O_WRONLY | F.O_CREAT | F.O_EXCL | F.O_NOFOLLOW, 0o600);
  } catch (e) { if (outFd !== undefined) closeSync(outFd); record.failure = e.message; throw e; }
  let child; let closed; let failure = null; let line = Buffer.alloc(0); let timer; let deadline;
  const fail = e => { if (!failure) failure = e; if (child?.pid) { try { process.kill(-child.pid, "SIGTERM"); } catch (x) { if (x.code !== "ESRCH") failure ??= x; } } };
  const now = ctx.fixture && ctx.doubles.now ? ctx.doubles.now : Date.now;
  const startedAt = now();
  const poll = () => {
    try { if (ctx.cancelled) throw ctx.cancelled; record.lastResource = diskFloor(ctx); requireThat(now() - startedAt <= LIMITS.buildMs, "Build deadline exceeded"); }
    catch (e) { fail(e); }
  };
  const receive = (bytes, isOut) => {
    try {
      const capacity = LIMITS.log - record.logs.bytes;
      if (capacity > 0) { const kept = bytes.subarray(0, capacity); writeAll(isOut ? outFd : errFd, kept); record.logs.bytes += kept.length; }
      requireThat(bytes.length <= capacity, "Combined build log budget exceeded");
      if (isOut) {
        const data = Buffer.concat([line, bytes]); let start = 0; let index;
        while ((index = data.indexOf(10, start)) !== -1) {
          requireThat(index - start <= LIMITS.line && index > start, "Cargo JSON line budget/empty record");
          let message;
          try { message = JSON.parse(utf8.decode(data.subarray(start, index))); }
          catch { throw new Error("Malformed Cargo JSON line"); }
          validateObservation(message, ctx.closure, compiler, observations); start = index + 1;
        }
        line = Buffer.from(data.subarray(start)); requireThat(line.length <= LIMITS.line, "Cargo JSON line budget exceeded");
      }
      poll();
    } catch (e) { fail(e); }
  };
  try {
    ctx.cancelChild = fail;
    const launch = ctx.fixture ? ctx.doubles.spawnBuild :
      (tool, argv, options) => spawn(tool, argv, options);
    requireThat(typeof launch === "function", "Missing fixture process double");
    child = launch(ctx.args.cargo, recipe.argv, { cwd: ctx.args.source, env: recipe.env,
      detached: true, stdio: ["ignore", "pipe", "pipe"] }, { label, compiler: compiler.path, temp: temp.path, closure: ctx.closure });
    ctx.owner.childrenStopped = !child.pid; record.pid = child.pid ?? null;
    // A failed child that ignores TERM is forcibly stopped even before close.
    closed = new Promise(resolve => {
      child.on("error", e => { record.spawnError = e.code ?? e.message; fail(new Error("Build process spawn failed")); });
      child.on("exit", (code, signal) => { record.exit = code; record.signal = signal; });
      child.on("close", (code, signal) => { record.exit = code; record.signal = signal; resolve(); });
    });
    child.stdout.on("data", bytes => receive(bytes, true)); child.stderr.on("data", bytes => receive(bytes, false));
    child.stdout.on("error", fail); child.stderr.on("error", fail);
    poll();
    timer = setInterval(() => { poll(); if (failure && child.pid) {
      try { process.kill(-child.pid, "SIGKILL"); } catch (e) { if (e.code !== "ESRCH") fail(e); }
    } }, 1000);
    deadline = setTimeout(() => fail(new Error("Build deadline exceeded")), LIMITS.buildMs);
    await closed;
    ctx.owner.childrenStopped = await stopGroup(child.pid, Boolean(failure));
    requireThat(ctx.owner.childrenStopped, "Owned descendants did not stop");
    requireThat(!failure, failure?.message ?? "Build failed");
    requireThat(record.exit === 0 && record.signal === null, "Cargo build nonzero exit/signal");
    requireThat(line.length === 0, "Incomplete Cargo JSON tail");
    finishObservations(ctx.closure, observations);
    shippedOutputInventory(compiler);
  } catch (e) {
    failure ??= e;
    if (child?.pid) {
      ctx.owner.childrenStopped = await stopGroup(child.pid, true);
      if (closed) await closed;
    }
    record.failure = failure.message;
  } finally {
    clearInterval(timer); clearTimeout(deadline); ctx.cancelChild = null; record.elapsedMs = now() - startedAt;
    record.descendantsStopped = ctx.owner.childrenStopped;
    record.observations = { finished: observations.finished, shipped: [...observations.shipped.values()],
      dependencies: observations.dependencies, diagnostics: observations.diagnostics,
      packages: [...observations.packages].sort(), features: [...observations.features].map(([id, set]) => ({ id, features: [...set].sort(),
        variants: [...observations.featureSets.get(id)].sort().map(s => JSON.parse(s)) })) };
    try { ctx.sync(outFd, "log"); ctx.sync(errFd, "log"); syncDir(ctx.owner.root, ctx.sync); }
    catch (e) { failure ??= e; record.synchronizationFailure = e.message; }
    finally { closeSync(outFd); closeSync(errFd); }
    record.success = !failure;
  }
  if (failure) throw failure;
  return observations;
}

export function compareFiles(a, b, size) {
  const x = heldFile(a, { executable: true, singleLink: true });
  const y = heldFile(b, { executable: true, singleLink: true });
  try {
    requireThat(x.initial.size === size && y.initial.size === size &&
      !(x.initial.dev === y.initial.dev && x.initial.ino === y.initial.ino), "Byte comparator attachment/size alias");
    const xb = Buffer.alloc(64 * 1024); const yb = Buffer.alloc(64 * 1024);
    let offset = 0;
    while (offset < size) {
      const count = Math.min(xb.length, size - offset);
      requireThat(readSync(x.fd, xb, 0, count, offset) === count && readSync(y.fd, yb, 0, count, offset) === count,
        "Byte comparator premature EOF");
      requireThat(xb.subarray(0, count).equals(yb.subarray(0, count)), "Full byte comparison mismatch"); offset += count;
    }
    requireThat(readSync(x.fd, xb, 0, 1, offset) === 0 && readSync(y.fd, yb, 0, 1, offset) === 0, "Byte comparator trailing data");
    x.check(); y.check(); return { bytes: offset, equal: true };
  } finally { x.close(); y.close(); }
}
function snapshots(ctx, label, compiler, temp, observations, record) {
  const dir = ctx.owner.directory(`artifacts-${label}`); record.snapshotDirectory = dir;
  const result = []; record.artifacts = result;
  const savedIds = new Set();
  const sourceIds = new Set(NAMES.map(n => {
    const p = observations.shipped.get(n).executable; const s = lstatSync(p); return `${s.dev}:${s.ino}`;
  }));
  for (const name of NAMES) {
    ctx.owner.directoryCheck(compiler); ctx.owner.directoryCheck(dir);
    const src = observations.shipped.get(name).executable;
    requireThat(src === path.join(compiler.path, TARGET, "release", name), "Snapshot source outside closed target");
    const before = hashFile(src, { executable: true });
    const input = heldFile(src, { executable: true });
    const destination = path.join(dir.path, name);
    const fd = openSync(destination, F.O_WRONLY | F.O_CREAT | F.O_EXCL | F.O_NOFOLLOW, before.mode);
    try {
      const buffer = Buffer.alloc(64 * 1024);
      for (let offset = 0; offset < before.size;) {
        const n = readSync(input.fd, buffer, 0, Math.min(buffer.length, before.size - offset), offset);
        requireThat(n > 0, "Snapshot premature EOF"); writeAll(fd, buffer.subarray(0, n)); offset += n;
      }
      fchmodSync(fd, before.mode); // Preserve actual mode, never normalize to 0755.
      ctx.sync(fd, "artifact"); input.check();
    } finally { closeSync(fd); input.close(); }
    if (ctx.fixture) ctx.doubles.afterCopy?.({ label, name, src, destination });
    const after = hashFile(src, { executable: true });
    const saved = hashFile(destination, { executable: true, singleLink: true });
    const key = `${saved.dev}:${saved.ino}`;
    requireThat(same(before, after) && saved.sha256 === before.sha256 && saved.size === before.size &&
      saved.mode === before.mode && !savedIds.has(key) && !sourceIds.has(key), "Snapshot bytes/mode/source attachment/identity mismatch");
    savedIds.add(key); result.push({ name, packageId: observations.shipped.get(name).package_id, source: before, ...saved });
  }
  syncDir(dir.path, ctx.sync); syncDir(ctx.owner.root, ctx.sync);
  for (const artifact of result) requireThat(same(hashFile(artifact.path, { executable: true, singleLink: true }),
    Object.fromEntries(Object.entries(artifact).filter(([k]) => !["name", "packageId", "source"].includes(k)))), "Saved artifact changed after synchronization");
  for (const artifact of result) ctx.seals.push(heldFile(artifact.path, { executable: true, singleLink: true }));
  compiler.snapshotsVerified = true; temp.snapshotsVerified = true;
  record.snapshotVerified = true; return result;
}
export function compareArtifacts(a, b, { verifyHashes = true } = {}) {
  requireThat(a.length === NAMES.length && b.length === NAMES.length &&
    a.every((r, i) => r.name === NAMES[i]) && b.every((r, i) => r.name === NAMES[i]), "Artifact name/count mismatch");
  const identities = new Set(); const comparisons = []; const held = [];
  try {
    for (const r of [...a, ...b]) {
      const h = heldFile(r.path, { executable: true, singleLink: true }); held.push(h);
      requireThat(same(stamp(h.initial), { dev: r.dev, ino: r.ino, uid: r.uid, mode: r.mode, size: r.size,
        mtime: r.mtime, ctime: r.ctime, nlink: r.nlink }), "Saved artifact recorded attachment drift");
    }
  for (let i = 0; i < NAMES.length; i++) {
    const x = a[i]; const y = b[i];
    for (const r of [x, y]) {
      const h = hashFile(r.path, { executable: true, singleLink: true });
      requireThat(h.dev === r.dev && h.ino === r.ino && h.size === r.size && h.mode === r.mode &&
        (!verifyHashes || h.sha256 === r.sha256), "Saved artifact attachment/hash drift");
      const key = `${h.dev}:${h.ino}`; requireThat(!identities.has(key), "Saved artifacts alias"); identities.add(key);
    }
    requireThat(x.packageId === y.packageId && x.size === y.size && x.mode === y.mode && x.sha256 === y.sha256,
      "Artifact mode/size/hash mismatch");
    comparisons.push({ name: x.name, ...compareFiles(x.path, y.path, x.size) });
  }
    for (const h of held) h.check(); return comparisons;
  } finally { for (const h of held) h.close(); }
}
function usageBytes(root) {
  let size = 0; let count = 0;
  const walk = p => {
    const s = lstatSync(p); requireThat(!s.isSymbolicLink(), "Output use inventory symlink");
    requireThat(++count < 500_000, "Output inventory entry budget exceeded");
    if (s.isDirectory()) for (const n of readdirSync(p)) walk(path.join(p, n));
    else { requireThat(s.isFile(), "Illegal output inventory type"); size += s.size; }
  };
  walk(root); return { apparentBytes: size, entries: count };
}
async function orchestrate(args, { fixture = false, doubles = {}, callerEnv = process.env } = {}) {
  const ctx = { args, fixture, doubles, callerEnv, seals: [], execute: fixture ? doubles.execute : execute,
    sync: fixture && doubles.sync ? doubles.sync : fsyncSync };
  requireThat(!fixture || typeof doubles.execute === "function", "Missing fixture tool doubles");
  validateCallerEnv(callerEnv); ctx.env = baseEnv(args);
  checkConfig(args, callerEnv); outputPolicy(ctx);
  const manifest = { format: "sunrise-edge-native-evidence-v1", evidenceKind: fixture ? "fixture" : "native-local",
    complete: false, fixturePassed: false, sourcePath: args.source, expectedSha: args["expected-sha"],
    limits: LIMITS, stage: "initial", boundaries: [], builds: { a: { started: false }, b: { started: false } }, cleanup: [],
    sourceLease: { path: leasePath(args.source), identity: null, acquired: false, released: false },
    limitsOfEvidence: ["same-host equality, not cross-machine/hermetic/upstream authenticity proof",
      "unenumerated sysroot/runtime/system dependencies", "coordinator must freeze source and allocate budget",
      "lease blocks only duplicate tool invocations, not unrelated Git/host writers",
      "trusted child process group; hostile tools escaping their group are out of scope",
      "no M7 completion, release/process/provider/custody/PKI/advisory/public authority"] };
  let baseline;
  let failure;
  const onSignal = signal => { ctx.cancelled ??= new Error(`Runner interrupted by ${signal}`); ctx.cancelChild?.(ctx.cancelled); };
  const onInt = () => onSignal("SIGINT"); const onTerm = () => onSignal("SIGTERM");
  process.on("SIGINT", onInt); process.on("SIGTERM", onTerm);
  const stage = async name => {
    if (ctx.cancelled) throw ctx.cancelled;
    manifest.stage = name;
    if (fixture) await doubles.stage?.(name, ctx);
    if (ctx.cancelled) throw ctx.cancelled;
    ctx.owner.manifest(manifest);
  };
  const boundary = async name => {
    await stage(name); diskFloor(ctx);
    const snapshot = await inputs(ctx);
    if (ctx.cancelled) throw ctx.cancelled;
    manifest.boundaries.push({ name, sha256: snapshot.sha256 });
    if (!baseline) {
      baseline = snapshot; manifest.inputs = snapshot.result;
      ctx.source = snapshot.result.source; ctx.closure = snapshot.result.closure;
      // Metadata/Git control roots are known now; reapply overlap policy without the occupied-output check.
      for (const p of [ctx.source.gitDir, ctx.source.commonDir]) requireThat(!overlaps(ctx.owner.root, p), "Output overlaps Git control root");
    } else requireThat(snapshot.sha256 === baseline.sha256, `Input drift at ${name}`);
    for (const h of ctx.seals) h.check();
    ctx.owner.manifest(manifest);
  };
  try {
    ctx.owner = new RunOwner(args["output-dir"], ctx.sync);
    ctx.owner.initialize();
    ctx.owner.manifest(manifest);
    await stage("source-lease");
    ctx.lease = sourceLease(args.source, ctx.sync);
    manifest.sourceLease.identity = ctx.lease.id; manifest.sourceLease.acquired = true;
    ctx.owner.manifest(manifest);
    await stage("admission"); manifest.admission = admission(ctx);
    await boundary("before-a");
    for (const label of ["a", "b"]) {
      if (label === "b") await boundary("before-b");
      const compiler = ctx.owner.directory(`compiler-${label}`);
      const temp = ctx.owner.directory(`temp-${label}`);
      const record = manifest.builds[label]; record.compiler = compiler; record.temp = temp;
      await stage(`build-${label}`);
      const observations = await build(ctx, label, compiler, temp, record);
      ctx.owner.manifest(manifest);
      await boundary(`after-${label}`);
      await stage(`snapshot-${label}`);
      snapshots(ctx, label, compiler, temp, observations, record);
      record.outputUse = usageBytes(compiler.path);
      ctx.owner.manifest(manifest);
      if (label === "b") {
        await stage("compare");
        ctx.owner.directoryCheck(manifest.builds.a.snapshotDirectory);
        ctx.owner.directoryCheck(manifest.builds.b.snapshotDirectory);
        manifest.comparisons = compareArtifacts(manifest.builds.a.artifacts, manifest.builds.b.artifacts);
      }
      await stage(`cleanup-${label}`);
      manifest.cleanup.push(ctx.owner.cleanup(compiler));
      manifest.cleanup.push(ctx.owner.cleanup(temp));
      ctx.owner.manifest(manifest); diskFloor(ctx);
    }
    await boundary("final");
    await stage("verified");
    for (const h of ctx.seals) h.check();
    for (const label of ["a", "b"]) ctx.owner.directoryCheck(manifest.builds[label].snapshotDirectory);
    ctx.lease.release(); manifest.sourceLease.released = true;
    // A fixture can exercise every success transition but can NEVER claim native completion.
    manifest.complete = !fixture; manifest.fixturePassed = fixture;
    ctx.owner.manifest(manifest);
  } catch (e) {
    failure = e; manifest.complete = false; manifest.fixturePassed = false;
    manifest.failure = { stage: manifest.stage, message: e.message };
    if (ctx.owner?.childrenStopped && ctx.lease && !ctx.lease.released) {
      try { ctx.lease.release(); manifest.sourceLease.released = true; }
      catch (leaseError) { manifest.failure.lease = leaseError.message; }
    }
    if (ctx.owner) {
      try { ctx.owner.manifest(manifest); }
      catch (saveError) { manifest.failure.persistence = saveError.message; }
    }
  }
  let closeFailure;
  for (const h of ctx.seals) { try { h.close(); } catch (e) { closeFailure ??= e; } }
  if (closeFailure) {
    failure ??= closeFailure; manifest.complete = false; manifest.fixturePassed = false;
    manifest.failure ??= { stage: "close-saved-attachments", message: closeFailure.message };
    try { ctx.owner.manifest(manifest); } catch (e) { manifest.failure.persistence = e.message; }
  }
  process.off("SIGINT", onInt); process.off("SIGTERM", onTerm);
  if (failure) {
    const error = new Error(`Incomplete ${fixture ? "fixture" : "native"} evidence at ${manifest.stage}: ${failure.message}`);
    error.evidence = manifest; error.output = args["output-dir"]; throw error;
  }
  return manifest;
}
export async function runNativeReleaseEvidence(argv) {
  requireThat(process.platform === "linux" && process.arch === "x64" && process.version === NODE_VERSION, "Requires Linux x86_64 and installed Node 22.20.0");
  requireThat(process.execArgv.length === 0, "Undeclared Node execution flags");
  return orchestrate(parseCli(argv)); // No production CLI bypass or injected doubles.
}
export async function runFixtureEvidence(args, doubles, callerEnv = {}) {
  return orchestrate(parseCli(args), { fixture: true, doubles, callerEnv });
}
if (process.argv[1] && path.resolve(process.argv[1]) === SCRIPT) {
  try {
    await runNativeReleaseEvidence(process.argv.slice(2));
    process.stdout.write("Two native builds and eleven full-byte comparisons succeeded; local evidence only.\n");
  } catch (e) {
    process.stderr.write(`${e.message}\n`); process.exitCode = 1;
  }
}
