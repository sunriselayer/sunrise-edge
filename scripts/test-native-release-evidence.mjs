#!/usr/bin/env node
// Compiler/DB/network-free controls; all orchestration evidence is labelled fixture.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, lstatSync, chmodSync,
  symlinkSync, linkSync, renameSync, unlinkSync, rmSync, existsSync, fsyncSync } from "node:fs";
import path from "node:path";
import { gzipSync } from "node:zlib";
import { NODE_VERSION, NAMES, TARGET, LIMITS, parseCli, validateCallerEnv, verifyRegistryPackage,
  verifyCargoOk, compareFiles, compareArtifacts, runFixtureEvidence, runNativeReleaseEvidence } from "./check-native-release-evidence.mjs";

assert.equal(process.version, NODE_VERSION, "Use installed pinned Node 22.20.0");
const root = mkdtempSync("/tmp/sunrise-edge-native-fixtures-");
let passed = 0;
const sha = b => createHash("sha256").update(b).digest("hex");
function file(p, bytes, mode = 0o644) { mkdirSync(path.dirname(p), { recursive: true }); writeFileSync(p, bytes); chmodSync(p, mode); }
function header(name, type, bytes) {
  const b = Buffer.alloc(512); b.write(name, 0, 100); b.write("0000644\0", 100);
  b.write("0000000\0", 108); b.write("0000000\0", 116);
  b.write(bytes.length.toString(8).padStart(11, "0") + "\0", 124); b.write("00000000000\0", 136);
  b.fill(32, 148, 156); b.write(type, 156); b.write("ustar\0", 257); b.write("00", 263);
  b.write(b.reduce((a, x) => a + x, 0).toString(8).padStart(6, "0") + "\0 ", 148); return b;
}
function fixChecksum(b) {
  b.fill(32, 148, 156);
  b.write(b.subarray(0, 512).reduce((n, x) => n + x, 0).toString(8).padStart(6, "0") + "\0 ", 148);
}
function archive(entries, mutate = null) {
  const blocks = [];
  for (const e of entries) { const data = Buffer.from(e.data ?? "");
    blocks.push(header(e.name, e.type ?? "0", data), data, Buffer.alloc((512 - data.length % 512) % 512)); }
  blocks.push(Buffer.alloc(1024)); const tar = Buffer.concat(blocks); mutate?.(tar); return gzipSync(tar);
}
function packageFixture(label) {
  const parent = path.join(root, label); mkdirSync(parent);
  const expanded = path.join(parent, "vcpkg-0.2.15"); mkdirSync(expanded);
  const long = "vcpkg-0.2.15/nested/" + "n".repeat(130) + ".rs";
  const entries = [
    { name: "vcpkg-0.2.15/Cargo.toml", data: '[package]\nname="vcpkg"\nversion="0.2.15"\n' },
    { name: "vcpkg-0.2.15/src/lib.rs", data: "// fixture library\n" },
    { name: "vcpkg-0.2.15/build.rs", data: "// fixture build script\n" },
    { name: "././@LongLink", type: "L", data: long + "\0" },
    { name: "placeholder", data: "// independent long-name source\n" },
  ];
  file(path.join(expanded, "Cargo.toml"), entries[0].data); file(path.join(expanded, "src/lib.rs"), entries[1].data);
  file(path.join(expanded, "build.rs"), entries[2].data); file(path.join(parent, long), entries[4].data);
  file(path.join(expanded, ".cargo-ok"), '{"v":1}\n');
  const bytes = archive(entries); const crate = path.join(parent, "vcpkg-0.2.15.crate"); file(crate, bytes);
  return { id: "registry+https://github.com/rust-lang/crates.io-index#vcpkg@0.2.15", name: "vcpkg", version: "0.2.15",
    source: "registry+https://github.com/rust-lang/crates.io-index", manifest_path: path.join(expanded, "Cargo.toml"),
    expanded, archive: crate, checksum: sha(bytes), entries, parent };
}
function replace(p, entries, mutate = null, suffix = null) {
  let bytes = archive(entries, mutate); if (suffix) bytes = Buffer.concat([bytes, suffix]);
  file(p.archive, bytes); p.checksum = sha(bytes);
}
async function check(name, fn) { await fn(); passed++; process.stdout.write(`[FIXTURE PASS] ${name}\n`); }
async function badArchive(label, change, pattern, limits = LIMITS) {
  const p = packageFixture(label); change(p); await assert.rejects(() => verifyRegistryPackage(p, limits), pattern);
}
function target(name, src, kind = "lib") {
  return { name, kind: [kind], crate_types: [kind === "custom-build" ? "bin" : kind], src_path: src, edition: "2024" };
}
function fixture(label, scenario = {}) {
  const parent = path.join(root, label); mkdirSync(parent);
  const source = path.join(parent, "source"); mkdirSync(source);
  const cache = path.join(parent, "cargo-home"); const bucket = "index.crates.io-1949cf8c6b5b557f";
  const src = path.join(cache, "registry/src", bucket); const archives = path.join(cache, "registry/cache", bucket);
  mkdirSync(src, { recursive: true }); mkdirSync(archives, { recursive: true });
  const dep = packageFixture(label + "-dep");
  renameSync(dep.expanded, path.join(src, "vcpkg-0.2.15")); renameSync(dep.archive, path.join(archives, "vcpkg-0.2.15.crate"));
  dep.expanded = path.join(src, "vcpkg-0.2.15"); dep.archive = path.join(archives, "vcpkg-0.2.15.crate"); dep.manifest_path = path.join(dep.expanded, "Cargo.toml");
  const packages = [];
  function workspace(name, dir, targets, features = {}) {
    const manifest = path.join(source, dir, "Cargo.toml"); file(manifest, `[package]\nname="${name}"\nversion="0.1.0"\n`);
    for (const t of targets) file(t.src_path, "// independent committed fixture source\n");
    packages.push({ name, version: "0.1.0", id: `path+file://${path.dirname(manifest)}#${name}@0.1.0`, source: null,
      manifest_path: manifest, targets, features, dependencies: [] });
  }
  workspace("sunrise-edge-operator", "apps/operator", NAMES.slice(0, -1).map(n => target(n, path.join(source, "apps/operator/src/bin", n + ".rs"), "bin")));
  workspace("sunrise-edge-cli", "apps/cli", [target("sunrise_edge_cli", path.join(source, "apps/cli/src/lib.rs")),
    target("sunrise-edge-cli", path.join(source, "apps/cli/src/main.rs"), "bin")], { default: [], "usb-hid": [] });
  workspace("sunrise-edge-ledger", "crates/ledger", [target("sunrise_edge_ledger", path.join(source, "crates/ledger/src/lib.rs"))], { default: [], "usb-hid": [] });
  workspace("runtime-postgres", "crates/runtime-postgres", [target("runtime_postgres", path.join(source, "crates/runtime-postgres/src/lib.rs"))]);
  packages.push({ ...dep, features: {}, dependencies: [], targets: [target("vcpkg", path.join(dep.expanded, "src/lib.rs")),
    target("build-script-build", path.join(dep.expanded, "build.rs"), "custom-build")] });
  file(path.join(source, "Cargo.toml"), '[workspace]\nresolver="3"\n');
  file(path.join(source, "rust-toolchain.toml"), '[toolchain]\nchannel = "1.97.1"\n');
  file(path.join(source, "scripts/check-native-release-evidence.mjs"), "// committed fixture marker\n");
  file(path.join(source, "Cargo.lock"), "version = 4\n\n" + packages.map(p => `[[package]]\nname = "${p.name}"\nversion = "${p.version}"\n` +
    (p.source ? `source = "${p.source}"\nchecksum = "${dep.checksum}"\n` : "")).join("\n"));
  mkdirSync(path.join(parent, "git-control")); const tools = path.join(parent, "tools"); mkdirSync(tools); mkdirSync(path.join(tools, "sysroot"));
  const toolNames = ["node", "git", "cargo", "rustc", "rustdoc", "cc", "ar", "ld"];
  for (const n of toolNames) file(path.join(tools, n), `fixture tool ${n}\n`, 0o755);
  file(path.join(tools, "sysroot/lib/rustlib", TARGET, "bin/gcc-ld/ld.lld"), "fixture LLD wrapper", 0o755);
  file(path.join(tools, "sysroot/lib/rustlib", TARGET, "bin/rust-lld"), "fixture LLD implementation", 0o755);
  const output = path.join(parent, "evidence");
  const args = ["--source", source, "--expected-sha", "a".repeat(40), "--cargo-home", cache, "--output-dir", output,
    ...toolNames.flatMap(n => [`--${n}`, path.join(tools, n)])];
  const tracked = [];
  function walk(d) { for (const n of readdirSync(d).sort()) { const p = path.join(d, n); if (lstatSync(p).isDirectory()) walk(p); else tracked.push(p); } }
  walk(source);
  const tree = tracked.map(p => { const b = readFileSync(p); const oid = createHash("sha1").update(`blob ${b.length}\0`).update(b).digest("hex");
    return `100644 blob ${oid}\t${path.relative(source, p)}\0`; }).join("");
  const metadata = { version: 1, workspace_root: source, workspace_members: packages.filter(p => !p.source).map(p => p.id), packages, resolve: { nodes: [] } };
  const treeText = packages.map(p => `${p.name} v${p.version}${p.source ? "" : ` (${path.dirname(p.manifest_path)})`}|`).join("\n") + "\n";
  const doubles = {
    resources: () => ({ disk: 100 * 1024 ** 3, memory: 16 * 1024 ** 3 }),
    execute(tool, argv, cwd, env) {
      assert.equal(env.HOME, undefined); assert.equal(env.AWS_SECRET_ACCESS_KEY, undefined);
      const name = path.basename(tool); let out;
      if (name === "git") {
        const a = argv.filter((_, i) => argv[i] !== "-c" && argv[i - 1] !== "-c"); const key = a.join(" ");
        const map = { "--version": "git version fixture", "rev-parse --show-toplevel": source, "rev-parse HEAD": "a".repeat(40),
          "rev-parse --show-object-format": "sha1", "status --porcelain=v1 -z --untracked-files=normal": scenario.dirty ? " M file\0" : "",
          "ls-files --others --directory --no-empty-directory -z": scenario.untracked ? "ignored/\0" : "",
          [`rev-parse ${"a".repeat(40)}^{tree}`]: "b".repeat(40), [`show -s --format=%ct ${"a".repeat(40)}`]: "1234567890",
          [`ls-tree -r -z --full-tree ${"a".repeat(40)}`]: tree, "rev-parse --absolute-git-dir": path.join(parent, "git-control"),
          "rev-parse --path-format=absolute --git-common-dir": path.join(parent, "git-control") };
        assert.ok(Object.hasOwn(map, key), key); out = map[key];
      } else if (name === "cargo" && argv[0] === "metadata") {
        assert.ok(argv.includes("--filter-platform") && !argv.includes("--target")); assert.ok(argv.includes("--locked") && argv.includes("--offline")); out = JSON.stringify(metadata);
      } else if (name === "cargo" && argv[0] === "tree") {
        assert.equal(argv[argv.indexOf("--edges") + 1], "normal,build"); assert.equal(argv[argv.indexOf("--target") + 1], TARGET); out = treeText;
      } else if (["cargo", "rustc", "rustdoc"].includes(name) && argv[0] === "-vV") out = `${name} 1.97.1 (fixture)\nhost: ${TARGET}\nLLVM version: 22.1.6\n`;
      else if (name === "rustc" && argv[1] === "sysroot") out = path.join(tools, "sysroot");
      else if (name === "rustc" && argv[1] === "cfg") out = 'target_arch="x86_64"\ntarget_os="linux"\ntarget_env="gnu"\ntarget_pointer_width="64"\n';
      else if (name === "node") out = NODE_VERSION;
      else if (name === "cc" && argv[0] === "-dumpmachine") out = scenario.abi ?? "x86_64-redhat-linux";
      else if (name === "cc" && argv[0] === "-dM") out = "#define __x86_64__ 1\n#define __linux__ 1\n#define __LP64__ 1\n";
      else if (name === "cc" && argv[0] === "-print-prog-name=ld") out = path.join(tools, scenario.wrongLinker ? "ar" : "ld");
      else if (name === "ld.lld" || name === "rust-lld") out = "LLD 22.1.6 (fixture) (compatible with GNU linkers)";
      else if (["cc", "ar", "ld"].includes(name)) out = `GNU ${name} fixture`;
      else assert.fail(`Unexpected probe: ${name} ${argv.join(" ")}`);
      return Buffer.from(out);
    },
    spawnBuild(tool, argv, options, data) {
      assert.ok(argv.includes("--locked") && argv.includes("--offline") && argv.includes("--release"));
      assert.equal(argv[argv.indexOf("--jobs") + 1], "1"); assert.equal(options.env.HOME, undefined);
      assert.equal(options.env.RUSTC, path.join(tools, "rustc")); assert.equal(options.env.RUSTDOC, path.join(tools, "rustdoc"));
      const flags = JSON.parse(argv.find(a => a.startsWith("build.rustflags=")).slice("build.rustflags=".length));
      assert.deepEqual(flags.slice(0, 4), ["-C", "linker-features=-lld", "-C", "link-self-contained=-linker"]);
      if (scenario.fault === "spawn") return spawn("/nonexistent-native-fixture-tool", [], options);
      const artifacts = [];
      for (const p of data.closure.selected) for (const t of p.targets) {
        const shipped = data.closure.shipped.find(s => s.name === t.name && s.packageId === p.id);
        const output = shipped ? path.join(data.compiler, TARGET, "release", t.name) : path.join(data.compiler, "release/deps", `${p.name}-${t.name}`);
        artifacts.push({ reason: "compiler-artifact", package_id: p.id, manifest_path: p.manifest_path, target: t,
          profile: { test: false, opt_level: t.kind.includes("custom-build") ? "0" : "3" }, features: [], fresh: false,
          executable: shipped ? output : null, filenames: [output] });
      }
      const payload = { artifacts, fault: data.label === (scenario.faultBuild ?? "a") ? scenario.fault : null,
        different: scenario.different && data.label === "b", mode: scenario.mode, name: data.closure.shipped[0].name };
      const script = `const fs=require('node:fs'),p=require('node:path'),cp=require('node:child_process'); const d=${JSON.stringify(payload)};
        if(d.fault==='descendant'){process.on('SIGTERM',()=>{});cp.spawn(process.execPath,['-e',"process.on('SIGTERM',()=>{});setInterval(()=>{},1000)"],{stdio:'ignore'});process.stdout.write('{bad json}\\n');setInterval(()=>{},1000);}
        else if(d.fault==='hang'){process.on('SIGTERM',()=>{});setInterval(()=>{},1000);}
        else {for(const a of d.artifacts){const f=a.filenames[0];fs.mkdirSync(p.dirname(f),{recursive:true});fs.writeFileSync(f,'FIXTURE:'+a.target.name+(d.different?'Y':'X'),{mode:d.mode??0o755});}
          if(d.fault==='nonregular'){const f=d.artifacts.find(a=>a.executable).executable;fs.unlinkSync(f);fs.symlinkSync('/dev/null',f);}
          if(d.fault==='missing')d.artifacts=d.artifacts.filter(a=>a.target.name!==d.name);
          if(d.fault==='duplicate')d.artifacts.push(d.artifacts.find(a=>a.executable));
          if(d.fault==='features')d.artifacts[0].features=['usb-hid'];
          if(d.fault==='host-role'){const a=d.artifacts.find(a=>a.target.kind.includes('custom-build'));a.filenames=[p.join(p.dirname(d.artifacts.find(a=>a.executable).executable),'wrong-host-script')];}
          if(d.fault==='target')d.artifacts[0].target.src_path='/escaped/source.rs';
          if(d.fault==='package')d.artifacts[0].package_id='unexpected-package';
          if(d.fault==='escape')d.artifacts.find(a=>a.executable).executable='/escaped/output';
          if(d.fault==='fresh')d.artifacts[0].fresh=true;
          if(d.fault==='unexpected-file')fs.writeFileSync(p.join(p.dirname(d.artifacts.find(a=>a.executable).executable),'pg-only-unobserved'), 'FIXTURE',{mode:0o755});
          process.stderr.write('separate non-JSON stderr fixture\\n');
          if(d.fault==='malformed')process.stdout.write('{bad json}\\n');
          else if(d.fault==='line')process.stdout.write('x'.repeat(${LIMITS.line + 1})+'\\n');
          else {for(const a of d.artifacts)process.stdout.write(JSON.stringify(a)+'\\n');process.stdout.write(JSON.stringify({reason:'build-finished',success:d.fault!=='failed'})+(d.fault==='tail'?'':'\\n'));}process.exitCode=d.fault==='failed'?7:0;}`;
      return spawn(process.execPath, ["-e", script], options);
    },
    async stage(name, ctx) { await scenario.stage?.(name, ctx, { source, tools, dep, parent }); },
  };
  return { args, doubles, source, tools, dep, parent, output, packages };
}
async function badRun(f, pattern, more = () => {}) {
  let caught; try { await runFixtureEvidence(f.args, f.doubles); } catch (e) { caught = e; }
  assert.ok(caught, "Negative control passed"); assert.match(caught.message, pattern); assert.equal(caught.evidence.complete, false);
  const saved = JSON.parse(readFileSync(path.join(f.output, "manifest.json"), "utf8"));
  assert.equal(saved.complete, false); assert.equal(saved.evidenceKind, "fixture"); more(caught.evidence); return caught.evidence;
}

try {
  await check("GNU L archive/source and cargo-ok independent positive", async () => {
    const p = packageFixture("archive-positive"); const r = await verifyRegistryPackage(p);
    assert.equal(r.entries, 5); assert.equal(r.inventory.filter(x => x.kind === "file").length, 4);
    assert.equal(r.marker.present, true); file(path.join(p.expanded, ".cargo-ok"), ""); assert.equal(verifyCargoOk(p.expanded).present, true);
  });
  const archiveCases = [
    ["hash", p => p.checksum = "0".repeat(64), /checksum/],
    ["source-bytes", p => file(path.join(p.expanded, "src/lib.rs"), "// changed library!!\n"), /size mismatch|bytes mismatch/],
    ["extra-file", p => file(path.join(p.expanded, "extra"), "x"), /Unexplained/],
    ["extra-empty-dir", p => mkdirSync(path.join(p.expanded, "extra")), /Unexplained/],
    ["expanded-link", p => { unlinkSync(path.join(p.expanded, "src/lib.rs")); symlinkSync("/dev/null", path.join(p.expanded, "src/lib.rs")); }, /regular|symlink/],
    ["marker-size", p => file(path.join(p.expanded, ".cargo-ok"), "x".repeat(129)), /byte budget/],
    ["marker-extra", p => file(path.join(p.expanded, ".cargo-ok"), '{"v":1,"x":2}'), /cargo-ok/],
    ["marker-duplicate", p => file(path.join(p.expanded, ".cargo-ok"), '{"v":1,"v":1}'), /cargo-ok/],
    ["duplicate", p => replace(p, [...p.entries, p.entries[0]]), /Duplicate/],
    ["escape", p => replace(p, [{ name: "vcpkg-0.2.15/../escape", data: "x" }]), /path/],
    ["root-file", p => replace(p, [{ name: "vcpkg-0.2.15", data: "x" }]), /root/],
    ["link-type", p => replace(p, [{ name: "vcpkg-0.2.15/a", type: "2" }]), /type/],
    ["long-orphan", p => replace(p, [{ name: "././@LongLink", type: "L", data: "vcpkg-0.2.15/a\0" }]), /Orphan|orphan/],
    ["long-repeat", p => replace(p, [{ name: "././@LongLink", type: "L", data: "a\0" }, { name: "././@LongLink", type: "L", data: "b\0" }]), /Repeated/],
    ["long-next", p => replace(p, [{ name: "././@LongLink", type: "L", data: "a\0" }, { name: "a", type: "x" }]), /incompatible/],
    ["long-budget", p => replace(p, [{ name: "././@LongLink", type: "L", data: "x".repeat(4097) + "\0" }]), /GNU L/],
    ["long-nul", p => replace(p, [{ name: "././@LongLink", type: "L", data: "no-terminal-nul" }]), /terminal NUL/],
    ["long-extra-nul", p => replace(p, [{ name: "././@LongLink", type: "L", data: "bad\0name\0" }]), /terminal NUL/],
    ["long-effective-path", p => replace(p, [{ name: "././@LongLink", type: "L", data: "vcpkg-0.2.15/../bad\0" }, { name: "placeholder", data: "x" }]), /path/],
    ["magic", p => replace(p, p.entries, b => b[257] = 120), /magic/],
    ["octal", p => replace(p, p.entries, b => { b[124] = 56; fixChecksum(b); }), /octal/],
    ["utf8", p => replace(p, p.entries, b => { b[0] = 255; fixChecksum(b); }), /encoded data/],
    ["trailing-gzip", p => replace(p, p.entries, null, Buffer.from("trailing")), /trailing/],
    ["second-gzip", p => replace(p, p.entries, null, gzipSync(Buffer.from("next"))), /trailing/],
    ["gzip-crc", p => { const b = readFileSync(p.archive); b[b.length - 8] ^= 1; file(p.archive, b); p.checksum = sha(b); }, /CRC/],
    ["tar-framing", p => { const b = gzipSync(Buffer.from("not tar")); file(p.archive, b); p.checksum = sha(b); }, /Incomplete/],
  ];
  for (const [name, change, pattern] of archiveCases) await check(`archive refusal ${name}`, () => badArchive("archive-" + name, change, pattern));
  await check("immediate archive and GNU metadata budgets", async () => {
    for (const [field, max, pattern] of [["compressed", 10, /compressed/], ["expanded", 10, /entry\/expanded/], ["entries", 3, /entry\/expanded/], ["file", 10, /file\/directory size/]])
      await badArchive("budget-" + field, () => {}, pattern, { ...LIMITS, [field]: max });
  });
  await check("closed CLI and environment; rejected values never printed", () => {
    const f = fixture("cli"); parseCli(f.args); assert.throws(() => parseCli([...f.args, "--test-mode", "fixture"]), /Unknown/);
    assert.throws(() => parseCli([...f.args, "--source", f.source]), /Duplicate/);
    for (const key of ["RUSTFLAGS", "RUSTDOC", "CARGO_PROFILE_RELEASE_LTO", "CC_x86_64", "NODE_OPTIONS", "LD_PRELOAD", "GIT_CONFIG_COUNT", "PKG_CONFIG_PATH"])
      assert.throws(() => validateCallerEnv({ [key]: "DO-NOT-PRINT" }), e => e.message.includes(key) && !e.message.includes("DO-NOT-PRINT"));
    assert.throws(() => parseCli(f.args.map(x => x === f.source ? "relative" : x)), /absolute/);
  });
  await check("full sequential orchestration positive; fixture NEVER native complete", async () => {
    const f = fixture("positive", { mode: 0o751 }); const sentinel = path.join(f.parent, "sentinel"); file(sentinel, "original before run");
    const r = await runFixtureEvidence(f.args, f.doubles, { AWS_SECRET_ACCESS_KEY: "not inherited" });
    assert.equal(r.complete, false); assert.equal(r.fixturePassed, true); assert.equal(r.comparisons.length, 11); assert.equal(r.boundaries.length, 5);
    assert.ok(r.builds.a.artifacts.every(a => a.mode === 0o751)); assert.equal(existsSync(path.join(f.output, "compiler-a")), false);
    assert.equal(existsSync(path.join(f.output, "compiler-b")), false); assert.equal(readFileSync(sentinel, "utf8"), "original before run");
    assert.equal(r.sourceLease.released, true); assert.equal(r.builds.b.exit, 0); assert.match(readFileSync(r.builds.a.logs.stderr, "utf8"), /non-JSON/);
    assert.ok(r.builds.a.observations.dependencies.some(a => a.target.kind.includes("custom-build")));
    assert.equal(r.inputs.tools.linkerRoles.target.linker, path.join(f.tools, "ld"));
    assert.match(r.inputs.tools.linkerRoles.host.implementation, /rust-lld$/);
  });
  for (const [name, scenario, pattern] of [["dirty-index", { dirty: true }, /Dirty/], ["ignored", { untracked: true }, /Untracked/],
    ["abi", { abi: "x86_64-unknown-linux-musl" }, /ABI/], ["linker", { wrongLinker: true }, /supplied linker/]])
    await check("pre-A " + name, async () => { const f = fixture(name, scenario); await badRun(f, pattern, r => assert.equal(r.builds.a.started, false)); });
  const driftCases = [
    ["hidden-source", f => file(path.join(f.source, "apps/cli/src/main.rs"), "// hidden by Git flags\n"), /Tracked/],
    ["tool", f => file(path.join(f.tools, "cc"), "changed tool", 0o755), /Input drift/],
    ["source-config", f => file(path.join(f.source, ".cargo/config.toml"), "[build]\n"), /Cargo config/],
    ["cache-config", f => file(path.join(path.dirname(path.dirname(path.dirname(path.dirname(f.dep.expanded)))), "config.toml"), "[source]\n"), /Cargo config/],
    ["expanded", f => file(path.join(f.dep.expanded, "src/lib.rs"), "// changed bytes!\n"), /size mismatch|bytes mismatch/],
    ["archive", f => { const b = readFileSync(f.dep.archive); b[10] ^= 1; file(f.dep.archive, b); }, /checksum/],
    ["marker", f => file(path.join(f.dep.expanded, ".cargo-ok"), ""), /Input drift/],
    ["host-lld", f => file(path.join(f.tools, "sysroot/lib/rustlib", TARGET, "bin/rust-lld"), "changed host linker", 0o755), /Input drift/],
  ];
  for (const [name, change, pattern] of driftCases) await check("real file recheck " + name, async () => {
    const f = fixture("drift-" + name, { stage(n, ctx, fields) { if (n === "after-a") change(fields); } });
    await badRun(f, pattern, r => { assert.equal(r.builds.a.exit, 0); assert.equal(r.builds.b.started, false); assert.ok(existsSync(path.join(f.output, "compiler-a"))); });
  });
  for (const [fault, pattern] of [["missing", /Missing shipped/], ["duplicate", /duplicate/], ["features", /features/], ["target", /target identity/],
    ["package", /outside selected/], ["escape", /illegal shipped/], ["fresh", /reused/], ["host-role", /not host output/], ["malformed", /Malformed/], ["tail", /Incomplete Cargo/],
    ["line", /line budget/], ["failed", /nonzero/], ["nonregular", /Illegal target release|regular/], ["unexpected-file", /Unexpected target release executable/]]) await check("process/observation " + fault, async () => {
      const f = fixture("build-" + fault, { fault }); await badRun(f, pattern, r => { assert.equal(r.builds.b.started, false);
        assert.equal(r.builds.a.descendantsStopped, true); assert.ok(readFileSync(r.builds.a.logs.stdout).length); assert.ok(existsSync(path.join(f.output, "compiler-a"))); });
    });
  await check("B exit failure retains B and A snapshots", async () => {
    const f = fixture("b-failure", { fault: "failed", faultBuild: "b" }); await badRun(f, /nonzero/, r => {
      assert.equal(r.builds.b.exit, 7); assert.equal(r.builds.a.snapshotVerified, true); assert.ok(existsSync(path.join(f.output, "compiler-b"))); });
  });
  await check("actual spawn failure preserves attempted stage and never starts B", async () => {
    const f = fixture("spawn", { fault: "spawn" }); await badRun(f, /spawn failed/, r => {
      assert.equal(r.builds.a.spawnError, "ENOENT"); assert.equal(r.builds.a.pid, null);
      assert.equal(r.builds.a.descendantsStopped, true); assert.equal(r.builds.b.started, false); });
  });
  await check("A/B byte mismatch retains B", async () => { const f = fixture("mismatch", { different: true }); await badRun(f, /hash mismatch/, r => assert.ok(existsSync(path.join(f.output, "compiler-b")))); });
  await check("resource admission refuses A", async () => {
    const f = fixture("admission"); f.doubles.resources = () => ({ disk: LIMITS.admissionDisk - 1, memory: LIMITS.admissionMemory });
    await badRun(f, /admission/, r => assert.equal(r.builds.a.started, false));
  });
  await check("during-build disk floor stops actual child", async () => {
    let active = false; const f = fixture("disk-abort", { fault: "hang", stage(n) { if (n === "build-a") active = true; } });
    f.doubles.resources = () => ({ disk: active ? LIMITS.abortDisk - 1 : 100 * 1024 ** 3, memory: 16 * 1024 ** 3 });
    await badRun(f, /abort floor/, r => { assert.ok(r.builds.a.signal); assert.equal(r.builds.a.descendantsStopped, true); });
  });
  await check("available-memory admission remains fixed", async () => {
    const f = fixture("memory-admission"); f.doubles.resources = () => ({ disk: 100 * 1024 ** 3, memory: LIMITS.admissionMemory - 1 });
    await badRun(f, /admission/, r => assert.equal(r.builds.a.started, false));
  });
  await check("deadline records actual signal and waits for stopped group", async () => {
    let time = 0; const f = fixture("deadline", { fault: "hang" }); f.doubles.now = () => { time += LIMITS.buildMs + 1; return time; };
    await badRun(f, /deadline/, r => { assert.ok(r.builds.a.signal); assert.equal(r.builds.a.descendantsStopped, true); });
  });
  await check("TERM-ignoring descendants forcibly stop before return", async () => {
    const f = fixture("descendant", { fault: "descendant" }); await badRun(f, /Malformed/, r => {
      assert.equal(r.builds.a.descendantsStopped, true); assert.equal(r.builds.a.signal, "SIGKILL"); });
  });
  await check("runner interruption follows owned group shutdown and incomplete evidence", async () => {
    const f = fixture("interrupt", { fault: "hang" }); const old = f.doubles.spawnBuild;
    f.doubles.spawnBuild = (...args) => { const child = old(...args); setTimeout(() => process.emit("SIGTERM"), 50); return child; };
    await badRun(f, /interrupted by SIGTERM/, r => { assert.equal(r.builds.a.descendantsStopped, true); assert.equal(r.builds.b.started, false); assert.ok(r.builds.a.signal); });
  });
  await check("snapshot source change refuses B", async () => {
    const f = fixture("copy-drift"); f.doubles.afterCopy = ({ src }) => file(src, "changed executable", 0o755);
    await badRun(f, /Snapshot/, r => assert.equal(r.builds.b.started, false));
  });
  await check("artifact sync failure retains partial snapshots/compiler", async () => {
    const f = fixture("artifact-sync"); let failed = false;
    f.doubles.sync = (fd, kind) => { if (kind === "artifact" && !failed) { failed = true; throw new Error("fixture artifact synchronization failure"); } fsyncSync(fd); };
    await badRun(f, /synchronization failure/, r => assert.ok(existsSync(path.join(f.output, "compiler-a"))));
  });
  await check("unsafe cleanup preserves unrelated sentinel created BEFORE checks", async () => {
    const sentinel = path.join(root, "cleanup-sentinel"); file(sentinel, "keep original");
    const f = fixture("unsafe-cleanup", { stage(n, ctx) { if (n === "cleanup-a") symlinkSync(sentinel, path.join(ctx.owner.root, "compiler-a/unsafe-link")); } });
    await badRun(f, /Unsafe cleanup/, r => { assert.equal(r.builds.b.started, false); assert.equal(readFileSync(sentinel, "utf8"), "keep original"); });
  });
  await check("cleanup identity mismatch retains displaced output", async () => {
    const f = fixture("cleanup-owner", { stage(n, ctx) { if (n === "cleanup-a") { const p = path.join(ctx.owner.root, "compiler-a"); renameSync(p, p + "-displaced"); mkdirSync(p, { mode: 0o700 }); } } });
    await badRun(f, /identity mismatch/, r => { assert.equal(r.builds.b.started, false); assert.ok(existsSync(path.join(f.output, "compiler-a-displaced"))); });
  });
  await check("manifest sync failure remains incomplete", async () => {
    let failNext = false; const f = fixture("manifest-sync", { stage(n) { if (n === "snapshot-a") failNext = true; } });
    f.doubles.sync = (fd, kind) => { if (failNext && kind === "file") { failNext = false; throw new Error("fixture manifest sync failed"); } fsyncSync(fd); };
    await badRun(f, /manifest sync/, r => assert.equal(r.builds.b.started, false));
  });
  await check("initial owner synchronization failure retains incomplete evidence", async () => {
    const f = fixture("initial-sync"); let failed = false;
    f.doubles.sync = (fd, kind) => { if (kind === "directory" && !failed) { failed = true; throw new Error("fixture initial owner sync failed"); } fsyncSync(fd); };
    await badRun(f, /initial owner sync/, r => { assert.equal(r.builds.a.started, false); assert.equal(r.sourceLease.acquired, false); });
  });
  await check("missing expanded manifest fails before Cargo introspection or A", async () => {
    const f = fixture("implicit-expansion"); unlinkSync(path.join(f.dep.expanded, "Cargo.toml"));
    const old = f.doubles.execute; let cargoCalled = false;
    f.doubles.execute = (...args) => { if (path.basename(args[0]) === "cargo" && ["metadata", "tree"].includes(args[1][0])) cargoCalled = true; return old(...args); };
    await badRun(f, /implicit expansion/, r => assert.equal(r.builds.a.started, false)); assert.equal(cargoCalled, false);
  });
  await check("saved artifact attachment drift at final input check is incomplete", async () => {
    const f = fixture("saved-drift", { stage(n, ctx) {
      if (n === "final") file(path.join(ctx.owner.root, "artifacts-a", NAMES[0]), "changed saved bytes", 0o755);
    } });
    await badRun(f, /File drift/, r => { assert.equal(r.complete, false); assert.equal(r.builds.b.exit, 0); });
  });
  await check("occupied/overlapping output preserves unrelated data", async () => {
    const f = fixture("occupied"); mkdirSync(f.output); const sentinel = path.join(f.output, "sentinel"); file(sentinel, "keep");
    await assert.rejects(() => runFixtureEvidence(f.args, f.doubles), /Occupied/); assert.equal(readFileSync(sentinel, "utf8"), "keep");
    await assert.rejects(() => runFixtureEvidence(f.args.map(x => x === f.output ? path.join(f.source, "new-evidence") : x), f.doubles), /overlaps/);
  });
  await check("source lease independent of output choice", async () => {
    const f = fixture("lease"); let tested = false;
    f.doubles.stage = async n => { if (n === "build-a") { await assert.rejects(() => runFixtureEvidence(f.args.map(x => x === f.output ? path.join(f.parent, "other-evidence") : x), f.doubles), /EEXIST/); tested = true; } };
    const r = await runFixtureEvidence(f.args, f.doubles); assert.equal(r.fixturePassed, true); assert.equal(tested, true);
  });
  await check("independent comparator, forged hash equality, exact EOF and aliases", () => {
    const a = path.join(root, "bytes-a"), b = path.join(root, "bytes-b"), c = path.join(root, "bytes-c");
    file(a, Buffer.alloc(131073, 65), 0o755); file(b, Buffer.alloc(131073, 65), 0o755); file(c, Buffer.alloc(131073, 66), 0o755);
    assert.equal(compareFiles(a, b, 131073).equal, true); assert.throws(() => compareFiles(a, c, 131073), /byte comparison/);
    const alias = path.join(root, "alias"); linkSync(a, alias); assert.throws(() => compareFiles(a, alias, 131073), /Aliased/); unlinkSync(alias);
    const aa = [], bb = [];
    for (const n of NAMES) for (const [dir, value, list] of [["forged-a", "AX", aa], ["forged-b", "BY", bb]]) {
      const p = path.join(root, dir, n); file(p, value, 0o755); const s = lstatSync(p);
      list.push({ name: n, path: p, packageId: "fixture", size: 2, mode: 0o755, dev: s.dev, ino: s.ino,
        uid: s.uid, nlink: s.nlink, mtime: s.mtimeMs, ctime: s.ctimeMs, sha256: "forged-equal" });
    }
    assert.throws(() => compareArtifacts(aa, bb, { verifyHashes: false }), /byte comparison/);
    assert.throws(() => compareArtifacts(aa.slice(1), bb), /name\/count/);
  });
  await check("production CLI cannot select fixture mode", async () => { const f = fixture("no-bypass"); await assert.rejects(() => runNativeReleaseEvidence([...f.args, "--test-mode", "true"]), /Unknown/); });
  process.stdout.write(`[FIXTURE] ${passed} controls passed; ZERO native builds; native/M7/full acceptance remain unexecuted.\n`);
} finally {
  // Exact mkdtemp directory created by this invocation, never any source/cache/user target.
  rmSync(root, { recursive: true, force: false });
}
