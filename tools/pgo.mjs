#!/usr/bin/env node
// Profile-guided build cycle, never a build failure:
//
//   1. plain release build (the safety net - always produced first)
//   2. instrumented build for the RUNNING Node's ABI into build/pgo-instr/
//   3. training workload (tools/pgo-train.mjs + the node --test suites)
//      against that binary via MORO_ENGINE_BINARY
//   4. llvm-profdata merge -> build/pgo/moro.profdata
//   5. optimised build (--pgo=use) for every requested ABI, replacing the
//      plain binaries only after test/smoke.mjs passes against the new one
//
// Any failure in 2-5 leaves the plain binaries from step 1 in place and exits
// 0 with a warning, unless --strict (the dedicated CI lane), which exits 1.
// One profile per platform/arch is reused across ABIs: the engine code is
// identical, only V8-header inlines differ (build.mjs silences the resulting
// "unprofiled function" notes).
//
//   node tools/pgo.mjs [--all | --abi N] [--arch A] [--strict] [--seconds=N] [--no-suites]
//
// Windows: MSVC PGO is attempted the same way (/LTCG:PGINSTRUMENT -> train
// with pgort140.dll on PATH -> /LTCG:PGOPTIMIZE) and falls back identically.

import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync, rmSync, copyFileSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const buildDir = join(root, 'build');
const instrDir = join(buildDir, 'pgo-instr');
const profDir = join(buildDir, 'pgo');
const platform = process.platform;
const argv = process.argv.slice(2);
const strict = argv.includes('--strict');
const passThrough = argv.filter((a) => !a.startsWith('--strict') && !a.startsWith('--seconds') && !a.startsWith('--no-suites'));
const seconds = argv.find((a) => a.startsWith('--seconds='))?.slice('--seconds='.length) ?? '4';
const noSuites = argv.includes('--no-suites');
const hostAbi = parseInt(process.versions.modules, 10);
// Instrumentation and training always happen on the HOST arch (the profile
// is IR-level and applies to a cross-compiled --arch build just as well - the
// darwin x64 binaries are built on arm64 hosts from the arm64 profile).
const hostArch = process.arch;

function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { cwd: root, stdio: 'inherit', shell: platform === 'win32', ...opts });
  if (r.status !== 0) throw new Error(`${cmd} ${args.join(' ')} exited ${r.status}`);
}

function findProfdata() {
  // Distros ship versioned names only (Debian's `llvm` = llvm-profdata-14;
  // apt.llvm.org = -18/-19/-20/-21); try those, then whatever llvm-config or
  // the clang on PATH points at.
  const versioned = [];
  for (let v = 22; v >= 14; v--) versioned.push(`llvm-profdata-${v}`);
  for (const cand of [process.env.LLVM_PROFDATA, 'llvm-profdata', ...versioned]) {
    if (!cand) continue;
    try {
      execFileSync(cand, ['--version'], { stdio: 'ignore' });
      return cand;
    } catch {
      // next
    }
  }
  for (const cfg of ['llvm-config', ...Array.from({ length: 9 }, (_, i) => `llvm-config-${22 - i}`)]) {
    try {
      const bin = join(execFileSync(cfg, ['--bindir'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim(), 'llvm-profdata');
      if (existsSync(bin)) return bin;
    } catch {
      // next
    }
  }
  try {
    const clang = execFileSync(platform === 'win32' ? 'where' : 'which', [process.env.CXX || 'clang++'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim().split('\n')[0];
    if (clang) {
      const bin = join(dirname(clang), 'llvm-profdata');
      if (existsSync(bin)) return bin;
    }
  } catch {
    // none
  }
  if (platform === 'darwin') {
    for (const p of ['/opt/homebrew/opt/llvm/bin/llvm-profdata', '/usr/local/opt/llvm/bin/llvm-profdata']) {
      if (existsSync(p)) return p;
    }
    try {
      return execFileSync('xcrun', ['-f', 'llvm-profdata'], { encoding: 'utf8' }).trim();
    } catch {
      // none
    }
  }
  return null;
}

function binaryName(abi) {
  let libc = '';
  if (platform === 'linux') libc = existsSync('/etc/alpine-release') ? '_musl' : '_gnu';
  return `moro_engine_${platform}_${hostArch}${libc}_${abi}.node`;
}

function fail(msg) {
  if (strict) {
    console.error(`pgo: ${msg}`);
    process.exit(1);
  }
  console.warn(`pgo: ${msg} - keeping the plain build`);
  process.exit(0);
}

// 1. plain build (the safety net)
console.log('pgo: [1/5] plain build');
run(process.execPath, [join(root, 'tools', 'build.mjs'), ...passThrough]);

if (platform === 'win32' && !process.env.MORO_PGO_WINDOWS) {
  // MSVC PGO needs pgort140.dll reachable by the training node process and a
  // matching VS toolset; opt in with MORO_PGO_WINDOWS=1 (the release lane
  // sets it once the toolchain there is verified).
  console.log('pgo: MSVC PGO not enabled (MORO_PGO_WINDOWS unset) - plain build kept');
  process.exit(0);
}

const profdata = platform === 'win32' ? null : findProfdata();
if (platform !== 'win32' && !profdata) fail('llvm-profdata not found (install llvm)');

try {
  // 2. instrumented build for the host ABI, into a side directory
  console.log(`pgo: [2/5] instrumented build (ABI ${hostAbi}) -> ${instrDir}`);
  rmSync(instrDir, { recursive: true, force: true });
  rmSync(profDir, { recursive: true, force: true });
  mkdirSync(profDir, { recursive: true });
  const pgd = join(profDir, 'moro.pgd');
  run(process.execPath, [
    join(root, 'tools', 'build.mjs'),
    '--abi',
    String(hostAbi),
    '--arch',
    hostArch,
    '--pgo=generate',
    `--pgo-dir=${profDir}`,
    ...(platform === 'win32' ? [`--pgo-profile=${pgd}`] : []),
    `--out-dir=${instrDir}`,
  ]);
  const instrBinary = join(instrDir, binaryName(hostAbi));
  if (!existsSync(instrBinary)) throw new Error(`instrumented binary missing: ${instrBinary}`);

  // 3. train
  console.log('pgo: [3/5] training');
  const env = {
    ...process.env,
    MORO_ENGINE_BINARY: instrBinary,
    // %p-%m: one file per process (the suites spawn many), merged below.
    LLVM_PROFILE_FILE: join(profDir, 'moro-%p-%m.profraw'),
  };
  run(process.execPath, [join(root, 'tools', 'pgo-train.mjs'), `--seconds=${seconds}`, ...(noSuites ? ['--no-suites'] : [])], { env });

  // 4. merge
  let profile;
  if (platform === 'win32') {
    // The instrumented link writes moro.pgd; training appends moro!N.pgc
    // files next to it, which /LTCG:PGOPTIMIZE merges on its own.
    profile = pgd;
    if (!existsSync(profile)) throw new Error('no .pgd produced');
  } else {
    const raws = readdirSync(profDir).filter((f) => f.endsWith('.profraw')).map((f) => join(profDir, f));
    if (raws.length === 0) throw new Error('training produced no .profraw files');
    profile = join(profDir, 'moro.profdata');
    console.log(`pgo: [4/5] merging ${raws.length} raw profiles`);
    run(profdata, ['merge', '-o', profile, ...raws]);
  }

  // 5. optimised build over the requested ABIs; verify with smoke before
  //    letting it replace the plain binaries.
  console.log('pgo: [5/5] optimised build');
  const optDir = join(buildDir, 'pgo-opt');
  rmSync(optDir, { recursive: true, force: true });
  run(process.execPath, [
    join(root, 'tools', 'build.mjs'),
    ...passThrough,
    '--pgo=use',
    `--pgo-profile=${profile}`,
    `--out-dir=${optDir}`,
  ]);
  const optHost = join(optDir, binaryName(hostAbi));
  if (existsSync(optHost)) {
    run(process.execPath, [join(root, 'test', 'smoke.mjs')], { env: { ...process.env, MORO_ENGINE_BINARY: optHost } });
  }
  let n = 0;
  for (const f of readdirSync(optDir)) {
    if (!f.endsWith('.node')) continue;
    copyFileSync(join(optDir, f), join(buildDir, f));
    n++;
  }
  rmSync(optDir, { recursive: true, force: true });
  rmSync(instrDir, { recursive: true, force: true });
  console.log(`pgo: done - ${n} PGO-optimised binar${n === 1 ? 'y' : 'ies'} in build/ (profile: ${profile}, ${statSync(profile).size} bytes)`);
} catch (err) {
  fail(err.message);
}
