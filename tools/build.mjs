#!/usr/bin/env node
// Build driver for @morojs/engine native binaries.
//
// For each target Node ABI: download the matching Node headers, then compile
// src/ with the host toolchain into
// build/moro_engine_<platform>_<arch>[_<libc>]_<abi>.node (libc segment on
// linux only — gnu|musl — so glibc and musl artifacts can never collide).
//
// Usage:
//   node tools/build.mjs                 # build for the running Node's ABI only
//   node tools/build.mjs --all           # build every ABI in TARGETS
//   node tools/build.mjs --abi 137       # build one specific ABI
//   node tools/build.mjs --arch x64      # cross-target arch (darwin only)
//   node tools/build.mjs --sanitize      # ASan/UBSan debug build (CI sanitizer job)
//
// Raw-V8 bindings are ABI-specific by design (maximum perf), so a
// new Node release = one line added to TARGETS + a CI run.

import { execFileSync } from 'child_process';
import { mkdirSync, existsSync, createWriteStream, rmSync, readFileSync, renameSync } from 'fs';
import { createHash } from 'crypto';
import { get } from 'https';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import os from 'os';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const buildDir = join(root, 'build');
const headersDir = join(buildDir, 'headers');

// Node version -> ABI (node_module_version). Add a line per new Node major.
export const TARGETS = [
  { node: 'v20.11.0', abi: 115 },
  { node: 'v22.0.0', abi: 127 },
  { node: 'v23.0.0', abi: 131 },
  { node: 'v24.0.0', abi: 137 },
  { node: 'v25.0.0', abi: 141 },
  { node: 'v26.0.0', abi: 147 },
];

const platform = os.platform(); // darwin | linux | win32
const hostArch = os.arch() === 'arm64' ? 'arm64' : 'x64';

// Binary filenames carry the libc flavor on linux (gnu|musl) so that glibc and
// musl builds of the same arch/ABI can coexist in one artifact store. Detected
// from the running Node, which matches the toolchain: CI builds musl inside an
// alpine container and glibc on ubuntu.
function libcTag() {
  if (platform !== 'linux') return '';
  try {
    const report = process.report && process.report.getReport();
    return report && report.header && report.header.glibcVersionRuntime ? '_gnu' : '_musl';
  } catch {
    return '_gnu';
  }
}

function parseArgs(argv) {
  const args = { all: false, abi: null, arch: hostArch, sanitize: false };
  for (let i = 2; i < argv.length; i++) {
    if (argv[i] === '--all') args.all = true;
    else if (argv[i] === '--abi') args.abi = parseInt(argv[++i], 10);
    else if (argv[i] === '--arch') args.arch = argv[++i];
    else if (argv[i] === '--sanitize') args.sanitize = true;
  }
  if (args.arch !== hostArch && platform !== 'darwin') {
    // Only the darwin branch passes -target; anywhere else a foreign --arch
    // would silently emit host-arch code under a mislabeled filename.
    throw new Error(`--arch ${args.arch} cross-compilation is only supported on darwin`);
  }
  return args;
}

function download(url, dest) {
  return new Promise((resolve, reject) => {
    get(url, res => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return download(res.headers.location, dest).then(resolve, reject);
      }
      if (res.statusCode !== 200) {
        return reject(new Error(`GET ${url} -> ${res.statusCode}`));
      }
      const out = createWriteStream(dest);
      res.pipe(out);
      out.on('finish', () => out.close(resolve));
      out.on('error', reject);
    }).on('error', reject);
  });
}

// Verify the headers tarball against the SHASUMS256.txt published alongside it
// on nodejs.org, so a tampered or corrupted download can't feed the compiler.
function verifyChecksum(tarball, shasumsFile, entryName) {
  const shasums = readFileSync(shasumsFile, 'utf8');
  const line = shasums.split('\n').find(l => l.trim().endsWith(entryName));
  if (!line) {
    throw new Error(`${entryName} not listed in SHASUMS256.txt`);
  }
  const expected = line.trim().split(/\s+/)[0];
  const actual = createHash('sha256').update(readFileSync(tarball)).digest('hex');
  if (actual !== expected) {
    throw new Error(`checksum mismatch for ${entryName}: expected ${expected}, got ${actual}`);
  }
}

// Windows: raw-V8 addons link against node.lib (the import library for every
// symbol node.exe exports - v8, libuv, OpenSSL, zlib). Downloaded per Node
// version from nodejs.org and checksum-verified exactly like the headers
// tarball (the same SHASUMS256.txt lists `win-x64/node.lib`).
async function fetchWinLib(nodeVersion, arch) {
  const winArch = arch === 'arm64' ? 'win-arm64' : 'win-x64';
  const dir = join(headersDir, nodeVersion);
  const libFile = join(dir, `node-${winArch}.lib`);
  if (existsSync(libFile)) return libFile;

  mkdirSync(dir, { recursive: true });
  const entryName = `${winArch}/node.lib`;
  const tmp = join(dir, 'node.lib.download');
  const shasumsFile = join(dir, 'SHASUMS256-winlib.txt');
  const base = `https://nodejs.org/dist/${nodeVersion}`;
  console.log(`  fetching ${base}/${entryName}`);
  await download(`${base}/${entryName}`, tmp);
  await download(`${base}/SHASUMS256.txt`, shasumsFile);
  verifyChecksum(tmp, shasumsFile, entryName);
  rmSync(shasumsFile);
  renameSync(tmp, libFile);
  return libFile;
}

async function fetchHeaders(nodeVersion) {
  const dir = join(headersDir, nodeVersion);
  const includeDir = join(dir, `node-${nodeVersion}`, 'include', 'node');
  if (existsSync(includeDir)) return includeDir;

  mkdirSync(dir, { recursive: true });
  const entryName = `node-${nodeVersion}-headers.tar.gz`;
  const tarball = join(dir, 'headers.tar.gz');
  const shasumsFile = join(dir, 'SHASUMS256.txt');
  const base = `https://nodejs.org/dist/${nodeVersion}`;
  console.log(`  fetching ${base}/${entryName}`);
  await download(`${base}/${entryName}`, tarball);
  await download(`${base}/SHASUMS256.txt`, shasumsFile);
  verifyChecksum(tarball, shasumsFile, entryName);
  execFileSync('tar', ['-xzf', tarball, '-C', dir]);
  rmSync(tarball);
  rmSync(shasumsFile);
  if (!existsSync(includeDir)) {
    throw new Error(`headers extracted but ${includeDir} not found`);
  }
  return includeDir;
}

function compile({ includeDir, abi, arch, sanitize, libFile = null }) {
  const output = join(buildDir, `moro_engine_${platform}_${arch}${libcTag()}_${abi}.node`);
  const sources = [join(root, 'src', 'binding.cpp')];

  const modeFlags = sanitize
    ? [
        // Sanitizer build (CI only, never shipped): debuggable, halt on the
        // first finding. FORTIFY/LTO are omitted — FORTIFY needs -O2+ and
        // interferes with ASan interceptors.
        '-O1',
        '-g',
        '-fno-omit-frame-pointer',
        '-fsanitize=address,undefined',
        '-fno-sanitize-recover=all',
      ]
    : [
        '-O3',
        '-flto',
        // Release + hardening: this addon parses untrusted network input, so a
        // hypothetical future memory bug should at least hit stack canaries and
        // fortified libc calls instead of being silently exploitable.
        '-DNDEBUG',
        '-fstack-protector-strong',
        '-D_FORTIFY_SOURCE=2',
        // src/ uses no exceptions or RTTI, and the V8 headers compile with
        // both off (node core itself builds this way) — drop the machinery.
        '-fno-exceptions',
        '-fno-rtti',
      ];

  const common = [
    '-std=c++20',
    ...modeFlags,
    // x64 ISA floor: x86-64-v2 (SSE4.2/POPCNT, ~2009 Nehalem and later;
    // RHEL 9's baseline). arm64 stays at the compiler's default armv8-a.
    // Release-only so the sanitizer lane's flags stay exactly as-is.
    ...(!sanitize && arch === 'x64' ? ['-march=x86-64-v2'] : []),
    '-fvisibility=hidden',
    `-I${includeDir}`,
    '-DBUILDING_NODE_EXTENSION',
    '-shared',
    '-o',
    output,
    ...sources,
  ];

  let cmd;
  let args;
  if (platform === 'darwin') {
    // Honor CXX (as the linux path does). Node 25/26's V8 headers use braced-
    // init template arguments (P2308) that need clang 18+, newer than the Apple
    // clang on GitHub's macOS runners — CI points CXX at Homebrew LLVM. Local
    // dev defaults to Apple clang.
    cmd = process.env.CXX || 'clang++';
    // Point the compiler at the macOS SDK. Homebrew clang otherwise uses its own
    // libc++, which clashes with the system C library (unresolved ldiv_t etc.);
    // Apple clang already uses the SDK, so this is a harmless explicit there.
    const sdk = execFileSync('xcrun', ['--show-sdk-path'], { encoding: 'utf8' }).trim();
    args = [
      ...common,
      '-fPIC',
      '-undefined',
      'dynamic_lookup',
      '-target',
      `${arch === 'arm64' ? 'arm64' : 'x86_64'}-apple-macos12`,
      '-isysroot',
      sdk,
    ];
  } else if (platform === 'linux') {
    cmd = process.env.CXX || 'g++';
    args = [
      ...common,
      '-fPIC',
      '-static-libstdc++',
      '-static-libgcc',
      // Linker hardening: read-only relocations, immediate binding, NX stack.
      '-Wl,-z,relro,-z,now',
      '-Wl,-z,noexecstack',
    ];
  } else if (platform === 'win32') {
    if (sanitize) {
      // MSVC has /fsanitize=address but no UBSan and no LD_PRELOAD-style
      // conformance-run story; the sanitizer lane stays on Linux.
      throw new Error('--sanitize is supported on linux/darwin only');
    }
    if (!libFile) throw new Error('win32 build requires node.lib (fetchWinLib)');
    cmd = 'cl.exe';
    // Flag parity with the POSIX release build (documented mapping):
    //   -O3 -flto              -> /O2 /GL + /LTCG (link)
    //   -fstack-protector-strong -> /GS (on by default; kept explicit)
    //   FORTIFY/relro/now      -> /guard:cf /DYNAMICBASE /HIGHENTROPYVA
    //                             /NXCOMPAT (PE-world equivalents)
    //   -fvisibility=hidden    -> PE exports are opt-in already
    // /DELAYLOAD:node.exe + delayimp.lib + the hook in
    // src/win_delay_load_hook.h bind the imports to whatever process hosts
    // the addon (renamed node, embedders) at first call.
    args = [
      '/nologo',
      '/std:c++20',
      // No throw/dynamic_cast in src; V8 headers compile with exceptions and
      // RTTI off (as node core does) — mirrors -fno-exceptions/-fno-rtti.
      '/EHs-c-',
      '/D_HAS_EXCEPTIONS=0',
      '/GR-',
      '/O2',
      '/GL',
      '/GS',
      '/guard:cf',
      '/Zc:__cplusplus',
      '/DNDEBUG',
      '/DBUILDING_NODE_EXTENSION',
      '/DNOMINMAX',
      '/DWIN32_LEAN_AND_MEAN',
      `/I${includeDir}`,
      '/LD',
      ...sources,
      `/Fo${buildDir}\\`,
      '/link',
      '/LTCG',
      '/guard:cf',
      '/DYNAMICBASE',
      '/HIGHENTROPYVA',
      '/NXCOMPAT',
      '/DELAYLOAD:node.exe',
      libFile,
      'delayimp.lib',
      `/OUT:${output}`,
    ];
  } else {
    throw new Error(`unsupported platform: ${platform}`);
  }

  console.log(`  ${cmd} -> ${output}`);
  execFileSync(cmd, args, { stdio: 'inherit' });
  return output;
}

async function main() {
  const args = parseArgs(process.argv);
  mkdirSync(buildDir, { recursive: true });

  let targets;
  if (args.all) targets = TARGETS;
  else if (args.abi) targets = TARGETS.filter(t => t.abi === args.abi);
  else targets = TARGETS.filter(t => t.abi === parseInt(process.versions.modules, 10));

  if (targets.length === 0) {
    console.error(
      `No target for ABI ${args.abi ?? process.versions.modules}. Known: ${TARGETS.map(t => t.abi).join(', ')}`
    );
    process.exit(1);
  }

  for (const target of targets) {
    console.log(
      `Building ABI ${target.abi} (Node ${target.node}) for ${platform}/${args.arch}` +
        (args.sanitize ? ' [ASan/UBSan]' : '')
    );
    const includeDir = await fetchHeaders(target.node);
    const libFile = platform === 'win32' ? await fetchWinLib(target.node, args.arch) : null;
    compile({ includeDir, abi: target.abi, arch: args.arch, sanitize: args.sanitize, libFile });
  }
  console.log('done');
}

main().catch(err => {
  console.error(err.message);
  process.exit(1);
});
