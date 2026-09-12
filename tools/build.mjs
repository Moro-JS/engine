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

import { pathToFileURL } from 'node:url';
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
  // fastApiSha256: the sha256 of deps/v8/include/v8-fast-api-calls.h at that
  // exact nodejs/node tag. Node's headers tarball omits this header (the
  // fast-call ABI is per-V8-version, and the tarball only ships the stable
  // embedder surface), but the node binary exports everything it needs, so
  // the build fetches the tag's own copy and pins it here the way the tarball
  // is pinned by SHASUMS256.txt. Bump the pin when bumping `node`.
  { node: 'v20.11.0', abi: 115, fastApiSha256: '9fb8eacf2e97ffe89c99e6d711632cd287fff55bd999fc5ac99a78f282e7504b' },
  { node: 'v22.0.0', abi: 127, fastApiSha256: 'f76b4fa7d7af6968f9a3bee4e947cb4d181a7d1b6a116c21b11e5cb54c66ec6c' },
  { node: 'v23.0.0', abi: 131, fastApiSha256: '223c9578c7596de7cd5a4cb5a08f398e08685b666b62e17e2d45d284d6e9ccd8' },
  { node: 'v24.0.0', abi: 137, fastApiSha256: 'c6c8b22ebf8014ef5b1cb04bec2af7549754cede52b745474aae1762e060b842' },
  { node: 'v25.0.0', abi: 141, fastApiSha256: 'a4377dddfabf15668b14234a7b8a894ee6f9cd98cae3f39fd7d049c52aef7c0a' },
  { node: 'v26.0.0', abi: 147, fastApiSha256: '507a4e27c3e20e02f21f9155dfa0c808c5af1dc08fcf83039735b05b4e34a1a5' },
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
  // --no-fast-api (or MORO_FAST_API=0): compile without the V8 fast-call
  // targets - no header fetch, plain callbacks only (probe().fastApi.compiled
  // === false). For bisecting and for offline builds.
  const args = {
    all: false,
    abi: null,
    arch: hostArch,
    sanitize: false,
    fastApi: process.env.MORO_FAST_API !== '0',
    // Profile-guided optimisation (tools/pgo.mjs drives the whole cycle):
    //   --pgo=generate            instrumented build, raw profiles under --pgo-dir
    //   --pgo=use --pgo-profile=F optimised build from a merged profile
    // MORO_PGO / MORO_PGO_DIR / MORO_PGO_PROFILE are honoured as the env form.
    pgo: process.env.MORO_PGO || '',
    pgoDir: process.env.MORO_PGO_DIR || join(buildDir, 'pgo'),
    pgoProfile: process.env.MORO_PGO_PROFILE || '',
    // --out-dir: write binaries somewhere other than build/ (an instrumented
    // build must not replace the shippable one; the loader can be pointed at
    // it with MORO_ENGINE_BINARY).
    outDir: buildDir,
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    const eq = a.indexOf('=');
    const key = eq === -1 ? a : a.slice(0, eq);
    const val = eq === -1 ? null : a.slice(eq + 1);
    if (key === '--all') args.all = true;
    else if (key === '--abi') args.abi = parseInt(val ?? argv[++i], 10);
    else if (key === '--arch') args.arch = val ?? argv[++i];
    else if (key === '--sanitize') args.sanitize = true;
    else if (key === '--no-fast-api') args.fastApi = false;
    else if (key === '--pgo') args.pgo = val ?? argv[++i];
    else if (key === '--pgo-dir') args.pgoDir = val ?? argv[++i];
    else if (key === '--pgo-profile') args.pgoProfile = val ?? argv[++i];
    else if (key === '--out-dir') args.outDir = val ?? argv[++i];
    else throw new Error(`unknown argument: ${a}`);
  }
  if (args.pgo && !['generate', 'use'].includes(args.pgo)) {
    throw new Error(`--pgo must be "generate" or "use", got "${args.pgo}"`);
  }
  if (args.pgo === 'use' && !args.pgoProfile) {
    throw new Error('--pgo=use requires --pgo-profile=<file.profdata|.pgd>');
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

// The one V8 header the tarball omits (see TARGETS.fastApiSha256): fetched
// from the exact tag and verified against the pinned sha256 before it can
// reach the compiler. Idempotent: a present file that matches the pin is
// reused; a present file that does NOT match is replaced (never trusted).
function sha256File(file) {
  return createHash('sha256').update(readFileSync(file)).digest('hex');
}

async function fetchFastApiHeader(nodeVersion, includeDir, expectedSha) {
  const dest = join(includeDir, 'v8-fast-api-calls.h');
  if (existsSync(dest) && sha256File(dest) === expectedSha) return dest;
  const url = `https://raw.githubusercontent.com/nodejs/node/${nodeVersion}/deps/v8/include/v8-fast-api-calls.h`;
  const tmp = `${dest}.download`;
  console.log(`  fetching ${url}`);
  await download(url, tmp);
  const actual = sha256File(tmp);
  if (actual !== expectedSha) {
    rmSync(tmp);
    throw new Error(
      `checksum mismatch for v8-fast-api-calls.h (${nodeVersion}): expected ${expectedSha}, got ${actual}`
    );
  }
  renameSync(tmp, dest);
  return dest;
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

// Toolchain probes (cached): which C++ compiler, and whether clang can link
// with lld (clang's -flto needs an LTO-aware linker; GNU ld without the gold
// plugin silently produces a non-LTO binary or fails).
let toolchainCache = null;
function toolchain() {
  if (toolchainCache) return toolchainCache;
  let cxx = process.env.CXX;
  if (!cxx) {
    if (platform === 'linux') {
      // Prefer clang (PGO profiles + the LLVM toolchain the darwin/musl lanes
      // already use); g++ remains fully supported when clang is absent or
      // when CXX says so (the sanitizer lane pins g++ for its LD_PRELOAD flow).
      cxx = which('clang++') ? 'clang++' : 'g++';
    } else {
      cxx = 'clang++';
    }
  }
  const isClang = /clang/.test(cxx) || (() => {
    try {
      return /clang/.test(execFileSync(cxx, ['--version'], { encoding: 'utf8' }));
    } catch {
      return false;
    }
  })();
  let lld = false;
  if (isClang && platform === 'linux') {
    lld = !!(which('ld.lld') || which('lld'));
  }
  toolchainCache = { cxx, isClang, lld };
  return toolchainCache;
}

function which(bin) {
  try {
    return execFileSync(platform === 'win32' ? 'where' : 'which', [bin], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim() || null;
  } catch {
    return null;
  }
}

function compile({ includeDir, abi, arch, sanitize, libFile = null, fastApi = false, pgo = '', pgoDir = '', pgoProfile = '', outDir = buildDir }) {
  mkdirSync(outDir, { recursive: true });
  const output = join(outDir, `moro_engine_${platform}_${arch}${libcTag()}_${abi}.node`);
  const sources = [join(root, 'src', 'binding.cpp')];

  // Profile-guided optimisation (clang spelling; tools/pgo.mjs drives the
  // generate -> train -> merge -> use cycle, and never fails a build over it).
  // Branch-heavy parser/state-machine code typically gains 5-15% from PGO.
  // -Wno-profile-instr-*: a profile trained on one ABI's build is reused for
  // the others (the engine code is identical; only V8-header inlines differ),
  // so "out of date"/"unprofiled function" notes are expected, not errors.
  const tc = toolchain();
  const pgoFlags = [];
  if (!sanitize && platform !== 'win32' && pgo) {
    if (!tc.isClang) throw new Error(`--pgo needs clang (CXX=${tc.cxx})`);
    if (pgo === 'generate') {
      pgoFlags.push(`-fprofile-generate=${pgoDir}`);
    } else if (pgo === 'use') {
      pgoFlags.push(`-fprofile-use=${pgoProfile}`, '-Wno-profile-instr-out-of-date', '-Wno-profile-instr-unprofiled', '-Wno-backend-plugin');
    }
  }
  // clang's -flto needs lld (or a gold plugin); without it, build without LTO
  // rather than fail - the single-TU build loses little to LTO anyway.
  const wantLto = !sanitize;
  const ltoFlags = wantLto
    ? tc.isClang && platform === 'linux' && !tc.lld
      ? (console.warn('  warning: clang without lld - building without -flto'), [])
      : ['-flto']
    : [];

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
        ...ltoFlags,
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
    ...pgoFlags,
    // x64 ISA floor: x86-64-v2 (SSE4.2/POPCNT, ~2009 Nehalem and later;
    // RHEL 9's baseline). arm64 ISA floor: armv8.2-a (Neoverse/Graviton2,
    // Apple Silicon and later). Release-only so the sanitizer lane's flags
    // stay exactly as-is.
    ...(!sanitize && arch === 'x64' ? ['-march=x86-64-v2'] : []),
    ...(!sanitize && arch === 'arm64' ? ['-march=armv8.2-a'] : []),
    '-fvisibility=hidden',
    `-I${includeDir}`,
    '-DBUILDING_NODE_EXTENSION',
    // V8 fast-call targets (src/fast_api.h) compile in only when the per-tag
    // header was fetched + verified (see fetchFastApiHeader).
    ...(fastApi ? ['-DMORO_FAST_API=1'] : []),
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
    cmd = tc.cxx;
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
    cmd = tc.cxx;
    args = [
      ...common,
      '-fPIC',
      ...(tc.isClang && tc.lld ? ['-fuse-ld=lld'] : []),
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
      ...(fastApi ? ['/DMORO_FAST_API=1'] : []),
      '/DNOMINMAX',
      '/DWIN32_LEAN_AND_MEAN',
      `/I${includeDir}`,
      '/LD',
      ...sources,
      `/Fo${buildDir}\\`,
      '/link',
      // MSVC PGO (best effort, tools/pgo.mjs): instrument, train with
      // pgort140.dll on PATH, then optimise from the .pgd.
      ...(pgo === 'generate' ? ['/LTCG:PGINSTRUMENT', `/PGD:${pgoProfile || join(pgoDir, 'moro.pgd')}`]
        : pgo === 'use' ? ['/LTCG:PGOPTIMIZE', `/PGD:${pgoProfile}`]
        : ['/LTCG']),
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
        (args.sanitize ? ' [ASan/UBSan]' : '') +
        (args.pgo ? ` [pgo:${args.pgo}]` : '') +
        (args.outDir !== buildDir ? ` -> ${args.outDir}` : '')
    );
    const includeDir = await fetchHeaders(target.node);
    const libFile = platform === 'win32' ? await fetchWinLib(target.node, args.arch) : null;
    let fastApi = false;
    if (args.fastApi) {
      await fetchFastApiHeader(target.node, includeDir, target.fastApiSha256);
      fastApi = true;
    } else {
      console.log('  fast API calls: disabled (--no-fast-api / MORO_FAST_API=0)');
    }
    compile({
      includeDir,
      abi: target.abi,
      arch: args.arch,
      sanitize: args.sanitize,
      libFile,
      fastApi,
      pgo: args.pgo,
      pgoDir: args.pgoDir,
      pgoProfile: args.pgoProfile,
      outDir: args.outDir,
    });
  }
  console.log('done');
}

// Run only as the entry point: `import { TARGETS } from './build.mjs'` (the
// release/PGO tooling, ad-hoc pin checks) must not start a build.
if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  main().catch(err => {
    console.error(err.message);
    process.exit(1);
  });
}
