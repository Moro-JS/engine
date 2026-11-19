#!/usr/bin/env node
// Profile-guided build cycle, never a build failure:
//
//   1. plain release build of every requested binary (the safety net - always
//      produced first)
//   2. for each requested ABI that has a Node.js to train under:
//        instrumented build into build/pgo-instr/
//        training workload (tools/pgo-train.mjs) against that binary via
//        MORO_ENGINE_BINARY, each training group into its own directory
//        merge: the groups scaled to their shares -> one profile for that ABI
//   3. optimised build (--pgo=use) of every requested ABI from its own
//      profile, replacing the plain binaries only after test/smoke.mjs passes
//      against the new one
//
// A failure in 2-3 leaves the plain binaries from step 1 in place for the
// binaries it concerns and exits 0 with a warning, unless --strict (the
// dedicated CI lanes), which exits 1.
//
// One profile per ABI and architecture. A profile is matched to the code by a
// hash of each function's control flow, taken after the small functions it
// calls have been inlined into it - and those include the inline functions of
// the V8 headers, which differ from one Node.js line to the next. Built from
// another ABI's profile, the functions that touch V8 most (the response and
// accessor entry points, the dispatch loop) lose theirs and are compiled as
// unprofiled code; built for x64 from an arm64 profile, so does everything
// with a line of architecture-specific code in it. So each ABI is trained
// under a Node.js of that ABI: the one running this script, and for the
// others a pinned release (TRAINING_NODES below; or MORO_PGO_NODES, a
// path-list of node binaries to use first). An ABI nothing here can run (no
// build of that Node.js for the platform; darwin x64 without Rosetta 2) is
// built from the nearest ABI's profile, as every ABI but the running one was
// before 1.2.0.
//
// The test suites are a training group like the others, but run once: their
// profile is merged into every ABI's (a function whose hash differs there
// keeps the counts of its own training and simply has none from the suites).
// The profile is trained on the BoringSSL binary, the one the loader prefers,
// and reused for the one on node's OpenSSL (eight of its functions, the TLS
// session's, lose theirs there; trained on its own that binary came out 1.4%
// slower per HTTPS request, so it is not).
//
// The bundled TLS library has a profile of its own, one per architecture:
// after the engine's training, one more instrumented build - this time with
// the library instrumented as well - runs the TLS and HTTP/2 groups, and
// libssl is built from what they recorded (tools/boringssl.mjs,
// prelinkBoringSsl). The engine's profiles above come from builds whose
// library is not instrumented, so they hold the engine's counts only and the
// engine's code does not change with the library's.
//
//   node tools/pgo.mjs [--all | --abi N[,N...]] [--arch A] [--tls=T] [--strict]
//                      [--seconds=N] [--no-suites] [--no-fetch]
//
// Windows (MORO_PGO_WINDOWS=1): MSVC's profile database belongs to the one
// link that created it, so there each binary (ABI and TLS library) gets its
// own cycle: /LTCG:PGINSTRUMENT -> train with pgort140.dll on PATH -> pgomgr
// /merge -> /LTCG:PGOPTIMIZE. The suites train the running ABI's binaries only.

import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, copyFileSync, statSync, chmodSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { delimiter, dirname, join } from 'node:path';
import { TARGETS, download, boringSslLto } from './build.mjs';
import { TRAINING_GROUPS } from './pgo-train.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const buildDir = join(root, 'build');
const instrDir = join(buildDir, 'pgo-instr');
const profDir = join(buildDir, 'pgo');
const optDir = join(buildDir, 'pgo-opt');
const nodesDir = join(buildDir, 'pgo-nodes');
const platform = process.platform;
const hostAbi = parseInt(process.versions.modules, 10);
const hostArch = process.arch === 'arm64' ? 'arm64' : 'x64';
const musl = platform === 'linux' && existsSync('/etc/alpine-release');

// The Node.js each ABI is trained under when it is not the one running this
// script: the newest release of the line when this table was last touched,
// and the sha256 of its archive per platform (of node.exe itself on Windows).
// From nodejs.org/dist/<version>/SHASUMS256.txt; the musl builds are the
// Node.js project's unofficial-builds, the ones the node:*-alpine images are
// made of. The binary only has to have the ABI, so these need not follow
// every release; add an entry with each line added to TARGETS in build.mjs.
// A platform without an entry (there is no musl arm64 build of Node 23) is
// built from the nearest ABI's profile.
export const TRAINING_NODES = {
  115: {
    node: 'v20.20.2',
    sha256: {
      'linux-x64': '19e56f0825510207dd904f087fe52faa0a4eb6b2aab5f0ea7a33830d04888b8b',
      'linux-arm64': '47ef73d543ecf6eb19435f6c03a0ac4809b3bf0dd6b26c7c571efc2a6572a74d',
      'linux-x64-musl': '0a335b43b5f0a3279d9c411b333a55ce98c02b875ba14033952c809ef89ac773',
      'linux-arm64-musl': '7549872a8d1be4670d5219f39dc0aed6e6432c976f3cd25543bc249aa850f041',
      'darwin-arm64': '466e05f3477c20dfb723054dfebffe55bc74660ee77f612166fca121dacb65b6',
      'darwin-x64': '8be6f5e4bb128c82774f8a0b8d7a1cc1365a7977d9657cece0ca647b3fe04e61',
      'win32-x64': '56c1520ee33b801e8bdb92fb321cf2e98529735b6d12bd4a2a6dec0ac0bab937',
    },
  },
  127: {
    node: 'v22.23.5',
    sha256: {
      'linux-x64': 'c54118104acc524633b5abe106bbf44a53126ec8b4e5fa105cb92b5d7de8a1a1',
      'linux-arm64': '8bd3dc69eee8f3f226315a80d7d1d4faccf217a4c8fae500168ac2e38f3bdba3',
      'linux-x64-musl': '5916fad10a05e47f2dcbd70f993a03967ffd51330f40415ec8afdd9928dc10be',
      'linux-arm64-musl': '51c72e3a1385b10d4c862a40c845fc7bea5b19e30c7e109dbdcc2077c55e39bb',
      'darwin-arm64': 'e7131995759b61a0170b646010d2ad35a5d37b4cb0d471f3e8317eac6f742f3d',
      'darwin-x64': 'c53383238206b9ae4db23c5d8a63645e2e753bec8ab51a49cc81939aa64e9422',
      'win32-x64': '247e9693d316da9857e44990e5e11709f596f18112251b8026ec6eed80bdf38a',
    },
  },
  131: {
    node: 'v23.11.1',
    sha256: {
      'linux-x64': 'a2029c2b0cb05d10248e887c5df3f8547b7ab4aaa4e63b8e4da03e72f478140e',
      'linux-arm64': '277316a0b0ae3f50eb2cd57b74fa8a07f4d17fe0433468a790e6e47da297a9f6',
      'linux-x64-musl': 'e9d2cc25c7dd149f3033acb811c6d09119ce6808f4ccf03e8ad35290c536277c',
      'darwin-arm64': '255509d2c4fe8e1d6fefb950ad8db285ed75ba543e18744d83dc139f978e404d',
      'darwin-x64': '7e384a0cfa8b44ee4833b3823485baad78bf258e54f47020d2d2b4b75e9275d3',
      'win32-x64': 'd84556784656e4f47eb086fa00af01c032a88b086492eb3cf1e9fab5029eb94a',
    },
  },
  137: {
    node: 'v24.22.3',
    sha256: {
      'linux-x64': '061ec3e3062115705b56b51fa9cc330ab50d34b6969387d4e4b1a50c6809acc2',
      'linux-arm64': '261af2af250dfd7e9f25cf151d1b2713a0adf8f10a9ad116c4947f68627affe8',
      'linux-x64-musl': '2db4f8a40abe5f5b5d119964223fedc9c4c7c5e7c632901ae860af522c7844b2',
      'linux-arm64-musl': '248c96a84f6c8338646b9fd73bf125124678f8fb08db5f23023f462055e0eedc',
      'darwin-arm64': 'ff6e17d4874b76d272212b908cc020d6e815fba5a6c7eaaa06add725840307fd',
      'darwin-x64': '977614af0504c81045e7fd85596dbca0e5f951b96681516dadafedcca8c447f7',
      'win32-x64': '86fc4785327db5f5c7558dc6156c543b433c313e813a222e088086222ab4afa6',
    },
  },
  141: {
    node: 'v25.9.0',
    sha256: {
      'linux-x64': '134e55b2408448a219760fe04dc44d6851f9de8a79549021ffd870e9082d9e7b',
      'linux-arm64': '8fb4283301b8c720fc9f18bffff0f659e72cc14d0cf207a3bb411808aaa73a57',
      'linux-x64-musl': '1ac44af012be6bc17f1e3723edbf12897c0baeae5d1dc75b9f97d71413e4c8f5',
      'linux-arm64-musl': '97f6fe125faa51f84a7bb600d0cd7aefcfaaa0e75a5f49a7c61c3df91d12d535',
      'darwin-arm64': 'e479f3c469d3d9303a44f00a8ea37a3788395d171bb8059c48a4bbbd2e371b59',
      'darwin-x64': '7d737b53ce191142bfa1c17cfa5b070d96e84eebf76b8dd06d84981cbdc3f7e3',
      'win32-x64': '98843732431bad6c2c165908bb7dde6fe2a221ddbc491a955d548a2e6ab9ebff',
    },
  },
  147: {
    node: 'v26.13.1',
    sha256: {
      'linux-x64': '518674de2b621728a5e4486f5fb3b7d2900bb3cc4aa97969edaa463db99f9778',
      'linux-arm64': '80a330b35415382878df18d41afbd106ea89bfb3be0087d6608e289a14c5cc7d',
      'linux-x64-musl': '04bf9ed3e32ea139c9af52f6dd06879ff6f8880555a0aa1183ef2d156c0e02d3',
      'linux-arm64-musl': '42684e7f1830ef9eaadd040672cba41bbaff9549d834600699f92ee1ee5b1fb1',
      'darwin-arm64': 'aec2514ea1ceb2ba52455e9ec65986f6749a06dd759e5db2a72e6889668c9735',
      'darwin-x64': '82bb96078a24ca50b9c9a38f2379e6be6d87171fcd400fc14c8934b3bce96e2f',
      'win32-x64': 'f5109dc868ec38703ad8f305e0aceece717cb60d4889873f434017af4e96cccb',
    },
  },
};

export function binaryName(abi, tls, arch = hostArch) {
  const libc = platform === 'linux' ? (musl ? '_musl' : '_gnu') : '';
  return `moro_engine_${platform}_${arch}${libc}_${abi}${tls === 'boringssl' ? '_boringssl' : ''}.node`;
}

function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { cwd: root, stdio: 'inherit', ...opts });
  if (r.status !== 0) throw new Error(`${cmd} ${args.join(' ')} ${r.error ? `failed: ${r.error.message}` : `exited ${r.status ?? r.signal}`}`);
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
    const clang = execFileSync('which', [process.env.CXX || 'clang++'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim().split('\n')[0];
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

// ---- the Node.js to train each ABI under ------------------------------------

// What a node binary is: its ABI and architecture, or null when it does not
// run here (another libc; x64 on an arm64 Mac without Rosetta 2).
function probeNode(file) {
  try {
    const out = execFileSync(file, ['-p', 'process.versions.modules + " " + process.arch'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 60_000 }).trim();
    const [abi, arch] = out.split(' ');
    return { file, abi: parseInt(abi, 10), arch: arch === 'arm64' ? 'arm64' : 'x64' };
  } catch {
    return null;
  }
}

// The pinned release for one ABI, fetched once into build/pgo-nodes/ and
// verified against the table before anything of it is run. null: the table
// has no build for this platform.
export async function fetchNode(abi, arch) {
  const entry = TRAINING_NODES[abi];
  const key = `${platform}-${arch}${musl ? '-musl' : ''}`;
  const pinned = entry?.sha256[key];
  if (!pinned) return null;
  const dir = join(nodesDir, `${entry.node}-${key}`);
  const exe = join(dir, platform === 'win32' ? 'node.exe' : 'node');
  if (existsSync(exe)) return exe;
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  let url;
  let member = null;
  if (platform === 'win32') {
    url = `https://nodejs.org/dist/${entry.node}/win-${arch}/node.exe`;
  } else {
    const name = `node-${entry.node}-${platform}-${arch}${musl ? '-musl' : ''}`;
    url = `${musl ? 'https://unofficial-builds.nodejs.org/download/release' : 'https://nodejs.org/dist'}/${entry.node}/${name}.tar.gz`;
    member = `${name}/bin/node`;
  }
  console.log(`pgo: fetching ${url}`);
  const tmp = join(dir, 'download');
  await download(url, tmp);
  const actual = createHash('sha256').update(readFileSync(tmp)).digest('hex');
  if (actual !== pinned) {
    rmSync(dir, { recursive: true, force: true });
    throw new Error(`checksum mismatch for ${url}: tools/pgo.mjs pins ${pinned}, the server sent ${actual}`);
  }
  if (member) {
    execFileSync('tar', ['-xzf', tmp, '-C', dir, member]);
    renameSync(join(dir, member), exe);
    rmSync(join(dir, member.split('/')[0]), { recursive: true, force: true });
    rmSync(tmp);
    chmodSync(exe, 0o755);
  } else {
    renameSync(tmp, exe);
  }
  return exe;
}

// ---- merging ----------------------------------------------------------------

/**
 * Sum of every counter in a profile: the size a training group is scaled by.
 * `llvm-profdata show` prints it as "Total count".
 */
export function profileTotal(profdata, file) {
  const out = execFileSync(profdata, ['show', '--detailed-summary', file], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  const m = /^Total count: (\d+)$/m.exec(out);
  if (!m) throw new Error(`llvm-profdata show did not report a total count for ${file}`);
  return Number(m[1]);
}

/**
 * Whole-number weights that give each group its share of the merged counts.
 * `groups`: [{ share, total }]. A group that got through ten times as many
 * requests as another, for the same share, gets a tenth of its weight. The
 * smallest weight is 100, so the shares hold to within a percent of
 * themselves.
 */
export function groupWeights(groups) {
  const raw = groups.map((g) => g.share / g.total);
  const least = Math.min(...raw);
  return raw.map((w) => Math.round((w / least) * 100));
}

/**
 * One profile from the per-group raw profiles under `dir`. `extra`: groups
 * already merged elsewhere, { name: file }. Returns { name: file } of the
 * per-group profiles it used.
 */
export function mergeGroups(profdata, dir, out, extra = {}) {
  const groups = [];
  for (const group of TRAINING_GROUPS) {
    let file = extra[group.name];
    if (!file) {
      const raws = existsSync(join(dir, group.name)) ? readdirSync(join(dir, group.name)).filter((f) => f.endsWith('.profraw')).map((f) => join(dir, group.name, f)) : [];
      if (raws.length === 0) continue;
      file = join(dir, `${group.name}.profdata`);
      run(profdata, ['merge', '-o', file, ...raws]);
      rmSync(join(dir, group.name), { recursive: true, force: true });
    }
    groups.push({ ...group, file, total: profileTotal(profdata, file) });
  }
  if (!groups.some((g) => g.name !== 'suites' && !extra[g.name])) throw new Error('training produced no profiles');
  // A group whose process ran but trained next to nothing must not be scaled
  // up to a full share.
  const most = Math.max(...groups.map((g) => g.total));
  const usable = groups.filter((g) => g.total > most / 10000);
  const weights = groupWeights(usable);
  const shares = usable.reduce((n, g) => n + g.share, 0);
  console.log(`pgo: merging ${usable.length} training groups`);
  usable.forEach((g, i) => console.log(`       ${g.name.padEnd(15)} ${String(g.total).padStart(13)} counts  x${String(weights[i]).padEnd(7)} -> ${((100 * g.share) / shares).toFixed(1)}%`));
  run(profdata, ['merge', '-o', out, ...usable.flatMap((g, i) => ['-weighted-input', `${weights[i]},${g.file}`])]);
  return Object.fromEntries(groups.map((g) => [g.name, g.file]));
}

// ---- the cycle --------------------------------------------------------------

function flag(argv, name, fallback = null) {
  const i = argv.findIndex((a) => a === `--${name}` || a.startsWith(`--${name}=`));
  if (i === -1) return fallback;
  return argv[i].includes('=') ? argv[i].slice(argv[i].indexOf('=') + 1) : (argv[i + 1] ?? fallback);
}

async function main(argv) {
  const strict = argv.includes('--strict');
  const noSuites = argv.includes('--no-suites');
  const fetch = !argv.includes('--no-fetch') && process.env.MORO_PGO_FETCH !== '0';
  const seconds = flag(argv, 'seconds', '4');
  const own = ['--strict', '--no-suites', '--no-fetch', '--seconds'];
  const passThrough = argv.filter((a) => !own.some((o) => a === o || a.startsWith(`${o}=`)));
  const arch = flag(argv, 'arch', hostArch);
  const tlsOnly = flag(argv, 'tls', process.env.MORO_BUILD_TLS || 'all');
  // --tls=openssl (a build without the bundled library) trains on that binary.
  const trainTls = tlsOnly === 'openssl' ? 'openssl' : 'boringssl';
  const variants = tlsOnly === 'all' ? ['boringssl', 'openssl'] : [tlsOnly];
  const abiArg = flag(argv, 'abi');
  const abis = argv.includes('--all')
    ? TARGETS.map((t) => t.abi)
    : abiArg
      ? String(abiArg).split(',').map((a) => parseInt(a, 10))
      : [hostAbi];
  const build = join(root, 'tools', 'build.mjs');

  let problems = 0;
  const problem = (msg) => {
    problems++;
    console.warn(`pgo: ${msg}`);
  };

  // 1. plain build (the safety net). The one step whose failure is the
  //    script's: there is no build to keep.
  console.log('pgo: plain build');
  run(process.execPath, [build, ...passThrough]);

  if (platform === 'win32' && !process.env.MORO_PGO_WINDOWS) {
    // MSVC PGO needs pgort140.dll reachable by the training node process and
    // pgomgr on PATH, which a Visual Studio developer prompt gives: opt in
    // with MORO_PGO_WINDOWS=1 (the release and CI lanes set it).
    console.log('pgo: MSVC PGO not enabled (MORO_PGO_WINDOWS unset) - plain build kept');
    return;
  }

  let done = 0;
  try {
    const profdata = platform === 'win32' ? null : findProfdata();
    if (platform !== 'win32' && !profdata) throw new Error('llvm-profdata not found (install llvm)');

    // The node each requested ABI can be trained under.
    const local = [process.execPath, ...(process.env.MORO_PGO_NODES ?? '').split(delimiter).filter(Boolean)].map(probeNode).filter(Boolean);
    const nodes = new Map();
    for (const abi of abis) {
      let node = local.find((n) => n.abi === abi && n.arch === arch)?.file ?? null;
      if (!node && fetch) {
        try {
          const fetched = await fetchNode(abi, arch);
          const probed = fetched && probeNode(fetched);
          if (fetched && !probed) problem(`${fetched} does not run on this machine - ABI ${abi} (${arch}) is not trained`);
          else if (probed && (probed.abi !== abi || probed.arch !== arch)) throw new Error(`${fetched} is ABI ${probed.abi} ${probed.arch}`);
          else if (probed) node = fetched;
        } catch (err) {
          problem(`no Node.js to train ABI ${abi} (${arch}) under: ${err.message}`);
        }
      }
      if (node) nodes.set(abi, node);
    }
    // The running ABI first: its training carries the suites.
    const order = [...nodes.keys()].sort((a, b) => (b === hostAbi) - (a === hostAbi) || a - b);

    rmSync(instrDir, { recursive: true, force: true });
    rmSync(profDir, { recursive: true, force: true });
    rmSync(optDir, { recursive: true, force: true });
    mkdirSync(profDir, { recursive: true });

    const instrument = (abi, forArch, tls, extra = []) => {
      run(process.execPath, [build, '--abi', String(abi), '--arch', forArch, '--pgo=generate', `--pgo-dir=${join(profDir, 'unclaimed')}`, `--out-dir=${instrDir}`, `--tls=${tls}`, ...extra]);
      const file = join(instrDir, binaryName(abi, tls, forArch));
      if (!existsSync(file)) throw new Error(`instrumented binary missing: ${file}`);
      return file;
    };
    const train = (node, binary, dir, suites) => {
      run(node, [join(root, 'tools', 'pgo-train.mjs'), `--seconds=${seconds}`, ...(suites ? [] : ['--no-suites'])], {
        env: { ...process.env, MORO_ENGINE_BINARY: binary, MORO_PGO_PROFILE_DIR: dir },
      });
    };
    let libraryProfile = null;
    const optimise = (abi, profile, tls) => {
      run(process.execPath, [build, '--abi', String(abi), '--arch', arch, '--pgo=use', `--pgo-profile=${profile}`, `--out-dir=${optDir}`, `--tls=${tls}`, ...(libraryProfile ? [`--pgo-library-profile=${libraryProfile}`] : [])]);
    };
    // The library's profile builds belong to this cycle and go with it, so a
    // cached build/boringssl holds the plain library only.
    const dropLibraries = () => {
      const dir = join(buildDir, 'boringssl');
      for (const f of existsSync(dir) ? readdirSync(dir) : []) if (/-pgo-(generate|use)$/.test(f)) rmSync(join(dir, f), { recursive: true, force: true });
    };
    // Smoke under a node that can load it, then let it replace the plain binary.
    const accept = (abi, tls) => {
      const name = binaryName(abi, tls, arch);
      const built = join(optDir, name);
      if (!existsSync(built)) throw new Error(`optimised binary missing: ${built}`);
      const node = nodes.get(abi);
      if (node) run(node, [join(root, 'test', 'smoke.mjs')], { env: { ...process.env, MORO_ENGINE_BINARY: built } });
      // Copied beside its place and renamed into it, never written over the
      // plain binary: the suites load that one, and macOS kills any later
      // process that maps a signed file whose bytes changed under its inode.
      const incoming = join(buildDir, `${name}.pgo`);
      copyFileSync(built, incoming);
      renameSync(incoming, join(buildDir, name));
      done++;
    };

    if (platform === 'win32') {
      for (const abi of abis) {
        const node = nodes.get(abi);
        if (!node) {
          console.log(`pgo: ABI ${abi}: no Node.js of that ABI to train under - plain build kept`);
          continue;
        }
        for (const tls of variants) {
          const name = binaryName(abi, tls, arch);
          try {
            console.log(`pgo: ${name}: instrumented build`);
            const dir = join(profDir, name.replace(/\.node$/, ''));
            mkdirSync(dir, { recursive: true });
            const pgd = join(dir, 'moro.pgd');
            const binary = instrument(abi, arch, tls, [`--pgo-profile=${pgd}`]);
            if (!existsSync(pgd)) throw new Error('the instrumented link produced no .pgd');
            console.log(`pgo: ${name}: training under ${node}`);
            train(node, binary, dir, abi === hostAbi && !noSuites);
            // MSVC's tools do not report a profile's size, so the groups are
            // merged with fixed weights (TRAINING_GROUPS[].weight).
            let merged = 0;
            for (const group of TRAINING_GROUPS) {
              const pgcs = existsSync(join(dir, group.name)) ? readdirSync(join(dir, group.name)).filter((f) => f.endsWith('.pgc')).map((f) => join(dir, group.name, f)) : [];
              if (pgcs.length === 0) continue;
              run('pgomgr', [`/merge:${group.weight}`, ...pgcs, pgd]);
              merged += pgcs.length;
            }
            if (merged === 0) {
              // Not where VCPROFILE_PATH said: beside the database or the
              // binary, the profile runtime's own choices. Merged unweighted.
              const stray = [dir, instrDir].flatMap((d) => readdirSync(d).filter((f) => f.endsWith('.pgc')).map((f) => join(d, f)));
              if (stray.length === 0) throw new Error('training produced no .pgc files');
              run('pgomgr', ['/merge', ...stray, pgd]);
              merged = stray.length;
            }
            console.log(`pgo: ${name}: optimised build (${merged} .pgc merged)`);
            optimise(abi, pgd, tls);
            accept(abi, tls);
          } catch (err) {
            problem(`${name}: ${err.message} - plain build kept`);
          }
        }
      }
    } else {
      // 2. one profile per ABI
      const profiles = new Map();
      let suitesProfile = null;
      const trainAbi = (abi, forArch, node) => {
        console.log(`pgo: ABI ${abi} (${forArch}): instrumented build, training under ${node}`);
        const dir = join(profDir, `${forArch}-${abi}`);
        mkdirSync(dir, { recursive: true });
        const binary = instrument(abi, forArch, trainTls);
        const withSuites = !noSuites && !suitesProfile;
        train(node, binary, dir, withSuites);
        const out = join(profDir, `moro-${forArch}-${abi}.profdata`);
        const merged = mergeGroups(profdata, dir, out, suitesProfile ? { suites: suitesProfile } : {});
        if (withSuites) suitesProfile = merged.suites ?? null;
        return out;
      };
      for (const abi of order) {
        try {
          profiles.set(abi, trainAbi(abi, arch, nodes.get(abi)));
        } catch (err) {
          problem(`ABI ${abi}: ${err.message}`);
        }
      }
      let borrowed = null;
      if (profiles.size === 0 && arch !== hostArch) {
        // Nothing of the target architecture runs here (darwin x64 without
        // Rosetta 2): train the host's and build from that. The profile is
        // IR-level, so what is not architecture-specific still applies.
        try {
          borrowed = trainAbi(hostAbi, hostArch, process.execPath);
        } catch (err) {
          problem(`${hostArch} profile: ${err.message}`);
        }
      }

      // The library's own profile: any one trained ABI will do (the library
      // is the same code under all of them), the running one first.
      // Only for an architecture that could be trained: a library profile of
      // another architecture is not used.
      if (variants.includes('boringssl') && boringSslLto() && profiles.size > 0) {
        const abi = [...profiles.keys()].sort((a, b) => (b === hostAbi) - (a === hostAbi))[0];
        const node = nodes.get(abi);
        try {
          console.log(`pgo: bundled TLS library (${arch}): instrumented build, TLS and HTTP/2 training under ${node}`);
          const dir = join(profDir, `${arch}-boringssl`);
          mkdirSync(dir, { recursive: true });
          const binary = instrument(abi, arch, 'boringssl', ['--pgo-library']);
          run(node, [join(root, 'tools', 'pgo-train.mjs'), `--seconds=${seconds}`, '--only=tls,http2'], {
            env: { ...process.env, MORO_ENGINE_BINARY: binary, MORO_PGO_PROFILE_DIR: dir },
          });
          const raws = ['tls', 'http2'].flatMap((g) => (existsSync(join(dir, g)) ? readdirSync(join(dir, g)).filter((f) => f.endsWith('.profraw')).map((f) => join(dir, g, f)) : []));
          if (raws.length === 0) throw new Error('the training wrote no profile');
          libraryProfile = join(profDir, `moro-${arch}-boringssl.profdata`);
          run(profdata, ['merge', '-o', libraryProfile, ...raws]);
          rmSync(dir, { recursive: true, force: true });
        } catch (err) {
          libraryProfile = null;
          problem(`bundled TLS library: ${err.message} - it is built without a profile`);
        }
      }

      // 3. optimised builds
      for (const abi of abis) {
        let profile = profiles.get(abi);
        if (!profile) {
          const nearest = [...profiles.keys()].sort((a, b) => (b === hostAbi) - (a === hostAbi) || Math.abs(a - abi) - Math.abs(b - abi))[0];
          profile = nearest ? profiles.get(nearest) : borrowed;
          if (!profile) {
            problem(`ABI ${abi}: no profile - plain build kept`);
            continue;
          }
          console.log(`pgo: ABI ${abi} (${arch}): not trained here - built from the ${nearest ? `ABI ${nearest}` : hostArch} profile`);
        }
        try {
          console.log(`pgo: ABI ${abi} (${arch}): optimised build`);
          optimise(abi, profile, tlsOnly);
          for (const tls of variants) accept(abi, tls);
        } catch (err) {
          problem(`ABI ${abi}: ${err.message} - plain build kept`);
        }
      }
    }

    rmSync(optDir, { recursive: true, force: true });
    rmSync(instrDir, { recursive: true, force: true });
    dropLibraries();
    const kept = platform === 'win32' ? [] : readdirSync(profDir).filter((f) => /^moro-.*\.profdata$/.test(f));
    console.log(`pgo: done - ${done} PGO-optimised binar${done === 1 ? 'y' : 'ies'} in build/` + (kept.length ? ` (${kept.map((f) => `${f}: ${statSync(join(profDir, f)).size} bytes`).join(', ')})` : ''));
    if (done === 0) problem('no binary was optimised');
  } catch (err) {
    problem(`${err.message} - keeping the plain build`);
  }
  if (problems && strict) {
    console.error(`pgo: ${problems} problem${problems === 1 ? '' : 's'}, see above (--strict)`);
    process.exit(1);
  }
}

// Run only as the entry point: the helpers above are importable.
if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  main(process.argv.slice(2)).then(
    () => process.exit(0),
    (err) => {
      console.error(`pgo: ${err.message}`);
      process.exit(1);
    }
  );
}
