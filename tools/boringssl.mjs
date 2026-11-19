#!/usr/bin/env node
// BoringSSL for the engine's bundled-TLS binaries: the pin, the fetch, the
// build, and the freshness policy.
//
// The engine ships two binaries per platform and Node ABI. One links the
// OpenSSL the host `node` exports (the only kind there was up to 1.1.19); the
// other carries BoringSSL inside it. Bundling a TLS library means its security
// fixes reach users only through an engine release, so the copy that is bundled
// is pinned here, in one reviewed file, and never allowed to grow old quietly:
//
//   tools/boringssl.json   the pin: an upstream version tag and the commit it
//                          names. The commit is the integrity check - a fetch
//                          that does not resolve to it is refused.
//   check                  compares the pin with upstream's newest tag. The
//                          release script runs it and refuses to cut a release
//                          on a stale pin; CI runs it on a schedule.
//   roll                   moves the pin to upstream's newest tag (the scheduled
//                          workflow does this, then builds and tests everything
//                          before releasing).
//
//   node tools/boringssl.mjs pin                 # print the pin
//   node tools/boringssl.mjs latest              # upstream's newest version tag
//   node tools/boringssl.mjs check [--max-age-days=N] [--json]
//   node tools/boringssl.mjs roll [--to=<tag>] [--note] [--dry-run]
//                                                # rewrite tools/boringssl.json;
//                                                # --note also writes the release
//                                                # note for the next patch version
//   node tools/boringssl.mjs releasable [--verified=<sha>]
//                                                # may the scheduled roll release
//                                                # from this checkout? (exit 4: no)
//   node tools/boringssl.mjs build [--arch=A]    # fetch + build the static libraries
//
// Upstream tags are dated snapshots, `0.YYYYMMDD.N`, cut every two to three
// weeks. BoringSSL publishes no security advisories of its own, so "newest tag,
// regularly" is the policy: a pin is STALE once upstream has a newer tag and
// the pinned one is older than --max-age-days (default 21, the release cadence).

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync, appendFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import os from 'node:os';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const pinPath = join(root, 'tools', 'boringssl.json');
const cacheDir = join(root, 'build', 'boringssl');
const platform = os.platform();

export const DEFAULT_MAX_AGE_DAYS = 21;
const TAG_RE = /^0\.(\d{4})(\d{2})(\d{2})\.(\d+)$/;

/** `0.20261105.0` -> `2026-11-05` (the day upstream cut the snapshot). */
export function tagDate(tag) {
  const m = TAG_RE.exec(tag);
  if (!m) throw new Error(`not a BoringSSL version tag: ${tag}`);
  return `${m[1]}-${m[2]}-${m[3]}`;
}

function tagOrder(a, b) {
  const [, ay, am, ad, an] = TAG_RE.exec(a);
  const [, by, bm, bd, bn] = TAG_RE.exec(b);
  return `${ay}${am}${ad}`.localeCompare(`${by}${bm}${bd}`) || Number(an) - Number(bn);
}

/**
 * The pin in effect. MORO_BORINGSSL_PIN=<tag>@<commit> overrides the file for
 * one build: the scheduled workflow uses it to build and test a candidate on
 * every platform BEFORE the pin file is committed.
 */
export function readPin() {
  const pin = JSON.parse(readFileSync(pinPath, 'utf8'));
  const override = process.env.MORO_BORINGSSL_PIN;
  if (override) {
    const [tag, commit] = override.split('@');
    if (!TAG_RE.test(tag ?? '') || !/^[0-9a-f]{40}$/.test(commit ?? '')) {
      throw new Error(`MORO_BORINGSSL_PIN must be <tag>@<40-hex commit>, got "${override}"`);
    }
    pin.tag = tag;
    pin.commit = commit;
  }
  if (!TAG_RE.test(pin.tag) || !/^[0-9a-f]{40}$/.test(pin.commit)) {
    throw new Error(`tools/boringssl.json: tag must be 0.YYYYMMDD.N and commit a 40-hex sha`);
  }
  return { ...pin, date: tagDate(pin.tag) };
}

function git(args, opts = {}) {
  return execFileSync('git', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], ...opts }).trim();
}

/** Every upstream version tag with the commit it names, oldest first. */
export function upstreamTags(repository) {
  const out = git(['ls-remote', '--tags', repository], { timeout: 60_000 });
  const commits = new Map();
  for (const line of out.split('\n')) {
    const [sha, ref] = line.split('\t');
    if (!ref?.startsWith('refs/tags/')) continue;
    // An annotated tag lists twice: the tag object, then `^{}` with the commit.
    const peeled = ref.endsWith('^{}');
    const tag = ref.slice('refs/tags/'.length, peeled ? -3 : undefined);
    if (!TAG_RE.test(tag)) continue;
    if (peeled || !commits.has(tag)) commits.set(tag, sha);
  }
  return [...commits.keys()].sort(tagOrder).map(tag => ({ tag, commit: commits.get(tag), date: tagDate(tag) }));
}

export function daysBetween(fromIso, to = new Date()) {
  return Math.floor((to.getTime() - Date.parse(`${fromIso}T00:00:00Z`)) / 86_400_000);
}

/**
 * Freshness of the pin against upstream.
 *   fresh: the pin is upstream's newest tag, or a newer one exists but the pin
 *          is still inside the window.
 *   stale: a newer tag exists and the pin has aged past the window.
 */
export function checkPin({ maxAgeDays = DEFAULT_MAX_AGE_DAYS, now = new Date() } = {}) {
  const pin = readPin();
  const tags = upstreamTags(pin.repository);
  if (tags.length === 0) throw new Error(`no version tags found at ${pin.repository}`);
  const latest = tags[tags.length - 1];
  const known = tags.find(t => t.tag === pin.tag);
  if (!known) throw new Error(`pinned tag ${pin.tag} does not exist upstream`);
  if (known.commit !== pin.commit) {
    throw new Error(`pinned commit ${pin.commit} is not what upstream's ${pin.tag} names (${known.commit})`);
  }
  const ageDays = daysBetween(pin.date, now);
  const behind = tags.length - 1 - tags.indexOf(known);
  return { pin, latest, ageDays, behind, maxAgeDays, stale: behind > 0 && ageDays > maxAgeDays };
}

// ---- fetch -----------------------------------------------------------------

/** The pinned tree, fetched once per commit. The commit is verified, not trusted. */
export function fetchSource(pin = readPin()) {
  const dir = join(cacheDir, 'src', pin.commit);
  const stamp = join(dir, '.moro-fetched');
  if (existsSync(stamp)) return dir;
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  console.log(`  boringssl: fetching ${pin.tag} (${pin.commit.slice(0, 12)}) from ${pin.repository}`);
  const quiet = { cwd: dir, stdio: ['ignore', 'ignore', 'inherit'] };
  execFileSync('git', ['init', '-q'], quiet);
  execFileSync('git', ['fetch', '-q', '--depth', '1', pin.repository, `refs/tags/${pin.tag}`], quiet);
  const got = git(['rev-parse', 'FETCH_HEAD^{commit}'], { cwd: dir });
  if (got !== pin.commit) {
    rmSync(dir, { recursive: true, force: true });
    throw new Error(`boringssl: ${pin.tag} resolved to ${got}, the pin says ${pin.commit} - refusing to build it`);
  }
  execFileSync('git', ['-c', 'advice.detachedHead=false', 'checkout', '-q', '--detach', 'FETCH_HEAD'], quiet);
  writeFileSync(stamp, `${pin.tag}\n${pin.commit}\n`);
  return dir;
}

// ---- build -----------------------------------------------------------------

function has(bin, args = ['--version']) {
  try {
    execFileSync(bin, args, { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

function libcTag() {
  if (platform !== 'linux') return '';
  return existsSync('/etc/alpine-release') ? '-musl' : '-gnu';
}

// An LLVM binutil that reads what a clang writes: the one of the same LLVM
// release. Looked for under the compiler's version suffix (Debian's
// clang++-18 goes with llvm-ar-18), beside the real compiler (Homebrew,
// Alpine, /usr/lib/llvm-N/bin), where the compiler looks for its own
// programs, and on PATH - and taken only if it reports the compiler's major
// version. null for Apple's clang, whose bitcode only Apple's tools read.
export function llvmTool(cxx, tool) {
  const text = (bin, args) => {
    try {
      return execFileSync(bin, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
    } catch {
      return '';
    }
  };
  const version = text(cxx, ['--version']);
  const major = /clang version (\d+)\./.exec(version)?.[1];
  if (!major || /Apple/.test(version)) return null;
  const candidates = [];
  const suffix = /clang\+\+(-\d+)$/.exec(cxx)?.[1];
  if (suffix) candidates.push(`${tool}${suffix}`);
  try {
    candidates.push(join(dirname(realpathSync(text('which', [cxx]).trim().split('\n')[0])), tool));
  } catch {
    // not on PATH under that name
  }
  candidates.push(text(cxx, [`-print-prog-name=${tool}`]).trim(), tool);
  for (const c of candidates) {
    if (c && new RegExp(`LLVM version ${major}\\.`).test(text(c, ['--version']))) return c;
  }
  return null;
}

// The C compiler that goes with a C++ compiler: clang++-18 -> clang-18,
// g++ -> gcc, /opt/homebrew/opt/llvm/bin/clang++ -> .../clang.
function cCompilerFor(cxx) {
  const cc = cxx.replace(/clang\+\+/, 'clang').replace(/g\+\+/, 'gcc');
  return cc === cxx ? null : cc;
}

/**
 * Static libssl + libcrypto for one platform/arch, built once and cached under
 * build/boringssl/. Returns what the engine's compile and link lines need.
 *
 * Symbols are compiled hidden: inside the addon they bind to each other and to
 * the engine, never to the OpenSSL symbols of the same names that the host
 * `node` exports, and the addon exports none of them.
 */
export function ensureBoringSsl({ arch, cxx = null, lto = false, pgo = '', pgoDir = '', pgoProfile = '' } = {}) {
  const pin = readPin();
  if (!has('git')) throw new Error('boringssl: git is required to fetch the pinned source');
  if (!has('cmake')) {
    throw new Error('boringssl: cmake (3.22 or later) is required to build the bundled TLS library; install it, or build only the Node-OpenSSL binary with --tls=openssl');
  }
  const src = fetchSource(pin);

  const ninja = has('ninja');
  const config = ['-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_POSITION_INDEPENDENT_CODE=ON', '-DBUILD_SHARED_LIBS=OFF'];
  if (ninja) config.unshift('-GNinja');
  else if (platform === 'win32') config.unshift('-GNMake Makefiles');

  if (platform === 'win32') {
    // The engine is compiled /MT (cl's default without /MD); the libraries
    // must use the same static runtime. x64 assembly is NASM (BUILDING.md).
    if (!has('nasm', ['-v'])) throw new Error('boringssl: nasm is required on Windows x64 (choco install nasm)');
    config.push('-DCMAKE_C_COMPILER=cl', '-DCMAKE_CXX_COMPILER=cl', '-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded');
  } else {
    // The same stack protector and fortified libc calls as the engine's own
    // code (tools/build.mjs): upstream's build sets neither, and of the
    // release toolchains only Alpine's turns them on by default. -U first:
    // upstream compiles with -Werror, and a toolchain that predefines
    // _FORTIFY_SOURCE would otherwise fail on the redefinition.
    const hardening = '-fstack-protector-strong -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2';
    // lto (tools/build.mjs asks for it, clang only): the objects are LLVM
    // bitcode, so the engine's link optimises the library's C and C++
    // together with the engine (the assembly is untouched), and the archives
    // need LLVM's ar to get a symbol table.
    // What tools/build.mjs asks for on top (clang only). lto: the objects are
    // LLVM bitcode, so a later link optimises the library's C and C++ as one
    // (the assembly is untouched), and the archives need LLVM's ar to get a
    // symbol table. pgo: the instrumented library for a training run, or the
    // library compiled from that run's profile (upstream compiles with
    // -Werror, hence the same three -Wno- as the engine's own profile build).
    const extra = [];
    if (lto) extra.push('-flto');
    if (pgo === 'generate') extra.push(`-fprofile-generate=${pgoDir}`);
    if (pgo === 'use') extra.push(`-fprofile-use=${pgoProfile}`, '-Wno-profile-instr-out-of-date', '-Wno-profile-instr-unprofiled', '-Wno-backend-plugin');
    const hidden = ['-fvisibility=hidden -ffunction-sections -fdata-sections', hardening, ...extra].join(' ');
    config.push(`-DCMAKE_C_FLAGS=${hidden}`, `-DCMAKE_CXX_FLAGS=${hidden} -fvisibility-inlines-hidden`);
    if (lto) {
      if (!cxx) throw new Error('boringssl: an LTO build needs the compiler it is for (cxx)');
      for (const [variable, tool] of [['CMAKE_AR', 'llvm-ar'], ['CMAKE_RANLIB', 'llvm-ranlib']]) {
        const found = llvmTool(cxx, tool);
        if (!found) throw new Error(`boringssl: ${tool} (the one that goes with ${cxx}) is needed for the LTO build of the bundled TLS library`);
        config.push(`-D${variable}=${found}`);
      }
    }
    // Only ssl and crypto are built, so upstream's tests are not configured
    // either: their dependencies probe the compiler at -O0 with -Werror, and
    // glibc 2.28 (the linux-gnu build image) warns about _FORTIFY_SOURCE
    // without optimisation. The two libraries come out byte-identical.
    config.push('-DBUILD_TESTING=OFF');
    if (cxx) {
      config.push(`-DCMAKE_CXX_COMPILER=${cxx}`);
      const cc = cCompilerFor(cxx);
      if (cc && has(cc)) config.push(`-DCMAKE_C_COMPILER=${cc}`, `-DCMAKE_ASM_COMPILER=${cc}`);
    }
    if (platform === 'darwin') {
      const sdk = execFileSync('xcrun', ['--show-sdk-path'], { encoding: 'utf8' }).trim();
      config.push(
        `-DCMAKE_OSX_ARCHITECTURES=${arch === 'arm64' ? 'arm64' : 'x86_64'}`,
        '-DCMAKE_OSX_DEPLOYMENT_TARGET=12.0',
        `-DCMAKE_OSX_SYSROOT=${sdk}`
      );
    }
  }

  // One build directory per distinct configuration: a different compiler or
  // flag set never reuses another's objects.
  // A profile build is named as one (`-pgo-generate`, `-pgo-use`): it belongs
  // to one PGO cycle, which removes it (tools/pgo.mjs), and its key covers the
  // profile's content, not only its path.
  const profile = pgo === 'use' ? createHash('sha256').update(readFileSync(pgoProfile)).digest('hex') : '';
  const key = createHash('sha256').update(JSON.stringify([pin.commit, platform, arch, libcTag(), config, profile])).digest('hex').slice(0, 12);
  const out = join(cacheDir, `${pin.tag}-${platform}-${arch}${libcTag()}-${key}${pgo ? `-pgo-${pgo}` : ''}`);
  const lib = name => (platform === 'win32' ? join(out, `${name}.lib`) : join(out, `lib${name}.a`));
  const result = { tag: pin.tag, date: pin.date, commit: pin.commit, includeDir: join(src, 'include'), libs: [lib('ssl'), lib('crypto')] };
  const stamp = join(out, '.moro-built');
  if (existsSync(stamp) && result.libs.every(existsSync)) return result;

  console.log(`  boringssl: building ${pin.tag} for ${platform}/${arch}${libcTag()} (${ninja ? 'ninja' : 'make'}) -> ${out}`);
  rmSync(out, { recursive: true, force: true });
  mkdirSync(out, { recursive: true });
  // Upstream's configure step is chatty (it also configures test-only
  // dependencies that are never built here): kept in a log, shown on failure.
  const logPath = join(out, 'moro-build.log');
  const cmake = args => {
    try {
      appendFileSync(logPath, execFileSync('cmake', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 256 * 1024 * 1024 }));
    } catch (err) {
      const text = `${err.stdout ?? ''}${err.stderr ?? ''}`;
      appendFileSync(logPath, text);
      throw new Error(`boringssl: cmake ${args[0]} failed (full log: ${logPath})\n${text.split('\n').slice(-40).join('\n')}`);
    }
  };
  cmake(['-S', src, '-B', out, ...config]);
  cmake(['--build', out, '--target', 'ssl', 'crypto', '--parallel', String(os.availableParallelism?.() ?? os.cpus().length)]);
  for (const l of result.libs) {
    if (!existsSync(l)) throw new Error(`boringssl: the build finished but ${l} is missing (found: ${readdirSync(out).join(' ')})`);
  }
  writeFileSync(stamp, `${pin.tag}\n${pin.commit}\n`);
  return result;
}

/**
 * The library with libssl compiled from a profile (tools/pgo.mjs trains it:
 * the TLS and HTTP/2 groups, on a build whose library is instrumented), as
 * one archive to link in place of the two.
 *
 * libssl - the record layer, the handshake state machine, everything the
 * engine calls on each request - comes from the profile build; libcrypto from
 * the plain LTO build, because the profile makes its handshake arithmetic
 * (X25519, SHA-2 glue) slower, not faster. The two are then linked into one
 * relocatable object, which is where their link-time optimisation happens:
 * on their own, not in the engine's link. Optimised in the engine's link, a
 * profiled library changes what the engine's own code is compiled to (its
 * header parsing lost 4%), and the link accepts only one profile for
 * everything in it, so the library would be compiled again for every ABI.
 * This way it is built once per platform and the engine's code is what it is
 * without it.
 */
export function prelinkBoringSsl({ arch, cxx, profile }) {
  const plain = ensureBoringSsl({ arch, cxx, lto: true });
  const tuned = ensureBoringSsl({ arch, cxx, lto: true, pgo: 'use', pgoProfile: profile });
  const dir = dirname(tuned.libs[0]);
  const archive = join(dir, 'libmoro-boringssl.a');
  if (!existsSync(archive)) {
    const object = join(dir, 'moro-boringssl.o');
    const [ssl, crypto] = [tuned.libs[0], plain.libs[1]];
    const args = ['-r', '-nostdlib', '-flto', '-O3', '-o', object];
    if (platform === 'darwin') {
      const sdk = execFileSync('xcrun', ['--show-sdk-path'], { encoding: 'utf8' }).trim();
      // -keep_private_externs: the library's symbols are hidden, and ld -r
      // would otherwise make them local to the object.
      args.push('-target', `${arch === 'arm64' ? 'arm64' : 'x86_64'}-apple-macos12`, '-isysroot', sdk, '-Wl,-keep_private_externs', '-Wl,-all_load', ssl, crypto);
    } else {
      args.push('-fuse-ld=lld', '-ffunction-sections', '-fdata-sections', '-Wl,--whole-archive', ssl, crypto, '-Wl,--no-whole-archive');
    }
    console.log(`  boringssl: libssl from the profile, linked with libcrypto -> ${archive}`);
    execFileSync(cxx, args, { stdio: 'inherit' });
    // An archive again, so that what applies to archives applies to it
    // (-Wl,--exclude-libs,ALL keeps its symbols out of the dynamic table).
    execFileSync(llvmTool(cxx, 'llvm-ar'), ['rcs', archive, object], { stdio: 'inherit' });
    rmSync(object);
  }
  return { ...plain, libs: [archive] };
}

// ---- the release note of a roll --------------------------------------------

// A roll is released on its own, as the next patch version: the note says what
// moved and nothing else, because nothing else did. Written where the release
// script expects it (changelog/vX.Y.Z.md, indexed at the top of CHANGELOG.md).
export function writeRollNote(from, to) {
  const current = JSON.parse(readFileSync(join(root, 'packages', 'engine', 'package.json'), 'utf8')).version;
  // "The next patch version" exists only after a plain X.Y.Z: after a
  // prerelease (1.2.0-rc.1) there is no patch to add one to.
  if (!/^\d+\.\d+\.\d+$/.test(current)) {
    throw new Error(`the tree is at ${current}, not a released X.Y.Z: a roll has no patch version to release as`);
  }
  const [major, minor, patch] = current.split('.').map(n => parseInt(n, 10));
  const version = `${major}.${minor}.${patch + 1}`;
  // A note already there was written by hand, for a release in preparation.
  if (existsSync(join(root, 'changelog', `v${version}.md`))) {
    throw new Error(`changelog/v${version}.md already exists: ${version} is a release in preparation, and its note is not the roll's to replace`);
  }
  const note = `# @morojs/engine ${version}

Scheduled update of the bundled TLS library: BoringSSL ${from.tag} -> ${to.tag}
(upstream snapshots of ${tagDate(from.tag)} and ${to.date}).

No engine code changed. The binaries that carry BoringSSL
(\`probe().tls.library === 'boringssl'\`, the default) are rebuilt on the new
snapshot; before this release was cut, that build passed the whole CI gate on
every platform - the conformance, TLS and HTTP/2 suites, the sanitizers, and
the load test of every published binary. The binaries on node's OpenSSL are
rebuilt from the same engine source and behave as in ${current}.

What changed upstream:
${from.repository}/+log/${from.commit}..${to.commit}

BoringSSL publishes no advisories of its own, so this release is not a
statement that ${from.tag} had a known flaw: the engine follows upstream's
snapshots on a schedule so that a fix made there reaches servers here within
weeks, whether or not anyone announced it. Updating is \`npm update @morojs/engine\`.
`;
  writeFileSync(join(root, 'changelog', `v${version}.md`), note);
  const indexPath = join(root, 'CHANGELOG.md');
  const index = readFileSync(indexPath, 'utf8');
  const line = `- [${version}](changelog/v${version}.md) — bundled BoringSSL updated to ${to.tag} (scheduled; no engine changes).\n`;
  const at = index.indexOf('- [');
  if (at === -1) throw new Error('CHANGELOG.md: no release list to add to');
  writeFileSync(indexPath, index.slice(0, at) + line + index.slice(at));
  return version;
}

// ---- may the scheduled roll release? ----------------------------------------

/**
 * The scheduled roll publishes by itself, as "the last release on a newer
 * BoringSSL, no engine code changed". That sentence has to be true of the
 * checkout it releases from:
 *   - the tree is a released X.Y.Z, not a prerelease;
 *   - HEAD is the commit the gate ran on (`verified`), so nothing pushed while
 *     the gate was running rides along untested;
 *   - HEAD is the commit origin's tag v<version> names, so nothing committed
 *     since the last release - work for the next one - is published with it.
 * Anything else is left for a person: the roll stops, the workflow reports it,
 * and tools/release.mjs still refuses the next release on a stale pin.
 */
export function rollReleasable({ verified = null } = {}) {
  const version = JSON.parse(readFileSync(join(root, 'packages', 'engine', 'package.json'), 'utf8')).version;
  if (!/^\d+\.\d+\.\d+$/.test(version)) {
    return { ok: false, reason: `the tree is at ${version}, a prerelease: the roll releases patch versions of a released X.Y.Z only` };
  }
  const head = git(['rev-parse', 'HEAD'], { cwd: root });
  if (verified && head !== verified) {
    return { ok: false, reason: `the branch moved while the gate was running: it verified ${verified}, the checkout is ${head}` };
  }
  // Asked of origin, not of the local tags: a CI checkout has none.
  const ref = `refs/tags/v${version}`;
  const out = git(['ls-remote', 'origin', ref, `${ref}^{}`], { cwd: root, timeout: 60_000 });
  let tagged = null;
  for (const line of out.split('\n')) {
    const [sha, name] = line.split('\t');
    // An annotated tag lists twice; the `^{}` line is the commit.
    if (name === `${ref}^{}` || (name === ref && !tagged)) tagged = sha;
  }
  if (!tagged) return { ok: false, reason: `origin has no tag v${version}: ${version} was never released from this repository` };
  if (tagged !== head) {
    return { ok: false, reason: `the branch (${head}) is not the commit v${version} was released from (${tagged}): it carries commits that are not released yet` };
  }
  return { ok: true, version, head };
}

// ---- CLI -------------------------------------------------------------------

function flag(argv, name, fallback = null) {
  const hit = argv.find(a => a === `--${name}` || a.startsWith(`--${name}=`));
  if (!hit) return fallback;
  return hit.includes('=') ? hit.slice(hit.indexOf('=') + 1) : true;
}

// `key=value` lines for a workflow step's outputs, when run inside one.
function output(pairs) {
  if (!process.env.GITHUB_OUTPUT) return;
  appendFileSync(process.env.GITHUB_OUTPUT, Object.entries(pairs).map(([k, v]) => `${k}=${v}\n`).join(''));
}

function main(argv) {
  const cmd = argv[0];
  if (cmd === 'pin') {
    console.log(JSON.stringify(readPin(), null, 2));
  } else if (cmd === 'latest') {
    const tags = upstreamTags(readPin().repository);
    console.log(JSON.stringify(tags[tags.length - 1], null, 2));
  } else if (cmd === 'check') {
    const maxAgeDays = Number(flag(argv, 'max-age-days', DEFAULT_MAX_AGE_DAYS));
    const r = checkPin({ maxAgeDays });
    output({ stale: r.stale, behind: r.behind, pinned: r.pin.tag, latest: r.latest.tag });
    if (flag(argv, 'json')) console.log(JSON.stringify(r, null, 2));
    else if (r.behind === 0) console.log(`boringssl: ${r.pin.tag} is upstream's newest tag (${r.ageDays} days old)`);
    else {
      console.log(
        `boringssl: pinned ${r.pin.tag} (${r.ageDays} days old), upstream is at ${r.latest.tag} - ` +
          (r.stale ? `STALE (older than ${maxAgeDays} days): run  node tools/boringssl.mjs roll` : `inside the ${maxAgeDays}-day window`)
      );
    }
    // 3 = stale: distinct from 1 (the check itself failed, e.g. no network).
    if (r.stale) process.exit(3);
  } else if (cmd === 'roll') {
    const pin = JSON.parse(readFileSync(pinPath, 'utf8'));
    const tags = upstreamTags(pin.repository);
    const to = flag(argv, 'to');
    const target = to ? tags.find(t => t.tag === to) : tags[tags.length - 1];
    if (!target) throw new Error(`no upstream tag ${to}`);
    const changed = target.tag !== pin.tag || target.commit !== pin.commit;
    output({ changed, from: pin.tag, to: target.tag, commit: target.commit, date: target.date });
    if (!changed) {
      console.log(`boringssl: already at ${pin.tag}`);
      return;
    }
    if (!flag(argv, 'dry-run')) {
      // The note first: it can refuse, and then the pin stays as it was.
      if (flag(argv, 'note')) {
        const version = writeRollNote(pin, target);
        output({ version });
        console.log(`boringssl: release note written for ${version}`);
      }
      writeFileSync(pinPath, JSON.stringify({ repository: pin.repository, tag: target.tag, commit: target.commit }, null, 2) + '\n');
    }
    console.log(`boringssl: ${pin.tag} -> ${target.tag} (${target.commit})${flag(argv, 'dry-run') ? '  (dry run)' : ''}`);
  } else if (cmd === 'releasable') {
    const verified = flag(argv, 'verified');
    const r = rollReleasable({ verified: typeof verified === 'string' ? verified : null });
    if (!r.ok) {
      console.error(`boringssl: not releasing - ${r.reason}`);
      // 4: distinct from 1 (the check itself failed) and 3 (stale).
      process.exit(4);
    }
    console.log(`boringssl: ${r.head.slice(0, 12)} is v${r.version} as released and as verified - a roll can release from it`);
  } else if (cmd === 'build') {
    const arch = flag(argv, 'arch', os.arch() === 'arm64' ? 'arm64' : 'x64');
    const r = ensureBoringSsl({ arch, cxx: process.env.CXX || null });
    console.log(JSON.stringify(r, null, 2));
  } else {
    console.error('usage: node tools/boringssl.mjs <pin|latest|check|roll|releasable|build> [options]');
    process.exit(2);
  }
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  try {
    main(process.argv.slice(2));
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }
}
