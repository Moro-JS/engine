'use strict';
// @morojs/engine loader (CJS core - .node addon loading is require-based).
//
// Resolution order:
//   1. The matching per-platform package (@morojs/engine-<platform>-<arch>[-libc])
//      published as an exact-version optionalDependency of this package.
//   2. A local build/ directory, when running from the engine repository
//      itself (development).
//
// Binary naming: moro_engine_<platform>_<arch>[_<libc>]_<abi>[_boringssl].node
// (libc segment on linux only: gnu | musl)
//
// Two binaries exist per platform and ABI, and they differ in one thing: the
// TLS library. `..._boringssl.node` carries BoringSSL and is the default. The
// unsuffixed one links the OpenSSL the running node exports; it is chosen when
// the process has that library specially configured (FIPS, an OpenSSL config
// file, providers), when the app or operator asks for it, and as the fallback
// when the BoringSSL binary cannot be loaded. See tlsPreference() below.

const { existsSync } = require('fs');
const { join, dirname, sep } = require('path');

// The engine version is whatever this package publishes: tools/prepare-release.mjs
// stamps package.json from the release tag, so reading it here keeps probe() and
// `.version` in lockstep with the published package — one source of truth, no
// compiled constant to drift. (The native binding still carries kEngineVersion
// as a build-time fallback; the loader overrides it below.)
const { version: ENGINE_VERSION } = require('./package.json');

function libcSuffix() {
  if (process.platform !== 'linux') return '';
  // Fast path: Alpine (by far the common musl host) marks itself on disk —
  // far cheaper than generating a process report.
  if (existsSync('/etc/alpine-release')) return '-musl';
  // glibc exposes its version in the process report; musl does not. When the
  // report API is unavailable entirely, assume glibc (the overwhelmingly
  // common case) rather than musl.
  try {
    let report = null;
    if (process.report) {
      // Skip env serialization while generating the report — we only need the
      // header — then restore whatever the app had configured.
      const prevExcludeEnv = process.report.excludeEnv;
      process.report.excludeEnv = true;
      try {
        report = process.report.getReport();
      } finally {
        process.report.excludeEnv = prevExcludeEnv;
      }
    }
    if (!report) return '-gnu';
    if (report.header && report.header.glibcVersionRuntime) return '-gnu';
    return '-musl';
  } catch {
    return '-gnu';
  }
}

function binaryName(tls) {
  const libc = libcSuffix().replace('-', '_'); // '' | '_gnu' | '_musl'
  const variant = tls === 'boringssl' ? '_boringssl' : '';
  return `moro_engine_${process.platform}_${process.arch}${libc}_${process.versions.modules}${variant}.node`;
}

// ---- which TLS library ------------------------------------------------------

// Set by selectTls() before the binding is loaded; null = not chosen in code.
let selectedTls = null;
// The ssl options the first TLS server will be created with, when the caller
// said so (selectTls(library, ssl)): lets the load itself settle on a library
// that accepts them.
let plannedSsl = null;

// Node options that configure the process's OpenSSL. An operator who passes
// one expects TLS to go through that library - a FIPS provider, an engine or
// provider module, a policy file - and the bundled BoringSSL knows none of it.
const OPENSSL_NODE_FLAGS = ['--enable-fips', '--force-fips', '--openssl-config', '--openssl-shared-config', '--openssl-legacy-provider'];

// The same options given through node's configuration file
// (--experimental-config-file=<path>, or node.config.json in the working
// directory with --experimental-default-config-file): they take effect like
// the flags and appear in neither execArgv nor NODE_OPTIONS.
function opensslOptionInNodeConfigFile(flags) {
  let file = null;
  const named = /--experimental-config-file(?:=|\s+)("[^"]+"|'[^']+'|\S+)/.exec(flags);
  if (named) file = named[1].replace(/^["']|["']$/g, '');
  else if (flags.includes('--experimental-default-config-file')) file = 'node.config.json';
  if (!file) return null;
  try {
    const options = JSON.parse(require('fs').readFileSync(file, 'utf8')).nodeOptions || {};
    for (const flag of OPENSSL_NODE_FLAGS) {
      const value = options[flag.slice(2)];
      if (value !== undefined && value !== false) return `${flag} in ${file}`;
    }
  } catch {
    // unreadable here: node has already refused to start on a file it cannot read
  }
  return null;
}

function opensslIsConfigured() {
  const flags = `${process.execArgv.join(' ')} ${process.env.NODE_OPTIONS || ''}`;
  for (const flag of OPENSSL_NODE_FLAGS) {
    if (flags.includes(flag)) return flag;
  }
  const fromFile = opensslOptionInNodeConfigFile(flags);
  if (fromFile) return fromFile;
  if (process.env.OPENSSL_CONF) return 'OPENSSL_CONF';
  if (process.env.OPENSSL_MODULES) return 'OPENSSL_MODULES';
  try {
    if (require('crypto').getFips()) return 'FIPS mode';
  } catch {
    // a node built without crypto: nothing is configured
  }
  return null;
}

function normalizeTls(value, source) {
  const v = String(value).toLowerCase();
  if (v === 'boringssl' || v === 'openssl' || v === 'auto') return v;
  if (v === 'node') return 'openssl'; // "the one node ships"
  const error = new Error(`@morojs/engine: ${source} must be "boringssl", "openssl" or "auto", got "${value}"`);
  error.code = 'MORO_ENGINE_TLS_INVALID';
  throw error;
}

/**
 * The TLS library to load and why. `explicit` means someone asked for it by
 * name: then a binary that cannot be loaded is an error, never a silent switch
 * to the other library.
 */
function tlsPreference() {
  let asked = selectedTls;
  let reason = 'selectTls()';
  if (!asked || asked === 'auto') {
    const env = process.env.MORO_ENGINE_TLS;
    asked = env ? normalizeTls(env, 'MORO_ENGINE_TLS') : 'auto';
    reason = 'MORO_ENGINE_TLS';
  }
  if (asked !== 'auto') return { library: asked, explicit: true, reason };
  const configured = opensslIsConfigured();
  if (configured) return { library: 'openssl', explicit: false, reason: `node's OpenSSL is configured (${configured})` };
  return { library: 'boringssl', explicit: false, reason: 'default' };
}

function platformPackageName() {
  return `@morojs/engine-${process.platform}-${process.arch}${libcSuffix()}`;
}

// One binary by file name: the per-platform package first, then a local build.
function loadNamed(name, attempts) {
  // 1. Per-platform npm package
  const pkg = platformPackageName();
  try {
    const path = resolveInInstall(pkg, name);
    const packageVersion = packageVersionAt(dirname(path));
    // The binaries of another release are not this package's to run: the
    // two are published together and pinned to each other.
    if (packageVersion && packageVersion !== ENGINE_VERSION) {
      throw new Error(`found ${path}, which is ${pkg} ${packageVersion}, not ${ENGINE_VERSION}: not loaded`);
    }
    return { module: require(path), from: pkg, path, packageVersion };
  } catch (err) {
    attempts.push(`${pkg}/${name}: ${err.message.split('\n')[0]}`);
  }

  // 2. Engine repo local build (development). Only inside the engine
  //    repository: installed, the same relative path is node_modules/build,
  //    which belongs to whatever package is called "build".
  if (!inEngineRepo()) return null;
  const local = join(__dirname, '..', '..', 'build', name);
  if (existsSync(local)) {
    try {
      return { module: require(local), from: local, path: local };
    } catch (err) {
      attempts.push(`${local}: ${err.message.split('\n')[0]}`);
    }
  } else {
    attempts.push(`${local}: not present`);
  }
  return null;
}

// Where a file of the platform package is, looked for only inside the
// node_modules tree this package was installed into: the node_modules of each
// directory from this one up to the outermost node_modules on this file's
// path. That is every place a package manager puts a dependency of this
// package (beside it, nested under it, hoisted above it, or linked next to it
// in a store). Plain module resolution would go on from there to the
// node_modules of every directory above the application, to NODE_PATH and to
// the home directory's module folders, and a native binary is not taken from
// a place the installation does not own. Outside a node_modules tree (the
// engine repository, a bundle), and under Yarn Plug'n'Play, where resolution
// is already limited to declared dependencies, it is plain resolution.
function resolveInInstall(pkg, name) {
  const request = `${pkg}/${name}`;
  const marker = `${sep}node_modules${sep}`;
  const at = `${__dirname}${sep}`.indexOf(marker);
  if (at === -1 || process.versions.pnp) return require.resolve(request);
  const top = __dirname.slice(0, at + marker.length - 1); // .../node_modules
  for (const dir of require.resolve.paths(request) || []) {
    if (dir !== top && !dir.startsWith(top + sep)) continue;
    const file = join(dir, pkg, name);
    if (existsSync(file)) return file;
  }
  throw new Error(`not installed in ${top}`);
}

// The version stamped into the platform package in `dir` (the release
// assembler writes it; this package pins it exactly in optionalDependencies).
function packageVersionAt(dir) {
  try {
    return String(require(join(dir, 'package.json')).version || '') || null;
  } catch {
    return null;
  }
}

// Whether this file is running from a checkout of the engine repository
// (packages/engine under the monorepo root), as opposed to an install.
let engineRepo;
function inEngineRepo() {
  if (engineRepo === undefined) {
    try {
      engineRepo = require(join(__dirname, '..', '..', 'package.json')).name === '@morojs/engine-monorepo';
    } catch {
      engineRepo = false;
    }
  }
  return engineRepo;
}

function tryLoad() {
  const attempts = [];

  // 0. Explicit binary (build/diagnostics only, never needed by users): the
  //    PGO training run loads an instrumented build from a side directory,
  //    and A/B runs can pin a specific .node. A path that fails to load is a
  //    hard error - falling through to a different binary would defeat the
  //    point of asking for this one.
  const explicit = process.env.MORO_ENGINE_BINARY;
  if (explicit) {
    try {
      return { module: require(explicit), from: explicit, path: explicit };
    } catch (err) {
      const error = new Error(`@morojs/engine: MORO_ENGINE_BINARY=${explicit} failed to load: ${err.message}`);
      error.code = 'MORO_ENGINE_BINARY_MISSING';
      return { error };
    }
  }

  let pref;
  try {
    pref = tlsPreference();
  } catch (error) {
    return { error };
  }

  const first = loadNamed(binaryName(pref.library), attempts);
  if (first) {
    // BoringSSL by default, and the caller told us the TLS configuration it
    // is about to serve: make sure BoringSSL takes it. One it has no support
    // for - an Ed448 or DSA key, a CCM suite, a brainpool group - worked on
    // node's OpenSSL up to 1.1.19, and keeps working there now.
    if (pref.library === 'boringssl' && !pref.explicit && plannedSsl) {
      const planned = withNodeTlsPolicy(plannedSsl);
      const refused = tlsRefusal(first.module, planned);
      if (refused) {
        const other = loadNamed(binaryName('openssl'), []);
        if (other && !tlsRefusal(other.module, planned)) {
          return { ...other, tls: { reason: 'fallback', fallbackReason: notAccepted(refused) } };
        }
        // Neither library takes it: the configuration is simply wrong, and
        // serve() will say so.
      }
    }
    return { ...first, tls: { reason: pref.reason } };
  }

  // The BoringSSL binary is the default, not a requirement: when nobody asked
  // for it by name and it is not there (a platform package from before 1.1.20,
  // a local build made with --tls=openssl) or will not load, the binary on
  // node's OpenSSL serves instead, and probe().tls says so.
  if (pref.library === 'boringssl' && !pref.explicit) {
    const fallbackReason = attempts.join('; ');
    const second = loadNamed(binaryName('openssl'), attempts);
    if (second) return { ...second, tls: { reason: 'fallback', fallbackReason } };
  }

  const pkg = platformPackageName();
  const error = new Error(
    `@morojs/engine: no prebuilt binary for ${process.platform}/${process.arch} ` +
      `on Node ABI ${process.versions.modules} (Node ${process.versions.node}).\n` +
      `Expected package: ${pkg}\n` +
      `Attempts:\n  ${attempts.join('\n  ')}\n` +
      `If the platform package is missing from node_modules, this is usually npm's ` +
      `optional-dependency lockfile bug (npm/cli#4828): rm -rf node_modules package-lock.json && npm install.\n` +
      `MoroJS falls back to the Node.js http server automatically; the reason is ` +
      `logged at startup and exposed via app.engine.fallbackReason.`
  );
  error.code = 'MORO_ENGINE_BINARY_MISSING';
  return { error };
}

// "" when the binary's TLS library can build a context from these ssl options,
// otherwise why not (the message serve() would throw). Older binaries have no
// such check and are taken to accept.
function tlsRefusal(binding, ssl) {
  return typeof binding._tlsCheck === 'function' ? binding._tlsCheck(ssl) : '';
}
const notAccepted = (why) => `BoringSSL did not accept the TLS configuration (${String(why).split('\n')[0]})`;

let loaded = null;

function loadBinding() {
  if (!loaded) loaded = tryLoad();
  if (loaded.error) throw loaded.error;
  return loaded.module;
}

// probe().binary: the file that was loaded and, when it came from a platform
// package, that package's version - the release the running code belongs to.
function binaryInfo() {
  const info = { path: loaded.path };
  if (loaded.packageVersion) info.version = loaded.packageVersion;
  return info;
}

/**
 * Non-throwing diagnostics: can the engine load here, and what is it?
 * MoroJS's preflight uses this instead of exception-driven detection.
 */
function probe() {
  if (!loaded) loaded = tryLoad();
  if (loaded.error) {
    return {
      ok: false,
      version: ENGINE_VERSION,
      platform: process.platform,
      arch: process.arch,
      abi: process.versions.modules,
      error: loaded.error.message,
    };
  }
  // package.json is the source of truth for the version (see ENGINE_VERSION);
  // override the binding's build-time constant so the two can never disagree.
  const native = loaded.module.probe();
  return { ...native, version: ENGINE_VERSION, tls: tlsInfo(native), binary: binaryInfo() };
}

// `0.YYYYMMDD.N`, BoringSSL's version tags: the day upstream cut the snapshot.
function boringSslDate(version) {
  const m = /^0\.(\d{4})(\d{2})(\d{2})\.\d+$/.exec(version || '');
  return m ? `${m[1]}-${m[2]}-${m[3]}` : null;
}

// probe().tls: what the binary reports (library, version) plus what only the
// loader knows - why this binary was the one loaded.
function tlsInfo(native) {
  // A binary from before 1.1.20 reports nothing: it links node's OpenSSL.
  const base = native.tls || { library: 'openssl', version: process.versions.openssl || '' };
  const info = { library: base.library, version: base.version, reason: loaded.tls ? loaded.tls.reason : 'MORO_ENGINE_BINARY' };
  const date = base.library === 'boringssl' ? boringSslDate(base.version) : null;
  if (date) info.date = date;
  if (loaded.tls && loaded.tls.fallbackReason) info.fallbackReason = loaded.tls.fallbackReason;
  return info;
}

/**
 * Choose the TLS library before the binding is loaded: 'boringssl' (bundled),
 * 'openssl' (the running node's) or 'auto'. The choice is per thread and has
 * to come before the first probe()/serve() there; asking for the other library
 * once a binary is loaded throws, because a loaded addon cannot be swapped.
 * Operators can set MORO_ENGINE_TLS instead and change no code.
 *
 * `ssl` (optional): the ssl options the server will be created with. When the
 * library is not named, the load then checks that BoringSSL accepts them and
 * settles on OpenSSL if it does not.
 */
function selectTls(library, ssl) {
  const want = normalizeTls(library, 'selectTls()');
  if (ssl && typeof ssl === 'object') plannedSsl = ssl;
  if (loaded && !loaded.error) {
    const have = tlsInfo(loaded.module.probe()).library;
    if (want === 'auto' || want === have) return have;
    const error = new Error(
      `@morojs/engine: selectTls('${want}') came after the binding was loaded with ${have}. ` +
        `Call it before the first probe() or serve(), or set MORO_ENGINE_TLS=${want}.`
    );
    error.code = 'MORO_ENGINE_TLS_LOADED';
    throw error;
  }
  selectedTls = want;
  loaded = null; // a failed earlier attempt may succeed with the other library
  return want;
}

// ---- how old is the bundled TLS code ----------------------------------------

// A bundled TLS library gets its fixes through engine releases, and a server
// that nobody updates would otherwise never say so. Past this age the first
// TLS server of the process emits one warning (code MORO_ENGINE_TLS_STALE).
// The engine re-pins BoringSSL about every three weeks, so a build this old
// has missed several of them. MORO_ENGINE_TLS_AGE_WARNING=0 turns it off.
const TLS_STALE_DAYS = 180;

function warnIfBundledTlsIsOld(binding) {
  if (process.env.MORO_ENGINE_TLS_AGE_WARNING === '0') return;
  const tls = tlsInfo(binding.probe());
  if (tls.library !== 'boringssl' || !tls.date) return;
  const ageDays = Math.floor((Date.now() - Date.parse(`${tls.date}T00:00:00Z`)) / 86_400_000);
  if (!(ageDays > TLS_STALE_DAYS)) return;
  // Once per process, whichever thread gets here first - and in a cluster,
  // from the first worker only, not once per worker process.
  try {
    const cluster = require('cluster');
    if (cluster.isWorker && cluster.worker && cluster.worker.id !== 1) return;
  } catch {
    // no cluster module: not a cluster
  }
  if (typeof binding._tlsAgeNoticeOnce === 'function' && !binding._tlsAgeNoticeOnce()) return;
  process.emitWarning(
    `the TLS library bundled with @morojs/engine ${ENGINE_VERSION} (BoringSSL ${tls.version}) is ${ageDays} days old. ` +
      `Its security fixes arrive only with engine releases: update @morojs/engine. ` +
      `(MORO_ENGINE_TLS_AGE_WARNING=0 silences this; MORO_ENGINE_TLS=openssl uses node's OpenSSL instead.)`,
    { code: 'MORO_ENGINE_TLS_STALE' }
  );
}

// serve() as the loader hands it out. Creating a server is not a hot path;
// everything per request stays the raw native call.
//
// Two things happen here that the native function cannot do. A server that
// terminates TLS gets one look at the age of the bundled TLS library. And the
// first TLS server of a thread that is on BoringSSL only because nobody chose
// - not by name, not through MORO_ENGINE_TLS - is retried on node's OpenSSL
// when BoringSSL refuses its configuration: a key type or cipher BoringSSL
// does not have was accepted up to 1.1.19, and an update must not turn it
// into a server that will not start. The retry needs the thread to hold
// nothing of the first binary yet (no server, no other native function handed
// out), because ids and functions of two binaries do not mix; when it does
// hold something, the error is thrown as it is, with the way out appended.
let serversCreated = 0;
const handedOut = new Set();

function serveOnOpenSslInstead(error, self, argsFor) {
  if (!loaded.tls || loaded.tls.reason !== 'default') return undefined; // chosen by name, or not BoringSSL
  if (serversCreated > 0 || handedOut.size > 0) {
    error.message += ` [TLS library: the bundled BoringSSL. If node's OpenSSL accepts this configuration, MORO_ENGINE_TLS=openssl selects it.]`;
    return undefined;
  }
  const other = loadNamed(binaryName('openssl'), []);
  if (!other) return undefined;
  let serverId;
  try {
    serverId = other.module.serve.apply(self, argsFor(other.module));
  } catch {
    return undefined; // wrong for both libraries: the first error stands
  }
  loaded = { ...other, tls: { reason: 'fallback', fallbackReason: notAccepted(error.message) } };
  return serverId;
}

let tlsAgeChecked = false;

// What the operator told node about every TLS server of the process, applied
// to an ssl options object that does not say otherwise: `node --tls-min-v1.3`
// (tls.DEFAULT_MIN_VERSION) raises the protocol floor, `node --tls-max-v1.2`
// (tls.DEFAULT_MAX_VERSION) lowers the ceiling, and
// `node --tls-cipher-list=...` (tls.DEFAULT_CIPHERS) is the cipher list, its
// TLS 1.3 suite names going to `ciphersuites` as node itself splits them.
// node's own servers obey both; a server here that did not would accept what
// the operator ruled out, and say nothing. The app's own minVersion,
// maxVersion, ciphers or ciphersuites win, as they do for node. Returns `ssl`
// itself when there is nothing to add.
function withNodeTlsPolicy(ssl) {
  if (!ssl || typeof ssl !== 'object') return ssl;
  let nodeTls;
  try {
    nodeTls = require('tls');
  } catch {
    return ssl; // a node built without crypto
  }
  let out = ssl;
  if (ssl.minVersion == null && nodeTls.DEFAULT_MIN_VERSION === 'TLSv1.3') {
    out = { ...out, minVersion: 'TLSv1.3' };
  }
  if (ssl.maxVersion == null && ssl.minVersion !== 'TLSv1.3' && nodeTls.DEFAULT_MAX_VERSION === 'TLSv1.2') {
    out = { ...out, maxVersion: 'TLSv1.2' };
  }
  // A list other than the one compiled into node: the flag was given (or
  // the app assigned tls.DEFAULT_CIPHERS). Asked this way and not of
  // execArgv, where a test runner repeats every option with its default.
  let builtIn;
  try {
    builtIn = require('crypto').constants.defaultCoreCipherList;
  } catch {
    builtIn = undefined;
  }
  const listed = nodeTls.DEFAULT_CIPHERS;
  if (ssl.ciphers == null && ssl.ciphersuites == null && typeof listed === 'string' && typeof builtIn === 'string' && listed !== builtIn) {
    const names = listed.split(':').filter(Boolean);
    const suites = names.filter((name) => name.startsWith('TLS_'));
    const list = names.filter((name) => !name.startsWith('TLS_'));
    if (suites.length) out = { ...out, ciphersuites: suites.join(':') };
    if (list.length) out = { ...out, ciphers: list.join(':') };
  }
  return out;
}

// ---- dispatch trampolines ---------------------------------------------------
//
// onRequest, onRequestBatch, onAborted and onWritable reach the engine wrapped
// in one of the functions below. The engine enters them through
// node::MakeCallback, which keeps Node's callback scope on the native stack
// (a scope opened around a plain call is allocated per call), and for that
// has no exception handler of its own around the call. So the wrapper does
// what the engine's native handler did: an exception the application's
// callback throws is reported on stderr (the same line) and goes no further,
// and the batch wrapper tells the engine that the application has left its
// loop over the batch before anything queued by the handlers runs. Nothing
// else changes for the callback: it is called with the same arguments and
// with `this` the global object, and what a nextTick callback or a microtask
// it queued throws is the process's uncaught exception, as before. A stack
// trace taken inside it has this file's frame below it.
//
// MORO_ENGINE_DISPATCH=scope turns the wrapping off (diagnostics): the engine
// then opens the scope and catches natively, as it does for callbacks handed
// to the binding directly.
const DISPATCH_TRAMPOLINES = process.env.MORO_ENGINE_DISPATCH !== 'scope';
const ReflectApply = Reflect.apply;
const FunctionPrototypeBind = Function.prototype.bind;
// The callback, called on the global object whatever it is called on.
const onGlobal = (cb) => ReflectApply(FunctionPrototypeBind, cb, [globalThis]);

function requestTrampoline(cb, report) {
  const call = onGlobal(cb);
  return function dispatchRequest(reqId, methodIdx, path) {
    try {
      call(reqId, methodIdx, path);
    } catch (error) {
      report(0, error);
    }
  };
}

function noticeTrampoline(cb, report) {
  const call = onGlobal(cb);
  return function dispatchNotice(reqId) {
    try {
      call(reqId);
    } catch (error) {
      report(0, error);
    }
  };
}

function batchTrampoline(cb, report, batchDone) {
  const call = onGlobal(cb);
  return function dispatchBatch(count) {
    try {
      call(count);
    } catch (error) {
      batchDone();
      report(1, error);
      return;
    }
    batchDone();
  };
}

// The callbacks object serve() hands to `binding`: each property read once,
// in the order the binding reads them, the four above wrapped.
function readCallbacks(callbacks) {
  return {
    onRequest: callbacks.onRequest,
    onRequestBatch: callbacks.onRequestBatch,
    onAborted: callbacks.onAborted,
    onWritable: callbacks.onWritable,
    onWsOpen: callbacks.onWsOpen,
    onWsMessage: callbacks.onWsMessage,
    onWsClose: callbacks.onWsClose,
  };
}
function withTrampolines(binding, read) {
  const report = binding._reportCaught;
  const batchDone = binding._batchDone;
  const out = { ...read };
  if (typeof read.onRequest === 'function') out.onRequest = requestTrampoline(read.onRequest, report);
  if (typeof read.onRequestBatch === 'function') out.onRequestBatch = batchTrampoline(read.onRequestBatch, report, batchDone);
  if (typeof read.onAborted === 'function') out.onAborted = noticeTrampoline(read.onAborted, report);
  if (typeof read.onWritable === 'function') out.onWritable = noticeTrampoline(read.onWritable, report);
  return out;
}
const canTrampoline = (binding) => typeof binding._reportCaught === 'function' && typeof binding._batchDone === 'function';

function serve(callbacks, options) {
  const tls = Boolean(options && options.ssl);
  const binding = loaded.module;
  const args = Array.prototype.slice.call(arguments);
  if (tls) {
    const ssl = withNodeTlsPolicy(options.ssl);
    if (ssl !== options.ssl) args[1] = { ...options, ssl };
  }
  // (A callbacks argument that is not an object goes to the binding as it
  // is, and is refused there.)
  const wrap = DISPATCH_TRAMPOLINES && callbacks !== null && (typeof callbacks === 'object' || typeof callbacks === 'function');
  const read = wrap ? readCallbacks(callbacks) : null;
  const argsFor = (mod) => {
    // The third argument says "these are trampolines"; nothing else may.
    if (!wrap || !canTrampoline(mod)) return args.slice(0, 2);
    return [withTrampolines(mod, read), args[1], true];
  };
  let serverId;
  try {
    serverId = binding.serve.apply(this, argsFor(binding));
  } catch (error) {
    serverId = tls ? serveOnOpenSslInstead(error, this, argsFor) : undefined;
    if (serverId === undefined) throw error;
  }
  serversCreated++;
  if (tls && !tlsAgeChecked) {
    tlsAgeChecked = true;
    warnIfBundledTlsIsOld(loaded.module);
  }
  return serverId;
}

// updateSsl() builds a whole new context from the options it is given, so
// the process-wide policy above goes into it the same way.
function updateSsl(serverId, ssl) {
  return loaded.module.updateSsl(serverId, withNodeTlsPolicy(ssl));
}

// The native binding's function exports (src/binding.cpp Initialize; mirrored by
// the ESM named exports in index.mjs). ONLY these names force a native load —
// anything else reads as undefined without loading, so `require`/`import` of
// this package never throws on a platform with no prebuilt binary, even when a
// module-interop probe (TypeScript `__importDefault` reads `__esModule`, Babel
// `interopRequireDefault` reads `default`, `JSON.stringify` reads `toJSON`,
// `util.inspect` reads assorted keys) walks the exports object. `probe` and
// `version` are served from the target below and likewise never load.
const NATIVE_API = new Set([
  'serve',
  'listen',
  'close',
  'stopListening',
  'updateSsl',
  'getMethod',
  'getBatchBuffers',
  'getPath',
  'getQuery',
  'getHeaders',
  'getHeader',
  'getBody',
  'getBodyType',
  'getBodyText',
  'getBodyLent',
  'getRemoteAddress',
  'isAborted',
  'respond',
  'writeHead',
  'write',
  'end',
  'setStaticRoute',
  'clearStaticRoutes',
  'setParamRoute',
  'clearParamRoutes',
  'prepareResponse',
  'releaseTemplates',
  'respondPrepared',
  'respondPreparedEmpty',
  'writeHeadPrepared',
  'endWith',
  'upgradeToWebSocket',
  'wsSend',
  'wsClose',
  'setWsAutoUpgrade',
  'wsGetHeaders',
  'wsGetQuery',
  'wsGetRemoteAddress',
]);

module.exports = new Proxy(
  { probe, selectTls, version: ENGINE_VERSION },
  {
    get(target, prop) {
      if (prop in target) return target[prop];
      // Only a known native API name forces the load. Everything else —
      // symbols, `then` (awaiting the module), and interop probes like
      // `__esModule`/`default`/`toJSON` — resolves to undefined WITHOUT loading,
      // so importing this package can never throw on an unsupported platform.
      if (typeof prop === 'string' && NATIVE_API.has(prop)) {
        // Cache the native function on the target so every later read
        // short-circuits on `prop in target` above: the call site then sees
        // one constant function (inline-cacheable, fast-call eligible)
        // instead of a fresh trap invocation per call.
        const binding = loadBinding();
        if (prop === 'serve') {
          target.serve = serve;
          return serve;
        }
        handedOut.add(prop);
        const fn = prop === 'updateSsl' && typeof binding.updateSsl === 'function' ? updateSsl : binding[prop];
        target[prop] = fn;
        return fn;
      }
      return undefined;
    },
    has(target, prop) {
      // Keep `in` consistent with the get trap (so `'serve' in engine` works for
      // feature detection) without forcing a native load: a key is present iff
      // it is served from the target or is a known native API name.
      if (prop in target) return true;
      return typeof prop === 'string' && NATIVE_API.has(prop);
    },
  }
);
