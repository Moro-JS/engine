'use strict';
// @morojs/engine loader (CJS core - .node addon loading is require-based).
//
// Resolution order:
//   1. The matching per-platform package (@morojs/engine-<platform>-<arch>[-libc])
//      published as an exact-version optionalDependency of this package.
//   2. A local build/ directory (engine repo development).
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
const { join } = require('path');

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

function opensslIsConfigured() {
  const flags = `${process.execArgv.join(' ')} ${process.env.NODE_OPTIONS || ''}`;
  for (const flag of OPENSSL_NODE_FLAGS) {
    if (flags.includes(flag)) return flag;
  }
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
    return { module: require(require.resolve(`${pkg}/${name}`)), from: pkg };
  } catch (err) {
    attempts.push(`${pkg}/${name}: ${err.message.split('\n')[0]}`);
  }

  // 2. Engine repo local build (development)
  const local = join(__dirname, '..', '..', 'build', name);
  if (existsSync(local)) {
    try {
      return { module: require(local), from: local };
    } catch (err) {
      attempts.push(`${local}: ${err.message.split('\n')[0]}`);
    }
  } else {
    attempts.push(`${local}: not present`);
  }
  return null;
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
      return { module: require(explicit), from: explicit };
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
      const refused = tlsRefusal(first.module, plannedSsl);
      if (refused) {
        const other = loadNamed(binaryName('openssl'), []);
        if (other && !tlsRefusal(other.module, plannedSsl)) {
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
  return { ...native, version: ENGINE_VERSION, tls: tlsInfo(native) };
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

function serveOnOpenSslInstead(error, self, args) {
  if (!loaded.tls || loaded.tls.reason !== 'default') return undefined; // chosen by name, or not BoringSSL
  if (serversCreated > 0 || handedOut.size > 0) {
    error.message += ` [TLS library: the bundled BoringSSL. If node's OpenSSL accepts this configuration, MORO_ENGINE_TLS=openssl selects it.]`;
    return undefined;
  }
  const other = loadNamed(binaryName('openssl'), []);
  if (!other) return undefined;
  let serverId;
  try {
    serverId = other.module.serve.apply(self, args);
  } catch {
    return undefined; // wrong for both libraries: the first error stands
  }
  loaded = { ...other, tls: { reason: 'fallback', fallbackReason: notAccepted(error.message) } };
  return serverId;
}

let tlsAgeChecked = false;

function serve(callbacks, options) {
  const tls = Boolean(options && options.ssl);
  const binding = loaded.module;
  let serverId;
  try {
    serverId = binding.serve.apply(this, arguments);
  } catch (error) {
    serverId = tls ? serveOnOpenSslInstead(error, this, arguments) : undefined;
    if (serverId === undefined) throw error;
  }
  serversCreated++;
  if (tls && !tlsAgeChecked) {
    tlsAgeChecked = true;
    warnIfBundledTlsIsOld(loaded.module);
  }
  return serverId;
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
        const fn = binding[prop];
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
