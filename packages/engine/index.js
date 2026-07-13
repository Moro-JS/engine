'use strict';
// @morojs/engine loader (CJS core - .node addon loading is require-based).
//
// Resolution order:
//   1. The matching per-platform package (@morojs/engine-<platform>-<arch>[-libc])
//      published as an exact-version optionalDependency of this package.
//   2. A local build/ directory (engine repo development).
//
// Binary naming: moro_engine_<platform>_<arch>[_<libc>]_<abi>.node
// (libc segment on linux only: gnu | musl)

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

function binaryName() {
  const libc = libcSuffix().replace('-', '_'); // '' | '_gnu' | '_musl'
  return `moro_engine_${process.platform}_${process.arch}${libc}_${process.versions.modules}.node`;
}

function platformPackageName() {
  return `@morojs/engine-${process.platform}-${process.arch}${libcSuffix()}`;
}

function tryLoad() {
  const name = binaryName();
  const attempts = [];

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
  return { ...loaded.module.probe(), version: ENGINE_VERSION };
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
  'getMethod',
  'getQuery',
  'getHeaders',
  'getHeader',
  'getBody',
  'getRemoteAddress',
  'isAborted',
  'respond',
  'writeHead',
  'write',
  'end',
  'upgradeToWebSocket',
  'wsSend',
  'wsClose',
]);

module.exports = new Proxy(
  { probe, version: ENGINE_VERSION },
  {
    get(target, prop) {
      if (prop in target) return target[prop];
      // Only a known native API name forces the load. Everything else —
      // symbols, `then` (awaiting the module), and interop probes like
      // `__esModule`/`default`/`toJSON` — resolves to undefined WITHOUT loading,
      // so importing this package can never throw on an unsupported platform.
      if (typeof prop === 'string' && NATIVE_API.has(prop)) {
        return loadBinding()[prop];
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
