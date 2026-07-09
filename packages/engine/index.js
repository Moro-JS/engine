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
  // glibc exposes its version in the process report; musl does not. When the
  // report API is unavailable entirely, assume glibc (the overwhelmingly
  // common case) rather than musl.
  try {
    const report = process.report && process.report.getReport();
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

module.exports = new Proxy(
  { probe, version: ENGINE_VERSION },
  {
    get(target, prop) {
      if (prop in target) return target[prop];
      // Structural probes must never force (and possibly fail) the native
      // load: `then` is touched by `await`/Promise.resolve() on the module,
      // and symbols by console.log/util.inspect. Real engine API props are
      // string-named and never `then`.
      if (typeof prop === 'symbol' || prop === 'then') return undefined;
      // Everything else (serve, listen, ... as the engine grows) comes from the
      // native binding, loaded on first touch. `probe` and `version` are served
      // from the target above so neither forces a native load.
      const binding = loadBinding();
      return binding[prop];
    },
  }
);
