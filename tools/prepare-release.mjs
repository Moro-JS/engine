#!/usr/bin/env node
// Release assembler for @morojs/engine.
//
// Given a version and a build/ directory of compiled binaries (one .node per
// platform x arch x libc x Node ABI, produced by the build matrix), this:
//   1. Copies each platform's matching binaries into its per-platform package
//      directory and drops the root LICENSE alongside them.
//   2. Syncs EVERY package.json version to the release version, and rewrites the
//      meta package's exact-pinned optionalDependencies to the same version, so
//      the hand-maintained version strings (meta + every platform package) can
//      never drift.
//
//   3. Puts BoringSSL's licence beside the binaries that carry it
//      (LICENSE-BORINGSSL, from the pinned source tree, commit-verified).
//
// Binary naming: moro_engine_<platform>_<arch>[_<libc>]_<abi>[_boringssl].node
// Package dirs:  engine-<platform>-<arch>[-<libc>]  (so <platform>_<arch>[_<libc>]
//                is the dir name after 'engine-' with '-' -> '_').
//
// Usage: node tools/prepare-release.mjs <version> [--check]
//   --check verifies every platform package (win32 included) received BOTH
//           binaries - the one on node's OpenSSL and the one carrying
//           BoringSSL - for EVERY supported Node ABI. A release must not
//           publish a package that is missing one: the loader would quietly
//           serve TLS from the other library, or have nothing to load.

import {
  readdirSync,
  readFileSync,
  writeFileSync,
  copyFileSync,
  existsSync,
  mkdirSync,
} from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { TARGETS } from './build.mjs';
import { fetchSource, readPin } from './boringssl.mjs';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const buildDir = join(root, 'build');
const packagesDir = join(root, 'packages');
const licenseSrc = join(root, 'LICENSE');

const version = process.argv[2];
const check = process.argv.includes('--check');
if (!version || version.startsWith('--')) {
  console.error('usage: node tools/prepare-release.mjs <version> [--check]');
  process.exit(1);
}
if (!/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(version)) {
  console.error(`invalid semver version: ${version}`);
  process.exit(1);
}

function readJson(p) {
  return JSON.parse(readFileSync(p, 'utf8'));
}
function writeJson(p, obj) {
  writeFileSync(p, JSON.stringify(obj, null, 2) + '\n');
}

// Every per-platform package directory (engine-*, excluding the meta 'engine').
const platformDirs = readdirSync(packagesDir).filter(
  (d) => d.startsWith('engine-') && existsSync(join(packagesDir, d, 'package.json'))
);

const binaries = existsSync(buildDir)
  ? readdirSync(buildDir).filter((f) => f.endsWith('.node'))
  : [];

const problems = [];

// The BoringSSL binaries are a redistribution of BoringSSL: its licence text
// travels with them. Taken from the exact tree the binaries were built from.
let boringLicense = null;
if (binaries.some((b) => b.endsWith('_boringssl.node'))) {
  const pin = readPin();
  boringLicense = { path: join(fetchSource(pin), 'LICENSE'), tag: pin.tag };
  if (!existsSync(boringLicense.path)) {
    console.error(`BoringSSL ${pin.tag} has no LICENSE file at ${boringLicense.path}`);
    process.exit(1);
  }
}

for (const dir of platformDirs) {
  const pkgPath = join(packagesDir, dir, 'package.json');
  const pkg = readJson(pkgPath);
  pkg.version = version;
  writeJson(pkgPath, pkg);

  // engine-linux-x64-musl -> prefix "moro_engine_linux_x64_musl_"
  const prefix = `moro_engine_${dir.slice('engine-'.length).replace(/-/g, '_')}_`;
  const matches = binaries.filter((b) => b.startsWith(prefix));
  const destDir = join(packagesDir, dir);
  for (const b of matches) {
    copyFileSync(join(buildDir, b), join(destDir, b));
  }
  if (existsSync(licenseSrc)) {
    copyFileSync(licenseSrc, join(destDir, 'LICENSE'));
  }
  if (boringLicense && matches.some((b) => b.endsWith('_boringssl.node'))) {
    copyFileSync(boringLicense.path, join(destDir, 'LICENSE-BORINGSSL'));
  }
  console.log(`${dir}: version ${version}, ${matches.length} binaries`);
  if (check) {
    for (const { abi } of TARGETS) {
      for (const name of [`${prefix}${abi}.node`, `${prefix}${abi}_boringssl.node`]) {
        if (!matches.includes(name)) problems.push(`${dir}: ${name} is missing`);
      }
    }
    if (boringLicense && !existsSync(join(destDir, 'LICENSE-BORINGSSL'))) {
      problems.push(`${dir}: LICENSE-BORINGSSL is missing`);
    }
  }
}

// Meta package: sync its own version and every optionalDependency pin.
const metaPath = join(packagesDir, 'engine', 'package.json');
const meta = readJson(metaPath);
meta.version = version;
if (meta.optionalDependencies) {
  for (const dep of Object.keys(meta.optionalDependencies)) {
    meta.optionalDependencies[dep] = version;
  }
}
writeJson(metaPath, meta);
console.log(`engine (meta): version ${version}, ${Object.keys(meta.optionalDependencies ?? {}).length} pinned optionalDependencies`);

if (problems.length) {
  console.error('\nRelease check failed:');
  for (const p of problems) console.error(`  - ${p}`);
  process.exit(1);
}
console.log('\nRelease prepared.');
