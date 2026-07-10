#!/usr/bin/env node
// One-command release driver for @morojs/engine.
//
//   node tools/release.mjs patch          # 1.0.0 -> 1.0.1
//   node tools/release.mjs minor          # 1.0.0 -> 1.1.0
//   node tools/release.mjs major          # 1.0.0 -> 2.0.0
//   node tools/release.mjs 1.2.3          # explicit version
//
// Flags:
//   --dry-run       show everything that WOULD happen, change nothing
//   --no-push       commit + tag locally, but don't push (push later yourself)
//   --skip-checks   skip the build + smoke gate (not recommended)
//
// What it does, in order:
//   1. Safety gates: clean working tree, on main, --skip-checks-able build+smoke.
//   2. Bumps the version EVERYWHERE it lives: the meta package + its exact
//      optionalDependencies pins, all 6 platform packages, the monorepo root,
//      and the kEngineVersion fallback in src/binding.cpp.
//   3. Commits "chore: release vX.Y.Z", tags vX.Y.Z, pushes main + the tag.
//   4. The pushed tag triggers .github/workflows/release.yml, which rebuilds
//      every platform and publishes to npm with provenance. Nothing publishes
//      from this machine.
//
// (CI's prepare-release.mjs re-syncs versions from the tag at publish time, so
// even a missed file here can't drift what actually ships - this script keeps
// the repo itself consistent.)

import { execSync } from 'node:child_process';
import { readFileSync, writeFileSync, readdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const args = process.argv.slice(2);
const dryRun = args.includes('--dry-run');
const noPush = args.includes('--no-push');
const skipChecks = args.includes('--skip-checks');
const bumpArg = args.find(a => !a.startsWith('--'));

function die(msg) {
  console.error(`\nrelease aborted: ${msg}`);
  process.exit(1);
}
function sh(cmd, opts = {}) {
  return execSync(cmd, { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], ...opts }).trim();
}
function run(cmd) {
  console.log(`  $ ${cmd}`);
  if (!dryRun) execSync(cmd, { cwd: root, stdio: 'inherit' });
}

// ---- compute the next version ----
const metaPath = join(root, 'packages/engine/package.json');
const current = JSON.parse(readFileSync(metaPath, 'utf8')).version;
let next;
if (/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(bumpArg ?? '')) {
  next = bumpArg;
} else if (['patch', 'minor', 'major'].includes(bumpArg ?? '')) {
  const [ma, mi, pa] = current.split('.').map(n => parseInt(n, 10));
  next =
    bumpArg === 'major' ? `${ma + 1}.0.0` :
    bumpArg === 'minor' ? `${ma}.${mi + 1}.0` :
    `${ma}.${mi}.${pa + 1}`;
} else {
  die(`usage: node tools/release.mjs <patch|minor|major|x.y.z> [--dry-run] [--no-push] [--skip-checks]\n  current version: ${current}`);
}

console.log(`\n@morojs/engine release: ${current} -> ${next}${dryRun ? '  (DRY RUN)' : ''}\n`);

// ---- safety gates ----
const dirty = sh('git status --porcelain');
if (dirty) die(`working tree is not clean - commit or stash first:\n${dirty}`);

const branch = sh('git branch --show-current');
if (branch !== 'main') die(`on branch '${branch}' - releases cut from main`);

if (sh(`git tag -l v${next}`)) die(`tag v${next} already exists`);

if (!skipChecks) {
  console.log('build + smoke gate (skip with --skip-checks):');
  run('node tools/build.mjs');
  run('node test/smoke.mjs');
} else {
  console.log('  (build/smoke gate skipped)');
}

// ---- bump every version ----
console.log('\nbumping versions:');
function bumpJson(path) {
  const pkg = JSON.parse(readFileSync(path, 'utf8'));
  pkg.version = next;
  if (pkg.optionalDependencies) {
    for (const dep of Object.keys(pkg.optionalDependencies)) {
      pkg.optionalDependencies[dep] = next;
    }
  }
  console.log(`  ${path.replace(root + '/', '')} -> ${next}`);
  if (!dryRun) writeFileSync(path, JSON.stringify(pkg, null, 2) + '\n');
}
bumpJson(metaPath);
bumpJson(join(root, 'package.json'));
for (const dir of readdirSync(join(root, 'packages'))) {
  const p = join(root, 'packages', dir, 'package.json');
  if (dir.startsWith('engine-') && existsSync(p)) bumpJson(p);
}

// kEngineVersion is a build-time fallback (the loader overrides it from
// package.json), but keep it in step so a raw binary never reports stale.
const bindingPath = join(root, 'src/binding.cpp');
const binding = readFileSync(bindingPath, 'utf8');
const stamped = binding.replace(
  /(static const char\* kEngineVersion = ")[^"]+(";)/,
  `$1${next}$2`
);
if (stamped === binding) die('could not find kEngineVersion in src/binding.cpp');
console.log(`  src/binding.cpp kEngineVersion -> ${next}`);
if (!dryRun) writeFileSync(bindingPath, stamped);

// ---- commit, tag, push ----
console.log('\ngit:');
run(`git add -A`);
run(`git commit -m "chore: release v${next}"`);
run(`git tag v${next}`);
if (noPush) {
  console.log(`\ndone (not pushed). When ready:  git push origin main v${next}`);
} else {
  run(`git push origin main v${next}`);
  console.log(`\ndone. Tag v${next} pushed - release.yml is now building all platforms and will publish to npm with provenance.`);
  console.log(`watch it: https://github.com/Moro-JS/engine/actions`);
}
