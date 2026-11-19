#!/usr/bin/env node
// The versions this repository releases, and the npm dist-tag each one is
// published under.
//
//   X.Y.Z                       a release            -> dist-tag `latest`
//   X.Y.Z-rc.N (alpha|beta|rc)  a release candidate  -> dist-tag `next`
//
// A release candidate is installed only by someone who asks for it
// (`npm install @morojs/engine@next`, or the exact version): `latest`, which
// is what a plain install and every semver range resolve against, does not
// move. Nothing else is a version here - no build metadata, no bare numeric
// or unnumbered prerelease (`1.2.0-1`, `1.2.0-rc`, `1.2.0-rc1`): npm would
// order those in ways that are easy to get wrong, and the release tooling
// refuses what it cannot place.
//
//   node tools/version.mjs <version | vX.Y.Z tag>
//       prints version, dist-tag and prerelease; inside a workflow step also
//       writes them as outputs (version, dist_tag, prerelease). Exit 1 when
//       the argument is not a version this repository releases.

import { appendFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const NUM = '(0|[1-9]\\d*)';
const VERSION_RE = new RegExp(`^${NUM}\\.${NUM}\\.${NUM}(?:-(alpha|beta|rc)\\.([1-9]\\d*))?$`);
const STAGE = { alpha: 0, beta: 1, rc: 2 };

/** Parse `1.2.3` or `1.2.3-rc.1`; throws on anything else. */
export function parseVersion(text) {
  const m = VERSION_RE.exec(String(text));
  if (!m) {
    throw new Error(
      `"${text}" is not a version this repository releases: X.Y.Z, or X.Y.Z-rc.N (also -beta.N, -alpha.N; N from 1) for a release candidate`
    );
  }
  const pre = m[4] ? { stage: m[4], n: Number(m[5]) } : null;
  return {
    version: m[0],
    core: `${m[1]}.${m[2]}.${m[3]}`,
    major: Number(m[1]),
    minor: Number(m[2]),
    patch: Number(m[3]),
    pre,
    prerelease: pre !== null,
    distTag: pre ? 'next' : 'latest',
  };
}

/** Semver order of two versions of the form above: <0, 0, >0. */
export function compareVersions(a, b) {
  const x = typeof a === 'string' ? parseVersion(a) : a;
  const y = typeof b === 'string' ? parseVersion(b) : b;
  for (const k of ['major', 'minor', 'patch']) {
    if (x[k] !== y[k]) return x[k] - y[k];
  }
  if (!x.pre || !y.pre) return (x.pre ? 0 : 1) - (y.pre ? 0 : 1); // a release is after its candidates
  return STAGE[x.pre.stage] - STAGE[y.pre.stage] || x.pre.n - y.pre.n;
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  try {
    const arg = process.argv[2] ?? '';
    const v = parseVersion(arg.startsWith('v') ? arg.slice(1) : arg);
    console.log(`${v.version}: dist-tag ${v.distTag}${v.prerelease ? ' (release candidate: latest does not move)' : ''}`);
    if (process.env.GITHUB_OUTPUT) {
      appendFileSync(process.env.GITHUB_OUTPUT, `version=${v.version}\ndist_tag=${v.distTag}\nprerelease=${v.prerelease}\n`);
    }
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }
}
