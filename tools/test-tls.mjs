#!/usr/bin/env node
// The suites that terminate TLS, run against one named TLS library.
//
//   node tools/test-tls.mjs openssl      # the binary on node's OpenSSL
//   node tools/test-tls.mjs boringssl    # the binary that carries BoringSSL
//
// `npm run test:suites` runs everything against the loader's default
// (BoringSSL) and then calls this for OpenSSL, so every lane that runs the
// suites proves both binaries. MORO_ENGINE_REQUIRE_TLS makes a silent fallback
// to the other library a failure instead of a pass on the wrong one.

import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const library = process.argv[2];
if (library !== 'openssl' && library !== 'boringssl') {
  console.error('usage: node tools/test-tls.mjs <openssl|boringssl>');
  process.exit(2);
}
if (process.env.MORO_ENGINE_BINARY) {
  // One binary is pinned for this run (PGO training, an A/B): it is the only
  // one that can be loaded, and the suites have already run against it.
  console.log(`test-tls: MORO_ENGINE_BINARY is set - not re-running the TLS suites on ${library}`);
  process.exit(0);
}

const suites = [
  'test/tls-conformance.test.mjs',
  'test/tls-hardening.test.mjs',
  'test/tls-reload.test.mjs',
  'test/tls-write-path.test.mjs',
  'test/http2.test.mjs',
];
console.log(`test-tls: ${suites.length} suites on ${library}`);
const r = spawnSync(process.execPath, ['--test', ...suites], {
  cwd: root,
  stdio: 'inherit',
  env: { ...process.env, MORO_ENGINE_TLS: library, MORO_ENGINE_REQUIRE_TLS: library },
});
process.exit(r.status ?? 1);
