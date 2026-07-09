// Smoke test: the addon for this platform/ABI loads, reports sane
// diagnostics, and (when the binary is TLS-capable) terminates one HTTPS
// request end-to-end. CI's smoke matrix is the only thing validating every
// published binary flavor on every OS/Node line, so the TLS probe belongs
// here, not just in the conformance suites.
// Run after tools/build.mjs.
import assert from 'assert';
import https from 'node:https';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import engine, { probe } from '../packages/engine/index.mjs';

const result = probe();
console.log('probe():', result);

assert.strictEqual(result.ok, true, `engine failed to load: ${result.error}`);
assert.strictEqual(String(result.abi), String(process.versions.modules), 'ABI mismatch');
assert.strictEqual(result.platform, process.platform);
assert.ok(engine.version, 'version export missing');

if (result.capabilities?.tls) {
  const fx = (n) => fileURLToPath(new URL(`./fixtures/tls/${n}`, import.meta.url));
  const sid = engine.serve(
    {
      onRequest(reqId) {
        engine.respond(reqId, 200, null, 'tls-smoke');
      },
      onAborted() {},
    },
    { ssl: { key_file_name: fx('localhost.key'), cert_file_name: fx('localhost.pem') } }
  );
  const port = engine.listen(sid, '127.0.0.1', 0);
  const body = await new Promise((resolve, reject) => {
    const req = https.get(
      { host: '127.0.0.1', port, path: '/', ca: readFileSync(fx('ca.pem')), servername: 'localhost' },
      (res) => {
        let d = '';
        res.on('data', (c) => (d += c));
        res.on('end', () => resolve(`${res.statusCode}:${d}`));
      }
    );
    req.on('error', reject);
    req.setTimeout(5000, () => reject(new Error('tls smoke timeout')));
  });
  engine.close(sid);
  assert.strictEqual(body, '200:tls-smoke', 'HTTPS round-trip failed');
  console.log('tls smoke OK');
}

console.log(`smoke OK - @morojs/engine ${engine.version} on Node ${process.versions.node} (ABI ${process.versions.modules})`);
