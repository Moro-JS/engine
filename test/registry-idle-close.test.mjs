// The per-thread request registry (flat_map.h) uses key 0 as its empty-slot
// marker. A connection that closes before it ever surfaced a request still
// carries reqId 0, and its teardown erased "key 0" - which found the first
// empty slot, shifted live entries into it and drove the size counter below
// zero. From then on every insert grew the table, doubling it each time, until
// the process stalled in the rehash. Forty idle closes between requests were
// enough. The registry now ignores key 0 on both insert and erase; this keeps
// it that way: idle closes interleaved with requests, then a burst of requests
// that must all complete promptly.
import { test } from 'node:test';
import assert from 'node:assert';
import net from 'node:net';
import engine from '../packages/engine/index.mjs';

const CRLF = '\r\n';

function idleClose(port) {
  return new Promise((resolve) => {
    const s = net.connect(port, '127.0.0.1', () => s.destroy());
    s.on('close', resolve);
    s.on('error', resolve);
  });
}

function get(port, path) {
  return new Promise((resolve, reject) => {
    const s = net.connect(port, '127.0.0.1', () =>
      s.write(`GET ${path} HTTP/1.1${CRLF}Host: t${CRLF}Connection: close${CRLF}${CRLF}`)
    );
    let buf = '';
    s.on('data', (d) => (buf += d));
    s.on('end', () => resolve(buf));
    s.on('error', reject);
    s.setTimeout(3000, () => {
      s.destroy();
      reject(new Error(`timeout after ${JSON.stringify(buf.slice(0, 40))}`));
    });
  });
}

test('connections closed before a request do not corrupt the request registry', async () => {
  let hits = 0;
  const sid = engine.serve({
    onRequest(reqId) {
      hits++;
      engine.respond(reqId, 200, null, 'ok');
    },
    onAborted() {},
  });
  const port = engine.listen(sid, '127.0.0.1', 0);
  try {
    // Sixty idle closes, each followed by one served request: the old registry
    // was doubling its table on every second cycle by this point.
    for (let i = 0; i < 60; i++) {
      await idleClose(port);
      const r = await get(port, `/${i}`);
      assert.match(r, /^HTTP\/1\.1 200/);
    }
    // A burst on top: every request answered, none stalled.
    const started = Date.now();
    const burst = await Promise.all(Array.from({ length: 50 }, (_, i) => get(port, `/b/${i}`)));
    for (const r of burst) assert.ok(r.endsWith('ok'), r.slice(0, 60));
    assert.ok(Date.now() - started < 2500, `burst took ${Date.now() - started}ms`);
    assert.strictEqual(hits, 110);
  } finally {
    engine.close(sid);
  }
});
