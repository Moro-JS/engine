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
import { spawnSync } from 'node:child_process';
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

// A binding call resolves its reqId to a connection and then acts on that
// connection. Reading the other arguments can run JavaScript - a status with
// a valueOf, a header value with a toString, an element getter - and that
// JavaScript can answer the very request the call is for. The id has to be
// resolved after the arguments are read: resolved before, the outer call went
// on to write a second response on a connection that had no request any
// more, which a keep-alive client reads as the answer to its next request.
function exchange(port, bytes, quietMs = 150) {
  return new Promise((resolve, reject) => {
    const s = net.connect(port, '127.0.0.1', () => s.write(bytes));
    let buf = '';
    s.on('data', (d) => (buf += d.toString('latin1')));
    s.on('error', reject);
    setTimeout(() => {
      s.destroy();
      resolve(buf);
    }, quietMs);
  });
}

const reentrantCalls = {
  'respond(): the status answers the request': (reqId) =>
    engine.respond(reqId, { valueOf: () => (engine.respond(reqId, 200, null, 'inner'), 200) }, null, 'outer'),
  'respond(): a header value answers the request': (reqId) =>
    engine.respond(reqId, 200, ['x-a', { toString: () => (engine.respond(reqId, 200, null, 'inner'), 'v') }], 'outer'),
  'respond(): a header array getter answers the request': (reqId) => {
    const headers = ['x-a', 'v'];
    Object.defineProperty(headers, 1, { get: () => (engine.respond(reqId, 200, null, 'inner'), 'v') });
    engine.respond(reqId, 200, headers, 'outer');
  },
  'writeHead(): the status answers the request': (reqId) => {
    engine.writeHead(reqId, { valueOf: () => (engine.respond(reqId, 200, null, 'inner'), 200) }, null);
    engine.end(reqId, 'outer');
  },
  'respondPrepared(): the template id answers the request': (reqId, tpl) =>
    engine.respondPrepared(reqId, { valueOf: () => (engine.respond(reqId, 200, null, 'inner'), tpl) }, 'outer'),
  'respondPreparedEmpty(): the template id answers the request': (reqId, tpl) =>
    engine.respondPreparedEmpty(reqId, { valueOf: () => (engine.respond(reqId, 200, null, 'inner'), tpl) }),
  'writeHeadPrepared(): the template id answers the request': (reqId, tpl) => {
    engine.writeHeadPrepared(reqId, { valueOf: () => (engine.respond(reqId, 200, null, 'inner'), tpl) });
    engine.end(reqId, 'outer');
  },
  // (returns what it read: the request was over by the time the name was known)
  'getHeader(): the name answers the request': (reqId) =>
    engine.getHeader(reqId, { toString: () => (engine.respond(reqId, 200, null, 'inner'), 'host') }),
};

for (const [name, call] of Object.entries(reentrantCalls)) {
  test(`one response per request - ${name}`, async () => {
    let tpl = 0;
    const returned = [];
    const sid = engine.serve({
      onRequest(reqId, _m, path) {
        if (path === '/next') engine.respond(reqId, 200, null, 'next');
        else returned.push(call(reqId, tpl));
      },
      onAborted() {},
    });
    tpl = engine.prepareResponse(sid, 200, ['x-t', '1']);
    const port = engine.listen(sid, '127.0.0.1', 0);
    try {
      // Alone, then with a second request pipelined behind it: the second
      // must get its own answer, not the outer call's.
      const alone = await exchange(port, `GET /a HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`);
      assert.strictEqual((alone.match(/HTTP\/1\.1 /g) || []).length, 1, JSON.stringify(alone));
      assert.ok(alone.endsWith('inner'), JSON.stringify(alone));
      const two = await exchange(port, `GET /a HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}GET /next HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`);
      assert.strictEqual((two.match(/HTTP\/1\.1 /g) || []).length, 2, JSON.stringify(two));
      assert.ok(two.endsWith('next'), JSON.stringify(two));
      assert.ok(!two.includes('outer'), JSON.stringify(two));
      assert.deepStrictEqual(returned, [undefined, undefined], 'nothing is read from a request that is over');
    } finally {
      engine.close(sid);
    }
  });
}

// The same on HTTP/2, where each request sits on a pooled object of its own:
// answered from inside the argument read, that object went back to the pool
// and the outer call framed an HTTP/1 response on something with no socket.
// In a child process: the process ending is what the unfixed engine did.
test('one response per request on HTTP/2, and the process lives', () => {
  const script = `
    import http2 from 'node:http2';
    const { default: engine } = await import(${JSON.stringify(new URL('../packages/engine/index.mjs', import.meta.url).href)});
    const sid = engine.serve({
      onRequest(reqId) {
        engine.respond(reqId, { valueOf: () => (engine.respond(reqId, 200, null, 'inner'), 200) }, null, 'outer');
      },
      onAborted() {},
    }, { http2: true });
    const port = engine.listen(sid, '127.0.0.1', 0);
    const client = http2.connect('http://127.0.0.1:' + port);
    const bodies = [];
    for (let i = 0; i < 3; i++) {
      bodies.push(await new Promise((resolve, reject) => {
        const r = client.request({ ':path': '/' + i });
        let b = '';
        r.on('data', (d) => (b += d));
        r.on('end', () => resolve(b));
        r.on('error', reject);
        r.end();
      }));
    }
    client.close();
    engine.close(sid);
    console.log(JSON.stringify(bodies));
  `;
  const r = spawnSync(process.execPath, ['--input-type=module', '-e', script], { encoding: 'utf8', timeout: 20000 });
  assert.strictEqual(r.status, 0, `status ${r.status} signal ${r.signal}\n${r.stderr.slice(-600)}`);
  assert.deepStrictEqual(JSON.parse(r.stdout.trim()), ['inner', 'inner', 'inner']);
});

// serve() reads its callbacks and options through ordinary property gets. One
// that throws must fail the call with nothing created: the server ids stay
// dense, which they did not while a failed call still built a server (one
// nobody held an id for, and so nobody could close).
test('a serve() that throws creates no server', () => {
  const ok = () => {
    const sid = engine.serve({ onRequest() {} });
    engine.close(sid);
    return sid;
  };
  const before = ok();
  const boom = new Error('getter');
  const throwing = [
    [{ get onRequest() { throw boom; } }, undefined],
    [{ onRequest() {} }, { get maxBodySize() { throw boom; } }],
    [{ onRequest() {} }, new Proxy({}, { get() { throw boom; } })],
    [{ onRequest() {} }, { http2: { get maxFrameSize() { throw boom; } } }],
    [{ onRequest() {} }, { wsDeflate: { get threshold() { throw boom; } } }],
    [{ onRequest() {} }, { ssl: { get key() { throw boom; } } }],
  ];
  for (const [callbacks, options] of throwing) {
    assert.throws(() => engine.serve(callbacks, options), (e) => e === boom);
  }
  assert.strictEqual(ok(), before + 1, 'no id was used up by the calls that threw');
});
