// Parameter routes: a route with one variable path segment whose body is that
// segment, answered inside the engine without entering JS, byte-identical to
// respond(status, headers, segment). Non-matching shapes - empty segment, a
// second slash, another method, a different suffix - still reach onRequest.
import { test } from 'node:test';
import assert from 'node:assert';
import net from 'node:net';
import engine from '../packages/engine/index.mjs';

const GET = 0;
const POST = 1;

function raw(port, reqLine) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(port, '127.0.0.1', () => sock.write(reqLine));
    let buf = '';
    sock.on('data', (d) => (buf += d));
    sock.on('end', () => resolve(buf));
    sock.on('error', reject);
    sock.setTimeout(5000, () => {
      sock.destroy();
      reject(new Error('timeout'));
    });
  });
}

const req = (method, path) =>
  `${method} ${path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n`;

test('probe advertises paramRoutes', () => {
  assert.strictEqual(engine.probe().capabilities?.paramRoutes, true);
});

test('a parameter route echoes the segment without entering JS', async () => {
  let jsHits = 0;
  const seen = [];
  const sid = engine.serve({
    onRequest(reqId, method, path) {
      jsHits++;
      seen.push(`${method}:${path}`);
      engine.respond(reqId, 200, null, 'from-js');
    },
    onAborted() {},
  });
  const port = engine.listen(sid, '127.0.0.1', 0);
  try {
    engine.setParamRoute(sid, GET, '/user/', '', 200, null);
    engine.setParamRoute(sid, GET, '/files/', '.json', 200, ['content-type', 'application/json']);

    const a = await raw(port, req('GET', '/user/42'));
    assert.match(a, /^HTTP\/1\.1 200/);
    assert.ok(a.endsWith('\r\n\r\n42'), `body should be the segment: ${JSON.stringify(a)}`);
    assert.match(a, /Content-Length: 2\r\n/i);
    assert.strictEqual(jsHits, 0, 'the parameter route must not reach JS');

    const b = await raw(port, req('GET', '/files/report.json'));
    assert.ok(b.endsWith('\r\n\r\nreport'), `suffix route body wrong: ${JSON.stringify(b)}`);
    assert.match(b, /content-type: application\/json\r\n/i);
    assert.strictEqual(jsHits, 0);

    // Undecoded, as on the wire.
    const c = await raw(port, req('GET', '/user/a%20b'));
    assert.ok(c.endsWith('\r\n\r\na%20b'), `segment must be verbatim: ${JSON.stringify(c)}`);
    assert.strictEqual(jsHits, 0);

    // Shapes that do NOT match still reach JS.
    for (const [method, path] of [
      ['GET', '/user/'],        // empty segment
      ['GET', '/user/1/2'],     // a second slash
      ['POST', '/user/42'],     // another method
      ['GET', '/files/x.txt'],  // suffix mismatch
      ['GET', '/user'],         // shorter than prefix + a segment
    ]) {
      const r = await raw(port, req(method, path));
      assert.ok(r.endsWith('from-js'), `${method} ${path} should be served by JS: ${JSON.stringify(r)}`);
    }
    assert.strictEqual(jsHits, 5);
    assert.deepStrictEqual(seen, ['0:/user/', '0:/user/1/2', '1:/user/42', '0:/files/x.txt', '0:/user']);
  } finally {
    engine.close(sid);
  }
});

test('the reply is byte-identical to respond() with the same segment', async () => {
  const sid = engine.serve({
    onRequest(reqId, _method, path) {
      engine.respond(reqId, 200, null, path.slice('/user/'.length));
    },
    onAborted() {},
  });
  const port = engine.listen(sid, '127.0.0.1', 0);
  try {
    const viaJs = (await raw(port, req('GET', '/user/7'))).replace(/^Date: .*\r\n/im, '');
    engine.setParamRoute(sid, GET, '/user/', '', 200, null);
    const viaEngine = (await raw(port, req('GET', '/user/7'))).replace(/^Date: .*\r\n/im, '');
    assert.strictEqual(viaEngine, viaJs);
  } finally {
    engine.close(sid);
  }
});

test('re-registration replaces, clearParamRoutes hands the route back to JS', async () => {
  let jsHits = 0;
  const sid = engine.serve({
    onRequest(reqId) {
      jsHits++;
      engine.respond(reqId, 200, null, 'from-js');
    },
    onAborted() {},
  });
  const port = engine.listen(sid, '127.0.0.1', 0);
  try {
    engine.setParamRoute(sid, POST, '/items/', '', 201, null);
    engine.setParamRoute(sid, POST, '/items/', '', 202, null); // replaces
    const a = await raw(port, req('POST', '/items/9'));
    assert.match(a, /^HTTP\/1\.1 202/);
    assert.strictEqual(jsHits, 0);

    engine.clearParamRoutes(sid);
    const b = await raw(port, req('POST', '/items/9'));
    assert.ok(b.endsWith('from-js'));
    assert.strictEqual(jsHits, 1);
  } finally {
    engine.close(sid);
  }
});
