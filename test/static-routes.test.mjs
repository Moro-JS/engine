// Static routes: a registered (method, path) is answered inside the engine
// without entering JS, and the bytes on the wire are identical to the same
// response sent through respond().
import { test } from 'node:test';
import assert from 'node:assert';
import net from 'node:net';
import engine from '../packages/engine/index.mjs';

const GET = 0;
const POST = 1;

// One raw request/response on a fresh connection, returned verbatim so we can
// compare framing byte for byte (not just the parsed body).
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

test('static route answers without entering JS', async () => {
  let jsHits = 0;
  const seen = [];
  const sid = engine.serve({
    onRequest(reqId, method, path) {
      jsHits++;
      seen.push(path);
      engine.respond(reqId, 200, null, 'from-js');
    },
    onAborted() {},
  });
  const port = engine.listen(sid, '127.0.0.1', 0);

  engine.setStaticRoute(sid, GET, '/static', 200, null, 'hello');
  engine.setStaticRoute(sid, POST, '/user', 200, null, '');

  const a = await raw(port, req('GET', '/static'));
  assert.match(a, /^HTTP\/1\.1 200/, 'static GET should be 200');
  assert.ok(a.endsWith('hello'), `static GET body wrong: ${JSON.stringify(a)}`);
  assert.strictEqual(jsHits, 0, 'static route must not reach JS');

  const b = await raw(port, req('POST', '/user'));
  assert.match(b, /^HTTP\/1\.1 200/, 'static POST should be 200');
  assert.strictEqual(jsHits, 0, 'static POST must not reach JS');

  // An unregistered path still reaches JS.
  const c = await raw(port, req('GET', '/dynamic'));
  assert.ok(c.endsWith('from-js'), 'dynamic route should be served by JS');
  assert.strictEqual(jsHits, 1, 'dynamic route should reach JS exactly once');
  assert.deepStrictEqual(seen, ['/dynamic']);

  // A method with no static entry on a static path falls through to JS.
  const d = await raw(port, req('DELETE', '/static'));
  assert.ok(d.endsWith('from-js'), 'unregistered method should fall through');
  assert.strictEqual(jsHits, 2);

  // HEAD against a registered GET is deliberately NOT short-circuited.
  await raw(port, req('HEAD', '/static'));
  assert.strictEqual(jsHits, 3, 'HEAD must fall through to JS');

  engine.close(sid);
});

test('static response is byte-identical to the respond() path', async () => {
  // Same status, headers and body served both ways; the wire bytes must match.
  const headers = ['content-type', 'text/plain', 'x-marker', 'abc'];

  const jsSid = engine.serve({
    onRequest(reqId) {
      engine.respond(reqId, 201, headers, 'payload');
    },
    onAborted() {},
  });
  const jsPort = engine.listen(jsSid, '127.0.0.1', 0);
  const viaJs = await raw(jsPort, req('GET', '/x'));
  engine.close(jsSid);

  const stSid = engine.serve({
    onRequest(reqId) {
      engine.respond(reqId, 500, null, 'should-not-be-reached');
    },
    onAborted() {},
  });
  const stPort = engine.listen(stSid, '127.0.0.1', 0);
  engine.setStaticRoute(stSid, GET, '/x', 201, headers, 'payload');
  const viaStatic = await raw(stPort, req('GET', '/x'));
  engine.close(stSid);

  const strip = (s) => s.replace(/^date:.*\r\n/gim, '');
  assert.strictEqual(strip(viaStatic), strip(viaJs), 'static bytes differ from respond() bytes');
});

test('re-registering replaces, and clearStaticRoutes restores JS routing', async () => {
  let jsHits = 0;
  const sid = engine.serve({
    onRequest(reqId) {
      jsHits++;
      engine.respond(reqId, 200, null, 'from-js');
    },
    onAborted() {},
  });
  const port = engine.listen(sid, '127.0.0.1', 0);

  engine.setStaticRoute(sid, GET, '/r', 200, null, 'first');
  const one = await raw(port, req('GET', '/r'));
  assert.ok(one.endsWith('first'));

  engine.setStaticRoute(sid, GET, '/r', 200, null, 'second');
  const two = await raw(port, req('GET', '/r'));
  assert.ok(two.endsWith('second'), 're-registration should replace, not duplicate');
  assert.strictEqual(jsHits, 0);

  engine.clearStaticRoutes(sid);
  const three = await raw(port, req('GET', '/r'));
  assert.ok(three.endsWith('from-js'), 'cleared route should fall back to JS');
  assert.strictEqual(jsHits, 1);

  engine.close(sid);
});
