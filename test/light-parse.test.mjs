// Route-first parsing: a request the engine will answer itself (static or
// parameter route, nothing queued ahead of it) is parsed in "light" mode -
// headers validated and the framing ones interpreted, none stored. This pins
// down that light mode keeps every semantic of the full parse: body framing
// (Content-Length, chunked), the 400/413/431 rejections, Connection and
// HTTP/1.0 keep-alive rules, Expect handling, and that a JS-routed request
// on the same connection - before, after, or pipelined between engine
// routes - still sees its headers and its order.
import { test } from 'node:test';
import assert from 'node:assert';
import net from 'node:net';
import engine from '../packages/engine/index.mjs';

const CRLF = '\r\n';
const GET = 0;
const POST = 1;

function open(port) {
  return new Promise((resolve, reject) => {
    const s = net.connect(port, '127.0.0.1', () => resolve(s));
    s.on('error', reject);
  });
}
// Send bytes; collect until `n` complete responses (Content-Length framed,
// bodies counted) or the socket ends.
function exchange(port, bytes, n = 1, { waitClose = false } = {}) {
  return new Promise((resolve, reject) => {
    const s = net.connect(port, '127.0.0.1', () => s.write(bytes, 'latin1'));
    let buf = '';
    const count = () => {
      let k = 0, pos = 0;
      for (;;) {
        const he = buf.indexOf('\r\n\r\n', pos);
        if (he < 0) return k;
        const cl = parseInt(buf.slice(pos, he).match(/\r\ncontent-length:\s*(\d+)/i)?.[1] ?? '0', 10);
        if (buf.length < he + 4 + cl) return k;
        k++;
        pos = he + 4 + cl;
      }
    };
    s.on('data', (d) => {
      buf += d.toString('latin1');
      if (!waitClose && count() >= n) { s.destroy(); resolve({ buf, closed: false }); }
    });
    s.on('end', () => resolve({ buf, closed: true }));
    s.on('close', () => resolve({ buf, closed: true }));
    s.on('error', reject);
    s.setTimeout(4000, () => { s.destroy(); reject(new Error(`timeout: ${JSON.stringify(buf.slice(0, 120))}`)); });
  });
}
const statuses = (buf) => [...buf.matchAll(/HTTP\/1\.1 (\d{3})/g)].map((m) => Number(m[1]));
// Bodies of the Content-Length framed responses in a stream, in order.
const bodies = (buf) => {
  const out = [];
  let pos = 0;
  for (;;) {
    const he = buf.indexOf('\r\n\r\n', pos);
    if (he < 0) return out;
    const cl = parseInt(buf.slice(pos, he).match(/\r\ncontent-length:\s*(\d+)/i)?.[1] ?? '0', 10);
    out.push(buf.slice(he + 4, he + 4 + cl));
    pos = he + 4 + cl;
  }
};

test('light parse keeps framing, errors, keep-alive and JS visibility', async () => {
  const seen = [];
  const sid = engine.serve({
    onRequest(reqId, _m, path) {
      const headers = engine.getHeaders ? engine.getHeaders(reqId) : null;
      seen.push({ path, headers });
      engine.respond(reqId, 200, null, `js:${path}`);
    },
    onAborted() {},
  });
  const port = engine.listen(sid, '127.0.0.1', 0);
  engine.setStaticRoute(sid, GET, '/s', 200, null, 'static');
  engine.setStaticRoute(sid, POST, '/s', 200, null, 'posted');
  engine.setParamRoute(sid, GET, '/user/', '', 200, null);
  const H = `Host: t${CRLF}`;
  try {
    // Content-Length body on an engine route is consumed and the connection stays usable.
    let r = await exchange(port, `POST /s HTTP/1.1${CRLF}${H}Content-Length: 5${CRLF}${CRLF}hello` + `GET /user/7 HTTP/1.1${CRLF}${H}${CRLF}`, 2);
    assert.deepStrictEqual(statuses(r.buf), [200, 200]);
    assert.deepStrictEqual(bodies(r.buf), ['posted', '7']);

    // Chunked body on an engine route.
    r = await exchange(port, `POST /s HTTP/1.1${CRLF}${H}Transfer-Encoding: chunked${CRLF}${CRLF}5${CRLF}hello${CRLF}0${CRLF}${CRLF}` + `GET /s HTTP/1.1${CRLF}${H}${CRLF}`, 2);
    assert.deepStrictEqual(statuses(r.buf), [200, 200]);

    // Rejections behave as on the full parse.
    r = await exchange(port, `GET /s HTTP/1.1${CRLF}${CRLF}`); // no Host on 1.1
    assert.deepStrictEqual(statuses(r.buf), [400]);
    r = await exchange(port, `POST /s HTTP/1.1${CRLF}${H}Content-Length: 1${CRLF}Content-Length: 2${CRLF}${CRLF}xx`);
    assert.deepStrictEqual(statuses(r.buf), [400]);
    r = await exchange(port, `POST /s HTTP/1.1${CRLF}${H}Content-Length: 5${CRLF}Transfer-Encoding: chunked${CRLF}${CRLF}`);
    assert.deepStrictEqual(statuses(r.buf), [400]);
    r = await exchange(port, `POST /s HTTP/1.1${CRLF}${H}Transfer-Encoding: gzip${CRLF}${CRLF}`);
    assert.deepStrictEqual(statuses(r.buf), [400]);
    r = await exchange(port, `POST /s HTTP/1.1${CRLF}${H}Content-Length: 99999999999${CRLF}${CRLF}`);
    assert.deepStrictEqual(statuses(r.buf), [413]);
    r = await exchange(port, `GET /s HTTP/1.1${CRLF}${H}X-Bad Name: 1${CRLF}${CRLF}`); // space in field name
    assert.deepStrictEqual(statuses(r.buf), [400]);
    r = await exchange(port, `GET /s HTTP/1.1${CRLF}${H}` + 'X-N: 1\r\n'.repeat(150) + CRLF); // > maxHeaders
    assert.deepStrictEqual(statuses(r.buf), [431]);

    // Connection semantics.
    r = await exchange(port, `GET /s HTTP/1.1${CRLF}${H}Connection: close${CRLF}${CRLF}`, 1, { waitClose: true });
    assert.ok(r.closed && r.buf.includes('Connection: close'), 'http/1.1 close: ' + JSON.stringify(r));
    r = await exchange(port, `GET /s HTTP/1.0${CRLF}${H}${CRLF}`, 1, { waitClose: true });
    assert.ok(r.closed && r.buf.includes('Connection: close'), 'http/1.0: ' + JSON.stringify(r));
    r = await exchange(port, `GET /s HTTP/1.0${CRLF}${H}Connection: keep-alive${CRLF}${CRLF}` + `GET /s HTTP/1.0${CRLF}${H}Connection: keep-alive${CRLF}${CRLF}`, 2);
    assert.deepStrictEqual(statuses(r.buf), [200, 200]);
    assert.ok(r.buf.includes('Connection: keep-alive'));

    // Expect: 100-continue with the body already sent: the final reply is
    // enough (RFC 9110 §10.1.1); with the body withheld, the interim is sent.
    r = await exchange(port, `POST /s HTTP/1.1${CRLF}${H}Expect: 100-continue${CRLF}Content-Length: 2${CRLF}${CRLF}hi`);
    assert.ok(statuses(r.buf).includes(200));
    {
      const s = await open(port);
      let buf = '';
      s.on('data', (d) => (buf += d));
      s.write(`POST /s HTTP/1.1${CRLF}${H}Expect: 100-continue${CRLF}Content-Length: 2${CRLF}${CRLF}`);
      await new Promise((res) => setTimeout(res, 150));
      assert.match(buf, /^HTTP\/1\.1 100 Continue\r\n\r\n$/);
      s.write('hi');
      await new Promise((res) => setTimeout(res, 150));
      assert.ok(buf.includes('HTTP/1.1 200 OK'), buf);
      s.destroy();
    }

    // Nothing above reached JS: every request was an engine route or rejected.
    assert.strictEqual(seen.length, 0);

    // The cached frame of an engine route carries a live Date: two replies
    // straddling a second boundary differ, and the later one is current.
    {
      const dateOf = (buf) => buf.match(/^Date: (.*)\r\n/m)?.[1];
      const first = dateOf((await exchange(port, `GET /s HTTP/1.1${CRLF}${H}${CRLF}`)).buf);
      const p1 = dateOf((await exchange(port, `GET /user/1 HTTP/1.1${CRLF}${H}${CRLF}`)).buf);
      const t0 = Date.now();
      await new Promise((res) => setTimeout(res, 1100 - (t0 % 1000) + 50));
      const second = dateOf((await exchange(port, `GET /s HTTP/1.1${CRLF}${H}${CRLF}`)).buf);
      const p2 = dateOf((await exchange(port, `GET /user/1 HTTP/1.1${CRLF}${H}${CRLF}`)).buf);
      assert.ok(first && second && first !== second, `static Date did not advance: ${first} / ${second}`);
      assert.ok(p1 && p2 && p1 !== p2, `param Date did not advance: ${p1} / ${p2}`);
      assert.ok(Math.abs(Date.parse(second) - Date.now()) < 2500, `stale Date: ${second}`);
    }

    // A JS route after light requests on the same connection sees its headers;
    // a pipelined [engine, js, engine] batch keeps order and JS visibility.
    seen.length = 0;
    r = await exchange(port, `GET /s HTTP/1.1${CRLF}${H}X-A: 1${CRLF}${CRLF}` + `GET /js/1 HTTP/1.1${CRLF}${H}X-B: 2${CRLF}${CRLF}` + `GET /user/9 HTTP/1.1${CRLF}${H}${CRLF}`, 3);
    assert.deepStrictEqual(statuses(r.buf), [200, 200, 200]);
    assert.deepStrictEqual(bodies(r.buf), ['static', 'js:/js/1', '9']);
    assert.strictEqual(seen.length, 1);
    if (seen[0].headers) {
      const flat = JSON.stringify(seen[0].headers).toLowerCase();
      assert.ok(flat.includes('x-b') && flat.includes('"2"'), flat);
      assert.ok(!flat.includes('x-a'), 'headers of the earlier light request leaked: ' + flat);
    }
  } finally {
    engine.close(sid);
  }
});

// One keep-alive socket, one request at a time: send bytes, get the bytes of
// the next `n` Content-Length framed responses.
function session(port) {
  return new Promise((resolve, reject) => {
    let buf = '';
    let waiter = null;
    const framed = () => {
      let k = 0, pos = 0;
      for (;;) {
        const he = buf.indexOf('\r\n\r\n', pos);
        if (he < 0) return k;
        const cl = parseInt(buf.slice(pos, he).match(/\r\ncontent-length:\s*(\d+)/i)?.[1] ?? '0', 10);
        if (buf.length < he + 4 + cl) return k;
        k++;
        pos = he + 4 + cl;
      }
    };
    const s = net.connect(port, '127.0.0.1', () => resolve(api));
    s.on('data', (d) => {
      buf += d.toString('latin1');
      if (waiter && framed() >= waiter.n) {
        const out = buf;
        buf = '';
        const w = waiter;
        waiter = null;
        w.resolve(out);
      }
    });
    s.on('error', reject);
    const api = {
      send: (bytes, n = 1) =>
        new Promise((res, rej) => {
          const t = setTimeout(() => rej(new Error(`timeout: ${JSON.stringify(buf.slice(0, 120))}`)), 4000);
          waiter = { n, resolve: (v) => { clearTimeout(t); res(v); } };
          s.write(bytes, 'latin1');
        }),
      close: () => s.destroy(),
    };
  });
}

// Repeated requests on one keep-alive connection, through the fast lane:
// the reply, its live Date, the route table (a replaced or cleared route
// takes effect on the very next request), a different request in between,
// and two copies in one write (answered in order).
test('repeated requests on a keep-alive connection follow the route table and the clock', async () => {
  const seen = [];
  const sid = engine.serve({
    onRequest(reqId, _m, path) {
      seen.push(path);
      engine.respond(reqId, 200, null, `js:${path}`);
    },
    onAborted() {},
  });
  const port = engine.listen(sid, '127.0.0.1', 0);
  engine.setStaticRoute(sid, GET, '/s', 200, null, 'static');
  engine.setParamRoute(sid, GET, '/user/', '', 200, null);
  const H = `Host: t${CRLF}`;
  const S = `GET /s HTTP/1.1${CRLF}${H}${CRLF}`;
  const U = (id) => `GET /user/${id} HTTP/1.1${CRLF}${H}${CRLF}`;
  const ses = await session(port);
  try {
    let b;
    for (let i = 0; i < 3; i++) {
      b = await ses.send(S);
      assert.deepStrictEqual(statuses(b), [200]);
      assert.deepStrictEqual(bodies(b), ['static']);
    }
    // A JS route in between leaves the repeat valid.
    b = await ses.send(`GET /js HTTP/1.1${CRLF}${H}${CRLF}`);
    assert.deepStrictEqual(bodies(b), ['js:/js']);
    b = await ses.send(S);
    assert.deepStrictEqual(bodies(b), ['static']);
    // A different request is not a repeat; a parameter route is remembered in turn.
    b = await ses.send(U(42));
    assert.deepStrictEqual(bodies(b), ['42']);
    b = await ses.send(U(42));
    assert.deepStrictEqual(bodies(b), ['42']);
    b = await ses.send(U(43));
    assert.deepStrictEqual(bodies(b), ['43']);
    b = await ses.send(U(43));
    assert.deepStrictEqual(bodies(b), ['43']);
    b = await ses.send(U(42));
    assert.deepStrictEqual(bodies(b), ['42']);
    // Two copies in one write are not a repeat of one: both answered, in order.
    b = await ses.send(S + S, 2);
    assert.deepStrictEqual(bodies(b), ['static', 'static']);
    b = await ses.send(S);
    assert.deepStrictEqual(bodies(b), ['static']);
    // A replaced route answers with its new reply at once.
    engine.setStaticRoute(sid, GET, '/s', 200, null, 'renewed');
    b = await ses.send(S);
    assert.deepStrictEqual(bodies(b), ['renewed']);
    b = await ses.send(S);
    assert.deepStrictEqual(bodies(b), ['renewed']);
    // A cleared table hands the repeat to JS; a re-registered route takes it back.
    engine.clearStaticRoutes(sid);
    b = await ses.send(S);
    assert.deepStrictEqual(bodies(b), ['js:/s']);
    b = await ses.send(S);
    assert.deepStrictEqual(bodies(b), ['js:/s']);
    engine.setStaticRoute(sid, GET, '/s', 200, null, 'back');
    b = await ses.send(S);
    assert.deepStrictEqual(bodies(b), ['back']);
    engine.clearParamRoutes(sid);
    b = await ses.send(U(42));
    assert.deepStrictEqual(bodies(b), ['js:/user/42']);
    // A repeat across a second boundary carries a fresh Date.
    const dateOf = (buf) => buf.match(/^Date: (.*)\r\n/m)?.[1];
    const d1 = dateOf(await ses.send(S));
    const t0 = Date.now();
    await new Promise((res) => setTimeout(res, 1100 - (t0 % 1000) + 50));
    const d2 = dateOf(await ses.send(S));
    assert.ok(d1 && d2 && d1 !== d2, `Date on a repeat did not advance: ${d1} / ${d2}`);
    assert.ok(Math.abs(Date.parse(d2) - Date.now()) < 2500, `stale Date: ${d2}`);
    assert.deepStrictEqual(seen, ['/js', '/s', '/s', '/user/42']);
  } finally {
    ses.close();
    engine.close(sid);
  }
});
