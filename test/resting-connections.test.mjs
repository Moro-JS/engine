// A connection between requests holds no request state
// (capabilities.restingConnections): the parser, the request snapshot and the
// response buffers are taken from the server's pool when bytes arrive and
// given back when the connection comes to rest. probe().connections reports
// how many of the calling thread's connections are at rest, which is what
// these tests watch, together with the one thing that must not change: every
// request is answered with its own data, however many connections have used
// the same pooled state in between.
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import net from 'node:net';
import tls from 'node:tls';
import { fileURLToPath } from 'node:url';
import engine from '../packages/engine/index.mjs';

const CRLF = '\r\n';
const delay = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitFor(predicate, message, timeout = 3000) {
  const end = Date.now() + timeout;
  for (;;) {
    if (predicate()) return;
    if (Date.now() > end) assert.fail(`${message} (connections: ${JSON.stringify(engine.probe().connections)})`);
    await delay(5);
  }
}

// A client socket that hands back one complete response at a time (the
// fixture always sends Content-Length).
function client(port) {
  return new Promise((resolve, reject) => {
    const s = net.connect(port, '127.0.0.1');
    s.setNoDelay(true);
    let buf = Buffer.alloc(0);
    let waiter = null;
    const take = () => {
      const text = buf.toString('latin1');
      const headEnd = text.indexOf(CRLF + CRLF);
      if (headEnd < 0) return null;
      const m = /content-length: (\d+)/i.exec(text.slice(0, headEnd));
      const total = headEnd + 4 + (m ? Number(m[1]) : 0);
      if (buf.length < total) return null;
      const one = buf.subarray(0, total).toString('latin1');
      buf = buf.subarray(total);
      return { status: Number(one.slice(9, 12)), head: one.slice(0, headEnd), body: one.slice(headEnd + 4) };
    };
    const pump = () => {
      if (!waiter) return;
      const r = take();
      if (r) {
        const w = waiter;
        waiter = null;
        w.resolve(r);
      }
    };
    s.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      pump();
    });
    s.on('error', (e) => (waiter ? waiter.reject(e) : reject(e)));
    s.on('connect', () =>
      resolve({
        socket: s,
        write: (bytes) => s.write(bytes),
        response: () =>
          new Promise((res, rej) => {
            waiter = { resolve: res, reject: rej };
            pump();
          }),
        close: () => new Promise((res) => (s.once('close', res), s.destroy())),
      })
    );
  });
}

const request = (path, { method = 'GET', headers = {}, body = '' } = {}) => {
  let head = `${method} ${path} HTTP/1.1${CRLF}Host: t${CRLF}`;
  for (const [k, v] of Object.entries(headers)) head += `${k}: ${v}${CRLF}`;
  if (body) head += `Content-Length: ${Buffer.byteLength(body)}${CRLF}`;
  return head + CRLF + body;
};

const caps = engine.probe().capabilities;
const skip = caps.restingConnections ? false : 'this engine build keeps request state on the connection';

describe('resting connections', { skip }, () => {
  let sid;
  let port;
  const held = new Map(); // path -> reqId, for requests a test answers later
  const conns = () => engine.probe().connections;

  before(() => {
    sid = engine.serve({
      onRequest(reqId, _method, path) {
        if (path.startsWith('/hold')) {
          held.set(path, reqId);
          return;
        }
        // Everything the request carried, so that an answer built from
        // another request's state cannot pass for this one's.
        const body = engine.getBody(reqId);
        const echo = JSON.stringify({
          path,
          query: engine.getQuery(reqId),
          tag: engine.getHeader(reqId, 'x-tag') ?? null,
          body: body ? Buffer.from(body).toString('latin1') : '',
          ...(path.startsWith('/full/') || path.startsWith('/bare/') ? { headers: engine.getHeaders(reqId) } : {}),
        });
        engine.respond(reqId, 200, ['content-type', 'application/json'], echo);
      },
      onAborted() {},
    });
    port = engine.listen(sid, '127.0.0.1', 0);
  });
  after(() => engine.close(sid));

  it('a connection is at rest from the moment it is accepted, and again after every answered request', async () => {
    const cs = await Promise.all(Array.from({ length: 20 }, () => client(port)));
    await waitFor(() => conns().open === 20 && conns().resting === 20, 'accepted connections are at rest');
    for (let round = 0; round < 3; round++) {
      for (const [i, c] of cs.entries()) c.write(request(`/r${round}/c${i}`));
      const answers = await Promise.all(cs.map((c) => c.response()));
      answers.forEach((a, i) => assert.equal(JSON.parse(a.body).path, `/r${round}/c${i}`));
      await waitFor(() => conns().resting === 20, 'every connection is at rest after its response');
    }
    await Promise.all(cs.map((c) => c.close()));
    await waitFor(() => conns().open === 0 && conns().resting === 0, 'closed connections are counted out');
  });

  it('each request is answered with its own path, query, header and body, whoever used the state before', async () => {
    const a = await client(port);
    const b = await client(port);
    for (let i = 0; i < 150; i++) {
      // Different shapes on the two connections, so that every field of the
      // pooled state changes hands between them: one with everything, one
      // with nothing.
      const full = i % 2 === 0 ? a : b;
      const bare = i % 2 === 0 ? b : a;
      const payload = 'p'.repeat(1 + (i % 40)) + i;
      full.write(request(`/full/${i}?q=${i}&z=${'y'.repeat(i % 30)}`, { method: 'POST', headers: { 'X-Tag': `t${i}` }, body: payload }));
      assert.deepEqual(JSON.parse((await full.response()).body), {
        path: `/full/${i}`,
        query: `q=${i}&z=${'y'.repeat(i % 30)}`,
        tag: `t${i}`,
        body: payload,
        headers: ['host', 't', 'x-tag', `t${i}`, 'content-length', String(payload.length)],
      });
      bare.write(request(`/bare/${i}`));
      // Exactly its own header list: nothing of the request before it.
      assert.deepEqual(JSON.parse((await bare.response()).body), {
        path: `/bare/${i}`,
        query: '',
        tag: null,
        body: '',
        headers: ['host', 't'],
      });
    }
    await waitFor(() => conns().resting === 2, 'both connections end at rest');
    await a.close();
    await b.close();
  });

  it('a request that arrives in pieces keeps its state until it is complete', async () => {
    const c = await client(port);
    await waitFor(() => conns().resting === 1, 'at rest before the request');
    const bytes = request('/pieces?x=1', { method: 'POST', headers: { 'X-Tag': 'split' }, body: 'hello world' });
    c.write(bytes.slice(0, 9)); // inside the request line
    await delay(60);
    assert.equal(conns().resting, 0, 'mid request line: not at rest');
    c.write(bytes.slice(9, bytes.indexOf('X-Tag') + 3)); // inside a header
    await delay(60);
    assert.equal(conns().resting, 0, 'mid headers: not at rest');
    c.write(bytes.slice(bytes.indexOf('X-Tag') + 3, bytes.length - 4)); // inside the body
    await delay(60);
    assert.equal(conns().resting, 0, 'mid body: not at rest');
    c.write(bytes.slice(bytes.length - 4));
    assert.deepEqual(JSON.parse((await c.response()).body), { path: '/pieces', query: 'x=1', tag: 'split', body: 'hello world' });
    await waitFor(() => conns().resting === 1, 'at rest once answered');
    await c.close();
  });

  it('pipelined requests are answered in order and leave the connection at rest', async () => {
    const c = await client(port);
    let batch = '';
    for (let i = 0; i < 40; i++) batch += request(`/pipe/${i}?n=${i}`, { headers: { 'X-Tag': `p${i}` } });
    c.write(batch);
    for (let i = 0; i < 40; i++) {
      assert.deepEqual(JSON.parse((await c.response()).body), { path: `/pipe/${i}`, query: `n=${i}`, tag: `p${i}`, body: '' });
    }
    await waitFor(() => conns().resting === 1, 'at rest after the batch');
    // A batch whose last request is incomplete: the tail keeps the state.
    const tail = request('/pipe/tail', { headers: { 'X-Tag': 'last' } });
    c.write(request('/pipe/a') + request('/pipe/b') + tail.slice(0, tail.length - 6));
    assert.equal(JSON.parse((await c.response()).body).path, '/pipe/a');
    assert.equal(JSON.parse((await c.response()).body).path, '/pipe/b');
    await delay(60);
    assert.equal(conns().resting, 0, 'an unfinished request behind a batch: not at rest');
    c.write(tail.slice(tail.length - 6));
    assert.deepEqual(JSON.parse((await c.response()).body), { path: '/pipe/tail', query: '', tag: 'last', body: '' });
    await waitFor(() => conns().resting === 1, 'at rest again');
    await c.close();
  });

  it('a request a handler holds is not at rest; answered later, the connection rests at the next read on the server', async () => {
    const slow = await client(port);
    const other = await client(port);
    slow.write(request('/hold/1'));
    await waitFor(() => held.has('/hold/1'), 'the handler received the request');
    assert.deepEqual(conns(), { open: 2, resting: 1 });
    // Requests on another connection come and go; the held one stays put.
    for (let i = 0; i < 5; i++) {
      other.write(request(`/meanwhile/${i}`));
      assert.equal(JSON.parse((await other.response()).body).path, `/meanwhile/${i}`);
    }
    assert.deepEqual(conns(), { open: 2, resting: 1 });

    engine.respond(held.get('/hold/1'), 200, null, 'late');
    assert.equal((await slow.response()).body, 'late');
    // Answered outside a read: its state goes back when the server next reads.
    other.write(request('/after'));
    await other.response();
    await waitFor(() => conns().resting === 2, 'the answered connection is at rest');

    // And it serves its next request as any other.
    slow.write(request('/again?k=v', { headers: { 'X-Tag': 'again' } }));
    assert.deepEqual(JSON.parse((await slow.response()).body), { path: '/again', query: 'k=v', tag: 'again', body: '' });
    await slow.close();
    await other.close();
    held.clear();
  });

  it('a connection that closes while its request is held is counted out once', async () => {
    const c = await client(port);
    c.write(request('/hold/gone'));
    await waitFor(() => held.has('/hold/gone'), 'the handler received the request');
    assert.deepEqual(conns(), { open: 1, resting: 0 });
    await c.close();
    await waitFor(() => conns().open === 0, 'the connection is gone');
    assert.equal(conns().resting, 0);
    // The answer goes nowhere and breaks nothing.
    engine.respond(held.get('/hold/gone'), 200, null, 'too late');
    held.clear();
    const next = await client(port);
    next.write(request('/next'));
    assert.equal(JSON.parse((await next.response()).body).path, '/next');
    await next.close();
    await waitFor(() => conns().open === 0 && conns().resting === 0, 'counted out');
  });

  it('a Connection: close exchange and a rejected request never rest, and are counted out', async () => {
    const c = await client(port);
    c.write(request('/bye', { headers: { Connection: 'close' } }));
    assert.equal(JSON.parse((await c.response()).body).path, '/bye');
    await c.close();
    const bad = await client(port);
    bad.write(`GET /x HTTP/1.1${CRLF}Host: a${CRLF}Host: b${CRLF}${CRLF}`);
    assert.equal((await bad.response()).status, 400);
    await bad.close();
    await waitFor(() => conns().open === 0 && conns().resting === 0, 'counted out');
  });

  it('trimMemory() returns the heap that start-up left behind and the server serves on', { skip: caps.memoryTrim ? false : 'no trimMemory()' }, async () => {
    assert.equal(typeof engine.trimMemory, 'function');
    assert.equal(engine.trimMemory(), undefined);
    const c = await client(port);
    c.write(request('/after-trim?ok=1'));
    assert.deepEqual(JSON.parse((await c.response()).body), { path: '/after-trim', query: 'ok=1', tag: null, body: '' });
    await c.close();
  });
});

describe('resting connections over TLS', { skip }, () => {
  it('a connection is at rest once its handshake is done, and after each request', async () => {
    const dir = new URL('./fixtures/tls/', import.meta.url);
    const sid = engine.serve(
      {
        onRequest(reqId, _m, path) {
          engine.respond(reqId, 200, null, `tls ${path}`);
        },
        onAborted() {},
      },
      {
        ssl: {
          key_file_name: fileURLToPath(new URL('localhost.key', dir)),
          cert_file_name: fileURLToPath(new URL('localhost.pem', dir)),
        },
      }
    );
    const port = engine.listen(sid, '127.0.0.1', 0);
    const conns = () => engine.probe().connections;
    try {
      const socks = await Promise.all(
        Array.from({ length: 8 }, () =>
          new Promise((resolve, reject) => {
            const s = tls.connect({ host: '127.0.0.1', port, rejectUnauthorized: false, ALPNProtocols: ['http/1.1'] });
            s.once('secureConnect', () => resolve(s));
            s.once('error', reject);
          })
        )
      );
      // Handshake done, no request sent: nothing of a request is held.
      await waitFor(() => conns().open === 8 && conns().resting === 8, 'handshaken connections are at rest');
      for (let round = 0; round < 3; round++) {
        const answers = await Promise.all(
          socks.map(
            (s, i) =>
              new Promise((resolve) => {
                let buf = '';
                const onData = (d) => {
                  buf += d;
                  if (buf.includes(`tls /r${round}/${i}`)) {
                    s.off('data', onData);
                    resolve(buf);
                  }
                };
                s.on('data', onData);
                s.write(request(`/r${round}/${i}`));
              })
          )
        );
        answers.forEach((a) => assert.match(a, /^HTTP\/1\.1 200/));
        await waitFor(() => conns().resting === 8, 'at rest after the responses');
      }
      socks.forEach((s) => s.destroy());
      await waitFor(() => conns().open === 0 && conns().resting === 0, 'counted out');
    } finally {
      engine.close(sid);
    }
  });
});

describe('connections that keep their request state', { skip }, () => {
  it('a WebSocket is open and never at rest', async () => {
    let opened = 0;
    const sid = engine.serve({
      onRequest(reqId) {
        engine.respond(reqId, 200, null, 'http');
      },
      onAborted() {},
      onWsOpen() {
        opened++;
      },
      onWsMessage() {},
      onWsClose() {},
    });
    engine.setWsAutoUpgrade(sid, true);
    const port = engine.listen(sid, '127.0.0.1', 0);
    try {
      const s = net.connect(port, '127.0.0.1');
      await new Promise((r) => s.once('connect', r));
      s.write(
        `GET /chat?room=1 HTTP/1.1${CRLF}Host: t${CRLF}Upgrade: websocket${CRLF}Connection: Upgrade${CRLF}` +
          `Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==${CRLF}Sec-WebSocket-Version: 13${CRLF}${CRLF}`
      );
      await waitFor(() => opened === 1, 'the upgrade completed');
      await delay(50);
      assert.deepEqual(engine.probe().connections, { open: 1, resting: 0 });
      s.destroy();
      await waitFor(() => engine.probe().connections.open === 0, 'the socket is gone');
      assert.equal(engine.probe().connections.resting, 0);
    } finally {
      engine.close(sid);
    }
  });
});
