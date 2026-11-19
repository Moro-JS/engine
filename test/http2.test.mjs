// HTTP/2, end to end: the engine behind a real client (node:http2, which is
// nghttp2) and, where a client would never send it, behind frames written by
// hand. test/http2-unit.cpp covers the protocol machine alone and
// test/run-h2spec.sh the RFC's conformance suite; what is pinned here is the
// part only a running server has - that a request arriving on a stream is a
// request like any other to everything above the engine, that many of them
// share a socket without stepping on each other, and what becomes of them
// when the client, the handler or the server lets go first.

import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import http2 from 'node:http2';
import net from 'node:net';
import tls from 'node:tls';
import { spawnSync } from 'node:child_process';
import { loadEngine, startFixtureServer, rawRequest, parseResponse, waitFor, delay } from './helpers.mjs';
import { sslFileOptions, fixturePem, openRawTls } from './tls-helpers.mjs';

const T = { timeout: 30000 };
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');

function pattern(n, seed = 1) {
  const out = Buffer.allocUnsafe(n);
  let x = seed >>> 0;
  for (let i = 0; i < n; i++) {
    x = (Math.imul(x, 1664525) + 1013904223) >>> 0;
    out[i] = x >>> 24;
  }
  return out;
}

// One request on a client session. Resolves to { status, headers, body }
// (body a Buffer); rejects with the stream's error.
function request(session, headers, body, { onStream } = {}) {
  return new Promise((resolve, reject) => {
    const stream = session.request(headers, { endStream: body === undefined });
    const chunks = [];
    let head;
    stream.on('response', (h) => (head = h));
    stream.on('data', (d) => chunks.push(d));
    stream.on('end', () => resolve({ status: head?.[':status'], headers: head, body: Buffer.concat(chunks) }));
    stream.on('error', reject);
    if (onStream) onStream(stream);
    if (body !== undefined) stream.end(body);
  });
}

// ---- a client that writes frames by hand ----
//
// For what a real client never does: opening its windows and not reading,
// resetting a stream between two frames, sending bytes a compliant encoder
// would not. Header blocks are literals without indexing; the server's
// blocks are decoded from the two forms its encoder writes (a static index
// for the status, literals with a new or a static name).
const FT = { DATA: 0, HEADERS: 1, PRIORITY: 2, RST_STREAM: 3, SETTINGS: 4, PING: 6, GOAWAY: 7, WINDOW_UPDATE: 8 };
const END_STREAM = 0x1;
const END_HEADERS = 0x4;
const H2_PREFACE = Buffer.from('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n');
const STATIC_NAMES = {
  8: ':status', 18: 'accept-ranges', 20: 'access-control-allow-origin', 21: 'age', 22: 'allow', 24: 'cache-control',
  25: 'content-disposition', 26: 'content-encoding', 27: 'content-language', 28: 'content-length', 29: 'content-location',
  30: 'content-range', 31: 'content-type', 33: 'date', 34: 'etag', 36: 'expires', 44: 'last-modified', 45: 'link',
  46: 'location', 53: 'retry-after', 54: 'server', 55: 'set-cookie', 56: 'strict-transport-security', 59: 'vary',
  61: 'www-authenticate',
};
const STATIC_STATUS = { 0x88: '200', 0x89: '204', 0x8a: '206', 0x8b: '304', 0x8c: '400', 0x8d: '404', 0x8e: '500' };

const u32 = (v) => {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(v >>> 0);
  return b;
};
function h2frame(type, flags, stream, payload = Buffer.alloc(0)) {
  const head = Buffer.alloc(9);
  head.writeUIntBE(payload.length, 0, 3);
  head[3] = type;
  head[4] = flags;
  head.writeUInt32BE(stream >>> 0, 5);
  return Buffer.concat([head, payload]);
}
function hpackInt(prefixBits, value) {
  const mask = (1 << prefixBits) - 1;
  if (value < mask) return [value];
  const out = [mask];
  value -= mask;
  while (value >= 128) {
    out.push((value & 0x7f) | 0x80);
    value >>>= 7;
  }
  out.push(value);
  return out;
}
function hpackBlock(fields) {
  const parts = [];
  for (const [name, value] of fields) {
    const n = Buffer.from(name, 'latin1');
    const v = Buffer.from(value, 'latin1');
    parts.push(Buffer.from([0, ...hpackInt(7, n.length)]), n, Buffer.from(hpackInt(7, v.length)), v);
  }
  return Buffer.concat(parts);
}
const requestFields = (method, path, extra = [], authority = 'h2.test') => [
  [':method', method],
  [':scheme', 'http'],
  [':path', path],
  ...(authority === null ? [] : [[':authority', authority]]),
  ...extra,
];
// A whole request without a body: HEADERS with END_STREAM.
const h2get = (stream, path, extra = [], method = 'GET') =>
  h2frame(FT.HEADERS, END_HEADERS | END_STREAM, stream, hpackBlock(requestFields(method, path, extra)));
function h2settings(pairs = []) {
  const b = Buffer.alloc(pairs.length * 6);
  pairs.forEach(([id, value], i) => {
    b.writeUInt16BE(id, i * 6);
    b.writeUInt32BE(value >>> 0, i * 6 + 2);
  });
  return h2frame(FT.SETTINGS, 0, 0, b);
}
function decodeResponseBlock(block) {
  const fields = [];
  let pos = 0;
  const int = (prefixBits) => {
    const mask = (1 << prefixBits) - 1;
    let value = block[pos++] & mask;
    if (value < mask) return value;
    let shift = 0;
    for (;;) {
      const b = block[pos++];
      value += (b & 0x7f) << shift;
      if (!(b & 0x80)) return value;
      shift += 7;
    }
  };
  const str = () => {
    const len = int(7);
    const out = block.subarray(pos, pos + len).toString('latin1');
    pos += len;
    return out;
  };
  while (pos < block.length) {
    if (block[pos] & 0x80) {
      fields.push([':status', STATIC_STATUS[block[pos++]] ?? '?']);
      continue;
    }
    const index = int(4);
    const name = index === 0 ? str() : STATIC_NAMES[index] ?? `#${index}`;
    fields.push([name, str()]);
  }
  return fields;
}

// Connects, sends the preface and SETTINGS (`settings`: [id, value] pairs),
// and keeps what comes back per stream: { status, fields, bytes, ended, rst }.
// `secure`: over TLS with ALPN h2. `read: false`: the socket is never read
// until resume() - the peer the write high-water mark is there for.
async function rawH2(port, { settings = [], read = true, keepBody = false, secure = false, connectionWindow = 0 } = {}) {
  const socket = secure
    ? tls.connect({ host: '127.0.0.1', port, servername: 'localhost', ca: fixturePem('ca.pem'), ALPNProtocols: ['h2'] })
    : net.connect(port, '127.0.0.1');
  const c = { socket, streams: new Map(), frames: [], closed: false, goaway: -1, received: 0, dataFrames: 0 };
  const stream = (id) => {
    let st = c.streams.get(id);
    if (!st) c.streams.set(id, (st = { status: undefined, fields: [], bytes: 0, body: [], ended: false, rst: -1, headerFrames: 0 }));
    return st;
  };
  const onFrame = (f, payload) => {
    if (f.type === FT.DATA) {
      const st = stream(f.stream);
      c.dataFrames++;
      st.bytes += f.length;
      if (keepBody && payload) st.body.push(payload);
      if (f.flags & END_STREAM) st.ended = true;
      return;
    }
    c.frames.push({ type: f.type, flags: f.flags, stream: f.stream, payload });
    if (f.type === FT.HEADERS) {
      const st = stream(f.stream);
      st.headerFrames++;
      const fields = decodeResponseBlock(payload);
      if (fields[0]?.[1] !== '100') {
        st.fields = fields;
        st.status = Number(fields[0]?.[1]);
      }
      if (f.flags & END_STREAM) st.ended = true;
    } else if (f.type === FT.RST_STREAM) {
      stream(f.stream).rst = payload.readUInt32BE(0);
    } else if (f.type === FT.GOAWAY) {
      c.goaway = payload.readUInt32BE(4);
    }
  };
  const head = Buffer.alloc(9);
  let have = 0;
  let need = -1;
  let cur = null;
  let parts = [];
  socket.on('data', (chunk) => {
    c.received += chunk.length;
    let pos = 0;
    while (pos < chunk.length) {
      if (need < 0) {
        const n = Math.min(9 - have, chunk.length - pos);
        chunk.copy(head, have, pos, pos + n);
        have += n;
        pos += n;
        if (have < 9) break;
        have = 0;
        cur = { length: head.readUIntBE(0, 3), type: head[3], flags: head[4], stream: head.readUInt32BE(5) & 0x7fffffff };
        need = cur.length;
        parts = [];
        if (need === 0) {
          need = -1;
          onFrame(cur, Buffer.alloc(0));
        }
        continue;
      }
      const n = Math.min(need, chunk.length - pos);
      if (cur.type !== FT.DATA || keepBody) parts.push(chunk.subarray(pos, pos + n));
      pos += n;
      need -= n;
      if (need === 0) {
        need = -1;
        onFrame(cur, Buffer.concat(parts));
      }
    }
  });
  socket.on('error', () => {});
  socket.on('close', () => (c.closed = true));
  if (!read) socket.pause();
  await new Promise((resolve, reject) => {
    socket.once(secure ? 'secureConnect' : 'connect', resolve);
    socket.once('error', reject);
  });
  c.send = (...buffers) => new Promise((resolve) => socket.write(Buffer.concat(buffers), () => resolve()));
  c.resume = () => socket.resume();
  c.stream = stream;
  c.bodyOf = (id) => Buffer.concat(stream(id).body).toString('latin1');
  c.field = (id, name) => stream(id).fields.find(([n]) => n === name)?.[1];
  // The response on `id` is over: END_STREAM, or a reset.
  c.done = (id, timeout = 5000) => waitFor(() => stream(id).ended || stream(id).rst >= 0, { timeout, message: `stream ${id} did not end` });
  c.destroy = () => socket.destroy();
  await c.send(
    H2_PREFACE,
    h2settings(settings),
    connectionWindow ? h2frame(FT.WINDOW_UPDATE, 0, 0, u32(connectionWindow - 65535)) : Buffer.alloc(0)
  );
  return c;
}

describe('HTTP/2', () => {
  let engine;
  before(async () => {
    engine = await loadEngine();
  });

  // A server and a connected client; both are closed afterwards.
  async function withH2(handler, fn, { secure = false, options = {}, client = {} } = {}) {
    const server = await startFixtureServer(engine, handler, {
      http2: true,
      ...(secure ? { ssl: sslFileOptions() } : {}),
      ...options,
    });
    const session = secure
      ? http2.connect(`https://localhost:${server.port}`, { ca: fixturePem('ca.pem'), ...client })
      : http2.connect(`http://127.0.0.1:${server.port}`, client);
    const errors = [];
    session.on('error', (err) => errors.push(err));
    try {
      await fn({ server, session, errors });
    } finally {
      if (!session.destroyed) session.destroy();
      server.close();
    }
  }

  it('is advertised', T, () => {
    assert.equal(engine.probe().capabilities.http2, true);
  });

  for (const secure of [false, true]) {
    const kind = secure ? 'TLS (ALPN h2)' : 'cleartext (prior knowledge)';

    it(`${kind}: a request is what an HTTP/1 request is to the handler`, T, async () => {
      let seen;
      await withH2(
        (ctx) => {
          seen = {
            method: ctx.method,
            path: ctx.path,
            query: ctx.query(),
            headers: ctx.headers(),
            host: ctx.header('host'),
            remote: ctx.remoteAddress(),
          };
          ctx.respond(200, ['Content-Type', 'text/plain', 'X-Mixed-Case', 'kept'], 'hello');
        },
        async ({ session }) => {
          const res = await request(session, {
            ':path': '/a/b?x=1&y=two',
            accept: 'text/plain',
            cookie: ['a=1', 'b=2'],
            'x-custom': 'v',
          });
          assert.equal(res.status, 200);
          assert.equal(res.body.toString(), 'hello');
          assert.equal(res.headers['content-type'], 'text/plain');
          assert.equal(res.headers['x-mixed-case'], 'kept');
          assert.equal(res.headers['content-length'], '5');
          assert.match(res.headers.date, /GMT$/);
        },
        { secure }
      );
      assert.equal(seen.method, 'GET');
      assert.equal(seen.path, '/a/b');
      assert.equal(seen.query, 'x=1&y=two');
      assert.match(seen.host, /^(localhost|127\.0\.0\.1):\d+$/);
      assert.match(seen.remote, /127\.0\.0\.1|::1/);
      // Flat [name, value, ...], lowercased, no pseudo-headers.
      const flat = seen.headers;
      const names = flat.filter((_, i) => i % 2 === 0);
      assert.ok(names.every((n) => n === n.toLowerCase() && !n.startsWith(':')), names.join(','));
      assert.ok(names.includes('host') && names.includes('accept') && names.includes('x-custom'));
      const cookies = flat.filter((_, i) => i % 2 === 1 && flat[i - 1] === 'cookie');
      assert.deepEqual(cookies.join('; ').split('; ').sort(), ['a=1', 'b=2']);
    });

    it(`${kind}: two hundred concurrent requests each get their own answer`, T, async () => {
      await withH2(
        async (ctx) => {
          const n = Number(ctx.path.slice(2));
          if (n % 3 === 0) await delay(n % 7); // some answer later, out of order
          ctx.respond(200, ['content-type', 'text/plain'], `answer ${n} ${'x'.repeat(n)}`);
        },
        async ({ session }) => {
          const results = await Promise.all(
            Array.from({ length: 200 }, (_, i) => request(session, { ':path': `/r${i}` }))
          );
          results.forEach((res, i) => {
            assert.equal(res.status, 200);
            assert.equal(res.body.toString(), `answer ${i} ${'x'.repeat(i)}`);
          });
        },
        { secure, options: { http2: { maxConcurrentStreams: 300 } } }
      );
    });

    it(`${kind}: bodies both ways through flow control, byte for byte`, T, async () => {
      const up = pattern(3 << 20, 11);
      const down = pattern(5 << 20, 12);
      let received;
      await withH2(
        (ctx) => {
          if (ctx.method === 'POST') {
            received = sha(Buffer.from(ctx.body()));
            ctx.respond(200, ['content-type', 'application/octet-stream'], Buffer.from(ctx.body()));
          } else {
            ctx.respond(200, ['content-type', 'application/octet-stream'], down);
          }
        },
        async ({ session }) => {
          const echo = await request(session, { ':method': 'POST', ':path': '/up' }, up);
          assert.equal(echo.status, 200);
          assert.equal(received, sha(up));
          assert.equal(sha(echo.body), sha(up));
          // The client's default windows are 64 KiB: the reply is thousands of
          // frames paced by its WINDOW_UPDATEs.
          const big = await request(session, { ':path': '/down' });
          assert.equal(big.headers['content-length'], String(down.length));
          assert.equal(sha(big.body), sha(down));
          // ...and several at once share the connection's window.
          const many = await Promise.all([1, 2, 3, 4].map(() => request(session, { ':path': '/down' })));
          for (const res of many) assert.equal(sha(res.body), sha(down));
        },
        { secure, options: { maxBodySize: 8 << 20 } }
      );
    });
  }

  it('the typed body reads work on an HTTP/2 request', T, async () => {
    const seen = [];
    await withH2(
      (ctx) => {
        const type = engine.getBodyType(ctx.reqId);
        if (ctx.path === '/text') {
          seen.push([type, engine.getBodyText(ctx.reqId)]);
          ctx.respond(200, null, 'ok');
        } else {
          const lent = engine.getBodyLent(ctx.reqId);
          seen.push([type, lent.byteLength]);
          ctx.respond(200, ['content-type', 'application/octet-stream'], Buffer.from(lent));
          seen.push(['after', lent.byteLength]);
        }
      },
      async ({ session }) => {
        await request(session, { ':method': 'POST', ':path': '/text', 'content-type': 'application/json' }, '{"a":1}');
        const bytes = pattern(70000, 5);
        const echo = await request(
          session,
          { ':method': 'POST', ':path': '/lent', 'content-type': 'application/octet-stream' },
          bytes
        );
        assert.equal(sha(echo.body), sha(bytes));
        const none = await request(session, { ':path': '/text' });
        assert.equal(none.status, 200);
      }
    );
    assert.deepEqual(seen, [
      ['application/json', '{"a":1}'],
      ['application/octet-stream', 70000],
      ['after', 0],
      [null, ''], // no body: no type, and the empty text
    ]);
  });

  it('status codes, HEAD, bodyless statuses and the headers HTTP/2 forbids', T, async () => {
    await withH2(
      (ctx) => {
        switch (ctx.path) {
          case '/teapot':
            return ctx.respond(418, ['content-type', 'text/plain'], 'short and stout');
          case '/none':
            return ctx.respond(204, null, 'ignored');
          case '/notmodified':
            return ctx.respond(304, ['etag', '"v1"', 'content-length', '1234'], null);
          case '/h1headers':
            return ctx.respond(
              200,
              ['Connection', 'close', 'Keep-Alive', 'timeout=5', 'Transfer-Encoding', 'chunked', 'x-kept', 'yes'],
              'body'
            );
          case '/cookies':
            return ctx.respond(200, ['set-cookie', 'a=1; Path=/', 'set-cookie', 'b=2; HttpOnly'], '');
          default:
            return ctx.respond(200, ['content-type', 'text/plain'], 'head or get');
        }
      },
      async ({ session }) => {
        const teapot = await request(session, { ':path': '/teapot' });
        assert.equal(teapot.status, 418);
        assert.equal(teapot.body.toString(), 'short and stout');

        const none = await request(session, { ':path': '/none' });
        assert.equal(none.status, 204);
        assert.equal(none.body.length, 0);
        assert.equal(none.headers['content-length'], undefined);

        const nm = await request(session, { ':path': '/notmodified' });
        assert.equal(nm.status, 304);
        assert.equal(nm.headers.etag, '"v1"');
        assert.equal(nm.body.length, 0);

        const head = await request(session, { ':method': 'HEAD', ':path': '/x' });
        assert.equal(head.status, 200);
        assert.equal(head.headers['content-length'], '11');
        assert.equal(head.body.length, 0);

        const h1 = await request(session, { ':path': '/h1headers' });
        assert.equal(h1.status, 200);
        assert.equal(h1.body.toString(), 'body');
        assert.equal(h1.headers['x-kept'], 'yes');
        for (const name of ['connection', 'keep-alive', 'transfer-encoding'])
          assert.equal(h1.headers[name], undefined, `${name} must not reach an HTTP/2 client`);

        const cookies = await request(session, { ':path': '/cookies' });
        assert.deepEqual(cookies.headers['set-cookie'], ['a=1; Path=/', 'b=2; HttpOnly']);
      }
    );
  });

  // RFC 9110 §8.6 and §15.3.6, as on HTTP/1: no content-length on a 204, the
  // handler's on a 304, and a 205 has no content and says so.
  it('a handler-supplied content-length is sent on a 304, never on a 204; a 205 has no content', T, async () => {
    await withH2(
      (ctx) => {
        const [, how, st] = ctx.path.split('/');
        if (how === 'stream') {
          ctx.writeHead(Number(st), ['content-length', '4']);
          ctx.end(st === '205' ? 'BODY' : undefined);
          return;
        }
        ctx.respond(Number(st), how === 'plain' ? null : ['content-length', '4'], 'BODY');
      },
      async ({ session }) => {
        for (const how of ['respond', 'stream']) {
          const none = await request(session, { ':path': `/${how}/204` });
          assert.equal(none.status, 204);
          assert.equal(none.headers['content-length'], undefined, `${how}: 204`);
          const nm = await request(session, { ':path': `/${how}/304` });
          assert.equal(nm.status, 304);
          assert.equal(nm.headers['content-length'], '4', `${how}: 304`);
          const reset = await request(session, { ':path': `/${how}/205` });
          assert.equal(reset.status, 205);
          assert.equal(reset.headers['content-length'], '0', `${how}: 205`);
          assert.equal(reset.body.length, 0, `${how}: 205`);
        }
        const plain = await request(session, { ':path': '/plain/205' });
        assert.equal(plain.headers['content-length'], '0');
        assert.equal(plain.body.length, 0);
        const head = await request(session, { ':method': 'HEAD', ':path': '/respond/205' });
        assert.equal(head.headers['content-length'], '0');
      }
    );
  });

  it('streamed responses: writeHead, write, end - with and without a declared length', T, async () => {
    await withH2(
      async (ctx) => {
        if (ctx.path === '/chunks') {
          ctx.writeHead(200, ['content-type', 'text/plain']);
          for (let i = 0; i < 5; i++) {
            ctx.write(`part${i};`);
            await delay(2);
          }
          ctx.end('done');
        } else if (ctx.path === '/declared') {
          ctx.writeHead(200, ['content-type', 'text/plain', 'content-length', '6']);
          ctx.write('abc');
          ctx.end('def');
        } else if (ctx.path === '/implicit') {
          ctx.write('no head, ');
          ctx.end('still a 200');
        } else if (ctx.path === '/endonly') {
          ctx.end('just end');
        } else {
          ctx.writeHead(200, ['content-length', '100']);
          ctx.write('too short');
          ctx.end();
        }
      },
      async ({ session }) => {
        const chunks = await request(session, { ':path': '/chunks' });
        assert.equal(chunks.body.toString(), 'part0;part1;part2;part3;part4;done');
        assert.equal(chunks.headers['content-length'], undefined);
        const declared = await request(session, { ':path': '/declared' });
        assert.equal(declared.body.toString(), 'abcdef');
        assert.equal(declared.headers['content-length'], '6');
        const implicit = await request(session, { ':path': '/implicit' });
        assert.equal(implicit.status, 200);
        assert.equal(implicit.body.toString(), 'no head, still a 200');
        const endOnly = await request(session, { ':path': '/endonly' });
        assert.equal(endOnly.body.toString(), 'just end');
        assert.equal(endOnly.headers['content-length'], '8');
        // Ending short of the declared length is an error the client sees,
        // never a response that looks complete.
        await assert.rejects(request(session, { ':path': '/short' }));
        // ...and the connection is fine afterwards.
        const again = await request(session, { ':path': '/endonly' });
        assert.equal(again.status, 200);
      }
    );
  });

  it('a streamed response waits for a reader that stops reading, and resumes', T, async () => {
    const piece = Buffer.alloc(64 * 1024, 0x71);
    const total = 300;
    let waited = 0;
    await withH2(
      async (ctx) => {
        ctx.writeHead(200, ['content-type', 'application/octet-stream']);
        for (let i = 0; i < total; i++) {
          if (ctx.isAborted()) return;
          if (!ctx.write(piece)) {
            waited++;
            await ctx.waitWritable();
          }
        }
        ctx.end();
      },
      async ({ session }) => {
        let stream;
        const done = request(session, { ':path': '/slow' }, undefined, { onStream: (s) => (stream = s) });
        stream.pause();
        await delay(300); // the windows fill and the handler is told to wait
        assert.ok(waited > 0, 'write() must report backpressure while nothing is read');
        stream.resume();
        const res = await done;
        assert.equal(res.body.length, total * piece.length);
        assert.ok(res.body.every((b) => b === 0x71));
      }
    );
  });

  it('a stream the client cancels is an abort for its handler, and only for it', T, async () => {
    const gates = new Map();
    await withH2(
      async (ctx) => {
        if (ctx.path === '/ok') return ctx.respond(200, null, 'fine');
        await new Promise((resolve) => gates.set(ctx.path, { resolve, ctx }));
        ctx.respond(200, null, 'too late'); // a no-op for the cancelled one
      },
      async ({ server, session }) => {
        let cancelled;
        const a = request(session, { ':path': '/a' }, undefined, { onStream: (s) => (cancelled = s) });
        const b = request(session, { ':path': '/b' });
        a.catch(() => {});
        await waitFor(() => gates.size === 2);
        cancelled.close(http2.constants.NGHTTP2_CANCEL);
        await waitFor(() => server.aborted.length === 1);
        assert.equal(server.aborted[0], gates.get('/a').ctx.reqId);
        assert.equal(engine.isAborted(gates.get('/a').ctx.reqId), true);
        assert.equal(engine.isAborted(gates.get('/b').ctx.reqId), false);
        gates.get('/a').resolve();
        gates.get('/b').resolve();
        assert.equal((await b).body.toString(), 'too late');
        assert.equal((await request(session, { ':path': '/ok' })).body.toString(), 'fine');
        await delay(50);
        assert.equal(server.aborted.length, 1, 'one abort, once');
      }
    );
  });

  it('a connection that goes away aborts every request in flight on it', T, async () => {
    const reqIds = [];
    await withH2(
      (ctx) => {
        reqIds.push(ctx.reqId); // never answered
      },
      async ({ server, session }) => {
        const pending = [1, 2, 3, 4, 5].map((i) => request(session, { ':path': `/p${i}` }));
        pending.forEach((p) => p.catch(() => {}));
        await waitFor(() => reqIds.length === 5);
        session.destroy();
        await waitFor(() => server.aborted.length === 5);
        assert.deepEqual([...server.aborted].sort(), [...reqIds].sort());
      }
    );
  });

  it('closing the server aborts what is in flight; stopListening says GOAWAY and lets it finish', T, async () => {
    // close(): everything is cut.
    {
      const reqIds = [];
      const server = await startFixtureServer(engine, (ctx) => reqIds.push(ctx.reqId), { http2: true });
      const session = http2.connect(`http://127.0.0.1:${server.port}`);
      session.on('error', () => {});
      const pending = request(session, { ':path': '/held' });
      pending.catch(() => {});
      await waitFor(() => reqIds.length === 1);
      server.close();
      await assert.rejects(pending);
      assert.deepEqual(server.aborted, reqIds);
      session.destroy();
    }
    // stopListening(): the client is told to open no more streams, and the
    // request already there completes.
    {
      let release;
      const server = await startFixtureServer(
        engine,
        async (ctx) => {
          await new Promise((r) => (release = r));
          ctx.respond(200, null, 'finished');
        },
        { http2: true }
      );
      const session = http2.connect(`http://127.0.0.1:${server.port}`);
      session.on('error', () => {});
      let goaway = false;
      session.on('goaway', () => (goaway = true));
      const pending = request(session, { ':path': '/inflight' });
      await waitFor(() => release !== undefined);
      engine.stopListening(server.serverId);
      await waitFor(() => goaway);
      release();
      assert.equal((await pending).body.toString(), 'finished');
      session.destroy();
      server.close();
    }
  });

  it('limits: a body, a header list and a stream count over what the server allows', T, async () => {
    await withH2(
      (ctx) => ctx.respond(200, null, 'ok'),
      async ({ session }) => {
        if (session.remoteSettings?.maxConcurrentStreams !== 7)
          await new Promise((resolve) => session.once('remoteSettings', resolve));
        assert.equal(session.remoteSettings.maxConcurrentStreams, 7);
        assert.equal(session.remoteSettings.initialWindowSize, 131072);

        const tooBig = await request(session, { ':method': 'POST', ':path': '/b' }, Buffer.alloc(5000)).catch(
          (err) => ({ error: err })
        );
        // 413, or the reset that follows it racing the client's upload.
        assert.ok(tooBig.status === 413 || tooBig.error, JSON.stringify(tooBig.status));

        const declared = await request(
          session,
          { ':method': 'POST', ':path': '/b', 'content-length': '5000' },
          Buffer.alloc(5000)
        ).catch((err) => ({ error: err }));
        assert.ok(declared.status === 413 || declared.error);

        const manyHeaders = {};
        for (let i = 0; i < 40; i++) manyHeaders[`x-h${i}`] = 'v'.repeat(100);
        const tooMany = await request(session, { ':path': '/h', ...manyHeaders });
        assert.equal(tooMany.status, 431);

        // Still serving.
        assert.equal((await request(session, { ':path': '/ok' })).status, 200);
      },
      {
        options: {
          maxBodySize: 1000,
          maxHeadSize: 2048,
          http2: { maxConcurrentStreams: 7, initialWindowSize: 131072 },
        },
      }
    );
  });

  it('static routes and prepared responses answer HTTP/2 requests', T, async () => {
    const GET = 0;
    let tpl;
    await withH2(
      (ctx) => {
        if (ctx.path === '/tpl') return engine.respondPrepared(ctx.reqId, tpl, '{"from":"template"}');
        if (ctx.path === '/tpl-empty') return engine.respondPreparedEmpty(ctx.reqId, tpl);
        ctx.respond(404, null, 'no');
      },
      async ({ server, session }) => {
        engine.setStaticRoute(server.serverId, GET, '/static', 200, ['content-type', 'text/plain', 'x-static', '1'], 'static body');
        tpl = engine.prepareResponse(server.serverId, 201, ['content-type', 'application/json', 'x-tpl', 'yes']);
        for (let round = 0; round < 3; round++) {
          const st = await request(session, { ':path': '/static' });
          assert.equal(st.status, 200);
          assert.equal(st.body.toString(), 'static body');
          assert.equal(st.headers['x-static'], '1');
          const viaTpl = await request(session, { ':path': '/tpl' });
          assert.equal(viaTpl.status, 201);
          assert.equal(viaTpl.headers['content-type'], 'application/json');
          assert.equal(viaTpl.headers['x-tpl'], 'yes');
          assert.equal(viaTpl.body.toString(), '{"from":"template"}');
          const empty = await request(session, { ':path': '/tpl-empty' });
          assert.equal(empty.status, 201);
          assert.equal(empty.body.length, 0);
        }
        // The same static route over HTTP/1.1 on the same port.
        const h1 = parseResponse(await rawRequest(server.port, 'GET /static HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n'));
        assert.equal(h1.status, 200);
        assert.equal(h1.body, 'static body');
      }
    );
  });

  it('HTTP/1.1 and HTTP/2 share a cleartext port, whatever the first bytes look like', T, async () => {
    const seen = [];
    const server = await startFixtureServer(
      engine,
      (ctx) => {
        seen.push(`${ctx.method === 'OTHER' ? engine.getMethod(ctx.reqId) : ctx.method} ${ctx.path}`);
        ctx.respond(200, null, 'ok');
      },
      { http2: true }
    );
    try {
      const h1 = parseResponse(await rawRequest(server.port, 'GET /one HTTP/1.1\r\nHost: x\r\n\r\n'));
      assert.equal(h1.status, 200);
      // A method that begins like the preface is still HTTP/1.
      const lookalike = parseResponse(await rawRequest(server.port, 'PRI /two HTTP/1.1\r\nHost: x\r\n\r\n'));
      assert.equal(lookalike.status, 200);
      const pr = parseResponse(await rawRequest(server.port, 'PROPFIND /three HTTP/1.1\r\nHost: x\r\n\r\n'));
      assert.equal(pr.status, 200);

      // The preface arriving a few bytes at a time is still HTTP/2.
      const preface = Buffer.from('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n');
      const settings = Buffer.from([0, 0, 0, 4, 0, 0, 0, 0, 0]);
      // GET /four as literals without indexing
      const lit = (n, v) => Buffer.concat([Buffer.from([0, n.length]), Buffer.from(n), Buffer.from([v.length]), Buffer.from(v)]);
      const block = Buffer.concat([lit(':method', 'GET'), lit(':scheme', 'http'), lit(':path', '/four'), lit(':authority', 'h2.test')]);
      const headers = Buffer.concat([Buffer.from([0, 0, block.length, 1, 5, 0, 0, 0, 1]), block]);
      const socket = net.connect(server.port, '127.0.0.1');
      await new Promise((r) => socket.once('connect', r));
      let got = Buffer.alloc(0);
      socket.on('data', (d) => (got = Buffer.concat([got, d])));
      for (let i = 0; i < preface.length; i += 5) {
        socket.write(preface.subarray(i, i + 5));
        await delay(5);
      }
      socket.write(Buffer.concat([settings, headers]));
      await waitFor(() => seen.includes('GET /four'));
      await waitFor(() => got.includes('ok'));
      assert.equal(got[3], 4, 'the server speaks first with SETTINGS');
      socket.destroy();
    } finally {
      server.close();
    }
    assert.deepEqual(seen, ['GET /one', 'PRI /two', 'PROPFIND /three', 'GET /four']);
  });

  it('TLS: a client that does not offer h2 gets HTTP/1.1; a server without the option never offers it', T, async () => {
    const ok = (ctx) => ctx.respond(200, null, 'ok');
    const withH2Option = await startFixtureServer(engine, ok, { http2: true, ssl: sslFileOptions() });
    try {
      const h1 = await openRawTls(withH2Option.port, { alpnProtocols: ['http/1.1'] });
      assert.equal(h1.socket.alpnProtocol, 'http/1.1');
      await h1.send('GET / HTTP/1.1\r\nHost: t\r\n\r\n');
      assert.equal(parseResponse(await h1.read()).status, 200);
      h1.destroy();
      const none = await openRawTls(withH2Option.port);
      await none.send('GET / HTTP/1.1\r\nHost: t\r\n\r\n');
      assert.equal(parseResponse(await none.read()).status, 200);
      none.destroy();
      const both = await openRawTls(withH2Option.port, { alpnProtocols: ['h2', 'http/1.1'] });
      assert.equal(both.socket.alpnProtocol, 'h2');
      both.destroy();
    } finally {
      withH2Option.close();
    }
    const without = await startFixtureServer(engine, ok, { ssl: sslFileOptions() });
    try {
      const both = await openRawTls(without.port, { alpnProtocols: ['h2', 'http/1.1'] });
      assert.equal(both.socket.alpnProtocol, 'http/1.1');
      await both.send('GET / HTTP/1.1\r\nHost: t\r\n\r\n');
      assert.equal(parseResponse(await both.read()).status, 200);
      both.destroy();
      // ...and its cleartext twin treats the preface as the bad request it is.
    } finally {
      without.close();
    }
    const plain = await startFixtureServer(engine, ok, {});
    try {
      const res = await rawRequest(plain.port, 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n', { expectClose: true });
      assert.ok(!res.includes('\u0000\u0000'), 'no HTTP/2 frames from a server that was not asked for them');
    } finally {
      plain.close();
    }
  });

  it('a connection error from the client is answered with GOAWAY and a close', T, async () => {
    const server = await startFixtureServer(engine, (ctx) => ctx.respond(200, null, 'ok'), { http2: true });
    try {
      const socket = net.connect(server.port, '127.0.0.1');
      await new Promise((r) => socket.once('connect', r));
      let got = Buffer.alloc(0);
      let closed = false;
      socket.on('data', (d) => (got = Buffer.concat([got, d])));
      socket.on('close', () => (closed = true));
      socket.on('error', () => {});
      socket.write(
        Buffer.concat([
          Buffer.from('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'),
          Buffer.from([0, 0, 0, 4, 0, 0, 0, 0, 0]),
          Buffer.from([0, 0, 1, 0, 0, 0, 0, 0, 0, 0x78]), // DATA on stream 0
        ])
      );
      await waitFor(() => closed, { timeout: 5000 });
      // Find the GOAWAY (type 7) among the frames received.
      let pos = 0;
      let goawayCode = -1;
      while (pos + 9 <= got.length) {
        const len = got.readUIntBE(pos, 3);
        if (got[pos + 3] === 7) goawayCode = got.readUInt32BE(pos + 9 + 4);
        pos += 9 + len;
      }
      assert.equal(goawayCode, 1, 'PROTOCOL_ERROR');
    } finally {
      server.close();
    }
  });

  it('thousands of requests on one connection leave nothing behind', T, async () => {
    let served = 0;
    await withH2(
      (ctx) => {
        served++;
        ctx.respond(200, null, ctx.path);
      },
      async ({ session }) => {
        for (let round = 0; round < 40; round++) {
          const results = await Promise.all(
            Array.from({ length: 100 }, (_, i) => request(session, { ':path': `/${round}/${i}` }))
          );
          assert.ok(results.every((res, i) => res.body.toString() === `/${round}/${i}`));
        }
        assert.equal(served, 4000);
      }
    );
  });

  it('an idle HTTP/2 connection is closed by the idle timeout; one with a request in flight is not', T, async () => {
    let release;
    const server = await startFixtureServer(
      engine,
      async (ctx) => {
        if (ctx.path === '/held') await new Promise((r) => (release = r));
        ctx.respond(200, null, 'ok');
      },
      { http2: true, idleTimeoutMs: 400 }
    );
    try {
      const idle = http2.connect(`http://127.0.0.1:${server.port}`);
      idle.on('error', () => {});
      let idleClosed = false;
      idle.on('close', () => (idleClosed = true));
      assert.equal((await request(idle, { ':path': '/' })).status, 200);

      const busy = http2.connect(`http://127.0.0.1:${server.port}`);
      busy.on('error', () => {});
      let busyClosed = false;
      busy.on('close', () => (busyClosed = true));
      const held = request(busy, { ':path': '/held' });
      await waitFor(() => release !== undefined);

      await waitFor(() => idleClosed, { timeout: 8000 });
      assert.equal(busyClosed, false, 'a handler is still working on it');
      release();
      assert.equal((await held).status, 200);
      busy.destroy();
    } finally {
      server.close();
    }
  });

  // Hand-written frames for the cases below.
  const frameOf = (type, flags, id, payload = Buffer.alloc(0)) => {
    const h = Buffer.alloc(9);
    h.writeUIntBE(payload.length, 0, 3);
    h[3] = type;
    h[4] = flags;
    h.writeUInt32BE(id, 5);
    return Buffer.concat([h, payload]);
  };
  const PREFACE = Buffer.from('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n');

  it('responses a peer keeps behind closed windows are bounded in time by responseTimeoutMs', T, async () => {
    const body = Buffer.alloc(256 * 1024, 0x61);
    const server = await startFixtureServer(engine, (ctx) => ctx.respond(200, null, body), {
      http2: true,
      responseTimeoutMs: 600,
      idleTimeoutMs: 600,
    });
    try {
      const socket = net.connect(server.port, '127.0.0.1');
      await new Promise((r) => socket.once('connect', r));
      let closed = false;
      socket.on('close', () => (closed = true));
      socket.on('error', () => {});
      socket.on('data', () => {}); // it reads; it just never opens a window
      const initialWindowZero = Buffer.from([0, 4, 0, 0, 0, 0]);
      const get = Buffer.concat([Buffer.from([0x82, 0x86, 0x84, 0x01, 7]), Buffer.from('h2.test')]); // GET http / on h2.test
      socket.write(Buffer.concat([PREFACE, frameOf(4, 0, 0, initialWindowZero)]));
      socket.write(Buffer.concat(Array.from({ length: 20 }, (_, i) => frameOf(1, 5, 2 * i + 1, get))));
      const ping = setInterval(() => !closed && socket.write(frameOf(6, 0, 0, Buffer.alloc(8))), 150);
      try {
        await waitFor(() => closed, { timeout: 8000, message: 'the connection was kept open by its PINGs' });
      } finally {
        clearInterval(ping);
        socket.destroy();
      }
    } finally {
      server.close();
    }
  });

  it('respond() after writeHead() finishes the body; the head is not sent twice', T, async () => {
    await withH2(
      (ctx) => {
        ctx.writeHead(201, ['x-first', '1']);
        ctx.respond(200, ['x-second', '2'], 'tail');
      },
      async ({ session }) => {
        const res = await request(session, { ':path': '/' });
        assert.equal(res.status, 201);
        assert.equal(res.headers['x-first'], '1');
        assert.equal(res.headers['x-second'], undefined);
        assert.equal(res.body.toString(), 'tail');
      }
    );
  });

  it('a cleartext connection that sends part of the preface and stops is under requestTimeoutMs', T, async () => {
    const server = await startFixtureServer(engine, (ctx) => ctx.respond(200, null, 'ok'), {
      http2: true,
      requestTimeoutMs: 600,
      idleTimeoutMs: 60000,
    });
    try {
      const socket = net.connect(server.port, '127.0.0.1');
      await new Promise((r) => socket.once('connect', r));
      let closed = false;
      socket.on('close', () => (closed = true));
      socket.on('error', () => {});
      socket.on('data', () => {});
      socket.write(PREFACE.subarray(0, 10));
      await waitFor(() => closed, { timeout: 8000, message: 'a partial preface held the connection' });
    } finally {
      server.close();
    }
  });


  // ---- what one connection can make the server hold ----

  for (const secure of [false, true]) {
    it(`${secure ? 'TLS' : 'cleartext'}: a client that opens its windows wide and does not read the socket is answered up to the write high-water mark, and in full once it reads`, T, async () => {
      const body = Buffer.alloc(128 * 1024, 0x62);
      const total = 600; // 75 MiB of responses
      const server = await startFixtureServer(engine, (ctx) => ctx.respond(200, null, body), {
        http2: true,
        ...(secure ? { ssl: sslFileOptions() } : {}),
      });
      try {
        const client = await rawH2(server.port, {
          settings: [[4, 0x7fffffff]],
          connectionWindow: 0x7fffffff,
          read: false,
          secure,
        });
        await client.send(...Array.from({ length: total }, (_, i) => h2get(1 + 2 * i, '/r')));
        await delay(400);
        // Answered: what the socket buffers took, the mark (256 KiB) and the
        // requests of the read that crossed it - not the 600 flow control allows.
        const answered = server.requests.length;
        assert.ok(answered >= 1 && answered < total / 2, `${answered} of ${total} requests answered into a socket nobody reads`);
        await delay(200);
        assert.equal(server.requests.length, answered, 'nothing more is answered while nothing is read');
        client.resume();
        await waitFor(() => [...client.streams.values()].filter((st) => st.ended).length === total, {
          timeout: 25000,
          message: 'the responses did not all arrive once the client read',
        });
        assert.equal(server.requests.length, total);
        for (const st of client.streams.values()) {
          assert.equal(st.status, 200);
          assert.equal(st.bytes, body.length);
        }
        assert.equal(client.goaway, -1);
        client.destroy();
      } finally {
        server.close();
      }
    });
  }

  it('what a client sends while its answers wait unread is kept and acted on once it reads; more than flow control allows is cut off', T, async () => {
    const body = Buffer.alloc(128 * 1024, 0x62);
    const uploads = [];
    const server = await startFixtureServer(
      engine,
      (ctx) => {
        if (ctx.method !== 'POST') return ctx.respond(200, null, body);
        uploads.push(sha(Buffer.from(ctx.body())));
        ctx.respond(200, null, 'stored');
      },
      { http2: true, maxPendingBytes: 1 << 20 }
    );
    try {
      const gets = Array.from({ length: 300 }, (_, i) => h2get(1 + 2 * i, '/r'));
      const wide = { settings: [[4, 0x7fffffff]], connectionWindow: 0x7fffffff, read: false };

      // Kept: an upload within the windows the client was given.
      const client = await rawH2(server.port, wide);
      await client.send(...gets);
      await delay(300);
      assert.ok(server.requests.length < 150, `${server.requests.length} answered`);
      const upload = pattern(300000, 7);
      const post = [h2frame(FT.HEADERS, END_HEADERS, 1001, hpackBlock(requestFields('POST', '/up')))];
      for (let off = 0; off < upload.length; off += 16384) {
        post.push(h2frame(FT.DATA, off + 16384 >= upload.length ? END_STREAM : 0, 1001, upload.subarray(off, off + 16384)));
      }
      await client.send(...post);
      await delay(200);
      assert.deepEqual(uploads, [], 'not acted on while the answers before it are unread');
      client.resume();
      await client.done(1001, 25000);
      assert.equal(client.stream(1001).status, 200);
      assert.deepEqual(uploads, [sha(upload)]);
      client.destroy();

      // Cut off: input far past one connection window (8 MiB) and
      // maxPendingBytes, into a connection that is not reading its answers.
      const before = server.requests.length;
      const flood = await rawH2(server.port, wide);
      await flood.send(...gets);
      await delay(300);
      const junk = Buffer.concat(Array(64).fill(h2frame(0x7a, 0, 0, Buffer.alloc(16384)))); // a frame type nobody knows
      let sent = 0;
      while (!flood.closed && sent < 96 << 20) {
        await Promise.race([flood.send(junk), delay(300)]);
        sent += junk.length;
      }
      await waitFor(() => flood.closed, { timeout: 10000, message: `a peer flooding a connection it does not read was not closed (${sent} bytes sent)` });
      assert.ok(server.requests.length - before < 150);
    } finally {
      server.close();
    }
  });

  it('uploads that together are more than a connection buffers: the newest are refused, the others complete, none is left waiting', { timeout: 90000 }, async () => {
    const sizes = [];
    await withH2(
      (ctx) => {
        sizes.push(ctx.body().byteLength);
        ctx.respond(200, null, 'stored');
      },
      async ({ session }) => {
        // Six uploads of 9 MiB, each within maxBodySize (10 MiB), on one
        // connection: 54 MiB, where the connection buffers 32 MiB and a
        // window (8 MiB) on top. Sent evenly, none can complete before that
        // is full.
        const body = Buffer.alloc(9 << 20, 0x75);
        const upload = (i) =>
          request(session, { ':method': 'POST', ':path': `/up${i}` }, body).then(
            (res) => res.status,
            (err) => (/REFUSED_STREAM/.test(err.message) ? 'refused' : `error: ${err.message}`)
          );
        const outcome = await Promise.race([
          Promise.all([0, 1, 2, 3, 4, 5].map(upload)),
          delay(30000).then(() => 'still waiting after 30 s'),
        ]);
        assert.notEqual(outcome, 'still waiting after 30 s');
        const stored = outcome.filter((o) => o === 200).length;
        const refused = outcome.filter((o) => o === 'refused').length;
        assert.equal(stored + refused, 6, JSON.stringify(outcome));
        assert.ok(stored >= 3, `${stored} of 6 completed`);
        assert.deepEqual(sizes, Array(stored).fill(body.length));
        // Refused means nothing was processed: the client sends it again.
        assert.equal(await upload('again'), 200);
        assert.equal(sizes.length, stored + 1);
      },
      { client: { maxSessionMemory: 512 } }
    );
  });

  // RFC 9113 8.3.1: with :authority present a server must not use Host. The
  // Host line a request carries beside it keeps its place among the headers
  // and holds the :authority value; :authority alone is delivered as Host,
  // and a Host field alone as it is.
  it('a request with :authority and a Host field that differs is given the :authority value as Host', T, async () => {
    const seen = new Map();
    const server = await startFixtureServer(
      engine,
      (ctx) => {
        seen.set(ctx.path, ctx.headers());
        ctx.respond(200, null, 'ok');
      },
      { http2: true }
    );
    try {
      const client = await rawH2(server.port);
      const req = (stream, path, fields) => h2frame(FT.HEADERS, END_HEADERS | END_STREAM, stream, hpackBlock(fields));
      await client.send(
        req(1, '/both', requestFields('GET', '/both', [['host', 'other.test'], ['x-a', '1']], 'h2.test')),
        req(3, '/authority', requestFields('GET', '/authority', [['x-a', '1']], 'h2.test')),
        req(5, '/host', requestFields('GET', '/host', [['host', 'other.test'], ['x-a', '1']], null))
      );
      await waitFor(() => seen.size === 3);
      assert.deepEqual(seen.get('/both'), ['host', 'h2.test', 'x-a', '1']);
      assert.deepEqual(seen.get('/authority'), ['x-a', '1', 'host', 'h2.test']);
      assert.deepEqual(seen.get('/host'), ['host', 'other.test', 'x-a', '1']);
    } finally {
      server.close();
    }
  });

  it('a request the client makes the server reset costs what a request the client resets itself costs', T, async () => {
    const server = await startFixtureServer(engine, () => {}, { http2: true }); // a handler at work: it has not answered
    try {
      const client = await rawH2(server.port);
      // 600 requests, each followed by a frame that is an error on its stream
      // (a window update of zero), which the server answers by resetting it.
      const frames = [];
      for (let i = 0; i < 600; i++) frames.push(h2get(1 + 2 * i, '/work'), h2frame(FT.WINDOW_UPDATE, 0, 1 + 2 * i, u32(0)));
      await client.send(...frames);
      await waitFor(() => client.closed, { timeout: 5000, message: 'the connection was not closed' });
      assert.equal(client.goaway, 11, 'ENHANCE_YOUR_CALM');
      // The budget is 2000 units and a reset four: 500, and the one that went over.
      assert.ok(server.requests.length >= 500 && server.requests.length <= 510, `${server.requests.length} requests reached a handler`);
      await waitFor(() => server.aborted.length === server.requests.length);
    } finally {
      server.close();
    }
  });

  // ---- one request, two protocols ----

  it('what HTTP/1.1 refuses in a request HTTP/2 refuses too, and what both accept reaches the handler the same', T, async () => {
    const seen = [];
    const server = await startFixtureServer(
      engine,
      (ctx) => {
        seen.push({ method: ctx.method, path: ctx.path, query: ctx.query(), headers: ctx.headers(), body: Buffer.from(ctx.body() ?? []).toString('latin1') });
        ctx.respond(200, null, 'ok');
      },
      { http2: true }
    );
    const h1 = (lines, body = '') => `${lines.join('\r\n')}\r\n\r\n${body}`;
    const refused = [
      ['a control byte in a field value', h1(['GET / HTTP/1.1', 'Host: h2.test', 'X-V: a\x01b']), requestFields('GET', '/', [['x-v', 'a\x01b']])],
      ['ESC in a field value', h1(['GET / HTTP/1.1', 'Host: h2.test', 'X-V: \x1b[31m']), requestFields('GET', '/', [['x-v', '\x1b[31m']])],
      ['DEL in a field value', h1(['GET / HTTP/1.1', 'Host: h2.test', 'X-V: a\x7fb']), requestFields('GET', '/', [['x-v', 'a\x7fb']])],
      ['NUL in a field value', h1(['GET / HTTP/1.1', 'Host: h2.test', 'X-V: a\x00b']), requestFields('GET', '/', [['x-v', 'a\x00b']])],
      ['a control byte in the target', h1(['GET /a\x01b HTTP/1.1', 'Host: h2.test']), requestFields('GET', '/a\x01b')],
      ['DEL in the target', h1(['GET /a\x7f HTTP/1.1', 'Host: h2.test']), requestFields('GET', '/a\x7f')],
      ['a field name that is not a token', h1(['GET / HTTP/1.1', 'Host: h2.test', 'X V: a']), requestFields('GET', '/', [['x v', 'a']])],
      ['two Host lines', h1(['GET / HTTP/1.1', 'Host: h2.test', 'Host: h2.test']), requestFields('GET', '/', [['host', 'h2.test'], ['host', 'h2.test']], null)],
      ['a Host with a path in it', h1(['GET / HTTP/1.1', 'Host: h2.test/x']), requestFields('GET', '/', [], 'h2.test/x')],
      ['a Host with userinfo', h1(['GET / HTTP/1.1', 'Host: u@h2.test']), requestFields('GET', '/', [], 'u@h2.test')],
      ['a Host with a space', h1(['GET / HTTP/1.1', 'Host: h2 .test']), requestFields('GET', '/', [['host', 'h2 .test']], null)],
      ['a Content-Length that is not a number', h1(['POST / HTTP/1.1', 'Host: h2.test', 'Content-Length: 1x']), requestFields('POST', '/', [['content-length', '1x']])],
      ['an empty Content-Length', h1(['POST / HTTP/1.1', 'Host: h2.test', 'Content-Length:']), requestFields('POST', '/', [['content-length', '']])],
      ['two Content-Lengths that differ', h1(['POST / HTTP/1.1', 'Host: h2.test', 'Content-Length: 0', 'Content-Length: 1']), requestFields('POST', '/', [['content-length', '0'], ['content-length', '1']])],
      ['Transfer-Encoding beside Content-Length', h1(['POST / HTTP/1.1', 'Host: h2.test', 'Content-Length: 0', 'Transfer-Encoding: chunked'], '0\r\n\r\n'), requestFields('POST', '/', [['content-length', '0'], ['transfer-encoding', 'chunked']])],
    ];
    try {
      for (const [what, http1, fields] of refused) {
        const res = parseResponse(await rawRequest(server.port, http1, { expectClose: true }));
        assert.equal(res.status, 400, `HTTP/1.1: ${what}`);
        const client = await rawH2(server.port);
        await client.send(h2frame(FT.HEADERS, END_HEADERS | END_STREAM, 1, hpackBlock(fields)));
        await client.done(1);
        assert.equal(client.stream(1).rst, 1, `HTTP/2: ${what} is answered RST_STREAM(PROTOCOL_ERROR)`);
        assert.equal(client.stream(1).status, undefined, `HTTP/2: ${what}`);
        assert.deepEqual(seen, [], `${what}: no handler`);
        client.destroy();
      }
      // The same request on both: HTAB and bytes past ASCII in a value, a
      // query, a body.
      const extra = [
        ['accept', 'text/plain'],
        ['x-tab', 'a\tb'],
        ['x-utf8', 'caf\xc3\xa9'],
        ['cookie', 'a=1; b=2'],
        ['content-length', '5'],
      ];
      await rawRequest(
        server.port,
        h1(['POST /same/path?x=1&y=tw%20o HTTP/1.1', 'Host: h2.test', ...extra.map(([n, v]) => `${n}: ${v}`), 'Connection: close'], 'hello')
      );
      const client = await rawH2(server.port);
      await client.send(
        h2frame(FT.HEADERS, END_HEADERS, 1, hpackBlock(requestFields('POST', '/same/path?x=1&y=tw%20o', extra))),
        h2frame(FT.DATA, END_STREAM, 1, Buffer.from('hello'))
      );
      await client.done(1);
      client.destroy();
      assert.equal(seen.length, 2);
      const pairs = (flat) => {
        const out = [];
        for (let i = 0; i < flat.length; i += 2) if (flat[i] !== 'connection') out.push(`${flat[i]}: ${flat[i + 1]}`);
        return out.sort();
      };
      assert.deepEqual({ ...seen[1], headers: pairs(seen[1].headers) }, { ...seen[0], headers: pairs(seen[0].headers) });
      assert.equal(seen[1].body, 'hello');
    } finally {
      server.close();
    }
  });

  it('HEAD, 204 and 304 responses carry no body on HTTP/2, with the content-length HTTP/1.1 gives them', T, async () => {
    const server = await startFixtureServer(
      engine,
      (ctx) => {
        switch (ctx.path) {
          case '/respond':
            return ctx.respond(200, ['content-type', 'text/plain'], 'eleven byte');
          case '/declared':
            ctx.writeHead(200, ['content-length', '11']);
            ctx.write('eleven');
            return ctx.end(' byte');
          case '/undeclared':
            ctx.writeHead(200, ['content-type', 'text/plain']);
            ctx.write('eleven');
            return ctx.end(' byte');
          case '/endonly':
            return ctx.end('eleven byte');
          case '/204':
            return ctx.respond(204, ['content-length', '7'], 'ignored');
          case '/204-streamed':
            ctx.writeHead(204, ['content-length', '7']);
            ctx.write('ignored');
            return ctx.end('ignored');
          case '/304':
            return ctx.respond(304, ['etag', '"v"', 'content-length', '11'], 'ignored');
          case '/304-streamed':
            ctx.writeHead(304, ['etag', '"v"', 'content-length', '11']);
            ctx.write('ignored');
            return ctx.end('ignored');
          default:
            return ctx.respond(404, null, 'no');
        }
      },
      { http2: true }
    );
    // [method, path, status, content-length]
    const cases = [
      ['HEAD', '/respond', 200, '11'],
      ['HEAD', '/declared', 200, '11'],
      ['HEAD', '/undeclared', 200, undefined],
      ['HEAD', '/endonly', 200, '0'],
      ['GET', '/204', 204, undefined],
      ['GET', '/204-streamed', 204, undefined],
      ['HEAD', '/204', 204, undefined],
      ['GET', '/304', 304, '11'],
      ['GET', '/304-streamed', 304, '11'],
      ['HEAD', '/304', 304, '11'],
    ];
    try {
      const client = await rawH2(server.port, { keepBody: true });
      let id = 1;
      for (const [method, path, status, length] of cases) {
        const what = `${method} ${path}`;
        const h1 = parseResponse(
          await rawRequest(server.port, `${method} ${path} HTTP/1.1\r\nHost: h2.test\r\nConnection: close\r\n\r\n`, { expectClose: true }),
          { noBody: true }
        );
        assert.equal(h1.status, status, `HTTP/1.1 ${what}`);
        assert.equal(h1.headers['content-length'], length, `HTTP/1.1 ${what}`);
        assert.equal(h1.rest, '', `HTTP/1.1 ${what}: no body bytes`);

        await client.send(h2get(id, path, [], method));
        await client.done(id);
        const st = client.stream(id);
        assert.equal(st.status, status, `HTTP/2 ${what}`);
        assert.equal(st.rst, -1, `HTTP/2 ${what}: ended, not reset`);
        assert.equal(st.ended, true, `HTTP/2 ${what}`);
        assert.equal(st.bytes, 0, `HTTP/2 ${what}: no DATA payload`);
        assert.equal(st.headerFrames, 1, `HTTP/2 ${what}: one header block`);
        assert.equal(client.field(id, 'content-length'), length, `HTTP/2 ${what}`);
        id += 2;
      }
      // The connection is in step afterwards: a GET with a body.
      await client.send(h2get(id, '/respond'));
      await client.done(id);
      assert.equal(client.bodyOf(id), 'eleven byte');
      assert.equal(client.goaway, -1);
      client.destroy();
    } finally {
      server.close();
    }
  });

  // ---- streams and the things that end them ----

  it('a stream left waiting for the rest of its request does not keep an idle connection open', T, async () => {
    const server = await startFixtureServer(engine, (ctx) => ctx.respond(200, null, 'ok'), { http2: true, idleTimeoutMs: 400 });
    try {
      const client = await rawH2(server.port);
      await client.send(
        h2frame(FT.HEADERS, END_HEADERS, 1, hpackBlock(requestFields('POST', '/never-finished', [['content-length', '10']]))),
        h2frame(FT.DATA, 0, 1, Buffer.from('half'))
      );
      await waitFor(() => client.closed, { timeout: 8000, message: 'the idle timeout did not close the connection' });
      assert.equal(server.requests.length, 0);
      assert.equal(client.goaway, 0, 'GOAWAY(NO_ERROR)');
      assert.equal(client.stream(1).rst, 2, 'the request that was arriving is reset');
    } finally {
      server.close();
    }
  });

  // Requests in every state a response can be in when its stream ends under
  // it: nothing sent, a head and some body sent, a declared length part
  // sent, the whole response given and waiting on the client's window, and a
  // handler waiting to write more. `leave` ends them; the handlers then call
  // everything they could still call.
  async function inEveryState(leave, check) {
    const big = Buffer.alloc(200000, 0x67);
    const held = new Map();
    let streamer = null;
    const server = await startFixtureServer(
      engine,
      async (ctx) => {
        held.set(ctx.path, ctx);
        if (ctx.path === '/ok') return ctx.respond(200, null, 'ok');
        if (ctx.path === '/started') {
          ctx.writeHead(200, ['content-type', 'text/plain']);
          ctx.write('first;');
        } else if (ctx.path === '/declared') {
          ctx.writeHead(200, ['content-length', '100']);
          ctx.write('some');
        } else if (ctx.path === '/waiting') {
          ctx.respond(200, null, big); // complete for the handler; all but a window's worth held back
        } else if (ctx.path === '/streaming') {
          ctx.writeHead(200, null);
          const piece = Buffer.alloc(65536, 0x73);
          let writes = 0;
          while (!ctx.isAborted() && writes < 2000) {
            writes++;
            if (!ctx.write(piece)) await ctx.waitWritable();
          }
          streamer = { writes, aborted: ctx.isAborted() };
          ctx.end();
        }
      },
      { http2: true }
    );
    try {
      const client = await rawH2(server.port, { settings: [[4, 1000]], keepBody: true }); // SETTINGS_INITIAL_WINDOW_SIZE: 1000
      const paths = ['/held', '/started', '/declared', '/waiting', '/streaming'];
      await client.send(
        ...paths.map((path, i) => h2get(1 + 2 * i, path)),
        // ...and a request still arriving: no handler has it.
        h2frame(FT.HEADERS, END_HEADERS, 11, hpackBlock(requestFields('POST', '/arriving', [['content-length', '100000']]))),
        h2frame(FT.DATA, 0, 11, Buffer.alloc(5000, 0x61))
      );
      await waitFor(() => held.size === paths.length && client.stream(7).bytes === 1000 && client.stream(9).bytes === 1000);
      await delay(50); // the streaming handler has filled its window and is waiting
      const handlerHeld = ['/held', '/started', '/declared', '/streaming'].map((path) => held.get(path).reqId).sort();
      await leave({ client, server, held });
      await waitFor(() => server.aborted.length === handlerHeld.length && streamer !== null, { message: `aborted: ${server.aborted.length}` });
      assert.deepEqual([...server.aborted].sort(), handlerHeld, 'the requests handlers held, and only those');
      assert.equal(streamer.aborted, true);
      assert.ok(streamer.writes < 2000, 'the streaming handler stopped');
      const framesBefore = client.frames.length;
      const dataBefore = client.dataFrames;
      for (const [path, ctx] of held) {
        assert.equal(ctx.isAborted(), true, path);
        ctx.respond(200, ['x-late', '1'], 'late');
        ctx.writeHead(200, ['x-late', '1']);
        assert.ok(!ctx.write('late'), `${path}: write() reports the request gone`);
        ctx.end('late');
        ctx.end();
        ctx.respond(500, null, 'again');
      }
      await check({ client, server, framesBefore, dataBefore });
      await delay(50);
      assert.equal(server.aborted.length, handlerHeld.length, 'each told once');
    } finally {
      server.close();
    }
  }

  it('respond, writeHead, write and end for a request whose stream the client reset do nothing, whatever the response had got to', T, async () => {
    await inEveryState(
      ({ client }) => client.send(...[1, 3, 5, 7, 9, 11].map((id) => h2frame(FT.RST_STREAM, 0, id, u32(8)))),
      async ({ client, framesBefore, dataBefore }) => {
        // The connection is still there, and is sent nothing on the reset streams.
        await client.send(h2get(13, '/ok'));
        await client.done(13);
        assert.equal(client.bodyOf(13), 'ok');
        assert.deepEqual(client.frames.slice(framesBefore).map((f) => f.stream).filter((id) => id !== 13), []);
        assert.equal(client.dataFrames, dataBefore + 1);
        assert.equal(client.goaway, -1);
        client.destroy();
      }
    );
  });

  it('a client that disconnects with requests in every state aborts the ones handlers hold, once each; the server goes on', T, async () => {
    await inEveryState(
      ({ client }) => client.destroy(),
      async ({ server }) => {
        const again = await rawH2(server.port, { keepBody: true });
        await again.send(h2get(1, '/ok'));
        await again.done(1);
        assert.equal(again.bodyOf(1), 'ok');
        again.destroy();
      }
    );
  });

  it('closing the server with streams in every state aborts the ones handlers hold, once each, and tells the client what became of them', T, async () => {
    await inEveryState(
      ({ server }) => server.close(),
      async ({ client }) => {
        await waitFor(() => client.closed, { message: 'the connection was not closed' });
        assert.equal(client.goaway, 0, 'GOAWAY(NO_ERROR)');
        for (const id of [1, 3, 5, 7, 9, 11]) assert.equal(client.stream(id).rst, 2, `stream ${id} reset`);
      }
    );
  });

  it('a handler that answers while the server is closing, and one that closes it from inside a request, leave nothing behind', T, async () => {
    // close() from a handler, with other requests of the same read behind it
    // and requests of another connection in flight.
    let closing = false;
    let wroteAfterClose;
    const calls = [];
    let server;
    server = await startFixtureServer(
      engine,
      (ctx) => {
        calls.push(ctx.path);
        if (ctx.path === '/close') {
          ctx.writeHead(200, null);
          ctx.write('going');
          server.close();
          wroteAfterClose = ctx.write('gone');
          ctx.end('gone');
          ctx.respond(200, null, 'gone');
          closing = true;
        }
        // the others are held
      },
      { http2: true }
    );
    const other = await rawH2(server.port);
    await other.send(h2get(1, '/other-1'), h2get(3, '/other-2'));
    await waitFor(() => calls.length === 2);
    const client = await rawH2(server.port);
    await client.send(h2get(1, '/before'), h2get(3, '/close'), h2get(5, '/after-1'), h2get(7, '/after-2'));
    await waitFor(() => closing && client.closed && other.closed, { message: 'connections not closed' });
    await delay(50);
    assert.ok(!wroteAfterClose, 'write() after close() reports the request gone');
    assert.deepEqual(calls.filter((path) => path.startsWith('/after')), [], 'no request reaches a handler after close()');
    // /other-1, /other-2, /before and /close were held by handlers.
    assert.equal(server.aborted.length, 4);
    assert.equal(new Set(server.aborted).size, 4);
  });

  describe('batched dispatch', () => {
    // The adapter's loop: answer slot after slot, read the control cell
    // between them, stop at a slot whose handler did not finish.
    async function withBatch(handle, fn) {
      const log = { batches: [], order: [], aborted: [], ids: new Map() };
      let buffers;
      const callbacks = {
        onRequest(reqId, m, path) {
          log.order.push(path);
          handle(reqId, path, log);
        },
        onRequestBatch(count) {
          const { descriptors: d, control: ctl, paths } = buffers;
          log.batches.push(count);
          let i = 0;
          for (;;) {
            const reqId = d[3 * i];
            const pi = d[3 * i + 2];
            const path = pi === 0xffffffff ? engine.getPath(reqId) : paths[pi];
            log.order.push(path);
            log.ids.set(reqId, path);
            handle(reqId, path, log);
            const next = ctl[0];
            if (next === i) return i + 1;
            if (next >= count) return count;
            i = next;
          }
        },
        onAborted(reqId) {
          log.aborted.push(reqId);
        },
        onWritable() {},
      };
      const serverId = engine.serve(callbacks, { http2: true });
      // A handler may close the server itself (once).
      log.closeServer = () => {
        if (!log.serverClosed) engine.close(serverId);
        log.serverClosed = true;
      };
      buffers = engine.getBatchBuffers(serverId);
      const port = await engine.listen(serverId, '127.0.0.1', 0);
      const session = http2.connect(`http://127.0.0.1:${port}`);
      session.on('error', () => {});
      try {
        await fn({ session, log, port });
      } finally {
        session.destroy();
        log.closeServer();
      }
    }

    it('requests that arrive together are handed over together', T, async (t) => {
      if (!engine.probe().capabilities.batchDispatch) return t.skip('batch dispatch is off');
      await withBatch(
        (reqId, path) => engine.respond(reqId, 200, null, `r:${path}`),
        async ({ session, log }) => {
          const results = await Promise.all(
            Array.from({ length: 60 }, (_, i) => request(session, { ':path': `/b${i}` }))
          );
          results.forEach((res, i) => assert.equal(res.body.toString(), `r:/b${i}`));
          assert.equal(log.order.length, 60);
          assert.ok(log.batches.length < 60, `60 requests in ${log.batches.length} calls`);
          assert.ok(log.batches.every((n) => n >= 1 && n <= 16));
          assert.equal(log.batches.reduce((a, b) => a + b, 0) >= 60, true);
        }
      );
    });

    it('a handler that answers later does not hold up the ones behind it', T, async (t) => {
      if (!engine.probe().capabilities.batchDispatch) return t.skip('batch dispatch is off');
      const late = [];
      await withBatch(
        (reqId, path) => {
          const n = Number(path.slice(2));
          if (n % 4 === 1) late.push(() => engine.respond(reqId, 200, null, `late:${path}`));
          else engine.respond(reqId, 200, null, `now:${path}`);
        },
        async ({ session, log }) => {
          const pending = Array.from({ length: 40 }, (_, i) => request(session, { ':path': `/s${i}` }));
          // Every request reaches its handler although a quarter of them
          // have not answered.
          await waitFor(() => log.order.length === 40);
          assert.equal(new Set(log.order).size, 40, 'each exactly once');
          assert.equal(late.length, 10);
          const early = await Promise.all(pending.filter((_, i) => i % 4 !== 1));
          assert.ok(early.every((res) => res.body.toString().startsWith('now:')));
          late.forEach((answer) => answer());
          const rest = await Promise.all(pending.filter((_, i) => i % 4 === 1));
          assert.ok(rest.every((res) => res.body.toString().startsWith('late:')));
        }
      );
    });

    it('a handler that answers from a microtask or nextTick does not make the batch skip the one behind it', T, async (t) => {
      if (!engine.probe().capabilities.batchDispatch) return t.skip('batch dispatch is off');
      await withBatch(
        (reqId, path) => {
          const n = Number(path.slice(2));
          const send = () => engine.respond(reqId, 200, null, `r:${path}`);
          if (n % 3 === 0) Promise.resolve().then(send);
          else if (n % 3 === 1) process.nextTick(send);
          else send();
        },
        async ({ session, log }) => {
          const results = await Promise.all(
            Array.from({ length: 48 }, (_, i) => request(session, { ':path': `/m${i}` }))
          );
          results.forEach((res, i) => assert.equal(res.body.toString(), `r:/m${i}`));
          assert.equal(log.order.length, 48, 'each handed over once');
          assert.equal(new Set(log.order).size, 48);
        }
      );
    });


    it('a read that carries more requests than a batch holds, some reset before they are handed over and some after', T, async (t) => {
      if (!engine.probe().capabilities.batchDispatch) return t.skip('batch dispatch is off');
      const waiting = new Map(); // path -> reqId, for the ones not answered at once
      await withBatch(
        (reqId, path) => {
          const n = Number(path.slice(2));
          if (n % 3 === 0) engine.respond(reqId, 200, null, `r:${path}`);
          else waiting.set(path, reqId);
        },
        async ({ log, port }) => {
          const client = await rawH2(port, { keepBody: true });
          const total = 50;
          const idOf = (n) => 1 + 2 * n;
          // Reset by the frame right behind their request: gone before the
          // batch they would have been in is handed over.
          const gone = new Set([4, 10, 22, 37]);
          const frames = [];
          for (let n = 0; n < total; n++) {
            frames.push(h2get(idOf(n), `/q${n}`));
            if (gone.has(n)) frames.push(h2frame(FT.RST_STREAM, 0, idOf(n), u32(8)));
          }
          await client.send(...frames); // one write, one read
          await waitFor(() => log.order.length >= total - gone.size);
          await delay(30);
          assert.equal(log.order.length, total - gone.size, 'each of the others handed over once');
          assert.equal(new Set(log.order).size, total - gone.size);
          for (const n of gone) assert.ok(!log.order.includes(`/q${n}`), `/q${n} was reset before it was handed over`);
          assert.deepEqual(log.aborted, [], 'a request no handler saw is not reported aborted');
          assert.ok(log.batches.length >= 3 && log.batches.every((count) => count >= 1 && count <= 16), log.batches.join(','));
          for (let n = 0; n < total; n += 3) {
            if (gone.has(n)) continue;
            await client.done(idOf(n));
            assert.equal(client.bodyOf(idOf(n)), `r:/q${n}`);
          }
          // After they were handed over: the client resets half of the ones
          // still held; the handlers then answer all of them.
          const held = [...waiting.keys()];
          const reset = held.filter((_, i) => i % 2 === 0);
          const kept = held.filter((_, i) => i % 2 === 1);
          await client.send(...reset.map((path) => h2frame(FT.RST_STREAM, 0, idOf(Number(path.slice(2))), u32(8))));
          await waitFor(() => log.aborted.length === reset.length);
          assert.deepEqual([...log.aborted].sort(), reset.map((path) => waiting.get(path)).sort());
          for (const path of held) engine.respond(waiting.get(path), 200, null, `late:${path}`);
          for (const path of kept) {
            const id = idOf(Number(path.slice(2)));
            await client.done(id);
            assert.equal(client.bodyOf(id), `late:${path}`);
          }
          await delay(30);
          for (const path of reset) assert.equal(client.stream(idOf(Number(path.slice(2)))).status, undefined, `${path} was reset: no answer`);
          assert.equal(log.aborted.length, reset.length, 'each told once');
          assert.equal(client.goaway, -1);
          client.destroy();
        }
      );
    });

    it('a client that does not read is answered no further than the write high-water mark, and batch after batch once it reads', T, async (t) => {
      if (!engine.probe().capabilities.batchDispatch) return t.skip('batch dispatch is off');
      const body = Buffer.alloc(128 * 1024, 0x62);
      await withBatch(
        (reqId) => engine.respond(reqId, 200, null, body),
        async ({ log, port }) => {
          const total = 400;
          const client = await rawH2(port, { settings: [[4, 0x7fffffff]], connectionWindow: 0x7fffffff, read: false });
          await client.send(...Array.from({ length: total }, (_, i) => h2get(1 + 2 * i, `/n${i}`)));
          await delay(400);
          const answered = log.order.length;
          assert.ok(answered >= 1 && answered < total / 2, `${answered} of ${total} requests answered into a socket nobody reads`);
          client.resume();
          await waitFor(() => [...client.streams.values()].filter((st) => st.ended).length === total, { timeout: 25000 });
          assert.equal(log.order.length, total);
          assert.equal(new Set(log.order).size, total, 'each handed over once');
          assert.deepEqual(log.order, Array.from({ length: total }, (_, i) => `/n${i}`), 'in the order they were sent');
          for (const st of client.streams.values()) assert.equal(st.bytes, body.length);
          client.destroy();
        }
      );
    });

    it('a client that disconnects in the middle of a batch of streams: the held ones are aborted once, the rest never reach a handler', T, async (t) => {
      if (!engine.probe().capabilities.batchDispatch) return t.skip('batch dispatch is off');
      const held = [];
      await withBatch(
        (reqId, path) => {
          if (path.startsWith('/hold')) held.push(reqId);
          else engine.respond(reqId, 200, null, 'x'.repeat(1000));
        },
        async ({ log, port }) => {
          for (let round = 0; round < 5; round++) {
            const client = await rawH2(port);
            const before = held.length;
            await client.send(...Array.from({ length: 40 }, (_, i) => h2get(1 + 2 * i, i % 2 ? `/hold${round}-${i}` : `/now${round}-${i}`)));
            await waitFor(() => held.length === before + 20);
            client.destroy();
            await waitFor(() => log.aborted.length === held.length, { message: `round ${round}: ${log.aborted.length} of ${held.length} aborted` });
          }
          assert.deepEqual([...log.aborted].sort((a, b) => a - b), [...held].sort((a, b) => a - b));
          for (const reqId of held) {
            assert.equal(engine.isAborted(reqId), true);
            engine.respond(reqId, 200, null, 'late');
            engine.end(reqId, 'late');
          }
          await delay(30);
          assert.equal(log.aborted.length, held.length, 'each told once');
        }
      );
    });

    for (const answerFirst of [false, true]) {
      it(`a connection closed from inside the loop over its own batch ends the loop (${answerFirst ? 'after answering' : 'before answering'})`, T, async (t) => {
        if (!engine.probe().capabilities.batchDispatch) return t.skip('batch dispatch is off');
        // The first handler closes the server while the other requests of
        // its batch are still ahead of the loop. Closing releases every one
        // of them: none may reach a handler afterwards, and none that no
        // handler has seen is reported aborted (at most the one slot the
        // loop was about to take, which the engine cannot tell from one
        // whose handler is running).
        let closed = false;
        const afterClose = [];
        await withBatch(
          (reqId, path, log) => {
            if (closed) return void afterClose.push(path);
            if (answerFirst) engine.respond(reqId, 200, null, `r:${path}`);
            closed = true;
            log.closeServer();
          },
          async ({ session, log: l }) => {
            const pending = Array.from({ length: 12 }, (_, i) => request(session, { ':path': `/c${i}` }).catch(() => null));
            await waitFor(() => closed, { message: 'no handler ran' });
            await Promise.all(pending);
            await delay(30);
            assert.deepEqual(afterClose, [], 'a request of the closed connection reached a handler');
            assert.deepEqual(l.order, ['/c0']);
            assert.deepEqual(l.batches, [12], 'the twelve arrived as one batch');
            const neverSeen = l.aborted.filter((id) => !l.ids.has(id));
            assert.ok(neverSeen.length <= 1, `${neverSeen.length} requests no handler saw were reported aborted`);
            assert.equal(l.aborted.filter((id) => l.ids.has(id)).length, answerFirst ? 0 : 1, 'the request its handler held is reported once, unless it was answered');
          }
        );
      });
    }
  });

  // The two delivery modes side by side, each in a process of its own: the
  // start of a script that serves HTTP/2 and speaks it over a socket.
  const childPrelude = `
    import net from 'node:net';
    const { default: engine } = await import(${JSON.stringify(new URL('../packages/engine/index.mjs', import.meta.url).href)});
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    const until = async (f) => { for (let i = 0; i < 1000 && !f(); i++) await sleep(5); return f(); };
    const u32 = (v) => { const b = Buffer.alloc(4); b.writeUInt32BE(v >>> 0); return b; };
    const frame = (type, flags, stream, payload = Buffer.alloc(0)) => {
      const h = Buffer.alloc(9); h.writeUIntBE(payload.length, 0, 3); h[3] = type; h[4] = flags; h.writeUInt32BE(stream, 5);
      return Buffer.concat([h, payload]);
    };
    const lit = (n, v) => Buffer.concat([Buffer.from([0, n.length]), Buffer.from(n), Buffer.from([v.length]), Buffer.from(v)]);
    const head = (method, path) => Buffer.concat([lit(':method', method), lit(':scheme', 'http'), lit(':path', path), lit(':authority', 'h2.test')]);
    const get = (id, path) => frame(1, 5, id, head('GET', path));
    const post = (id, path) => frame(1, 4, id, head('POST', path));   // its body is still to come
    const wu = (id, n) => frame(8, 0, id, u32(n));
    const preface = (settings = []) => Buffer.concat([Buffer.from('PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n'), frame(4, 0, 0, Buffer.from(settings))]);
    async function connect(port) {
      const s = net.connect(port, '127.0.0.1');
      const got = { socket: s, bytes: new Map(), text: new Map(), ended: new Set(), goaway: false };
      let buf = Buffer.alloc(0);
      s.on('error', () => {});
      s.on('data', (d) => {
        buf = Buffer.concat([buf, d]);
        while (buf.length >= 9 && buf.length >= 9 + buf.readUIntBE(0, 3)) {
          const len = buf.readUIntBE(0, 3), type = buf[3], flags = buf[4], id = buf.readUInt32BE(5);
          if (type === 0) {
            got.bytes.set(id, (got.bytes.get(id) ?? 0) + len);
            if (len <= 64) got.text.set(id, (got.text.get(id) ?? '') + buf.toString('latin1', 9, 9 + len));
          }
          if (type <= 1 && (flags & 1)) got.ended.add(id);
          if (type === 7) got.goaway = true;
          buf = buf.subarray(9 + len);
        }
      });
      await new Promise((r) => s.once('connect', r));
      return got;
    }
  `;
  const runChild = (script, mode) => {
    const r = spawnSync(process.execPath, ['--input-type=module', '-e', childPrelude + script], {
      env: { ...process.env, MORO_ENGINE_NOTIFY: mode === 'sync' ? 'sync' : '' },
      encoding: 'utf8',
      timeout: 25000,
    });
    assert.equal(r.status, 0, `the process ended with ${r.signal ?? r.status}: ${r.stderr.slice(0, 3000)}`);
    const res = JSON.parse(r.stdout.trim().split('\n').pop());
    assert.equal(res.notify, mode);
    return res.out;
  };

  // A handler told that its stream has room may end the response at once.
  // With notifications delivered in place (MORO_ENGINE_NOTIFY=sync) that
  // happens inside the window update that drained the stream, which then
  // goes on - and must not go on with the stream the handler just ended.
  // More streams have come and gone than the session keeps spare, so that
  // stream's memory is released the moment it ends: a build with the
  // sanitizers is what sees it read. The response arrives whole and the
  // connection goes on, in both modes.
  for (const mode of ['deferred', 'sync']) {
    it(`a response ended from onWritable, while the window update that made room is still being handled, arrives whole (${mode} delivery)`, T, () => {
      const out = runChild(
        `
        const big = Buffer.alloc(400000, 0x61);
        async function scenario(waitsFor) {
          const waiters = new Map();
          const sid = engine.serve({
            onRequest(reqId, _m, path) {
              if (path !== '/t') return engine.respond(reqId, 200, null, null);
              engine.writeHead(reqId, 200, null);
              if (engine.write(reqId, big)) engine.end(reqId, 'tail');
              else waiters.set(reqId, () => engine.end(reqId, 'tail'));
            },
            onAborted(reqId) { waiters.delete(reqId); },
            onWritable(reqId) { const w = waiters.get(reqId); waiters.delete(reqId); w?.(); },
          }, { http2: true });
          const c = await connect(engine.listen(sid, '127.0.0.1', 0));
          // The stream's own window is what holds the response back, or the connection's.
          const first = [preface(waitsFor === 'stream' ? [0, 4, 0, 0, 0, 0] : [0, 4, 1, 0, 0, 0])];
          // 200 requests are opened before the one under test and finished
          // after it: when it ends, the session has all the spare streams
          // it keeps and this one is freed.
          for (let i = 0; i < 200; i++) first.push(post(1 + 2 * i, '/s'));
          first.push(get(401, '/t'));
          for (let i = 0; i < 200; i++) first.push(frame(0, 1, 1 + 2 * i));
          c.socket.write(Buffer.concat(first));
          const started = await until(() => c.ended.has(399) && waiters.size === 1);
          await sleep(30);
          if (waitsFor === 'stream') {
            c.socket.write(wu(0, 1 << 20));
            await sleep(20);
            c.socket.write(Buffer.concat([wu(401, 1 << 20), wu(0, 1000), wu(401, 1000)]));
          } else {
            c.socket.write(Buffer.concat([wu(0, 1 << 22), wu(0, 1000), wu(401, 1000)]));
          }
          const ended = await until(() => c.ended.has(401));
          c.socket.write(Buffer.concat([get(403, '/s'), wu(0, 1000)]));
          const next = await until(() => c.ended.has(403));
          const out = { waitsFor, started, ended, bytes: c.bytes.get(401) ?? 0, next, goaway: c.goaway };
          c.socket.destroy();
          engine.close(sid);
          return out;
        }
        const out = [await scenario('stream'), await scenario('connection')];
        console.log(JSON.stringify({ notify: engine.probe().notify, out }));
      `,
        mode
      );
      for (const o of out) {
        assert.deepEqual(o, { waitsFor: o.waitsFor, started: true, ended: true, bytes: 400004, next: true, goaway: false });
      }
    });

    // A connection goes away with several requests held, and the handler,
    // told about the first, finishes the others there and then. In place,
    // that is inside the loop that is telling them one by one: a request
    // finished there is over, and was finished a second time when its turn
    // came - leaving its slot to be handed to two later requests at once.
    it(`requests finished from inside another's onAborted, as their connection goes away, are finished once (${mode} delivery)`, T, () => {
      const out = runChild(
        `
        const held = [], late = [];
        let aborted = 0;
        const sid = engine.serve({
          onRequest(reqId, _m, path) { (path === '/held' ? held : late).push([reqId, path]); },
          onAborted(reqId) {
            aborted++;
            for (const [id] of held.splice(0)) if (id !== reqId) engine.end(id, 'bye');
          },
          onWritable() {},
        }, { http2: true });
        const port = engine.listen(sid, '127.0.0.1', 0);
        const one = await connect(port);
        one.socket.write(Buffer.concat([preface(), get(1, '/held'), get(3, '/held'), get(5, '/held'), get(7, '/held')]));
        await until(() => held.length === 4);
        one.socket.destroy();
        await until(() => aborted > 0);
        await sleep(30);
        // Six requests in flight together on a new connection, each answered with its own path.
        const two = await connect(port);
        two.socket.write(Buffer.concat([preface(), ...[1, 3, 5, 7, 9, 11].map((id) => get(id, '/late/' + id))]));
        await until(() => late.length === 6);
        for (const [id, path] of late) engine.respond(id, 200, null, path);
        await until(() => two.ended.size === 6);
        const out = { aborted: aborted > 0, answers: [1, 3, 5, 7, 9, 11].map((id) => two.text.get(id) ?? null) };
        two.socket.destroy();
        engine.close(sid);
        console.log(JSON.stringify({ notify: engine.probe().notify, out }));
      `,
        mode
      );
      assert.deepEqual(out, { aborted: true, answers: ['/late/1', '/late/3', '/late/5', '/late/7', '/late/9', '/late/11'] });
    });
  }

  it('WINDOW_UPDATE frames for nothing sent draw on the control-frame budget; the ones a download needs do not', T, async () => {
    const body = Buffer.alloc(4 << 20, 0x64);
    const server = await startFixtureServer(engine, (ctx) => ctx.respond(200, null, body), { http2: true });
    try {
      // A client that opens both windows again for every 16 KiB it takes in.
      const fair = await rawH2(server.port, { settings: [[4, 16384]] });
      await fair.send(h2get(1, '/big'));
      let acked = 0;
      let updates = 0;
      while (!fair.stream(1).ended && !fair.closed) {
        const got = fair.stream(1).bytes;
        if (got > acked) {
          await fair.send(h2frame(FT.WINDOW_UPDATE, 0, 0, u32(got - acked)), h2frame(FT.WINDOW_UPDATE, 0, 1, u32(got - acked)));
          acked = got;
          updates += 2;
        } else {
          await delay(1);
        }
      }
      assert.equal(fair.stream(1).bytes, body.length);
      assert.ok(updates > 200, `${updates} window updates`);
      assert.equal(fair.goaway, -1);
      fair.destroy();

      // One that sends them for nothing: told to calm down, and closed.
      const flood = await rawH2(server.port);
      const one = h2frame(FT.WINDOW_UPDATE, 0, 0, u32(1));
      await flood.send(Buffer.concat(Array.from({ length: 3000 }, () => one)));
      await waitFor(() => flood.closed, { timeout: 5000, message: 'the connection was not closed' });
      assert.equal(flood.goaway, 11, 'GOAWAY(ENHANCE_YOUR_CALM)');
    } finally {
      server.close();
    }
  });

  // RFC 9113 8.2.3: a client may send each cookie pair as a field of its own;
  // to the application they are one Cookie field, as on HTTP/1.1.
  it('cookie fields sent separately reach the application as one, joined with "; "', T, async () => {
    const seen = new Map();
    const server = await startFixtureServer(
      engine,
      (ctx) => {
        seen.set(ctx.path, { all: ctx.headers(), cookie: ctx.header('cookie') });
        ctx.respond(200, null, 'ok');
      },
      { http2: true }
    );
    try {
      const client = await rawH2(server.port);
      await client.send(
        h2get(1, '/three', [['cookie', 'a=1'], ['x-between', '1'], ['cookie', 'b=2'], ['cookie', 'c=3; d=4']]),
        h2get(3, '/one', [['cookie', 'only=1']]),
        h2get(5, '/none')
      );
      await client.done(5);
      assert.deepEqual(seen.get('/three').all, ['cookie', 'a=1; b=2; c=3; d=4', 'x-between', '1', 'host', 'h2.test']);
      assert.equal(seen.get('/three').cookie, 'a=1; b=2; c=3; d=4');
      assert.equal(seen.get('/one').cookie, 'only=1');
      assert.deepEqual(seen.get('/none').all, ['host', 'h2.test']);
      client.destroy();
    } finally {
      server.close();
    }
  });

  // An http or https request names its authority, as :authority or as Host
  // (RFC 9110 7.2: a user agent must send one or the other), and the name is
  // never empty: with neither field, or an empty one, the request is
  // malformed, as an HTTP/1.1 request without Host is a 400. That holds for
  // every target, `OPTIONS *` included. A scheme of another kind may have no
  // authority at all and is delivered as it comes.
  it('an http or https request without an authority, or with an empty one, is malformed', T, async () => {
    const paths = [];
    const server = await startFixtureServer(
      engine,
      (ctx) => {
        paths.push([ctx.path, ctx.header('host') ?? null]);
        ctx.respond(200, null, 'ok');
      },
      { http2: true }
    );
    try {
      const client = await rawH2(server.port);
      const req = (stream, path, extra, authority) =>
        h2frame(FT.HEADERS, END_HEADERS | END_STREAM, stream, hpackBlock(requestFields('GET', path, extra, authority)));
      await client.send(
        req(1, '/empty-authority', [], ''),
        req(3, '/empty-authority-and-host', [['host', 'other.test']], ''),
        req(5, '/empty-host', [['host', '']], null),
        req(7, '/authority-and-empty-host', [['host', '']], 'h2.test'),
        req(9, '/authority', [], 'h2.test'),
        req(11, '/neither', [], null),
        req(13, '/neither-with-fields', [['accept', '*/*'], ['x-forwarded-host', 'h2.test']], null),
        h2frame(FT.HEADERS, END_HEADERS | END_STREAM, 15, hpackBlock([[':method', 'OPTIONS'], [':scheme', 'https'], [':path', '*']])),
        h2frame(FT.HEADERS, END_HEADERS | END_STREAM, 17, hpackBlock([[':method', 'GET'], [':scheme', 'HTTP'], [':path', '/upper']])),
        req(19, '/host-only', [['host', 'h2.test']], null),
        h2frame(FT.HEADERS, END_HEADERS | END_STREAM, 21, hpackBlock([[':method', 'GET'], [':scheme', 'urn'], [':path', '/other-scheme']]))
      );
      await client.done(21);
      for (const id of [1, 3, 5, 7, 11, 13, 15, 17]) {
        assert.equal(client.stream(id).rst, 1, `stream ${id}: RST_STREAM(PROTOCOL_ERROR)`);
      }
      assert.deepEqual(paths, [['/authority', 'h2.test'], ['/host-only', 'h2.test'], ['/other-scheme', null]]);
      assert.equal(client.goaway, -1);
      client.destroy();
    } finally {
      server.close();
    }
  });
});
