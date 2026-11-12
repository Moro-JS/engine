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
      const block = Buffer.concat([lit(':method', 'GET'), lit(':scheme', 'http'), lit(':path', '/four')]);
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

  describe('batched dispatch', () => {
    // The adapter's loop: answer slot after slot, read the control cell
    // between them, stop at a slot whose handler did not finish.
    async function withBatch(handle, fn) {
      const log = { batches: [], order: [] };
      let buffers;
      const callbacks = {
        onRequest(reqId, m, path) {
          log.order.push(path);
          handle(reqId, path);
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
            handle(reqId, path);
            const next = ctl[0];
            if (next === i) return i + 1;
            if (next >= count) return count;
            i = next;
          }
        },
        onAborted() {},
        onWritable() {},
      };
      const serverId = engine.serve(callbacks, { http2: true });
      buffers = engine.getBatchBuffers(serverId);
      const port = await engine.listen(serverId, '127.0.0.1', 0);
      const session = http2.connect(`http://127.0.0.1:${port}`);
      session.on('error', () => {});
      try {
        await fn({ session, log });
      } finally {
        session.destroy();
        engine.close(serverId);
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
  });
});
