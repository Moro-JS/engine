// Regression conformance suite for @morojs/engine.
//
// Locks in the security/correctness fixes layered on top of the base HTTP/1.1
// conformance and hardening suites:
//   - H1  chunked trailers are cumulatively bounded (unbounded-memory DoS)
//   - M2  multiple Transfer-Encoding headers are rejected (request smuggling)
//   - M1  a HEAD response to a streaming handler emits NO chunked terminator
//         (keep-alive stays in sync; no "0\r\n\r\n" desync)
//   - L1  Connection: "keep-alive, close" closes the connection
//   - L3  a non-digit HTTP minor version is rejected 400
//
// Each case drives the real running engine over a raw TCP socket. Run with:
//   node --test

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  loadEngine,
  startFixtureServer,
  rawRequest,
  openRaw,
  parseResponse,
  parseResponses,
  responsesComplete,
} from './helpers.mjs';

const engine = await loadEngine();
const skip = engine
  ? false
  : '@morojs/engine native binding not usable yet — regression suite skipped';

const T = { timeout: 30000 };
const CRLF = '\r\n';

async function withServer(handler, optionsOrFn, maybeFn) {
  const options = typeof optionsOrFn === 'function' ? {} : optionsOrFn;
  const fn = typeof optionsOrFn === 'function' ? optionsOrFn : maybeFn;
  const server = await startFixtureServer(engine, handler, options);
  try {
    return await fn(server);
  } finally {
    server.close();
  }
}

const ok = (ctx) => ctx.respond(200, ['content-type', 'text/plain'], 'ok');

describe('@morojs/engine regression conformance', { skip }, () => {
  // ---- M2: multiple Transfer-Encoding headers -> 400 (smuggling defense) ----

  it('two Transfer-Encoding headers (chunked, then bogus) are rejected 400', T, async () => {
    await withServer(ok, async (server) => {
      const raw = await rawRequest(
        server.port,
        `POST / HTTP/1.1${CRLF}Host: t${CRLF}Transfer-Encoding: chunked${CRLF}` +
          `Transfer-Encoding: cow${CRLF}${CRLF}0${CRLF}${CRLF}`,
        { expectClose: true }
      );
      const res = parseResponse(raw);
      assert.equal(res.status, 400, 'conflicting multi-TE must be a 400, not parsed as chunked');
      assert.equal(server.requests.length, 0, 'the handler must never run for a rejected request');
    });
  });

  it('two Transfer-Encoding headers (bogus, then chunked) are rejected 400', T, async () => {
    await withServer(ok, async (server) => {
      const raw = await rawRequest(
        server.port,
        `POST / HTTP/1.1${CRLF}Host: t${CRLF}Transfer-Encoding: cow${CRLF}` +
          `Transfer-Encoding: chunked${CRLF}${CRLF}0${CRLF}${CRLF}`,
        { expectClose: true }
      );
      const res = parseResponse(raw);
      assert.equal(res.status, 400, 'ordering must not decide acceptance');
      assert.equal(server.requests.length, 0);
    });
  });

  // ---- H1: chunked trailer accumulation is cumulatively bounded ----

  it('a flood of chunk trailer lines is bounded (431), server survives (no OOM/hang)', T, async () => {
    await withServer(ok, { maxHeadSize: 16 * 1024 }, async (server) => {
      const client = await openRaw(server.port);
      try {
        // Zero-length body: enter the trailer state, then stream trailer lines
        // far exceeding maxHeadSize. Pre-fix this grew buf_ without bound and
        // never completed; now it must be rejected 431 and the socket closed.
        await client.send(
          `POST / HTTP/1.1${CRLF}Host: t${CRLF}Transfer-Encoding: chunked${CRLF}${CRLF}0${CRLF}`
        );
        const line = `X-Trailer-Pad: ${'a'.repeat(200)}${CRLF}`;
        for (let i = 0; i < 500 && !client.closed; i++) {
          try {
            await client.send(line);
          } catch {
            break; // server closed mid-write — acceptable
          }
        }
        const raw = await client.read({ expectClose: true, timeout: 8000 }).catch(() => '');
        if (raw) {
          const res = parseResponse(raw);
          assert.equal(res.status, 431, 'oversized trailer block must be 431');
        }
        await client.waitClose({ timeout: 5000 }).catch(() => {});
        assert.equal(client.closed, true, 'the connection must be closed, not left buffering');
        assert.equal(server.requests.length, 0, 'the handler must not run');
      } finally {
        client.destroy();
      }
    });
  });

  it('a small, well-formed chunk trailer is still accepted', T, async () => {
    await withServer(
      (ctx) => ctx.respond(200, null, ctx.body() ? Buffer.from(ctx.body()).toString() : ''),
      async (server) => {
        const raw = await rawRequest(
          server.port,
          `POST / HTTP/1.1${CRLF}Host: t${CRLF}Transfer-Encoding: chunked${CRLF}${CRLF}` +
            `5${CRLF}hello${CRLF}0${CRLF}X-Trailer: ok${CRLF}${CRLF}`
        );
        const res = parseResponse(raw);
        assert.equal(res.status, 200, 'a legitimate single trailer line must still parse');
        assert.equal(res.body, 'hello');
      }
    );
  });

  // ---- M1: HEAD to a streaming handler emits no chunked terminator ----

  it('HEAD to a streaming (chunked) handler: no body bytes, keep-alive stays in sync', T, async () => {
    await withServer(
      (ctx) => {
        ctx.writeHead(200, ['content-type', 'text/plain']);
        ctx.write('this body is suppressed for HEAD');
        ctx.end();
      },
      async (server) => {
        const client = await openRaw(server.port);
        try {
          // Pipeline a HEAD then a GET on the same socket. If the HEAD response
          // leaked a "0\r\n\r\n" chunked terminator, it would be parsed as the
          // start of the GET's response and desync the second exchange.
          await client.send(
            `HEAD / HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}` +
              `GET / HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`
          );
          const raw = await client.read({ timeout: 5000 });
          const head = parseResponse(raw, { noBody: true });
          assert.equal(head.status, 200, 'HEAD status');
          // The next bytes must be a clean second response, not a stray "0\r\n".
          const second = parseResponse(head.rest);
          assert.equal(second.status, 200, 'the follow-up GET must parse cleanly (no desync)');
          assert.equal(second.body, 'this body is suppressed for HEAD');
        } finally {
          client.destroy();
        }
      }
    );
  });

  // ---- L1: Connection token list containing close ----

  it('Connection: "keep-alive, close" closes the connection', T, async () => {
    await withServer(ok, async (server) => {
      const raw = await rawRequest(
        server.port,
        `GET / HTTP/1.1${CRLF}Host: t${CRLF}Connection: keep-alive, close${CRLF}${CRLF}`,
        { expectClose: true }
      );
      const res = parseResponse(raw);
      assert.equal(res.status, 200);
      assert.match(
        (res.headers['connection'] || '').toLowerCase(),
        /close/,
        'a close token anywhere must win over keep-alive'
      );
    });
  });

  // ---- App-supplied framing/hop-by-hop headers are stripped ----

  it('app-supplied Transfer-Encoding/Connection/Date headers are dropped (no framing ambiguity)', T, async () => {
    await withServer(
      (ctx) =>
        ctx.respond(
          200,
          [
            'transfer-encoding', 'chunked',
            'connection', 'close',
            'date', 'Thu, 01 Jan 1970 00:00:00 GMT',
            'x-app', 'kept',
          ],
          'body'
        ),
      async (server) => {
        const raw = await rawRequest(server.port, `GET / HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`);
        const res = parseResponse(raw);
        assert.equal(res.status, 200);
        assert.equal(res.body, 'body');
        // The engine owns framing: exactly ONE Content-Length, no app TE.
        assert.equal(res.headers['transfer-encoding'], undefined, 'app Transfer-Encoding must be stripped');
        assert.ok(res.headers['content-length'] !== undefined, 'engine sets its own Content-Length');
        // Date/Connection are engine-owned singletons (not the app values).
        assert.ok(!/1970/.test(res.headers['date'] || ''), 'app Date must not survive');
        assert.equal(res.headers['x-app'], 'kept', 'ordinary app headers still pass through');
      }
    );
  });

  // ---- L3: malformed HTTP minor version ----

  it('a non-digit HTTP minor version (HTTP/1.x) is rejected 400', T, async () => {
    await withServer(ok, async (server) => {
      const raw = await rawRequest(
        server.port,
        `GET / HTTP/1.x${CRLF}Host: t${CRLF}${CRLF}`,
        { expectClose: true }
      );
      const res = parseResponse(raw);
      assert.equal(res.status, 400, 'a malformed version must be 400, not served');
      assert.equal(server.requests.length, 0);
    });
  });

  // Request bodies are collected straight into the body buffer as they
  // arrive (not accumulated in the read buffer and copied out whole at the
  // end), and handed to JS without a copy. These pin the paths that differ
  // from the one-read case: a body that trails its head across several
  // reads, a head that arrives alone, a pipelined request behind a body in
  // the same read, and the hand-over being repeatable.
  describe('request body collection and hand-over', () => {
    const delay = (ms) => new Promise((r) => setTimeout(r, ms));
    const payload = (n) => Array.from({ length: n }, (_, i) => String.fromCharCode(33 + ((i * 7) % 94))).join('');
    const echoBody = (ctx) => ctx.respond(200, null, ctx.body() ?? '');

    it('Content-Length body arriving in pieces after its head is echoed intact', T, async () => {
      const body = payload(40000);
      await withServer(echoBody, async ({ port }) => {
        const client = await openRaw(port);
        try {
          const head = `POST /u HTTP/1.1${CRLF}Host: t${CRLF}Content-Length: ${body.length}${CRLF}${CRLF}`;
          // head plus a first slice in one write, then the rest in uneven slices
          await client.send(head + body.slice(0, 1000));
          let off = 1000;
          for (const size of [1, 7000, 3, 20000, 11996]) {
            await delay(15);
            await client.send(body.slice(off, off + size));
            off += size;
          }
          assert.equal(off, body.length);
          const res = parseResponse(await client.read({ until: responsesComplete(1), timeout: 5000 }));
          assert.equal(res.status, 200);
          assert.equal(res.body.length, body.length);
          assert.equal(res.body, body);
        } finally {
          client.destroy();
        }
      });
    });

    it('head alone, then the body: echoed intact (buffered head, direct body)', T, async () => {
      const body = payload(30000);
      await withServer(echoBody, async ({ port }) => {
        const client = await openRaw(port);
        try {
          await client.send(`POST /u HTTP/1.1${CRLF}Host: t${CRLF}Content-Length: ${body.length}${CRLF}${CRLF}`);
          await delay(20);
          await client.send(body.slice(0, 12345));
          await delay(20);
          await client.send(body.slice(12345));
          const res = parseResponse(await client.read({ until: responsesComplete(1), timeout: 5000 }));
          assert.equal(res.status, 200);
          assert.equal(res.body, body);
        } finally {
          client.destroy();
        }
      });
    });

    it('a head split inside a header line, with the body in the same later write', T, async () => {
      const body = payload(5000);
      await withServer(echoBody, async ({ port }) => {
        const client = await openRaw(port);
        try {
          await client.send(`POST /u HTTP/1.1${CRLF}Host: t${CRLF}Content-Le`);
          await delay(20);
          await client.send(`ngth: ${body.length}${CRLF}${CRLF}${body}`);
          const res = parseResponse(await client.read({ until: responsesComplete(1), timeout: 5000 }));
          assert.equal(res.status, 200);
          assert.equal(res.body, body);
        } finally {
          client.destroy();
        }
      });
    });

    it('pipelined request behind a body in one write: both answered in order', T, async () => {
      const first = payload(9000);
      const second = payload(300);
      await withServer(echoBody, async ({ port }) => {
        const raw = await rawRequest(
          port,
          `POST /a HTTP/1.1${CRLF}Host: t${CRLF}Content-Length: ${first.length}${CRLF}${CRLF}${first}` +
            `POST /b HTTP/1.1${CRLF}Host: t${CRLF}Content-Length: ${second.length}${CRLF}${CRLF}${second}`,
          { until: responsesComplete(2) }
        );
        const [a, b] = parseResponses(raw);
        assert.equal(a.status, 200);
        assert.equal(a.body, first);
        assert.equal(b.status, 200);
        assert.equal(b.body, second);
      });
    });

    it('pipelined request arriving in the write that completes a body', T, async () => {
      const first = payload(8000);
      await withServer(echoBody, async ({ port }) => {
        const client = await openRaw(port);
        try {
          await client.send(`POST /a HTTP/1.1${CRLF}Host: t${CRLF}Content-Length: ${first.length}${CRLF}${CRLF}${first.slice(0, 5000)}`);
          await delay(20);
          await client.send(`${first.slice(5000)}GET /b HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`);
          const [a, b] = parseResponses(await client.read({ until: responsesComplete(2), timeout: 5000 }));
          assert.equal(a.status, 200);
          assert.equal(a.body, first);
          assert.equal(b.status, 200);
          assert.equal(b.body, '');
        } finally {
          client.destroy();
        }
      });
    });

    it('body() twice in one request: the same bytes both times, and nothing after the response', T, async () => {
      const body = payload(6000);
      let seen = null;
      await withServer((ctx) => {
        const one = ctx.body();
        const two = ctx.body();
        seen = {
          same: Buffer.from(one).equals(Buffer.from(two)),
          length: one.byteLength,
        };
        ctx.respond(200, null, two);
      }, async ({ port }) => {
        const raw = await rawRequest(
          port,
          `POST /u HTTP/1.1${CRLF}Host: t${CRLF}Content-Length: ${body.length}${CRLF}${CRLF}${body}`,
          { until: responsesComplete(1) }
        );
        const res = parseResponse(raw);
        assert.equal(res.status, 200);
        assert.equal(res.body, body);
        assert.deepEqual(seen, { same: true, length: body.length });
      });
    });

    it('a request without a body reports null, before and after one with a body', T, async () => {
      const body = payload(100);
      const bodies = [];
      await withServer((ctx) => {
        const b = ctx.body();
        bodies.push(b === null ? null : b.byteLength);
        ctx.respond(200, null, 'ok');
      }, async ({ port }) => {
        const raw = await rawRequest(
          port,
          `GET /a HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}` +
            `POST /b HTTP/1.1${CRLF}Host: t${CRLF}Content-Length: ${body.length}${CRLF}${CRLF}${body}` +
            `GET /c HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`,
          { until: responsesComplete(3) }
        );
        assert.equal(parseResponses(raw).length, 3);
        assert.deepEqual(bodies, [null, 100, null]);
      });
    });
  });

  // The epoll transport records ready sockets in the poll phase and serves
  // them once per loop turn. libuv waits again within a turn whenever a wait
  // fills its 1024-event buffer; with more ready sockets than that, each used
  // to be queued once per wait and read that many times. They are now served
  // a full buffer at a time, each socket once a turn. These prove that every
  // one of them is still answered, with its own reply, turn after turn.
  describe('more ready sockets than one poll reports', () => {
    const net = () => import('node:net');
    const N = 1500;
    const big = process.platform === 'linux' ? false : 'needs a few thousand descriptors; run on Linux (the epoll transport)';

    // In waves well under the listen backlog: a burst of connects larger than
    // the accept queue is the kernel's to drop or reset, which is not what
    // these are about.
    async function connectAll(port) {
      const { default: netMod } = await net();
      const socks = [];
      while (socks.length < N) {
        const wave = Math.min(200, N - socks.length);
        socks.push(...(await Promise.all(
          Array.from({ length: wave }, () => new Promise((resolve, reject) => {
            const s = netMod.connect(port, '127.0.0.1');
            s.buf = '';
            s.setEncoding('latin1');
            s.on('data', (d) => { s.buf += d; });
            s.on('error', reject);
            s.once('connect', () => resolve(s));
          }))
        )));
      }
      return socks;
    }
    // One request on every socket in the same tick, so the server's next
    // wait finds all of them readable; resolves once each holds one reply.
    async function round(socks, tag) {
      for (const s of socks) s.buf = '';
      socks.forEach((s, i) => s.write(`GET /${tag}/${i} HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`));
      const deadline = Date.now() + 20000;
      while (socks.some((s) => parseResponses(s.buf).length < 1)) {
        if (Date.now() > deadline) assert.fail(`${socks.filter((s) => parseResponses(s.buf).length < 1).length} of ${N} sockets were never answered`);
        await new Promise((r) => setTimeout(r, 10));
      }
      socks.forEach((s, i) => {
        const all = parseResponses(s.buf);
        assert.equal(all.length, 1, `socket ${i} got ${all.length} replies`);
        assert.equal(all[0].status, 200);
        assert.equal(all[0].body, `/${tag}/${i}`);
      });
    }

    it(`${N} sockets readable at once are each answered once, over repeated turns`, { ...T, skip: big }, async () => {
      await withServer((ctx) => ctx.respond(200, ['content-type', 'text/plain'], ctx.path), async ({ port }) => {
        const socks = await connectAll(port);
        try {
          await round(socks, 'a');
          await round(socks, 'b');
          await round(socks, 'c');
        } finally {
          for (const s of socks) s.destroy();
        }
      });
    });

    it(`${N} sockets readable at once with replies sent later from timers`, { ...T, skip: big }, async () => {
      const later = (ctx) => { const path = ctx.path; setTimeout(() => ctx.respond(200, ['content-type', 'text/plain'], path), 5); };
      await withServer(later, async ({ port }) => {
        const socks = await connectAll(port);
        try {
          await round(socks, 'x');
          await round(socks, 'y');
        } finally {
          for (const s of socks) s.destroy();
        }
      });
    });

    it('a socket that sends again while its turn is being served is answered at the next', { ...T, skip: big }, async () => {
      // Each socket pipelines a second request a moment after the first, while
      // the server is still working through the first wave.
      await withServer((ctx) => ctx.respond(200, ['content-type', 'text/plain'], ctx.path), async ({ port }) => {
        const socks = await connectAll(port);
        try {
          socks.forEach((s, i) => s.write(`GET /p/${i} HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`));
          await new Promise((r) => setImmediate(r));
          socks.forEach((s, i) => s.write(`GET /q/${i} HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`));
          const deadline = Date.now() + 20000;
          while (socks.some((s) => parseResponses(s.buf).length < 2)) {
            if (Date.now() > deadline) assert.fail('not every socket received both replies');
            await new Promise((r) => setTimeout(r, 10));
          }
          socks.forEach((s, i) => {
            assert.deepEqual(parseResponses(s.buf).map((r) => r.body), [`/p/${i}`, `/q/${i}`]);
          });
        } finally {
          for (const s of socks) s.destroy();
        }
      });
    });
  });

  // A queued write that is sent at once still completes on the loop, at its
  // next pass. Made from setImmediate - after this turn's pass - it waits a
  // turn, and a connection closed in the meantime is freed before that pass
  // runs: the completion must go with it. What goes wrong otherwise is a read
  // of freed memory, so it is the sanitizer lanes that fail this test; a
  // plain build only shows that the shutdown is clean.
  it('a response queued from setImmediate and the server closed in the same turn', T, async () => {
    const { default: netMod } = await import('node:net');
    const pending = [];
    const sid = engine.serve({ onRequest: (reqId) => pending.push(reqId), onAborted() {}, onWritable() {} });
    const port = engine.listen(sid, '127.0.0.1', 0);
    const socks = [];
    let closed = false;
    try {
      for (let i = 0; i < 8; i++) {
        const s = netMod.connect(port, '127.0.0.1');
        s.on('error', () => {});
        await new Promise((resolve) => s.once('connect', resolve));
        // Two requests: with the second one waiting behind it, the response
        // to the first takes the queued path.
        s.write(`GET /a HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}GET /b HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`);
        socks.push(s);
      }
      const deadline = Date.now() + 5000;
      while (pending.length < socks.length && Date.now() < deadline) await new Promise((r) => setTimeout(r, 5));
      assert.equal(pending.length, socks.length, 'the first request of every connection reached the handler');
      await new Promise((resolve) =>
        setImmediate(() => {
          for (const reqId of pending) engine.respond(reqId, 200, ['content-type', 'text/plain'], 'x');
          engine.close(sid);
          closed = true;
          resolve();
        })
      );
      // Further loop turns, with new allocations of the size just freed.
      const more = await startFixtureServer(engine, ok);
      try {
        for (let i = 0; i < 8; i++) {
          const res = parseResponse(await rawRequest(more.port, `GET / HTTP/1.1${CRLF}Host: t${CRLF}Connection: close${CRLF}${CRLF}`, { expectClose: true }));
          assert.equal(res.status, 200);
        }
      } finally {
        more.close();
      }
    } finally {
      for (const s of socks) s.destroy();
      if (!closed) engine.close(sid);
    }
  });
});

// Lifecycle calls made where the engine did not expect them. Each runs in a
// process of its own: what went wrong before was an abort inside libuv, or a
// loop that never emptied, and neither may take the suite down with it.
describe('lifecycle calls at an unexpected moment', { skip }, () => {
  const ENGINE_ENTRY = new URL('../packages/engine/index.mjs', import.meta.url).href;
  const run = (script) =>
    spawnSync(process.execPath, ['--input-type=module', '-e', script], { encoding: 'utf8', timeout: 20000 });

  // A server has one listener. libuv refuses to bind a bound handle; the
  // epoll transport set a second listening socket up over the first (the
  // first port went deaf, and closing the server aborted the process in
  // libuv's close path), and the io_uring transport accepted on both and
  // then never finished close().
  it('a second listen(), and one after stopListening(), is refused with EINVAL', T, () => {
    const r = run(`
      import net from 'node:net';
      const { default: engine } = await import(${JSON.stringify(ENGINE_ENTRY)});
      const get = (port) => new Promise((resolve) => {
        const s = net.connect(port, '127.0.0.1', () => s.write('GET / HTTP/1.1\\r\\nHost: t\\r\\nConnection: close\\r\\n\\r\\n'));
        let b = '';
        s.on('data', (d) => (b += d));
        s.on('close', () => resolve(b.slice(9, 12)));
        s.on('error', () => resolve('error'));
        s.setTimeout(3000, () => { s.destroy(); resolve('timeout'); });
      });
      const sid = engine.serve({ onRequest(reqId) { engine.respond(reqId, 200, null, 'ok'); }, onAborted() {} });
      const port = engine.listen(sid, '127.0.0.1', 0);
      const out = { second: 'accepted', afterStop: 'accepted' };
      try { engine.listen(sid, '127.0.0.1', 0); } catch (e) { out.second = e.code; }
      out.first = await get(port);
      engine.stopListening(sid);
      try { engine.listen(sid, '127.0.0.1', 0); } catch (e) { out.afterStop = e.code; }
      engine.close(sid);
      console.log(JSON.stringify(out));
    `);
    assert.equal(r.status, 0, `the process ends by itself once the server is closed (signal ${r.signal})\n${r.stderr}`);
    assert.deepEqual(JSON.parse(r.stdout.trim()), { second: 'EINVAL', afterStop: 'EINVAL', first: '200' });
  });

  // The engine closes a WebSocket on its own account - here a peer that
  // stopped reading, at the delivery deadline - and reports it with
  // onWsClose(1006) from the middle of that teardown. An application that
  // closes its server there (the last socket of a shutdown has gone) closes
  // this connection too; the teardown then went on to close it a second
  // time, which libuv answers with an abort.
  it('close() from inside the onWsClose of a socket the engine is tearing down', T, () => {
    const r = run(`
      import net from 'node:net';
      const { default: engine } = await import(${JSON.stringify(ENGINE_ENTRY)});
      const codes = [];
      const sid = engine.serve({
        onRequest(reqId) { if (engine.upgradeToWebSocket(reqId) === -1) engine.respond(reqId, 400, null, ''); },
        onAborted() {},
        onWsOpen(wsId) { engine.wsSend(wsId, Buffer.alloc(8 << 20, 0x61), true); },
        onWsMessage() {},
        onWsClose(wsId, code) { codes.push(code); engine.close(sid); },
      }, { responseTimeoutMs: 300 });
      const port = engine.listen(sid, '127.0.0.1', 0);
      const s = net.connect(port, '127.0.0.1', () => {
        s.pause();  // never reads what it is sent
        s.write('GET /ws HTTP/1.1\\r\\nHost: t\\r\\nUpgrade: websocket\\r\\nConnection: Upgrade\\r\\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\\r\\nSec-WebSocket-Version: 13\\r\\n\\r\\n');
      });
      s.on('error', () => {});
      process.on('exit', () => console.log(JSON.stringify(codes)));
    `);
    assert.equal(r.status, 0, `the process survives and ends by itself (signal ${r.signal})\n${r.stderr}`);
    assert.deepEqual(JSON.parse(r.stdout.trim()), [1006]);
  });
});
