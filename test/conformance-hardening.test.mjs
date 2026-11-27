// Hardening conformance suite for @morojs/engine.
//
// Covers the defenses added on top of the base HTTP/1.1 conformance:
//   - response-splitting (CRLF header injection) rejection
//   - write()-before-writeHead() implicit head
//   - Content-Length integrity (mismatch, overflow clamp, short-write close)
//   - bodyless statuses via the streaming path
//   - status-code clamping
//   - requestTimeoutMs (slow-drip / slowloris budget)
//   - stopListening() graceful-drain phase
//   - reusePort (SO_REUSEPORT) multi-listener binding
//   - WebSocket frames pipelined with the upgrade handshake
//
// Run with: node --test

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import {
  loadEngine,
  startFixtureServer,
  rawRequest,
  openRaw,
  parseResponse,
  parseResponses,
  responsesComplete,
  delay,
  waitFor,
  exchange,
} from './helpers.mjs';

const engine = await loadEngine();
const skip = engine
  ? false
  : '@morojs/engine native binding not usable yet — hardening suite skipped';

const T = { timeout: 30000 };
const CRLF = '\r\n';
const get = (path, extraHeaders = '') =>
  `GET ${path} HTTP/1.1${CRLF}Host: t${CRLF}${extraHeaders}${CRLF}`;

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

describe('@morojs/engine hardening conformance', { skip }, () => {
  // -------------------------------------------------------------------------
  // Response-splitting defense
  // -------------------------------------------------------------------------

  it('header value containing CRLF is dropped, not emitted (no response splitting)', T, async () => {
    await withServer(
      (ctx) =>
        ctx.respond(
          200,
          ['x-safe', 'ok', 'x-evil', `attacker${CRLF}x-injected: 1${CRLF}${CRLF}HTTP/1.1 200 OK`],
          'body'
        ),
      async ({ port }) => {
        const raw = await rawRequest(port, get('/'));
        const responses = parseResponses(raw);
        assert.equal(responses.length, 1, 'exactly one response on the wire');
        const res = responses[0];
        assert.equal(res.status, 200);
        assert.equal(res.headers['x-safe'], 'ok');
        assert.equal(res.headers['x-evil'], undefined, 'header with CRLF must be dropped');
        assert.equal(res.headers['x-injected'], undefined, 'no injected header');
        assert.equal(res.body, 'body');
      }
    );
  });

  it('header with an invalid (non-token) name is dropped; valid siblings survive', T, async () => {
    await withServer(
      (ctx) => ctx.respond(200, ['bad name', 'v', 'x-ok', '1', '', 'empty-name'], 'b'),
      async ({ port }) => {
        const raw = await rawRequest(port, get('/'));
        const res = parseResponse(raw);
        assert.equal(res.status, 200);
        assert.equal(res.headers['x-ok'], '1');
        assert.ok(!raw.includes('bad name'), 'invalid name must not reach the wire');
        assert.ok(!raw.includes('empty-name'), 'empty name must not reach the wire');
      }
    );
  });

  // -------------------------------------------------------------------------
  // write()-before-writeHead()
  // -------------------------------------------------------------------------

  it('write() without writeHead() synthesizes a valid 200 chunked head', T, async () => {
    await withServer(
      (ctx) => {
        ctx.write('hello ');
        ctx.write('world');
        ctx.end();
      },
      async ({ port }) => {
        const client = await openRaw(port);
        try {
          await client.send(get('/'));
          const r1 = parseResponse(await client.read({ until: responsesComplete(1) }));
          assert.equal(r1.statusLine, 'HTTP/1.1 200 OK', 'implicit head must be a real status line');
          assert.equal((r1.headers['transfer-encoding'] || '').toLowerCase(), 'chunked');
          assert.equal(r1.body, 'hello world');
          // The connection must NOT be desynced: a follow-up request works.
          await client.send(get('/'));
          const r2 = parseResponse(await client.read({ until: responsesComplete(1) }));
          assert.equal(r2.status, 200);
          assert.equal(r2.body, 'hello world');
        } finally {
          client.destroy();
        }
      }
    );
  });

  // -------------------------------------------------------------------------
  // Content-Length integrity
  // -------------------------------------------------------------------------

  it('respond() with a mismatched Content-Length: the actual body length is emitted', T, async () => {
    await withServer(
      (ctx) => ctx.respond(200, ['content-length', '999'], 'abc'),
      async ({ port }) => {
        const client = await openRaw(port);
        try {
          await client.send(get('/'));
          const r1 = parseResponse(await client.read({ until: responsesComplete(1) }));
          assert.equal(r1.status, 200);
          assert.equal(r1.headers['content-length'], '3', 'engine owns framing: actual size wins');
          assert.equal(r1.body, 'abc');
          // Keep-alive stays usable (no desync).
          await client.send(get('/'));
          const r2 = parseResponse(await client.read({ until: responsesComplete(1) }));
          assert.equal(r2.body, 'abc');
        } finally {
          client.destroy();
        }
      }
    );
  });

  it('streaming write() beyond the declared Content-Length is clamped; connection stays in sync', T, async () => {
    await withServer(
      (ctx) => {
        ctx.writeHead(200, ['content-length', '3']);
        ctx.write('abcdef'); // 3 bytes over
        ctx.end();
      },
      async ({ port }) => {
        const client = await openRaw(port);
        try {
          await client.send(get('/'));
          const r1 = parseResponse(await client.read({ until: responsesComplete(1) }));
          assert.equal(r1.headers['content-length'], '3');
          assert.equal(r1.body, 'abc', 'excess bytes must never reach the wire');
          await client.send(get('/'));
          const r2 = parseResponse(await client.read({ until: responsesComplete(1) }));
          assert.equal(r2.status, 200, 'next response must not be corrupted by overflow bytes');
        } finally {
          client.destroy();
        }
      }
    );
  });

  it('ending short of the declared Content-Length forces the connection closed (truncation, not poisoning)', T, async () => {
    await withServer(
      (ctx) => {
        ctx.writeHead(200, ['content-length', '10']);
        ctx.write('abc');
        ctx.end(); // 7 bytes short
      },
      async ({ port }) => {
        const client = await openRaw(port);
        try {
          await client.send(get('/'));
          await client.waitClose(5000);
          assert.equal(client.closed, true, 'short fixed-length response must close the connection');
        } finally {
          client.destroy();
        }
      }
    );
  });

  it('writeHead(204) + end(): no body framing headers, no body, keep-alive intact', T, async () => {
    await withServer(
      (ctx) => {
        ctx.writeHead(204);
        ctx.write('should-be-suppressed');
        ctx.end();
      },
      async ({ port }) => {
        const client = await openRaw(port);
        try {
          await client.send(get('/'));
          const raw = await client.read({ until: (buf) => buf.includes('\r\n\r\n') });
          const res = parseResponse(raw);
          assert.equal(res.status, 204);
          assert.equal(res.headers['transfer-encoding'], undefined, '204 must not be chunked');
          assert.equal(res.headers['content-length'], undefined);
          // Connection must still serve the next request (no stray body bytes).
          await client.send(get('/'));
          const raw2 = await client.read({ until: (buf) => buf.includes('\r\n\r\n'), timeout: 5000 });
          assert.ok(raw2.includes('204'), 'second 204 response arrives — no desync');
        } finally {
          client.destroy();
        }
      }
    );
  });

  it('out-of-range status codes are clamped to 500 (status line stays well-formed)', T, async () => {
    await withServer(
      (ctx) => ctx.respond(99999, null, 'x'),
      async ({ port }) => {
        const res = parseResponse(await rawRequest(port, get('/')));
        assert.equal(res.status, 500);
      }
    );
  });

  // -------------------------------------------------------------------------
  // requestTimeoutMs (slow-drip slowloris budget)
  // -------------------------------------------------------------------------

  it('a stalled partial request is answered 408 and closed once requestTimeoutMs expires', T, async () => {
    await withServer(
      (ctx) => ctx.respond(200, null, 'ok'),
      { requestTimeoutMs: 500 },
      async ({ port, requests }) => {
        const client = await openRaw(port);
        try {
          await client.send('GET / HTTP/1.1\r\nHost: t\r\nX-Slow:'); // head never completes
          const raw = await client.read({
            until: (buf) => buf.includes('\r\n\r\n'),
            timeout: 10000,
          });
          const res = parseResponse(raw);
          assert.equal(res.status, 408);
          await client.waitClose(5000);
          assert.equal(requests.length, 0, 'handler must never see the incomplete request');
        } finally {
          client.destroy();
        }
      }
    );
  });

  it('slow-drip within the budget still parses; an idle keep-alive connection is NOT 408d', T, async () => {
    await withServer(
      (ctx) => ctx.respond(200, null, 'ok'),
      { requestTimeoutMs: 5000 },
      async ({ port }) => {
        const client = await openRaw(port);
        try {
          // Complete a request, then idle past several sweep intervals: the
          // request budget must not tick while no request is in progress.
          await client.send(get('/'));
          const r1 = parseResponse(await client.read({ until: responsesComplete(1) }));
          assert.equal(r1.status, 200);
          await delay(1500);
          assert.equal(client.closed, false, 'idle keep-alive must survive (idle timeout governs it)');
          await client.send(get('/'));
          const r2 = parseResponse(await client.read({ until: responsesComplete(1) }));
          assert.equal(r2.status, 200);
        } finally {
          client.destroy();
        }
      }
    );
  });

  // -------------------------------------------------------------------------
  // stopListening() — graceful-drain phase
  // -------------------------------------------------------------------------

  it('stopListening(): established connections keep working, new connects are refused', T, async () => {
    if (typeof engine.stopListening !== 'function') {
      assert.fail('engine.stopListening is not exported');
    }
    await withServer(
      (ctx) => ctx.respond(200, null, 'ok'),
      async ({ port, serverId }) => {
        const existing = await openRaw(port);
        try {
          // One round trip first: the client's 'connect' fires when the TCP
          // handshake completes, which can be before the server has accept()ed
          // the socket out of the backlog - closing the listener at that
          // instant would reset it (kernel behaviour, both transports). A
          // served response proves the connection is established server-side.
          await existing.send(get('/'));
          assert.equal(parseResponse(await existing.read({ until: responsesComplete(1) })).status, 200);
          engine.stopListening(serverId);
          await delay(50);
          // New connection: refused (listener closed).
          await assert.rejects(
            () =>
              new Promise((resolve, reject) => {
                const s = net.connect({ host: '127.0.0.1', port, timeout: 1000 });
                s.on('connect', () => {
                  s.destroy();
                  resolve();
                });
                s.on('error', reject);
                s.on('timeout', () => {
                  s.destroy();
                  reject(new Error('connect timeout'));
                });
              }),
            'new connections must be refused after stopListening()'
          );
          // Existing connection: still served.
          await existing.send(get('/'));
          const res = parseResponse(await existing.read({ until: responsesComplete(1) }));
          assert.equal(res.status, 200);
          assert.equal(res.body, 'ok');
        } finally {
          existing.destroy();
        }
      }
    );
  });


  // A server listens once. listen() on one that is already listening, has
  // stopped listening or is closing is refused with EINVAL on every
  // transport, as libuv's own listener always refused it. The epoll and
  // io_uring listeners opened a second socket instead: over the first one (it
  // stopped accepting and was never closed), into a poll handle that was in
  // the middle of closing (libuv ends the process on that), or behind a
  // close(), where nothing would ever close it again and the thread could
  // not end. One child process per order, since ending is what is asserted.
  it('listen() is refused on a server that is listening, has stopped listening or is closing', T, () => {
    const orders = {
      'listen, listen': `
        const first = engine.listen(sid, '127.0.0.1', 0);
        tryListen();
        report.firstPortAnswers = /200 OK/.test(await get(first));
        engine.close(sid);`,
      'listen, stopListening, listen': `
        engine.listen(sid, '127.0.0.1', 0);
        engine.stopListening(sid);
        tryListen();
        await sleep(50);
        engine.close(sid);`,
      'close, listen': `
        engine.close(sid);
        tryListen();`,
      'listen, close, listen': `
        engine.listen(sid, '127.0.0.1', 0);
        engine.close(sid);
        tryListen();`,
      'listen whose host argument closes the server': `
        try { engine.listen(sid, { toString() { engine.close(sid); return '127.0.0.1'; } }, 0); report.second = 'listening'; } catch (e) { report.second = e.code; }`,
    };
    for (const [name, body] of Object.entries(orders)) {
      // In a worker thread: a listener left behind shows as a thread that
      // cannot be terminated.
      const script = `
        import { Worker, isMainThread, parentPort } from 'node:worker_threads';
        const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
        if (isMainThread) {
          const w = new Worker(new URL(import.meta.url));
          const report = await new Promise((resolve, reject) => { w.once('message', resolve); w.once('error', reject); });
          report.terminated = await Promise.race([w.terminate().then(() => true), sleep(3000).then(() => false)]);
          console.log(JSON.stringify(report));
          if (!report.terminated) process.kill(process.pid, 'SIGKILL');  // exiting would wait for the thread
          process.exit(0);
        } else {
          const net = await import('node:net');
          const { default: engine } = await import(${JSON.stringify(new URL('../packages/engine/index.mjs', import.meta.url).href)});
          const report = {};
          const sid = engine.serve({ onRequest(reqId) { engine.respond(reqId, 200, null, 'ok'); }, onAborted() {} });
          const tryListen = () => { try { engine.listen(sid, '127.0.0.1', 0); report.second = 'listening'; } catch (e) { report.second = e.code; } };
          const get = (port) => new Promise((resolve) => {
            const s = net.connect(port, '127.0.0.1', () => s.write('GET / HTTP/1.1\\r\\nHost: t\\r\\nConnection: close\\r\\n\\r\\n'));
            let b = ''; s.on('data', (d) => (b += d)); s.on('close', () => resolve(b)); s.on('error', () => resolve(b));
            setTimeout(() => s.destroy(), 1500);
          });
          ${body}
          await sleep(50);
          parentPort.postMessage(report);
        }
      `;
      const file = path.join(os.tmpdir(), `moro-listen-order-${process.pid}-${Object.keys(orders).indexOf(name)}.mjs`);
      fs.writeFileSync(file, script);
      try {
        const r = spawnSync(process.execPath, [file], { encoding: 'utf8', timeout: 20000 });
        assert.equal(r.status, 0, `${name}: status ${r.status} signal ${r.signal}\n${r.stdout}${r.stderr.slice(-600)}`);
        const expected = { second: 'EINVAL', terminated: true };
        if (name === 'listen, listen') expected.firstPortAnswers = true;
        assert.deepEqual(JSON.parse(r.stdout.trim()), { ...expected }, name);
      } finally {
        fs.rmSync(file, { force: true });
      }
    }
  });

  // -------------------------------------------------------------------------
  // reusePort — clustering support
  // -------------------------------------------------------------------------

  it('reusePort: two engine servers bind the same port and both serve', T, async () => {
    if (process.platform === 'win32') return; // SO_REUSEPORT is POSIX-only
    const a = await startFixtureServer(engine, (ctx) => ctx.respond(200, null, 'ok'), {
      reusePort: true,
    });
    let bId = null;
    try {
      const noop = () => {};
      bId = engine.serve(
        { onRequest: (reqId) => engine.respond(reqId, 200, null, 'ok'), onAborted: noop, onWritable: noop },
        { reusePort: true }
      );
      const bPort = engine.listen(bId, '127.0.0.1', a.port);
      assert.equal(bPort, a.port, 'second server must bind the SAME port via SO_REUSEPORT');
      // The kernel load-balances accepts; either server answering proves both
      // listeners share the port without EADDRINUSE.
      for (let i = 0; i < 5; i++) {
        const res = parseResponse(await rawRequest(a.port, get('/')));
        assert.equal(res.status, 200);
      }
    } finally {
      if (bId !== null) engine.close(bId);
      a.close();
    }
  });

  // -------------------------------------------------------------------------
  // WebSocket: frames pipelined with the handshake
  // -------------------------------------------------------------------------

  it('a WS frame sent in the same TCP segment as the upgrade handshake is delivered', T, async () => {
    const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
    const messages = [];
    const callbacks = {
      onRequest(reqId) {
        const wsId = engine.upgradeToWebSocket(reqId);
        if (wsId === -1) engine.respond(reqId, 400, null, 'not an upgrade');
      },
      onAborted() {},
      onWritable() {},
      onWsOpen() {},
      onWsMessage(wsId, data) {
        messages.push(String(data));
        engine.wsSend(wsId, data, false); // echo
      },
      onWsClose() {},
    };
    const serverId = engine.serve(callbacks);
    const port = engine.listen(serverId, '127.0.0.1', 0);
    try {
      const key = crypto.randomBytes(16).toString('base64');
      const handshake =
        `GET /ws HTTP/1.1${CRLF}Host: t${CRLF}Upgrade: websocket${CRLF}` +
        `Connection: Upgrade${CRLF}Sec-WebSocket-Key: ${key}${CRLF}` +
        `Sec-WebSocket-Version: 13${CRLF}${CRLF}`;
      // Masked text frame "early" (client frames MUST be masked, §5.1)
      const payload = Buffer.from('early', 'utf8');
      const maskKey = Buffer.from([1, 2, 3, 4]);
      const masked = Buffer.from(payload.map((b, i) => b ^ maskKey[i & 3]));
      const frame = Buffer.concat([
        Buffer.from([0x81, 0x80 | payload.length]),
        maskKey,
        masked,
      ]);

      const received = await new Promise((resolve, reject) => {
        const socket = net.connect({ host: '127.0.0.1', port });
        socket.setNoDelay(true);
        let buf = Buffer.alloc(0);
        const timer = setTimeout(() => {
          socket.destroy();
          reject(new Error('no echo frame within 5s'));
        }, 5000);
        socket.on('connect', () => {
          // ONE write: handshake + first frame in the same segment.
          socket.write(Buffer.concat([Buffer.from(handshake, 'latin1'), frame]));
        });
        socket.on('data', (d) => {
          buf = Buffer.concat([buf, d]);
          const headEnd = buf.indexOf('\r\n\r\n');
          if (headEnd === -1) return;
          const head = buf.subarray(0, headEnd + 4).toString('latin1');
          if (!head.startsWith('HTTP/1.1 101')) {
            clearTimeout(timer);
            socket.destroy();
            return reject(new Error(`expected 101, got: ${head.split('\r\n')[0]}`));
          }
          const rest = buf.subarray(headEnd + 4);
          if (rest.length < 2) return;
          const len = rest[1] & 0x7f;
          if (rest.length < 2 + len) return;
          clearTimeout(timer);
          socket.destroy();
          resolve(rest.subarray(2, 2 + len).toString('utf8'));
        });
        socket.on('error', (err) => {
          clearTimeout(timer);
          reject(err);
        });
      });

      assert.equal(received, 'early', 'the pipelined frame must be echoed back');
      assert.deepEqual(messages, ['early'], 'onWsMessage must see the pipelined frame');
    } finally {
      engine.close(serverId);
    }
  });

  // -------------------------------------------------------------------------
  // Host header discipline (RFC 9112 §3.2)
  // -------------------------------------------------------------------------

  it('HTTP/1.1 without a Host header: 400 + close, handler never invoked', T, async () => {
    await withServer((ctx) => ctx.respond(200, null, 'x'), async ({ port, requests }) => {
      const raw = await rawRequest(port, `GET /x HTTP/1.1${CRLF}X-Other: 1${CRLF}${CRLF}`, {
        expectClose: true,
      });
      assert.equal(parseResponse(raw).status, 400);
      assert.equal(requests.length, 0, 'a Host-less HTTP/1.1 request must never reach routing');
    });
  });

  it('duplicate Host headers: 400 + close, handler never invoked (host-confusion defense)', T, async () => {
    await withServer((ctx) => ctx.respond(200, null, 'x'), async ({ port, requests }) => {
      const raw = await rawRequest(
        port,
        `GET /x HTTP/1.1${CRLF}Host: a${CRLF}Host: b${CRLF}${CRLF}`,
        { expectClose: true }
      );
      assert.equal(parseResponse(raw).status, 400);
      assert.equal(requests.length, 0);
    });
  });

  // -------------------------------------------------------------------------
  // Request-target and header-value byte hygiene
  // -------------------------------------------------------------------------

  it('raw control byte in the request target: 400, handler never sees it (log-injection defense)', T, async () => {
    await withServer((ctx) => ctx.respond(200, null, ctx.path), async ({ port, requests }) => {
      for (const target of ['/a\x01b', '/a\x7fb', '/a\rb', '/q?x=\x02']) {
        const raw = await rawRequest(port, `GET ${target} HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`, {
          expectClose: true,
        });
        assert.equal(parseResponse(raw).status, 400, `target ${JSON.stringify(target)} must be rejected`);
      }
      assert.equal(requests.length, 0);
    });
  });

  // A request-target is ASCII (RFC 3986 §2): a client that means é sends
  // %C3%A9. Raw high bytes are where an overlong form of "/" or "." gets past
  // a path check that runs before decoding.
  it('raw high bytes in the target are 400: UTF-8, an overlong form, a lone byte', T, async () => {
    await withServer((ctx) => ctx.respond(200, null, ctx.path), async ({ port, requests }) => {
      // openRaw sends latin1, so \xc3\xa9 goes out as the raw UTF-8 of é
      for (const target of ['/caf\xc3\xa9', '/\xc0\xaf', '/a?b=\xff', '/\x80']) {
        const raw = await rawRequest(port, `GET ${target} HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`, { expectClose: true });
        assert.equal(parseResponse(raw).status, 400, JSON.stringify(target));
      }
      assert.equal(requests.length, 0, 'none reaches the handler');
      const ok = parseResponse(await rawRequest(port, `GET /caf%C3%A9 HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`));
      assert.equal(ok.status, 200);
      assert.equal(ok.body, '/caf%C3%A9');
    });
  });

  it('allowNonAsciiTarget hands raw high bytes over undecoded, as before 1.2.2', T, async () => {
    await withServer((ctx) => ctx.respond(200, null, ctx.path), { allowNonAsciiTarget: true }, async ({ port }) => {
      const raw = await rawRequest(port, `GET /caf\xc3\xa9 HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`);
      const res = parseResponse(raw);
      assert.equal(res.status, 200);
      assert.equal(Buffer.from(res.body, 'latin1').toString('utf8'), '/café');
    });
  });

  it('raw control byte in an inbound header value: 400 (inbound twin of the response-splitting filter)', T, async () => {
    await withServer((ctx) => ctx.respond(200, null, 'x'), async ({ port, requests }) => {
      const raw = await rawRequest(
        port,
        `GET / HTTP/1.1${CRLF}Host: t${CRLF}X-Bad: v\x01v${CRLF}${CRLF}`,
        { expectClose: true }
      );
      assert.equal(parseResponse(raw).status, 400);
      assert.equal(requests.length, 0);
    });
  });

  it('HTAB inside a header value stays legal (RFC 9110 §5.5)', T, async () => {
    await withServer((ctx) => ctx.respond(200, null, ctx.header('x-ok') ?? ''), async ({ port }) => {
      const raw = await rawRequest(port, `GET / HTTP/1.1${CRLF}Host: t${CRLF}X-Ok: a\tb${CRLF}${CRLF}`);
      const res = parseResponse(raw);
      assert.equal(res.status, 200);
      assert.equal(res.body, 'a\tb');
    });
  });

  // -------------------------------------------------------------------------
  // maxUriSize (opt-in 414)
  // -------------------------------------------------------------------------

  it('maxUriSize: a target over the cap answers 414; at the cap is served', T, async () => {
    await withServer(
      (ctx) => ctx.respond(200, null, 'ok'),
      { maxUriSize: 64 },
      async ({ port }) => {
        const at = '/' + 'a'.repeat(63); // exactly 64
        const okRes = parseResponse(
          await rawRequest(port, `GET ${at} HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`)
        );
        assert.equal(okRes.status, 200);

        const over = parseResponse(
          await rawRequest(port, `GET ${at}a HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`, {
            expectClose: true,
          })
        );
        assert.equal(over.status, 414);
      }
    );
  });

  it('no dedicated URI cap by default: a 2KB target is served (bounded only by maxHeadSize)', T, async () => {
    await withServer((ctx) => ctx.respond(200, null, 'ok'), async ({ port }) => {
      const raw = await rawRequest(
        port,
        `GET /${'b'.repeat(2048)} HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`
      );
      assert.equal(parseResponse(raw).status, 200);
    });
  });

  // -------------------------------------------------------------------------
  // Slow-read response DoS (response-delivery deadline + opt-in outbound cap).
  // The receive side has always been swept; these pin down the delivery side:
  // a client that takes its response too slowly (or never) must not hold
  // WriteReq buffers, kernel buffers, and an fd forever.
  // -------------------------------------------------------------------------

  // Far past loopback socket buffering, so a non-reading peer leaves the bulk
  // of the response queued in libuv and the terminal write never completes.
  const BIG = Buffer.alloc(32 * 1024 * 1024, 0x61);

  // Connect, send one GET, and never read the response (paused socket).
  function connectAndStall(port) {
    return new Promise((resolve, reject) => {
      const s = net.connect({ host: '127.0.0.1', port }, () => {
        s.write(`GET /big HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`, (err) =>
          err ? reject(err) : resolve(s)
        );
      });
      s.pause(); // zero consumption: the response can never drain
      s.on('error', () => {}); // RST on shed is expected
    });
  }

  // Skipped on Windows: Winsock reports the first two sends outstanding on a
  // socket complete once it has copied them into its buffer, whatever their
  // size and whatever SO_SNDBUF says (Microsoft, "Design issues - Sending
  // small data segments over TCP with Winsock"), so the 32 MB response is
  // never queued in the engine and the stall the sweep keys on does not
  // exist there. Shrinking the socket buffers would not change that. What
  // this means for applications on Windows is in docs/API.md (send
  // backpressure) and docs/THREAT_MODEL.md (response-delivery budget).
  it('slow-read defense: a client that never reads its response is shed at the delivery deadline',
    { ...T, skip: process.platform === 'win32' && 'loopback absorbs the payload; outbound backpressure is not reproducible on Windows' },
    async () => {
    // Async responder (the MoroJS shape): respond() runs after onRequest
    // returns, so the response takes the uncorked path and `active` stays set
    // until the terminal write flushes - the exact state the receive-side
    // timeouts used to skip forever. The shed must fire onAborted exactly once.
    await withServer(
      (ctx) => { setImmediate(() => ctx.respond(200, null, BIG)); },
      { responseTimeoutMs: 1000 },
      async ({ port, aborted, requests }) => {
        const s = await connectAndStall(port);
        try {
          await waitFor(() => requests.length === 1, { timeout: 5000, message: 'request not surfaced' });
          // The response is queued but undeliverable; the sweep must shed the
          // connection once no write completes for the whole budget.
          await waitFor(() => aborted.length === 1, {
            timeout: 15000,
            message: 'stalled connection was never shed (slow-read DoS)',
          });
        } finally {
          s.destroy();
        }
      }
    );
  });

  it('slow-read defense: a reader that stalls briefly but resumes before the deadline gets the full response', T, async () => {
    const body = Buffer.alloc(8 * 1024 * 1024, 0x62);
    await withServer(
      (ctx) => { setImmediate(() => ctx.respond(200, null, body)); },
      { responseTimeoutMs: 3000 },
      async ({ port, aborted }) => {
        const got = await new Promise((resolve, reject) => {
          let buf = Buffer.alloc(0);
          let expected = -1;
          const timer = setTimeout(() => {
            s.destroy();
            reject(new Error('full response not received'));
          }, 25000);
          const s = net.connect({ host: '127.0.0.1', port }, () => {
            s.write(`GET /big HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`);
            s.pause();
            // Stall for 1.2s - under the 3s budget - then drain everything.
            setTimeout(() => s.resume(), 1200);
          });
          s.pause();
          s.on('data', (d) => {
            buf = Buffer.concat([buf, d]);
            if (expected === -1) {
              const headEnd = buf.indexOf('\r\n\r\n');
              if (headEnd === -1) return;
              const m = /content-length: (\d+)/i.exec(buf.subarray(0, headEnd).toString('latin1'));
              if (!m) return reject(new Error('no content-length'));
              expected = headEnd + 4 + Number(m[1]);
            }
            if (buf.length >= expected) {
              clearTimeout(timer);
              s.destroy();
              resolve(buf.length);
            }
          });
          s.on('error', (err) => {
            clearTimeout(timer);
            reject(err);
          });
        });
        assert.ok(got > body.length, 'the full body must arrive');
        assert.equal(aborted.length, 0, 'a merely-slow reader must NOT be shed');
      }
    );
  });

  it('slow-read defense: a STEADY slow reader of a large single response receives the FULL body (no false positive)', { timeout: 60000 }, async () => {
    // H-1 regression: one large respond() is a single uv_write that only
    // completes when the whole body drains. Progress must be measured by the
    // outbound queue shrinking, not by write completion, or a steadily-reading
    // slow client is shed mid-transfer. 24 MB body, 1s deadline, client pulls
    // 256 KB every 120ms (~2 MB/s continuous) - far more sweep windows than
    // the deadline, so a completion-based check would kill it early.
    const body = Buffer.alloc(16 * 1024 * 1024, 0x63);
    await withServer(
      (ctx) => { setImmediate(() => ctx.respond(200, null, body)); },
      { responseTimeoutMs: 1000 },
      async ({ port, aborted }) => {
        const received = await new Promise((resolve, reject) => {
          let got = 0;
          let expected = -1;
          const s = net.connect({ host: '127.0.0.1', port }, () => {
            s.write(`GET /big HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`);
          });
          s.pause();
          // Drain a bounded slice per tick, falling back to whatever is
          // buffered so the reader always makes progress (a fixed-size read
          // returns null when fewer than that many bytes are buffered, which
          // would stall the drain and defeat the test's intent). Still paced
          // and continuous, spanning many sweep windows > responseTimeoutMs.
          const pull = setInterval(() => {
            const chunk = s.read(256 * 1024) ?? s.read();
            if (chunk) {
              got += chunk.length;
              if (expected === -1) {
                const headEnd = chunk.indexOf('\r\n\r\n'); // head is tiny; in the first slice
                if (headEnd !== -1) {
                  const m = /content-length: (\d+)/i.exec(chunk.subarray(0, headEnd).toString('latin1'));
                  if (m) expected = headEnd + 4 + Number(m[1]);
                }
              }
              if (expected > 0 && got >= expected) {
                clearInterval(pull);
                clearTimeout(guard);
                s.destroy();
                resolve(got);
              }
            }
          }, 120);
          const guard = setTimeout(() => {
            clearInterval(pull);
            s.destroy();
            reject(new Error(`did not receive full body: got ${got}, expected ${expected}`));
          }, 40000);
          s.on('close', () => {
            if (expected === -1 || got < expected) {
              clearInterval(pull);
              clearTimeout(guard);
              reject(new Error(`connection closed mid-download at ${got}/${expected} bytes (H-1 false positive)`));
            }
          });
          s.on('error', () => {});
        });
        assert.ok(received > body.length, 'the entire body must arrive uncut');
        assert.equal(aborted.length, 0, 'a steadily-draining slow reader must never be shed');
      }
    );
  });

  it('slow-read defense: a STEADY slow reader of a STREAMED (chunked write()) response gets the full body', { timeout: 60000 }, async () => {
    // Distinct code path from the single-respond() tests: streaming issues
    // many write() calls, each its own uv_write completing via onWrite. This
    // guards the per-completion writeTicks reset AND the queue-shrinkage reset
    // together against regression - SSE / chunked downloads to a slow reader
    // (the reviewer's named case) must not be severed. Handler respects
    // backpressure (waitWritable), streaming 8 MB in 64 KB chunks under a
    // fixed Content-Length.
    const total = 8 * 1024 * 1024;
    const CHUNK = 64 * 1024;
    await withServer(
      async (ctx) => {
        ctx.writeHead(200, ['content-length', String(total)]);
        const chunk = Buffer.alloc(CHUNK, 0x64);
        let sent = 0;
        while (sent < total) {
          if (!ctx.write(chunk)) await ctx.waitWritable();
          sent += CHUNK;
        }
        ctx.end();
      },
      { responseTimeoutMs: 1000 },
      async ({ port, aborted }) => {
        const gotBody = await new Promise((resolve, reject) => {
          let bodyBytes = 0;
          let headSeen = false;
          let pending = Buffer.alloc(0);
          const s = net.connect({ host: '127.0.0.1', port }, () => {
            s.write(`GET /stream HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`);
          });
          s.pause();
          const pull = setInterval(() => {
            const chunk = s.read(256 * 1024) ?? s.read();
            if (!chunk) return;
            if (!headSeen) {
              pending = Buffer.concat([pending, chunk]);
              const idx = pending.indexOf('\r\n\r\n');
              if (idx === -1) return;
              headSeen = true;
              bodyBytes += pending.length - (idx + 4);
              pending = Buffer.alloc(0);
            } else {
              bodyBytes += chunk.length;
            }
            if (bodyBytes >= total) {
              clearInterval(pull);
              clearTimeout(guard);
              s.destroy();
              resolve(bodyBytes);
            }
          }, 120);
          const guard = setTimeout(() => {
            clearInterval(pull);
            s.destroy();
            reject(new Error(`streamed body incomplete: ${bodyBytes}/${total}`));
          }, 45000);
          s.on('close', () => {
            if (bodyBytes < total) {
              clearInterval(pull);
              clearTimeout(guard);
              reject(new Error(`stream closed mid-body at ${bodyBytes}/${total} (slow-read false positive)`));
            }
          });
          s.on('error', () => {});
        });
        assert.equal(gotBody, total, 'the entire streamed body must arrive uncut');
        assert.equal(aborted.length, 0, 'a steadily-draining slow reader of a stream must never be shed');
      }
    );
  });

  // Skipped on Windows for the same reason as the slow-read shed test above:
  // loopback absorbs the 32 MB response, so the outbound queue never crosses
  // the 256 KB cap. The cap logic is unchanged and verified on Unix.
  it('responseBackpressureLimit (opt-in): outbound bytes past the cap shed the connection immediately',
    { ...T, skip: process.platform === 'win32' && 'loopback absorbs the payload; the outbound queue never crosses the cap on Windows' },
    async () => {
    await withServer(
      (ctx) => { setImmediate(() => ctx.respond(200, null, BIG)); }, // async: uncorked write path
      { responseBackpressureLimit: 256 * 1024, responseTimeoutMs: 0 }, // deadline off: the cap alone must act
      async ({ port, aborted }) => {
        const s = await connectAndStall(port);
        try {
          // No sweep involvement - queueing past the cap closes on the spot.
          await waitFor(() => aborted.length === 1, {
            timeout: 5000,
            message: 'over-cap outbound queue was not shed',
          });
        } finally {
          s.destroy();
        }
      }
    );
  });

  // -------------------------------------------------------------------------
  // Limit clamping: absurd operator values must degrade predictably
  // -------------------------------------------------------------------------

  it('absurdly large numeric limits are clamped defensively; the server still serves', T, async () => {
    await withServer(
      (ctx) => ctx.respond(200, null, ctx.body() ? Buffer.from(ctx.body()) : 'no-body'),
      {
        maxBodySize: Number.MAX_VALUE,
        maxHeadSize: Number.MAX_SAFE_INTEGER,
        maxPendingBytes: Number.MAX_VALUE,
        wsMaxMessageSize: Number.MAX_VALUE,
      },
      async ({ port }) => {
        const res = parseResponse(
          await rawRequest(port, `POST / HTTP/1.1${CRLF}Host: t${CRLF}Content-Length: 5${CRLF}${CRLF}hello`)
        );
        assert.equal(res.status, 200);
        assert.equal(res.body, 'hello');
      }
    );
  });
});

describe('responses built from handler input', { skip }, () => {
  it('a field name or value carrying CR, LF, NUL or another control byte is left out; nothing of it is sent', T, async () => {
    await withServer((ctx) => {
      ctx.respond(200, [
        'x-ok', 'fine',
        'x-crlf', 'a\r\nInjected: 1',
        'x-lf', 'a\nInjected: 2',
        'x-cr', 'a\rInjected: 3',
        'x-nul', 'a\x00b',
        'x-vt', 'a\x0bb',
        'x-del', 'a\x7fb',
        'x-name\r\nInjected: 4', 'v',
        'x-name\x00', 'v',
        'x name', 'v',
        'x:name', 'v',
        '', 'v',
        'set-cookie', 'a=b\r\nSet-Cookie: evil=1',
        'location', '/x\r\nInjected: 5\r\n\r\n<html>',
        'x-obj', { toString: () => 'o\r\nInjected: 6' },
        'x-arr', ['a', 'b\r\nInjected: 7'],
        'x-wide', 'čĊ', // code units whose low bytes are CR LF
        'x-tab', 'a\tb',
      ], 'BODY');
    }, async (server) => {
      const r = await exchange(server, get('/') + get('/'));
      assert.equal(r.responses.length, 2, 'two requests, exactly two responses');
      assert.ok(!/Injected/i.test(r.raw), 'no injected field');
      assert.ok(!r.raw.includes('evil=1'));
      assert.ok(!r.raw.includes('<html>'));
      assert.ok(!r.raw.includes('\x00') && !r.raw.includes('\x0b') && !r.raw.includes('\x7f'));
      const names = r.responses[0].rawHeaders.filter((_, i) => i % 2 === 0);
      assert.deepEqual(names, ['Date', 'x-ok', 'x-wide', 'x-tab', 'Content-Length']);
      // the wide characters went out as UTF-8, not truncated to their low bytes
      assert.equal(Buffer.from(r.responses[0].headers['x-wide'], 'latin1').toString('utf8'), 'čĊ');
      assert.equal(r.responses[0].body, 'BODY');
    });
  });

  it('a handler cannot set the framing or hop-by-hop fields the engine writes itself', T, async () => {
    await withServer((ctx) => {
      ctx.respond(200, ['Transfer-Encoding', 'chunked', 'TRANSFER-ENCODING', 'gzip', 'Connection', 'close', 'Keep-Alive', 'timeout=5', 'Date', 'yesterday', 'content-length', '-5', 'Content-Length', '1e3', 'content-length', ' 4'], 'BODY');
    }, async (server) => {
      const r = await exchange(server, get('/') + get('/'));
      assert.equal(r.responses.length, 2);
      const h = r.responses[0].headers;
      assert.equal(h['content-length'], '4');
      assert.ok(!('transfer-encoding' in h) && !('connection' in h) && !('keep-alive' in h));
      assert.notEqual(h.date, 'yesterday');
      assert.equal(r.closed, false);
    });
  });

  it('a Content-Length that disagrees with the body of respond() is replaced by the real length, on HTTP/1.0 too', T, async () => {
    await withServer((ctx) => ctx.respond(200, ['content-length', ctx.path === '/big' ? '100' : '2'], 'exact-body'), async (server) => {
      for (const path of ['/big', '/small']) {
        const r = await exchange(server, get(path) + get(path));
        assert.equal(r.responses.length, 2);
        assert.equal(r.responses[0].headers['content-length'], '10');
        assert.equal(r.responses[0].body, 'exact-body');
      }
      const r = await exchange(server, 'GET /big HTTP/1.0\r\n\r\n');
      assert.equal(r.responses[0].headers['content-length'], '10');
    });
  });

  it('a second respond(), and write()/end() after a completed response, change nothing on the wire', T, async () => {
    await withServer((ctx) => {
      ctx.respond(200, null, 'one');
      ctx.respond(500, null, 'two');
      ctx.write('three');
      ctx.end('four');
      ctx.writeHead(404, null);
    }, async (server) => {
      const r = await exchange(server, get('/') + get('/'));
      assert.deepEqual(r.responses.map((x) => x.body), ['one', 'one']);
      assert.equal(r.responses[1].rest, '');
    });
  });

  // respond() once the head is out (writeHead() or write() came first - an
  // error path that answers 500 for a handler that failed mid-stream): no
  // second status line may follow the first. Sent as it used to be, the
  // client read it as body bytes and every later response out of step.
  const startThenRespond = {
    'a declared length not yet reached': (ctx) => { ctx.writeHead(200, ['content-length', '400']); ctx.write('part'); ctx.respond(500, null, 'boom'); },
    'a chunked body': (ctx) => { ctx.writeHead(200, null); ctx.write('part'); ctx.respond(500, null, 'boom'); },
    'an implicit head (write() first)': (ctx) => { ctx.write('part'); ctx.respond(500, null, 'boom'); },
    'a later turn': (ctx) => { ctx.writeHead(200, ['content-length', '400']); ctx.write('part'); setTimeout(() => ctx.respond(500, null, 'boom'), 20); },
    'a prepared response': (ctx, server) => { ctx.writeHead(200, null); ctx.write('part'); engine.respondPrepared(ctx.reqId, engine.prepareResponse(server.serverId, 500, null), 'boom'); },
  };
  for (const [name, handler] of Object.entries(startThenRespond)) {
    for (const method of ['GET', 'HEAD']) {
      it(`respond() after the head has been sent (${name}, ${method}) ends the response there and closes; no second head is written`, T, async () => {
        let server;
        await withServer((ctx) => (ctx.path === '/next' ? ctx.respond(200, null, 'NEXT') : handler(ctx, server)), async (s) => {
          server = s;
          const r = await exchange(server, `${method} /first HTTP/1.1\r\nHost: t\r\n\r\n` + get('/next') + get('/next'), { wait: 300 });
          assert.equal((r.raw.match(/HTTP\/1\.1 /g) || []).length, 1, `one status line on the wire: ${JSON.stringify(r.raw)}`);
          assert.ok(r.raw.startsWith('HTTP/1.1 200 '));
          assert.ok(!r.raw.includes('boom') && !r.raw.includes('NEXT'));
          if (method === 'GET') assert.ok(r.raw.endsWith('part') || r.raw.endsWith('part\r\n'), 'the body stops where the handler left it');
          assert.equal(r.closed, true, 'the connection is closed behind the unfinished response');
          assert.equal(server.aborted.length, 0, 'the request was answered, not aborted');
        });
      });
    }
  }
});

describe('slow and silent clients', { skip }, () => {
  const echo = (ctx) => ctx.respond(200, null, ctx.path);

  it('a connection that sends nothing is closed at idleTimeoutMs, with no response', T, async () => {
    await withServer(echo, { idleTimeoutMs: 400, requestTimeoutMs: 0 }, async (server) => {
      const c = await openRaw(server.port);
      const t0 = Date.now();
      await c.waitClose(4000);
      const raw = await c.read().catch(() => '');
      assert.equal(raw, '');
      assert.ok(Date.now() - t0 >= 200, 'not at once: the sweep runs every 250 ms and closes on the second pass');
      c.destroy();
    });
  });

  it('an idle keep-alive connection is closed at idleTimeoutMs after its last request', T, async () => {
    await withServer(echo, { idleTimeoutMs: 400 }, async (server) => {
      const c = await openRaw(server.port);
      await c.send(get('/one'));
      assert.equal(parseResponse(await c.read()).status, 200);
      await c.waitClose(4000);
      c.destroy();
    });
  });

  it('a body that trickles in keeps the connection from idling out but not past requestTimeoutMs (408)', T, async () => {
    await withServer(echo, { idleTimeoutMs: 400, requestTimeoutMs: 1200 }, async (server) => {
      const c = await openRaw(server.port);
      try {
        await c.send(`POST /p HTTP/1.1${CRLF}Host: t${CRLF}Content-Length: 1000${CRLF}${CRLF}`);
        const t0 = Date.now();
        // one byte every 100 ms: always inside the idle window
        while (!c.closed && Date.now() - t0 < 6000) {
          await c.send('x').catch(() => {});
          await delay(100);
        }
        const res = parseResponse(await c.read().catch(() => ''));
        assert.equal(res.status, 408);
        assert.equal(res.headers.connection, 'close');
        assert.ok(Date.now() - t0 >= 1000 && Date.now() - t0 < 4000, `closed after ${Date.now() - t0} ms`);
        assert.equal(server.requests.length, 0);
      } finally {
        c.destroy();
      }
    });
  });

  // The sweep counts passes, and the first pass after a request's first
  // byte (or a connection's last) can come a millisecond after it. The
  // timeout acts on the pass after the one that completes the count: the
  // budget has gone by in full, and the answer comes within one sweep
  // interval after it. Wherever in the interval the first byte falls.
  it('requestTimeoutMs is a full budget: the 408 never comes before it has passed, and comes within a sweep interval after', T, async () => {
    const budget = 1000; // the sweep then runs every 500 ms
    await withServer(echo, { requestTimeoutMs: budget, idleTimeoutMs: 0 }, async (server) => {
      const took = [];
      // Four requests started at different points of the sweep interval, at once.
      await Promise.all(
        [0, 130, 260, 390].map(async (startAfter) => {
          await delay(startAfter);
          const c = await openRaw(server.port);
          try {
            const t0 = Date.now();
            await c.send(`GET /slow HTTP/1.1${CRLF}Host: t${CRLF}X-Unfinished:`);
            const res = parseResponse(await c.read({ until: (buf) => buf.includes(CRLF + CRLF), timeout: 6000 }));
            took.push(Date.now() - t0);
            assert.equal(res.status, 408);
          } finally {
            c.destroy();
          }
        })
      );
      for (const ms of took) {
        assert.ok(ms >= budget, `408 after ${ms} ms of a ${budget} ms budget (all: ${took})`);
        assert.ok(ms < budget + 500 + 400, `408 after ${ms} ms: more than a sweep interval late (all: ${took})`);
      }
      assert.equal(server.requests.length, 0);
    });
  });

  it('a request that takes most of requestTimeoutMs to arrive is served, not timed out', T, async () => {
    const budget = 1000;
    await withServer(echo, { requestTimeoutMs: budget, idleTimeoutMs: 0 }, async (server) => {
      await Promise.all(
        [0, 170, 340].map(async (startAfter) => {
          await delay(startAfter);
          const c = await openRaw(server.port);
          try {
            await c.send(`GET /patient/${startAfter} HTTP/1.1${CRLF}Host: t${CRLF}`);
            await delay(budget - 200); // inside the budget, past all but its last fifth
            await c.send(CRLF);
            const res = parseResponse(await c.read({ until: responsesComplete(1), timeout: 3000 }));
            assert.equal(res.status, 200, `started ${startAfter} ms into the run`);
            assert.equal(res.body, `/patient/${startAfter}`);
          } finally {
            c.destroy();
          }
        })
      );
    });
  });

  it('idleTimeoutMs is a full budget too: a keep-alive connection is not closed before it has been idle that long', T, async () => {
    const budget = 1000;
    await withServer(echo, { idleTimeoutMs: budget, requestTimeoutMs: 0 }, async (server) => {
      const idled = [];
      await Promise.all(
        [0, 130, 260, 390].map(async (startAfter) => {
          await delay(startAfter);
          const c = await openRaw(server.port);
          try {
            await c.send(get('/last'));
            assert.equal(parseResponse(await c.read({ until: responsesComplete(1) })).status, 200);
            const t0 = Date.now();
            await c.waitClose(6000);
            idled.push(Date.now() - t0);
          } finally {
            c.destroy();
          }
        })
      );
      for (const ms of idled) {
        // (a few milliseconds of grace: the clock starts when the response has been read)
        assert.ok(ms >= budget - 20, `closed after ${ms} ms idle with idleTimeoutMs ${budget} (all: ${idled})`);
        assert.ok(ms < budget + 500 + 400, `closed after ${ms} ms idle (all: ${idled})`);
      }
    });
  });

  it('with both receive timeouts off a silent connection is kept', T, async () => {
    await withServer(echo, { idleTimeoutMs: 0, requestTimeoutMs: 0 }, async (server) => {
      const c = await openRaw(server.port);
      await c.send('GET / HT');
      await delay(1500);
      assert.equal(c.closed, false);
      c.destroy();
    });
  });

  it('the time a handler takes is not counted against either receive timeout', T, async () => {
    await withServer((ctx) => { setTimeout(() => ctx.respond(200, null, 'late'), 1200); }, { idleTimeoutMs: 400, requestTimeoutMs: 400 }, async (server) => {
      const res = parseResponse(await rawRequest(server.port, get('/'), { timeout: 5000 }));
      assert.equal(res.status, 200);
      assert.equal(res.body, 'late');
    });
  });
});

// idleTimeoutMs is for a connection nobody is using. One whose response is
// still being written to a peer that is reading it is in use, whether the
// handler answered later (the request stays active until the last byte is
// out) or before it returned (the response is complete once framed, with its
// bytes still queued). How long delivery may take is responseTimeoutMs.
describe('idle timeout and a response still being delivered', { skip }, () => {
  // Read `port`'s answer to one GET at about `rate` bytes per second.
  function slowDownload(port, rate) {
    return new Promise((resolve) => {
      let got = 0;
      let expected = -1;
      let head = Buffer.alloc(0);
      const t0 = Date.now();
      const s = net.connect({ host: '127.0.0.1', port }, () => s.write(get('/big')));
      s.pause();
      const slice = Math.ceil(rate / 20);
      const done = (why) => {
        clearInterval(pull);
        clearTimeout(guard);
        s.destroy();
        resolve({ got, expected, why, ms: Date.now() - t0 });
      };
      const pull = setInterval(() => {
        const chunk = s.read(slice) ?? s.read();
        if (!chunk) return;
        got += chunk.length;
        if (expected === -1) {
          head = Buffer.concat([head, chunk]);
          const headEnd = head.indexOf('\r\n\r\n');
          if (headEnd !== -1) {
            const m = /content-length: (\d+)/i.exec(head.subarray(0, headEnd).toString('latin1'));
            expected = headEnd + 4 + Number(m[1]);
          }
        }
        if (expected > 0 && got >= expected) done('complete');
      }, 50);
      const guard = setTimeout(() => done('timeout'), 30000);
      s.on('close', () => done('closed'));
      s.on('error', () => {});
    });
  }

  it('capabilities.idleSparesDrainingResponse is reported', T, () => {
    assert.equal(engine.probe().capabilities.idleSparesDrainingResponse, true);
  });

  const body = Buffer.alloc(8 * 1024 * 1024, 0x64);
  for (const [name, handler] of [
    ['answered before the handler returns', (ctx) => ctx.respond(200, null, body)],
    ['answered later', (ctx) => void setImmediate(() => ctx.respond(200, null, body))],
  ]) {
    it(`a large response ${name} reaches a slow reader in full, well past idleTimeoutMs`, { timeout: 60000 }, async () => {
      await withServer(handler, { idleTimeoutMs: 500, responseTimeoutMs: 5000 }, async ({ port, aborted }) => {
        const r = await slowDownload(port, 2 * 1024 * 1024); // ~4 s for 8 MiB
        assert.equal(r.why, 'complete', `the download ended "${r.why}" after ${r.ms} ms with ${r.got} of ${r.expected} bytes`);
        assert.ok(r.ms > 1500, `the download outlasted the idle timeout several times over (${r.ms} ms)`);
        assert.equal(aborted.length, 0);
      });
    });
  }

  it('the connection idles out as usual once the response has been delivered', T, async () => {
    await withServer((ctx) => ctx.respond(200, null, 'small'), { idleTimeoutMs: 500, responseTimeoutMs: 5000 }, async (server) => {
      const c = await openRaw(server.port);
      await c.send(get('/one'));
      assert.equal(parseResponse(await c.read()).status, 200);
      const t0 = Date.now();
      await c.waitClose(4000);
      assert.ok(Date.now() - t0 >= 200, 'not at once');
      c.destroy();
    });
  });

  it('a peer that stops reading is closed by responseTimeoutMs; with that budget off, by idleTimeoutMs',
    { timeout: 60000, skip: process.platform === 'win32' && 'loopback absorbs the payload; outbound backpressure is not reproducible on Windows' },
    async () => {
    // The peer sends its request and then neither reads nor writes for
    // `quiet` ms; after that it reads whatever the server still lets it have.
    // A connection the server closed meanwhile ends short of the body.
    const size = 32 * 1024 * 1024;
    const stalled = async (options, quiet) => {
      let got = 0;
      await withServer((ctx) => ctx.respond(200, null, Buffer.alloc(size, 0x65)), options, async ({ port }) => {
        const s = net.connect({ host: '127.0.0.1', port }, () => s.write(get('/big')));
        s.pause();
        s.on('error', () => {});
        await delay(quiet);
        await new Promise((resolve) => {
          const guard = setTimeout(resolve, 15000);
          s.on('data', (d) => { got += d.length; });
          s.on('close', () => { clearTimeout(guard); resolve(); });
          s.resume();
        });
        s.destroy();
      });
      return got;
    };
    assert.ok((await stalled({ idleTimeoutMs: 60000, responseTimeoutMs: 1000 }, 3000)) < size, 'closed by responseTimeoutMs');
    assert.ok((await stalled({ idleTimeoutMs: 1000, responseTimeoutMs: 0, requestTimeoutMs: 0 }, 3000)) < size, 'closed by idleTimeoutMs when responseTimeoutMs is off');
    // and neither budget fires early: the same pause inside both of them costs nothing
    assert.ok((await stalled({ idleTimeoutMs: 60000, responseTimeoutMs: 60000 }, 1500)) > size, 'a pause inside the budgets loses nothing');
  });
});

// A process at its descriptor limit cannot accept. The transports that make
// the accept call themselves (epoll, io_uring) must then wait for a
// descriptor, not ask again on every loop turn: an event loop that never
// sleeps, for as long as peers hold the process at its limit.
describe('the accept path at the descriptor limit', { skip }, () => {
  const ENGINE_ENTRY = new URL('../packages/engine/index.mjs', import.meta.url).href;
  const own = engine && ['epoll', 'uring'].includes(engine.probe().transport);
  const skipHere = !own && 'the libuv transport leaves accept to libuv';

  // The subject serves under RLIMIT_NOFILE 64 and takes every descriptor
  // that is left, the way an application at its limit holds them. `order`:
  //   'listen-first'  it was listening before the descriptors ran out;
  //   'limit-first'   they ran out first - the transport could not open the
  //                   spare descriptor it sheds waiting connections with -
  //                   and it listens with the one that then came back.
  // On 'measure' it reports the CPU time it used over one second, on 'free'
  // it gives the descriptors back.
  const subject = (order) => `
    import fs from 'node:fs';
    const { default: engine } = await import(${JSON.stringify(ENGINE_ENTRY)});
    const sid = engine.serve({ onRequest(reqId) { engine.respond(reqId, 200, null, 'ok'); }, onAborted() {} }, {});
    const taken = [];
    const exhaust = () => { try { for (;;) taken.push(fs.openSync('/dev/null', 'r')); } catch {} };
    let port;
    if (${JSON.stringify(order)} === 'limit-first') {
      exhaust();
      try { engine.listen(sid, '127.0.0.1', 0); } catch {}
      fs.closeSync(taken.pop());
      port = engine.listen(sid, '127.0.0.1', 0);
    } else {
      port = engine.listen(sid, '127.0.0.1', 0);
      exhaust();
    }
    console.log('PORT ' + port);
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (d) => {
      if (d.includes('measure')) {
        const before = process.cpuUsage();
        setTimeout(() => { const u = process.cpuUsage(before); console.log('CPU ' + Math.round((u.user + u.system) / 1000)); }, 1000);
      }
      if (d.includes('free')) { for (const fd of taken.splice(0)) fs.closeSync(fd); console.log('FREED'); }
      if (d.includes('exit')) { engine.close(sid); process.stdin.destroy(); }
    });
  `;

  for (const order of ['listen-first', 'limit-first']) {
    it(`peers that arrive while no descriptor is free cost no CPU, and are served once one is (${order})`, { ...T, skip: skipHere }, async () => {
      const child = spawn('sh', ['-c', 'ulimit -n 64; exec "$0" --input-type=module -e "$SUBJECT"', process.execPath], {
        env: { ...process.env, SUBJECT: subject(order) },
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      let out = '';
      let err = '';
      child.stdout.on('data', (d) => { out += d; });
      child.stderr.on('data', (d) => { err += d; });
      const exited = new Promise((resolve) => child.on('exit', resolve));
      const said = async (re) => {
        let m;
        await waitFor(() => (m = re.exec(out)) !== null || child.exitCode !== null, { timeout: 10000 }).catch(() => {});
        assert.ok(m, `the subject said ${re} (stdout: ${out}; stderr: ${err})`);
        return m;
      };
      const peers = [];
      try {
        const port = parseInt((await said(/PORT (\d+)/))[1], 10);
        for (let i = 0; i < 8; i++) {
          const s = net.connect(port, '127.0.0.1');
          s.on('error', () => {});
          peers.push(s);
        }
        await delay(300);
        child.stdin.write('measure\n');
        const cpuMs = parseInt((await said(/CPU (\d+)/))[1], 10);
        assert.ok(cpuMs < 300, `an idle second at the limit, with peers waiting, used ${cpuMs} ms of CPU`);
        child.stdin.write('free\n');
        await said(/FREED/);
        // Accepting starts again within a sweep of the descriptors coming back.
        const res = parseResponse(await rawRequest(port, get('/', `Connection: close${CRLF}`), { expectClose: true, timeout: 5000 }));
        assert.equal(res.status, 200);
      } finally {
        for (const s of peers) s.destroy();
        child.stdin.write('exit\n');
        const guard = setTimeout(() => child.kill('SIGKILL'), 5000);
        const code = await exited;
        clearTimeout(guard);
        assert.equal(code, 0, `the subject ends by itself after close(): ${err}`);
      }
    });
  }
});

// The same on the libuv transport of a Linux host, where the engine makes
// the accept call as well. The hard case there is an application that
// competes for descriptors from other threads: the descriptor the listener
// gives up for a moment to turn a waiting peer away is taken before the
// listener has it back, and from then on a waiting connection can be neither
// accepted nor dropped.
describe('the libuv accept path at the descriptor limit', { skip }, () => {
  const ENGINE_ENTRY = new URL('../packages/engine/index.mjs', import.meta.url).href;
  const here = engine && process.platform === 'linux' && engine.probe().transport === 'uv';
  const skipHere = !here && 'the libuv transport on Linux only (the engine makes the accept call there)';

  // The subject serves under RLIMIT_NOFILE 64, takes every descriptor that
  // is left and keeps four pool threads asking for another, the way an
  // application that opens files does at its limit. 'calm' stops those and
  // reports how many they got, 'measure' reports the CPU time of one second,
  // 'free' gives every descriptor back.
  const subject = `
    import fs from 'node:fs';
    const { default: engine } = await import(${JSON.stringify(ENGINE_ENTRY)});
    const sid = engine.serve({ onRequest(reqId) { engine.respond(reqId, 200, null, 'ok'); }, onAborted() {} }, {});
    const port = engine.listen(sid, '127.0.0.1', 0);
    const taken = [];
    try { for (;;) taken.push(fs.openSync('/dev/null', 'r')); } catch {}
    const held = taken.length;
    let asking = true;
    const ask = () => { if (asking) fs.open('/dev/null', 'r', (err, fd) => { if (!err) taken.push(fd); ask(); }); };
    for (let i = 0; i < 4; i++) ask();
    console.log('PORT ' + port);
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (d) => {
      if (d.includes('calm')) { asking = false; setTimeout(() => console.log('TOOK ' + (taken.length - held)), 100); }
      if (d.includes('measure')) {
        const before = process.cpuUsage();
        setTimeout(() => { const u = process.cpuUsage(before); console.log('CPU ' + Math.round((u.user + u.system) / 1000)); }, 1000);
      }
      if (d.includes('free')) { for (const fd of taken.splice(0)) fs.closeSync(fd); console.log('FREED'); }
      if (d.includes('exit')) { engine.close(sid); process.stdin.destroy(); }
    });
  `;

  it('peers that can be neither accepted nor turned away cost no CPU, and service resumes with the descriptors', { ...T, skip: skipHere }, async () => {
    const child = spawn('sh', ['-c', 'ulimit -n 64; exec "$0" --input-type=module -e "$SUBJECT"', process.execPath], {
      env: { ...process.env, SUBJECT: subject },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let out = '';
    let err = '';
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { err += d; });
    const exited = new Promise((resolve) => child.on('exit', resolve));
    const said = async (re) => {
      let m;
      await waitFor(() => (m = re.exec(out)) !== null || child.exitCode !== null, { timeout: 10000 }).catch(() => {});
      assert.ok(m, `the subject said ${re} (stdout: ${out}; stderr: ${err})`);
      return m;
    };
    const peers = [];
    const knock = (port) =>
      new Promise((resolve) => {
        const s = net.connect(port, '127.0.0.1');
        s.on('error', () => {});
        s.on('connect', resolve);
        s.on('close', resolve);
        peers.push(s);
      });
    try {
      const port = parseInt((await said(/PORT (\d+)/))[1], 10);
      // Each of these makes the listener lend its spare descriptor once.
      for (let i = 0; i < 300; i++) await knock(port);
      child.stdin.write('calm\n');
      const took = parseInt((await said(/TOOK (\d+)/))[1], 10);
      for (let i = 0; i < 8; i++) await knock(port);
      await delay(300);
      child.stdin.write('measure\n');
      const cpuMs = parseInt((await said(/CPU (\d+)/))[1], 10);
      assert.ok(cpuMs < 300, `an idle second at the limit, with peers waiting, used ${cpuMs} ms of CPU (the pool threads took ${took} descriptor(s))`);
      for (const s of peers.splice(0)) s.destroy();
      child.stdin.write('free\n');
      await said(/FREED/);
      // Accepting starts again within a sweep of the descriptors coming back.
      const res = parseResponse(await rawRequest(port, get('/', `Connection: close${CRLF}`), { expectClose: true, timeout: 5000 }));
      assert.equal(res.status, 200);
    } finally {
      for (const s of peers) s.destroy();
      child.stdin.write('exit\n');
      const guard = setTimeout(() => child.kill('SIGKILL'), 5000);
      const code = await exited;
      clearTimeout(guard);
      assert.equal(code, 0, `the subject ends by itself after close(): ${err}`);
    }
  });
});
