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

  it('raw UTF-8 high bytes in the target are still served (lenient like Node)', T, async () => {
    await withServer((ctx) => ctx.respond(200, null, ctx.path), async ({ port }) => {
      // openRaw sends latin1, so \xc3\xa9 goes out as the raw UTF-8 of é
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

  it('slow-read defense: a client that never reads its response is shed at the delivery deadline', T, async () => {
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

  it('responseBackpressureLimit (opt-in): outbound bytes past the cap shed the connection immediately', T, async () => {
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
