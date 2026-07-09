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
});
