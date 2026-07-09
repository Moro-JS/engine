// Limit-configurability conformance suite for @morojs/engine.
//
// Every serve() limit option is exercised at its boundary over a real socket:
//   - maxHeadSize          431 above the cap, 200 at it
//   - maxHeaders           431 above the cap, 200 at it
//   - maxBodySize          413 above the cap, 200 at it; and a RAISED cap
//                          (12 MiB) accepting an 11 MiB body the default
//                          would reject
//   - wsMaxMessageSize     Close 1009 above the cap, echo at it
//   - wsBackpressureLimit / writeHighWaterMark  write() backpressure + drain
//   - backlog              option accepted, sequential connections serve
//   - Content-Length overflow regression: a 30-digit CL is rejected 413
//     during header parsing, handler never invoked
//
// Run with: node --test

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  loadEngine,
  startFixtureServer,
  rawRequest,
  openRaw,
  parseResponse,
} from './helpers.mjs';

const engine = await loadEngine();
const skip = engine
  ? false
  : '@morojs/engine native binding not usable yet — limits suite skipped';

const T = { timeout: 30000 };
const CRLF = '\r\n';

const ok = (ctx) => ctx.respond(200, null, 'ok');
const echoLen = (ctx) => {
  const b = ctx.body();
  ctx.respond(200, null, String(b ? b.byteLength : 0));
};

async function withServer(handler, options, fn) {
  const server = await startFixtureServer(engine, handler, options);
  try {
    return await fn(server);
  } finally {
    server.close();
  }
}

// Minimal masked client frame builder (RFC 6455 §5.2/§5.3) for the WS cases.
function maskedTextFrame(payload) {
  const data = Buffer.isBuffer(payload) ? payload : Buffer.from(payload, 'utf8');
  const key = crypto.randomBytes(4);
  let header;
  if (data.length <= 125) {
    header = Buffer.from([0x81, 0x80 | data.length]);
  } else if (data.length <= 0xffff) {
    header = Buffer.from([0x81, 0x80 | 126, (data.length >> 8) & 0xff, data.length & 0xff]);
  } else {
    throw new Error('test frame too large');
  }
  const masked = Buffer.from(data);
  for (let i = 0; i < masked.length; i++) masked[i] ^= key[i & 3];
  return Buffer.concat([header, key, masked]);
}

async function wsHandshake(client) {
  const key = crypto.randomBytes(16).toString('base64');
  await client.send(
    `GET / HTTP/1.1${CRLF}Host: t${CRLF}Upgrade: websocket${CRLF}` +
      `Connection: Upgrade${CRLF}Sec-WebSocket-Key: ${key}${CRLF}` +
      `Sec-WebSocket-Version: 13${CRLF}${CRLF}`
  );
  const head = await client.read({ until: (s) => s.includes('\r\n\r\n') });
  assert.match(head, /^HTTP\/1\.1 101 /, 'upgrade must be accepted');
}

describe('@morojs/engine limit configurability', { skip }, () => {
  // -------------------------------------------------------------------------
  // maxHeadSize
  // -------------------------------------------------------------------------

  it('maxHeadSize: a head just under the cap is served, one over is 431', T, async () => {
    await withServer(ok, { maxHeadSize: 512 }, async (server) => {
      // Base request without padding; pad X-P's value to hit a target size.
      const base = (pad) => `GET / HTTP/1.1${CRLF}Host: t${CRLF}X-P: ${pad}${CRLF}${CRLF}`;
      const fixedLen = base('').length;

      const fits = base('a'.repeat(512 - fixedLen));
      const under = await rawRequest(server.port, fits);
      assert.equal(parseResponse(under).status, 200, 'head == maxHeadSize must be served');

      const over = base('a'.repeat(512 - fixedLen + 1));
      const raw = await rawRequest(server.port, over, { expectClose: true });
      assert.equal(parseResponse(raw).status, 431, 'head > maxHeadSize must be 431');
      assert.equal(server.requests.length, 1, 'oversized head must not reach the handler');
    });
  });

  // -------------------------------------------------------------------------
  // maxHeaders
  // -------------------------------------------------------------------------

  it('maxHeaders: N headers serve, N+1 is 431', T, async () => {
    await withServer(ok, { maxHeaders: 5 }, async (server) => {
      const req = (n) => {
        let h = `GET / HTTP/1.1${CRLF}Host: t${CRLF}`; // Host is header #1
        for (let i = 2; i <= n; i++) h += `X-H${i}: v${CRLF}`;
        return h + CRLF;
      };
      const under = await rawRequest(server.port, req(5));
      assert.equal(parseResponse(under).status, 200, '5 headers must be served');

      const raw = await rawRequest(server.port, req(6), { expectClose: true });
      assert.equal(parseResponse(raw).status, 431, '6th header must be 431');
      assert.equal(server.requests.length, 1);
    });
  });

  // -------------------------------------------------------------------------
  // maxBodySize
  // -------------------------------------------------------------------------

  it('maxBodySize: a body at the cap is served, one byte over is 413', T, async () => {
    await withServer(echoLen, { maxBodySize: 16 }, async (server) => {
      const post = (body) =>
        `POST / HTTP/1.1${CRLF}Host: t${CRLF}Content-Length: ${body.length}${CRLF}${CRLF}${body}`;

      const at = await rawRequest(server.port, post('x'.repeat(16)));
      const atRes = parseResponse(at);
      assert.equal(atRes.status, 200);
      assert.equal(atRes.body, '16', 'body == maxBodySize must reach the handler intact');

      const raw = await rawRequest(server.port, post('x'.repeat(17)), { expectClose: true });
      assert.equal(parseResponse(raw).status, 413, 'body > maxBodySize must be 413');
      assert.equal(server.requests.length, 1, 'oversized body must not reach the handler');
    });
  });

  it('maxBodySize raised above the default: an 11 MiB body is accepted end-to-end', T, async () => {
    await withServer(echoLen, { maxBodySize: 12 * 1024 * 1024 }, async (server) => {
      const size = 11 * 1024 * 1024; // > the 10 MiB default, < the raised cap
      const body = Buffer.alloc(size, 0x61);
      const client = await openRaw(server.port);
      try {
        await client.send(
          `POST / HTTP/1.1${CRLF}Host: t${CRLF}Content-Length: ${size}${CRLF}${CRLF}`
        );
        await client.send(body);
        const raw = await client.read({ until: (s) => /\r\n\r\n\d+$/.test(s), timeout: 20000 });
        const res = parseResponse(raw);
        assert.equal(res.status, 200, 'raised cap must accept a body the default rejects');
        assert.equal(res.body, String(size), 'all bytes must arrive');
      } finally {
        client.destroy();
      }
    });
  });

  // -------------------------------------------------------------------------
  // Content-Length overflow regression (long-digit CL)
  // -------------------------------------------------------------------------

  it('a 30-digit Content-Length is rejected 413 during parsing, handler never invoked', T, async () => {
    await withServer(ok, {}, async (server) => {
      const raw = await rawRequest(
        server.port,
        `POST / HTTP/1.1${CRLF}Host: t${CRLF}Content-Length: ${'9'.repeat(30)}${CRLF}${CRLF}`,
        { expectClose: true }
      );
      assert.equal(parseResponse(raw).status, 413, 'absurd CL must be rejected as too large');
      assert.equal(server.requests.length, 0, 'handler must never see the request');
    });
  });

  // -------------------------------------------------------------------------
  // wsMaxMessageSize
  // -------------------------------------------------------------------------

  it('wsMaxMessageSize: a message at the cap echoes; one over closes with 1009', T, async () => {
    // Dedicated server with WS callbacks: upgrade in onRequest, echo messages.
    const messages = [];
    const closes = [];
    const sid = engine.serve(
      {
        onRequest(reqId) {
          if (engine.upgradeToWebSocket(reqId) === -1) {
            engine.respond(reqId, 400, null, 'not a websocket upgrade');
          }
        },
        onAborted() {},
        onWsOpen() {},
        onWsMessage(wsId, data, isBinary) {
          messages.push({
            size: typeof data === 'string' ? Buffer.byteLength(data) : data.byteLength,
          });
          engine.wsSend(wsId, data, isBinary); // echo verbatim
        },
        onWsClose(wsId, code) {
          closes.push(code);
        },
      },
      { wsMaxMessageSize: 64 }
    );
    const port = await engine.listen(sid, '127.0.0.1', 0);
    try {
      // At the cap: echoes.
      let client = await openRaw(port);
      await wsHandshake(client);
      await client.send(maskedTextFrame('a'.repeat(64)));
      const echoed = await client.read({ until: (s) => s.length >= 2 + 64 });
      assert.equal(echoed.charCodeAt(0) & 0x0f, 0x1, 'echo must be a text frame');
      client.destroy();

      // One over: Close 1009 then TCP close.
      client = await openRaw(port);
      await wsHandshake(client);
      await client.send(maskedTextFrame('a'.repeat(65)));
      const bytes = await client.read({ expectClose: true });
      const buf = Buffer.from(bytes, 'latin1');
      assert.equal(buf[0] & 0x0f, 0x8, 'server must send a Close frame');
      assert.equal(buf.readUInt16BE(2), 1009, 'close code must be 1009 Message Too Big');
      await client.waitClose();
      assert.ok(closes.includes(1009), 'onWsClose must surface 1009');
      client.destroy();
    } finally {
      engine.close(sid);
    }
  });

  // -------------------------------------------------------------------------
  // writeHighWaterMark (streaming backpressure threshold)
  // -------------------------------------------------------------------------

  it('writeHighWaterMark: a tiny mark makes write() report backpressure, then onWritable drains', T, async () => {
    // uv_write flushes inline while the kernel buffers have room, so
    // backpressure only appears once the client stalls: pause() the socket
    // before the request so the TCP window fills while the handler streams.
    const net = await import('node:net');
    const chunk = 'z'.repeat(64 * 1024);
    let writesBeforeFalse = -1;
    let drained = false;
    const handler = async (ctx) => {
      ctx.writeHead(200, ['content-type', 'text/plain']);
      let i = 0;
      while (i < 256 && ctx.write(chunk)) i++;
      writesBeforeFalse = i < 256 ? i : -1; // -1: never saw backpressure
      if (i < 256) {
        await ctx.waitWritable(); // onWritable must fire once the client reads
        drained = true;
      }
      ctx.end();
    };
    await withServer(handler, { writeHighWaterMark: 1024 }, async (server) => {
      await new Promise((resolve, reject) => {
        const socket = net.connect({ host: '127.0.0.1', port: server.port }, () => {
          socket.pause();
          socket.write(`GET / HTTP/1.1${CRLF}Host: t${CRLF}Connection: close${CRLF}${CRLF}`);
          // Give the handler time to hit the full kernel buffer, then drain.
          setTimeout(() => socket.resume(), 500);
        });
        let bytes = 0;
        socket.on('data', (d) => {
          bytes += d.length;
        });
        socket.on('close', () => resolve(bytes));
        socket.on('error', reject);
        socket.setTimeout(20000, () => reject(new Error('stalled')));
      });
      assert.notEqual(writesBeforeFalse, -1, 'write() must report backpressure once the socket stalls');
      assert.equal(drained, true, 'onWritable must fire after the client drains');
    });
  });

  // -------------------------------------------------------------------------
  // backlog
  // -------------------------------------------------------------------------

  it('backlog: a backlog of 1 still serves sequential connections', T, async () => {
    await withServer(ok, { backlog: 1 }, async (server) => {
      for (let i = 0; i < 5; i++) {
        const raw = await rawRequest(server.port, `GET / HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`);
        assert.equal(parseResponse(raw).status, 200, `sequential connection ${i} must serve`);
      }
    });
  });
});
