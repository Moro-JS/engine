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
import net from 'node:net';
import {
  loadEngine,
  startFixtureServer,
  rawRequest,
  openRaw,
  parseResponse,
  parseResponses,
  exchange,
  bodyText,
  delay,
  waitFor,
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

  it('a 30-digit Content-Length is rejected 400 during parsing, handler never invoked', T, async () => {
    await withServer(ok, {}, async (server) => {
      const raw = await rawRequest(
        server.port,
        `POST / HTTP/1.1${CRLF}Host: t${CRLF}Content-Length: ${'9'.repeat(30)}${CRLF}${CRLF}`,
        { expectClose: true }
      );
      assert.equal(parseResponse(raw).status, 400, 'a value no 64-bit length holds is malformed');
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

describe('connection and backlog caps', { skip }, () => {
  const get = (path) => `GET ${path} HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`;

  it('maxConnections: a connection over the cap is closed at once with no response; a slot freed is reusable', T, async () => {
    await withServer(ok, { maxConnections: 2 }, async (server) => {
      const a = await openRaw(server.port);
      const b = await openRaw(server.port);
      await a.send(get('/a'));
      assert.equal(parseResponse(await a.read()).status, 200);
      const over = await openRaw(server.port);
      await over.waitClose(3000);
      assert.equal(await over.read().catch(() => ''), '');
      b.destroy();
      await delay(100);
      const again = await openRaw(server.port);
      await again.send(get('/again'));
      assert.equal(parseResponse(await again.read()).status, 200);
      a.destroy();
      again.destroy();
    });
  });

  it('maxPendingBytes: bytes pipelined behind a response in flight are capped; over the cap the connection is closed and the request aborted once', T, async () => {
    let respond;
    await withServer((ctx) => { respond = () => ctx.respond(200, null, 'late'); }, { maxPendingBytes: 4096 }, async (server) => {
      const c = await openRaw(server.port);
      try {
        await c.send(get('/held'));
        await delay(50);
        await c.send(get('/' + 'p'.repeat(2000)));
        await delay(50);
        assert.equal(c.closed, false, 'under the cap the bytes are kept');
        await c.send(get('/' + 'p'.repeat(4000))).catch(() => {});
        await c.waitClose(3000);
        await waitFor(() => server.aborted.length === 1);
        respond(); // late answer for the aborted request: a no-op
        await delay(50);
        assert.equal(server.requests.length, 1);
      } finally {
        c.destroy();
      }
    });
  });
});

// What one connection can make the server hold. A request body is bounded by
// maxBodySize, the input waiting behind a response by maxPendingBytes, and
// the responses waiting on a peer by the write high-water mark: once that
// much is queued, no further request is taken from the connection until the
// peer has read.
describe('per-connection memory', { skip }, () => {
  // The cases that need the server's write queue to back up behind a peer
  // that is not reading: Windows loopback buffers absorb tens of megabytes,
  // so the queue never forms there (the engine behaves the same; over a real
  // network the peer's receive window does what loopback does elsewhere).
  // The sizes leave room for the 10 MB or so a Linux loopback pair takes.
  const needsBackpressure = { skip: process.platform === 'win32' && 'outbound backpressure is not reproducible on Windows loopback' };
  const MB = 1024 * 1024;
  const get = (path) => `GET ${path} HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`;
  const paused = async (port) => {
    const sock = net.connect({ host: '127.0.0.1', port });
    await new Promise((resolve) => sock.once('connect', resolve));
    sock.pause(); // reads nothing until resumed
    sock.on('error', () => {});
    return sock;
  };

  it('the framing of a chunked body - sizes and extensions - is not kept in memory for the length of the request', { timeout: 120000 }, async () => {
    let seen = -1;
    await withServer((ctx) => { seen = ctx.body().byteLength; ctx.respond(200, null, 'ok'); }, {}, async (server) => {
      const sock = net.connect({ host: '127.0.0.1', port: server.port });
      await new Promise((resolve) => sock.once('connect', resolve));
      sock.on('error', () => {});
      let got = '';
      sock.on('data', (d) => (got += d.toString('latin1')));
      sock.write(`POST /amp HTTP/1.1${CRLF}Host: t${CRLF}Transfer-Encoding: chunked${CRLF}${CRLF}`);
      // 100 KB of body in 1-byte chunks, each with a 1000-byte extension: ~96 MB on the wire.
      const block = Buffer.from(('1;' + 'e'.repeat(1000) + '\r\nX\r\n').repeat(1000), 'latin1');
      const before = process.memoryUsage().rss;
      let peak = before;
      for (let i = 0; i < 100 && !sock.destroyed; i++) {
        if (!sock.write(block)) await new Promise((resolve) => sock.once('drain', resolve));
        if (i % 10 === 9) peak = Math.max(peak, process.memoryUsage().rss);
      }
      await delay(200);
      peak = Math.max(peak, process.memoryUsage().rss);
      sock.write('0\r\n\r\n');
      await waitFor(() => got.includes('\r\n\r\nok'), { timeout: 10000, message: `no response: ${JSON.stringify(got.slice(0, 40))}` });
      sock.destroy();
      assert.equal(seen, 100000, 'the body itself arrives whole');
      const grown = peak - before;
      assert.ok(grown < 48 * MB, `RSS grew by ${(grown / MB).toFixed(0)} MB while a 100 KB body was received`);
    });
  });

  it('requests are not taken from a connection whose responses are not being read', { ...T, ...needsBackpressure }, async () => {
    const big = Buffer.alloc(MB, 0x61);
    await withServer((ctx) => ctx.respond(200, null, big), {}, async (server) => {
      const sock = await paused(server.port);
      sock.write(get('/big').repeat(100));
      await delay(300);
      sock.write(get('/big').repeat(100));
      await delay(500);
      const handled = server.requests.length;
      sock.destroy();
      // 200 requests are 5.6 KB of input; answering them all queues 200 MB.
      assert.ok(handled <= 32, `${handled} of 200 pipelined requests were answered into memory with nothing read`);
    });
  });

  it('the same connection is served in full and in order once the peer reads', { timeout: 60000, ...needsBackpressure }, async () => {
    const big = Buffer.alloc(MB, 0x61);
    let n = 0;
    await withServer((ctx) => ctx.respond(200, ['x-n', String(n++)], big), {}, async (server) => {
      const sock = await paused(server.port);
      sock.write(get('/big').repeat(30));
      await delay(200);
      sock.write(get('/big').repeat(10)); // arrives while intake is held
      await delay(200);
      const heldAt = server.requests.length;
      let bytes = 0;
      const order = [];
      let tail = '';
      sock.on('data', (d) => {
        bytes += d.length;
        const text = tail + d.toString('latin1');
        for (const m of text.matchAll(/x-n: (\d+)\r\n/g)) order.push(Number(m[1]));
        tail = text.slice(-16).replace(/x-n: \d+\r\n/g, '');
      });
      sock.resume();
      await waitFor(() => bytes >= 40 * MB, { timeout: 30000, interval: 50, message: 'the held requests were never served' }).catch(() => {});
      sock.destroy();
      assert.ok(heldAt < 40, 'intake was held while nothing was read');
      assert.ok(bytes >= 40 * MB, `received ${bytes} bytes`);
      assert.deepEqual(order, Array.from({ length: 40 }, (_, i) => i));
      assert.equal(server.requests.length, 40, 'each request reached the handler exactly once');
    });
  });

  it('a request with a body, a 100-continue and an error held behind unread responses all get their turn', { timeout: 60000, ...needsBackpressure }, async () => {
    const big = Buffer.alloc(MB, 0x61);
    await withServer((ctx) => (ctx.path === '/big' ? ctx.respond(200, null, big) : ctx.respond(200, null, `${ctx.path}:${bodyText(ctx)}`)), {}, async (server) => {
      const sock = await paused(server.port);
      const N = 24;
      sock.write(get('/big').repeat(N));
      await delay(200);
      // all of this arrives while intake is held
      sock.write(`POST /a HTTP/1.1${CRLF}Host: t${CRLF}Content-Length: 5${CRLF}${CRLF}he`);
      await delay(50);
      sock.write(`llo` + `POST /b HTTP/1.1${CRLF}Host: t${CRLF}Expect: 100-continue${CRLF}Content-Length: 3${CRLF}${CRLF}`);
      await delay(50);
      sock.write(`abc` + get('/c') + `BAD LINE${CRLF}${CRLF}` + get('/never'));
      await delay(100);
      assert.ok(server.requests.length < N, 'nothing behind the unread responses has been handed over yet');
      const chunks = [];
      sock.on('data', (d) => chunks.push(d));
      sock.resume();
      await new Promise((resolve) => { sock.on('close', resolve); setTimeout(resolve, 20000); });
      sock.destroy();
      const responses = parseResponses(Buffer.concat(chunks).toString('latin1'));
      assert.deepEqual(responses.map((r) => r.status), [...Array(N).fill(200), 200, 100, 200, 200, 400]);
      assert.deepEqual(responses.slice(N).map((r) => r.body), ['/a:hello', '', '/b:abc', '/c:', '']);
      assert.ok(!server.requests.some((q) => q.path === '/never'));
    });
  });

  it('input sent while intake is held is bounded by maxPendingBytes', { ...T, ...needsBackpressure }, async () => {
    const big = Buffer.alloc(MB, 0x61);
    await withServer((ctx) => ctx.respond(200, null, big), { maxPendingBytes: 64 * 1024 }, async (server) => {
      const sock = await paused(server.port);
      let closed = false;
      sock.on('close', () => { closed = true; });
      sock.write(get('/big').repeat(32));
      await delay(200);
      const handled = server.requests.length;
      assert.ok(handled < 32, 'intake is held');
      // 256 KB more, against a 64 KB cap: the connection is closed, not buffered further.
      // (A paused socket does not see the close until it writes again.)
      for (let i = 0; i < 16 && !closed; i++) {
        sock.write(get('/' + 'p'.repeat(16 * 1024)));
        await delay(30);
      }
      await waitFor(() => closed, { timeout: 5000, message: 'the connection was kept past maxPendingBytes' });
      // (One more of the first 32 may have been taken meanwhile, as the kernel took more of the queue.)
      assert.ok(server.requests.length < 32, 'intake stayed held');
      assert.ok(server.requests.every((q) => q.path === '/big'), 'none of what was sent afterwards was handed to the handler');
    });
  });

  // The cap is on everything received and not yet dispatched. Counted per
  // response - on what arrived since the last one was given - it let one
  // connection add another maxPendingBytes for every response it read.
  it('input pipelined behind one response after another is bounded by maxPendingBytes in total', T, async () => {
    const CAP = 64 * 1024;
    await withServer((ctx) => { setTimeout(() => ctx.respond(200, null, 'ok'), 3); }, { maxPendingBytes: CAP }, async (server) => {
      const sock = net.connect({ host: '127.0.0.1', port: server.port });
      await new Promise((resolve) => sock.once('connect', resolve));
      sock.on('error', () => {});
      let closed = false;
      sock.on('close', () => { closed = true; });
      // After each response, 48 KB more of small requests: under the cap each time.
      const burst = get('/p').repeat(Math.floor((48 * 1024) / get('/p').length));
      const ROUNDS = 40;
      let sent = 0;
      let responses = 0;
      let text = '';
      sock.on('data', (d) => {
        text += d.toString('latin1');
        for (let at = text.indexOf('\r\n\r\nok'); at !== -1; at = text.indexOf('\r\n\r\nok')) {
          text = text.slice(at + 6);
          responses++;
          if (responses <= ROUNDS && !closed) {
            sock.write(burst);
            sent += burst.length;
          }
        }
      });
      sock.write(get('/first'));
      await waitFor(() => closed || responses > ROUNDS, { timeout: 20000, interval: 20, message: 'neither closed nor served' });
      sock.destroy();
      assert.ok(closed, `still open after ${sent} bytes were sent ahead of their responses, against a cap of ${CAP}`);
      assert.ok(sent <= 4 * CAP, `${sent} bytes were taken before the connection was closed`);
    });
  });

  it('maxBodySize: a chunk that would take the body over the limit is answered 413 at its size line, before its data', T, async () => {
    const echo = (ctx) => ctx.respond(200, null, String(bodyText(ctx).length));
    const head = `POST /c HTTP/1.1${CRLF}Host: t${CRLF}Transfer-Encoding: chunked${CRLF}${CRLF}`;
    await withServer(echo, { maxBodySize: 1000 }, async (server) => {
      // 5 bytes collected, then a chunk of 996 announced: one more than is left. Not a byte of it is sent.
      let r = await exchange(server, head + `5${CRLF}hello${CRLF}3e4${CRLF}`, { wait: 300 });
      assert.deepEqual(r.statuses, [413]);
      assert.equal(r.closed, true);
      assert.equal(r.handled, 0);
      // announced in a later write than the first chunk: the same
      r = await exchange(server, null, { wait: 300, parts: [head + `5${CRLF}hello${CRLF}`, `3e4${CRLF}`] });
      assert.deepEqual(r.statuses, [413]);
      // exactly what is left is taken
      r = await exchange(server, head + `5${CRLF}hello${CRLF}3e3${CRLF}${'x'.repeat(995)}${CRLF}0${CRLF}${CRLF}`, { wait: 300 });
      assert.deepEqual(r.statuses, [200]);
      assert.equal(r.responses[0].body, '1000');
    });
  });

  // 431 says the head is over maxHeadSize, 400 that it is malformed. Which
  // of the two a head that is both gets is decided line by line - 431 for
  // the first line that takes the head over the limit, 400 for a malformed
  // line before that - and so does not depend on how the bytes arrived.
  it('maxHeadSize: a malformed head gets the same answer in one write and in several', T, async () => {
    const pad = (n) => 'a'.repeat(n);
    const cases = [
      ['a short malformed request line with a long read behind it', `BAD LINE${CRLF}Host: t${CRLF}X-Pad: ${pad(3000)}${CRLF}${CRLF}`, 400],
      ['an unsupported version with a long read behind it', `GET / HTTP/2.0${CRLF}Host: t${CRLF}${CRLF}${pad(3000)}`, 505],
      ['a malformed request line that is itself over the limit', `BAD ${pad(3000)}${CRLF}Host: t${CRLF}${CRLF}`, 431],
      ['a malformed header line that crosses the limit', `GET / HTTP/1.1${CRLF}Host: t${CRLF}X A: ${pad(3000)}${CRLF}${CRLF}`, 431],
      ['a malformed header line ahead of the one that crosses the limit', `GET / HTTP/1.1${CRLF}Host: t${CRLF}X A: b${CRLF}X-Pad: ${pad(3000)}${CRLF}${CRLF}`, 400],
      ['a malformed header line past the limit', `GET / HTTP/1.1${CRLF}Host: t${CRLF}X-Pad: ${pad(2100)}${CRLF}X A: b${CRLF}${CRLF}`, 431],
    ];
    await withServer(ok, { maxHeadSize: 2048 }, async (server) => {
      for (const [label, bytes, status] of cases) {
        const whole = await exchange(server, bytes, { wait: 250 });
        assert.deepEqual(whole.statuses, [status], `${label}: one write`);
        const parts = [];
        for (let i = 0; i < bytes.length; i += 700) parts.push(bytes.slice(i, i + 700));
        const split = await exchange(server, null, { wait: 250, parts, gap: 25 });
        assert.deepEqual(split.statuses, [status], `${label}: ${parts.length} writes`);
        assert.equal(whole.handled + split.handled, 0, label);
      }
    });
  });

  // The trailer section of a chunked body is limited to maxHeadSize; the
  // request pipelined behind it in the same read is not part of it.
  it('maxHeadSize: the trailer limit does not count the request pipelined behind a chunked body', T, async () => {
    const echo = (ctx) => ctx.respond(200, null, `${ctx.path}:${bodyText(ctx).length}`);
    const chunkedPost = (trailer = '') => `POST /c HTTP/1.1${CRLF}Host: t${CRLF}Transfer-Encoding: chunked${CRLF}${CRLF}5${CRLF}hello${CRLF}0${CRLF}${trailer}${CRLF}`;
    const bigPost = `POST /b HTTP/1.1${CRLF}Host: t${CRLF}Content-Length: 8192${CRLF}${CRLF}${'x'.repeat(8192)}`;
    await withServer(echo, { maxHeadSize: 4096 }, async (server) => {
      let r = await exchange(server, chunkedPost() + bigPost, { wait: 400 });
      assert.deepEqual(r.statuses, [200, 200], 'both requests in one write');
      assert.deepEqual(r.responses.map((x) => x.body), ['/c:5', '/b:8192']);
      r = await exchange(server, chunkedPost(`X-T: ${'a'.repeat(3000)}${CRLF}`) + bigPost, { wait: 400 });
      assert.deepEqual(r.statuses, [200, 200], 'a trailer inside the limit, with a large request behind it');
      // the limit itself still holds, whatever follows
      r = await exchange(server, chunkedPost(`X-T: ${'a'.repeat(5000)}${CRLF}`) + bigPost, { wait: 400 });
      assert.deepEqual(r.statuses, [431]);
      r = await exchange(server, chunkedPost(`X-T: aaaaaaaaaa${CRLF}`.repeat(300)), { wait: 400 });
      assert.deepEqual(r.statuses, [431]);
    });
  });
});
