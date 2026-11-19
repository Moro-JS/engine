// The TLS write path: a reply's records go to the socket as they are
// encrypted when nothing is queued ahead of them, and whatever the socket
// does not take is queued behind, in order. What a client receives must be
// the same bytes in the same order whichever of the two each record took -
// which is what a reader that falls behind, a reply in two pieces, a streamed
// reply and a pipelined batch each put to the test.

import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { loadEngine, startFixtureServer, parseResponse, parseResponses, decodeChunked } from './helpers.mjs';
import { sslFileOptions, openRawTls, rawTlsRequest } from './tls-helpers.mjs';

const T = { timeout: 30000 };
const CRLF = '\r\n';
const GET = (path = '/') => `GET ${path} HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`;

// Deterministic bytes that differ everywhere, so a reordered or repeated
// record cannot go unnoticed.
function pattern(n, seed = 1) {
  const out = Buffer.allocUnsafe(n);
  let x = seed >>> 0;
  for (let i = 0; i < n; i++) {
    x = (Math.imul(x, 1664525) + 1013904223) >>> 0;
    out[i] = x >>> 24;
  }
  return out;
}
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');

// Read one response whose body length its head declares (Content-Length),
// straight off the socket as bytes. With `pauseMs` the socket is left unread
// for that long first, so the server's socket buffer fills and its writes
// queue.
async function readResponse(socket, { pauseMs = 0 } = {}) {
  const chunks = [];
  let got = 0;
  let total = -1;
  if (pauseMs) {
    socket.pause();
    await new Promise((r) => setTimeout(r, pauseMs));
  }
  return await new Promise((resolve, reject) => {
    const finish = () => {
      socket.off('data', onData);
      resolve(Buffer.concat(chunks));
    };
    const onData = (d) => {
      chunks.push(d);
      got += d.length;
      if (total === -1) {
        const all = Buffer.concat(chunks);
        const headEnd = all.indexOf('\r\n\r\n');
        if (headEnd !== -1) {
          const m = /content-length: (\d+)/i.exec(all.subarray(0, headEnd).toString('latin1'));
          total = headEnd + 4 + (m ? Number(m[1]) : 0);
        }
      }
      if (total !== -1 && got >= total) finish();
    };
    socket.on('data', onData);
    socket.once('end', finish);
    socket.once('error', reject);
    socket.resume();
  });
}

describe('TLS write path', () => {
  let engine;
  before(async () => {
    engine = await loadEngine();
  });

  async function withTlsServer(handler, fn, options = {}) {
    const server = await startFixtureServer(engine, handler, { ssl: sslFileOptions(), ...options });
    try {
      await fn(server);
    } finally {
      server.close();
    }
  }

  const bodyOf = (raw, n) => raw.subarray(raw.length - n);

  for (const size of [1, 100, 16384, 16385, 70000, 5 << 20]) {
    it(`a ${size}-byte body sent as head + buffer arrives intact`, T, async () => {
      const body = pattern(size, size);
      await withTlsServer(
        (ctx) => ctx.respond(200, ['content-type', 'application/octet-stream'], body),
        async (server) => {
          const client = await openRawTls(server.port);
          try {
            await client.send(GET());
            const raw = await readResponse(client.socket);
            const head = raw.subarray(0, raw.indexOf('\r\n\r\n') + 4).toString('latin1');
            assert.match(head, /^HTTP\/1\.1 200 /);
            assert.match(head, new RegExp(`content-length: ${size}\\r\\n`, 'i'));
            assert.equal(raw.length - head.length, size);
            assert.equal(sha(bodyOf(raw, size)), sha(body));
          } finally {
            client.destroy();
          }
        }
      );
    });
  }

  it('a reader that falls behind gets every byte, in order', T, async () => {
    const size = 12 << 20;
    const body = pattern(size, 7);
    await withTlsServer(
      (ctx) => ctx.respond(200, ['content-type', 'application/octet-stream'], body),
      async (server) => {
        const client = await openRawTls(server.port);
        try {
          await client.send(GET());
          // Long enough for the server to fill the socket and queue the rest.
          const raw = await readResponse(client.socket, { pauseMs: 300 });
          assert.equal(sha(bodyOf(raw, size)), sha(body));
        } finally {
          client.destroy();
        }
      }
    );
  });

  it('a string body (one buffer with the head) arrives intact past the record size', T, async () => {
    const text = 'abcdefghij'.repeat(5000);
    await withTlsServer(
      (ctx) => ctx.respond(200, ['content-type', 'text/plain'], text),
      async (server) => {
        const res = parseResponse(await rawTlsRequest(server.port, GET()));
        assert.equal(res.status, 200);
        assert.equal(res.body, text);
      }
    );
  });

  it('a reply sent later, outside the request callback, takes the same path', T, async () => {
    const body = pattern(200000, 3);
    await withTlsServer(
      async (ctx) => {
        await new Promise((r) => setTimeout(r, 10));
        ctx.respond(200, ['content-type', 'application/octet-stream'], body);
      },
      async (server) => {
        const client = await openRawTls(server.port);
        try {
          await client.send(GET());
          const raw = await readResponse(client.socket, { pauseMs: 100 });
          assert.equal(sha(bodyOf(raw, body.length)), sha(body));
        } finally {
          client.destroy();
        }
      }
    );
  });

  it('a streamed reply keeps its chunks in order through backpressure', T, async () => {
    const pieces = Array.from({ length: 300 }, (_, i) => pattern(8192, i + 1));
    await withTlsServer(
      async (ctx) => {
        ctx.writeHead(200, ['content-type', 'application/octet-stream']);
        for (const piece of pieces) {
          if (!ctx.write(piece)) await ctx.waitWritable();
        }
        ctx.end();
      },
      async (server) => {
        const client = await openRawTls(server.port);
        try {
          await client.send(GET());
          client.socket.pause();
          await new Promise((r) => setTimeout(r, 200));
          client.socket.resume();
          const raw = await client.read({ timeout: 20000, until: (s) => s.endsWith('0\r\n\r\n') });
          const res = parseResponse(raw);
          assert.equal(res.status, 200);
          const decoded = decodeChunked(raw.slice(raw.indexOf('\r\n\r\n') + 4));
          assert.equal(decoded.complete, true);
          assert.equal(sha(Buffer.from(decoded.body, 'latin1')), sha(Buffer.concat(pieces)));
        } finally {
          client.destroy();
        }
      }
    );
  });

  it('pipelined requests are answered in order, each with its own body', T, async () => {
    const n = 40;
    await withTlsServer(
      (ctx) => ctx.respond(200, ['content-type', 'text/plain'], `${ctx.path}:${'x'.repeat(2000)}`),
      async (server) => {
        const client = await openRawTls(server.port);
        try {
          await client.send(Array.from({ length: n }, (_, i) => GET(`/r${i}`)).join(''));
          const raw = await client.read({ until: (s) => parseResponses(s).length >= n, timeout: 10000 });
          const responses = parseResponses(raw);
          assert.equal(responses.length, n);
          responses.forEach((res, i) => {
            assert.equal(res.status, 200);
            assert.equal(res.body, `/r${i}:${'x'.repeat(2000)}`);
          });
        } finally {
          client.destroy();
        }
      }
    );
  });

  it('many requests on one connection, one at a time, each get the right reply', T, async () => {
    const bodies = new Map();
    await withTlsServer(
      (ctx) => {
        const body = pattern(3000 + (ctx.reqId % 7) * 4000, ctx.reqId);
        bodies.set(ctx.path, body);
        ctx.respond(200, ['content-type', 'application/octet-stream'], body);
      },
      async (server) => {
        const client = await openRawTls(server.port);
        try {
          for (let i = 0; i < 60; i++) {
            await client.send(GET(`/n${i}`));
            const raw = Buffer.from(
              await client.read({
                until: (s) => {
                  const head = s.indexOf('\r\n\r\n');
                  if (head === -1) return false;
                  const m = /content-length: (\d+)/i.exec(s.slice(0, head));
                  return m !== null && s.length - head - 4 >= Number(m[1]);
                },
              }),
              'latin1'
            );
            const expected = bodies.get(`/n${i}`);
            assert.equal(sha(bodyOf(raw, expected.length)), sha(expected), `reply ${i}`);
          }
        } finally {
          client.destroy();
        }
      }
    );
  });

  // A large piece of a streamed reply is encrypted from the handler's bytes,
  // with only the ends of a chunk copied; sizes on and around the record size
  // and its multiples, each chunk different bytes.
  it('large chunks of a streamed reply arrive intact, whatever their size', T, async () => {
    const sizes = [32768, 32769, 40000, 65536, 49152 + 7, 100001, 16384 * 5, 10, 1048579, 50000, 3];
    const pieces = sizes.map((n, i) => pattern(n, i + 11));
    await withTlsServer(
      async (ctx) => {
        ctx.writeHead(200, ['content-type', 'application/octet-stream']);
        for (const piece of pieces) {
          if (!ctx.write(piece)) await ctx.waitWritable();
        }
        ctx.end();
      },
      async (server) => {
        const client = await openRawTls(server.port);
        try {
          await client.send(GET());
          client.socket.pause();
          await new Promise((r) => setTimeout(r, 100));
          client.socket.resume();
          const raw = await client.read({ timeout: 20000, until: (s) => s.endsWith('0\r\n\r\n') });
          assert.equal(parseResponse(raw).status, 200);
          const decoded = decodeChunked(raw.slice(raw.indexOf('\r\n\r\n') + 4));
          assert.equal(decoded.complete, true);
          assert.equal(decoded.body.length, sizes.reduce((a, b) => a + b, 0));
          assert.equal(sha(Buffer.from(decoded.body, 'latin1')), sha(Buffer.concat(pieces)));
        } finally {
          client.destroy();
        }
      }
    );
  });

  it('a streamed reply with a declared length is those bytes, large pieces and small', T, async () => {
    const pieces = [70000, 5, 32768, 200000, 4096, 131072].map((n, i) => pattern(n, i + 29));
    const body = Buffer.concat(pieces);
    await withTlsServer(
      async (ctx) => {
        ctx.writeHead(200, ['content-type', 'application/octet-stream', 'content-length', String(body.length)]);
        for (const piece of pieces.slice(0, -1)) {
          if (!ctx.write(piece)) await ctx.waitWritable();
        }
        ctx.end(pieces[pieces.length - 1]);
      },
      async (server) => {
        const client = await openRawTls(server.port);
        try {
          await client.send(GET());
          const raw = await readResponse(client.socket, { pauseMs: 100 });
          const head = raw.subarray(0, raw.indexOf('\r\n\r\n') + 4).toString('latin1');
          assert.match(head, new RegExp(`content-length: ${body.length}\\r\\n`, 'i'));
          assert.equal(raw.length - head.length, body.length);
          assert.equal(sha(bodyOf(raw, body.length)), sha(body));
          // ...and the connection is in step for the next request
          await client.send(GET());
          const again = await readResponse(client.socket);
          assert.equal(sha(bodyOf(again, body.length)), sha(body));
        } finally {
          client.destroy();
        }
      }
    );
  });

  // Small replies of a pipelined batch share records; one too large for that
  // is encrypted on its own, behind the ones before it and ahead of the ones
  // after.
  it('pipelined replies of every size keep their order', T, async () => {
    const sizes = [10, 3000, 5000, 70000, 100, 4000, 4200, 0, 16384, 1, 40000, 2, 3, 20000, 600];
    const n = 45;
    const bodyFor = (i) => pattern(sizes[i % sizes.length], i + 1);
    await withTlsServer(
      (ctx) => ctx.respond(200, ['content-type', 'application/octet-stream', 'x-n', ctx.path.slice(2)], bodyFor(Number(ctx.path.slice(2)))),
      async (server) => {
        const client = await openRawTls(server.port);
        try {
          await client.send(Array.from({ length: n }, (_, i) => GET(`/r${i}`)).join(''));
          const raw = await client.read({ until: (s) => parseResponses(s).length >= n, timeout: 15000 });
          const responses = parseResponses(raw);
          assert.equal(responses.length, n);
          responses.forEach((res, i) => {
            assert.equal(res.status, 200);
            assert.equal(res.headers['x-n'], String(i), `reply ${i} is in its place`);
            assert.equal(sha(Buffer.from(res.body, 'latin1')), sha(bodyFor(i)), `reply ${i}`);
          });
        } finally {
          client.destroy();
        }
      }
    );
  });

  // WebSocket frames over TLS: the echoes of the frames of one read share
  // records, a large one is encrypted from where it is, and a send to
  // another socket (outside any read of its own) goes out at once.
  it('WSS: the echoes of one read and sends to another socket arrive whole and in order', T, async () => {
    const frame = (payload, opcode = 2) => {
      const n = payload.length;
      const head = n < 126 ? Buffer.from([0x80 | opcode, 0x80 | n]) : n < 65536 ? Buffer.from([0x80 | opcode, 0x80 | 126, n >> 8, n & 255]) : Buffer.concat([Buffer.from([0x80 | opcode, 0x80 | 127, 0, 0, 0, 0]), Buffer.from([n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255])]);
      const mask = crypto.randomBytes(4);
      const masked = Buffer.from(payload);
      for (let i = 0; i < n; i++) masked[i] ^= mask[i & 3];
      return Buffer.concat([head, mask, masked]);
    };
    // The server's frames (never masked) cut out of a byte stream.
    const reader = (socket) => {
      let buf = Buffer.alloc(0);
      const waiting = [];
      const pump = () => {
        for (;;) {
          if (!waiting.length || buf.length < 2) return;
          let n = buf[1] & 0x7f, at = 2;
          if (n === 126) { if (buf.length < 4) return; n = buf.readUInt16BE(2); at = 4; }
          else if (n === 127) { if (buf.length < 10) return; n = Number(buf.readBigUInt64BE(2)); at = 10; }
          if (buf.length < at + n) return;
          const payload = Buffer.from(buf.subarray(at, at + n));
          buf = buf.subarray(at + n);
          waiting.shift()(payload);
        }
      };
      socket.on('data', (d) => { buf = Buffer.concat([buf, d]); pump(); });
      return () => new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('no frame within 10 s')), 10000);
        waiting.push((p) => { clearTimeout(timer); resolve(p); });
        pump();
      });
    };
    const fanout = [pattern(50000, 71), pattern(10, 72), pattern(100000, 73), pattern(3000, 74), pattern(32768, 75)];
    const sockets = new Set();
    const sid = engine.serve(
      {
        onRequest(reqId) {
          if (engine.upgradeToWebSocket(reqId) === -1) engine.respond(reqId, 400, null, 'not an upgrade');
        },
        onAborted() {},
        onWsOpen(wsId) { sockets.add(wsId); },
        onWsMessage(wsId, data, isBinary) {
          if (!isBinary && data === 'fanout') {
            for (const other of sockets) if (other !== wsId) for (const m of fanout) engine.wsSend(other, m, true);
            return;
          }
          engine.wsSend(wsId, data, isBinary);
        },
        onWsClose(wsId) { sockets.delete(wsId); },
      },
      { ssl: sslFileOptions() }
    );
    const port = engine.listen(sid, '127.0.0.1', 0);
    const open = async () => {
      const client = await openRawTls(port);
      await client.send(
        `GET /ws HTTP/1.1${CRLF}Host: t${CRLF}Upgrade: websocket${CRLF}Connection: Upgrade${CRLF}` +
          `Sec-WebSocket-Key: ${crypto.randomBytes(16).toString('base64')}${CRLF}Sec-WebSocket-Version: 13${CRLF}${CRLF}`
      );
      assert.match(await client.read({ until: (s) => s.includes('\r\n\r\n') }), /^HTTP\/1\.1 101 /);
      return client;
    };
    const a = await open();
    const b = await open();
    try {
      const nextA = reader(a.socket);
      const sizes = [5, 200, 4000, 40000, 3, 70000, 126, 65536, 1, 4090, 4096, 0, 9000];
      const payloads = sizes.map((n, i) => pattern(n, i + 41));
      // One write, so that as many frames as fit arrive in one read.
      await a.send(Buffer.concat(payloads.map((p) => frame(p))));
      for (let i = 0; i < payloads.length; i++) {
        const got = await nextA();
        assert.equal(got.length, sizes[i], `echo ${i}: length`);
        assert.equal(sha(got), sha(payloads[i]), `echo ${i}`);
      }
      await b.send(frame(Buffer.from('fanout'), 1));
      for (let i = 0; i < fanout.length; i++) assert.equal(sha(await nextA()), sha(fanout[i]), `fanout ${i}`);
      // The echoing side is still in step afterwards.
      await a.send(frame(Buffer.from('still here')));
      assert.equal((await nextA()).toString(), 'still here');
    } finally {
      a.destroy();
      b.destroy();
      engine.close(sid);
    }
  });

  it('a response with no body and a HEAD response are complete on their own', T, async () => {
    await withTlsServer(
      (ctx) => (ctx.path === '/empty' ? ctx.respond(204, null, null) : ctx.respond(200, null, 'hello')),
      async (server) => {
        const client = await openRawTls(server.port);
        try {
          await client.send(GET('/empty'));
          assert.equal(parseResponse(await client.read()).status, 204);
          await client.send(`HEAD /x HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`);
          const head = parseResponse(await client.read(), { noBody: true });
          assert.equal(head.status, 200);
          // ...and the connection is still in step for the next one
          await client.send(GET('/x'));
          assert.equal(parseResponse(await client.read()).body, 'hello');
        } finally {
          client.destroy();
        }
      }
    );
  });

  // The small replies of a batch share records. Whatever ends the sharing
  // early - a handler that answers later, the write high-water mark, a reply
  // that closes the connection - every reply still arrives, once, in order.
  it('a pipelined batch in which some handlers answer later is answered in order', T, async () => {
    const n = 60;
    const bodyFor = (i) => pattern(40 + (i * 37) % 900, i + 3);
    await withTlsServer(
      (ctx) => {
        const i = Number(ctx.path.slice(2));
        const reply = () => ctx.respond(200, ['x-n', String(i)], bodyFor(i));
        if (i % 5 === 3) setImmediate(reply);
        else if (i % 7 === 6) queueMicrotask(reply);
        else reply();
      },
      async (server) => {
        const client = await openRawTls(server.port);
        try {
          for (let round = 0; round < 2; round++) {
            await client.send(Array.from({ length: n }, (_, i) => GET(`/r${i}`)).join(''));
            const raw = await client.read({ until: (s) => parseResponses(s).length >= n, timeout: 15000 });
            const responses = parseResponses(raw);
            assert.equal(responses.length, n);
            responses.forEach((res, i) => {
              assert.equal(res.headers['x-n'], String(i), `round ${round}: reply ${i} is in its place`);
              assert.equal(sha(Buffer.from(res.body, 'latin1')), sha(bodyFor(i)), `round ${round}: reply ${i}`);
            });
          }
        } finally {
          client.destroy();
        }
      }
    );
  });

  it('small replies past the write high-water mark, to a reader that falls behind', T, async () => {
    const n = 150;
    const bodyFor = (i) => pattern(2500 + (i % 11) * 100, i + 9);
    await withTlsServer(
      (ctx) => ctx.respond(200, ['x-n', ctx.path.slice(2)], bodyFor(Number(ctx.path.slice(2)))),
      async (server) => {
        const client = await openRawTls(server.port);
        try {
          client.socket.pause();
          // In pieces: one write this large would be one read of 64 KiB after another.
          for (let from = 0; from < n; from += 50)
            await client.send(Array.from({ length: 50 }, (_, k) => GET(`/r${from + k}`)).join(''));
          await new Promise((r) => setTimeout(r, 200));
          client.socket.resume();
          const raw = await client.read({ until: (s) => parseResponses(s).length >= n, timeout: 20000 });
          const responses = parseResponses(raw);
          assert.equal(responses.length, n);
          responses.forEach((res, i) => {
            assert.equal(res.headers['x-n'], String(i), `reply ${i} is in its place`);
            assert.equal(sha(Buffer.from(res.body, 'latin1')), sha(bodyFor(i)), `reply ${i}`);
          });
        } finally {
          client.destroy();
        }
      },
      { writeHighWaterMark: 16384 }
    );
  });

  it('a batch whose last request closes the connection: every reply, then the end', T, async () => {
    await withTlsServer(
      (ctx) => ctx.respond(200, ['x-n', ctx.path.slice(2)], `reply ${ctx.path.slice(2)}`),
      async (server) => {
        const client = await openRawTls(server.port);
        try {
          const reqs = Array.from({ length: 9 }, (_, i) => GET(`/r${i}`)).join('') +
            `GET /r9 HTTP/1.1${CRLF}Host: t${CRLF}Connection: close${CRLF}${CRLF}`;
          await client.send(reqs);
          const raw = await client.read({ expectClose: true, timeout: 10000 });
          const responses = parseResponses(raw);
          assert.equal(responses.length, 10);
          responses.forEach((res, i) => assert.equal(res.body, `reply ${i}`));
          assert.equal(responses[9].headers.connection, 'close');
        } finally {
          client.destroy();
        }
      }
    );
  });

  it('end() with a large body and no writeHead(), and a large last chunk, among small replies', T, async () => {
    const big = pattern(180000, 61);
    await withTlsServer(
      (ctx) => {
        if (ctx.path === '/end') return ctx.end(big);
        if (ctx.path === '/chunked') {
          ctx.writeHead(200, ['content-type', 'application/octet-stream']);
          ctx.write('first');
          return ctx.end(big);
        }
        ctx.respond(200, null, 'small');
      },
      async (server) => {
        const client = await openRawTls(server.port);
        try {
          await client.send(GET('/s') + GET('/end') + GET('/s') + GET('/chunked') + GET('/s'));
          const raw = await client.read({ until: (s) => parseResponses(s).length >= 5, timeout: 15000 });
          const r = parseResponses(raw);
          assert.equal(r.length, 5);
          for (const i of [0, 2, 4]) assert.equal(r[i].body, 'small');
          assert.equal(r[1].headers['content-length'], String(big.length));
          assert.equal(sha(Buffer.from(r[1].body, 'latin1')), sha(big));
          assert.equal(r[3].headers['transfer-encoding'], 'chunked');
          assert.equal(sha(Buffer.from(r[3].body, 'latin1')), sha(Buffer.concat([Buffer.from('first'), big])));
        } finally {
          client.destroy();
        }
      }
    );
  });
});
