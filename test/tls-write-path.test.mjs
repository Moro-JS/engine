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
});
