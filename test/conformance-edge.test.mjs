// Additional HTTP/1.1 conformance EDGE cases for @morojs/engine.
//
// Companion to conformance.test.mjs — this file adds over-the-wire edge cases
// NOT covered there (duplicate headers, OWS trimming, long query strings,
// empty header values, non-standard methods, chunk extensions/trailers, deep
// pipelining, slow-drip framing, exact body-limit boundaries, Content-Length:0,
// handler-supplied Content-Length, connection reuse after streaming, HTTP/1.0
// keep-alive, and two smuggling/malformed-syntax defenses).
//
// Like the sibling suite, everything is driven over a raw TCP socket via the
// shared helpers, and the whole file SKIPS cleanly when the native binding is
// not usable yet. Run with: node --test test/conformance-edge.test.mjs
//
// Policy: these tests assert the engine's ACTUAL wire behavior. Where a case
// exercises arguable-but-defensible behavior, the assertion documents what the
// engine really does (see inline notes).

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
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
  : '@morojs/engine native binding not usable yet (binary missing, probe().ok false, or serve() not implemented) — conformance-edge suite skipped';

// Generous per-test ceiling; individual reads have their own tighter timeouts.
const T = { timeout: 30000 };

const CRLF = '\r\n';
const get = (path, extraHeaders = '') => `GET ${path} HTTP/1.1${CRLF}Host: t${CRLF}${extraHeaders}${CRLF}`;

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

const echoPath = (ctx) => ctx.respond(200, ['content-type', 'text/plain'], `echo:${ctx.path}`);
const echoBody = (ctx) => ctx.respond(200, null, ctx.body() ?? '');

// All values for `name` in a flat [k,v,k,v,...] header array (keys lowercased).
function headerValues(flat, name) {
  const out = [];
  for (let i = 0; i + 1 < flat.length; i += 2) {
    if (flat[i] === name) out.push(flat[i + 1]);
  }
  return out;
}

// Count occurrences of a response header (case-insensitive) in the raw head.
function countResponseHeader(raw, name) {
  const headEnd = raw.indexOf('\r\n\r\n');
  const head = headEnd === -1 ? raw : raw.slice(0, headEnd);
  let count = 0;
  for (const line of head.split('\r\n')) {
    const idx = line.indexOf(':');
    if (idx !== -1 && line.slice(0, idx).trim().toLowerCase() === name.toLowerCase()) count++;
  }
  return count;
}

describe('@morojs/engine HTTP/1.1 conformance — edge cases', { skip }, () => {
  it('duplicate headers: two X-Forwarded-For are both visible in getHeaders() flat array', T, async () => {
    let flat = null;
    await withServer((ctx) => {
      flat = ctx.headers();
      ctx.respond(200, null, 'ok');
    }, async ({ port }) => {
      const res = parseResponse(
        await rawRequest(
          port,
          get('/', `X-Forwarded-For: 1.1.1.1${CRLF}X-Forwarded-For: 2.2.2.2${CRLF}`),
          { until: responsesComplete(1) }
        )
      );
      assert.equal(res.status, 200);
      const vals = headerValues(flat, 'x-forwarded-for');
      assert.deepEqual(vals, ['1.1.1.1', '2.2.2.2'], 'both duplicate headers must survive in order');
    });
  });

  it('OWS trimming: internal spaces preserved; leading/trailing OWS (SP/HTAB) stripped', T, async () => {
    let flat = null;
    await withServer((ctx) => {
      flat = ctx.headers();
      ctx.respond(200, null, 'ok');
    }, async ({ port }) => {
      // X-Spaced keeps internal spaces; X-Trim has SP+HTAB padding to strip.
      const res = parseResponse(
        await rawRequest(
          port,
          get('/', `X-Spaced: alpha beta  gamma${CRLF}X-Trim: \t  padded value \t ${CRLF}`),
          { until: responsesComplete(1) }
        )
      );
      assert.equal(res.status, 200);
      assert.equal(headerValues(flat, 'x-spaced')[0], 'alpha beta  gamma', 'internal spaces preserved');
      assert.equal(headerValues(flat, 'x-trim')[0], 'padded value', 'leading/trailing OWS trimmed');
    });
  });

  it('long query string (several KB): path and query split correctly', T, async () => {
    let seen = null;
    const query = 'q=' + 'x'.repeat(6000) + '&flag=1';
    await withServer((ctx) => {
      seen = { path: ctx.path, query: ctx.query() };
      ctx.respond(200, null, 'ok');
    }, async ({ port }) => {
      const res = parseResponse(await rawRequest(port, get(`/search?${query}`), { until: responsesComplete(1) }));
      assert.equal(res.status, 200);
      assert.equal(seen.path, '/search');
      assert.equal(seen.query, query, 'raw multi-KB query must round-trip exactly');
    });
  });

  it('empty header value ("X-Empty:") is accepted; value is the empty string', T, async () => {
    let flat = null;
    let direct;
    await withServer((ctx) => {
      flat = ctx.headers();
      direct = ctx.header('x-empty');
      ctx.respond(200, null, 'ok');
    }, async ({ port }) => {
      const res = parseResponse(
        await rawRequest(port, get('/', `X-Empty:${CRLF}`), { until: responsesComplete(1) })
      );
      assert.equal(res.status, 200);
      assert.deepEqual(headerValues(flat, 'x-empty'), [''], 'empty header must be present with value ""');
      assert.equal(direct, '', 'getHeader() for an empty header returns ""');
    });
  });

  it('non-standard method (PROPFIND / PURGE): methodIdx=7 OTHER, getMethod returns the verb', T, async () => {
    const seen = [];
    await withServer((ctx) => {
      seen.push({ ctxMethod: ctx.method, verb: engine.getMethod(ctx.reqId), path: ctx.path });
      ctx.respond(200, null, 'ok');
    }, async ({ port }) => {
      for (const verb of ['PROPFIND', 'PURGE']) {
        const res = parseResponse(
          await rawRequest(port, `${verb} /res HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`, {
            until: responsesComplete(1),
          })
        );
        assert.equal(res.status, 200, `${verb} should reach the handler`);
      }
      assert.equal(seen.length, 2);
      for (const s of seen) {
        assert.equal(s.ctxMethod, 'OTHER', 'METHODS[7] is OTHER for a non-standard verb');
      }
      assert.equal(seen[0].verb, 'PROPFIND', 'getMethod() returns the raw verb for OTHER');
      assert.equal(seen[1].verb, 'PURGE');
    });
  });

  it('no headers at all (request line + blank line only): engine is lenient and serves it', T, async () => {
    await withServer(echoPath, async ({ port }) => {
      // No Host header — HTTP/1.1 technically requires it, but the engine is lenient.
      const res = parseResponse(
        await rawRequest(port, `GET /bare HTTP/1.1${CRLF}${CRLF}`, { until: responsesComplete(1) })
      );
      assert.equal(res.status, 200);
      assert.equal(res.body, 'echo:/bare');
    });
  });

  it('chunked body with chunk extensions: extension ignored, body reassembled', T, async () => {
    await withServer(echoBody, async ({ port }) => {
      const framed =
        `POST /c HTTP/1.1${CRLF}Host: t${CRLF}Transfer-Encoding: chunked${CRLF}${CRLF}` +
        `5;foo=bar;baz=qux${CRLF}hello${CRLF}` +
        `6; ext${CRLF} world${CRLF}` +
        `0${CRLF}${CRLF}`;
      const res = parseResponse(await rawRequest(port, framed, { until: responsesComplete(1) }));
      assert.equal(res.status, 200);
      assert.equal(res.body, 'hello world', 'chunk extensions must not leak into the body');
    });
  });

  it('chunked body with a trailer field after the last chunk: trailer consumed, body correct', T, async () => {
    await withServer(echoBody, async ({ port }) => {
      const framed =
        `POST /c HTTP/1.1${CRLF}Host: t${CRLF}Transfer-Encoding: chunked${CRLF}${CRLF}` +
        `5${CRLF}hello${CRLF}` +
        `0${CRLF}` +
        `X-Checksum: abc123${CRLF}` +
        `X-Trailer-Two: value${CRLF}` +
        `${CRLF}`;
      const res = parseResponse(await rawRequest(port, framed, { until: responsesComplete(1) }));
      assert.equal(res.status, 200);
      assert.equal(res.body, 'hello', 'trailer fields must be consumed, not appended to the body');
    });
  });

  it('deep pipelining: 20 requests in one write are all answered, in order', T, async () => {
    await withServer(echoPath, async ({ port }) => {
      const client = await openRaw(port);
      try {
        const N = 20;
        let payload = '';
        for (let i = 0; i < N; i++) payload += get(`/p${i}`);
        await client.send(payload);
        const raw = await client.read({ until: responsesComplete(N), timeout: 10000 });
        const responses = parseResponses(raw);
        assert.equal(responses.length, N, `expected ${N} responses, got ${responses.length}`);
        for (let i = 0; i < N; i++) {
          assert.equal(responses[i].status, 200, `response ${i} status`);
          assert.equal(responses[i].body, `echo:/p${i}`, `response ${i} must be for /p${i} (order preserved)`);
        }
      } finally {
        client.destroy();
      }
    });
  });

  it('slow-drip: request delivered 1 byte per write with ~5ms gaps still parses', T, async () => {
    await withServer(echoPath, async ({ port }) => {
      const reqBytes = `GET /drip?a=1 HTTP/1.1${CRLF}Host: a${CRLF}X-Trace: on${CRLF}${CRLF}`;
      const client = await openRaw(port);
      try {
        for (const byte of reqBytes) {
          await client.send(byte);
          await delay(5);
        }
        const res = parseResponse(await client.read({ until: responsesComplete(1), timeout: 5000 }));
        assert.equal(res.status, 200);
        assert.equal(res.body, 'echo:/drip');
      } finally {
        client.destroy();
      }
    });
  });

  it('body exactly at maxBodySize succeeds; one byte over -> 413 without invoking the handler', T, async () => {
    const LIMIT = 1024;
    await withServer(echoBody, { maxBodySize: LIMIT }, async (server) => {
      // Exactly at the limit: served.
      const exact = 'a'.repeat(LIMIT);
      const okRes = parseResponse(
        await rawRequest(
          server.port,
          `POST /at HTTP/1.1${CRLF}Host: t${CRLF}Content-Length: ${LIMIT}${CRLF}${CRLF}${exact}`,
          { until: responsesComplete(1) }
        )
      );
      assert.equal(okRes.status, 200, 'a body exactly at maxBodySize must be accepted');
      assert.equal(okRes.body.length, LIMIT);
      assert.equal(server.requests.length, 1, 'the at-limit request must reach the handler');

      // One byte over: 413, handler NOT invoked.
      const over = 'b'.repeat(LIMIT + 1);
      const overRes = parseResponse(
        await rawRequest(
          server.port,
          `POST /over HTTP/1.1${CRLF}Host: t${CRLF}Content-Length: ${LIMIT + 1}${CRLF}${CRLF}${over}`,
          { tolerateWriteError: true }
        )
      );
      assert.equal(overRes.status, 413, 'one byte over maxBodySize must be 413');
      assert.equal(server.requests.length, 1, 'the over-limit request must NOT reach the handler');
    });
  });

  it('Content-Length: 0 POST: handler sees empty/no body and responds (no hang)', T, async () => {
    let seen = null;
    await withServer((ctx) => {
      const body = ctx.body();
      seen = { method: ctx.method, isNull: body === null, byteLength: body ? body.byteLength : 0 };
      ctx.respond(200, null, body ?? '');
    }, async ({ port }) => {
      const res = parseResponse(
        await rawRequest(port, `POST /empty HTTP/1.1${CRLF}Host: t${CRLF}Content-Length: 0${CRLF}${CRLF}`, {
          until: responsesComplete(1),
        })
      );
      assert.equal(res.status, 200);
      assert.equal(res.headers['content-length'], '0');
      assert.equal(res.body, '');
      assert.equal(seen.method, 'POST');
      assert.ok(seen.isNull || seen.byteLength === 0, 'CL:0 body must be empty (null or 0 bytes)');
    });
  });

  it('handler-supplied Content-Length is respected; the engine does not double-add it', T, async () => {
    const body = 'custom-length-body'; // 18 bytes
    let raw;
    await withServer((ctx) => {
      ctx.respond(200, ['content-length', String(body.length), 'x-marker', 'set'], body);
    }, async ({ port }) => {
      raw = await rawRequest(port, get('/cl'), { until: responsesComplete(1) });
    });
    assert.equal(
      countResponseHeader(raw, 'content-length'),
      1,
      'exactly one Content-Length header (engine must not add a second)'
    );
    const res = parseResponse(raw);
    assert.equal(res.status, 200);
    assert.equal(res.headers['content-length'], String(body.length));
    assert.equal(res.body, body);
  });

  it('connection reuse after a chunked streamed response: a follow-up POST on the same socket works', T, async () => {
    await withServer((ctx) => {
      if (ctx.path === '/stream') {
        ctx.writeHead(200, null);
        ctx.write('chunk-A');
        ctx.write('chunk-B');
        ctx.end();
        return;
      }
      // Second request carries a body: exercises body parsing after a stream.
      ctx.respond(200, null, `re:${ctx.body() ? Buffer.from(ctx.body()).toString('latin1') : ''}`);
    }, async ({ port }) => {
      const client = await openRaw(port);
      try {
        await client.send(get('/stream'));
        const r1 = parseResponse(await client.read({ until: responsesComplete(1) }));
        assert.equal(r1.status, 200);
        assert.equal((r1.headers['transfer-encoding'] || '').toLowerCase(), 'chunked');
        assert.equal(r1.body, 'chunk-Achunk-B');
        assert.equal(client.closed, false, 'socket must survive the chunked response');

        const payload = 'after-stream';
        await client.send(
          `POST /next HTTP/1.1${CRLF}Host: t${CRLF}Content-Length: ${payload.length}${CRLF}${CRLF}${payload}`
        );
        const r2 = parseResponse(await client.read({ until: responsesComplete(1) }));
        assert.equal(r2.status, 200);
        assert.equal(r2.body, `re:${payload}`, 'a body request after a stream must parse on the reused socket');
      } finally {
        client.destroy();
      }
    });
  });

  it('HTTP/1.0 with explicit Connection: keep-alive keeps the socket open for a second request', T, async () => {
    await withServer(echoPath, async ({ port }) => {
      const client = await openRaw(port);
      try {
        await client.send(`GET /one HTTP/1.0${CRLF}Host: t${CRLF}Connection: keep-alive${CRLF}${CRLF}`);
        const r1 = parseResponse(await client.read({ until: responsesComplete(1) }));
        assert.equal(r1.status, 200);
        assert.equal(r1.body, 'echo:/one');
        assert.equal(client.closed, false, 'HTTP/1.0 keep-alive must hold the connection open');

        await client.send(`GET /two HTTP/1.0${CRLF}Host: t${CRLF}Connection: keep-alive${CRLF}${CRLF}`);
        const r2 = parseResponse(await client.read({ until: responsesComplete(1) }));
        assert.equal(r2.status, 200);
        assert.equal(r2.body, 'echo:/two', 'second request on the kept-alive HTTP/1.0 socket must be answered');
      } finally {
        client.destroy();
      }
    });
  });

  it('bad request line (no HTTP version) -> 400, connection closed, server survives', T, async () => {
    await withServer(echoPath, async (server) => {
      const raw = await rawRequest(server.port, `GET${CRLF}${CRLF}`, {
        expectClose: true,
        tolerateWriteError: true,
        timeout: 5000,
      });
      if (raw.length > 0) {
        const res = parseResponse(raw);
        assert.equal(res.status, 400, 'malformed request line should yield 400');
      }
      assert.equal(server.requests.length, 0, 'a malformed request line must not reach the handler');
      // No crash: a fresh connection still works.
      const again = parseResponse(await rawRequest(server.port, get('/alive'), { until: responsesComplete(1) }));
      assert.equal(again.status, 200);
      assert.equal(again.body, 'echo:/alive');
    });
  });

  it('whitespace before the colon in a header name -> 400 (smuggling / injection defense)', T, async () => {
    await withServer(echoPath, async (server) => {
      const raw = await rawRequest(
        server.port,
        `GET / HTTP/1.1${CRLF}Host: t${CRLF}X-Bad : value${CRLF}${CRLF}`,
        { expectClose: true, tolerateWriteError: true, timeout: 5000 }
      );
      if (raw.length > 0) {
        const res = parseResponse(raw);
        assert.equal(res.status, 400, 'space between field-name and colon must be rejected');
      }
      assert.equal(server.requests.length, 0, 'a syntactically invalid header must not reach the handler');
      // Server still healthy.
      const again = parseResponse(await rawRequest(server.port, get('/alive'), { until: responsesComplete(1) }));
      assert.equal(again.status, 200);
    });
  });
});
