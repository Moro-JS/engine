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
  exchange,
  expectRejected,
  bodyText,
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

  it('no headers at all (request line + blank line only): HTTP/1.1 without Host is 400 (RFC 9112 §3.2)', T, async () => {
    await withServer(echoPath, async ({ port, requests }) => {
      const res = parseResponse(
        await rawRequest(port, `GET /bare HTTP/1.1${CRLF}${CRLF}`, { expectClose: true })
      );
      assert.equal(res.status, 400);
      assert.equal(requests.length, 0, 'the handler must never see a Host-less HTTP/1.1 request');
    });
  });

  it('HTTP/1.0 request line + blank line only: served — Host predates HTTP/1.1', T, async () => {
    await withServer(echoPath, async ({ port }) => {
      const res = parseResponse(
        await rawRequest(port, `GET /bare HTTP/1.0${CRLF}${CRLF}`, { expectClose: true })
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

// ---------------------------------------------------------------------------
// Request syntax and framing in detail (RFC 9110 / RFC 9112). One request per
// connection through exchange(); a rejected request is one error response
// with Connection: close, the socket closed, and the handler not run.
// ---------------------------------------------------------------------------

const H = 'Host: t\r\n';
const post = (extra, body = '', path = '/p') => `POST ${path} HTTP/1.1\r\n${H}${extra}\r\n${body}`;
const chunked = (body, path = '/c') => post('Transfer-Encoding: chunked\r\n', body, path);
const echo = (ctx) => ctx.respond(200, null, `${ctx.method}|${ctx.path}|${bodyText(ctx)}`);

describe('request framing: Content-Length and Transfer-Encoding', { skip }, () => {
  it('Content-Length forms that are not 1*DIGIT are rejected 400', T, async () => {
    await withServer(echo, async (server) => {
      for (const v of ['+3', '-3', '3 3', '0x3', '3.0', '3e0', '3, 3', '', '3;q=1', '\xb3']) {
        await expectRejected(server, post(`Content-Length: ${v}\r\n`, 'abc'), 400, `Content-Length: ${JSON.stringify(v)}`);
      }
    });
  });

  it('OWS around a Content-Length value and leading zeros are accepted (RFC 9110 §5.5, §8.6)', T, async () => {
    await withServer(echo, async (server) => {
      for (const v of ['  3  ', '\t3\t', '003']) {
        const r = await exchange(server, post(`Content-Length:${v}\r\n`, 'abc'));
        assert.deepEqual(r.statuses, [200], JSON.stringify(v));
        assert.equal(r.responses[0].body, 'POST|/p|abc');
      }
    });
  });

  it('a Content-Length past 2^64 is 400, never wrapped to a small number; the largest that fits is 413', T, async () => {
    await withServer(echo, async (server) => {
      // 2^64 + 3 would be 3 after a wrap. No 64-bit length holds it: it is malformed, not too large.
      await expectRejected(server, post('Content-Length: 18446744073709551619\r\n', 'abc'), 400, '2^64+3');
      await expectRejected(server, post('Content-Length: 99999999999999999999\r\n', ''), 400, '20 nines');
      await expectRejected(server, post('Content-Length: 18446744073709551615\r\n', 'abc'), 413, '2^64-1');
    });
  });

  it('two equal Content-Length lines are one length; the body is read once', T, async () => {
    await withServer(echo, async (server) => {
      const r = await exchange(server, post('Content-Length: 3\r\nContent-Length: 3\r\n', 'abc') + get('/next'));
      assert.deepEqual(r.statuses, [200, 200]);
      assert.equal(r.responses[0].body, 'POST|/p|abc');
      assert.equal(r.responses[1].body, 'GET|/next|');
    });
  });

  it('Transfer-Encoding is accepted only as exactly "chunked", in any case, with OWS', T, async () => {
    await withServer(echo, async (server) => {
      for (const v of ['chunked', 'CHUNKED', 'ChUnKeD', ' chunked ', '\tchunked']) {
        const r = await exchange(server, post(`Transfer-Encoding:${v}\r\n`, '3\r\nabc\r\n0\r\n\r\n'));
        assert.deepEqual(r.statuses, [200], JSON.stringify(v));
        assert.equal(r.responses[0].body, 'POST|/p|abc');
      }
      for (const v of [
        'gzip, chunked', 'chunked, gzip', 'identity', 'chunked, chunked', ',chunked', 'chunked,',
        'chunked;q=1', 'xchunked', 'chunkedx', 'chunked\tx', '', 'gzip',
      ]) {
        await expectRejected(server, post(`Transfer-Encoding: ${v}\r\n`, '3\r\nabc\r\n0\r\n\r\n'), 400, `TE ${JSON.stringify(v)}`);
      }
    });
  });

  it('Transfer-Encoding before or after Content-Length, in any letter case: 400', T, async () => {
    await withServer(echo, async (server) => {
      await expectRejected(server, post('transfer-encoding: chunked\r\nCONTENT-LENGTH: 3\r\n', 'abc'), 400, 'TE then CL');
      await expectRejected(server, post('content-length: 3\r\nTRANSFER-ENCODING: CHUNKED\r\n', 'abc'), 400, 'CL then TE');
    });
  });

  it('a field name that only resembles a framing header frames nothing', T, async () => {
    await withServer(echo, async (server) => {
      // Content_Length is some other field: the request has no body, and the
      // three bytes after the head are a malformed request line.
      const r = await exchange(server, post('Content_Length: 3\r\n', 'abc\r\n'));
      assert.deepEqual(r.statuses, [200, 400]);
      assert.equal(r.responses[0].body, 'POST|/p|');
      assert.equal(r.closed, true);
      assert.equal(r.handled, 1);
    });
  });
});

describe('line endings and field syntax', { skip }, () => {
  it('a bare LF ends the request line and field lines (RFC 9112 §2.2 MAY)', T, async () => {
    await withServer(echo, async (server) => {
      const r = await exchange(server, 'GET /lf HTTP/1.1\nHost: t\nX-A: b\n\n');
      assert.deepEqual(r.statuses, [200]);
      assert.equal(r.responses[0].body, 'GET|/lf|');
    });
  });

  it('a bare CR is never a line terminator: nothing is parsed until a LF arrives', T, async () => {
    await withServer(echo, async (server) => {
      const c = await openRaw(server.port);
      try {
        await c.send('GET /cr HTTP/1.1\rHost: t\r\r');
        await delay(200);
        assert.equal(server.requests.length, 0);
        assert.equal(c.closed, false);
        // the LF completes ONE line that contains bare CRs: rejected
        await c.send('\n\r\n');
        const res = parseResponse(await c.read({ expectClose: true }));
        assert.equal(res.status, 400);
        assert.equal(server.requests.length, 0);
      } finally {
        c.destroy();
      }
    });
  });

  it('a CR that is not followed by LF is rejected wherever it appears', T, async () => {
    await withServer(echo, async (server) => {
      await expectRejected(server, get('/', 'X-A: a\rb\r\n'), 400, 'inside a value');
      await expectRejected(server, get('/', 'X-A: ab\r\r\n'), 400, 'before the CRLF of a value');
      await expectRejected(server, `GET /a\rb HTTP/1.1\r\n${H}\r\n`, 400, 'in the target');
      await expectRejected(server, `GET / HTTP/1.1\r\r\n${H}\r\n`, 400, 'after the version');
      await expectRejected(server, get('/', 'X-\rA: b\r\n'), 400, 'in a field name');
    });
  });

  it('empty lines before the request line are skipped, CRLF or LF, also between pipelined requests', T, async () => {
    await withServer(echo, async (server) => {
      const r = await exchange(server, '\r\n\r\n\n' + get('/one') + '\r\n\r\n' + get('/two'));
      assert.deepEqual(r.statuses, [200, 200]);
      assert.equal(r.responses[1].body, 'GET|/two|');
    });
  });

  it('a flood of empty lines is bounded by maxHeadSize (431)', T, async () => {
    await withServer(echo, { maxHeadSize: 4096 }, async (server) => {
      const r = await exchange(server, '\r\n'.repeat(4096));
      assert.deepEqual(r.statuses, [431]);
      assert.equal(r.closed, true);
    });
  });

  it('whitespace before the request line, and TAB or doubled SP inside it: 400', T, async () => {
    await withServer(echo, async (server) => {
      await expectRejected(server, ' ' + get('/'), 400, 'leading SP');
      await expectRejected(server, `GET\t/\tHTTP/1.1\r\n${H}\r\n`, 400, 'TAB separators');
      await expectRejected(server, `GET  / HTTP/1.1\r\n${H}\r\n`, 400, 'two SP after the method');
      await expectRejected(server, `GET /  HTTP/1.1\r\n${H}\r\n`, 400, 'two SP before the version');
      await expectRejected(server, `GET / HTTP/1.1 \r\n${H}\r\n`, 400, 'SP after the version');
      await expectRejected(server, `GET /a b HTTP/1.1\r\n${H}\r\n`, 400, 'SP inside the target');
    });
  });

  it('a line-folded field (obs-fold) is rejected 400, SP or HTAB, first field or later', T, async () => {
    await withServer(echo, async (server) => {
      await expectRejected(server, get('/', 'X-A: a\r\n b\r\n'), 400, 'SP continuation');
      await expectRejected(server, get('/', 'X-A: a\r\n\tb\r\n'), 400, 'HTAB continuation');
      await expectRejected(server, `GET / HTTP/1.1\r\n Host: t\r\n\r\n`, 400, 'first field line');
    });
  });

  it('field names must be tokens: no colon, empty name, separators, NUL, high bytes -> 400', T, async () => {
    await withServer(echo, async (server) => {
      const bad = ['NoColonHere', ': v', 'X A: v', 'X(A: v', 'X"A: v', 'X@A: v', 'X/A: v', 'X\x00A: v', 'X\x80A: v', 'X\tA: v', 'X,A: v', 'X;A: v', 'X=A: v', 'X[A]: v', 'X{A}: v', 'X\\A: v', 'X?A: v', 'X<A>: v'];
      for (const line of bad) {
        await expectRejected(server, get('/', line + '\r\n'), 400, JSON.stringify(line));
      }
    });
  });

  it('every tchar is accepted in a field name and the name arrives lowercased', T, async () => {
    let flat;
    await withServer((ctx) => { flat = ctx.headers(); ctx.respond(200, null, 'ok'); }, async (server) => {
      const name = "X-!#$%&'*+-.^_`|~09azAZ";
      const r = await exchange(server, get('/', `${name}: v\r\n`));
      assert.deepEqual(r.statuses, [200]);
      assert.ok(flat.includes(name.toLowerCase()));
    });
  });

  it('C0 controls and DEL in a field value are 400; bytes above 0x7f are delivered', T, async () => {
    let flat;
    await withServer((ctx) => { flat = ctx.headers(); ctx.respond(200, null, 'ok'); }, async (server) => {
      for (const ch of ['\x00', '\x01', '\x08', '\x0b', '\x0c', '\x1b', '\x1f', '\x7f']) {
        await expectRejected(server, get('/', `X-A: a${ch}b\r\n`), 400, `0x${ch.charCodeAt(0).toString(16)}`);
      }
      const r = await exchange(server, get('/', 'X-A: a\x80\xffb\r\n'));
      assert.deepEqual(r.statuses, [200]);
      assert.ok(flat.includes('x-a'));
    });
  });
});

describe('request line and Host', { skip }, () => {
  it('unknown methods are handed over verbatim; a method that is not a token is 400', T, async () => {
    const seen = [];
    await withServer((ctx) => { seen.push(engine.getMethod(ctx.reqId)); ctx.respond(200, null, 'ok'); }, async (server) => {
      for (const m of ['CONNECT', 'TRACE', 'M-SEARCH', "!#$%&'*+-.^_`|~", 'A'.repeat(64)]) {
        const r = await exchange(server, `${m} /m HTTP/1.1\r\n${H}\r\n`);
        assert.deepEqual(r.statuses, [200], m.slice(0, 20));
      }
      assert.deepEqual(seen.slice(0, 3), ['CONNECT', 'TRACE', 'M-SEARCH']);
      for (const m of ['G=T', 'G@T', 'G\x00T', 'G(T', 'G\xc9T', '']) {
        await expectRejected(server, `${m} /m HTTP/1.1\r\n${H}\r\n`, 400, JSON.stringify(m));
      }
    });
  });

  // RFC 9112 §3: a method longer than any the server implements is 501. The
  // bound is 64 bytes, and the answer does not wait for the line to end, or
  // turn into the head-size 431 when the method alone is past maxHeadSize.
  it('a method token of more than 64 bytes is 501, as soon as it is that long', T, async () => {
    let calls = 0;
    await withServer((ctx) => { calls++; ctx.respond(200, null, 'ok'); }, async (server) => {
      for (const len of [65, 300, 100000]) {
        await expectRejected(server, `${'A'.repeat(len)} /m HTTP/1.1\r\n${H}\r\n`, 501, `${len} bytes`);
      }
      await expectRejected(server, null, 501, 'never finished', { parts: ['B'.repeat(40), 'B'.repeat(40)] });
      assert.equal(calls, 0);
    });
  });

  // A cleartext listener that speaks HTTP/2 as well: first bytes that are
  // neither the HTTP/2 preface nor an HTTP/1 request line are answered in
  // neither protocol. An HTTP/1 error would reach an HTTP/2 client as a
  // malformed frame (h2spec 3.5/2 reads it as an unexpected EOF).
  it('with http2 on, a first line with no HTTP-version in it ends the connection without a reply', T, async () => {
    await withServer(echo, { http2: true }, async (server) => {
      for (const first of ['INVALID CONNECTION PREFACE\r\n\r\n', 'GARBAGE\r\n\r\n', 'GET /\r\n\r\n']) {
        const r = await exchange(server, first, { wait: 200 });
        assert.deepEqual(r.statuses, [], JSON.stringify(first));
        assert.equal(r.closed, true, JSON.stringify(first));
      }
      // A request line that is HTTP/1 and wrong is still told so ...
      await expectRejected(server, 'GET /x HTTP/1.9x\r\nHost: h\r\n\r\n', 400, 'bad minor version');
      await expectRejected(server, 'GET /x HTTP/3.0\r\nHost: h\r\n\r\n', 505, 'HTTP/3.0');
      // ... and so is a line that is not, once the connection has spoken HTTP/1.
      const r = await exchange(server, `GET /a HTTP/1.1\r\n${H}\r\nGARBAGE\r\n\r\n`);
      assert.deepEqual(r.statuses, [200, 400]);
    });
    // Without http2 the same bytes get the HTTP/1 answer they always did.
    await withServer(echo, async (server) => {
      await expectRejected(server, 'INVALID CONNECTION PREFACE\r\n\r\n', 400, 'no http2');
    });
  });

  // RFC 9112 §3.2.4: asterisk-form is for a server-wide OPTIONS only.
  it('"*" is a request-target for OPTIONS and for no other method', T, async () => {
    const seen = [];
    await withServer((ctx) => { seen.push(`${engine.getMethod(ctx.reqId)} ${ctx.path}`); ctx.respond(204, null, ''); }, async (server) => {
      const r = await exchange(server, `OPTIONS * HTTP/1.1\r\n${H}\r\n`);
      assert.deepEqual(r.statuses, [204]);
      assert.deepEqual(seen, ['OPTIONS *']);
      for (const m of ['GET', 'HEAD', 'POST', 'DELETE', 'TRACE']) {
        await expectRejected(server, `${m} * HTTP/1.1\r\n${H}\r\n`, 400, m);
      }
      assert.equal(seen.length, 1);
    });
  });

  it('HTTP-version: any 1.x digit is served as HTTP/1.1; other majors are 505; malformed is 400', T, async () => {
    await withServer(echo, async (server) => {
      for (const v of ['HTTP/1.2', 'HTTP/1.9']) {
        const r = await exchange(server, `GET /v ${v}\r\n${H}\r\n`);
        assert.deepEqual(r.statuses, [200], v);
        assert.equal(r.closed, false, `${v} is treated as HTTP/1.1 (persistent)`);
        assert.match(r.raw, /^HTTP\/1\.1 200 /);
      }
      for (const v of ['HTTP/0.9', 'HTTP/2.0', 'HTTP/3.0', 'HTTP/9.9']) {
        await expectRejected(server, `GET /v ${v}\r\n${H}\r\n`, 505, v);
      }
      for (const v of ['HTTP/2', 'http/1.1', 'HTTP/1.10', 'HTTP/01.1', 'HTTPS/1.1', 'HTTP/1,1', 'HTTP/1.', 'HTTP/.1', 'HTTP/1.1x', 'FTP/1.1']) {
        await expectRejected(server, `GET /v ${v}\r\n${H}\r\n`, 400, v);
      }
    });
  });

  it('an HTTP/0.9 simple request ("GET /path") is 400', T, async () => {
    await withServer(echo, async (server) => {
      await expectRejected(server, 'GET /v\r\n', 400, 'simple request');
    });
  });

  it('the cleartext HTTP/2 preface on a server without http2 is 505 and closed', T, async () => {
    await withServer(echo, async (server) => {
      await expectRejected(server, 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n', 505, 'preface');
    });
  });

  it('Host: required once on HTTP/1.1 (even with an absolute-form target), and it names a host', T, async () => {
    await withServer(echo, async (server) => {
      await expectRejected(server, 'GET http://example.test/a HTTP/1.1\r\n\r\n', 400, 'absolute-form without Host');
      await expectRejected(server, 'GET /h HTTP/1.0\r\nHost: a\r\nHost: b\r\n\r\n', 400, 'two Host lines on HTTP/1.0');
      await expectRejected(server, 'GET /h HTTP/1.1\r\nHost: t\r\nhOsT: t\r\n\r\n', 400, 'two equal Host lines');
      // An empty value, or a port with no host before it, names none (RFC 9112 §3.2).
      await expectRejected(server, 'GET /h HTTP/1.1\r\nHost:\r\n\r\n', 400, 'empty Host');
      await expectRejected(server, 'GET /h HTTP/1.1\r\nHost: \r\n\r\n', 400, 'Host of one space');
      await expectRejected(server, 'GET /h HTTP/1.1\r\nHost: :8080\r\n\r\n', 400, 'a port alone');
      await expectRejected(server, 'GET /h HTTP/1.0\r\nHost:\r\n\r\n', 400, 'empty Host on HTTP/1.0');
    });
  });

  // RFC 9112 §3.2: a request whose Host field value is invalid is answered
  // 400. Host = uri-host [ ":" port ] (RFC 9110 §7.2).
  it('a Host value that is not uri-host[:port] is rejected 400', T, async () => {
    await withServer(echo, async (server) => {
      const bad = [
        'a b', 'a/b', 'a, b', 'u@a', 'a:99x', 'a?x', 'a#x', 'a\\b', 'evil.test/.good.test', 'a:1:2',
        'a\tb', '::1', '[::1', '::1]', '[]', '[::1]x', '[::1]:8x', '[a/b]', 'a"b', 'a<b>', 'b\xfccher.example',
      ];
      for (const host of bad) {
        await expectRejected(server, `GET /h HTTP/1.1\r\nHost: ${host}\r\n\r\n`, 400, `Host: ${JSON.stringify(host)}`);
      }
      // the same check on an HTTP/1.0 request that sends one, and on a request the engine parses in pieces
      await expectRejected(server, 'GET /h HTTP/1.0\r\nHost: a b\r\n\r\n', 400, 'HTTP/1.0');
      await expectRejected(server, null, 400, 'split', { parts: ['GET /h HTTP/1.1\r\nHo', 'st: a/b\r\n\r\n'] });
    });
  });

  it('well-formed Host values are served: names with _ and -, ports, IPv4, bracketed IPv6, a trailing dot', T, async () => {
    let seen;
    await withServer((ctx) => { seen = ctx.header('host'); ctx.respond(200, null, 'ok'); }, async (server) => {
      const good = [
        'example.test', 'my_service:3000', 'a-b.c', '127.0.0.1:8080', '[::1]', '[2001:db8::1]:443', '[fe80::1%25en0]:80',
        '[v1.fe80::a+en1]', 'example.test.', 'xn--bcher-kva.example', 'EXAMPLE.test', 'localhost:', 'localhost:65535',
        'a~b!$&\'()*+;=c', 'caf%C3%A9.test',
      ];
      for (const host of good) {
        const r = await exchange(server, `GET /h HTTP/1.1\r\nHost: ${host}\r\n\r\n`, { wait: 60 });
        assert.deepEqual(r.statuses, [200], `Host: ${JSON.stringify(host)}`);
        assert.equal(seen, host, 'the value reaches the handler unchanged');
      }
    });
  });

  it('a target up to maxHeadSize is served; past it the answer is 431 (414 with maxUriSize)', T, async () => {
    await withServer(echo, async (server) => {
      const ok = await exchange(server, `GET /${'a'.repeat(60000)} HTTP/1.1\r\n${H}\r\n`, { wait: 400 });
      assert.deepEqual(ok.statuses, [200]);
      await expectRejected(server, `GET /${'a'.repeat(70000)} HTTP/1.1\r\n${H}\r\n`, 431, '70 KB target');
    });
    await withServer(echo, { maxUriSize: 100 }, async (server) => {
      await expectRejected(server, `GET /${'a'.repeat(200)} HTTP/1.1\r\n${H}\r\n`, 414, 'over maxUriSize');
    });
  });

  it('a target that never ends (no LF) is cut at maxHeadSize with 431', T, async () => {
    await withServer(echo, { maxHeadSize: 2048 }, async (server) => {
      const c = await openRaw(server.port);
      try {
        await c.send('GET /' + 'a'.repeat(1500));
        await delay(50);
        await c.send('a'.repeat(1500)).catch(() => {});
        const res = parseResponse(await c.read({ expectClose: true }));
        assert.equal(res.status, 431);
      } finally {
        c.destroy();
      }
    });
  });
});

describe('chunked request bodies', { skip }, () => {
  it('chunk sizes: hex in either case, leading zeros; sign, 0x prefix, inner space and non-hex are 400', T, async () => {
    await withServer(echo, async (server) => {
      for (const size of ['3', '03', '0003', '0'.repeat(200) + '3']) {
        const r = await exchange(server, chunked(`${size}\r\nabc\r\n0\r\n\r\n`));
        assert.deepEqual(r.statuses, [200], size.slice(-6));
        assert.equal(r.responses[0].body, 'POST|/c|abc');
      }
      const r = await exchange(server, chunked('a\r\n0123456789\r\nA\r\n0123456789\r\n0\r\n\r\n'));
      assert.equal(r.responses[0].body, 'POST|/c|01234567890123456789');
      for (const size of ['0x3', '+3', '-3', '3 3', '', 'g', '3h', '３']) {
        await expectRejected(server, chunked(`${size}\r\nabc\r\n0\r\n\r\n`), 400, JSON.stringify(size));
      }
    });
  });

  it('a chunk size that overflows 64 bits is 400, never wrapped; the largest that fits is 413', T, async () => {
    await withServer(echo, async (server) => {
      await expectRejected(server, chunked('ffffffffffffffff\r\nabc\r\n0\r\n\r\n'), 413, '2^64-1');
      // 0x1_0000_0000_0000_0003 is 3 after a 64-bit wrap. No 64-bit size holds it: malformed, not too large.
      for (const size of ['10000000000000000', '10000000000000003', 'FFFFFFFFFFFFFFFF0', 'f'.repeat(40) + '3']) {
        await expectRejected(server, chunked(`${size}\r\nabc\r\n0\r\n\r\n`), 400, size);
      }
    });
  });

  it('the sum of chunk sizes is held to maxBodySize (413), whatever the size of each chunk', T, async () => {
    await withServer(echo, { maxBodySize: 10 }, async (server) => {
      const ok = await exchange(server, chunked('5\r\nabcde\r\n5\r\nfghij\r\n0\r\n\r\n'));
      assert.deepEqual(ok.statuses, [200]);
      await expectRejected(server, chunked('5\r\nabcde\r\n5\r\nfghij\r\n1\r\nk\r\n0\r\n\r\n'), 413, '11 bytes in three chunks');
      await expectRejected(server, chunked('b\r\n'), 413, 'one 11-byte chunk, declared');
    });
  });

  it('chunk data must be followed by CRLF exactly: LF alone, CR alone or more data is 400', T, async () => {
    await withServer(echo, async (server) => {
      await expectRejected(server, chunked('3\r\nabc\n0\r\n\r\n'), 400, 'LF only');
      await expectRejected(server, chunked('3\r\nabc\r0\r\n\r\n'), 400, 'CR only');
      await expectRejected(server, chunked('3\r\nabcXX0\r\n\r\n'), 400, 'no terminator');
      await expectRejected(server, chunked('3\r\nabcd\r\n0\r\n\r\n'), 400, 'one byte too many');
    });
  });

  // chunk = chunk-size [ chunk-ext ] CRLF chunk-data CRLF (RFC 9112 §7.1).
  // The bare LF a server may take for a line end (§2.2) is an allowance for
  // the start line and the field lines; taken inside chunk framing too, the
  // server and an intermediary that does not take it disagree about where
  // the body ends.
  it('a chunk-size line ended by a bare LF is rejected', T, async () => {
    await withServer(echo, async (server) => {
      await expectRejected(server, chunked('3\nabc\r\n0\r\n\r\n'), 400, 'data chunk');
      await expectRejected(server, chunked('3;x=y\nabc\r\n0\r\n\r\n'), 400, 'after an extension');
      await expectRejected(server, null, 400, 'in two writes', { parts: [chunked('3'), '\nabc\r\n0\r\n\r\n'] });
    });
  });

  it('a bare LF inside a chunk extension does not end the chunk-size line', T, async () => {
    await withServer(echo, async (server) => {
      // Read with LF as a line end this is: chunk "xx", the last chunk, and a second request.
      const r = await exchange(server, chunked('2;\nxx\r\n0\r\n\r\n' + get('/second')));
      assert.deepEqual(r.statuses, [400]);
      assert.equal(server.requests.length, 0, 'neither the chunked request nor what followed it reached the handler');
    });
  });

  it('the last chunk and the lines of the trailer section need CRLF too', T, async () => {
    await withServer(echo, async (server) => {
      await expectRejected(server, chunked('3\r\nabc\r\n0\n\n'), 400, 'last chunk and blank line');
      await expectRejected(server, chunked('3\r\nabc\r\n0\n\r\n'), 400, 'last chunk');
      await expectRejected(server, chunked('3\r\nabc\r\n0\r\n\n'), 400, 'blank line');
      await expectRejected(server, chunked('3\r\nabc\r\n0\r\nX-T: v\n\r\n'), 400, 'trailer line');
    });
  });

  it('whitespace around a chunk size is rejected (chunk-size = 1*HEXDIG), except as BWS before a ";"', T, async () => {
    await withServer(echo, async (server) => {
      for (const size of [' 3', '\t3', ' ', ' ;x', '3 ', '3\t', '3 \t ', '3;x ']) {
        await expectRejected(server, chunked(`${size}\r\nabc\r\n0\r\n\r\n`), 400, JSON.stringify(size));
      }
      for (const size of ['3 ;x', '3\t;\tx', '3 ; x = "y z"']) {
        const r = await exchange(server, chunked(`${size}\r\nabc\r\n0\r\n\r\n`));
        assert.deepEqual(r.statuses, [200], JSON.stringify(size));
        assert.equal(r.responses[0].body, 'POST|/c|abc');
      }
    });
  });

  // RFC 9112 §7.1.1: chunk-ext = *( BWS ";" BWS chunk-ext-name [ BWS "=" BWS chunk-ext-val ] ),
  // a name a token, a value a token or a quoted-string.
  it('chunk extensions are not interpreted, but are held to their grammar', T, async () => {
    await withServer(echo, async (server) => {
      const r = await exchange(server, chunked('3;a=b;c="d e\tf\xfc";g;h="i\\"j"\r\nabc\r\n0;last=1\r\n\r\n'));
      assert.deepEqual(r.statuses, [200]);
      assert.equal(r.responses[0].body, 'POST|/c|abc');
      for (const ch of ['\x00', '\x01', '\r', '\x1b', '\x7f']) {
        await expectRejected(server, chunked(`3;a=b${ch}c\r\nabc\r\n0\r\n\r\n`), 400, `0x${ch.charCodeAt(0).toString(16)}`);
        await expectRejected(server, chunked(`3;a="b${ch}c"\r\nabc\r\n0\r\n\r\n`), 400, `quoted 0x${ch.charCodeAt(0).toString(16)}`);
      }
      const bad = [
        '3;', '3; ', '3;a;', '3;;a',          // a ";" with no name behind it
        '3;bad[=x', '3;a b', '3;\xfc',        // a name that is not a token
        '3;=x', '3;a=', '3;a= ',              // "=" with a side missing
        '3;a=b c', '3;a=b[',                  // a value that is neither a token nor quoted
        '3;a="b', '3;a="b"c', '3;a="b\\',     // a quoted value that does not end where it should
      ];
      for (const line of bad) {
        await expectRejected(server, chunked(`${line}\r\nabc\r\n0\r\n\r\n`), 400, JSON.stringify(line));
      }
    });
  });

  // What a request is answered with must not depend on how TCP happened to
  // split it. The chunk-size line is bounded at 16 KiB up to its LF.
  it('a long chunk-size line gets the same answer in one write and in several', T, async () => {
    await withServer(echo, async (server) => {
      for (const [extLen, status] of [[2000, 200], [16000, 200], [16384 - 3, 200], [16384 - 2, 400], [40000, 400]]) {
        const head = chunked('3;' + 'e'.repeat(extLen)); // the line up to its LF is extLen + 3 bytes
        const rest = '\r\nabc\r\n0\r\n\r\n';
        const whole = await exchange(server, head + rest, { wait: 300 });
        const split = await exchange(server, null, { wait: 300, parts: [head.slice(0, 1500), head.slice(1500), rest] });
        assert.deepEqual(whole.statuses, [status], `one write, ${extLen}-byte extension`);
        assert.deepEqual(split.statuses, [status], `three writes, ${extLen}-byte extension`);
      }
    });
  });

  it('a chunked body is not complete until the line that ends the trailer section arrives', T, async () => {
    await withServer(echo, async (server) => {
      const c = await openRaw(server.port);
      try {
        await c.send(chunked('3\r\nabc\r\n0\r\n'));
        await delay(200);
        assert.equal(server.requests.length, 0, 'last-chunk alone does not complete the request');
        await c.send('\r\n');
        const res = parseResponse(await c.read());
        assert.equal(res.status, 200);
        assert.equal(res.body, 'POST|/c|abc');
      } finally {
        c.destroy();
      }
    });
  });

  it('trailer fields are consumed and dropped: they never appear among the headers or replace one', T, async () => {
    let flat;
    await withServer((ctx) => { if (ctx.method === 'POST') flat = ctx.headers(); ctx.respond(200, null, bodyText(ctx)); }, async (server) => {
      const r = await exchange(
        server,
        post('Transfer-Encoding: chunked\r\nX-Role: user\r\nTrailer: X-Role\r\n',
          '3\r\nabc\r\n0\r\nX-Role: admin\r\nHost: evil\r\nContent-Length: 99\r\nTransfer-Encoding: gzip\r\nAuthorization: Basic x\r\nX-Trailer-Only: 1\r\n\r\n') + get('/next')
      );
      assert.deepEqual(r.statuses, [200, 200], 'the trailer section does not disturb framing');
      assert.equal(r.responses[0].body, 'abc');
      const names = flat.filter((_, i) => i % 2 === 0);
      assert.deepEqual(names, ['host', 'transfer-encoding', 'x-role', 'trailer']);
      assert.equal(flat[flat.indexOf('x-role') + 1], 'user');
      assert.equal(flat[flat.indexOf('host') + 1], 't');
    });
  });

  // trailer-section = *( field-line CRLF ): a line that is not a field line
  // is a framing error there as it is among the header fields.
  it('a trailer line that is not a field line is rejected, not skipped', T, async () => {
    await withServer(echo, async (server) => {
      for (const line of ['garbage \x00\x01 line', 'GET /next HTTP/1.1', 'X-T : v', ' folded', ': v', 'X-T: a\x01b', 'X-T: a\rb']) {
        await expectRejected(server, chunked(`3\r\nabc\r\n0\r\n${line}\r\n\r\n`), 400, JSON.stringify(line));
      }
      const r = await exchange(server, chunked('3\r\nabc\r\n0\r\nX-T: v\r\nX-Empty:\r\nx-u: \xfc\tz \r\n\r\n') + get('/next'));
      assert.deepEqual(r.statuses, [200, 200], 'well-formed trailer lines are accepted as before');
    });
  });

  // The trailer section is limited to maxHeadSize; what follows the chunked
  // request in the same read - the next pipelined request - is not part of it.
  it('a chunked request is not rejected for the size of the request pipelined behind it', T, async () => {
    await withServer((ctx) => (ctx.path === '/slow' ? void setTimeout(() => ctx.respond(200, null, 'slow'), 150) : echo(ctx)), async (server) => {
      const r = await exchange(server, null, {
        wait: 600,
        parts: [get('/slow'), chunked('5\r\nhello\r\n0\r\n\r\n') + post('Content-Length: 100000\r\n', 'x'.repeat(100000), '/b')],
      });
      assert.deepEqual(r.statuses, [200, 200, 200]);
      assert.equal(r.responses[1].body, 'POST|/c|hello');
      assert.equal(r.responses[2].body.length, 'POST|/b|'.length + 100000);
    });
  });

  it('a chunked body that stops early leaves the request incomplete: no handler, 408 at the deadline', T, async () => {
    await withServer(echo, { requestTimeoutMs: 500 }, async (server) => {
      const c = await openRaw(server.port);
      try {
        await c.send(chunked('5\r\nab'));
        const res = parseResponse(await c.read({ expectClose: true, timeout: 4000 }));
        assert.equal(res.status, 408);
        assert.equal(server.requests.length, 0);
      } finally {
        c.destroy();
      }
    });
  });
});

describe('HTTP/1.0 clients', { skip }, () => {
  // RFC 9112 §6.1: a response carries Transfer-Encoding only when the request
  // was HTTP/1.1. An HTTP/1.0 client reads to the end of the connection and
  // would take chunk-size lines for content.
  it('a streamed response without a length is sent unframed and ended by the close', T, async () => {
    await withServer((ctx) => {
      if (ctx.path === '/implicit') { ctx.write('part1'); ctx.end('part2'); return; }
      ctx.writeHead(200, ['content-type', 'text/plain']);
      ctx.write('part1');
      ctx.end('part2');
    }, async (server) => {
      for (const req of ['GET /s HTTP/1.0\r\n\r\n', 'GET /s HTTP/1.0\r\nConnection: keep-alive\r\n\r\n', 'GET /implicit HTTP/1.0\r\nConnection: keep-alive\r\n\r\n']) {
        const c = await openRaw(server.port);
        try {
          await c.send(req);
          const raw = await c.read({ expectClose: true, timeout: 3000 });
          const headEnd = raw.indexOf('\r\n\r\n');
          const head = raw.slice(0, headEnd);
          assert.doesNotMatch(head, /transfer-encoding/i, req);
          assert.doesNotMatch(head, /content-length/i, req);
          assert.match(head, /\r\nConnection: close/, req);
          assert.equal(raw.slice(headEnd + 4), 'part1part2', req);
        } finally {
          c.destroy();
        }
      }
    });
  });

  it('a streamed response with a declared length keeps an HTTP/1.0 keep-alive connection open', T, async () => {
    await withServer((ctx) => { ctx.writeHead(200, ['content-length', '10']); ctx.write('part1'); ctx.end('part2'); }, async (server) => {
      const r = await exchange(server, 'GET /a HTTP/1.0\r\nConnection: keep-alive\r\n\r\nGET /b HTTP/1.0\r\nConnection: keep-alive\r\n\r\n');
      assert.deepEqual(r.statuses, [200, 200]);
      assert.equal(r.responses[0].headers.connection, 'keep-alive');
      assert.equal(r.responses[1].body, 'part1part2');
      assert.equal(r.closed, false);
    });
  });

  it('a HEAD response to a streaming handler carries no Transfer-Encoding and leaves keep-alive alone', T, async () => {
    await withServer((ctx) => { ctx.writeHead(200, ['x-a', 'b']); ctx.write('part1'); ctx.end('part2'); }, async (server) => {
      const c = await openRaw(server.port);
      try {
        await c.send('HEAD /s HTTP/1.0\r\nConnection: keep-alive\r\n\r\n');
        const raw = await c.read({ quiescence: 200 });
        assert.match(raw, /^HTTP\/1\.1 200 OK\r\n/);
        assert.doesNotMatch(raw, /transfer-encoding/i);
        assert.match(raw, /\r\nConnection: keep-alive\r\n\r\n$/, 'head only, no body bytes');
        assert.equal(c.closed, false);
      } finally {
        c.destroy();
      }
    });
  });

  it('an HTTP/1.1 client still gets chunked framing for the same handler', T, async () => {
    await withServer((ctx) => { ctx.writeHead(200, null); ctx.write('part1'); ctx.end('part2'); }, async (server) => {
      const r = await exchange(server, get('/s') + get('/s'));
      assert.deepEqual(r.statuses, [200, 200]);
      assert.equal(r.responses[0].headers['transfer-encoding'], 'chunked');
      assert.equal(r.responses[1].body, 'part1part2');
      assert.equal(r.closed, false);
    });
  });

  // RFC 9112 §6.1: an HTTP/1.0 message with Transfer-Encoding has unreliable
  // framing; the connection is closed after it has been processed.
  it('a request with Transfer-Encoding closes the connection after its response', T, async () => {
    await withServer(echo, async (server) => {
      const r = await exchange(server, 'POST /p HTTP/1.0\r\nConnection: keep-alive\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\nGET /second HTTP/1.0\r\n\r\n');
      assert.deepEqual(r.statuses, [200]);
      assert.equal(r.responses[0].body, 'POST|/p|abc');
      assert.equal(r.responses[0].headers.connection, 'close');
      assert.deepEqual(server.requests.map((q) => q.path), ['/p'], 'nothing behind it is served');
      assert.equal(r.closed, true);
    });
  });

  // RFC 9110 §10.1.1: a 100-continue expectation in an HTTP/1.0 request is
  // ignored; §15.2: no 1xx response is sent to an HTTP/1.0 client.
  it('no 100 Continue is sent, whether the body comes with the head or after it', T, async () => {
    await withServer(echo, async (server) => {
      let r = await exchange(server, null, { parts: ['POST /e HTTP/1.0\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\n', 'abc'] });
      assert.deepEqual(r.statuses, [200]);
      assert.equal(r.responses[0].body, 'POST|/e|abc');
      r = await exchange(server, 'POST /e HTTP/1.0\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\nabc');
      assert.deepEqual(r.statuses, [200]);
      // an HTTP/1.1 client is still answered 100 in both shapes
      r = await exchange(server, null, { parts: [post('Expect: 100-continue\r\nContent-Length: 3\r\n'), 'abc'] });
      assert.deepEqual(r.statuses, [100, 200]);
    });
  });
});

describe('Expect, Upgrade, Connection, HEAD and statuses without content', { skip }, () => {
  it('Expect: 100-continue is matched case-insensitively; an unknown expectation gets no interim response', T, async () => {
    await withServer(echo, async (server) => {
      let r = await exchange(server, post('Expect: 100-CONTINUE\r\nContent-Length: 3\r\n', 'abc'));
      assert.deepEqual(r.statuses, [100, 200]);
      r = await exchange(server, post('Expect: wibble\r\nContent-Length: 3\r\n', 'abc'));
      assert.deepEqual(r.statuses, [200]);
    });
  });

  it('no 100 Continue ahead of a rejection: an over-limit or malformed head is answered with the error alone', T, async () => {
    await withServer(echo, async (server) => {
      let r = await exchange(server, post('Expect: 100-continue\r\nContent-Length: 99999999999\r\n'));
      assert.deepEqual(r.statuses, [413]);
      r = await exchange(server, post('Expect: 100-continue\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n'));
      assert.deepEqual(r.statuses, [400]);
      assert.equal(server.requests.length, 0);
    });
  });

  it('100 Continue is sent once, before a chunked body too, and carries no header fields', T, async () => {
    await withServer(echo, async (server) => {
      const c = await openRaw(server.port);
      try {
        await c.send(post('Expect: 100-continue\r\nTransfer-Encoding: chunked\r\n'));
        const interim = await c.read();
        assert.equal(interim, 'HTTP/1.1 100 Continue\r\n\r\n');
        await c.send('3\r\nabc\r\n');
        await delay(60);
        await c.send('0\r\n\r\n');
        const res = parseResponse(await c.read());
        assert.equal(res.status, 200);
        assert.equal(res.body, 'POST|/p|abc');
      } finally {
        c.destroy();
      }
    });
  });

  it('an Upgrade the application does not act on is an ordinary request; the connection stays HTTP/1.1', T, async () => {
    await withServer(echo, async (server) => {
      const r = await exchange(
        server,
        get('/u', 'Connection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQCAAAAAAIAAAAA\r\n') + get('/after')
      );
      assert.deepEqual(r.statuses, [200, 200]);
      assert.equal(r.responses[1].body, 'GET|/after|');
      assert.ok(!('upgrade' in r.responses[0].headers));
    });
  });

  it('Connection: close in any case, in a list or in a second field line closes after the response', T, async () => {
    await withServer(echo, async (server) => {
      for (const extra of ['Connection: CLOSE\r\n', 'Connection: foo, close ,bar\r\n', 'Connection: keep-alive\r\nConnection: close\r\n', 'Connection: close\r\nConnection: keep-alive\r\n']) {
        const r = await exchange(server, get('/c', extra));
        assert.deepEqual(r.statuses, [200], extra);
        assert.equal(r.responses[0].headers.connection, 'close', extra);
        assert.equal(r.closed, true, extra);
      }
    });
  });

  it('HEAD: the head of the GET response and no body bytes, single-shot and streamed, pipelined', T, async () => {
    await withServer((ctx) => {
      if (ctx.path === '/stream') { ctx.writeHead(200, ['x-a', 'b']); ctx.write('part1'); ctx.end('part2'); return; }
      ctx.respond(200, ['content-type', 'text/plain'], 'thirteen-byte');
    }, async (server) => {
      const c = await openRaw(server.port);
      try {
        await c.send(`HEAD /h HTTP/1.1\r\n${H}\r\nHEAD /stream HTTP/1.1\r\n${H}\r\n` + get('/g'));
        const raw = await c.read({ until: (s) => s.endsWith('thirteen-byte') });
        const first = parseResponse(raw, { noBody: true });
        assert.equal(first.headers['content-length'], '13');
        const second = parseResponse(first.rest, { noBody: true });
        assert.equal(second.headers['transfer-encoding'], 'chunked');
        const third = parseResponse(second.rest);
        assert.equal(third.body, 'thirteen-byte');
        assert.equal(third.rest, '');
      } finally {
        c.destroy();
      }
    });
  });

  it('a HEAD request with a body: the body is consumed and the next request is in step', T, async () => {
    await withServer(echo, async (server) => {
      const c = await openRaw(server.port);
      try {
        await c.send(`HEAD /h HTTP/1.1\r\n${H}Content-Length: 3\r\n\r\nabc` + get('/g'));
        const raw = await c.read({ until: (s) => s.endsWith('GET|/g|') });
        const first = parseResponse(raw, { noBody: true });
        assert.equal(first.status, 200);
        assert.equal(parseResponse(first.rest).body, 'GET|/g|');
      } finally {
        c.destroy();
      }
    });
  });

  it('204 and 304: no body and no framing header from respond() or from writeHead/write/end; keep-alive holds', T, async () => {
    await withServer((ctx) => {
      const [, how, st] = ctx.path.split('/');
      if (how === 'respond') return ctx.respond(Number(st), ['x-a', 'b'], 'BODY');
      if (how === 'stream') { ctx.writeHead(Number(st), ['x-a', 'b']); ctx.write('BO'); ctx.end('DY'); return; }
      ctx.respond(200, null, 'next');
    }, async (server) => {
      for (const how of ['respond', 'stream']) {
        for (const st of [204, 304]) {
          const r = await exchange(server, get(`/${how}/${st}`) + get('/next'));
          assert.deepEqual(r.statuses, [st, 200], `${how} ${st}`);
          assert.ok(!('content-length' in r.responses[0].headers), `${how} ${st}: no Content-Length`);
          assert.ok(!('transfer-encoding' in r.responses[0].headers), `${how} ${st}: no Transfer-Encoding`);
          assert.equal(r.responses[0].body, '');
          assert.equal(r.responses[1].body, 'next');
          assert.ok(!r.raw.includes('BODY') && !r.raw.includes('BO'), 'no body bytes on the wire');
        }
      }
    });
  });

  // RFC 9110 §8.6: no Content-Length in a 1xx or 204 response. A 304 may
  // carry the length a 200 would have had, and a HEAD response likewise.
  it('a handler-supplied Content-Length is sent on a 304 and a HEAD response, never on a 204', T, async () => {
    await withServer((ctx) => {
      const [, how, st] = ctx.path.split('/');
      if (how === 'stream') { ctx.writeHead(Number(st), ['content-length', '4']); ctx.end(); return; }
      ctx.respond(Number(st), ['content-length', '4'], how === 'respond' ? 'BODY' : null);
    }, async (server) => {
      for (const how of ['respond', 'stream']) {
        let r = await exchange(server, get(`/${how}/204`) + get(`/${how}/204`));
        assert.deepEqual(r.statuses, [204, 204], how);
        assert.ok(!('content-length' in r.responses[0].headers), `${how}: 204 carries Content-Length: ${r.responses[0].headers['content-length']}`);
        r = await exchange(server, get(`/${how}/304`) + get(`/${how}/304`));
        assert.deepEqual(r.statuses, [304, 304], how);
        assert.equal(r.responses[0].headers['content-length'], '4', `${how}: 304 keeps the declared length`);
      }
      const c = await openRaw(server.port);
      try {
        await c.send(`HEAD /head/200 HTTP/1.1\r\n${H}\r\nHEAD /head/204 HTTP/1.1\r\n${H}\r\n`);
        const raw = await c.read({ quiescence: 200 });
        const first = parseResponse(raw, { noBody: true });
        assert.equal(first.headers['content-length'], '4', 'HEAD: the would-be length');
        const second = parseResponse(first.rest, { noBody: true });
        assert.equal(second.status, 204);
        assert.ok(!('content-length' in second.headers), 'HEAD on a 204: still none');
      } finally {
        c.destroy();
      }
    });
  });

  // RFC 9110 §15.3.6: no content in a 205 response; it is framed as an empty body.
  it('a 205 response carries Content-Length: 0 and no content, single-shot and streamed', T, async () => {
    await withServer((ctx) => {
      if (ctx.path === '/stream') { ctx.writeHead(205, ['x-a', 'b']); ctx.write('BO'); ctx.end('DY'); return; }
      if (ctx.path === '/declared') { ctx.writeHead(205, ['content-length', '4']); ctx.end('BODY'); return; }
      ctx.respond(205, ctx.path === '/cl' ? ['content-length', '4'] : null, 'BODY');
    }, async (server) => {
      for (const path of ['/respond', '/cl', '/stream', '/declared']) {
        const r = await exchange(server, get(path) + get(path));
        assert.deepEqual(r.statuses, [205, 205], path);
        assert.match(r.raw, /^HTTP\/1\.1 205 Reset Content\r\n/, path);
        assert.equal(r.responses[0].headers['content-length'], '0', path);
        assert.ok(!('transfer-encoding' in r.responses[0].headers), path);
        assert.ok(!r.raw.includes('BO'), `${path}: no body bytes on the wire`);
        assert.equal(r.closed, false, `${path}: keep-alive holds`);
      }
      const c = await openRaw(server.port);
      try {
        await c.send(`HEAD /cl HTTP/1.1\r\n${H}\r\n`);
        const head = parseResponse(await c.read({ quiescence: 200 }), { noBody: true });
        assert.equal(head.headers['content-length'], '0', 'HEAD: zero as well');
      } finally {
        c.destroy();
      }
    });
  });

  // A client must not act on the reason phrase (RFC 9112 §4), but it is what
  // logs, `curl -i` and fetch()'s statusText show.
  it('each registered status is sent with its own reason phrase', T, async () => {
    const phrases = {
      202: 'Accepted', 203: 'Non-Authoritative Information', 206: 'Partial Content', 207: 'Multi-Status',
      300: 'Multiple Choices', 303: 'See Other', 307: 'Temporary Redirect', 308: 'Permanent Redirect',
      402: 'Payment Required', 406: 'Not Acceptable', 409: 'Conflict', 410: 'Gone', 412: 'Precondition Failed',
      415: 'Unsupported Media Type', 416: 'Range Not Satisfiable', 417: 'Expectation Failed', 418: "I'm a Teapot",
      421: 'Misdirected Request', 422: 'Unprocessable Content', 423: 'Locked', 424: 'Failed Dependency',
      425: 'Too Early', 428: 'Precondition Required', 429: 'Too Many Requests', 451: 'Unavailable For Legal Reasons',
      502: 'Bad Gateway', 504: 'Gateway Timeout', 506: 'Variant Also Negotiates', 507: 'Insufficient Storage',
      508: 'Loop Detected', 510: 'Not Extended', 511: 'Network Authentication Required',
      // unchanged ones, and a code the registry does not know
      200: 'OK', 201: 'Created', 404: 'Not Found', 500: 'Internal Server Error', 503: 'Service Unavailable', 299: 'OK', 599: 'OK',
    };
    await withServer((ctx) => ctx.respond(Number(ctx.path.slice(1)), null, ''), async (server) => {
      const codes = Object.keys(phrases);
      const r = await exchange(server, codes.map((st) => get(`/${st}`)).join(''), { wait: 300 });
      const lines = r.responses.map((x) => x.statusLine);
      assert.deepEqual(lines, codes.map((st) => `HTTP/1.1 ${st} ${phrases[st]}`));
    });
  });
});

// A large body is written from the handler's own bytes behind its head, and a
// piece of a fixed-length stream without being staged first. What the client
// reads must be the same bytes in the same order whichever way each one left:
// in one write, in part with the rest queued, behind other replies of a
// batch, or after them.
describe('large bodies and fixed-length stream pieces', { skip }, () => {
  const fill = (n, seed) => {
    const out = Buffer.allocUnsafe(n);
    let x = (seed * 2654435761) >>> 0;
    for (let i = 0; i < n; i++) {
      x = (Math.imul(x, 1664525) + 1013904223) >>> 0;
      out[i] = x >>> 24;
    }
    return out;
  };
  const same = (text, buf) => Buffer.from(text, 'latin1').equals(buf);
  const SIZES = [16383, 16384, 16385, 40000, 65536, 300000, 1 << 20, 5, 0, 20000, 100000];
  const bodyFor = (i) => fill(SIZES[i % SIZES.length], i + 1);

  it('bodies on both sides of the direct-write size arrive intact, one request at a time', T, async () => {
    await withServer((ctx) => ctx.respond(200, ['x-n', ctx.path.slice(2)], bodyFor(Number(ctx.path.slice(2)))), async (server) => {
      const c = await openRaw(server.port);
      try {
        for (let i = 0; i < SIZES.length; i++) {
          await c.send(get(`/r${i}`));
          const raw = await c.read({ until: responsesComplete(1), timeout: 15000 });
          const [res] = parseResponses(raw);
          assert.equal(res.status, 200);
          assert.equal(res.headers['content-length'], String(SIZES[i]));
          assert.ok(same(res.body, bodyFor(i)), `body ${i} (${SIZES[i]} bytes)`);
        }
      } finally {
        c.destroy();
      }
    });
  });

  it('a pipelined batch of large and small bodies is answered in order, to a reader that falls behind', { timeout: 60000 }, async () => {
    const n = 33;
    await withServer((ctx) => ctx.respond(200, ['x-n', ctx.path.slice(2)], bodyFor(Number(ctx.path.slice(2)))), async (server) => {
      const c = await openRaw(server.port);
      try {
        c.socket.pause();  // the kernel's buffers fill, and what they do not take is queued
        await c.send(Array.from({ length: n }, (_, i) => get(`/r${i}`)).join(''));
        await delay(200);
        c.socket.resume();
        const raw = await c.read({ until: responsesComplete(n), timeout: 30000 });
        const responses = parseResponses(raw);
        assert.equal(responses.length, n);
        responses.forEach((res, i) => {
          assert.equal(res.headers['x-n'], String(i), `reply ${i} is in its place`);
          assert.ok(same(res.body, bodyFor(i)), `reply ${i}`);
        });
      } finally {
        c.destroy();
      }
    });
  });

  it('a large body given later, outside the request callback, and one that ends the connection', T, async () => {
    const big = fill(200000, 77);
    await withServer(
      (ctx) => {
        if (ctx.path === '/later') return void setTimeout(() => ctx.respond(200, null, big), 5);
        ctx.respond(200, null, big);
      },
      async (server) => {
        const c = await openRaw(server.port);
        try {
          await c.send(get('/later'));
          let [res] = parseResponses(await c.read({ until: responsesComplete(1), timeout: 15000 }));
          assert.ok(same(res.body, big), 'given later');
          await c.send(`HEAD /h HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`);
          const head = parseResponse(await c.read(), { noBody: true });
          assert.equal(head.headers['content-length'], String(big.length), 'HEAD: the length, no body');
          await c.send(get('/last', `Connection: close${CRLF}`));
          const raw = await c.read({ expectClose: true, timeout: 15000 });
          [res] = parseResponses(raw);
          assert.equal(res.headers.connection, 'close');
          assert.ok(same(res.body, big), 'the last response of the connection');
        } finally {
          c.destroy();
        }
      }
    );
  });

  it('end() with a large body and no writeHead() is that body under a Content-Length', T, async () => {
    const big = fill(150000, 5);
    await withServer((ctx) => ctx.end(ctx.path === '/small' ? 'tiny' : big), async (server) => {
      const c = await openRaw(server.port);
      try {
        await c.send(get('/big') + get('/small') + get('/big'));
        const responses = parseResponses(await c.read({ until: responsesComplete(3), timeout: 15000 }));
        assert.equal(responses.length, 3);
        assert.equal(responses[0].headers['content-length'], String(big.length));
        assert.ok(same(responses[0].body, big));
        assert.equal(responses[1].body, 'tiny');
        assert.ok(same(responses[2].body, big));
        await c.send(`HEAD /big HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`);
        const head = parseResponse(await c.read(), { noBody: true });
        assert.equal(head.status, 200);
        assert.equal(head.headers['content-length'], '0');
      } finally {
        c.destroy();
      }
    });
  });

  it('a stream with a declared length is exactly its pieces, written inside the callback and after it', { timeout: 60000 }, async () => {
    const pieces = [70000, 5, 16384, 200000, 1, 4096, 131072].map((n, i) => fill(n, i + 40));
    const body = Buffer.concat(pieces);
    const head = ['content-type', 'application/octet-stream', 'content-length', String(body.length)];
    await withServer(
      async (ctx) => {
        ctx.writeHead(200, head);
        if (ctx.path === '/sync') {
          for (const p of pieces.slice(0, -1)) ctx.write(p);
          ctx.write(Buffer.alloc(0));
          return ctx.end(pieces[pieces.length - 1]);
        }
        for (const p of pieces.slice(0, -1)) {
          if (!ctx.write(p)) await ctx.waitWritable();
        }
        if (ctx.path === '/over') {
          // More than was declared: the excess is not sent.
          ctx.write(Buffer.concat([pieces[pieces.length - 1], fill(5000, 99)]));
          return ctx.end(fill(100, 98));
        }
        ctx.end(pieces[pieces.length - 1]);
      },
      async (server) => {
        const c = await openRaw(server.port);
        try {
          for (const path of ['/sync', '/async', '/over', '/sync']) {
            c.socket.pause();
            await c.send(get(path));
            await delay(100);
            c.socket.resume();
            const [res] = parseResponses(await c.read({ until: responsesComplete(1), timeout: 20000 }));
            assert.equal(res.headers['content-length'], String(body.length), path);
            assert.ok(same(res.body, body), `${path}: the declared bytes, nothing else`);
          }
        } finally {
          c.destroy();
        }
      }
    );
  });

  // A large chunk of a chunked stream leaves as its size line, the handler's
  // bytes and the CRLF in one write; a small one is assembled first. Chunks
  // on both sides of that size, written inside the callback and after it, to
  // a reader that falls behind, with the next request already waiting.
  it('a chunked stream of large and small chunks is exactly its pieces, in order', { timeout: 60000 }, async () => {
    const sizes = [32768, 5, 32767, 100000, 1, 65536, 40000, 3000, 1 << 20, 32769];
    const pieces = sizes.map((n, i) => fill(n, i + 60));
    const body = Buffer.concat(pieces);
    await withServer(
      async (ctx) => {
        if (ctx.path === '/after') return ctx.respond(200, null, 'after');
        ctx.writeHead(200, ['content-type', 'application/octet-stream']);
        const lastLarge = ctx.path !== '/small-end';
        const upTo = lastLarge ? pieces.length - 1 : pieces.length;
        if (ctx.path === '/sync') {
          for (let i = 0; i < upTo; i++) ctx.write(pieces[i]);
        } else {
          for (let i = 0; i < upTo; i++) {
            if (!ctx.write(pieces[i])) await ctx.waitWritable();
          }
        }
        if (lastLarge) ctx.end(pieces[pieces.length - 1]);
        else ctx.end('!');
      },
      async (server) => {
        const c = await openRaw(server.port);
        try {
          for (const path of ['/sync', '/async', '/small-end', '/sync']) {
            c.socket.pause();
            await c.send(get(path) + get('/after'));
            await delay(100);
            c.socket.resume();
            const responses = parseResponses(await c.read({ until: responsesComplete(2), timeout: 20000 }));
            assert.equal(responses.length, 2, path);
            assert.equal(responses[0].headers['transfer-encoding'], 'chunked', path);
            const want = path === '/small-end' ? Buffer.concat([body, Buffer.from('!')]) : body;
            assert.ok(same(responses[0].body, want), `${path}: every chunk, once, in order`);
            assert.equal(responses[1].body, 'after', `${path}: the next response is in step`);
          }
          // The last response of the connection, ended with a large chunk.
          await c.send(get('/sync', `Connection: close${CRLF}`));
          const [last] = parseResponses(await c.read({ expectClose: true, timeout: 20000 }));
          assert.equal(last.headers.connection, 'close');
          assert.ok(same(last.body, body), 'the closing response');
        } finally {
          c.destroy();
        }
      }
    );
  });
});
