// HTTP/1.1 protocol conformance suite for @morojs/engine (docs/API.md).
//
// The native binding that implements serve()/listen()/respond() is developed
// in parallel: when it is missing (or serve() is not a function yet) the
// whole suite reports SKIPPED, never FAILED. Run with: node --test
//
// Every test talks to the engine over a raw TCP socket — no http.request —
// so wire-level behavior (framing, connection lifecycle, chunking, interim
// responses) is asserted byte-for-byte.

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
  waitFor,
  delay,
} from './helpers.mjs';

const engine = await loadEngine();
const skip = engine
  ? false
  : '@morojs/engine native binding not usable yet (binary missing, probe().ok false, or serve() not implemented) — conformance suite skipped';

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

function headerValue(flat, name) {
  for (let i = 0; i + 1 < flat.length; i += 2) {
    if (flat[i] === name) return flat[i + 1];
  }
  return undefined;
}

describe('@morojs/engine HTTP/1.1 conformance', { skip }, () => {
  it('basic GET: status line, date/content-length headers, intact body', T, async () => {
    await withServer((ctx) => ctx.respond(200, ['content-type', 'text/plain'], 'hello world'), async ({ port }) => {
      const raw = await rawRequest(port, get('/'));
      const res = parseResponse(raw);
      assert.equal(res.statusLine, 'HTTP/1.1 200 OK');
      assert.ok(res.headers['date'], 'date header must be present');
      assert.equal(res.headers['content-length'], '11');
      assert.equal(res.body, 'hello world');
      assert.equal(res.rest, '', 'no stray bytes after the response');
    });
  });

  it('keep-alive: two sequential requests on one socket, connection stays open', T, async () => {
    await withServer(echoPath, async ({ port }) => {
      const client = await openRaw(port);
      try {
        await client.send(get('/one'));
        const r1 = parseResponse(await client.read({ until: responsesComplete(1) }));
        assert.equal(r1.status, 200);
        assert.equal(r1.body, 'echo:/one');
        assert.equal(client.closed, false, 'connection must stay open after first response');

        await client.send(get('/two'));
        const r2 = parseResponse(await client.read({ until: responsesComplete(1) }));
        assert.equal(r2.status, 200);
        assert.equal(r2.body, 'echo:/two');
        assert.equal(client.closed, false, 'connection must stay open after second response');
      } finally {
        client.destroy();
      }
    });
  });

  it('Connection: close is honored (socket closed) and echoed in the response', T, async () => {
    await withServer(echoPath, async ({ port }) => {
      const raw = await rawRequest(port, get('/', `Connection: close${CRLF}`), { expectClose: true });
      const res = parseResponse(raw);
      assert.equal(res.status, 200);
      assert.equal((res.headers['connection'] || '').toLowerCase(), 'close');
      assert.equal(res.body, 'echo:/');
    });
  });

  it('HTTP/1.0 request without keep-alive: connection closed after response', T, async () => {
    await withServer(echoPath, async ({ port }) => {
      const raw = await rawRequest(port, `GET / HTTP/1.0${CRLF}Host: t${CRLF}${CRLF}`, { expectClose: true });
      const res = parseResponse(raw);
      assert.equal(res.status, 200);
      assert.equal(res.body, 'echo:/');
    });
  });

  it('pipelining: two requests in one write are both answered, in order', T, async () => {
    await withServer(echoPath, async ({ port }) => {
      const client = await openRaw(port);
      try {
        await client.send(get('/a') + get('/b'));
        const raw = await client.read({ until: responsesComplete(2), timeout: 5000 });
        const responses = parseResponses(raw);
        assert.equal(responses.length, 2, `expected 2 responses, got ${responses.length}`);
        assert.equal(responses[0].status, 200);
        assert.equal(responses[0].body, 'echo:/a', 'first response must be for /a');
        assert.equal(responses[1].status, 200);
        assert.equal(responses[1].body, 'echo:/b', 'second response must be for /b');
      } finally {
        client.destroy();
      }
    });
  });

  it('POST with Content-Length: handler sees the exact 8192-byte body', T, async () => {
    const payload = Array.from({ length: 8192 }, (_, i) => String.fromCharCode(33 + (i % 94))).join('');
    let seen = null;
    await withServer((ctx) => {
      const body = ctx.body();
      seen = { method: ctx.method, byteLength: body ? body.byteLength : -1 };
      ctx.respond(200, null, body ?? '');
    }, async ({ port }) => {
      const raw = await rawRequest(
        port,
        `POST /upload HTTP/1.1${CRLF}Host: t${CRLF}Content-Length: ${payload.length}${CRLF}${CRLF}${payload}`,
        { until: responsesComplete(1) }
      );
      const res = parseResponse(raw);
      assert.equal(res.status, 200);
      assert.equal(seen.method, 'POST');
      assert.equal(seen.byteLength, 8192, 'ctx.body() must contain all 8192 bytes');
      assert.equal(res.body, payload, 'echoed body must match the sent bytes exactly');
    });
  });

  it('chunked request body: handler body matches chunk concatenation', T, async () => {
    await withServer(echoBody, async ({ port }) => {
      const framed =
        `POST /chunky HTTP/1.1${CRLF}Host: t${CRLF}Transfer-Encoding: chunked${CRLF}${CRLF}` +
        `5${CRLF}hello${CRLF}` +
        `6${CRLF} world${CRLF}` +
        `1${CRLF}!${CRLF}` +
        `0${CRLF}${CRLF}`;
      const raw = await rawRequest(port, framed, { until: responsesComplete(1) });
      const res = parseResponse(raw);
      assert.equal(res.status, 200);
      assert.equal(res.body, 'hello world!');
    });
  });

  it('smuggling: Content-Length + Transfer-Encoding rejected with 400 and close', T, async () => {
    await withServer(echoBody, async (server) => {
      const raw = await rawRequest(
        server.port,
        `POST / HTTP/1.1${CRLF}Host: t${CRLF}Content-Length: 5${CRLF}Transfer-Encoding: chunked${CRLF}${CRLF}0${CRLF}${CRLF}`,
        { expectClose: true }
      );
      const res = parseResponse(raw);
      assert.equal(res.status, 400);
      assert.equal(server.requests.length, 0, 'handler must not be invoked for a smuggled request');
    });
  });

  it('smuggling: two conflicting Content-Length headers rejected with 400', T, async () => {
    await withServer(echoBody, async (server) => {
      const raw = await rawRequest(
        server.port,
        `POST / HTTP/1.1${CRLF}Host: t${CRLF}Content-Length: 5${CRLF}Content-Length: 6${CRLF}${CRLF}hello!`,
        { tolerateWriteError: true }
      );
      const res = parseResponse(raw);
      assert.equal(res.status, 400);
      assert.equal(server.requests.length, 0, 'handler must not be invoked for conflicting lengths');
    });
  });

  it('oversized head (~70KB header line): 431 or 400, connection closed, server survives', T, async () => {
    await withServer(echoPath, async ({ port }) => {
      const raw = await rawRequest(port, get('/', `X-Big: ${'a'.repeat(70 * 1024)}${CRLF}`), {
        expectClose: true,
        timeout: 5000,
      });
      assert.ok(raw.length > 0, 'server should answer with an error response before closing');
      const res = parseResponse(raw);
      assert.ok(
        res.status === 431 || res.status === 400,
        `expected 431 or 400 for oversized head, got ${res.status}`
      );
      // no crash: a fresh request on a new socket still works
      const again = parseResponse(await rawRequest(port, get('/alive'), { until: responsesComplete(1) }));
      assert.equal(again.status, 200);
      assert.equal(again.body, 'echo:/alive');
    });
  });

  it('413: body exceeding maxBodySize rejected without invoking the handler', T, async () => {
    await withServer(echoBody, { maxBodySize: 1024 }, async (server) => {
      const body = 'z'.repeat(4096);
      const raw = await rawRequest(
        server.port,
        `POST /big HTTP/1.1${CRLF}Host: t${CRLF}Content-Length: ${body.length}${CRLF}${CRLF}${body}`,
        { tolerateWriteError: true }
      );
      const res = parseResponse(raw);
      assert.equal(res.status, 413);
      assert.equal(server.requests.length, 0, 'handler must not be invoked for an oversized body');
    });
  });

  it('Expect: 100-continue: interim 100 response, then the final response after the body', T, async () => {
    await withServer(echoBody, async ({ port }) => {
      const body = 'continue-me';
      const client = await openRaw(port);
      try {
        await client.send(
          `POST /expect HTTP/1.1${CRLF}Host: t${CRLF}Content-Length: ${body.length}${CRLF}Expect: 100-continue${CRLF}${CRLF}`
        );
        const interimRaw = await client.read({ until: (r) => r.includes('\r\n\r\n'), timeout: 5000 });
        const interim = parseResponse(interimRaw);
        assert.equal(interim.status, 100, `expected interim 100 Continue, got ${interim.statusLine}`);

        await client.send(body);
        const finalRaw = interim.rest + (await client.read({ until: responsesComplete(1) }));
        const res = parseResponse(finalRaw);
        assert.equal(res.status, 200);
        assert.equal(res.body, body);
      } finally {
        client.destroy();
      }
    });
  });

  it('HEAD: content-length of the would-be body, zero body bytes on the wire', T, async () => {
    await withServer((ctx) => ctx.respond(200, ['content-type', 'text/plain'], 'hello world'), async ({ port }) => {
      // quiescence read (no early-exit predicate) so any erroneous body bytes are captured
      const raw = await rawRequest(port, `HEAD / HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`);
      const res = parseResponse(raw, { noBody: true });
      assert.equal(res.status, 200);
      assert.equal(res.headers['content-length'], '11');
      assert.equal(res.rest, '', 'HEAD response must carry no body bytes');
    });
  });

  it('query string: ctx.path excludes the query, ctx.query() returns the raw string', T, async () => {
    let seen = null;
    await withServer((ctx) => {
      seen = { path: ctx.path, query: ctx.query() };
      ctx.respond(200, null, 'ok');
    }, async ({ port }) => {
      const res = parseResponse(await rawRequest(port, get('/path?a=1&b=2'), { until: responsesComplete(1) }));
      assert.equal(res.status, 200);
      assert.equal(seen.path, '/path');
      assert.equal(seen.query, 'a=1&b=2');

      await rawRequest(port, get('/plain'), { until: responsesComplete(1) });
      assert.equal(seen.path, '/plain');
      assert.equal(seen.query, '', "query() must return '' when there is no query string");
    });
  });

  it('header access: mixed-case request headers arrive lowercased in the flat array', T, async () => {
    let flat = null;
    await withServer((ctx) => {
      flat = ctx.headers();
      ctx.respond(200, null, 'ok');
    }, async ({ port }) => {
      await rawRequest(
        port,
        get('/', `X-CuStOm-ToKeN: Alpha123${CRLF}X-ANOTHER-Header: Beta${CRLF}`),
        { until: responsesComplete(1) }
      );
      assert.ok(Array.isArray(flat), 'ctx.headers() must return an array');
      assert.equal(flat.length % 2, 0, 'flat header array must have even length');
      assert.equal(headerValue(flat, 'x-custom-token'), 'Alpha123');
      assert.equal(headerValue(flat, 'x-another-header'), 'Beta');
      for (let i = 0; i < flat.length; i += 2) {
        assert.equal(flat[i], flat[i].toLowerCase(), `header key not lowercased: ${flat[i]}`);
      }
    });
  });

  it('streaming response: writeHead + 3 writes + end arrives chunk-encoded and intact', T, async () => {
    await withServer((ctx) => {
      ctx.writeHead(200, ['content-type', 'text/plain']);
      ctx.write('alpha-');
      ctx.write('bravo-');
      ctx.write('charlie');
      ctx.end();
    }, async ({ port }) => {
      const raw = await rawRequest(port, get('/stream'), { until: responsesComplete(1) });
      const res = parseResponse(raw);
      assert.equal(res.status, 200);
      assert.equal(
        (res.headers['transfer-encoding'] || '').toLowerCase(),
        'chunked',
        'streaming response without content-length must use chunked encoding'
      );
      assert.equal(res.body, 'alpha-bravo-charlie');
    });
  });

  it('client abort: onAborted fires and a late respond() is a safe no-op', T, async () => {
    let neverReqId = null;
    await withServer((ctx) => {
      if (ctx.path === '/never') {
        neverReqId = ctx.reqId; // never respond
        return;
      }
      ctx.respond(200, null, 'alive');
    }, async (server) => {
      const client = await openRaw(server.port);
      await client.send(get('/never'));
      await waitFor(() => neverReqId !== null, { timeout: 3000, message: 'handler was never invoked' });
      client.destroy();
      await waitFor(() => server.aborted.includes(neverReqId), {
        timeout: 3000,
        message: 'onAborted did not fire after the client destroyed the socket',
      });
      assert.doesNotThrow(() => {
        engine.respond(neverReqId, 200, null, 'too late'); // must be a no-op, not a crash
      });
      // process/server still healthy
      const res = parseResponse(await rawRequest(server.port, get('/after'), { until: responsesComplete(1) }));
      assert.equal(res.status, 200);
      assert.equal(res.body, 'alive');
    });
  });

  it('keep-alive after a chunked streaming response: next request on same socket works', T, async () => {
    await withServer((ctx) => {
      if (ctx.path === '/stream') {
        ctx.writeHead(200, null);
        ctx.write('S1');
        ctx.write('S2');
        ctx.end();
      } else {
        ctx.respond(200, null, 'plain-ok');
      }
    }, async ({ port }) => {
      const client = await openRaw(port);
      try {
        await client.send(get('/stream'));
        const r1 = parseResponse(await client.read({ until: responsesComplete(1) }));
        assert.equal(r1.status, 200);
        assert.equal(r1.body, 'S1S2');
        assert.equal(client.closed, false, 'connection must survive a chunked response');

        await client.send(get('/plain'));
        const r2 = parseResponse(await client.read({ until: responsesComplete(1) }));
        assert.equal(r2.status, 200);
        assert.equal(r2.body, 'plain-ok');
      } finally {
        client.destroy();
      }
    });
  });

  it('large response: 1MB body via a single respond() received intact', T, async () => {
    const MB = 1024 * 1024;
    const big = '0123456789abcdef'.repeat(MB / 16);
    await withServer((ctx) => ctx.respond(200, null, big), async ({ port }) => {
      const raw = await rawRequest(port, get('/big'), { until: responsesComplete(1), timeout: 15000 });
      const res = parseResponse(raw);
      assert.equal(res.status, 200);
      assert.equal(res.headers['content-length'], String(MB));
      assert.equal(res.body.length, MB);
      assert.equal(res.body, big, '1MB body must arrive byte-identical');
    });
  });

  it('50 parallel connections each complete a GET successfully', T, async () => {
    await withServer(echoPath, async ({ port }) => {
      const results = await Promise.all(
        Array.from({ length: 50 }, (_, i) =>
          rawRequest(port, get(`/c${i}`), { until: responsesComplete(1), timeout: 10000 })
        )
      );
      results.forEach((raw, i) => {
        const res = parseResponse(raw);
        assert.equal(res.status, 200, `connection ${i} failed: ${res.statusLine}`);
        assert.equal(res.body, `echo:/c${i}`);
      });
    });
  });

  it('byte-trickle: request delivered one byte at a time is parsed correctly', T, async () => {
    await withServer(echoPath, async ({ port }) => {
      const reqBytes = `GET /t HTTP/1.1${CRLF}Host: a${CRLF}${CRLF}`;
      const client = await openRaw(port);
      try {
        for (const byte of reqBytes) {
          await client.send(byte);
          await delay(25);
        }
        const res = parseResponse(await client.read({ until: responsesComplete(1), timeout: 5000 }));
        assert.equal(res.status, 200);
        assert.equal(res.body, 'echo:/t');
      } finally {
        client.destroy();
      }
    });
  });
});
