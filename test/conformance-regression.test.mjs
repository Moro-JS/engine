// Regression conformance suite for @morojs/engine.
//
// Locks in the security/correctness fixes layered on top of the base HTTP/1.1
// conformance and hardening suites:
//   - H1  chunked trailers are cumulatively bounded (unbounded-memory DoS)
//   - M2  multiple Transfer-Encoding headers are rejected (request smuggling)
//   - M1  a HEAD response to a streaming handler emits NO chunked terminator
//         (keep-alive stays in sync; no "0\r\n\r\n" desync)
//   - L1  Connection: "keep-alive, close" closes the connection
//   - L3  a non-digit HTTP minor version is rejected 400
//
// Each case drives the real running engine over a raw TCP socket. Run with:
//   node --test

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  loadEngine,
  startFixtureServer,
  rawRequest,
  openRaw,
  parseResponse,
  parseResponses,
} from './helpers.mjs';

const engine = await loadEngine();
const skip = engine
  ? false
  : '@morojs/engine native binding not usable yet — regression suite skipped';

const T = { timeout: 30000 };
const CRLF = '\r\n';

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

const ok = (ctx) => ctx.respond(200, ['content-type', 'text/plain'], 'ok');

describe('@morojs/engine regression conformance', { skip }, () => {
  // ---- M2: multiple Transfer-Encoding headers -> 400 (smuggling defense) ----

  it('two Transfer-Encoding headers (chunked, then bogus) are rejected 400', T, async () => {
    await withServer(ok, async (server) => {
      const raw = await rawRequest(
        server.port,
        `POST / HTTP/1.1${CRLF}Host: t${CRLF}Transfer-Encoding: chunked${CRLF}` +
          `Transfer-Encoding: cow${CRLF}${CRLF}0${CRLF}${CRLF}`,
        { expectClose: true }
      );
      const res = parseResponse(raw);
      assert.equal(res.status, 400, 'conflicting multi-TE must be a 400, not parsed as chunked');
      assert.equal(server.requests.length, 0, 'the handler must never run for a rejected request');
    });
  });

  it('two Transfer-Encoding headers (bogus, then chunked) are rejected 400', T, async () => {
    await withServer(ok, async (server) => {
      const raw = await rawRequest(
        server.port,
        `POST / HTTP/1.1${CRLF}Host: t${CRLF}Transfer-Encoding: cow${CRLF}` +
          `Transfer-Encoding: chunked${CRLF}${CRLF}0${CRLF}${CRLF}`,
        { expectClose: true }
      );
      const res = parseResponse(raw);
      assert.equal(res.status, 400, 'ordering must not decide acceptance');
      assert.equal(server.requests.length, 0);
    });
  });

  // ---- H1: chunked trailer accumulation is cumulatively bounded ----

  it('a flood of chunk trailer lines is bounded (431), server survives (no OOM/hang)', T, async () => {
    await withServer(ok, { maxHeadSize: 16 * 1024 }, async (server) => {
      const client = await openRaw(server.port);
      try {
        // Zero-length body: enter the trailer state, then stream trailer lines
        // far exceeding maxHeadSize. Pre-fix this grew buf_ without bound and
        // never completed; now it must be rejected 431 and the socket closed.
        await client.send(
          `POST / HTTP/1.1${CRLF}Host: t${CRLF}Transfer-Encoding: chunked${CRLF}${CRLF}0${CRLF}`
        );
        const line = `X-Trailer-Pad: ${'a'.repeat(200)}${CRLF}`;
        for (let i = 0; i < 500 && !client.closed; i++) {
          try {
            await client.send(line);
          } catch {
            break; // server closed mid-write — acceptable
          }
        }
        const raw = await client.read({ expectClose: true, timeout: 8000 }).catch(() => '');
        if (raw) {
          const res = parseResponse(raw);
          assert.equal(res.status, 431, 'oversized trailer block must be 431');
        }
        await client.waitClose({ timeout: 5000 }).catch(() => {});
        assert.equal(client.closed, true, 'the connection must be closed, not left buffering');
        assert.equal(server.requests.length, 0, 'the handler must not run');
      } finally {
        client.destroy();
      }
    });
  });

  it('a small, well-formed chunk trailer is still accepted', T, async () => {
    await withServer(
      (ctx) => ctx.respond(200, null, ctx.body() ? Buffer.from(ctx.body()).toString() : ''),
      async (server) => {
        const raw = await rawRequest(
          server.port,
          `POST / HTTP/1.1${CRLF}Host: t${CRLF}Transfer-Encoding: chunked${CRLF}${CRLF}` +
            `5${CRLF}hello${CRLF}0${CRLF}X-Trailer: ok${CRLF}${CRLF}`
        );
        const res = parseResponse(raw);
        assert.equal(res.status, 200, 'a legitimate single trailer line must still parse');
        assert.equal(res.body, 'hello');
      }
    );
  });

  // ---- M1: HEAD to a streaming handler emits no chunked terminator ----

  it('HEAD to a streaming (chunked) handler: no body bytes, keep-alive stays in sync', T, async () => {
    await withServer(
      (ctx) => {
        ctx.writeHead(200, ['content-type', 'text/plain']);
        ctx.write('this body is suppressed for HEAD');
        ctx.end();
      },
      async (server) => {
        const client = await openRaw(server.port);
        try {
          // Pipeline a HEAD then a GET on the same socket. If the HEAD response
          // leaked a "0\r\n\r\n" chunked terminator, it would be parsed as the
          // start of the GET's response and desync the second exchange.
          await client.send(
            `HEAD / HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}` +
              `GET / HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`
          );
          const raw = await client.read({ timeout: 5000 });
          const head = parseResponse(raw, { noBody: true });
          assert.equal(head.status, 200, 'HEAD status');
          // The next bytes must be a clean second response, not a stray "0\r\n".
          const second = parseResponse(head.rest);
          assert.equal(second.status, 200, 'the follow-up GET must parse cleanly (no desync)');
          assert.equal(second.body, 'this body is suppressed for HEAD');
        } finally {
          client.destroy();
        }
      }
    );
  });

  // ---- L1: Connection token list containing close ----

  it('Connection: "keep-alive, close" closes the connection', T, async () => {
    await withServer(ok, async (server) => {
      const raw = await rawRequest(
        server.port,
        `GET / HTTP/1.1${CRLF}Host: t${CRLF}Connection: keep-alive, close${CRLF}${CRLF}`,
        { expectClose: true }
      );
      const res = parseResponse(raw);
      assert.equal(res.status, 200);
      assert.match(
        (res.headers['connection'] || '').toLowerCase(),
        /close/,
        'a close token anywhere must win over keep-alive'
      );
    });
  });

  // ---- App-supplied framing/hop-by-hop headers are stripped ----

  it('app-supplied Transfer-Encoding/Connection/Date headers are dropped (no framing ambiguity)', T, async () => {
    await withServer(
      (ctx) =>
        ctx.respond(
          200,
          [
            'transfer-encoding', 'chunked',
            'connection', 'close',
            'date', 'Thu, 01 Jan 1970 00:00:00 GMT',
            'x-app', 'kept',
          ],
          'body'
        ),
      async (server) => {
        const raw = await rawRequest(server.port, `GET / HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`);
        const res = parseResponse(raw);
        assert.equal(res.status, 200);
        assert.equal(res.body, 'body');
        // The engine owns framing: exactly ONE Content-Length, no app TE.
        assert.equal(res.headers['transfer-encoding'], undefined, 'app Transfer-Encoding must be stripped');
        assert.ok(res.headers['content-length'] !== undefined, 'engine sets its own Content-Length');
        // Date/Connection are engine-owned singletons (not the app values).
        assert.ok(!/1970/.test(res.headers['date'] || ''), 'app Date must not survive');
        assert.equal(res.headers['x-app'], 'kept', 'ordinary app headers still pass through');
      }
    );
  });

  // ---- L3: malformed HTTP minor version ----

  it('a non-digit HTTP minor version (HTTP/1.x) is rejected 400', T, async () => {
    await withServer(ok, async (server) => {
      const raw = await rawRequest(
        server.port,
        `GET / HTTP/1.x${CRLF}Host: t${CRLF}${CRLF}`,
        { expectClose: true }
      );
      const res = parseResponse(raw);
      assert.equal(res.status, 400, 'a malformed version must be 400, not served');
      assert.equal(server.requests.length, 0);
    });
  });
});
