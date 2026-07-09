// TLS conformance suite for @morojs/engine.
//
// The engine terminates TLS in-process (OpenSSL from the host Node binary,
// memory-BIO transform in src/tls.h). This suite proves:
//   - both ssl option shapes work (file paths and inline PEM), incl. an
//     encrypted key + passphrase and an RSA identity
//   - the HTTP/1.1 machinery is unchanged under TLS (GET, POST echo,
//     keep-alive, chunked streaming, 413/431 limits, abort -> onAborted)
//   - ALPN negotiates http/1.1 (and tolerates clients with no overlap)
//   - WSS: RFC 6455 upgrade + echo over the TLS socket
//   - config errors THROW from serve() (bad PEM, mismatch, missing file,
//     partial config) - never a silent plaintext server
//   - a plaintext client on the TLS port is dropped without a crash
//
// Run with: node --test

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  loadEngine,
  startFixtureServer,
  parseResponse,
} from './helpers.mjs';
import {
  fixturePath,
  fixturePem,
  sslFileOptions,
  sslInlineOptions,
  openRawTls,
  rawTlsRequest,
} from './tls-helpers.mjs';
import net from 'node:net';

const engine = await loadEngine();
const tlsCapable = engine?.probe?.().capabilities?.tls === true;
const skip = engine
  ? tlsCapable
    ? false
    : 'engine binary predates TLS support — TLS suite skipped'
  : '@morojs/engine native binding not usable yet — TLS suite skipped';

const T = { timeout: 30000 };
const CRLF = '\r\n';
const GET = (path = '/', extra = '') => `GET ${path} HTTP/1.1${CRLF}Host: t${CRLF}${extra}${CRLF}`;

const ok = (ctx) => ctx.respond(200, ['content-type', 'text/plain'], 'ok-tls');
const echoBody = (ctx) => ctx.respond(200, null, ctx.body() ?? '');

async function withTlsServer(handler, sslOptions, fn, extraOptions = {}) {
  const server = await startFixtureServer(engine, handler, { ssl: sslOptions, ...extraOptions });
  try {
    return await fn(server);
  } finally {
    server.close();
  }
}

describe('@morojs/engine TLS conformance', { skip }, () => {
  // -------------------------------------------------------------------------
  // Both option shapes + key algorithm coverage
  // -------------------------------------------------------------------------

  it('serves HTTPS with file-path ssl options (ECDSA)', T, async () => {
    await withTlsServer(ok, sslFileOptions(), async (server) => {
      const raw = await rawTlsRequest(server.port, GET());
      const res = parseResponse(raw);
      assert.equal(res.status, 200);
      assert.equal(res.body, 'ok-tls');
    });
  });

  it('serves HTTPS with inline-PEM ssl options', T, async () => {
    await withTlsServer(ok, sslInlineOptions(), async (server) => {
      const res = parseResponse(await rawTlsRequest(server.port, GET()));
      assert.equal(res.status, 200);
      assert.equal(res.body, 'ok-tls');
    });
  });

  it('inline PEM as Buffer works (node-style key/cert)', T, async () => {
    const sslBuf = {
      key: Buffer.from(fixturePem('localhost.key')),
      cert: Buffer.from(fixturePem('localhost.pem')),
    };
    await withTlsServer(ok, sslBuf, async (server) => {
      const res = parseResponse(await rawTlsRequest(server.port, GET()));
      assert.equal(res.status, 200);
    });
  });

  it('decrypts an encrypted private key with the passphrase', T, async () => {
    const ssl = {
      key_file_name: fixturePath('localhost-encrypted.key'),
      cert_file_name: fixturePath('localhost.pem'),
      passphrase: 'moro-test',
    };
    await withTlsServer(ok, ssl, async (server) => {
      const res = parseResponse(await rawTlsRequest(server.port, GET()));
      assert.equal(res.status, 200);
    });
  });

  it('serves with an RSA identity', T, async () => {
    const ssl = { key_file_name: fixturePath('rsa.key'), cert_file_name: fixturePath('rsa.pem') };
    await withTlsServer(ok, ssl, async (server) => {
      const res = parseResponse(await rawTlsRequest(server.port, GET()));
      assert.equal(res.status, 200);
    });
  });

  // -------------------------------------------------------------------------
  // HTTP/1.1 semantics unchanged under TLS
  // -------------------------------------------------------------------------

  it('POST body round-trips over TLS', T, async () => {
    await withTlsServer(echoBody, sslFileOptions(), async (server) => {
      const body = 'x'.repeat(4096);
      const req = `POST / HTTP/1.1${CRLF}Host: t${CRLF}Content-Length: ${body.length}${CRLF}${CRLF}${body}`;
      const res = parseResponse(await rawTlsRequest(server.port, req));
      assert.equal(res.status, 200);
      assert.equal(res.body, body);
    });
  });

  it('keep-alive: two sequential requests on one TLS connection', T, async () => {
    await withTlsServer(ok, sslFileOptions(), async (server) => {
      const client = await openRawTls(server.port);
      try {
        await client.send(GET('/first'));
        const r1 = parseResponse(await client.read());
        assert.equal(r1.status, 200);
        await client.send(GET('/second'));
        const r2 = parseResponse(await client.read());
        assert.equal(r2.status, 200);
        assert.equal(server.requests.length, 2, 'both requests on one connection');
      } finally {
        client.destroy();
      }
    });
  });

  it('chunked streaming response over TLS (writeHead/write/end)', T, async () => {
    const handler = (ctx) => {
      ctx.writeHead(200, ['content-type', 'text/plain']);
      ctx.write('alpha-');
      ctx.write('beta-');
      ctx.end('gamma');
    };
    await withTlsServer(handler, sslFileOptions(), async (server) => {
      const raw = await rawTlsRequest(server.port, GET(), {
        until: (s) => s.includes('0\r\n\r\n'),
      });
      const res = parseResponse(raw);
      assert.equal(res.status, 200);
      assert.equal(res.body, 'alpha-beta-gamma', 'chunked body must reassemble');
    });
  });

  it('limits compose with TLS: oversized body is 413', T, async () => {
    await withTlsServer(echoBody, sslFileOptions(), async (server) => {
      const body = 'x'.repeat(64);
      const req = `POST / HTTP/1.1${CRLF}Host: t${CRLF}Content-Length: ${body.length}${CRLF}${CRLF}${body}`;
      const raw = await rawTlsRequest(server.port, req, { expectClose: true });
      assert.equal(parseResponse(raw).status, 413);
      assert.equal(server.requests.length, 0);
    }, { maxBodySize: 16 });
  });

  it('client abort mid-response fires onAborted', T, async () => {
    let sawWritableAwait = false;
    const handler = async (ctx) => {
      ctx.writeHead(200, null);
      // Stream forever until the abort tears the request down.
      for (let i = 0; i < 10000; i++) {
        if (ctx.isAborted()) return;
        if (!ctx.write('data'.repeat(1024))) {
          sawWritableAwait = true;
          await ctx.waitWritable();
        }
      }
      ctx.end();
    };
    await withTlsServer(handler, sslFileOptions(), async (server) => {
      const client = await openRawTls(server.port);
      await client.send(GET());
      await client.read(); // some bytes arrived
      client.destroy();    // abort
      const deadline = Date.now() + 5000;
      while (server.aborted.length === 0 && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 25));
      }
      assert.ok(server.aborted.length > 0, 'onAborted must fire after a TLS client abort');
    });
  });

  // -------------------------------------------------------------------------
  // ALPN
  // -------------------------------------------------------------------------

  it('ALPN negotiates http/1.1 when offered', T, async () => {
    await withTlsServer(ok, sslFileOptions(), async (server) => {
      const client = await openRawTls(server.port, { alpnProtocols: ['http/1.1'] });
      try {
        assert.equal(client.socket.alpnProtocol, 'http/1.1');
        await client.send(GET());
        assert.equal(parseResponse(await client.read()).status, 200);
      } finally {
        client.destroy();
      }
    });
  });

  it('a client offering only unknown ALPN protocols still gets HTTP/1.1', T, async () => {
    await withTlsServer(ok, sslFileOptions(), async (server) => {
      const client = await openRawTls(server.port, { alpnProtocols: ['bogus/9'] });
      try {
        // No overlap -> engine continues without ALPN rather than alerting.
        assert.ok(!client.socket.alpnProtocol, 'no protocol must be selected');
        await client.send(GET());
        assert.equal(parseResponse(await client.read()).status, 200);
      } finally {
        client.destroy();
      }
    });
  });

  // -------------------------------------------------------------------------
  // WSS
  // -------------------------------------------------------------------------

  it('WSS: upgrade + masked echo over the TLS socket', T, async () => {
    const events = { messages: 0 };
    const sid = engine.serve(
      {
        onRequest(reqId) {
          if (engine.upgradeToWebSocket(reqId) === -1) {
            engine.respond(reqId, 400, null, 'not an upgrade');
          }
        },
        onAborted() {},
        onWsOpen() {},
        onWsMessage(wsId, data, isBinary) {
          events.messages++;
          engine.wsSend(wsId, data, isBinary);
        },
        onWsClose() {},
      },
      { ssl: sslFileOptions() }
    );
    const port = engine.listen(sid, '127.0.0.1', 0);
    const client = await openRawTls(port);
    try {
      const key = crypto.randomBytes(16).toString('base64');
      await client.send(
        `GET /ws HTTP/1.1${CRLF}Host: t${CRLF}Upgrade: websocket${CRLF}` +
          `Connection: Upgrade${CRLF}Sec-WebSocket-Key: ${key}${CRLF}` +
          `Sec-WebSocket-Version: 13${CRLF}${CRLF}`
      );
      const head = await client.read({ until: (s) => s.includes('\r\n\r\n') });
      assert.match(head, /^HTTP\/1\.1 101 /, 'WSS upgrade must be accepted');

      // Masked text frame 'wss-echo'
      const payload = Buffer.from('wss-echo', 'utf8');
      const mask = crypto.randomBytes(4);
      const masked = Buffer.from(payload);
      for (let i = 0; i < masked.length; i++) masked[i] ^= mask[i & 3];
      await client.send(Buffer.concat([Buffer.from([0x81, 0x80 | payload.length]), mask, masked]));

      const echoed = await client.read({ until: (s) => s.length >= 2 + payload.length });
      const buf = Buffer.from(echoed, 'latin1');
      assert.equal(buf[0] & 0x0f, 0x1, 'echo must be a text frame');
      assert.equal(buf.subarray(2, 2 + payload.length).toString('utf8'), 'wss-echo');
      assert.equal(events.messages, 1);
    } finally {
      client.destroy();
      engine.close(sid);
    }
  });

  // -------------------------------------------------------------------------
  // Config errors are loud
  // -------------------------------------------------------------------------

  it('serve() throws on malformed PEM', T, () => {
    assert.throws(
      () => engine.serve({ onRequest() {}, onAborted() {} }, { ssl: { key: 'nope', cert: 'nope' } }),
      /ssl/
    );
  });

  it('serve() throws on key/cert mismatch', T, () => {
    assert.throws(
      () =>
        engine.serve(
          { onRequest() {}, onAborted() {} },
          { ssl: { key_file_name: fixturePath('localhost.key'), cert_file_name: fixturePath('alt.pem') } }
        ),
      /ssl/
    );
  });

  it('serve() throws on a nonexistent key file', T, () => {
    assert.throws(
      () =>
        engine.serve(
          { onRequest() {}, onAborted() {} },
          { ssl: { key_file_name: fixturePath('missing.key'), cert_file_name: fixturePath('localhost.pem') } }
        ),
      /ssl/
    );
  });

  it('serve() throws on partial config (cert without key)', T, () => {
    assert.throws(
      () =>
        engine.serve(
          { onRequest() {}, onAborted() {} },
          { ssl: { cert_file_name: fixturePath('localhost.pem') } }
        ),
      /ssl requires both/
    );
  });

  it('serve() throws on a wrong passphrase', T, () => {
    assert.throws(
      () =>
        engine.serve(
          { onRequest() {}, onAborted() {} },
          {
            ssl: {
              key_file_name: fixturePath('localhost-encrypted.key'),
              cert_file_name: fixturePath('localhost.pem'),
              passphrase: 'wrong',
            },
          }
        ),
      /ssl/
    );
  });

  // -------------------------------------------------------------------------
  // Plaintext bytes on a TLS port
  // -------------------------------------------------------------------------

  it('plaintext HTTP sent to the TLS port is dropped cleanly', T, async () => {
    await withTlsServer(ok, sslFileOptions(), async (server) => {
      // Raw net socket, no TLS: the "GET " bytes are not a ClientHello.
      const closed = await new Promise((resolve, reject) => {
        const s = net.connect({ host: '127.0.0.1', port: server.port }, () => {
          s.write(`GET / HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`);
        });
        s.on('close', () => resolve(true));
        s.on('error', () => {}); // RST is acceptable
        s.setTimeout(5000, () => reject(new Error('server kept the plaintext socket open')));
      });
      assert.equal(closed, true);
      assert.equal(server.requests.length, 0, 'no request must surface');

      // ...and the server still serves proper TLS clients afterwards.
      const res = parseResponse(await rawTlsRequest(server.port, GET()));
      assert.equal(res.status, 200);
    });
  });
});
