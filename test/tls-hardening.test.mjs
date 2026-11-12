// TLS hardening suite: handshake-layer abuse. The TLS pump (src/tls.h) is a
// pure transform, so every failure here must resolve to a dropped connection
// and a healthy server - never a crash, hang, or unbounded buffer.
//
// Run with: node --test

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { loadEngine, startFixtureServer, parseResponse } from './helpers.mjs';
import { sslFileOptions, rawTlsRequest, openRawTls } from './tls-helpers.mjs';

const engine = await loadEngine();
const tlsCapable = engine?.probe?.().capabilities?.tls === true;
const skip = engine
  ? tlsCapable
    ? false
    : 'engine binary predates TLS support — TLS hardening suite skipped'
  : '@morojs/engine native binding not usable yet — TLS hardening suite skipped';

const T = { timeout: 30000 };
const CRLF = '\r\n';
const ok = (ctx) => ctx.respond(200, null, 'ok');

async function withTlsServer(handler, extraOptions, fn) {
  const server = await startFixtureServer(engine, handler, {
    ssl: sslFileOptions(),
    ...extraOptions,
  });
  try {
    return await fn(server);
  } finally {
    server.close();
  }
}

// Open a plain TCP socket to the TLS port, send `bytes`, and resolve when the
// server closes it (rejecting after `timeout`).
function sendRawExpectClose(port, bytes, timeout = 8000) {
  return new Promise((resolve, reject) => {
    const s = net.connect({ host: '127.0.0.1', port }, () => {
      if (bytes && bytes.length) s.write(bytes);
    });
    // Keep the stream flowing: without a reader the socket never consumes the
    // server's closing alert/FIN, so 'close' would never fire.
    s.resume();
    s.on('close', () => resolve());
    s.on('error', () => {}); // RST acceptable; 'close' still fires
    s.setTimeout(timeout, () => {
      s.destroy();
      reject(new Error(`server did not drop the connection within ${timeout}ms`));
    });
  });
}

describe('@morojs/engine TLS hardening', { skip }, () => {
  it('immediate garbage bytes on the TLS port are dropped', T, async () => {
    await withTlsServer(ok, {}, async (server) => {
      await sendRawExpectClose(server.port, Buffer.from([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]));
      assert.equal(server.requests.length, 0);
    });
  });

  it('a well-formed record header with garbage body is dropped', T, async () => {
    await withTlsServer(ok, {}, async (server) => {
      // TLS record: handshake(0x16), TLS1.0 legacy version, length 16, junk.
      const rec = Buffer.concat([Buffer.from([0x16, 0x03, 0x01, 0x00, 0x10]), Buffer.alloc(16, 0x41)]);
      await sendRawExpectClose(server.port, rec);
      assert.equal(server.requests.length, 0);
    });
  });

  it('a stalled handshake is reaped by the requestTimeoutMs budget', T, async () => {
    await withTlsServer(ok, { requestTimeoutMs: 500 }, async (server) => {
      const started = Date.now();
      // Partial record header, then silence: never a complete flight.
      await sendRawExpectClose(server.port, Buffer.from([0x16, 0x03, 0x01, 0x40]));
      const elapsed = Date.now() - started;
      assert.ok(elapsed < 8000, `reaped in ${elapsed}ms (budget 500ms + sweep granularity)`);
      assert.equal(server.requests.length, 0);
    });
  });

  it('a silent connection to the TLS port is reaped by idleTimeoutMs', T, async () => {
    await withTlsServer(ok, { idleTimeoutMs: 400 }, async (server) => {
      await sendRawExpectClose(server.port, null);
      assert.equal(server.requests.length, 0);
    });
  });

  // -------------------------------------------------------------------------
  // Explicit cipher/group policy (ssl.ciphers / ssl.ciphersuites /
  // ssl.ecdhCurve) - compliance-profile knobs mirroring Node's
  // tls.createSecureContext. Unset, host-OpenSSL defaults apply.
  // -------------------------------------------------------------------------

  it('ssl.ciphersuites pins the negotiated TLS 1.3 suite', T, async () => {
    await withTlsServer(
      ok,
      { ssl: { ...sslFileOptions(), ciphersuites: 'TLS_CHACHA20_POLY1305_SHA256' } },
      async (server) => {
        const client = await openRawTls(server.port);
        try {
          assert.equal(client.socket.getProtocol(), 'TLSv1.3');
          assert.equal(client.socket.getCipher().name, 'TLS_CHACHA20_POLY1305_SHA256');
          await client.send(`GET / HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`);
          const res = parseResponse(await client.read());
          assert.equal(res.status, 200, 'requests must still round-trip on the pinned suite');
        } finally {
          client.destroy();
        }
      }
    );
  });

  // -------------------------------------------------------------------------
  // The default preference, when the app names no ciphers: the linked
  // OpenSSL's own set, with the 128-bit AES-GCM suite ahead of its 256-bit
  // twin and ChaCha20 first for a client that asks for it first.
  // -------------------------------------------------------------------------

  const negotiated = async (server, tlsOptions) => {
    const client = await openRawTls(server.port, { tls: tlsOptions });
    try {
      const out = { protocol: client.socket.getProtocol(), cipher: client.socket.getCipher().name };
      await client.send(`GET / HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`);
      assert.equal(parseResponse(await client.read()).status, 200, `a request round-trips on ${out.cipher}`);
      return out;
    } finally {
      client.destroy();
    }
  };

  it('default: a TLS 1.3 client offering every suite gets AES-128-GCM', T, async () => {
    await withTlsServer(ok, { ssl: sslFileOptions() }, async (server) => {
      // Node's own client order: AES-256 first.
      assert.deepEqual(await negotiated(server, {}), {
        protocol: 'TLSv1.3',
        cipher: 'TLS_AES_128_GCM_SHA256',
      });
      assert.deepEqual(
        await negotiated(server, {
          ciphers: 'TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256',
        }),
        { protocol: 'TLSv1.3', cipher: 'TLS_AES_128_GCM_SHA256' }
      );
    });
  });

  it('default: a client that offers only AES-256-GCM still gets it', T, async () => {
    await withTlsServer(ok, { ssl: sslFileOptions() }, async (server) => {
      assert.equal(
        (await negotiated(server, { ciphers: 'TLS_AES_256_GCM_SHA384' })).cipher,
        'TLS_AES_256_GCM_SHA384'
      );
      assert.equal(
        (await negotiated(server, { ciphers: 'ECDHE-ECDSA-AES256-GCM-SHA384', maxVersion: 'TLSv1.2' })).cipher,
        'ECDHE-ECDSA-AES256-GCM-SHA384'
      );
    });
  });

  it('default: a client that lists ChaCha20 first gets ChaCha20', T, async () => {
    await withTlsServer(ok, { ssl: sslFileOptions() }, async (server) => {
      assert.equal(
        (
          await negotiated(server, {
            ciphers: 'TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384',
          })
        ).cipher,
        'TLS_CHACHA20_POLY1305_SHA256'
      );
      // ...and one that merely includes it, behind AES, gets AES-128.
      assert.equal(
        (
          await negotiated(server, {
            ciphers: 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256',
          })
        ).cipher,
        'TLS_AES_128_GCM_SHA256'
      );
    });
  });

  it('default: a TLS 1.2 client gets the ECDHE AES-128-GCM suite, or ChaCha20 when it leads with it', T, async () => {
    await withTlsServer(ok, { ssl: sslFileOptions() }, async (server) => {
      assert.deepEqual(
        await negotiated(server, {
          maxVersion: 'TLSv1.2',
          ciphers:
            'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305',
        }),
        { protocol: 'TLSv1.2', cipher: 'ECDHE-ECDSA-AES128-GCM-SHA256' }
      );
      assert.equal(
        (
          await negotiated(server, {
            maxVersion: 'TLSv1.2',
            ciphers:
              'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256',
          })
        ).cipher,
        'ECDHE-ECDSA-CHACHA20-POLY1305'
      );
    });
  });

  it('an explicit ssl.ciphersuites order is the app\'s and is left alone', T, async () => {
    await withTlsServer(
      ok,
      { ssl: { ...sslFileOptions(), ciphersuites: 'TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256' } },
      async (server) => {
        assert.equal((await negotiated(server, {})).cipher, 'TLS_AES_256_GCM_SHA384');
        // no ChaCha20 reprioritisation either: it is not in the app's list
        await assert.rejects(negotiated(server, { ciphers: 'TLS_CHACHA20_POLY1305_SHA256' }));
      }
    );
  });

  it('an explicit ssl.ciphers list leaves the TLS 1.2 order the app\'s too', T, async () => {
    await withTlsServer(
      ok,
      { ssl: { ...sslFileOptions(), ciphers: 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256' } },
      async (server) => {
        assert.equal(
          (
            await negotiated(server, {
              maxVersion: 'TLSv1.2',
              ciphers: 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384',
            })
          ).cipher,
          'ECDHE-ECDSA-AES256-GCM-SHA384'
        );
      }
    );
  });

  it('ssl.ecdhCurve pins the key-share group (HelloRetryRequest path included)', T, async () => {
    await withTlsServer(
      ok,
      { ssl: { ...sslFileOptions(), ecdhCurve: 'P-384' } },
      async (server) => {
        const client = await openRawTls(server.port);
        try {
          const eph = client.socket.getEphemeralKeyInfo();
          assert.equal(eph.name, 'secp384r1', 'key exchange must use the pinned group');
          await client.send(`GET / HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`);
          const res = parseResponse(await client.read());
          assert.equal(res.status, 200);
        } finally {
          client.destroy();
        }
      }
    );
  });

  it('invalid ssl.ciphers throws from serve() - config errors are loud, never a lax fallback', T, async () => {
    assert.throws(
      () => engine.serve({ onRequest() {} }, { ssl: { ...sslFileOptions(), ciphers: 'NO-SUCH-CIPHER' } }),
      /ciphers/
    );
    assert.throws(
      () => engine.serve({ onRequest() {} }, { ssl: { ...sslFileOptions(), ecdhCurve: 'not-a-group' } }),
      /ecdhCurve/
    );
  });

  it('a burst of failed handshakes leaves the server fully healthy', T, async () => {
    await withTlsServer(ok, {}, async (server) => {
      await Promise.all(
        Array.from({ length: 20 }, () =>
          sendRawExpectClose(server.port, Buffer.from('not a client hello at all'))
        )
      );
      const res = parseResponse(
        await rawTlsRequest(server.port, `GET / HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`)
      );
      assert.equal(res.status, 200, 'a real TLS client must still be served');
    });
  });
});
