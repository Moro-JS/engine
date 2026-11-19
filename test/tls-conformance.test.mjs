// TLS conformance suite for @morojs/engine.
//
// The engine terminates TLS in-process (OpenSSL from the host Node binary,
// memory-BIO transform in src/tls.h). This suite proves:
//   - both ssl option shapes work (file paths and inline PEM), incl. an
//     encrypted key + passphrase and an RSA identity
//   - the HTTP/1.1 machinery is unchanged under TLS (GET, POST echo,
//     keep-alive, chunked streaming, 413/431 limits, abort -> onAborted)
//   - ALPN negotiates http/1.1 (and tolerates clients with no overlap)
//   - ssl.ticketKeys (Node-compatible 48-byte layout) makes sessions resume
//     across servers sharing the keys, and only those
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
  clientCertOptions,
  withBrokenSignature,
  openShimTls,
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
  // Session tickets (ssl.ticketKeys, Node tls.Server-compatible)
  // -------------------------------------------------------------------------

  it('ticketKeys: session resumes across two servers sharing keys', T, async () => {
    const ticketKeys = crypto.randomBytes(48); // Node layout: name|hmac|aes
    const ssl = () => ({ ...sslInlineOptions(), ticketKeys });
    await withTlsServer(ok, ssl(), async (server1) => {
      await withTlsServer(ok, ssl(), async (server2) => {
        // Full handshake against server 1; capture the ticket. TLS 1.3
        // delivers NewSessionTicket after the handshake - with the first
        // response, on BoringSSL - so make a request and wait for the
        // 'session' event, not just secureConnect.
        const c1 = await openRawTls(server1.port);
        let session;
        try {
          session = await c1.waitSession(GET());
        } finally {
          c1.destroy();
        }
        // Offer the ticket to server 2: same ticket keys -> it decrypts the
        // foreign ticket and resumes.
        const c2 = await openRawTls(server2.port, { session });
        try {
          assert.equal(c2.socket.isSessionReused(), true,
            'server 2 must resume a session issued by server 1');
          await c2.send(GET());
          assert.equal(parseResponse(await c2.read()).status, 200);
        } finally {
          c2.destroy();
        }
      });
    });
  });

  it('ticketKeys: no resumption across servers with different keys', T, async () => {
    await withTlsServer(ok, { ...sslInlineOptions(), ticketKeys: crypto.randomBytes(48) },
      async (server1) => {
        await withTlsServer(ok, { ...sslInlineOptions(), ticketKeys: crypto.randomBytes(48) },
          async (server2) => {
            const c1 = await openRawTls(server1.port);
            let session;
            try {
              session = await c1.waitSession(GET());
            } finally {
              c1.destroy();
            }
            // Server 2 cannot decrypt the foreign ticket: the handshake still
            // SUCCEEDS as a full handshake, just without resumption.
            const c2 = await openRawTls(server2.port, { session });
            try {
              assert.equal(c2.socket.isSessionReused(), false,
                'a foreign ticket must fall back to a full handshake');
              await c2.send(GET());
              assert.equal(parseResponse(await c2.read()).status, 200,
                'full handshake must still serve requests');
            } finally {
              c2.destroy();
            }
          });
      });
  });

  // A resumed session skips what the full handshake decided: the client is
  // not asked for a certificate again, and under TLS 1.2 the cipher is the
  // session's. Shared ticket keys must therefore only carry a session
  // between servers that would have decided the same.
  for (const version of ['TLSv1.3', 'TLSv1.2']) {
    const only = { minVersion: version, maxVersion: version };

    it(`ticketKeys: a session from a server that asks for no client certificate does not open one that requires it (${version})`, T, async () => {
      const ticketKeys = crypto.randomBytes(48);
      const open = { ...sslInlineOptions(), ticketKeys };
      const guarded = { ...open, requestCert: true, rejectUnauthorized: true, ca: fixturePem('client-ca.pem') };
      await withTlsServer(ok, open, async (publicServer) => {
        await withTlsServer(ok, guarded, async (guardedServer) => {
          const c1 = await openRawTls(publicServer.port, { tls: only });
          let session;
          try {
            session = await c1.waitSession(GET());
          } finally {
            c1.destroy();
          }
          assert.ok(session, 'the public server issued a ticket');
          // Offered to the guarded server without a certificate: it is a
          // full handshake, and that one fails for want of a certificate.
          let served = false;
          try {
            const c2 = await openRawTls(guardedServer.port, { session, tls: only });
            try {
              await c2.send(GET('/guarded'));
              served = parseResponse(await c2.read()).status === 200;
            } finally {
              c2.destroy();
            }
          } catch {
            // refused during or right after the handshake
          }
          assert.equal(served, false, 'a client without a certificate was served by the server that requires one');
          assert.equal(guardedServer.requests.length, 0);
        });
      });
    });

    it(`ticketKeys: client-certificate sessions resume across servers with the same policy (${version})`, T, async () => {
      const ticketKeys = crypto.randomBytes(48);
      const guarded = () => ({
        ...sslInlineOptions(), ticketKeys, requestCert: true, rejectUnauthorized: true, ca: fixturePem('client-ca.pem'),
      });
      await withTlsServer(ok, guarded(), async (server1) => {
        await withTlsServer(ok, guarded(), async (server2) => {
          const c1 = await openRawTls(server1.port, { tls: { ...only, ...clientCertOptions() } });
          let session;
          try {
            session = await c1.waitSession(GET());
          } finally {
            c1.destroy();
          }
          const c2 = await openRawTls(server2.port, { session, tls: { ...only, ...clientCertOptions() } });
          try {
            assert.equal(c2.socket.isSessionReused(), true, 'the same policy on both servers: the session carries over');
            await c2.send(GET());
            assert.equal(parseResponse(await c2.read()).status, 200);
          } finally {
            c2.destroy();
          }
        });
      });
    });
  }

  it('ticketKeys: a TLS 1.2 session does not carry its cipher to a server whose list excludes it', T, async () => {
    const ticketKeys = crypto.randomBytes(48);
    const cbc = 'ECDHE-ECDSA-AES256-SHA';
    const gcm = 'ECDHE-ECDSA-AES128-GCM-SHA256';
    const client = { maxVersion: 'TLSv1.2', ciphers: `${cbc}:${gcm}:@SECLEVEL=0` };
    await withTlsServer(ok, { ...sslInlineOptions(), ticketKeys, ciphers: cbc }, async (lax) => {
      await withTlsServer(ok, { ...sslInlineOptions(), ticketKeys, ciphers: gcm }, async (strict) => {
        const c1 = await openRawTls(lax.port, { tls: client });
        let session;
        try {
          assert.equal(c1.socket.getCipher().name, cbc);
          session = await c1.waitSession(GET());
        } finally {
          c1.destroy();
        }
        const c2 = await openRawTls(strict.port, { session, tls: client });
        try {
          assert.equal(c2.socket.getCipher().name, gcm, 'the strict server speaks only what its list names');
          await c2.send(GET());
          assert.equal(parseResponse(await c2.read()).status, 200);
        } finally {
          c2.destroy();
        }
      });
    });
  });

  // -------------------------------------------------------------------------
  // Client certificates (ssl.requestCert / rejectUnauthorized / ca)
  // -------------------------------------------------------------------------

  const guardedSsl = (extra = {}) => ({
    ...sslInlineOptions(), requestCert: true, ca: fixturePem('client-ca.pem'), ...extra,
  });
  const servedWith = async (port, tlsOptions) => {
    try {
      const c = await openRawTls(port, { tls: tlsOptions });
      try {
        await c.send(GET());
        return parseResponse(await c.read()).status === 200;
      } finally {
        c.destroy();
      }
    } catch {
      return false;
    }
  };

  for (const version of ['TLSv1.3', 'TLSv1.2']) {
    const only = { minVersion: version, maxVersion: version };

    it(`requestCert: a certificate under ssl.ca is served, none or one under another CA is not (${version})`, T, async () => {
      await withTlsServer(ok, guardedSsl(), async (server) => {
        assert.equal(await servedWith(server.port, { ...only, ...clientCertOptions() }), true);
        assert.equal(await servedWith(server.port, only), false, 'no certificate');
        assert.equal(await servedWith(server.port, {
          ...only, key: fixturePem('selfsigned.key'), cert: fixturePem('selfsigned.pem'),
        }), false, 'a self-signed certificate');
        assert.equal(await servedWith(server.port, {
          ...only, key: fixturePem('client.key'), cert: withBrokenSignature(fixturePem('client.pem')),
        }), false, 'a certificate whose signature does not verify');
        assert.equal(server.requests.length, 1);
      });
      // The CA is taken from a file the same way.
      await withTlsServer(ok, { ...sslFileOptions(), requestCert: true, ca_file_name: fixturePath('client-ca.pem') }, async (server) => {
        assert.equal(await servedWith(server.port, { ...only, ...clientCertOptions() }), true);
        assert.equal(await servedWith(server.port, only), false);
      });
      // A server certificate's CA is not a client CA unless it is named as one.
      await withTlsServer(ok, guardedSsl({ ca: fixturePem('client-ca2.pem') }), async (server) => {
        assert.equal(await servedWith(server.port, { ...only, ...clientCertOptions() }), false);
      });
    });

    it(`requestCert with rejectUnauthorized: false serves any client, however its flight is split (${version})`, T, async () => {
      await withTlsServer(ok, guardedSsl({ rejectUnauthorized: false }), async (server) => {
        const broken = { key: fixturePem('client.key'), cert: withBrokenSignature(fixturePem('client.pem')) };
        assert.equal(await servedWith(server.port, only), true, 'no certificate');
        assert.equal(await servedWith(server.port, { ...only, ...broken }), true, 'a certificate that does not verify');
        // The same client with every record of its flight in a segment of
        // its own: the server sees the certificate, then has to wait for the
        // rest of the handshake.
        const { socket, raw } = await openShimTls(server.port, { ...only, ...broken, segment: true });
        try {
          const reply = new Promise((resolve, reject) => {
            let text = '';
            socket.on('data', (d) => { text += d; if (text.includes('ok-tls')) resolve(text); });
            socket.on('error', reject);
            socket.on('close', () => reject(new Error('closed before the response')));
            setTimeout(() => reject(new Error('no response')), 5000);
          });
          socket.write(GET());
          assert.equal(parseResponse(await reply).status, 200);
        } finally {
          socket.destroy();
          raw.destroy();
        }
      });
    });
  }

  const crlCapable = engine?.probe?.().capabilities?.tlsCrl === true;
  const revoked = () => ({ key: fixturePem('client-revoked.key'), cert: fixturePem('client-revoked.pem') });

  for (const version of ['TLSv1.3', 'TLSv1.2']) {
    const only = { minVersion: version, maxVersion: version };

    it(`ssl.crl: a client certificate the CA has revoked is refused (${version})`, { ...T, skip: !crlCapable }, async () => {
      // Without the list both leaves of the client CA are served...
      await withTlsServer(ok, guardedSsl(), async (server) => {
        assert.equal(await servedWith(server.port, { ...only, ...clientCertOptions() }), true);
        assert.equal(await servedWith(server.port, { ...only, ...revoked() }), true);
      });
      // ...with it, the one it lists is not.
      await withTlsServer(ok, guardedSsl({ crl: fixturePem('client-ca.crl.pem') }), async (server) => {
        assert.equal(await servedWith(server.port, { ...only, ...clientCertOptions() }), true);
        assert.equal(await servedWith(server.port, { ...only, ...revoked() }), false, 'the revoked certificate');
        assert.equal(server.requests.length, 1);
      });
    });

    it(`ssl.crl: a session made before the certificate was revoked ends with the update that revokes it (${version})`, { ...T, skip: !crlCapable }, async () => {
      const ticketKeys = crypto.randomBytes(48);
      await withTlsServer(ok, guardedSsl({ ticketKeys }), async (server) => {
        const c1 = await openRawTls(server.port, { tls: { ...only, ...revoked() } });
        let session;
        try {
          session = await c1.waitSession(GET());
        } finally {
          c1.destroy();
        }
        assert.ok(session);
        engine.updateSsl(server.serverId, guardedSsl({ crl: fixturePem('client-ca.crl.pem') }));
        const before = server.requests.length;
        let served = false;
        try {
          const c2 = await openRawTls(server.port, { session, tls: { ...only, ...revoked() } });
          try {
            await c2.send(GET());
            served = parseResponse(await c2.read()).status === 200;
          } finally {
            c2.destroy();
          }
        } catch {
          // refused during or right after the handshake
        }
        assert.equal(served, false);
        assert.equal(server.requests.length, before);
      });
    });
  }

  it('ssl.crl: malformed revocation lists throw from serve()', { ...T, skip: !crlCapable }, () => {
    for (const crl of ['not a crl', fixturePem('client-ca.pem')]) {
      assert.throws(
        () => engine.serve({ onRequest() {}, onAborted() {} }, { ssl: guardedSsl({ crl }) }),
        /crl/
      );
    }
  });

  it('ssl.maxVersion caps the protocol version', { ...T, skip: !crlCapable }, async () => {
    await withTlsServer(ok, { ...sslInlineOptions(), maxVersion: 'TLSv1.2' }, async (server) => {
      const c = await openRawTls(server.port);
      try {
        assert.equal(c.socket.getProtocol(), 'TLSv1.2');
      } finally {
        c.destroy();
      }
      assert.equal(await servedWith(server.port, { minVersion: 'TLSv1.3' }), false, 'a TLS 1.3-only client');
    });
    assert.throws(
      () => engine.serve({ onRequest() {}, onAborted() {} }, { ssl: { ...sslInlineOptions(), maxVersion: 'TLSv1.1' } }),
      /ssl\.maxVersion must be 'TLSv1\.2' or 'TLSv1\.3'/
    );
    assert.throws(
      () => engine.serve({ onRequest() {}, onAborted() {} }, { ssl: { ...sslInlineOptions(), minVersion: 'TLSv1.3', maxVersion: 'TLSv1.2' } }),
      /maxVersion is below ssl\.minVersion/
    );
  });

  it('serve() throws on wrong-length ticketKeys', T, () => {
    assert.throws(
      () =>
        engine.serve(
          { onRequest() {}, onAborted() {} },
          { ssl: { ...sslInlineOptions(), ticketKeys: crypto.randomBytes(47) } }
        ),
      /48/
    );
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

  // A send the session cannot encrypt ends the connection, and the close is
  // reported once wsSend() has returned, never from inside it: there the
  // binding may be reading a string payload straight out of the V8 heap, and
  // V8 ends the process if JS runs under that. Nothing a peer sends makes the
  // TLS library refuse to encrypt on an established session, so the failure
  // is switched on by the fault point of a test build (probe() says whether
  // this binary has it). Bytes go first: they are not read that way, so a
  // callback made inside the send fails this test instead.
  const noFaultPoints = engine?.probe?.().testFaults
    ? false
    : 'needs a build with fault points (tools/build.mjs --sanitize)';
  it('WSS: a send the session cannot encrypt reports the close after wsSend() has returned', { ...T, skip: noFaultPoints }, async () => {
    let sending = false;
    let lastWsId = 0;
    const closes = [];
    const sid = engine.serve(
      {
        onRequest(reqId) {
          lastWsId = engine.upgradeToWebSocket(reqId);
        },
        onAborted() {},
        onWsOpen() {},
        onWsMessage() {},
        onWsClose: (wsId, code) => closes.push({ wsId, code, insideSend: sending }),
      },
      { ssl: sslFileOptions() }
    );
    const port = engine.listen(sid, '127.0.0.1', 0);
    try {
      for (const payload of [Buffer.alloc(100, 0x61), 'a'.repeat(100)]) {
        const kind = typeof payload === 'string' ? 'string' : 'bytes';
        const client = await openRawTls(port);
        try {
          await client.send(
            `GET /ws HTTP/1.1${CRLF}Host: t${CRLF}Upgrade: websocket${CRLF}` +
              `Connection: Upgrade${CRLF}Sec-WebSocket-Key: ${crypto.randomBytes(16).toString('base64')}${CRLF}` +
              `Sec-WebSocket-Version: 13${CRLF}${CRLF}`
          );
          assert.match(await client.read({ until: (s) => s.includes('\r\n\r\n') }), /^HTTP\/1\.1 101 /);
          const wsId = lastWsId;
          process.env.MORO_ENGINE_TEST_FAIL_TLS_WRITE = '1';
          sending = true;
          try {
            engine.wsSend(wsId, payload, kind === 'bytes');
            engine.wsSend(wsId, payload, kind === 'bytes');
          } finally {
            sending = false;
            delete process.env.MORO_ENGINE_TEST_FAIL_TLS_WRITE;
          }
          const deadline = Date.now() + 3000;
          while (!closes.some((e) => e.wsId === wsId) && Date.now() < deadline) await new Promise((r) => setTimeout(r, 5));
          await new Promise((r) => setTimeout(r, 50));
          assert.deepEqual(
            closes.filter((e) => e.wsId === wsId),
            [{ wsId, code: 1006, insideSend: false }],
            `${kind}: one onWsClose(1006), delivered outside wsSend()`
          );
          assert.equal(engine.wsSend(wsId, 'x', false), false, `${kind}: the socket is gone`);
        } finally {
          client.destroy();
        }
      }
    } finally {
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

  it('serve() throws on a policy option of the wrong type instead of reading it as unset', T, () => {
    const wrong = [
      [{ requestCert: 1 }, /ssl\.requestCert must be a boolean/],
      [{ requestCert: 'true' }, /ssl\.requestCert must be a boolean/],
      [{ rejectUnauthorized: 0 }, /ssl\.rejectUnauthorized must be a boolean/],
      [{ minVersion: 1.3 }, /ssl\.minVersion must be a string/],
      [{ ciphers: ['ECDHE-ECDSA-AES128-GCM-SHA256'] }, /ssl\.ciphers must be a string/],
      [{ ciphersuites: ['TLS_AES_256_GCM_SHA384'] }, /ssl\.ciphersuites must be a string/],
      [{ ecdhCurve: 25519 }, /ssl\.ecdhCurve must be a string/],
      [{ passphrase: Buffer.from('moro-test') }, /ssl\.passphrase must be a string/],
    ];
    for (const [option, message] of wrong) {
      assert.throws(
        () => engine.serve({ onRequest() {}, onAborted() {} }, { ssl: { ...sslInlineOptions(), ...option } }),
        message,
        JSON.stringify(Object.keys(option))
      );
    }
    // undefined and null are "not given".
    const id = engine.serve({ onRequest() {}, onAborted() {} }, {
      ssl: { ...sslInlineOptions(), requestCert: undefined, rejectUnauthorized: null, minVersion: undefined, ciphers: null },
    });
    engine.close(id);
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
