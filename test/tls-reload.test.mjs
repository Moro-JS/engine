// TLS certificate reload (updateSsl) conformance for @morojs/engine.
//
// Proves that updateSsl(serverId, ssl):
//   - serves the NEW certificate to every handshake that starts afterwards
//   - leaves a connection that handshaked before the swap fully usable
//     (its SSL_CTX is refcounted by the session, not freed under it)
//   - rejects invalid material (bad PEM, key/cert mismatch, missing file,
//     partial config) with a throw and keeps serving the OLD certificate
//   - refuses a server that was not started with ssl
//   - keeps session-ticket keys across a rotation when the update omits them
//   - accepts both option shapes (file paths and inline PEM)
//
// Run with: node --test

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import tls from 'node:tls';
import { loadEngine, startFixtureServer, parseResponse } from './helpers.mjs';
import {
  fixturePath,
  fixturePem,
  sslFileOptions,
  sslInlineOptions,
  openRawTls,
  rawTlsRequest,
  clientCertOptions,
} from './tls-helpers.mjs';

const engine = await loadEngine();
const reloadCapable = engine?.probe?.().capabilities?.tlsReload === true;
const skip = engine
  ? reloadCapable
    ? false
    : 'engine binary predates updateSsl — TLS reload suite skipped'
  : '@morojs/engine native binding not usable yet — TLS reload suite skipped';

const T = { timeout: 30000 };
const CRLF = '\r\n';
const GET = (path = '/') => `GET ${path} HTTP/1.1${CRLF}Host: t${CRLF}${CRLF}`;
const ok = (ctx) => ctx.respond(200, ['content-type', 'text/plain'], 'ok-tls');

/** SHA-256 fingerprint of the certificate a fresh handshake is shown. */
function peerFingerprint(port) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      { host: '127.0.0.1', port, servername: 'localhost', rejectUnauthorized: false },
      () => {
        const fp = socket.getPeerCertificate().fingerprint256;
        socket.destroy();
        resolve(fp);
      }
    );
    socket.on('error', reject);
  });
}

function fingerprintOf(pemName) {
  const cert = new crypto.X509Certificate(fixturePem(pemName));
  return cert.fingerprint256;
}

const altFileOptions = () => ({
  key_file_name: fixturePath('alt.key'),
  cert_file_name: fixturePath('alt.pem'),
});
const altInlineOptions = () => ({ key: fixturePem('alt.key'), cert: fixturePem('alt.pem') });

describe('@morojs/engine TLS reload (updateSsl)', { skip }, () => {
  it('new handshakes see the new certificate after updateSsl (file paths)', T, async () => {
    const server = await startFixtureServer(engine, ok, { ssl: sslFileOptions() });
    try {
      assert.equal(await peerFingerprint(server.port), fingerprintOf('localhost.pem'));
      engine.updateSsl(server.serverId, altFileOptions());
      assert.equal(await peerFingerprint(server.port), fingerprintOf('alt.pem'));
      // and the listener still answers requests over the new identity
      const res = parseResponse(
        await rawTlsRequest(server.port, GET(), { rejectUnauthorized: false })
      );
      assert.equal(res.status, 200);
      assert.equal(res.body, 'ok-tls');
    } finally {
      server.close();
    }
  });

  it('accepts the inline-PEM shape too', T, async () => {
    const server = await startFixtureServer(engine, ok, { ssl: sslInlineOptions() });
    try {
      engine.updateSsl(server.serverId, altInlineOptions());
      assert.equal(await peerFingerprint(server.port), fingerprintOf('alt.pem'));
    } finally {
      server.close();
    }
  });

  it('a connection established before the swap keeps working', T, async () => {
    const server = await startFixtureServer(engine, ok, { ssl: sslFileOptions() });
    try {
      const before = await openRawTls(server.port);
      assert.equal(before.socket.getPeerCertificate().fingerprint256, fingerprintOf('localhost.pem'));
      engine.updateSsl(server.serverId, altFileOptions());
      // keep-alive request on the OLD session after the context was replaced
      for (let i = 0; i < 3; i++) {
        await before.send(GET(`/keepalive/${i}`));
        const res = parseResponse(await before.read());
        assert.equal(res.status, 200);
        assert.equal(res.body, 'ok-tls');
      }
      before.destroy();
      // while a NEW connection is shown the new certificate
      assert.equal(await peerFingerprint(server.port), fingerprintOf('alt.pem'));
    } finally {
      server.close();
    }
  });

  it('invalid material throws and the old certificate keeps serving', T, async () => {
    const server = await startFixtureServer(engine, ok, { ssl: sslFileOptions() });
    try {
      const bad = [
        { key: 'not a pem', cert: fixturePem('alt.pem') },
        { key: fixturePem('localhost.key'), cert: fixturePem('alt.pem') }, // mismatch
        { key_file_name: fixturePath('does-not-exist.key'), cert_file_name: fixturePath('alt.pem') },
        { cert: fixturePem('alt.pem') }, // partial
        { key: fixturePem('alt.key'), cert: fixturePem('alt.pem'), minVersion: 'TLSv1.1' },
      ];
      for (const ssl of bad) {
        assert.throws(() => engine.updateSsl(server.serverId, ssl), /ssl/);
        assert.equal(await peerFingerprint(server.port), fingerprintOf('localhost.pem'));
      }
      assert.throws(() => engine.updateSsl(server.serverId), /requires an ssl options object/);
    } finally {
      server.close();
    }
  });

  it('refuses a server that was not started with ssl', T, async () => {
    const server = await startFixtureServer(engine, ok, {});
    try {
      assert.throws(
        () => engine.updateSsl(server.serverId, altFileOptions()),
        /not started with ssl/
      );
    } finally {
      server.close();
    }
  });

  it('throws for an unknown serverId', T, async () => {
    assert.throws(() => engine.updateSsl(999999, altFileOptions()), /invalid serverId/);
  });

  it('session-ticket keys carry over when the update omits them', T, async () => {
    const ticketKeys = crypto.randomBytes(48);
    const server = await startFixtureServer(engine, ok, {
      ssl: { ...sslFileOptions(), ticketKeys },
    });
    try {
      const first = await openRawTls(server.port);
      const session = await first.waitSession(GET());
      first.destroy();
      assert.ok(session, 'server issued a session ticket');

      engine.updateSsl(server.serverId, altFileOptions());

      // A ticket minted under the old context resumes on the new one because
      // the keys were carried over...
      const resumed = await openRawTls(server.port, { session, rejectUnauthorized: false });
      assert.equal(resumed.socket.isSessionReused(), true);
      resumed.destroy();

      // ...and stops resuming once an update installs different keys.
      engine.updateSsl(server.serverId, { ...altFileOptions(), ticketKeys: crypto.randomBytes(48) });
      const fresh = await openRawTls(server.port, { session, rejectUnauthorized: false });
      assert.equal(fresh.socket.isSessionReused(), false);
      fresh.destroy();
    } finally {
      server.close();
    }
  });

  // The ticket keys carry over, the client-certificate policy does not: a
  // session whose certificate was verified against the CA the update removed
  // would otherwise keep resuming, with no certificate asked for, until its
  // ticket ran out.
  for (const version of ['TLSv1.3', 'TLSv1.2']) {
    it(`a session verified against a client CA the update replaced is not resumed (${version})`, T, async () => {
      const only = { minVersion: version, maxVersion: version, ...clientCertOptions() };
      const guarded = (ca) => ({ ...sslInlineOptions(), requestCert: true, rejectUnauthorized: true, ca: fixturePem(ca) });
      const server = await startFixtureServer(engine, ok, {
        ssl: { ...guarded('client-ca.pem'), ticketKeys: crypto.randomBytes(48) },
      });
      const attempt = async (session) => {
        try {
          const c = await openRawTls(server.port, { session, tls: only });
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
      try {
        const first = await openRawTls(server.port, { tls: only });
        const session = await first.waitSession(GET());
        first.destroy();
        assert.ok(session, 'server issued a session ticket');

        // The same policy again (a certificate rotation): the session lives on.
        engine.updateSsl(server.serverId, { ...guarded('client-ca.pem'), key: fixturePem('alt.key'), cert: fixturePem('alt.pem') });
        const kept = await openRawTls(server.port, { session, rejectUnauthorized: false, tls: only });
        assert.equal(kept.socket.isSessionReused(), true);
        kept.destroy();

        // The client CA replaced: the client's certificate is no longer
        // accepted, with its old session or without.
        engine.updateSsl(server.serverId, guarded('client-ca2.pem'));
        const before = server.requests.length;
        assert.equal(await attempt(undefined), false, 'a full handshake under the new CA');
        assert.equal(await attempt(session), false, 'the session from before the update');
        assert.equal(server.requests.length, before);
      } finally {
        server.close();
      }
    });
  }
});
