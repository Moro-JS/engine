// TLS test helpers: fixture-PKI loaders and a raw TLS client with the same
// contract as helpers.mjs' openRaw (send/read/waitClose/destroy), so every
// existing conformance pattern works unchanged over TLS.

import tls from 'node:tls';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { wrapRawSocket } from './helpers.mjs';

const FIXTURES = fileURLToPath(new URL('./fixtures/tls/', import.meta.url));

/** Absolute path of a fixture file (file-path-shaped ssl options). */
export function fixturePath(name) {
  return FIXTURES + name;
}

/** Fixture file contents as a UTF-8 string (inline-PEM-shaped ssl options). */
export function fixturePem(name) {
  return readFileSync(FIXTURES + name, 'utf8');
}

/** The standard file-path ssl options for the localhost ECDSA identity. */
export function sslFileOptions() {
  return { key_file_name: fixturePath('localhost.key'), cert_file_name: fixturePath('localhost.pem') };
}

/** The standard inline-PEM ssl options for the localhost ECDSA identity. */
export function sslInlineOptions() {
  return { key: fixturePem('localhost.key'), cert: fixturePem('localhost.pem') };
}

/**
 * Open a raw TLS client to 127.0.0.1:port, trusting the fixture CA.
 * Resolves (after the handshake) to the raw-client contract plus `.socket`
 * for alpnProtocol/authorized inspection, plus `.waitSession(request?)` which
 * resolves with the first session ticket the server delivers (TLS 1.3 sends
 * NewSessionTicket AFTER the handshake, so the listener is attached before
 * connecting to make the capture race-free; pass a request to make first).
 *
 * opts: { alpnProtocols?, servername = 'localhost', rejectUnauthorized = true,
 *         ca?, session? (a previously captured ticket, to attempt resumption),
 *         tls? (further tls.connect options: ciphers, minVersion, maxVersion) }
 */
export async function openRawTls(port, opts = {}) {
  const socket = tls.connect({
    host: '127.0.0.1',
    port,
    servername: opts.servername ?? 'localhost',
    ca: opts.ca ?? fixturePem('ca.pem'),
    rejectUnauthorized: opts.rejectUnauthorized !== false,
    ALPNProtocols: opts.alpnProtocols,
    session: opts.session,
    ...(opts.tls ?? {}),
  });
  const firstSession = new Promise((resolve) => socket.once('session', resolve));
  const client = await wrapRawSocket(socket, 'secureConnect');
  // `request`: bytes of one request to make first. The ticket travels with
  // the first thing the server writes after the handshake: OpenSSL sends it
  // on the handshake's heels, BoringSSL keeps it for the first response (one
  // packet where there would be two), so a test that needs the ticket from
  // either library asks for something.
  client.waitSession = async (request) => {
    if (request) {
      await client.send(request);
      await client.read();
    }
    return firstSession;
  };
  return client;
}

/**
 * One-shot raw HTTPS exchange (TLS mirror of helpers.mjs rawRequest).
 */
export async function rawTlsRequest(port, bytes, opts = {}) {
  const { expectClose = false, tolerateWriteError = expectClose } = opts;
  const client = await openRawTls(port, opts);
  try {
    try {
      await client.send(bytes);
    } catch (err) {
      if (!tolerateWriteError) throw err;
    }
    return await client.read(opts);
  } finally {
    client.destroy();
  }
}
