// TLS test helpers: fixture-PKI loaders and a raw TLS client with the same
// contract as helpers.mjs' openRaw (send/read/waitClose/destroy), so every
// existing conformance pattern works unchanged over TLS.

import tls from 'node:tls';
import net from 'node:net';
import crypto from 'node:crypto';
import { Duplex } from 'node:stream';
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

/** The fixture client identity (issued by client-ca.pem), for requestCert tests. */
export function clientCertOptions() {
  return { key: fixturePem('client.key'), cert: fixturePem('client.pem') };
}

/**
 * The same PEM certificate with one byte of its signature flipped: it still
 * parses, belongs to the same key, and no longer verifies.
 */
export function withBrokenSignature(pem) {
  const der = Buffer.from(pem.replace(/-----[^-]+-----|\s/g, ''), 'base64');
  der[der.length - 5] ^= 0xff;
  return `-----BEGIN CERTIFICATE-----\n${der.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`;
}

/**
 * A node:tls client over a shim, so the test owns the TCP socket underneath.
 * `segment`: each TLS record the client writes leaves in a TCP segment of its
 * own, `gap` ms after the one before (a peer chooses its own segmentation,
 * and a flight that arrives in pieces takes the server through its
 * "need more bytes" returns). Resolves once the handshake is done with
 * { socket, raw, secrets, serverHello } - the keylog secrets by label and the
 * first bytes the server sent.
 */
export function openShimTls(port, opts = {}) {
  const { segment = false, gap = 10, ...tlsOptions } = opts;
  return new Promise((resolve, reject) => {
    const raw = net.connect({ host: '127.0.0.1', port });
    raw.setNoDelay(true);
    let chain = Promise.resolve();
    const shim = new Duplex({
      read() {},
      write(chunk, _enc, cb) {
        if (!segment) return raw.write(chunk, () => cb());
        for (let off = 0; off < chunk.length; ) {
          const len = off + 5 <= chunk.length ? 5 + chunk.readUInt16BE(off + 3) : chunk.length - off;
          const piece = chunk.subarray(off, Math.min(chunk.length, off + len));
          off += piece.length;
          chain = chain.then(() => new Promise((next) => {
            if (!raw.destroyed) raw.write(piece);
            setTimeout(next, gap);
          }));
        }
        chain.then(() => cb());
      },
    });
    let serverHello = Buffer.alloc(0);
    const feed = (d) => {
      if (serverHello.length < 64) serverHello = Buffer.concat([serverHello, d]);
      shim.push(d);
    };
    raw.on('data', feed);
    raw.on('close', () => shim.push(null));
    raw.on('error', reject);
    const secrets = {};
    const socket = tls.connect({
      socket: shim,
      servername: 'localhost',
      ca: fixturePem('ca.pem'),
      ...tlsOptions,
    });
    socket.on('keylog', (line) => {
      const [label, random, secret] = line.toString().trim().split(' ');
      secrets[label] = { random: Buffer.from(random, 'hex'), secret: Buffer.from(secret, 'hex') };
    });
    socket.on('error', reject);
    socket.on('secureConnect', () => resolve({ socket, raw, secrets, serverHello, detach: () => raw.off('data', feed) }));
  });
}

function hkdfExpandLabel(secret, label, length) {
  const full = Buffer.from(`tls13 ${label}`);
  const info = Buffer.concat([Buffer.from([0, length, full.length]), full, Buffer.from([0, 1])]);
  return crypto.createHmac('sha256', secret).update(info).digest().subarray(0, length);
}

/**
 * Records a TLS 1.3 client may send after the handshake, written by hand
 * under the client's application traffic secret (TLS_AES_128_GCM_SHA256):
 * what node:tls has no call for, such as a KeyUpdate.
 */
class Tls13RecordWriter {
  constructor(secret) {
    this.rekey(secret);
  }
  rekey(secret) {
    this.secret = secret;
    this.key = hkdfExpandLabel(secret, 'key', 16);
    this.iv = hkdfExpandLabel(secret, 'iv', 12);
    this.seq = 0n;
  }
  record(type, payload) {
    const inner = Buffer.concat([payload, Buffer.from([type])]);
    const header = Buffer.from([0x17, 3, 3, (inner.length + 16) >> 8, (inner.length + 16) & 255]);
    const nonce = Buffer.from(this.iv);
    const seq = Buffer.alloc(12);
    seq.writeBigUInt64BE(this.seq++, 4);
    for (let i = 0; i < 12; i++) nonce[i] ^= seq[i];
    const cipher = crypto.createCipheriv('aes-128-gcm', this.key, nonce);
    cipher.setAAD(header);
    return Buffer.concat([header, cipher.update(inner), cipher.final(), cipher.getAuthTag()]);
  }
  applicationData(bytes) {
    return this.record(0x17, Buffer.from(bytes));
  }
  /** KeyUpdate(update_requested): the peer must answer with one of its own (RFC 8446 4.6.3). */
  keyUpdate() {
    const record = this.record(0x16, Buffer.from([24, 0, 0, 1, 1]));
    this.rekey(hkdfExpandLabel(this.secret, 'traffic upd', 32));
    return record;
  }
}

/** The same for TLS 1.2 with ECDHE-ECDSA-AES128-GCM-SHA256. */
class Tls12RecordWriter {
  constructor(key, iv) {
    this.key = key;
    this.iv = iv;
    this.seq = 1n; // the client's Finished was record 0
  }
  record(type, payload) {
    const seq = Buffer.alloc(8);
    seq.writeBigUInt64BE(this.seq++);
    const aad = Buffer.concat([seq, Buffer.from([type, 3, 3, payload.length >> 8, payload.length & 255])]);
    const cipher = crypto.createCipheriv('aes-128-gcm', this.key, Buffer.concat([this.iv, seq]));
    cipher.setAAD(aad);
    const body = Buffer.concat([seq, cipher.update(payload), cipher.final(), cipher.getAuthTag()]);
    return Buffer.concat([Buffer.from([type, 3, 3, body.length >> 8, body.length & 255]), body]);
  }
  /** A ClientHello header on an established connection: a renegotiation request. */
  renegotiationRequest() {
    return this.record(0x16, Buffer.from([1, 0, 0, 0]));
  }
}

/**
 * Handshake with node:tls, then hand the test the TCP socket and a record
 * writer keyed for what the client sends next. `version`: 'TLSv1.3' or
 * 'TLSv1.2'. The socket is paused: nothing the server sends is read until
 * the test resumes it.
 */
export async function openTakenOverTls(port, version = 'TLSv1.3') {
  const tls13 = version === 'TLSv1.3';
  const { raw, secrets, serverHello, detach } = await openShimTls(port, {
    minVersion: version,
    maxVersion: version,
    ...(tls13 ? { ciphersuites: 'TLS_AES_128_GCM_SHA256' } : { ciphers: 'ECDHE-ECDSA-AES128-GCM-SHA256' }),
  });
  detach();
  raw.pause();
  raw.removeAllListeners('error');
  raw.on('error', () => {});
  if (tls13) return { raw, writer: new Tls13RecordWriter(secrets.CLIENT_TRAFFIC_SECRET_0.secret) };
  // RFC 5246 6.3: key_block = PRF(master_secret, "key expansion", server_random + client_random);
  // for an AEAD suite it is the two write keys, then the two implicit IVs.
  const { random: clientRandom, secret: master } = secrets.CLIENT_RANDOM;
  const serverRandom = serverHello.subarray(11, 43); // record header 5, handshake header 4, version 2
  const seed = Buffer.concat([Buffer.from('key expansion'), serverRandom, clientRandom]);
  const hmac = (...parts) => {
    const h = crypto.createHmac('sha256', master);
    for (const part of parts) h.update(part);
    return h.digest();
  };
  const a1 = hmac(seed);
  const block = Buffer.concat([hmac(a1, seed), hmac(hmac(a1), seed)]);
  return { raw, writer: new Tls12RecordWriter(block.subarray(0, 16), block.subarray(32, 36)) };
}
