// Test helpers for the @morojs/engine HTTP/1.1 conformance suite.
//
// The native binding is developed in parallel with these tests: loadEngine()
// resolves to null when the binary is missing, probe() fails, or serve() is
// not implemented yet — and the conformance suite skips itself cleanly.

import net from 'node:net';

// Mirror of the engine's method index table (docs/API.md).
export const METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'OTHER'];

const ENGINE_ENTRY = new URL('../packages/engine/index.mjs', import.meta.url);

/**
 * Load @morojs/engine if (and only if) it is usable for HTTP conformance
 * testing. Returns null when:
 *   - the package cannot be imported at all,
 *   - probe().ok is not true (no binary for this platform/ABI),
 *   - serve() is not a function yet (binding exists but M1 not landed).
 */
export async function loadEngine() {
  let engine;
  try {
    ({ default: engine } = await import(ENGINE_ENTRY.href));
  } catch {
    return null;
  }
  try {
    const info = engine.probe();
    if (!info || info.ok !== true) return null;
    if (typeof engine.serve !== 'function') return null;
  } catch {
    return null;
  }
  return engine;
}

/**
 * Start a fixture server: engine.serve() with an onRequest that wraps the
 * raw reqId in a small ctx and hands it to `handler(ctx)`.
 *
 * Resolves to { port, close, serverId, aborted, requests }:
 *   - aborted:  reqIds for which onAborted fired
 *   - requests: { reqId, method, path } for every onRequest invocation
 *     (lets tests assert the handler was NOT invoked, e.g. 413/smuggling)
 *
 * engine.listen()'s return value is awaited, so both the real synchronous
 * binding (returns a number) and a promise-returning reference
 * implementation work unchanged.
 */
export async function startFixtureServer(engine, handler, options = {}) {
  const aborted = [];
  const requests = [];
  const writableWaiters = new Map();

  const notifyWritable = (reqId) => {
    const resolve = writableWaiters.get(reqId);
    if (resolve) {
      writableWaiters.delete(reqId);
      resolve();
    }
  };

  const callbacks = {
    onRequest(reqId, methodIdx, path) {
      const ctx = {
        reqId,
        method: METHODS[methodIdx] ?? 'OTHER',
        path,
        query: () => engine.getQuery(reqId),
        headers: () => engine.getHeaders(reqId),
        header: (name) => engine.getHeader(reqId, name),
        body: () => engine.getBody(reqId),
        remoteAddress: () => engine.getRemoteAddress(reqId),
        isAborted: () => engine.isAborted(reqId),
        respond: (status, headersFlat = null, body = null) =>
          engine.respond(reqId, status, headersFlat, body),
        writeHead: (status, headersFlat = null) => engine.writeHead(reqId, status, headersFlat),
        write: (chunk) => engine.write(reqId, chunk),
        end: (chunk) => (chunk === undefined ? engine.end(reqId) : engine.end(reqId, chunk)),
        waitWritable: () => new Promise((resolve) => writableWaiters.set(reqId, resolve)),
      };
      requests.push({ reqId, method: ctx.method, path });
      let result;
      try {
        result = handler(ctx);
      } catch (err) {
        safeErrorRespond(engine, reqId, err);
        return;
      }
      if (result && typeof result.then === 'function') {
        result.catch((err) => safeErrorRespond(engine, reqId, err));
      }
    },
    onAborted(reqId) {
      aborted.push(reqId);
      notifyWritable(reqId); // unblock any writer waiting on backpressure
    },
    onWritable(reqId) {
      notifyWritable(reqId);
    },
  };

  // Every key is a serve option (maxBodySize, requestTimeoutMs, reusePort, ...)
  const serveOptions = Object.keys(options).length ? options : undefined;
  const serverId = engine.serve(callbacks, serveOptions);
  const port = await listenAnyPort(engine, serverId);

  let closed = false;
  return {
    serverId,
    port,
    aborted,
    requests,
    close() {
      if (closed) return;
      closed = true;
      engine.close(serverId);
    },
  };
}

function safeErrorRespond(engine, reqId, err) {
  try {
    engine.respond(reqId, 500, null, `fixture handler error: ${err && err.stack ? err.stack : err}`);
  } catch {
    // reqId may already be finished/aborted — a fixture bug should not crash the run
  }
}

// Prefer ephemeral port 0 (listen() returns the actual bound port); if the
// engine does not support it yet, probe random ports in 20000-25000.
async function listenAnyPort(engine, serverId) {
  try {
    const port = await engine.listen(serverId, '127.0.0.1', 0);
    if (Number.isInteger(port) && port > 0) return port;
  } catch {
    // fall through to random probing
  }
  let lastErr = null;
  for (let attempt = 0; attempt < 25; attempt++) {
    const candidate = 20000 + Math.floor(Math.random() * 5001);
    try {
      const port = await engine.listen(serverId, '127.0.0.1', candidate);
      if (Number.isInteger(port) && port > 0) return port;
    } catch (err) {
      lastErr = err;
    }
  }
  throw new Error(
    `could not bind a fixture port: ${lastErr ? lastErr.message : 'listen() returned no port'}`
  );
}

/**
 * Open a raw TCP client to 127.0.0.1:port. Resolves to:
 *   { closed, send(bytes), read(opts), waitClose(timeout), destroy() }
 *
 * read({ until?, quiescence = 150, timeout = 5000, expectClose = false })
 * collects bytes until:
 *   - `until(bufferedString)` returns true,      or
 *   - the server closes the socket,              or
 *   - 150ms of silence after at least one byte (unless expectClose), or
 *   - the overall timeout (rejects when expectClose or when zero bytes seen).
 * It returns (and consumes) the buffered bytes as a latin1 string; bytes
 * arriving later are kept for the next read() (keep-alive flows).
 */
export function openRaw(port, host = '127.0.0.1') {
  return wrapRawSocket(net.connect({ host, port }), 'connect');
}

/**
 * Wrap an already-constructed duplex socket (net or tls) in the raw-client
 * contract above. `readyEvent` is the event that signals the transport is
 * usable ('connect' for net, 'secureConnect' for tls). The underlying socket
 * is exposed as `.socket` (ALPN / authorized inspection in TLS suites).
 */
export function wrapRawSocket(socket, readyEvent = 'connect') {
  return new Promise((resolveConnect, rejectConnect) => {
    socket.setNoDelay(true);

    let connected = false;
    let closed = false;
    let buffer = Buffer.alloc(0);
    const waiters = new Set();

    socket.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      for (const w of [...waiters]) w.onData();
    });
    socket.on('error', (err) => {
      if (!connected) rejectConnect(err);
      // post-connect errors (ECONNRESET/EPIPE) surface via 'close'
    });
    socket.on('close', () => {
      closed = true;
      for (const w of [...waiters]) w.onClose();
    });

    const client = {
      get closed() {
        return closed;
      },
      get socket() {
        return socket;
      },
      destroy() {
        socket.destroy();
      },
      send(bytes) {
        return new Promise((resolve, reject) => {
          if (closed) return reject(new Error('socket already closed'));
          socket.write(Buffer.from(bytes, 'latin1'), (err) => (err ? reject(err) : resolve()));
        });
      },
      read({ until = null, quiescence = 150, timeout = 5000, expectClose = false } = {}) {
        return new Promise((resolve, reject) => {
          let finished = false;
          let quietTimer = null;
          let overallTimer = null;

          function finish(err) {
            if (finished) return;
            finished = true;
            clearTimeout(quietTimer);
            clearTimeout(overallTimer);
            waiters.delete(waiter);
            if (err) return reject(err);
            const out = buffer.toString('latin1');
            buffer = Buffer.alloc(0);
            resolve(out);
          }

          function check() {
            if (until && until(buffer.toString('latin1'))) return finish();
            if (!expectClose && buffer.length > 0) {
              clearTimeout(quietTimer);
              quietTimer = setTimeout(() => finish(), quiescence);
            }
          }

          const waiter = { onData: check, onClose: () => finish() };
          overallTimer = setTimeout(() => {
            if (expectClose) {
              finish(new Error(`server did not close the connection within ${timeout}ms`));
            } else if (buffer.length > 0) {
              finish();
            } else {
              finish(new Error(`no response bytes within ${timeout}ms`));
            }
          }, timeout);
          waiters.add(waiter);
          if (closed) return finish();
          check();
        });
      },
      waitClose(timeout = 5000) {
        return new Promise((resolve, reject) => {
          if (closed) return resolve();
          const timer = setTimeout(() => {
            waiters.delete(waiter);
            reject(new Error(`socket not closed within ${timeout}ms`));
          }, timeout);
          const waiter = {
            onData: () => {},
            onClose: () => {
              clearTimeout(timer);
              waiters.delete(waiter);
              resolve();
            },
          };
          waiters.add(waiter);
        });
      },
    };

    socket.once(readyEvent, () => {
      connected = true;
      resolveConnect(client);
    });
  });
}

/**
 * One-shot raw HTTP exchange: connect, write `bytes`, collect the response,
 * destroy the socket. Options are passed through to read(); additionally:
 *   - expectClose: rejects unless the server closes the connection
 *   - tolerateWriteError (defaults to expectClose): ignore EPIPE/RST while
 *     writing (the server may legally slam the door mid-request)
 */
export async function rawRequest(port, bytes, opts = {}) {
  const { expectClose = false, tolerateWriteError = expectClose } = opts;
  const client = await openRaw(port);
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

/**
 * Parse one HTTP response off the front of `raw`.
 * Returns { complete, statusLine, status, headers, rawHeaders, body, rest }.
 *   - headers: object keyed by lowercased name (duplicates comma-joined)
 *   - body: chunked transfer-encoding is decoded transparently
 *   - rest: bytes following this response (pipelining / interim responses)
 *   - opts.noBody: for HEAD responses (content-length present, no body bytes)
 * 1xx/204/304 responses are treated as body-less per RFC 9112.
 */
export function parseResponse(raw, { noBody = false } = {}) {
  const headEnd = raw.indexOf('\r\n\r\n');
  if (headEnd === -1) {
    return { complete: false, statusLine: null, status: null, headers: {}, rawHeaders: [], body: '', rest: raw };
  }
  const lines = raw.slice(0, headEnd).split('\r\n');
  const statusLine = lines[0];
  const m = /^HTTP\/(\d\.\d) (\d{3})(?: (.*))?$/.exec(statusLine);
  if (!m) throw new Error(`malformed status line: ${JSON.stringify(statusLine)}`);
  const status = Number(m[2]);

  const headers = {};
  const rawHeaders = [];
  for (const line of lines.slice(1)) {
    const idx = line.indexOf(':');
    if (idx === -1) throw new Error(`malformed header line: ${JSON.stringify(line)}`);
    const key = line.slice(0, idx).trim().toLowerCase();
    const value = line.slice(idx + 1).trim();
    rawHeaders.push(line.slice(0, idx).trim(), value);
    headers[key] = key in headers ? `${headers[key]}, ${value}` : value;
  }

  let rest = raw.slice(headEnd + 4);
  let body = '';
  let complete = true;
  const bodyless = noBody || status === 204 || status === 304 || (status >= 100 && status < 200);

  if (!bodyless) {
    const te = (headers['transfer-encoding'] || '').toLowerCase();
    if (te.includes('chunked')) {
      const decoded = decodeChunked(rest);
      body = decoded.body;
      rest = decoded.rest;
      complete = decoded.complete;
    } else if (headers['content-length'] !== undefined) {
      const len = Number(headers['content-length']);
      if (!Number.isInteger(len) || len < 0) {
        throw new Error(`bad content-length: ${headers['content-length']}`);
      }
      if (rest.length < len) {
        complete = false;
        body = rest;
        rest = '';
      } else {
        body = rest.slice(0, len);
        rest = rest.slice(len);
      }
    } else {
      // no framing: body delimited by connection close
      body = rest;
      rest = '';
    }
  }

  return { complete, statusLine, status, headers, rawHeaders, body, rest };
}

/** Decode a chunked-encoded body. Returns { complete, body, rest }. */
export function decodeChunked(s) {
  let body = '';
  let pos = 0;
  for (;;) {
    const lineEnd = s.indexOf('\r\n', pos);
    if (lineEnd === -1) return { complete: false, body, rest: '' };
    const sizeLine = s.slice(pos, lineEnd);
    const size = parseInt(sizeLine.split(';')[0].trim(), 16);
    if (Number.isNaN(size)) throw new Error(`malformed chunk size line: ${JSON.stringify(sizeLine)}`);
    pos = lineEnd + 2;
    if (size === 0) {
      // trailers (usually none) terminated by an empty line
      for (;;) {
        const tEnd = s.indexOf('\r\n', pos);
        if (tEnd === -1) return { complete: false, body, rest: '' };
        const trailerLine = s.slice(pos, tEnd);
        pos = tEnd + 2;
        if (trailerLine === '') return { complete: true, body, rest: s.slice(pos) };
      }
    }
    if (s.length < pos + size + 2) return { complete: false, body: body + s.slice(pos), rest: '' };
    body += s.slice(pos, pos + size);
    pos += size + 2; // chunk data + trailing CRLF
  }
}

/** Parse all complete responses at the front of `raw`, in order. */
export function parseResponses(raw, opts) {
  const out = [];
  let rest = raw;
  while (rest.length > 0) {
    let res;
    try {
      res = parseResponse(rest, opts);
    } catch {
      break;
    }
    if (!res.complete) break;
    out.push(res);
    if (res.rest === rest) break;
    rest = res.rest;
  }
  return out;
}

/** read() `until` predicate: n complete responses have been buffered. */
export const responsesComplete = (n = 1, opts) => (raw) => parseResponses(raw, opts).length >= n;

export const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** Poll `predicate` until true or `timeout` elapses (then throw `message`). */
export async function waitFor(predicate, { timeout = 2000, interval = 10, message = 'condition not met in time' } = {}) {
  const deadline = Date.now() + timeout;
  for (;;) {
    if (predicate()) return;
    if (Date.now() >= deadline) break;
    await delay(interval);
  }
  if (predicate()) return;
  throw new Error(message);
}
