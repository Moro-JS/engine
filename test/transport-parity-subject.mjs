// Child process for test/transport-parity.test.mjs: one engine server (plus
// a TLS twin) whose handler covers every response shape, started under
// whichever transport the parent pinned via MORO_ENGINE_TRANSPORT. Prints one
// JSON line {transport, port, tlsPort} once both listeners are up, then waits
// for 'exit' on stdin.
import { fileURLToPath } from 'node:url';
import { loadEngine } from './helpers.mjs';

const engine = await loadEngine();
if (!engine) {
  console.log(JSON.stringify({ error: 'engine not loadable' }));
  process.exit(2);
}
const info = engine.probe();
const caps = info.capabilities || {};
const FIX = fileURLToPath(new URL('./fixtures/tls/', import.meta.url));

function handler(reqId, methodIdx, path) {
  switch (path) {
    case '/plain':
      return engine.respond(reqId, 200, ['content-type', 'text/plain'], 'hello, transport');
    case '/nocontent':
      return engine.respond(reqId, 204, ['x-empty', '1'], null);
    case '/notmod':
      return engine.respond(reqId, 304, ['etag', '"abc"'], null);
    case '/chunked':
      engine.writeHead(reqId, 200, ['content-type', 'text/plain']);
      engine.write(reqId, 'first-');
      engine.write(reqId, 'second-');
      return engine.end(reqId, 'third');
    case '/echo': {
      const body = engine.getBody(reqId);
      const text = typeof body === 'string' ? body : Buffer.from(body ?? '').toString('latin1');
      return engine.respond(reqId, 200, ['content-type', 'application/octet-stream'], `echo:${text}`);
    }
    case '/latin1':
      return engine.respond(reqId, 200, ['content-type', 'text/plain; charset=iso-8859-1'], 'café crème');
    case '/tpl':
      if (tplId > 0) return engine.respondPrepared(reqId, tplId, 'templated');
      return engine.respond(reqId, 200, ['content-type', 'text/plain'], 'templated');
    case '/ws': {
      const wsId = engine.upgradeToWebSocket(reqId);
      if (wsId === -1) engine.respond(reqId, 400, null, 'not an upgrade');
      return;
    }
    default:
      return engine.respond(reqId, 404, ['content-type', 'text/plain'], 'nope');
  }
}
const callbacks = {
  onRequest: handler,
  onAborted() {},
  onWritable() {},
  onWsOpen() {},
  onWsMessage(wsId, data, isBinary) {
    engine.wsSend(wsId, data, isBinary);
  },
  onWsClose() {},
};
// Small limits so 413/431 are cheap to trigger.
const limits = { maxBodySize: 1024, maxHeadSize: 2048, requestTimeoutMs: 5000, responseTimeoutMs: 5000 };

const sid = engine.serve(callbacks, limits);
let tplId = 0;
if (caps.responseTemplates && typeof engine.prepareResponse === 'function') {
  tplId = engine.prepareResponse(sid, 200, ['content-type', 'text/plain']);
}
if (caps.staticRoutes && typeof engine.setStaticRoute === 'function') {
  engine.setStaticRoute(sid, 0, '/static', 200, ['content-type', 'text/plain'], 'static-body');
} else {
  // No static routes on this engine: the handler answers the same bytes.
  const inner = callbacks.onRequest;
  callbacks.onRequest = (reqId, m, path) =>
    path === '/static' ? engine.respond(reqId, 200, ['content-type', 'text/plain'], 'static-body') : inner(reqId, m, path);
}
const port = engine.listen(sid, '127.0.0.1', 0);

let tlsPort = 0;
let tlsSid = -1;
if (caps.tls !== false) {
  try {
    tlsSid = engine.serve(callbacks, {
      ...limits,
      ssl: { key_file_name: FIX + 'localhost.key', cert_file_name: FIX + 'localhost.pem' },
    });
    tlsPort = engine.listen(tlsSid, '127.0.0.1', 0);
  } catch {
    tlsPort = 0;
  }
}

console.log(JSON.stringify({ transport: info.transport ?? 'uv', reason: info.transportReason ?? '', port, tlsPort }));

process.stdin.setEncoding('utf8');
process.stdin.on('data', (d) => {
  if (String(d).includes('exit')) {
    engine.close(sid);
    if (tlsSid >= 0) engine.close(tlsSid);
    setTimeout(() => process.exit(0), 50);
  }
});
process.stdin.on('end', () => process.exit(0));
