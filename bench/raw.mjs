// Raw hello-world throughput: @morojs/engine vs raw uWebSockets.js vs node:http.
// Not a MoroJS benchmark - measures the engine's own ceiling for the M1 gate.
//
//   node bench/raw.mjs engine     # this engine
//   node bench/raw.mjs node       # node:http baseline
//   node bench/raw.mjs uws        # raw uWebSockets.js (if installed)
//
// Each mode serves the same {"hello":"world"} JSON on '/', and prints
// "LISTENING <actual port>" once bound (PORT=0 picks an ephemeral port —
// bench/run.sh parses this line). Driven externally by autocannon.

import { pathToFileURL } from 'node:url';

const mode = process.argv[2] || 'engine';
const PORT = parseInt(process.env.PORT || '0', 10);
const BODY = JSON.stringify({ hello: 'world' });

if (mode === 'engine') {
  const engine = (await import(new URL('../packages/engine/index.mjs', import.meta.url)))
    .default;
  const headers = ['content-type', 'application/json'];
  const sid = engine.serve({
    onRequest(reqId) {
      engine.respond(reqId, 200, headers, BODY);
    },
    onAborted() {},
  });
  const port = engine.listen(sid, '127.0.0.1', PORT);
  console.log('LISTENING', port);
} else if (mode === 'node') {
  const http = await import('node:http');
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(BODY);
  });
  server.listen(PORT, '127.0.0.1', () => {
    console.log('LISTENING', server.address().port);
  });
} else if (mode === 'uws') {
  // uWS isn't a dep of the engine repo; resolve it from a sibling MoroJS
  // checkout by default, or point UWS_PATH at any uws.js. import() gets the
  // URL object directly (never .pathname, which percent-encodes spaces/%).
  const uwsUrl = process.env.UWS_PATH
    ? pathToFileURL(process.env.UWS_PATH)
    : new URL('../../MoroJS/node_modules/uWebSockets.js/uws.js', import.meta.url);
  const mod = await import(uwsUrl);
  const uws = mod.default ?? mod;
  uws
    .App()
    .any('/*', res => {
      res.writeHeader('content-type', 'application/json').end(BODY);
    })
    .listen('127.0.0.1', PORT, token => {
      if (!token) {
        console.error('uws listen failed');
        process.exit(1);
      }
      // Resolve the actual bound port for PORT=0; older uws builds without
      // us_socket_local_port fall back to the requested port.
      const port =
        typeof uws.us_socket_local_port === 'function' ? uws.us_socket_local_port(token) : PORT;
      console.log('LISTENING', port);
    });
}
