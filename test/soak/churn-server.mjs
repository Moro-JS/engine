// The engine server half of the churn soak, in its own process so the
// parent's client sockets and their garbage never enter the measurement.
// Prints "PORT <n>" once listening; GET /__stats answers this process's RSS
// (after a forced GC when --expose-gc is on) and open fd count.
import { readdirSync } from 'node:fs';
import { loadEngine } from '../helpers.mjs';

const engine = await loadEngine();
if (!engine) {
  console.log('ERROR engine not loadable');
  process.exit(2);
}
const BODY = 'soak-' + 'x'.repeat(200);
const BIG = BODY.repeat(2000);
const fdCount = () => { try { return readdirSync('/proc/self/fd').length; } catch { return -1; } };
let served = 0, aborted = 0;
const sid = engine.serve({
  onRequest(reqId, _m, path) {
    if (path === '/__stats') {
      if (globalThis.gc) globalThis.gc();
      const stats = { rss: process.memoryUsage.rss(), fds: fdCount(), served, aborted, transport: engine.probe().transport ?? 'uv' };
      engine.respond(reqId, 200, ['content-type', 'application/json'], JSON.stringify(stats));
      return;
    }
    served++;
    if (path === '/slow') {
      setTimeout(() => engine.respond(reqId, 200, ['content-type', 'text/plain'], BODY), 20);
      return;
    }
    engine.respond(reqId, 200, ['content-type', 'text/plain'], path === '/big' ? BIG : BODY);
  },
  onAborted() { aborted++; },
}, { responseTimeoutMs: 500, idleTimeoutMs: 2000 });
const port = engine.listen(sid, '127.0.0.1', 0);
console.log(`PORT ${port}`);
process.stdin.on('data', () => { engine.close(sid); setTimeout(() => process.exit(0), 50); });
process.stdin.on('end', () => process.exit(0));
