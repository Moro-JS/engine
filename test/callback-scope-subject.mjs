// Subject for callback-scope.test.mjs: a server whose handler throws, or
// queues work that throws, in a process of its own, so that what becomes the
// process's uncaught exception can be watched. argv[2] === 'batch' serves
// through onRequestBatch. Prints `PORT <n>`, then `UNCAUGHT <message>` for
// every uncaught exception.
import engine from '../packages/engine/index.mjs';

const batch = process.argv[2] === 'batch';
process.on('uncaughtException', (e) => console.log('UNCAUGHT ' + e.message));

function handle(reqId, path) {
  if (path === '/throw') {
    // Queued before the throw: runs when the callback returns, like the work
    // of a handler that returned.
    queueMicrotask(() => engine.respond(reqId, 200, null, 'after-throw'));
    throw new Error('handler boom');
  }
  if (path === '/tick-throw') {
    process.nextTick(() => {
      throw new Error('tick boom');
    });
    engine.respond(reqId, 200, null, 'tick-throw');
    return;
  }
  engine.respond(reqId, 200, null, 'ok');
}

let buffers = null;
const callbacks = {
  onRequest(reqId, _m, path) {
    handle(reqId, path);
  },
  onAborted() {},
};
if (batch) {
  callbacks.onRequestBatch = (count) => {
    const d = buffers.descriptors, ctl = buffers.control, paths = buffers.paths;
    let i = 0;
    for (;;) {
      const reqId = d[3 * i], pi = d[3 * i + 2];
      handle(reqId, pi === 0xffffffff ? engine.getPath(reqId) : paths[pi]);
      const next = ctl[0];
      if (next === i) return i + 1;
      if (next >= count) return count;
      i = next;
    }
  };
}
const sid = engine.serve(callbacks);
if (batch) buffers = engine.getBatchBuffers(sid);
console.log('PORT ' + engine.listen(sid, '127.0.0.1', 0));
