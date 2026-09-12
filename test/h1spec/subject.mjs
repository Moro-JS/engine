// h1spec test subject: the engine from this repo's build/ (via the loader's
// local-build fallback, or MORO_ENGINE_BINARY). Contract per the h1spec
// README: echo back whatever HTTP body arrives, any method.
import engine from '../../packages/engine/index.mjs';

const port = parseInt(process.env.PORT || '8000', 10);
const probe = engine.probe();
if (!probe.ok) {
  console.error('engine failed to load:', probe.error);
  process.exit(1);
}

const sid = engine.serve({
  onRequest(reqId) {
    const body = engine.getBody(reqId);
    engine.respond(reqId, 200, ['content-type', 'text/plain'], body ? Buffer.from(body) : '');
  },
  onAborted() {},
  onWritable() {},
});
const bound = engine.listen(sid, '127.0.0.1', port);
console.log(`@morojs/engine ${probe.version} h1spec echo subject on 127.0.0.1:${bound} (transport ${probe.transport ?? 'uv'})`);
