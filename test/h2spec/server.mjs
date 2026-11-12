// The server h2spec is pointed at (test/run-h2spec.sh): cleartext HTTP/2 on
// PORT (default 8080) and, with the fixture certificate, TLS on PORT+1.
// Every request is answered 200 with a body, as the suite expects of "/".
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));
const engine = require(path.join(here, '../../packages/engine'));
const port = Number(process.env.PORT || 8080);
const body = 'h2spec '.repeat(16);

function serve(options, listenPort) {
  const id = engine.serve(
    {
      onRequest(reqId) {
        engine.getBody(reqId);
        engine.respond(reqId, 200, ['content-type', 'text/plain'], body);
      },
      onAborted() {},
      onWritable() {},
    },
    options
  );
  engine.listen(id, '0.0.0.0', listenPort);
}

serve({ http2: true }, port);
serve(
  {
    http2: true,
    ssl: {
      key_file_name: path.join(here, '../fixtures/tls/localhost.key'),
      cert_file_name: path.join(here, '../fixtures/tls/localhost.pem'),
    },
  },
  port + 1
);
console.log(`h2spec target: h2c on ${port}, h2 on ${port + 1}`);
