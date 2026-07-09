// ESM wrapper for @morojs/engine.
//
// The core loader (index.js) is CJS because loading a .node addon is
// require-based, and it exposes the native API through a lazy Proxy. Node's
// CJS->ESM interop can only surface a Proxy's *default* export (cjs-module-lexer
// cannot enumerate dynamic props), so this wrapper restates the named surface
// declared in index.d.ts for ESM consumers.
//
// Every function is a thin lazy pass-through: it touches the native binding
// only when CALLED, so a bare `import` never loads the addon and never throws
// on a platform without a prebuilt binary. probe() stays non-throwing.
//
// Maintenance: keep this list in sync with the function exports in index.d.ts.
import engine from './index.js';

export default engine;

// probe() lives on the loader itself (never loads the binding) - safe to alias.
export const probe = engine.probe;

export const serve = (...a) => engine.serve(...a);
export const listen = (...a) => engine.listen(...a);
export const close = (...a) => engine.close(...a);
export const stopListening = (...a) => engine.stopListening(...a);
export const getMethod = (...a) => engine.getMethod(...a);
export const getQuery = (...a) => engine.getQuery(...a);
export const getHeaders = (...a) => engine.getHeaders(...a);
export const getHeader = (...a) => engine.getHeader(...a);
export const getBody = (...a) => engine.getBody(...a);
export const getRemoteAddress = (...a) => engine.getRemoteAddress(...a);
export const isAborted = (...a) => engine.isAborted(...a);
export const respond = (...a) => engine.respond(...a);
export const writeHead = (...a) => engine.writeHead(...a);
export const write = (...a) => engine.write(...a);
export const end = (...a) => engine.end(...a);
export const upgradeToWebSocket = (...a) => engine.upgradeToWebSocket(...a);
export const wsSend = (...a) => engine.wsSend(...a);
export const wsClose = (...a) => engine.wsClose(...a);
