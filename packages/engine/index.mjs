// ESM wrapper for @morojs/engine.
//
// The core loader (index.js) is CJS because loading a .node addon is
// require-based, and it exposes the native API through a lazy Proxy. Node's
// CJS->ESM interop can only surface a Proxy's *default* export (cjs-module-lexer
// cannot enumerate dynamic props), so this wrapper restates the named surface
// declared in index.d.ts for ESM consumers.
//
// Every function is a lazy pass-through that touches the native binding only
// when CALLED, so a bare `import` never loads the addon and never throws on a
// platform without a prebuilt binary. probe() stays non-throwing.
//
// The first successful call REBINDS the export to the native function itself
// (`export let` bindings are live for importers): every later call from a
// `import { respond } from '@morojs/engine'` site goes straight to the addon
// with no wrapper frame and a constant call target, which is what lets V8
// inline-cache the site and take the engine's fast-call path. If the addon
// fails to load, the assignment never happens and the wrapper keeps throwing
// the loader's error on every call.
//
// Maintenance: `npm run check:exports` diffs this list against the binding.
import engine from './index.js';

export default engine;

// probe() lives on the loader itself (never loads the binding) - safe to alias.
export const probe = engine.probe;

export let serve = (...a) => (serve = engine.serve)(...a);
export let listen = (...a) => (listen = engine.listen)(...a);
export let close = (...a) => (close = engine.close)(...a);
export let stopListening = (...a) => (stopListening = engine.stopListening)(...a);
export let updateSsl = (...a) => (updateSsl = engine.updateSsl)(...a);
export let getMethod = (...a) => (getMethod = engine.getMethod)(...a);
export let getBatchBuffers = (...a) => (getBatchBuffers = engine.getBatchBuffers)(...a);
export let getPath = (...a) => (getPath = engine.getPath)(...a);
export let getQuery = (...a) => (getQuery = engine.getQuery)(...a);
export let getHeaders = (...a) => (getHeaders = engine.getHeaders)(...a);
export let getHeader = (...a) => (getHeader = engine.getHeader)(...a);
export let getBody = (...a) => (getBody = engine.getBody)(...a);
export let getRemoteAddress = (...a) => (getRemoteAddress = engine.getRemoteAddress)(...a);
export let isAborted = (...a) => (isAborted = engine.isAborted)(...a);
export let respond = (...a) => (respond = engine.respond)(...a);
export let writeHead = (...a) => (writeHead = engine.writeHead)(...a);
export let write = (...a) => (write = engine.write)(...a);
export let end = (...a) => (end = engine.end)(...a);
export let setStaticRoute = (...a) => (setStaticRoute = engine.setStaticRoute)(...a);
export let clearStaticRoutes = (...a) => (clearStaticRoutes = engine.clearStaticRoutes)(...a);
export let prepareResponse = (...a) => (prepareResponse = engine.prepareResponse)(...a);
export let releaseTemplates = (...a) => (releaseTemplates = engine.releaseTemplates)(...a);
export let respondPrepared = (...a) => (respondPrepared = engine.respondPrepared)(...a);
export let respondPreparedEmpty = (...a) => (respondPreparedEmpty = engine.respondPreparedEmpty)(...a);
export let writeHeadPrepared = (...a) => (writeHeadPrepared = engine.writeHeadPrepared)(...a);
export let endWith = (...a) => (endWith = engine.endWith)(...a);
export let upgradeToWebSocket = (...a) => (upgradeToWebSocket = engine.upgradeToWebSocket)(...a);
export let wsSend = (...a) => (wsSend = engine.wsSend)(...a);
export let wsClose = (...a) => (wsClose = engine.wsClose)(...a);
