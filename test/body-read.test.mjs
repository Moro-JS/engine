// The three ways of reading a request body besides getBody():
//
//   getBodyType(reqId)  the Content-Type, '' without one, null without a body
//   getBodyText(reqId)  an all-ASCII body as a string, null otherwise
//   getBodyLent(reqId)  the body as an ArrayBuffer that is detached, and its
//                       bytes freed, when the response is complete
//
// What is pinned here is the contract an adapter builds on: the text is the
// exact bytes, a lent buffer never outlives its request in any state the
// request can end in, and a caller who asks for bytes to keep (getBody) gets
// bytes that are kept whatever was lent before.

import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import {
  loadEngine,
  startFixtureServer,
  openRaw,
  rawRequest,
  parseResponse,
  parseResponses,
  responsesComplete,
  waitFor,
} from './helpers.mjs';
import { sslFileOptions, rawTlsRequest } from './tls-helpers.mjs';

const T = { timeout: 15000 };

const post = (body, type, extra = '') =>
  Buffer.concat([
    Buffer.from(
      `POST /b HTTP/1.1\r\nHost: x\r\n${type === undefined ? '' : `Content-Type: ${type}\r\n`}` +
        `Content-Length: ${Buffer.byteLength(body)}\r\n${extra}\r\n`
    ),
    Buffer.isBuffer(body) ? body : Buffer.from(body),
  ]);

describe('reading a request body: type, text, lent', () => {
  let engine;
  before(async () => {
    engine = await loadEngine();
  });

  async function withServer(handler, fn, options = {}) {
    const server = await startFixtureServer(engine, handler, options);
    try {
      await fn(server);
    } finally {
      server.close();
    }
  }

  it('advertises both capabilities', T, () => {
    const caps = engine.probe().capabilities;
    assert.equal(caps.bodyText, true);
    assert.equal(caps.bodyLent, true);
  });

  describe('getBodyType', () => {
    it('is null without a body, the header with one, and empty when the header is missing', T, async () => {
      const seen = [];
      await withServer(
        (ctx) => {
          seen.push(engine.getBodyType(ctx.reqId));
          ctx.respond(200, null, 'ok');
        },
        async (server) => {
          await rawRequest(server.port, 'GET /b HTTP/1.1\r\nHost: x\r\nContent-Type: text/plain\r\n\r\n');
          await rawRequest(server.port, post('{"a":1}', 'application/json; charset=utf-8'));
          await rawRequest(server.port, post('abc', undefined));
          await rawRequest(server.port, post('', 'text/plain'));
        }
      );
      assert.deepEqual(seen, [null, 'application/json; charset=utf-8', '', null]);
    });

    it('still names the type after the body has been taken with getBody', T, async () => {
      let type;
      await withServer(
        (ctx) => {
          ctx.body();
          type = engine.getBodyType(ctx.reqId);
          ctx.respond(200, null, 'ok');
        },
        async (server) => {
          await rawRequest(server.port, post('abc', 'text/x-kept'));
        }
      );
      assert.equal(type, 'text/x-kept');
    });

    it('is null for a request that is gone', T, async () => {
      let later;
      await withServer(
        (ctx) => {
          ctx.respond(200, null, 'ok');
          later = engine.getBodyType(ctx.reqId);
        },
        async (server) => {
          await rawRequest(server.port, post('abc', 'text/plain'));
        }
      );
      assert.equal(later, null);
    });
  });

  describe('getBodyText', () => {
    it('returns an ASCII body as the string of its bytes', T, async () => {
      const body = JSON.stringify({ name: 'moro', n: [1, 2, 3], s: 'tab\\tquote\\"' });
      let text;
      let raw;
      await withServer(
        (ctx) => {
          text = engine.getBodyText(ctx.reqId);
          raw = Buffer.from(ctx.body()).toString('latin1'); // the bytes are still there to take
          ctx.respond(200, null, 'ok');
        },
        async (server) => {
          await rawRequest(server.port, post(body, 'application/json'));
        }
      );
      assert.equal(text, body);
      assert.equal(raw, body);
    });

    it('covers every ASCII byte, NUL and DEL included', T, async () => {
      const bytes = Buffer.from(Array.from({ length: 128 }, (_, i) => i));
      let text;
      await withServer(
        (ctx) => {
          text = engine.getBodyText(ctx.reqId);
          ctx.respond(200, null, 'ok');
        },
        async (server) => {
          await rawRequest(server.port, post(bytes, 'application/octet-stream'));
        }
      );
      assert.equal(text.length, 128);
      assert.ok(Buffer.from(text, 'latin1').equals(bytes));
    });

    it('returns null for a body with any byte above 0x7f, wherever it is', T, async () => {
      const results = [];
      const bodies = [
        Buffer.from('héllo', 'utf8'),
        Buffer.concat([Buffer.alloc(4096, 0x61), Buffer.from([0x80])]),
        Buffer.concat([Buffer.from([0xff]), Buffer.alloc(4096, 0x61)]),
        Buffer.concat([Buffer.alloc(33, 0x61), Buffer.from([0xc3, 0xa9]), Buffer.alloc(33, 0x61)]),
      ];
      await withServer(
        (ctx) => {
          results.push(engine.getBodyText(ctx.reqId));
          // ...and getBody still has every byte of it
          results.push(Buffer.from(ctx.body()).length);
          ctx.respond(200, null, 'ok');
        },
        async (server) => {
          for (const b of bodies) await rawRequest(server.port, post(b, 'text/plain'));
        }
      );
      assert.deepEqual(
        results,
        bodies.flatMap((b) => [null, b.length])
      );
    });

    it('is null once getBody has taken the bytes, and for a request that is gone', T, async () => {
      let afterTake;
      let afterEnd;
      await withServer(
        (ctx) => {
          ctx.body();
          afterTake = engine.getBodyText(ctx.reqId);
          ctx.respond(200, null, 'ok');
          afterEnd = engine.getBodyText(ctx.reqId);
        },
        async (server) => {
          await rawRequest(server.port, post('abc', 'text/plain'));
        }
      );
      assert.equal(afterTake, null);
      assert.equal(afterEnd, null);
    });

    it('reads a chunked body and a megabyte body the same way', T, async () => {
      const big = 'x'.repeat(1 << 20);
      const texts = [];
      await withServer(
        (ctx) => {
          texts.push(engine.getBodyText(ctx.reqId));
          ctx.respond(200, null, 'ok');
        },
        async (server) => {
          await rawRequest(
            server.port,
            'POST /b HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n'
          );
          await rawRequest(server.port, post(big, 'text/plain'));
        },
        { maxBodySize: 2 << 20 }
      );
      assert.equal(texts[0], 'hello world');
      assert.equal(texts[1].length, big.length);
      assert.equal(texts[1], big);
    });
  });

  describe('getBodyLent', () => {
    it('views the body for the length of the request, then is detached', T, async () => {
      const body = Buffer.from(Array.from({ length: 4096 }, (_, i) => i & 0xff));
      let lent;
      let view;
      let during;
      let sameAgain;
      await withServer(
        (ctx) => {
          lent = engine.getBodyLent(ctx.reqId);
          sameAgain = engine.getBodyLent(ctx.reqId) === lent;
          view = new Uint8Array(lent);
          during = Buffer.from(Buffer.from(lent)); // a copy of what it shows now
          ctx.respond(200, null, 'ok');
        },
        async (server) => {
          await rawRequest(server.port, post(body, 'application/octet-stream'));
        }
      );
      assert.ok(during.equals(body));
      assert.equal(sameAgain, true, 'one buffer per request, however often it is asked for');
      assert.equal(lent.byteLength, 0, 'detached once the response is complete');
      assert.equal(lent.detached ?? true, true);
      assert.equal(view.length, 0, 'a view made during the request is empty afterwards');
      assert.equal(view[0], undefined);
      assert.throws(() => new Uint8Array(lent), TypeError, 'and no new view can be made');
    });

    it('is null without a body and for a request that is gone', T, async () => {
      const seen = [];
      await withServer(
        (ctx) => {
          seen.push(engine.getBodyLent(ctx.reqId));
          ctx.respond(200, null, 'ok');
          seen.push(engine.getBodyLent(ctx.reqId));
        },
        async (server) => {
          await rawRequest(server.port, 'GET /b HTTP/1.1\r\nHost: x\r\n\r\n');
        }
      );
      assert.deepEqual(seen, [null, null]);
    });

    it('stays valid across an asynchronous handler and is detached when it answers', T, async () => {
      const body = Buffer.alloc(10240, 0x5a);
      let lent;
      let midway;
      await withServer(
        async (ctx) => {
          lent = engine.getBodyLent(ctx.reqId);
          await new Promise((r) => setTimeout(r, 30));
          midway = { length: lent.byteLength, ok: Buffer.from(lent).equals(body) };
          ctx.respond(200, null, 'ok');
        },
        async (server) => {
          const res = parseResponse(await rawRequest(server.port, post(body, 'application/octet-stream')));
          assert.equal(res.status, 200);
        }
      );
      assert.deepEqual(midway, { length: 10240, ok: true });
      assert.equal(lent.byteLength, 0);
    });

    it('can be sent back as the response body, over plaintext and over TLS', T, async () => {
      const body = Buffer.from(Array.from({ length: 70000 }, (_, i) => (i * 7) & 0xff));
      const handler = (ctx) => {
        const lent = engine.getBodyLent(ctx.reqId);
        ctx.respond(200, ['content-type', 'application/octet-stream'], Buffer.from(lent));
      };
      const tail = (raw) => Buffer.from(raw, 'latin1').subarray(-body.length);
      await withServer(
        handler,
        async (server) => {
          const raw = await rawRequest(server.port, post(body, 'application/octet-stream'));
          assert.equal(parseResponse(raw).status, 200);
          assert.ok(tail(raw).equals(body));
        },
        { maxBodySize: 1 << 20 }
      );
      await withServer(
        handler,
        async (server) => {
          const raw = await rawTlsRequest(server.port, post(body, 'application/octet-stream'));
          assert.equal(parseResponse(raw).status, 200);
          assert.ok(tail(raw).equals(body));
        },
        { maxBodySize: 1 << 20, ssl: sslFileOptions() }
      );
    });

    it('gives each pipelined request its own bytes, and takes the last one back before the next', T, async () => {
      const bodies = ['first-body-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'second-body-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'x'];
      const lentBuffers = [];
      const seen = [];
      const earlierLengths = [];
      await withServer(
        (ctx) => {
          earlierLengths.push(lentBuffers.map((b) => b.byteLength));
          const lent = engine.getBodyLent(ctx.reqId);
          lentBuffers.push(lent);
          seen.push(Buffer.from(lent).toString('latin1'));
          ctx.respond(200, null, 'ok');
        },
        async (server) => {
          const raw = await rawRequest(
            server.port,
            Buffer.concat(bodies.map((b) => post(b, 'text/plain'))),
            { until: responsesComplete(3) }
          );
          assert.equal(parseResponses(raw).length, 3);
        }
      );
      assert.deepEqual(seen, bodies);
      assert.deepEqual(earlierLengths, [[], [0], [0, 0]]);
      assert.deepEqual(lentBuffers.map((b) => b.byteLength), [0, 0, 0]);
    });

    it('is detached when the client goes away before the answer', T, async () => {
      let lent;
      let release;
      const gate = new Promise((r) => (release = r));
      await withServer(
        async (ctx) => {
          lent = engine.getBodyLent(ctx.reqId);
          await gate;
        },
        async (server) => {
          const client = await openRaw(server.port);
          await client.send(post(Buffer.alloc(2048, 0x41), 'application/octet-stream'));
          await waitFor(() => lent !== undefined);
          assert.equal(lent.byteLength, 2048);
          client.destroy();
          await waitFor(() => server.aborted.length === 1);
          assert.equal(lent.byteLength, 0, 'detached with the connection');
          release();
        }
      );
    });

    it('is detached when the server closes with the request unanswered', T, async () => {
      let lent;
      const server = await startFixtureServer(engine, (ctx) => {
        lent = engine.getBodyLent(ctx.reqId);
      });
      const client = await openRaw(server.port);
      await client.send(post(Buffer.alloc(512, 0x42), 'application/octet-stream'));
      await waitFor(() => lent !== undefined);
      assert.equal(lent.byteLength, 512);
      server.close();
      await waitFor(() => lent.byteLength === 0);
      client.destroy();
    });

    it('transferred away by the handler, the bytes are the new owner\'s to keep', T, async () => {
      const body = Buffer.from(Array.from({ length: 300 }, (_, i) => (i * 3) & 0xff));
      const kept = [];
      const lentBuffers = [];
      await withServer(
        (ctx) => {
          const lent = engine.getBodyLent(ctx.reqId);
          lentBuffers.push(lent);
          kept.push(
            ctx.path === '/clone' || typeof lent.transfer !== 'function'
              ? structuredClone(lent, { transfer: [lent] })
              : lent.transfer()
          );
          // nothing is left for a later read of the same request
          assert.equal(lent.byteLength, 0);
          assert.equal(ctx.body(), null);
          ctx.respond(200, null, 'ok');
        },
        async (server) => {
          await rawRequest(server.port, post(body, 'application/octet-stream'));
          await rawRequest(
            server.port,
            Buffer.from(post(body, 'application/octet-stream').toString('latin1').replace('/b', '/clone'), 'latin1')
          );
        }
      );
      assert.equal(kept.length, 2);
      for (const buffer of kept) assert.ok(Buffer.from(buffer).equals(body), 'intact after the response');
      assert.deepEqual(lentBuffers.map((b) => b.byteLength), [0, 0]);
    });

    it('leaves getBody its own bytes: a copy that outlives the request', T, async () => {
      const body = Buffer.from('keep-me-'.repeat(200));
      let lent;
      let kept;
      await withServer(
        (ctx) => {
          if (lent === undefined) {
            lent = engine.getBodyLent(ctx.reqId);
            kept = ctx.body();
          }
          ctx.respond(200, null, 'ok');
        },
        async (server) => {
          await rawRequest(server.port, post(body, 'application/octet-stream'));
          // another request on a new connection reuses nothing of the first
          await rawRequest(server.port, post(Buffer.alloc(body.length, 0x7a), 'application/octet-stream'));
        }
      );
      assert.equal(lent.byteLength, 0);
      assert.ok(Buffer.from(kept).equals(body), 'the kept bytes are untouched by later requests');
    });

    it('after getBody it is the kept buffer, not a loan', T, async () => {
      const body = Buffer.from('owned-'.repeat(50));
      let second;
      await withServer(
        (ctx) => {
          ctx.body();
          second = engine.getBodyLent(ctx.reqId);
          ctx.respond(200, null, 'ok');
        },
        async (server) => {
          await rawRequest(server.port, post(body, 'application/octet-stream'));
        }
      );
      assert.equal(second.byteLength, body.length, 'not detached: these bytes were handed over for keeps');
      assert.ok(Buffer.from(second).equals(body));
    });

    it('a body small enough to live inside the connection is lent and taken back like any other', T, async () => {
      const lentBuffers = [];
      const seen = [];
      await withServer(
        (ctx) => {
          const lent = engine.getBodyLent(ctx.reqId);
          lentBuffers.push(lent);
          seen.push(Buffer.from(lent).toString('latin1'));
          ctx.respond(200, null, 'ok');
        },
        async (server) => {
          const client = await openRaw(server.port);
          try {
            await client.send(post('ab', 'text/plain'));
            await client.read({ until: responsesComplete(1) });
            await client.send(post('cdefg', 'text/plain'));
            await client.read({ until: responsesComplete(1) });
          } finally {
            client.destroy();
          }
        }
      );
      assert.deepEqual(seen, ['ab', 'cdefg']);
      assert.deepEqual(lentBuffers.map((b) => b.byteLength), [0, 0]);
    });
  });
});
