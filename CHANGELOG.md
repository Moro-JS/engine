# Changelog

One file per release in [`changelog/`](changelog/); the GitHub Release for a
tag carries the same text. Newest first.

- [1.1.20](changelog/v1.1.20.md) — TLS on a bundled BoringSSL (two binaries per ABI; Node's OpenSSL selected by itself under FIPS or an OpenSSL config, or with `MORO_ENGINE_TLS` / `selectTls()`); the bundled copy follows upstream by a scheduled release; `probe().tls`.
- [1.1.19](changelog/v1.1.19.md) — HTTP/2 (ALPN and prior knowledge, the engine's own implementation; h2spec 146/146); TLS replies written straight to the socket, AES-128-GCM preferred by default; request bodies as heap strings or lent buffers (`getBodyType`, `getBodyText`, `getBodyLent`), body buffers pooled per loop; epoll: each ready socket served once per loop turn.
- [1.1.18](changelog/v1.1.18.md) — request bodies collected straight into the body buffer (one copy, half the peak memory of an upload); `getBody()` hands the bytes over without a copy; one callback scope per WebSocket read.
- [1.1.17](changelog/v1.1.17.md) — TLS on the engine's own BIOs (one copy in, one append out, no zeroing); bodies over 8 KiB encrypted from the caller's bytes; ciphertext scratch kept up to 1 MiB.
- [1.1.16](changelog/v1.1.16.md) — `wsSend()` borrows its payload (the backpressure shed is deferred); ASCII text frames as one-byte strings; TLS record buffers released again.
- [1.1.15](changelog/v1.1.15.md) — WebSocket upgrades performed by the engine (`setWsAutoUpgrade`, handshake accessors); frames built in the cork buffer; TLS record buffers kept between records.
- [1.1.14](changelog/v1.1.14.md) — WebSocket replies corked per read (one write for a pipelined batch); one ciphertext buffer per loop on the TLS write path.
- [1.1.13](changelog/v1.1.13.md) — epoll transport: the service order is selectable (grouped, arrival, or measured `auto`); the default is unchanged.
- [1.1.12](changelog/v1.1.12.md) — epoll transport serves each loop turn's sockets grouped by peer CPU.
- [1.1.11](changelog/v1.1.11.md) — epoll transport on one `epoll_wait` per loop turn; engine-answered routes parsed and routed per request.
- [1.1.10](changelog/v1.1.10.md) — engine-answered routes parsed in place and framed from a prepared head; epoll transport the Linux default; request-registry fix.
- [1.1.9](changelog/v1.1.9.md) — parameter routes (`setParamRoute`, `clearParamRoutes`).
- [1.1.8](changelog/v1.1.8.md) — TLS release, one new native function.
- [1.1.7](changelog/v1.1.7.md) — correctness release with one transport improvement.
- [1.1.6](changelog/v1.1.6.md) — the JS boundary: prepared templates, static routes, V8 fast API calls, worker-thread teardown, PGO builds.
- [1.1.5](changelog/v1.1.5.md) — hot-path and memory-headroom audit.
- [1.1.4](changelog/v1.1.4.md) — correctness hardening from the code-quality audit.
- [1.1.3](changelog/v1.1.3.md) — security hardening, third-party audit closed.
- [1.1.1](changelog/v1.1.1.md) — hot-path performance patch.
- [1.1.0](changelog/v1.1.0.md) — pipelined response corking, zero-allocation hot path.
