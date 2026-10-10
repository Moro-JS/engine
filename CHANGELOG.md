# Changelog

One file per release in [`changelog/`](changelog/); the GitHub Release for a
tag carries the same text. Newest first.

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
