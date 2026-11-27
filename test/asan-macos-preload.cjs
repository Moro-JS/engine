// macOS only, loaded by test/run-asan-macos.sh through NODE_OPTIONS.
//
// node is signed with the hardened runtime: dyld honours
// DYLD_INSERT_LIBRARIES for it and then removes the variable from the
// process's environment, so process.env does not have it and a child node a
// test starts (process.execPath, { env: { ...process.env } }) comes up
// without the sanitizer runtime - the sanitized addon then refuses to load
// ("Interceptors are not working"). The runner passes the runtime's path in
// a variable of its own; this puts it back where a child will be given it.
if (process.env.MORO_ASAN_RUNTIME && !process.env.DYLD_INSERT_LIBRARIES) {
  process.env.DYLD_INSERT_LIBRARIES = process.env.MORO_ASAN_RUNTIME;
}
