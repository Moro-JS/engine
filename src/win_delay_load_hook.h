// Windows delay-load hook for the raw-V8 addon.
//
// The addon is linked with /DELAYLOAD:node.exe, so its imports (v8, libuv,
// OpenSSL, zlib - everything from node.lib) are resolved at FIRST CALL
// rather than at DLL load. This hook redirects that resolution to the
// process's own executable module, whatever its name: a renamed node.exe,
// an embedder hosting Node, or an Electron-style host that exports the same
// surface. Without it the loader would look for a file literally named
// "node.exe" next to the process and fail under any other host name.
//
// Clean-room implementation of the standard delay-load pattern documented in
// Microsoft's delayimp reference. Original-code policy applies
// (CONTRIBUTING.md)

#pragma once

#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <delayimp.h>
#include <string.h>

namespace moro {
namespace engine {

inline FARPROC WINAPI moroDelayLoadHook(unsigned dliNotify, PDelayLoadInfo info) {
  if (dliNotify == dliNotePreLoadLibrary &&
      _stricmp(info->szDll, "node.exe") == 0) {
    // Resolve against the host executable: node.exe under any name, or an
    // embedder that exports the Node surface.
    return reinterpret_cast<FARPROC>(GetModuleHandle(nullptr));
  }
  return nullptr;
}

}  // namespace engine
}  // namespace moro

// delayimp.lib calls this global hook pointer when set.
extern "C" const PfnDliHook __pfnDliNotifyHook2 = moro::engine::moroDelayLoadHook;

#endif  // _WIN32
