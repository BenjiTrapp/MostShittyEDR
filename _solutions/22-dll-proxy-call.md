---
title: "Solution 22: DLL Proxy Call"
difficulty: medium
category: "API Hook Evasion"
---

[Back to Challenge]({{ '/challenges/22-dll-proxy-call/' | relative_url }})

## Overview

Rule 7 only reads the PE imports of the main executable (`info.imagePath`). DLLs loaded at runtime are never scanned, so placing the hooked API call inside a DLL bypasses detection entirely.

## Solution

**Step 1: Create the proxy DLL**

```c
// proxy.c - DLL that calls a hooked API
#include <windows.h>
#include <winternl.h>

__declspec(dllexport) BOOL DoAllocate(void) {
    PVOID base = NULL;
    SIZE_T size = 4096;
    // This static import of NtAllocateVirtualMemory is in the DLL, not the .exe
    NtAllocateVirtualMemory(GetCurrentProcess(), &base, 0, &size,
                            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    return base != NULL;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) { return TRUE; }
```

**Step 2: Create the clean loader**

```c
// loader.c - no ntdll imports at all
#include <windows.h>
#include <stdio.h>

typedef BOOL (*pDoAllocate)(void);

int main() {
    HMODULE dll = LoadLibraryA("proxy.dll");
    pDoAllocate alloc = (pDoAllocate)GetProcAddress(dll, "DoAllocate");
    if (alloc()) printf("Success via DLL proxy\n");
    FreeLibrary(dll);
    return 0;
}
```

## Why It Works

The main executable `loader.exe` only imports `LoadLibraryA`, `GetProcAddress`, and `FreeLibrary` from kernel32.dll. Rule 7 scans `loader.exe`'s IAT and finds no hooked APIs. The actual `NtAllocateVirtualMemory` call lives inside `proxy.dll`, which is never inspected.

A real EDR would:
- Enumerate all loaded modules via `EnumProcessModules`
- Use `PsSetLoadImageNotifyRoutine` kernel callback to track DLL loads
- Hook `LoadLibrary` / `LdrLoadDll` to inspect new modules

## How to Verify

1. Start the EDR: `.\edr_agent.exe --profile crowdstrike --verbose --no-kill`
2. Run `loader.exe` — should show `[OK]`, no Rule 7 detection
3. Verify the allocation actually succeeded (prints "Success via DLL proxy")
