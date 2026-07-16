---
title: "Solution 21: Dynamic API Resolution"
difficulty: medium
category: "API Hook Evasion"
---

[Back to Challenge]({{ '/challenges/21-dynamic-api-resolution/' | relative_url }})

## Overview

Rule 7 only inspects the PE Import Address Table (IAT) — the list of functions statically linked at compile time. By resolving `NtAllocateVirtualMemory` dynamically at runtime via `GetProcAddress`, the function never appears in the IAT.

## Solution

```c
// resolve_dynamic.c - bypasses static import detection
#include <windows.h>
#include <stdio.h>

typedef NTSTATUS (NTAPI *pNtAllocateVirtualMemory)(
    HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);

int main() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    pNtAllocateVirtualMemory NtAlloc =
        (pNtAllocateVirtualMemory)GetProcAddress(ntdll, "NtAllocateVirtualMemory");

    PVOID base = NULL;
    SIZE_T size = 4096;
    NtAlloc(GetCurrentProcess(), &base, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    printf("Allocated at %p via dynamic resolution\n", base);
    return 0;
}
```

Compile without linking ntdll.lib:
```powershell
cl.exe resolve_dynamic.c /link kernel32.lib
```

## Why It Works

The compiled PE only imports `GetModuleHandleA` and `GetProcAddress` from kernel32.dll. `NtAllocateVirtualMemory` is resolved at runtime via a function pointer — it never appears in the import table that Rule 7 scans.

A real EDR would:
- Hook `GetProcAddress` to monitor dynamic resolution
- Use kernel callbacks to intercept the actual syscall
- Monitor ETW telemetry for the allocation event

## How to Verify

1. Start the EDR: `.\edr_agent.exe --profile crowdstrike --verbose --no-kill`
2. Run a program that **statically imports** `NtAllocateVirtualMemory` — should trigger Rule 7
3. Run `resolve_dynamic.exe` — should show `[OK]` with no detection
