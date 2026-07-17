---
title: "Challenge 40: IOCTL Hijack — Kill via EDR's Own Driver"
difficulty: medium
category: "IOCTL Abuse"
---

# Challenge 40: IOCTL Hijack — Kill via EDR's Own Driver

**Difficulty:** Medium | **Category:** IOCTL Abuse | **Target:** Driver Device

## Objective

Open the MostShittyEDR driver's device and use its own `IOCTL_KILL_PROCESS` to terminate the EDR agent — no vulnerable third-party driver needed.

## Background

The MostShittyEDR kernel driver exposes its device at `\\.\MostShittyEDR` without any access control. The `DispatchCreateClose` handler always returns `STATUS_SUCCESS` — any process on the system can open the device. Once opened, all 5 IOCTLs are accessible, including `IOCTL_KILL_PROCESS` (`0x222004`), which calls `ZwTerminateProcess` from ring 0.

This means the EDR's own driver is a weaponizable IOCTL interface: instead of bringing your own vulnerable driver (BYOVD), you abuse the one the EDR already loaded.

## Weakness Exploited

1. **No DACL on the device object**: `IoCreateDevice` is called without setting a security descriptor — the default grants access to any local user
2. **No caller validation**: `DispatchCreateClose` doesn't check the calling process (PID, signature, integrity level)
3. **`FILE_ANY_ACCESS` on destructive IOCTLs**: `IOCTL_KILL_PROCESS` uses `FILE_ANY_ACCESS` instead of `FILE_WRITE_ACCESS`
4. **No PID validation**: The kill handler doesn't prevent terminating critical processes (PID 4, csrss.exe, the agent itself)
5. **`IoCreateDevice` with `Exclusive = FALSE`**: Multiple processes can open the device simultaneously

## Hints

1. The device symlink is `\\.\MostShittyEDR` — open it with `CreateFileA`
2. `IOCTL_KILL_PROCESS` is `0x222004` with `METHOD_BUFFERED`
3. The input buffer is an `EDR_COMMAND` struct: `{ Action: ULONG = 1, ProcessId: ULONG64 }`
4. Find the agent PID via `CreateToolhelp32Snapshot` / `Process32First`
5. You don't even need Administrator — the device has no access restrictions
6. Bonus: after killing the agent, use `IOCTL_CLEAR_BLOCK_RULES` (`0x22200C`) to remove all kernel block rules

## Success Criteria

- The `edr_agent.exe` process is terminated using the EDR's own driver IOCTL
- No external driver is loaded — only `\\.\MostShittyEDR` is used
- The attack works from a standard (non-elevated) user context

[View Solution]({{ '/solutions/40-ioctl-hijack-kill/' | relative_url }})
