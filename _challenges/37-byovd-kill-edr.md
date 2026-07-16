---
title: "Challenge 37: BYOVD — Kill the EDR Agent"
difficulty: hard
category: "BYOVD / Kernel Attacks"
---

# Challenge 37: BYOVD — Kill the EDR Agent

**Difficulty:** Hard | **Category:** BYOVD / Kernel Attacks | **Target:** Agent Process

## Objective

Use a vulnerable signed driver to terminate the EDR agent process from kernel level — even if it's running with `--driver` mode.

## Background

The MostShittyEDR agent (`edr_agent.exe`) runs as a **user-mode process**. Even in `--driver` mode, the agent itself is not a protected process (no PPL, no handle guard on its own PID). Any technique that can terminate an arbitrary process from kernel level will kill it instantly.

**BYOVD** (Bring Your Own Vulnerable Driver) exploits legitimately signed drivers that expose dangerous kernel primitives to user-mode callers. Several well-known drivers can terminate any process via IOCTL:

- **PROCEXP152.sys** (Process Explorer) — has a process-kill IOCTL
- **Blackout.sys** (gmer driver) — `0x9876C004` (init) + `0x9876C094` (kill)
- **Terminator.sys** — similar kill-by-PID interface

Tools like [NimBlackout](https://github.com/Helixo32/NimBlackout) implement this attack in Nim. See [BYOVD & IOCTL EDR Killer](https://benjitrapp.github.io/attacks/2026-06-24-byovd-ioctl-edr-killer/) for a deep dive into the IOCTL-based attack chain.

## Weakness Exploited

1. The EDR agent has **no self-protection** — it doesn't monitor or protect its own process
2. The kernel driver doesn't guard the agent's process handle (ObRegisterCallbacks only protects LSASS)
3. Windows does not treat loading a signed driver as a security boundary — Administrator can load any signed `.sys`
4. The agent does not detect vulnerable driver loads (no `PsSetLoadImageNotifyRoutine` monitoring in user-mode)

## Hints

1. The agent process name is `edr_agent.exe` — find its PID with `tasklist` or Toolhelp32
2. You need Administrator privileges to load a kernel driver
3. The driver must be validly signed (test-signed or production-signed)
4. `sc.exe create` + `sc.exe start` loads any kernel driver
5. After loading the vulnerable driver, open its device and send the kill IOCTL
6. The agent's `--driver` mode doesn't help — the kernel driver continues running but the agent (which reads events) is dead

## Success Criteria

- The `edr_agent.exe` process is terminated
- No detection is logged (the agent is dead before it can react)
- The kill works even if the agent was started with `--driver`

[View Solution]({{ '/solutions/37-byovd-kill-edr/' | relative_url }})
