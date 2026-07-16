---
title: "Challenge 39: BYOVD — Blind ETW-TI"
difficulty: hard
category: "BYOVD / Kernel Attacks"
---

# Challenge 39: BYOVD — Blind ETW-TI

**Difficulty:** Hard | **Category:** BYOVD / Kernel Attacks | **Target:** ETW Threat Intelligence

## Objective

Use a vulnerable driver to disable ETW Threat Intelligence (ETW-TI) at the kernel level — the one telemetry source that survives all user-mode bypasses.

## Background

Challenges 25-28 disabled ETW from user-mode: killing trace sessions, patching `EtwEventWrite`, unregistering providers. But ETW-TI (`Microsoft-Windows-Threat-Intelligence`) runs in the kernel and is protected by PPL — user-mode patching cannot touch it.

ETW-TI feeds kernel-level events directly to PPL-protected EDR processes. It monitors:
- Process creation/termination
- Memory allocation with executable permissions
- Image loading
- Handle operations on protected processes

The only way to blind ETW-TI without a signed PPL process is **from the kernel itself** — using a vulnerable driver's R/W primitives to zero the `ProviderEnableInfo` field in the ETW-TI provider's `TRACE_ENABLE_INFO` structure.

[EDRSandblast](https://github.com/wavestone-cdt/EDRSandblast) implements this technique via `DisableETWTI()`. See [BYOVD & IOCTL EDR Killer](https://benjitrapp.github.io/attacks/2026-06-24-byovd-ioctl-edr-killer/) for the underlying IOCTL patterns.

## Weakness Exploited

1. The MostShittyEDR's ETW provider is a **standard user-mode provider** — it's not PPL-protected, so it's even easier to blind
2. Even in `--driver` mode, ETW Rule 8 runs in user-mode — kernel-level ETW-TI blinding stops all ETW telemetry before it reaches the agent
3. The agent has **no fallback** if ETW goes silent — it doesn't detect missing events
4. The ETW provider GUID is **hardcoded** and discoverable in the binary

## Hints

1. Find the ETW-TI provider's `EtwThreatIntProvRegHandle` via PDB offsets from `nt!EtwThreatIntProvRegHandle`
2. The handle points to an `ETW_REG_ENTRY` containing a `GUID` and a pointer to `TRACE_ENABLE_INFO`
3. Zero the `IsEnabled` field and `Level`/`MatchAnyKeyword` in `TRACE_ENABLE_INFO`
4. For the MostShittyEDR's own user-mode provider: find its `_ETW_REG_ENTRY` in kernel memory and disable it
5. Alternatively: patch `EtwEventWrite` in `ntoskrnl.exe` memory (kernel-mode version) — requires finding the right offset and using the R/W driver to patch it
6. Test with `logman query providers` before and after to verify the provider is disabled

## Success Criteria

- ETW Rule 8 no longer detects ETW tampering (because it can't see anything)
- The agent's ETW trace session receives no more events
- No bluescreen — carefully validate kernel addresses
- `logman query providers` shows the provider disabled or no consumers attached

[View Solution]({{ '/solutions/39-byovd-blind-etw-ti/' | relative_url }})
