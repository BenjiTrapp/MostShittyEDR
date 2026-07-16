---
title: "Challenge 38: BYOVD — Remove Kernel Callbacks"
difficulty: hard
category: "BYOVD / Kernel Attacks"
---

# Challenge 38: BYOVD — Remove Kernel Callbacks

**Difficulty:** Hard | **Category:** BYOVD / Kernel Attacks | **Target:** Kernel Callbacks

## Objective

Use a vulnerable driver with arbitrary kernel read/write primitives to enumerate and remove the MostShittyEDR driver's kernel callbacks — blinding it without killing the process.

## Background

The MostShittyEDR kernel driver registers three types of callbacks:

1. **PsSetCreateProcessNotifyRoutineEx** — sees every process start/stop
2. **PsSetCreateThreadNotifyRoutine** — sees every thread creation
3. **ObRegisterCallbacks** — strips LSASS handle permissions

These callbacks are stored in kernel arrays (e.g., `PspCreateProcessNotifyRoutine` — an array of `EX_CALLBACK_ROUTINE_BLOCK` pointers). A BYOVD tool with kernel read/write can walk these arrays, find the EDR's callback entries, and zero them out — silently disabling monitoring.

Tools like [EDRSandblast](https://github.com/wavestone-cdt/EDRSandblast) and [CheekyBlinder](https://github.com/BR-Matt/CheekyBlinder) implement this technique. See [BYOVD & IOCTL EDR Killer](https://benjitrapp.github.io/attacks/2026-06-24-byovd-ioctl-edr-killer/) for how IOCTL-based R/W primitives enable this. Common vulnerable drivers for kernel R/W:

- **RTCore64.sys** (MSI Afterburner) — IOCTLs for arbitrary physical/virtual memory R/W
- **DBUtil_2_3.sys** (Dell) — similar R/W primitives
- **GDRV.sys** (Gigabyte) — arbitrary R/W via `MmMapIoSpace`

## Weakness Exploited

1. The EDR driver's callbacks are **not protected** — they're standard kernel pointers with no integrity check
2. No **callback guard** mechanism — the driver doesn't periodically verify its callbacks are still registered
3. The driver has a **well-known device name** (`\\.\MostShittyEDR`) making it trivial to identify which driver module to target
4. The callbacks live in kernel memory at **known offsets** from exported symbols (`PsSetCreateProcessNotifyRoutine` → `PspCreateProcessNotifyRoutine`)

## Hints

1. Find the kernel base address via `NtQuerySystemInformation(SystemModuleInformation)`
2. Locate `PspCreateProcessNotifyRoutine` using offsets from public PDB symbols
3. The callback array holds up to 64 entries — walk it and find the one pointing into the EDR's driver module
4. To identify the EDR's module range, use `NtQuerySystemInformation(SystemModuleInformation)` to find `MostShittyEDR.sys` base+size
5. Zero the callback's `Function` pointer with the vulnerable driver's write IOCTL
6. For ObRegisterCallbacks: find the `OB_CALLBACK_ENTRY` linked list and unlink the EDR's entry

## Success Criteria

- Process creation events stop flowing to the EDR agent (it sits idle)
- The EDR agent process is still running — it just receives no more events
- Thread creation and LSASS protection callbacks are also removed
- No bluescreen (carefully validate addresses before writing)

[View Solution]({{ '/solutions/38-byovd-remove-callbacks/' | relative_url }})
