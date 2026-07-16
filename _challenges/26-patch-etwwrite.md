---
layout: default
title: "Challenge 26: Patch EtwEventWrite"
difficulty: medium
category: "ETW Bypass"
rule: 8
---

# Challenge 26: Patch EtwEventWrite

<span class="badge badge-medium">Medium</span>
<span class="badge badge-category">ETW Bypass</span>

## Objective

Patch `ntdll!EtwEventWrite` in memory to silently disable all user-mode ETW telemetry without triggering Rule 8's integrity check.

## Background

Every user-mode ETW provider ultimately calls `ntdll!EtwEventWrite` to emit events. By patching this function in memory, you can blind **all** user-mode ETW providers in the process — including the EDR's telemetry.

This is one of the most common EDR bypass techniques. Tools like [TamperETW](https://github.com/outflanknl/TamperETW) use this approach to silently disable .NET ETW logging in `Assembly.Load` cradles.

## The Weakness

Rule 8 checks the **first byte** of `EtwEventWrite` for `0xC3` (the `ret` instruction). But it doesn't check for other patching patterns:

- `xor eax, eax; ret` → bytes `0x33, 0xC0, 0xC3` — returns `STATUS_SUCCESS` without logging
- The first byte is `0x33`, not `0xC3`, so Rule 8 **misses it entirely**

## Rules

1. The EDR agent must be running (ETW enabled)
2. Patch `EtwEventWrite` so it returns immediately without emitting events
3. Rule 8 must NOT detect your patch
4. Verify that ETW events are no longer being written

## Hints

<div class="hint-box">
<details>
<summary>Hint 1</summary>
You need to change the memory protection of the ntdll page before writing to it. What API changes page protections?
</details>
</div>

<div class="hint-box">
<details>
<summary>Hint 2</summary>
Use <code>VirtualProtect</code> to make the page <code>PAGE_EXECUTE_READWRITE</code>, write the patch bytes, then restore <code>PAGE_EXECUTE_READ</code>.
</details>
</div>

<div class="hint-box">
<details>
<summary>Hint 3</summary>
The patch <code>xor eax, eax; ret</code> is three bytes: <code>\x33\xC0\xC3</code>. It sets EAX to 0 (STATUS_SUCCESS) and returns — the caller thinks the write succeeded.
</details>
</div>

## Further Reading

- [Breaking ETW and EDR](https://benjitrapp.github.io/attacks/2024-02-11-offensive-etw/) — Offensive ETW techniques
- [ETW-TI Deep Dive](https://benjitrapp.github.io/defenses/2026-06-19-etw-ti/) — Why this doesn't work against kernel ETW
