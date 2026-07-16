---
layout: default
title: "Challenge 28: Hardware Breakpoint ETW Hook"
difficulty: hard
category: "ETW Bypass"
rule: 8
---

# Challenge 28: Hardware Breakpoint ETW Hook

<span class="badge badge-hard">Hard</span>
<span class="badge badge-category">ETW Bypass</span>

## Objective

Use hardware breakpoints (debug registers) and a Vectored Exception Handler to intercept `EtwEventWrite` calls without modifying any code bytes — completely evading Rule 8's memory integrity check.

## Background

Hardware breakpoints use the CPU's debug registers (DR0-DR3) to trigger exceptions when specific addresses are executed. Combined with a Vectored Exception Handler (VEH), you can intercept function calls without writing to code memory.

This technique is used in advanced EDR bypass tools for "patchless" hooking:
1. Set DR0 to point to `EtwEventWrite`
2. Register a VEH that catches `EXCEPTION_SINGLE_STEP`
3. When the breakpoint fires, modify the return value and skip the function
4. No code bytes are modified — memory integrity checks pass

This is essentially the same principle behind [ETW-TI's NtContinue monitoring](https://benjitrapp.github.io/defenses/2026-06-19-etw-ti/) — the kernel watches for debug register manipulation via `NtSetContextThread`.

## The Weakness

Rule 8's integrity check:
- Reads bytes at `EtwEventWrite` — **unchanged**, no patch detected
- Queries the trace session — **still running**
- Does **not** monitor debug registers (DR0-DR3)
- Does **not** detect VEH installation
- Has no kernel-mode component (no ETW-TI to catch `NtSetContextThread`)

## Rules

1. The EDR agent must be running with ETW enabled
2. Hook `EtwEventWrite` using only hardware breakpoints + VEH
3. No code bytes at `EtwEventWrite` may be modified
4. Rule 8 must not detect the hook
5. ETW events must be silently dropped

## Hints

<div class="hint-box">
<details>
<summary>Hint 1</summary>
Use <code>GetThreadContext</code> and <code>SetThreadContext</code> to read/write debug registers. Set <code>DR0</code> to the address of <code>EtwEventWrite</code> and enable the local breakpoint in <code>DR7</code>.
</details>
</div>

<div class="hint-box">
<details>
<summary>Hint 2</summary>
Register a Vectored Exception Handler with <code>AddVectoredExceptionHandler</code>. In the handler, check for <code>EXCEPTION_SINGLE_STEP</code> and verify the exception address matches <code>EtwEventWrite</code>.
</details>
</div>

<div class="hint-box">
<details>
<summary>Hint 3</summary>
In the VEH handler, set <code>RIP</code> to the return address (read from <code>[RSP]</code>), set <code>RAX</code> to 0 (STATUS_SUCCESS), adjust <code>RSP += 8</code>, and return <code>EXCEPTION_CONTINUE_EXECUTION</code>. The function is "called" but never actually runs.
</details>
</div>

## Further Reading

- [ETW-TI Deep Dive](https://benjitrapp.github.io/defenses/2026-06-19-etw-ti/) — How kernel-mode ETW-TI detects `NtSetContextThread` for debug register manipulation
- [Hell's Gate, Heaven's Gate & Tartarus Gate](https://benjitrapp.github.io/attacks/2026-01-19-hells-heaven-tartarus-gate/) — Related syscall-level bypass techniques
