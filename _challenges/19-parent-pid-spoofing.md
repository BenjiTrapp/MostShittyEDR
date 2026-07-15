---
title: "Challenge 19: Parent PID Spoofing"
difficulty: hard
category: "Advanced Bypass"
target_rule: "Architecture"
---

## Objective

Create a process with a spoofed parent PID to demonstrate that the EDR has no parent-child process chain analysis.

## Scanner Behavior

The EDR records `parentPid` from `PROCESSENTRY32W.th32ParentProcessID` but **never uses it for detection**. There are no rules that check:
- Whether the parent process is legitimate
- Whether the parent-child relationship makes sense
- Whether the parent PID was spoofed

## Rules

- Create a new process with a spoofed parent PID
- The parent should appear as a system process (e.g., `explorer.exe`, `svchost.exe`)
- Show that the EDR does not flag the suspicious parent relationship

## Hints

<details class="hint-box"><summary>Hint 1</summary>
Windows allows setting a custom parent process via <code>PROC_THREAD_ATTRIBUTE_PARENT_PROCESS</code> in <code>CreateProcessW</code> with <code>EXTENDED_STARTUPINFO_PRESENT</code>.
</details>

<details class="hint-box"><summary>Hint 2</summary>
Use <code>UpdateProcThreadAttribute</code> with <code>PROC_THREAD_ATTRIBUTE_PARENT_PROCESS</code> to specify a handle to the desired parent process.
</details>

<details class="hint-box"><summary>Hint 3</summary>
A real EDR would check if cmd.exe being spawned by winlogon.exe makes sense. This EDR has no such logic - it doesn't even look at parent PIDs in its detection rules.
</details>
