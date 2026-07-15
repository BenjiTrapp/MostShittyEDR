---
title: "Challenge 16: Elevated Process Evasion"
difficulty: medium
category: "Execution Evasion"
target_rule: "Architecture"
---

## Objective

Execute a suspicious command as an elevated (administrator) process to prevent the EDR from reading its command line.

## Scanner Behavior

The EDR reads command lines by opening target processes with `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ` and reading their PEB:

```nim
let hProc = OpenProcess(
  PROCESS_QUERY_INFORMATION or PROCESS_VM_READ,
  WINBOOL(0), pid)
if hProc == 0: return  # Can't read -> empty command line
```

If `OpenProcess` fails (e.g., due to insufficient privileges), the command line is empty, and **all command-line-based rules are bypassed**.

## Rules

- Run the EDR agent as a standard user
- Execute a suspicious command from an elevated (admin) prompt
- Show that command-line-based rules (2, 4, 5) are not triggered

## Hints

<details class="hint-box"><summary>Hint 1</summary>
A standard-user process cannot read the PEB of an elevated (admin) process.
</details>

<details class="hint-box"><summary>Hint 2</summary>
When <code>OpenProcess</code> fails, <code>getCommandLine</code> returns an empty string. No keywords can match an empty string.
</details>

<details class="hint-box"><summary>Hint 3</summary>
Rule 1 (process name blacklist) still works because <code>CreateToolhelp32Snapshot</code> can see all process names regardless of privilege level. But Rules 2, 4, and 5 are blind.
</details>
