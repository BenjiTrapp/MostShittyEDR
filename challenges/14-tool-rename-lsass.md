---
title: "Challenge 14: Tool Rename for LSASS"
difficulty: medium
category: "Process Monitoring Bypass"
target_rule: 4
---

## Objective

Use a known LSASS dump tool after renaming it to bypass the dual-condition detection rule.

## Scanner Behavior

Rule 4 checks if the process name or command line contains known dump tool names:

```nim
const LsassDumpIndicators = [
  "procdump", "sqldumper", "dumpert", "nanodump",
  "comsvcs", "minidumpwritedump", "dbghelp", "dbgcore"
]
```

The rule triggers only if a tool name matches AND a LSASS-related keyword is found.

## Rules

- Use procdump, sqldumper, or another dump tool
- Rename it so the tool name is not in the indicator list
- Target the LSASS process (by PID or name)
- The EDR must not trigger a `LSASS_DUMP` detection

## Hints

<details class="hint-box"><summary>Hint 1</summary>
If the tool name doesn't match any indicator, the rule never checks for "lsass" in the command line.
</details>

<details class="hint-box"><summary>Hint 2</summary>
<code>copy procdump.exe pd.exe</code> then <code>pd.exe -ma lsass</code> - "pd" is not in the indicator list.
</details>

<details class="hint-box"><summary>Hint 3</summary>
Note that Rule 1 (process blacklist) also catches "procdump.exe" by name. Renaming defeats both rules simultaneously.
</details>
