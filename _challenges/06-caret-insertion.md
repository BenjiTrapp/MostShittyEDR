---
title: "Challenge 06: Caret Insertion"
difficulty: easy
category: "Command Line Obfuscation"
target_rule: 2
---

## Objective

Execute `whoami` via `cmd.exe` without the EDR detecting the keyword in the command line.

## Scanner Behavior

Rule 2 uses simple substring matching on the command line:

```nim
proc ruleSuspiciousKeywords(info: ProcessInfo): seq[Detection] =
  let cmd = info.commandLine.toLowerAscii()
  for kw in SuspiciousKeywords:
    if kw in cmd:  # simple substring search
      ...
```

There is **no deobfuscation engine**. The raw command line string is checked as-is.

## Rules

- Execute `whoami` and see the output
- The EDR must not trigger a `SUSPICIOUS_CMDLINE` detection for "whoami"
- You must use `cmd.exe` to execute the command

## Hints

<details class="hint-box"><summary>Hint 1</summary>
The caret character <code>^</code> is an escape character in cmd.exe that is stripped during execution.
</details>

<details class="hint-box"><summary>Hint 2</summary>
<code>cmd.exe /c who^ami</code> - cmd.exe strips the caret, but the command line string still contains it.
</details>

<details class="hint-box"><summary>Hint 3</summary>
The EDR searches for "whoami" but the command line contains "who^ami". No match!
</details>
