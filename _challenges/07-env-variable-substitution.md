---
title: "Challenge 07: Environment Variable Substitution"
difficulty: medium
category: "Command Line Obfuscation"
target_rule: 2
---

## Objective

Execute a suspicious command by hiding keywords inside environment variables.

## Scanner Behavior

Rule 2 checks the **raw command line string** as it appears in the process's PEB. Environment variables like `%COMSPEC%` or `%USERNAME%` are stored unexpanded in the command line and only resolved at runtime by `cmd.exe`.

The EDR does **not** expand environment variables before checking.

## Rules

- Execute `whoami` or `net user` using environment variable substitution
- The command must execute successfully and show output
- The raw command line must not contain the keyword

## Hints

<details class="hint-box"><summary>Hint 1</summary>
Environment variables in the command line are not expanded when the EDR reads the PEB.
</details>

<details class="hint-box"><summary>Hint 2</summary>
You can build command strings using substrings of environment variables. <code>%COMSPEC%</code> expands to <code>C:\WINDOWS\system32\cmd.exe</code>.
</details>

<details class="hint-box"><summary>Hint 3</summary>
<code>cmd.exe /c %COMSPEC:~-7,1%%COMSPEC:~-6,1%oami</code> constructs "whoami" from substrings at runtime.
</details>
