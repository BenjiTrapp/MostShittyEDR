---
title: "Challenge 05: Path Manipulation"
difficulty: easy
category: "Command Line Obfuscation"
target_rule: 1
---

## Objective

Execute a blacklisted process using path tricks to confuse the filename extraction.

## Scanner Behavior

The EDR gets the process name from `PROCESSENTRY32W.szExeFile`, which contains only the executable filename (no path). However, the command line (Rule 2) contains the full command as typed.

## Rules

- Execute a blacklisted tool using the full path or UNC path
- Explore whether the EDR sees the full path or just the filename
- Document which rules are path-aware and which are not

## Hints

<details class="hint-box"><summary>Hint 1</summary>
<code>szExeFile</code> from Toolhelp32 only contains the filename, not the full path.
</details>

<details class="hint-box"><summary>Hint 2</summary>
The command line (Rule 2) contains whatever was typed. Can you use path syntax to hide keywords?
</details>

<details class="hint-box"><summary>Hint 3</summary>
Try using the full path: <code>C:\Windows\System32\notepad.exe</code> - is "notepad.exe" still extracted?
</details>
