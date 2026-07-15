---
title: "Challenge 08: Base64 Encoded Commands"
difficulty: medium
category: "Command Line Obfuscation"
target_rule: "2, 5"
---

## Objective

Execute suspicious PowerShell commands using Base64 encoding to bypass keyword detection.

## Scanner Behavior

Rule 2 checks for suspicious keywords in the raw command line. Rule 5 checks for PowerShell flags like `-encodedcommand` and `-enc`.

```nim
const SuspiciousPSFlags = [
  "-encodedcommand",
  "-enc ",
  ...
]
```

However, Rule 5 uses `toLowerAscii()` for comparison. And the flag list contains specific strings with specific casing.

## Rules

- Execute `Invoke-Expression` or `downloadstring` via PowerShell
- The raw command line must not contain those keywords in plaintext
- You must bypass both Rule 2 (keywords) and Rule 5 (PS flags)

## Hints

<details class="hint-box"><summary>Hint 1</summary>
PowerShell's <code>-EncodedCommand</code> parameter accepts Base64-encoded UTF-16LE commands.
</details>

<details class="hint-box"><summary>Hint 2</summary>
The flag <code>-encodedcommand</code> is in the detection list, but PowerShell accepts abbreviations: <code>-EC</code>, <code>-En</code>, <code>-Enco</code>.
</details>

<details class="hint-box"><summary>Hint 3</summary>
Rule 5 only checks if the process is <code>powershell.exe</code>. Using <code>pwsh.exe</code> bypasses Rule 5 entirely.
</details>
