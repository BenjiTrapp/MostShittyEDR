---
title: "Challenge 15: Alternative PowerShell Host"
difficulty: medium
category: "Execution Evasion"
target_rule: 5
---

## Objective

Execute suspicious PowerShell commands without using `powershell.exe`.

## Scanner Behavior

Rule 5 only activates when the process name contains `powershell.exe`:

```nim
proc rulePowerShell(info: ProcessInfo): seq[Detection] =
  # WEAKNESS: only detects powershell.exe, not pwsh.exe
  if "powershell.exe" notin info.exeName.toLowerAscii():
    return  # Skip entirely!
  ...
```

Any process that isn't named `powershell.exe` bypasses Rule 5 completely.

## Rules

- Execute a PowerShell command that would trigger Rule 5 (e.g., `Invoke-Expression`, `-EncodedCommand`)
- Do not use `powershell.exe` as the process
- The command must execute successfully

## Hints

<details class="hint-box"><summary>Hint 1</summary>
PowerShell 7+ installs as <code>pwsh.exe</code>, which is not in the detection check.
</details>

<details class="hint-box"><summary>Hint 2</summary>
You can host the PowerShell engine in custom applications. <code>System.Management.Automation.dll</code> can be loaded by any .NET process.
</details>

<details class="hint-box"><summary>Hint 3</summary>
<code>pwsh.exe -Command "Invoke-Expression 'whoami'"</code> - pwsh.exe is not powershell.exe, so Rule 5 is skipped entirely.
</details>
