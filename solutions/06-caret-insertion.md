---
title: "Solution 06: Caret Insertion"
difficulty: easy
category: "Command Line Obfuscation"
---

[Back to Challenge]({{ '/challenges/06-caret-insertion/' | relative_url }})

## Overview

The caret `^` is cmd.exe's escape character. It is stripped during command parsing but remains in the raw command line string that the EDR reads.

## Solution

```cmd
:: Single caret insertion
cmd.exe /c who^ami

:: Multiple carets
cmd.exe /c w^h^o^a^m^i

:: Applied to other commands
cmd.exe /c net^ user
cmd.exe /c net^ ^user /domain
cmd.exe /c n^e^t u^s^e^r
```

## Why It Works

1. The EDR reads the command line from the PEB: `cmd.exe /c who^ami`
2. It searches for `"whoami"` in the command line
3. The string `"who^ami"` does not contain the substring `"whoami"`
4. No match - no detection!
5. Meanwhile, cmd.exe strips the carets and executes `whoami` normally

## Alternative Approaches

```cmd
:: Double quotes (empty strings)
cmd.exe /c who""ami

:: Using cmd variable substitution
cmd.exe /c set x=whoami && call %x%
```
