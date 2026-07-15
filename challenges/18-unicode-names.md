---
title: "Challenge 18: Unicode Process Names"
difficulty: hard
category: "Execution Evasion"
target_rule: "Architecture"
---

## Objective

Use Unicode characters in process or command names to exploit the EDR's ASCII-only string handling.

## Scanner Behavior

The EDR converts wide strings (UTF-16) to ASCII by masking to 7 bits:

```nim
proc wcharToStr(arr: openArray[WCHAR]): string =
  for c in arr:
    if c == 0: break
    if int(c) < 128:
      result.add(chr(int(c)))
    else:
      result.add('?')  # Non-ASCII becomes '?'
```

Characters outside the ASCII range are replaced with `?`. This breaks pattern matching for names containing Unicode.

## Rules

- Create or rename an executable using Unicode characters that resemble ASCII letters (homoglyphs)
- The EDR must misidentify or fail to match the process name
- The executable must still run on Windows

## Hints

<details class="hint-box"><summary>Hint 1</summary>
Unicode has many characters that look like ASCII letters but have different code points. These are called homoglyphs.
</details>

<details class="hint-box"><summary>Hint 2</summary>
Cyrillic 'a' (U+0430) looks identical to Latin 'a' (U+0061) but has a different code point. The EDR converts it to '?'.
</details>

<details class="hint-box"><summary>Hint 3</summary>
<code>mimik?tz.exe</code> (with a Cyrillic 'a') becomes <code>mimik?tz.exe</code> in the EDR's view, which does not match "mimikatz.exe".
</details>
