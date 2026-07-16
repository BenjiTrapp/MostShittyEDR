---
layout: default
title: "Home | MostShittyEDR"
---

<div class="hero">
  <img src="{{ '/static/logo.png' | relative_url }}" alt="MostShittyEDR" class="hero-logo">
  <h1>MostShittyEDR</h1>
  <p class="subtitle">The World's Most Intentionally Terrible EDR — an educational platform for understanding EDR detection and evasion techniques.</p>
  <div class="stats">
    <div class="stat">
      <div class="stat-number">36</div>
      <div class="stat-label">Challenges</div>
    </div>
    <div class="stat">
      <div class="stat-number">9</div>
      <div class="stat-label">Categories</div>
    </div>
    <div class="stat">
      <div class="stat-number">36</div>
      <div class="stat-label">Solutions</div>
    </div>
  </div>
</div>

## Challenge Categories

<div class="card-grid">
  <a href="{{ '/challenges/#category-1-process-name-evasion' | relative_url }}" class="card">
    <div class="card-title">Process Name Evasion</div>
    <div class="card-description">Bypass the static process name blacklist through renaming, case tricks, and using unlisted tools.</div>
    <div class="card-meta">
      <span class="badge badge-category">4 Challenges</span>
      <span class="badge badge-easy">Easy</span>
    </div>
  </a>

  <a href="{{ '/challenges/#category-2-command-line-obfuscation' | relative_url }}" class="card">
    <div class="card-title">Command Line Obfuscation</div>
    <div class="card-description">Evade keyword detection using carets, environment variables, encoding, and discovering dead rules.</div>
    <div class="card-meta">
      <span class="badge badge-category">5 Challenges</span>
      <span class="badge badge-easy">Easy - Medium</span>
    </div>
  </a>

  <a href="{{ '/challenges/#category-3-process-monitoring-bypass' | relative_url }}" class="card">
    <div class="card-title">Process Monitoring Bypass</div>
    <div class="card-description">Exploit polling intervals, pre-existing processes, living-off-the-land, and LSASS dump evasion.</div>
    <div class="card-meta">
      <span class="badge badge-category">5 Challenges</span>
      <span class="badge badge-medium">Easy - Medium</span>
    </div>
  </a>

  <a href="{{ '/challenges/#category-4-execution-evasion' | relative_url }}" class="card">
    <div class="card-title">Execution Evasion</div>
    <div class="card-description">Alternative PowerShell hosts, privilege escalation, WoW64 tricks, and Unicode abuse.</div>
    <div class="card-meta">
      <span class="badge badge-category">4 Challenges</span>
      <span class="badge badge-medium">Medium - Hard</span>
    </div>
  </a>

  <a href="{{ '/challenges/#category-5-advanced-bypass' | relative_url }}" class="card">
    <div class="card-title">Advanced Bypass</div>
    <div class="card-description">Parent PID spoofing and discovering that hash-based detection is pure security theater.</div>
    <div class="card-meta">
      <span class="badge badge-category">2 Challenges</span>
      <span class="badge badge-hard">Easy - Hard</span>
    </div>
  </a>

  <a href="{{ '/challenges/#category-6-api-hook-evasion' | relative_url }}" class="card">
    <div class="card-title">API Hook Evasion</div>
    <div class="card-description">Bypass static import analysis using dynamic resolution, DLL proxying, direct syscalls, and ntdll unhooking. Uses real EDR hook profiles.</div>
    <div class="card-meta">
      <span class="badge badge-category">4 Challenges</span>
      <span class="badge badge-hard">Medium - Hard</span>
    </div>
  </a>

  <a href="{{ '/challenges/#category-7-etw-bypass' | relative_url }}" class="card">
    <div class="card-title">ETW Bypass</div>
    <div class="card-description">Blind the EDR's ETW telemetry via session killing, EtwEventWrite patching, provider manipulation, and patchless hardware breakpoint hooks.</div>
    <div class="card-meta">
      <span class="badge badge-category">4 Challenges</span>
      <span class="badge badge-hard">Easy - Hard</span>
    </div>
  </a>

  <a href="{{ '/challenges/#category-8-signature-bypass' | relative_url }}" class="card">
    <div class="card-title">Signature Bypass</div>
    <div class="card-description">Evade SHA256 hash-based detection via byte patching, signature file enumeration, process hollowing, and recompilation.</div>
    <div class="card-meta">
      <span class="badge badge-category">4 Challenges</span>
      <span class="badge badge-hard">Easy - Hard</span>
    </div>
  </a>

  <a href="{{ '/challenges/#category-9-packer--pe-evasion' | relative_url }}" class="card">
    <div class="card-title">Packer & PE Evasion</div>
    <div class="card-description">Evade PE structure analysis via UPX section renaming, custom packers, Astral-PE header obfuscation, and runtime unpacking.</div>
    <div class="card-meta">
      <span class="badge badge-category">4 Challenges</span>
      <span class="badge badge-hard">Medium - Hard</span>
    </div>
  </a>

  <a href="{{ '/challenges/' | relative_url }}" class="card">
    <div class="card-title">Getting Started</div>
    <div class="card-description">New here? Browse all 36 challenges, pick your difficulty, and start bypassing.</div>
    <div class="card-meta">
      <span class="badge badge-category">Guide</span>
    </div>
  </a>
</div>

---

## How It Works

The MostShittyEDR agent implements **9 detection rules** with intentional weaknesses:

| Rule | Method | Action | Exploitable? |
|------|--------|--------|:---:|
| 1 | Process Name Blacklist (12 names) | **BLOCKS** | Yes |
| 2 | Command Line Keywords (substring) | **BLOCKS** | Yes |
| 3 | Reconnaissance Detection | `discard` | Yes |
| 4 | LSASS Dump Detection (dual condition) | **BLOCKS** | Yes |
| 5 | PowerShell Analysis (flags) | **BLOCKS** | Yes |
| 6 | Hash-Based Detection (SHA256, `--signatures`) | **BLOCKS** | Yes |
| 7 | Hooked API Import Detection | **ALERTS** | Yes |
| 8 | ETW Integrity Check | **BLOCKS** | Yes |
| 9 | PE Structure Analysis (packer/header) | **ALERTS** | Yes |

> **Note:** This is NOT production security software. It is an educational tool designed for understanding EDR evasion techniques in a safe, controlled environment.

---

## Quick Start

```powershell
# Clone the repository
git clone https://github.com/BenjiTrapp/MostShittyEDR.git

# Build the EDR agent
make build

# Run in safe mode (detect only, no kills)
.\edr_agent.exe --verbose --no-kill
```

Browse the [Challenges]({{ '/challenges/' | relative_url }}) to begin, or check the [MostShittyAV](https://benjitrapp.github.io/MostShittyAV/) companion lab for AMSI bypass challenges.

---

## Further Reading

Deep-dive blog posts on EDR internals, bypass techniques, and defensive telemetry:

<div class="reading-grid">
  <a href="https://benjitrapp.github.io/attacks/2024-08-21-edr-and-malware/" class="reading-card" target="_blank">
    <span class="card-tag">EDR Deep Dive</span>
    <div class="card-title">Understanding and Attacking EDRs</div>
    <div class="card-description">How malware detection works, EDR internals, API/kernel hooking, and attack strategies against EDR solutions.</div>
  </a>

  <a href="https://benjitrapp.github.io/attacks/2026-06-19-edr-hook-detection/" class="reading-card" target="_blank">
    <span class="card-tag">Detection</span>
    <div class="card-title">Hunting the Watchers: Detecting EDR Hooks</div>
    <div class="card-description">Techniques to detect and identify EDR hooks in user-mode DLLs, including syscall stub analysis.</div>
  </a>

  <a href="https://benjitrapp.github.io/attacks/2026-01-18-EDR-bypass-roadmap/" class="reading-card" target="_blank">
    <span class="card-tag">Roadmap</span>
    <div class="card-title">EDR Bypass Roadmap</div>
    <div class="card-description">A structured path through EDR bypass techniques, from basic evasion to advanced kernel-level attacks.</div>
  </a>

  <a href="https://benjitrapp.github.io/attacks/2026-01-19-hells-heaven-tartarus-gate/" class="reading-card" target="_blank">
    <span class="card-tag">Syscalls</span>
    <div class="card-title">Hell's Gate, Heaven's Gate & Tartarus Gate</div>
    <div class="card-description">Direct and indirect syscall techniques to bypass user-mode EDR hooks entirely.</div>
  </a>

  <a href="https://benjitrapp.github.io/defenses/2026-06-19-etw-ti/" class="reading-card" target="_blank">
    <span class="card-tag">Telemetry</span>
    <div class="card-title">ETW-TI Deep Dive</div>
    <div class="card-description">Understanding Event Tracing for Windows Threat Intelligence — the kernel-level telemetry that feeds modern EDRs.</div>
  </a>

  <a href="https://benjitrapp.github.io/attacks/2024-02-11-offensive-etw/" class="reading-card" target="_blank">
    <span class="card-tag">Offense</span>
    <div class="card-title">Breaking ETW and EDR</div>
    <div class="card-description">Offensive techniques to blind EDR telemetry by tampering with ETW providers and consumers.</div>
  </a>
</div>

---

## Related Projects

- [MostShittyAV](https://benjitrapp.github.io/MostShittyAV/) — The companion AMSI bypass lab (43 challenges)
