---
layout: default
title: "EDR Explained | MostShittyEDR"
permalink: /edr-explained/
---

# EDR Explained: Endpoint Detection & Response

Modern EDR solutions are the frontline defense against advanced threats on endpoints. They combine multiple detection layers, from user-mode hooking to kernel-level telemetry, to identify and respond to malicious activity in real time. This page explains how they work, why they're effective, and where their weaknesses lie.

* * *

## What is an EDR?

An **Endpoint Detection & Response (EDR)** system is a security solution that continuously monitors endpoint activity, collects telemetry, and applies detection logic to identify threats. Unlike traditional antivirus that relies solely on signatures, EDRs combine behavioral analysis, kernel-level visibility, and centralized correlation to detect attacks that signatures miss.

**Key differences from traditional AV:**

- **AV** scans files at rest, while **EDR** monitors behavior in real time
- **AV** relies on known signatures, while **EDR** uses behavioral heuristics and correlation
- **AV** operates mostly in user-space, while **EDR** hooks deep into the kernel
- **AV** blocks or quarantines, while **EDR** detects, responds, AND provides forensic context

* * *

## EDR Architecture

A typical enterprise EDR consists of four core components working together:

| Component | Role | Examples |
|-----------|------|----------|
| **EDR Agent** | User-mode process that coordinates sensors, applies detection logic, and reports to the backend | CrowdStrike Falcon Sensor, SentinelOne Agent, Defender for Endpoint |
| **Sensors** | Components that observe system activity and convert events into telemetry | Kernel callbacks, minifilters, ETW consumers, API hooks |
| **Telemetry** | Raw event data representing system activity | Process creation, file writes, network connections, registry changes |
| **Detections** | Logic that correlates telemetry into threat verdicts | Signature rules, behavioral models, YARA rules, ML classifiers |

### High-Level Architecture

<pre class="mermaid">
graph TB
    subgraph Cloud["EDR Backend / Cloud"]
        CE[Correlation Engine]
        TI[Threat Intelligence]
        UI[Management UI]
    end

    subgraph Agent["EDR Agent (User-Mode)"]
        DE[Detection Engine]
        RA[Response Actions]
        TC[Telemetry Collector & Forwarder]
    end

    subgraph Kernel["Kernel-Mode Components"]
        PC[Process Callbacks]
        MF[Filesystem Minifilter]
        ETW[ETW Threat Intelligence]
    end

    Kernel -->|Raw Events| Agent
    Agent -->|Telemetry Upload| Cloud
    Cloud -->|Policy Updates| Agent
</pre>

* * *

## How Detection Works (Step by Step)

1. **Event occurs:** A process is created, a file is written, or a network connection is opened
2. **Kernel sensor fires:** A registered callback or minifilter captures the raw event
3. **Telemetry is generated:** The event is normalized into a structured data point
4. **Agent receives telemetry:** The user-mode agent collects events from all sensors
5. **Detection logic runs:** Rules, heuristics, and ML models evaluate the event in context
6. **Verdict is reached:** Clean, suspicious, or malicious
7. **Response executes:** Alert, block, quarantine, isolate, or kill the process
8. **Telemetry is forwarded:** Events and verdicts are sent to the cloud backend for correlation

* * *

## Kernel-Level Sensors

The kernel is where EDRs gain their deepest visibility. These are the primary kernel mechanisms:

### Process & Thread Callbacks

Windows provides kernel notification routines that fire on every process/thread lifecycle event:

| Callback | Purpose |
|----------|---------|
| `PsSetCreateProcessNotifyRoutineEx` | Notified on every process creation/exit, with the ability to block creation |
| `PsSetCreateThreadNotifyRoutine` | Notified on every thread creation/exit |
| `PsSetLoadImageNotifyRoutine` | Notified on every image (DLL/EXE) load |
| `ObRegisterCallbacks` | Intercepts handle operations (e.g., protect LSASS handles) |
| `CmRegisterCallbackEx` | Monitors registry operations |

These callbacks fire **in kernel context**, meaning they cannot be evaded by user-mode techniques alone.

### Filesystem Minifilters

Minifilters monitor all filesystem I/O through the Filter Manager framework:

- **Pre-operation callbacks** inspect and can block operations before they execute
- **Post-operation callbacks** inspect results after completion
- **Altitude-based ordering** uses a numerical altitude to determine execution order

**Common EDR minifilter altitudes:**

| Vendor | Driver | Altitude |
|--------|--------|----------|
| Microsoft Defender | WdFilter.sys | 328010 |
| CrowdStrike | csagent.sys | 321410 |
| SentinelOne | sentinelmonitor.sys | 389040 |
| Elastic | ElasticEndpoint.sys | 385100 |
| Carbon Black | cbk7.sys | 385200 |

### ETW Threat Intelligence

**Event Tracing for Windows (ETW)** provides high-fidelity telemetry directly from the kernel:

- `Microsoft-Windows-Threat-Intelligence` fires on memory allocation, process hollowing, and code injection
- Operates from `ntoskrnl.exe` kernel callbacks and is immune to user-mode tampering
- Cannot be disabled without kernel-level access (unlike regular ETW sessions)

ETW is critical enough to deserve its own deep-dive — see [ETW: Event Tracing for Windows](#etw-event-tracing-for-windows) below.

* * *

## User-Mode Hooking

EDRs inject DLLs into every process and hook critical Windows API functions in `ntdll.dll`:

### How Hooking Works

<pre class="mermaid">
graph LR
    subgraph Normal["Normal Execution"]
        A1[Application] --> N1[NtWriteVirtualMemory]
        N1 --> S1["mov r10, rcx<br/>mov eax, 0x3A<br/>syscall<br/>ret"]
        S1 --> K1[Kernel]
    end

    subgraph Hooked["Hooked Execution"]
        A2[Application] --> N2[NtWriteVirtualMemory]
        N2 --> J["jmp EDR_Hook"]
        J --> EDR["EDR Analysis<br/>(inspect args)"]
        EDR --> O["Execute original<br/>syscall stub"]
        O --> K2[Kernel]
    end
</pre>

### Hooking Methods

| Method | Technique | Detection Scope |
|--------|-----------|-----------------|
| **Inline Hooking** | Overwrites first bytes of ntdll functions with `jmp` to EDR code | Most common; intercepts all calls through ntdll |
| **IAT Hooking** | Modifies Import Address Table entries | Catches statically linked imports only |
| **Hardware Breakpoints** | Uses CPU debug registers (DR0-DR3) | Stealthy, limited to 4 breakpoints |
| **Trampoline Hooks** | Redirects via allocated code caves | Common variant of inline hooking |

* * *

## Syscall Stubs & Direct Syscalls

The transition from user-mode to kernel-mode happens through **syscall stubs** in `ntdll.dll`:

```asm
; Normal syscall stub (x64) for NtWriteVirtualMemory
NtWriteVirtualMemory:
    mov r10, rcx            ; Save first parameter
    mov eax, 0x3A           ; Syscall number (version-specific!)
    syscall                 ; Transition to kernel
    ret                     ; Return to caller
```

EDRs hook these stubs by replacing the first bytes with a `jmp`. Bypass techniques resolve the syscall number (SSN) dynamically and invoke `syscall` directly, skipping the hooked stub entirely.

**Resolution techniques:**

- **Hell's Gate** reads SSNs from neighboring unhooked stubs
- **Halos Gate** extends Hell's Gate with fallback resolution
- **Tartarus Gate** handles multiple consecutive hooked functions
- **SysWhispers** provides compile-time SSN resolution from version tables

* * *

## ETW: Event Tracing for Windows

ETW is the **single most important telemetry source** for modern EDRs on Windows. It provides structured, high-performance event tracing from both user-mode and kernel-mode components. Understanding ETW is essential for both defending and attacking EDR solutions.

For background, see [Breaking ETW and EDR](https://benjitrapp.github.io/attacks/2024-02-11-offensive-etw/) and [ETW-TI Deep Dive](https://benjitrapp.github.io/defenses/2026-06-19-etw-ti/).

### ETW Architecture

ETW is built on three roles: **Providers** generate events, **Controllers** manage trace sessions, and **Consumers** read events.

<pre class="mermaid">
graph LR
    subgraph Providers
        P1["Microsoft-Windows-<br/>Kernel-Process"]
        P2["Microsoft-Windows-<br/>Threat-Intelligence"]
        P3["Microsoft-Windows-<br/>DotNETRuntime"]
        P4["EDR Custom<br/>Provider"]
    end

    subgraph Controller["Controller (logman / ETW API)"]
        S1["Trace Session<br/>(real-time or file)"]
    end

    subgraph Consumers
        C1["EDR Agent"]
        C2["Windows<br/>Event Log"]
        C3["SIEM<br/>Forwarder"]
    end

    P1 -->|Events| S1
    P2 -->|Events| S1
    P3 -->|Events| S1
    P4 -->|Events| S1
    S1 -->|Buffered delivery| C1
    S1 -->|Buffered delivery| C2
    S1 -->|Buffered delivery| C3
</pre>

**Key concepts:**

| Concept | Description |
|---------|-------------|
| **Provider** | A component that emits structured events via `EventWrite` / `EtwWrite` |
| **Session** | A named kernel object that buffers events from enabled providers |
| **Consumer** | An application that reads events from a session (real-time or from `.etl` files) |
| **Controller** | Starts/stops sessions and enables/disables providers within them |
| **Keywords** | Bitmask filters that select which event categories a provider emits |
| **Level** | Severity filter (Critical=1, Error=2, Warning=3, Info=4, Verbose=5) |

### ETW Providers Used by EDRs

EDRs consume events from multiple built-in Windows providers:

| Provider | GUID | What It Monitors |
|----------|------|-----------------|
| `Microsoft-Windows-Kernel-Process` | `{22FB2CD6-...}` | Process creation, exit, image load |
| `Microsoft-Windows-Kernel-File` | `{EDD08927-...}` | File system operations |
| `Microsoft-Windows-Kernel-Network` | `{7DD42A49-...}` | TCP/UDP connection events |
| `Microsoft-Windows-Kernel-Registry` | `{70EB4F03-...}` | Registry key/value operations |
| `Microsoft-Windows-Threat-Intelligence` | `{F4E1897C-...}` | Cross-process memory ops, injection, code execution |
| `Microsoft-Windows-DotNETRuntime` | `{E13C0D23-...}` | .NET assembly loading, JIT compilation |
| `Microsoft-Windows-PowerShell` | `{A0C1853B-...}` | PowerShell script block logging |
| `Microsoft-Antimalware-Scan-Interface` | `{2A576B87-...}` | AMSI scan events |

EDRs typically also register their **own custom providers** for internal telemetry and diagnostics.

### User-Mode vs Kernel-Mode ETW

This is the most critical distinction for understanding ETW bypass:

<pre class="mermaid">
graph TB
    subgraph UserMode["User-Mode ETW (Bypassable)"]
        App["Application<br/>calls NtXxx()"]
        NtDll["ntdll.dll<br/>EtwEventWrite()"]
        App --> NtDll
        NtDll -.->|"Can be patched<br/>(ret / xor eax,eax;ret)"| Blind["Events<br/>Silenced ❌"]
    end

    subgraph KernelMode["Kernel-Mode ETW-TI (Protected)"]
        Syscall["syscall instruction"]
        Kernel["ntoskrnl.exe<br/>NtWriteVirtualMemory()"]
        EtwTi["EtwTiLogReadWriteVm()"]
        Session["ETW-TI Session<br/>(PPL-protected)"]
        Syscall --> Kernel
        Kernel --> EtwTi
        EtwTi -->|"Events fire from<br/>ring 0 — cannot be<br/>patched from user-mode"| Session
    end

    App -.->|"syscall"| Syscall

    style Blind fill:#c62828,color:#fff
    style Session fill:#2e7d32,color:#fff
</pre>

| Property | User-Mode ETW | Kernel-Mode ETW-TI |
|----------|--------------|-------------------|
| **Where events fire** | `ntdll.dll` (user-space) | `ntoskrnl.exe` (kernel-space) |
| **Patchable from user-mode?** | Yes — patch `EtwEventWrite` | No — code is in ring 0 |
| **Session killable?** | Yes — `logman stop` | No — requires PPL access |
| **Provider disablable?** | Yes — ETW controller APIs | No — only PPL consumers can subscribe |
| **Access control** | Admin can manage sessions | **PPL-AM** (Protected Process Light - Antimalware) required |
| **Bypass difficulty** | Easy to Medium | Requires kernel access (BYOVD, exploit) |

### ETW-TI: The Kernel's Eye

The `Microsoft-Windows-Threat-Intelligence` provider (GUID `{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}`) is a **kernel-mode-only** provider introduced in Windows 10 RS2. Events fire **after the syscall transitions to ring 0**, making them immune to all user-land bypass techniques.

<pre class="mermaid">
graph TB
    subgraph Operations["Monitored Operations"]
        O1["NtAllocateVirtualMemory<br/>(RWX detection)"]
        O2["NtWriteVirtualMemory<br/>(cross-process write)"]
        O3["NtMapViewOfSection<br/>(section mapping)"]
        O4["NtSetContextThread<br/>(thread hijacking)"]
        O5["NtQueueApcThread<br/>(APC injection)"]
        O6["NtCreateThreadEx<br/>(remote thread)"]
        O7["NtProtectVirtualMemory<br/>(permission change)"]
    end

    subgraph Kernel["ntoskrnl.exe"]
        ETL["EtwTiLog* Functions"]
        REG["nt!EtwThreatIntProvRegHandle"]
    end

    subgraph Consumer["PPL-Protected Consumer"]
        EDR["EDR Kernel Driver<br/>(ELAM-signed, PPL-AM)"]
        CORR["Behavioral<br/>Correlation"]
    end

    O1 & O2 & O3 & O4 & O5 & O6 & O7 --> ETL
    ETL --> REG
    REG -->|"Events"| EDR
    EDR --> CORR
</pre>

**What ETW-TI captures per event:**

- Calling process ID and target process ID
- Target virtual address and region size
- Memory protection flags (`PAGE_EXECUTE_READWRITE` is highly suspicious)
- Call stack at the point of invocation
- Whether the call bypassed user-mode hooks (direct syscall detection)

**Behavioral enrichment** — EDRs like Elastic annotate ETW-TI events with labels:

| Label | Meaning |
|-------|---------|
| `cross-process` | Source ≠ Target process |
| `direct_syscall` | Syscall stub was bypassed |
| `shellcode` | Execution from non-image (unbacked) memory |
| `unbacked_rwx` | RWX memory not backed by a file on disk |
| `image-hooked` | Inline hook detected in loaded module |

**Access protection:** Only processes running as `PS_PROTECTED_ANTIMALWARE_LIGHT` (PPL-AM) with an ELAM (Early Launch Antimalware) signed driver can subscribe to ETW-TI. This requires:
- A valid Microsoft-signed ELAM certificate
- The driver to load before other third-party drivers at boot
- `PS_PROTECTION.Type >= PsProtectedTypeProtectedLight`
- `PS_PROTECTION.Signer >= PsProtectedSignerAntimalware`

### ETW Bypass Techniques

These are the known approaches to blinding ETW telemetry, ordered by difficulty:

<pre class="mermaid">
graph TB
    subgraph Easy["Easy (User-Mode)"]
        B1["logman stop<br/>'Session-Name' -ets"]
        B2["Patch EtwEventWrite<br/>ret / xor eax,eax;ret"]
        B3["Provider disable<br/>via controller API"]
    end

    subgraph Medium["Medium (Advanced User-Mode)"]
        B4["Hardware breakpoint<br/>on EtwEventWrite"]
        B5["Unhook ntdll<br/>(restore from disk)"]
        B6["NtTraceControl<br/>manipulation"]
    end

    subgraph Hard["Hard (Kernel-Mode)"]
        B7["BYOVD: zero<br/>EtwThreatIntProvRegHandle"]
        B8["Kernel exploit<br/>disable EPROCESS flags"]
        B9["Callback removal<br/>via kernel R/W"]
    end

    subgraph Mitigations["Defenses"]
        D1["ETW-TI<br/>(immune to user-mode)"]
        D2["PatchGuard<br/>(detects kernel tampering)"]
        D3["PPL<br/>(protects EDR process)"]
    end

    Easy -.->|"Blocked by"| D1
    Medium -.->|"Blocked by"| D1
    Hard -.->|"Detected by"| D2
    
    style Easy fill:#1b5e20,color:#fff
    style Medium fill:#e65100,color:#fff
    style Hard fill:#b71c1c,color:#fff
    style Mitigations fill:#1565c0,color:#fff
</pre>

#### 1. Kill the Trace Session (Easy)

```powershell
logman stop "EDR-Session-Name" -ets
```

Requires admin, but session names are often discoverable via `logman query -ets`. See [Challenge 25](/challenges/25-kill-etw-session/).

#### 2. Patch EtwEventWrite (Easy-Medium)

```c
// Patch ntdll!EtwEventWrite to return SUCCESS without logging
BYTE patch[] = { 0x33, 0xC0, 0xC3 };  // xor eax, eax; ret
void* addr = GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite");
DWORD old;
VirtualProtect(addr, 3, PAGE_EXECUTE_READWRITE, &old);
memcpy(addr, patch, 3);
VirtualProtect(addr, 3, old, &old);
```

This blinds **all** user-mode ETW providers in the patched process. See [Challenge 26](/challenges/26-patch-etwwrite/).

#### 3. Provider Unregistration (Medium)

Disable a specific provider from a session using `EnableTraceEx2` with `EVENT_CONTROL_CODE_DISABLE_PROVIDER`. The session remains running but stops collecting from the targeted provider. See [Challenge 27](/challenges/27-provider-unregistration/).

#### 4. Hardware Breakpoint Hook (Hard)

Use CPU debug registers (DR0-DR3) and a Vectored Exception Handler to intercept `EtwEventWrite` without modifying code bytes — evading memory integrity checks entirely. See [Challenge 28](/challenges/28-hardware-breakpoint-hook/).

#### 5. Kernel-Mode Bypass (Expert)

The only way to bypass ETW-TI is with **kernel-level access**:

- **BYOVD** (Bring Your Own Vulnerable Driver): Load a signed driver with known vulnerabilities, use it to zero `nt!EtwThreatIntProvRegHandle` — but PatchGuard may detect the modification
- **Kernel exploit**: Direct ring-0 code execution to manipulate EPROCESS logging flags
- **NtSetInformationProcess** with `ProcessEnableLogging` class (patched in Windows 11, worked on some Windows 10 builds)

> **Key insight:** User-mode ETW bypass (patching `EtwEventWrite`, killing sessions) does NOT affect kernel-mode ETW-TI. Direct syscalls that bypass ntdll hooks still trigger ETW-TI events because they fire from `ntoskrnl.exe`.

### How the ETW Event Pipeline Flows

End-to-end path of a suspicious `NtWriteVirtualMemory` call through an EDR:

<pre class="mermaid">
sequenceDiagram
    participant App as Malware
    participant ntdll as ntdll.dll
    participant Hook as EDR Hook (user-mode)
    participant Kernel as ntoskrnl.exe
    participant TI as EtwTiLogReadWriteVm
    participant Session as ETW-TI Session
    participant Driver as EDR Kernel Driver
    participant Agent as EDR Agent

    App->>ntdll: NtWriteVirtualMemory()
    ntdll->>Hook: jmp EDR_hook_handler
    Hook->>Hook: Log arguments (user-mode ETW)
    Hook->>ntdll: Execute original stub
    ntdll->>Kernel: syscall (ring 0)
    Kernel->>TI: Cross-process write detected
    TI->>Session: EVENT: WriteVm (PID, target, flags, callstack)
    Session->>Driver: Buffered event delivery
    Driver->>Agent: Forward to user-mode for correlation
    Agent->>Agent: Correlate with other events
    Note over Agent: Write + CreateThread = injection pattern!
</pre>

Even if the malware patches `EtwEventWrite` (blinding user-mode ETW) or uses direct syscalls (bypassing the hook), the kernel path `Kernel → TI → Session → Driver` still fires.

* * *

## Detection Categories

### Signature-Based

Compares file hashes (MD5, SHA-256) or byte patterns against known malware databases.

**Strengths:** Fast, accurate for known threats, low false positives
**Weaknesses:** Zero detection of new/modified malware, trivially bypassed by recompilation

### Behavioral / Heuristic

Monitors execution patterns rather than static file properties:

- Process injection chains (alloc → write → create thread)
- Credential access patterns (LSASS handle with specific access rights)
- Lateral movement indicators (remote service creation, WMI execution)
- Living-off-the-land abuse (suspicious PowerShell, certutil downloads)

### PE Structure & Packer Analysis

Examines the on-disk PE (Portable Executable) structure for signs of packing, obfuscation, or tampering:

- **Section names** compared against known packer signatures (UPX0/UPX1, .aspack, .petite, etc.)
- **Section permissions** flagged when a section has RWX (Read/Write/Execute) — legitimate binaries almost never need this
- **Entry point location** verified to be inside the first code section — packed binaries often jump to a decompression stub in a later section
- **Section entropy** measured via Shannon entropy — encrypted/compressed payloads produce near-maximum entropy (~7.99 bits/byte) in their sections
- **Header integrity** validated against the PE specification — tools like [Astral-PE](https://github.com/DosX-dev/Astral-PE) corrupt fields that parsers rely on but the Windows loader ignores

**Strengths:** Catches off-the-shelf packers (UPX, ASPack, Petite) instantly, no signature database needed
**Weaknesses:** Custom packers with normal section names and standard permissions are invisible; header obfuscation crashes strict parsers silently; no entropy analysis means encrypted `.data` sections go unnoticed

### Machine Learning

Classifies files and behaviors using trained models:

- Static ML on PE features (imports, sections, entropy)
- Dynamic ML on execution traces
- Anomaly detection on process trees

* * *

## Response Actions

When a detection fires, the EDR can take graduated response actions:

| Action | Severity | Description |
|--------|----------|-------------|
| **Log** | Low | Record event for forensic review |
| **Alert** | Medium | Notify SOC analysts |
| **Block** | High | Prevent the operation from completing |
| **Kill** | Critical | Terminate the malicious process |
| **Isolate** | Critical | Disconnect endpoint from network (except EDR comms) |
| **Remediate** | Critical | Remove artifacts, roll back changes |

* * *

## Known EDR Weaknesses (Architectural)

Even well-implemented EDRs have structural limitations:

### 1. User-Mode Hooks Are Bypassable

Hooks in `ntdll.dll` exist in the process's own address space. An attacker with code execution can:
- Unhook by restoring original bytes from a clean ntdll copy
- Use direct/indirect syscalls to bypass hooks entirely
- Load a second ntdll from disk (`KnownDlls` or manual mapping)

### 2. Timing Windows

Kernel callbacks are not instantaneous and brief windows exist:
- Between process creation and hook initialization
- Between thread creation and callback registration
- Poll-based agents have gaps between scans

### 3. Kernel Trust Boundary

If an attacker gains kernel access (e.g., via BYOVD, Bring Your Own Vulnerable Driver):
- Callbacks can be unregistered
- Minifilters can be detached
- ETW providers can be disabled
- The EDR agent itself can be terminated

### 4. Blind Spots

- **Pre-existing processes** that were running before the EDR starts are not re-scanned
- **32-bit processes on 64-bit** systems are harder to monitor due to the WoW64 layer
- **Encrypted/packed content** can be flagged by static PE analysis (section names, entropy) but the actual payload cannot be analyzed until runtime unpacking occurs
- **Fileless attacks** executing only in memory avoid filesystem minifilters

### 5. Cloud Dependency

- Offline endpoints lose cloud correlation and updated threat intelligence
- Network-level blocking (firewall, proxy) can blind the backend
- Tools like **EDRSilencer** block telemetry upload via WFP rules

* * *

## How MostShittyEDR Implements (and Fails at) These Concepts

This lab deliberately implements each EDR concept in the weakest possible way:

| Real EDR Feature | MostShittyEDR Implementation | Why It's Weak |
|-----------------|------------------------------|---------------|
| Kernel callbacks | User-mode polling (Toolhelp32) | Timing gaps, no kernel visibility |
| Behavioral detection | Substring matching on command lines | No deobfuscation, no context |
| Hash database | SHA256 from plaintext file (`--signatures`) | Exact-match only, on-disk only, readable signature file |
| Process blocking | Case-sensitive name blacklist | Rename = bypass |
| LSASS protection | Dual-condition keyword match | Either condition alone = bypass |
| PowerShell analysis | Checks `powershell.exe` only | `pwsh.exe` is invisible |
| ETW telemetry | User-mode provider + session (Rule 8) | No kernel-mode ETW-TI, patchable `EtwEventWrite`, hardcoded session name |
| PE structure analysis | Section name matching + RWX check (Rule 9) | No entropy analysis, strict parser crashes on corrupted headers, no runtime re-scan |
| Response actions | `discard` on recon detection | Detects but never acts |

* * *

## EDR Bypass Categories

These are the primary categories of techniques used to evade EDR detection:

| Category | Technique | Complexity |
|----------|-----------|-----------|
| **Unhooking** | Restore original ntdll bytes from clean copy | Medium |
| **Direct Syscalls** | Invoke syscall instruction directly, skipping hooks | Medium |
| **Indirect Syscalls** | Jump to syscall instruction inside ntdll (avoids direct syscall detection) | Hard |
| **BYOVD** | Load vulnerable signed driver for kernel access | Hard |
| **Early Injection** | Inject before hooks are placed (Early Bird, Process Ghosting) | Hard |
| **ETW Blinding** | Patch ETW functions to suppress telemetry | Medium |
| **Minifilter Detach** | Unload or detach filesystem minifilters | Hard |
| **Callback Removal** | Enumerate and remove kernel notification callbacks | Hard |
| **Packer Evasion** | Custom packers with normal section names, or header obfuscation (Astral-PE) | Medium |
| **Telemetry Blocking** | Block EDR network communication via firewall/WFP | Easy |

* * *

## PatchGuard & Kernel Integrity

**Kernel Patch Protection (PatchGuard)** prevents unauthorized modification of kernel structures:

- Periodically verifies integrity of SSDT, IDT, GDT, and kernel code
- Triggers `CRITICAL_STRUCTURE_CORRUPTION` (bug check 0x109) on tampering
- Protects against SSDT hooking, which forces EDRs to use supported callback APIs instead
- Does NOT protect dynamically registered callbacks (EDR's own callback pointers)

This is why modern EDRs use `PsSetCreateProcessNotifyRoutineEx` instead of SSDT hooks. PatchGuard allows the callback-based approach.

* * *

## Further Reading

- [Understanding and Attacking EDRs](https://benjitrapp.github.io/attacks/2024-08-21-edr-and-malware/) for a deep dive into EDR internals and attack surfaces
- [EDR Hook Detection](https://benjitrapp.github.io/attacks/2026-06-19-edr-hook-detection/) for automated hook identification
- [Offensive ETW](https://benjitrapp.github.io/attacks/2024-02-11-offensive-etw/) on attacking Event Tracing for Windows
- [EDR Bypass Roadmap](https://benjitrapp.github.io/attacks/2026-01-18-EDR-bypass-roadmap/) for a strategic approach to bypassing EDR
- [ETW Threat Intelligence](https://benjitrapp.github.io/defenses/2026-06-19-etw-ti/) on kernel-level telemetry defense
- [MostShittyEDR Challenges](/MostShittyEDR/challenges/) to practice bypassing a deliberately weak EDR
