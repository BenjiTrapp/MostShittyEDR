## MostShittyEDR - EDR Bypass Lab
## A deliberately weak Endpoint Detection & Response agent
## for learning EDR evasion techniques.
##
## Usage: edr_agent.exe [--verbose] [--no-kill] [--interval MS] [--profile NAME]
##
## This agent monitors new processes via user-mode polling and
## applies intentionally weak detection rules. Each weakness
## maps to a bypass challenge.

import winim/lean
import winim/inc/tlhelp32
import std/[os, strutils, times, sets, parseopt, tables]

# ============================================================
# Constants
# ============================================================

const
  Version = "3.0.0"
  DefaultPollMs = 500

  # Windows console color attributes
  clReset   = 0x07'u16
  clRed     = 0x0C'u16
  clGreen   = 0x0A'u16
  clYellow  = 0x0E'u16
  clCyan    = 0x0B'u16
  clMagenta = 0x0D'u16
  clWhite   = 0x0F'u16

# ============================================================
# Types
# ============================================================

type
  Severity = enum
    sInfo     = "INFO"
    sWarning  = "WARN"
    sAlert    = "ALERT"
    sCritical = "CRIT"

  ProcessInfo = object
    pid: DWORD
    parentPid: DWORD
    exeName: string
    commandLine: string
    imagePath: string

  Detection = object
    ruleName: string
    ruleId: int
    severity: Severity
    description: string

  HookProfile = object
    name: string
    hookedApis: seq[string]

  Config = object
    verbose: bool
    noKill: bool
    noEtw: bool
    pollInterval: int
    profile: HookProfile

# ============================================================
# Globals
# ============================================================

var
  gRunning = true
  gKnownPids: HashSet[DWORD]
  gStats = (seen: 0, detections: 0, kills: 0)

let hStdout = GetStdHandle(STD_OUTPUT_HANDLE)

# ============================================================
# Console helpers
# ============================================================

proc setColor(c: uint16) =
  SetConsoleTextAttribute(hStdout, WORD(c))

proc ts(): string =
  now().format("HH:mm:ss'.'fff")

proc colorLine(c: uint16, msg: string) =
  setColor(c)
  echo msg
  setColor(clReset)

# ============================================================
# Ctrl+C handler
# ============================================================

proc ctrlHandler(ctrlType: DWORD): WINBOOL {.stdcall.} =
  if ctrlType == CTRL_C_EVENT or ctrlType == CTRL_BREAK_EVENT:
    gRunning = false
    return WINBOOL(1)
  return WINBOOL(0)

# ============================================================
# Wide string helper
# ============================================================

proc wcharToStr(arr: openArray[WCHAR]): string =
  result = ""
  for c in arr:
    if c == 0: break
    if int(c) < 128:
      result.add(chr(int(c)))
    else:
      result.add('?')

# ============================================================
# Hook Profile Loader
#
# Parses EDR hook profile files from the profiles/ directory.
# Format: "NtXxx is hooked" per line (from Mr-Un1k0d3r/EDRs).
# Deduplicates Nt*/Zw* pairs (they share the same syscall).
#
# WEAKNESS: Only loads a static file at startup (Challenge 23)
# WEAKNESS: Profile may not match the actual running EDR
# ============================================================

proc loadHookProfile(name: string): HookProfile =
  result.name = name
  result.hookedApis = @[]

  if name == "" or name == "none":
    return

  let profileDir = getAppDir() / ".." / "profiles"
  let altDir = getAppDir() / "profiles"
  var path = ""

  if fileExists(profileDir / name & ".txt"):
    path = profileDir / name & ".txt"
  elif fileExists(altDir / name & ".txt"):
    path = altDir / name & ".txt"
  elif fileExists(name):
    path = name
  elif fileExists(name & ".txt"):
    path = name & ".txt"
  else:
    echo "[!] Hook profile not found: ", name
    echo "    Searched: ", profileDir, " and ", altDir
    echo "    Available: crowdstrike, carbonblack, cylance, bitdefender, cortex, checkpoint"
    quit(1)

  var seen = initHashSet[string]()
  for line in lines(path):
    let stripped = line.strip()
    if stripped.len == 0 or stripped.startsWith("#") or stripped.startsWith("-"):
      continue

    var apiName = stripped
    if " is hooked" in stripped:
      apiName = stripped.split(" is hooked")[0].strip()

    # Normalize: Zw* and Nt* are the same syscall
    let normalized = if apiName.startsWith("Zw"):
      "Nt" & apiName[2..^1]
    else:
      apiName

    if normalized notin seen and normalized.startsWith("Nt"):
      seen.incl(normalized)
      result.hookedApis.add(normalized)

proc listProfiles(): seq[string] =
  result = @[]
  let profileDir = getAppDir() / ".." / "profiles"
  if dirExists(profileDir):
    for f in walkFiles(profileDir / "*.txt"):
      result.add(f.extractFilename().changeFileExt(""))

# ============================================================
# PE Import Table Parser
#
# Reads the Import Address Table (IAT) of a process's main
# executable to determine which ntdll.dll functions it imports.
#
# WEAKNESS: Only reads static imports, not GetProcAddress (Challenge 21)
# WEAKNESS: Only reads the main .exe, not loaded DLLs (Challenge 22)
# WEAKNESS: No detection of direct/indirect syscalls (Challenge 23)
# WEAKNESS: Cannot see runtime-resolved imports (Challenge 24)
# ============================================================

proc getProcessImagePath(pid: DWORD): string =
  result = ""
  let hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, WINBOOL(0), pid)
  if hProc == 0: return
  defer: CloseHandle(hProc)

  var buf: array[MAX_PATH, WCHAR]
  var size = DWORD(MAX_PATH)
  if QueryFullProcessImageNameW(hProc, 0, addr buf[0], addr size) != 0:
    result = wcharToStr(buf)

proc readPeImports(imagePath: string): seq[string] =
  result = @[]
  if imagePath.len == 0 or not fileExists(imagePath):
    return

  var f: File
  if not open(f, imagePath, fmRead):
    return
  defer: close(f)

  # Read DOS header
  var dosHeader: array[64, byte]
  if readBytes(f, dosHeader, 0, 64) != 64:
    return

  # Check MZ signature
  if dosHeader[0] != 0x4D or dosHeader[1] != 0x5A:
    return

  # e_lfanew at offset 0x3C
  let eLfaNew = cast[ptr int32](addr dosHeader[0x3C])[]
  if eLfaNew <= 0 or eLfaNew > 1024 * 1024:
    return

  # Read PE signature + COFF header + optional header start
  setFilePos(f, eLfaNew)
  var peData: array[4 + 20 + 240, byte]
  let peRead = readBytes(f, peData, 0, peData.len)
  if peRead < 4 + 20 + 16:
    return

  # Check PE signature
  if peData[0] != ord('P') or peData[1] != ord('E') or
     peData[2] != 0 or peData[3] != 0:
    return

  # Optional header magic (offset 24 from PE sig)
  let magic = cast[ptr uint16](addr peData[24])[]
  let is64 = magic == 0x020B

  # Import directory RVA and size
  var importDirRva: uint32
  var importDirSize: uint32
  if is64:
    # PE32+: import table at optional header offset 120 (from start of optional header)
    # optional header starts at PE+24, import dir entry at +120
    if peRead < 24 + 120 + 8: return
    importDirRva = cast[ptr uint32](addr peData[24 + 120])[]
    importDirSize = cast[ptr uint32](addr peData[24 + 124])[]
  else:
    # PE32: import table at optional header offset 104
    if peRead < 24 + 104 + 8: return
    importDirRva = cast[ptr uint32](addr peData[24 + 104])[]
    importDirSize = cast[ptr uint32](addr peData[24 + 108])[]

  if importDirRva == 0 or importDirSize == 0:
    return

  # Read section headers to resolve RVA -> file offset
  let coffHeaderStart = eLfaNew + 4
  let sizeOfOptionalHeader = cast[ptr uint16](addr peData[20])[]
  let numberOfSections = cast[ptr uint16](addr peData[6])[]
  let sectionStart = coffHeaderStart + 20 + int(sizeOfOptionalHeader)

  type SectionInfo = object
    virtualAddress: uint32
    virtualSize: uint32
    rawOffset: uint32
    rawSize: uint32
    name: string

  var sections: seq[SectionInfo] = @[]
  setFilePos(f, sectionStart)
  for i in 0 ..< int(numberOfSections):
    var secData: array[40, byte]
    if readBytes(f, secData, 0, 40) != 40:
      break
    var secName = ""
    for j in 0..7:
      if secData[j] != 0:
        secName.add(chr(secData[j]))
    sections.add(SectionInfo(
      name: secName,
      virtualSize: cast[ptr uint32](addr secData[8])[],
      virtualAddress: cast[ptr uint32](addr secData[12])[],
      rawSize: cast[ptr uint32](addr secData[16])[],
      rawOffset: cast[ptr uint32](addr secData[20])[]
    ))

  proc rvaToOffset(rva: uint32): int =
    for sec in sections:
      if rva >= sec.virtualAddress and
         rva < sec.virtualAddress + sec.rawSize:
        return int(sec.rawOffset + (rva - sec.virtualAddress))
    return -1

  # Read import directory entries
  let importOffset = rvaToOffset(importDirRva)
  if importOffset < 0:
    return

  setFilePos(f, importOffset)
  # Each import descriptor is 20 bytes
  var descriptorIdx = 0
  while descriptorIdx < 256:
    var desc: array[20, byte]
    if readBytes(f, desc, 0, 20) != 20:
      break

    let nameRva = cast[ptr uint32](addr desc[12])[]
    let iltRva = cast[ptr uint32](addr desc[0])[]  # OriginalFirstThunk

    # All zeros = end of import directory
    if nameRva == 0 and iltRva == 0:
      break

    # Read DLL name
    let nameOff = rvaToOffset(nameRva)
    if nameOff < 0:
      inc descriptorIdx
      continue

    let savedPos = getFilePos(f)
    setFilePos(f, nameOff)
    var dllName = ""
    for i in 0..255:
      var ch: array[1, byte]
      if readBytes(f, ch, 0, 1) != 1: break
      if ch[0] == 0: break
      dllName.add(chr(ch[0]))

    # Only care about ntdll.dll imports
    if dllName.toLowerAscii() == "ntdll.dll" and iltRva != 0:
      let iltOff = rvaToOffset(iltRva)
      if iltOff >= 0:
        setFilePos(f, iltOff)
        var entryIdx = 0
        while entryIdx < 512:
          if is64:
            var thunk: uint64
            var thunkBytes: array[8, byte]
            if readBytes(f, thunkBytes, 0, 8) != 8: break
            thunk = cast[ptr uint64](addr thunkBytes[0])[]
            if thunk == 0: break
            # Check ordinal flag (bit 63)
            if (thunk and 0x8000000000000000'u64) == 0:
              let hintNameRva = uint32(thunk and 0xFFFFFFFF'u64)
              let hintOff = rvaToOffset(hintNameRva)
              if hintOff >= 0:
                let iltPos = getFilePos(f)
                setFilePos(f, hintOff + 2)  # skip 2-byte hint
                var funcName = ""
                for i in 0..127:
                  var ch: array[1, byte]
                  if readBytes(f, ch, 0, 1) != 1: break
                  if ch[0] == 0: break
                  funcName.add(chr(ch[0]))
                if funcName.len > 0:
                  result.add(funcName)
                setFilePos(f, iltPos)
          else:
            var thunkBytes: array[4, byte]
            if readBytes(f, thunkBytes, 0, 4) != 4: break
            let thunk = cast[ptr uint32](addr thunkBytes[0])[]
            if thunk == 0: break
            if (thunk and 0x80000000'u32) == 0:
              let hintOff = rvaToOffset(thunk)
              if hintOff >= 0:
                let iltPos = getFilePos(f)
                setFilePos(f, hintOff + 2)
                var funcName = ""
                for i in 0..127:
                  var ch: array[1, byte]
                  if readBytes(f, ch, 0, 1) != 1: break
                  if ch[0] == 0: break
                  funcName.add(chr(ch[0]))
                if funcName.len > 0:
                  result.add(funcName)
                setFilePos(f, iltPos)
          inc entryIdx

    setFilePos(f, savedPos + 20)
    inc descriptorIdx

# ============================================================
# ETW Telemetry Provider
#
# The agent registers a custom ETW provider and starts a
# real-time trace session for detection event telemetry.
# Real EDRs use ETW extensively for event collection.
#
# Provider: MostShittyEDR-Telemetry
# GUID: {4D6F7374-5368-6974-7479-454452000000}
# Session: "MostShittyEDR-Telemetry"
#
# WEAKNESS: User-mode only — patching ntdll!EtwEventWrite
#           disables all events (Challenge 26)
# WEAKNESS: Trace session name is hardcoded/discoverable,
#           can be stopped via logman (Challenge 25)
# WEAKNESS: No provider re-registration check (Challenge 27)
# WEAKNESS: No kernel-mode ETW-TI — hardware breakpoint
#           hooks are invisible (Challenge 28)
# ============================================================

const
  EtwSessionName = "MostShittyEDR-Telemetry"
  WNODE_FLAG_TRACED_GUID = 0x00020000'u32
  EVENT_TRACE_REAL_TIME_MODE = 0x00000100'u32
  EVENT_TRACE_CONTROL_QUERY = ULONG(0)
  EVENT_TRACE_CONTROL_STOP = ULONG(1)
  TRACE_LEVEL_INFORMATION = 4'u8
  EVENT_CONTROL_CODE_ENABLE_PROVIDER = ULONG(1)
  ETP_STRUCT_SIZE = 120

type
  REGHANDLE = uint64
  TRACEHANDLE = uint64

  EVENT_DESCRIPTOR = object
    Id: uint16
    Version: uint8
    Channel: uint8
    Level: uint8
    Opcode: uint8
    Task: uint16
    Keyword: uint64

  EVENT_DATA_DESCRIPTOR = object
    DataPtr: uint64
    Size: uint32
    Reserved: uint32

let gEtwProviderGuid = GUID(
  Data1: 0x4D6F7374,
  Data2: 0x5368,
  Data3: 0x6974,
  Data4: [0x74'u8, 0x79, 0x45, 0x44, 0x52, 0x00, 0x00, 0x00]
)

proc EventRegister(
  ProviderId: ptr GUID,
  EnableCallback: pointer,
  CallbackContext: pointer,
  RegHandle: ptr REGHANDLE
): ULONG {.stdcall, dynlib: "advapi32.dll", importc.}

proc EventWriteRaw(
  RegHandle: REGHANDLE,
  EventDescriptor: ptr EVENT_DESCRIPTOR,
  UserDataCount: ULONG,
  UserData: ptr EVENT_DATA_DESCRIPTOR
): ULONG {.stdcall, dynlib: "advapi32.dll", importc: "EventWrite".}

proc EventUnregister(
  RegHandle: REGHANDLE
): ULONG {.stdcall, dynlib: "advapi32.dll", importc.}

proc StartTraceW(
  SessionHandle: ptr TRACEHANDLE,
  SessionName: LPCWSTR,
  Properties: pointer
): ULONG {.stdcall, dynlib: "advapi32.dll", importc.}

proc ControlTraceW(
  SessionHandle: TRACEHANDLE,
  SessionName: LPCWSTR,
  Properties: pointer,
  ControlCode: ULONG
): ULONG {.stdcall, dynlib: "advapi32.dll", importc.}

proc EnableTraceEx2(
  TraceHandle: TRACEHANDLE,
  ProviderId: ptr GUID,
  ControlCode: ULONG,
  Level: uint8,
  MatchAnyKeyword: uint64,
  MatchAllKeyword: uint64,
  Timeout: ULONG,
  EnableParameters: pointer
): ULONG {.stdcall, dynlib: "advapi32.dll", importc.}

var
  gEtwRegHandle: REGHANDLE = 0
  gEtwSessionHandle: TRACEHANDLE = 0
  gEtwTamperAlerted: bool = false
  gEtwSessionActive: bool = false

proc toWideSessionName(): array[128, WCHAR] =
  for i, c in EtwSessionName:
    result[i] = WCHAR(c)
  result[EtwSessionName.len] = 0

proc initEtwProvider(): bool =
  var guid = gEtwProviderGuid
  let status = EventRegister(addr guid, nil, nil, addr gEtwRegHandle)
  return status == 0

proc startEtwSession(): bool =
  let nameLen = (EtwSessionName.len + 1) * 2
  let bufSize = ETP_STRUCT_SIZE + nameLen + 2
  var buf = newSeq[byte](bufSize)
  zeroMem(addr buf[0], bufSize)

  cast[ptr uint32](addr buf[0])[] = uint32(bufSize)
  cast[ptr uint32](addr buf[44])[] = WNODE_FLAG_TRACED_GUID
  cast[ptr uint32](addr buf[64])[] = EVENT_TRACE_REAL_TIME_MODE
  cast[ptr uint32](addr buf[112])[] = 0'u32
  cast[ptr uint32](addr buf[116])[] = uint32(ETP_STRUCT_SIZE)

  for i, c in EtwSessionName:
    buf[ETP_STRUCT_SIZE + i * 2] = byte(c)

  var wname = toWideSessionName()
  let status = StartTraceW(addr gEtwSessionHandle, addr wname[0], addr buf[0])

  if status == 0:
    var guid = gEtwProviderGuid
    discard EnableTraceEx2(gEtwSessionHandle, addr guid,
      EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION,
      0xFFFFFFFFFFFFFFFF'u64, 0'u64, ULONG(0), nil)
    gEtwSessionActive = true
    return true
  elif status == ULONG(0xB7):
    gEtwSessionActive = true
    return true
  else:
    return false

proc writeEtwDetection(det: Detection, info: ProcessInfo) =
  if gEtwRegHandle == 0: return

  var desc = EVENT_DESCRIPTOR(
    Id: uint16(det.ruleId),
    Version: 1,
    Channel: 0,
    Level: case det.severity
      of sCritical: 1'u8
      of sAlert: 2'u8
      of sWarning: 3'u8
      of sInfo: 4'u8,
    Opcode: 0,
    Task: 0,
    Keyword: 0xFFFFFFFFFFFFFFFF'u64
  )

  let msg = det.description & " | PID:" & $info.pid & " | " & info.exeName
  if msg.len == 0: return
  var dataDesc = EVENT_DATA_DESCRIPTOR(
    DataPtr: cast[uint64](unsafeAddr msg[0]),
    Size: uint32(msg.len + 1),
    Reserved: 0
  )

  discard EventWriteRaw(gEtwRegHandle, addr desc, 1, addr dataDesc)

proc queryEtwSession(): bool =
  var buf = newSeq[byte](ETP_STRUCT_SIZE + 512)
  zeroMem(addr buf[0], buf.len)
  cast[ptr uint32](addr buf[0])[] = uint32(buf.len)
  cast[ptr uint32](addr buf[116])[] = uint32(ETP_STRUCT_SIZE)

  var wname = toWideSessionName()
  let status = ControlTraceW(0, addr wname[0], addr buf[0], EVENT_TRACE_CONTROL_QUERY)
  return status == 0

proc shutdownEtw() =
  if gEtwSessionActive:
    var buf = newSeq[byte](ETP_STRUCT_SIZE + 512)
    zeroMem(addr buf[0], buf.len)
    cast[ptr uint32](addr buf[0])[] = uint32(buf.len)
    cast[ptr uint32](addr buf[116])[] = uint32(ETP_STRUCT_SIZE)

    var wname = toWideSessionName()
    discard ControlTraceW(0, addr wname[0], addr buf[0], EVENT_TRACE_CONTROL_STOP)

  if gEtwRegHandle != 0:
    discard EventUnregister(gEtwRegHandle)
    gEtwRegHandle = 0

# ============================================================
# Process enumeration via CreateToolhelp32Snapshot
# WEAKNESS: Polling-based, processes that start and exit
#           between polls are invisible (Challenge 10)
# ============================================================

proc enumerateProcesses(): seq[ProcessInfo] =
  result = @[]
  let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
  if snap == INVALID_HANDLE_VALUE: return
  defer: CloseHandle(snap)

  var pe: PROCESSENTRY32W
  pe.dwSize = DWORD(sizeof(PROCESSENTRY32W))

  if Process32FirstW(snap, addr pe) == 0: return

  while true:
    result.add ProcessInfo(
      pid: pe.th32ProcessID,
      parentPid: pe.th32ParentProcessID,
      exeName: wcharToStr(pe.szExeFile)
    )
    if Process32NextW(snap, addr pe) == 0: break

# ============================================================
# Command line reading via PEB
# WEAKNESS: Only works for 64-bit processes (Challenge 17)
# WEAKNESS: Fails for elevated/protected processes (Challenge 16)
# WEAKNESS: ASCII-only conversion, Unicode chars become '?' (Challenge 18)
# ============================================================

type
  PROCESS_BASIC_INFORMATION = object
    Reserved1: PVOID
    PebBaseAddress: PVOID
    Reserved2: array[2, PVOID]
    UniqueProcessId: ULONG_PTR
    Reserved3: PVOID

proc NtQueryInformationProcess(
  ProcessHandle: HANDLE,
  ProcessInformationClass: ULONG,
  ProcessInformation: PVOID,
  ProcessInformationLength: ULONG,
  ReturnLength: ptr ULONG
): LONG {.stdcall, dynlib: "ntdll.dll", importc.}

proc getCommandLine(pid: DWORD): string =
  result = ""
  if pid == 0 or pid == 4: return

  let hProc = OpenProcess(
    PROCESS_QUERY_INFORMATION or PROCESS_VM_READ,
    WINBOOL(0), pid)
  if hProc == 0: return
  defer: CloseHandle(hProc)

  var pbi: PROCESS_BASIC_INFORMATION
  var retLen: ULONG = 0

  if NtQueryInformationProcess(hProc, 0, addr pbi,
      ULONG(sizeof(pbi)), addr retLen) != 0:
    return

  if pbi.PebBaseAddress == nil: return

  var procParams: uint64
  var bytesRead: SIZE_T = 0
  let pebAddr = cast[uint64](pbi.PebBaseAddress)

  # ProcessParameters at PEB + 0x20 (64-bit)
  if ReadProcessMemory(hProc,
      cast[LPCVOID](pebAddr + 0x20'u64),
      addr procParams, SIZE_T(sizeof(procParams)),
      addr bytesRead) == 0:
    return

  # CommandLine UNICODE_STRING at ProcessParameters + 0x70
  var cmdLineLen: USHORT = 0
  if ReadProcessMemory(hProc,
      cast[LPCVOID](procParams + 0x70'u64),
      addr cmdLineLen, SIZE_T(sizeof(cmdLineLen)),
      addr bytesRead) == 0:
    return

  if cmdLineLen == 0: return

  # Buffer pointer at ProcessParameters + 0x78
  var cmdLineBuf: uint64 = 0
  if ReadProcessMemory(hProc,
      cast[LPCVOID](procParams + 0x78'u64),
      addr cmdLineBuf, SIZE_T(sizeof(cmdLineBuf)),
      addr bytesRead) == 0:
    return

  if cmdLineBuf == 0: return

  var buf = newSeq[byte](int(cmdLineLen) + 2)
  if ReadProcessMemory(hProc,
      cast[LPCVOID](cmdLineBuf),
      addr buf[0], SIZE_T(cmdLineLen),
      addr bytesRead) == 0:
    return

  # WEAKNESS: ASCII-only conversion, drops Unicode (Challenge 18)
  let wcharCount = int(cmdLineLen) div 2
  for i in 0 ..< wcharCount:
    let lo = buf[i * 2]
    let hi = buf[i * 2 + 1]
    if hi == 0 and lo < 128:
      result.add(chr(lo))
    else:
      result.add('?')

# ============================================================
# DETECTION RULE 1: Process Name Blacklist
#
# WEAKNESS: Case-SENSITIVE comparison (Challenge 1, 2)
# WEAKNESS: Exact name match only, renaming bypasses (Challenge 3)
# WEAKNESS: Hardcoded list, unlisted tools pass (Challenge 4)
# WEAKNESS: No path analysis, only filename (Challenge 5)
# ============================================================

const BlacklistedProcesses = [
  "mimikatz.exe",
  "procdump.exe",
  "procdump64.exe",
  "dumpert.exe",
  "nanodump.exe",
  "rubeus.exe",
  "seatbelt.exe",
  "sharphound.exe",
  "lazagne.exe",
  "safetykatz.exe",
  "bloodhound.exe",
  "notepad.exe"
]

proc ruleProcessBlacklist(info: ProcessInfo): seq[Detection] =
  result = @[]
  # BUG: case-sensitive! "Mimikatz.exe" != "mimikatz.exe"
  for name in BlacklistedProcesses:
    if info.exeName == name:
      result.add Detection(
        ruleName: "BLACKLISTED_PROCESS",
        ruleId: 1,
        severity: sCritical,
        description: "Blacklisted process detected: " & info.exeName
      )
      return

# ============================================================
# DETECTION RULE 2: Command Line Keyword Detection
#
# WEAKNESS: No deobfuscation - carets, env vars bypass (Challenge 6, 7)
# WEAKNESS: toLowerAscii only handles bytes 0x41-0x5A (Challenge 18)
# WEAKNESS: Simple substring match, no context (Challenge 8)
# ============================================================

const SuspiciousKeywords = [
  "mimikatz",
  "sekurlsa",
  "kerberos::list",
  "invoke-mimikatz",
  "invoke-expression",
  "downloadstring",
  "webclient",
  "-dumpcreds",
  "-dcsync",
  "dump lsass",
  "minidump lsass",
  "comsvcs.dll"
]

proc ruleSuspiciousKeywords(info: ProcessInfo): seq[Detection] =
  result = @[]
  let cmd = info.commandLine.toLowerAscii()
  for kw in SuspiciousKeywords:
    if kw in cmd:
      result.add Detection(
        ruleName: "SUSPICIOUS_CMDLINE",
        ruleId: 2,
        severity: sCritical,
        description: "Suspicious keyword in command line: " & kw
      )
      return

# ============================================================
# DETECTION RULE 3: Reconnaissance Command Detection
#
# WEAKNESS: Detects but result is DISCARDED - never blocks!
#           (Challenge 9)
# WEAKNESS: Only checks known commands (Challenge 12)
# ============================================================

const ReconCommands = [
  "whoami",
  "net user",
  "net group",
  "net localgroup",
  "net view",
  "net share",
  "nltest /dclist",
  "dsquery",
  "gpresult",
  "ipconfig /all",
  "systeminfo",
  "arp -a",
  "netstat -an"
]

proc ruleReconDetection(info: ProcessInfo): seq[Detection] =
  result = @[]
  let cmd = info.commandLine.toLowerAscii()
  for recon in ReconCommands:
    if recon in cmd:
      result.add Detection(
        ruleName: "RECON_ACTIVITY",
        ruleId: 3,
        severity: sWarning,
        description: "Reconnaissance command: " & recon
      )
      return

# ============================================================
# DETECTION RULE 4: LSASS Dump Tool Detection
#
# WEAKNESS: Requires BOTH tool name AND "lsass" keyword (Challenge 13)
# WEAKNESS: Tool name is case-insensitive but checked via
#           contains, not suffix (Challenge 14)
# ============================================================

const LsassDumpIndicators = [
  "procdump",
  "sqldumper",
  "dumpert",
  "nanodump",
  "comsvcs",
  "minidumpwritedump",
  "dbghelp",
  "dbgcore"
]

proc ruleLsassDump(info: ProcessInfo): seq[Detection] =
  result = @[]
  let nameLower = info.exeName.toLowerAscii()
  let cmdLower = info.commandLine.toLowerAscii()

  for tool in LsassDumpIndicators:
    if tool in nameLower or tool in cmdLower:
      # WEAKNESS: requires "lsass" keyword - omitting it bypasses
      if "lsass" in cmdLower or "-ma" in cmdLower:
        result.add Detection(
          ruleName: "LSASS_DUMP",
          ruleId: 4,
          severity: sCritical,
          description: "LSASS dump attempt via " & tool
        )
        return

# ============================================================
# DETECTION RULE 5: Suspicious PowerShell Execution
#
# WEAKNESS: Only checks "powershell.exe", not "pwsh.exe" or
#           other hosts (Challenge 15)
# WEAKNESS: Short flags like "-e" cause false positives but
#           "-EncodedCommand" with mixed case bypasses (Challenge 8)
# ============================================================

const SuspiciousPSFlags = [
  "-encodedcommand",
  "-enc ",
  "-windowstyle hidden",
  "bypass",
  "-noprofile",
  "iex(",
  "iex (",
  "invoke-expression"
]

proc rulePowerShell(info: ProcessInfo): seq[Detection] =
  result = @[]
  # WEAKNESS: only detects powershell.exe, not pwsh.exe
  if "powershell.exe" notin info.exeName.toLowerAscii():
    return

  let cmdLower = info.commandLine.toLowerAscii()
  for flag in SuspiciousPSFlags:
    if flag in cmdLower:
      result.add Detection(
        ruleName: "SUSPICIOUS_POWERSHELL",
        ruleId: 5,
        severity: sAlert,
        description: "Suspicious PowerShell flags: " & flag
      )
      return

# ============================================================
# DETECTION RULE 6: Hash-Based Detection (Security Theater)
#
# WEAKNESS: The hash database is EMPTY. This rule exists only
#           to look impressive in the feature list. It will
#           never detect anything. (Challenge 20)
# ============================================================

let KnownMalwareHashes: seq[string] = @[]

proc ruleHashCheck(info: ProcessInfo): seq[Detection] =
  result = @[]
  # "Checking" known malware hashes...
  for h in KnownMalwareHashes:
    discard h
  # Always returns empty - pure security theater

# ============================================================
# DETECTION RULE 7: Hooked API Import Detection
#
# Cross-references the PE import table of new processes against
# a loaded EDR hook profile to detect processes that statically
# import APIs that a real EDR would be monitoring.
#
# WEAKNESS: Only checks static imports in the IAT (Challenge 21)
#   -> Bypass: use GetProcAddress / LoadLibrary at runtime
# WEAKNESS: Only checks the main .exe, not loaded DLLs (Challenge 22)
#   -> Bypass: put the suspicious call in a loaded DLL
# WEAKNESS: No direct/indirect syscall detection (Challenge 23)
#   -> Bypass: use Hell's Gate / Heaven's Gate / Tartarus Gate
# WEAKNESS: No runtime hook verification (Challenge 24)
#   -> Bypass: unhook ntdll.dll at runtime, then call normally
# ============================================================

proc ruleHookedApiImports(info: ProcessInfo, profile: HookProfile): seq[Detection] =
  result = @[]
  if profile.hookedApis.len == 0:
    return

  let imports = readPeImports(info.imagePath)
  if imports.len == 0:
    return

  var matchedApis: seq[string] = @[]
  for imp in imports:
    let normalized = if imp.startsWith("Zw"):
      "Nt" & imp[2..^1]
    else:
      imp
    if normalized in profile.hookedApis:
      matchedApis.add(imp)

  if matchedApis.len > 0:
    let apiList = if matchedApis.len <= 5:
      matchedApis.join(", ")
    else:
      matchedApis[0..4].join(", ") & " (+" & $(matchedApis.len - 5) & " more)"

    let sev = if matchedApis.len >= 3: sAlert
              elif matchedApis.len >= 1: sWarning
              else: sInfo

    result.add Detection(
      ruleName: "HOOKED_API_IMPORT",
      ruleId: 7,
      severity: sev,
      description: "[" & profile.name & "] Process imports hooked APIs: " & apiList
    )

# ============================================================
# DETECTION RULE 8: ETW Integrity Check
#
# Checks if the ETW telemetry pipeline is intact by verifying:
# 1. ntdll!EtwEventWrite has not been patched
# 2. The trace session is still running
#
# WEAKNESS: Only checks first byte for 0xC3 (ret) — misses
#           xor eax,eax;ret (0x33,0xC0,0xC3) (Challenge 26)
# WEAKNESS: Session query runs periodically, stop-restart
#           between checks goes unnoticed (Challenge 25)
# WEAKNESS: Does not re-verify provider registration (Challenge 27)
# WEAKNESS: No hardware breakpoint detection — DR register
#           hooks are invisible (Challenge 28)
# ============================================================

proc ruleEtwIntegrity(): seq[Detection] =
  result = @[]
  if gEtwTamperAlerted: return

  let hNtdll = GetModuleHandleA("ntdll.dll")
  if hNtdll != 0:
    let pEtwWrite = GetProcAddress(hNtdll, "EtwEventWrite")
    if pEtwWrite != nil:
      let firstByte = cast[ptr byte](pEtwWrite)[]
      # WEAKNESS: Only checks for bare ret (0xC3)
      if firstByte == 0xC3:
        gEtwTamperAlerted = true
        result.add Detection(
          ruleName: "ETW_PATCHED",
          ruleId: 8,
          severity: sCritical,
          description: "ETW BLINDED! EtwEventWrite patched to ret (0xC3)"
        )
        return

  if gEtwSessionActive and not queryEtwSession():
    gEtwTamperAlerted = true
    result.add Detection(
      ruleName: "ETW_SESSION_KILLED",
      ruleId: 8,
      severity: sCritical,
      description: "ETW session '" & EtwSessionName & "' has been terminated!"
    )

# ============================================================
# Analysis Engine
# ============================================================

proc analyzeProcess(info: ProcessInfo, cfg: Config): seq[Detection] =
  var enriched = info
  enriched.commandLine = getCommandLine(info.pid)
  enriched.imagePath = getProcessImagePath(info.pid)

  result = @[]
  result.add ruleProcessBlacklist(enriched)
  result.add ruleSuspiciousKeywords(enriched)

  # WEAKNESS: recon detection runs but result is discarded!
  discard ruleReconDetection(enriched)

  result.add ruleLsassDump(enriched)
  result.add rulePowerShell(enriched)

  # WEAKNESS: hash check runs but database is empty
  discard ruleHashCheck(enriched)

  # Rule 7: Check PE imports against hook profile
  result.add ruleHookedApiImports(enriched, cfg.profile)

# ============================================================
# Response Engine
# ============================================================

proc killProcess(pid: DWORD): bool =
  let h = OpenProcess(PROCESS_TERMINATE, WINBOOL(0), pid)
  if h == 0: return false
  defer: CloseHandle(h)
  return TerminateProcess(h, 1) != 0

proc respond(info: ProcessInfo, detections: seq[Detection], cfg: Config) =
  for det in detections:
    inc gStats.detections

    let color = case det.severity
      of sCritical: clRed
      of sAlert:    clYellow
      of sWarning:  clCyan
      of sInfo:     clReset

    let icon = case det.severity
      of sCritical: "[CRITICAL]"
      of sAlert:    "[ALERT]   "
      of sWarning:  "[WARN]    "
      of sInfo:     "[INFO]    "

    setColor(color)
    echo "[", ts(), "] ", icon, " ", det.description
    echo "             PID: ", info.pid, " | Image: ", info.exeName

    if not cfg.noEtw:
      writeEtwDetection(det, info)

    if det.severity == sCritical and not cfg.noKill:
      setColor(clRed)
      echo "             [ACTION] Terminating PID ", info.pid
      if killProcess(info.pid):
        inc gStats.kills
        setColor(clGreen)
        echo "             [+] Process terminated successfully"
      else:
        setColor(clRed)
        echo "             [-] Termination failed (err=", GetLastError(), ")"

    setColor(clReset)

# ============================================================
# Banner
# ============================================================

proc displayBanner(cfg: Config) =
  setColor(clCyan)
  echo ""
  echo r"  __  __         _   ___ _    _ _   _          ___ ___  ___  "
  echo r" |  \/  |___ ___| |_/ __| |_ (_) |_| |_ _  _ | __|   \| _ \"
  echo r" | |\/| / _ (_-<  _\__ \ ' \| |  _|  _| || | | _|| |) |   /"
  echo r" |_|  |_\___/__/\__|___/_||_|_|\__|\__|\_, | |___|___/|_|_\"
  echo r"                                        |__/                "
  setColor(clYellow)
  echo ""
  echo "  The World's Most Intentionally Terrible EDR"
  echo "  \"If you can't bypass this, you definitely need more practice\""
  echo ""
  setColor(clGreen)
  echo "  Version: ", Version
  echo "  Mode:    User-mode process monitoring (no driver required)"
  echo ""
  setColor(clCyan)
  echo "  Detection Rules:"
  echo "    [1] Process Name Blacklist    (", BlacklistedProcesses.len, " entries)"
  echo "    [2] Command Line Keywords     (", SuspiciousKeywords.len, " patterns)"
  echo "    [3] Recon Command Detection   (", ReconCommands.len, " commands) [WARN ONLY]"
  echo "    [4] LSASS Dump Detection      (", LsassDumpIndicators.len, " indicators)"
  echo "    [5] PowerShell Flag Analysis  (", SuspiciousPSFlags.len, " flags)"
  echo "    [6] Hash-Based Detection      (", KnownMalwareHashes.len, " hashes) [EMPTY]"

  if cfg.profile.hookedApis.len > 0:
    setColor(clMagenta)
    echo "    [7] Hooked API Detection      (", cfg.profile.hookedApis.len, " APIs) [", cfg.profile.name.toUpperAscii(), "]"
  else:
    setColor(clWhite)
    echo "    [7] Hooked API Detection      (disabled - use --profile)"

  if not cfg.noEtw:
    setColor(clCyan)
    echo "    [8] ETW Integrity Check       (EtwEventWrite + session)"
    echo ""
    setColor(clGreen)
    echo "  ETW Provider: {4D6F7374-5368-6974-7479-454452000000}"
    echo "  ETW Session:  ", EtwSessionName
  else:
    setColor(clWhite)
    echo "    [8] ETW Integrity Check       (disabled - --no-etw)"

  echo ""
  setColor(clReset)

# ============================================================
# Help
# ============================================================

proc showHelp() =
  echo "MostShittyEDR v", Version, " - EDR Bypass Lab"
  echo ""
  echo "Usage: edr_agent.exe [OPTIONS]"
  echo ""
  echo "Options:"
  echo "  --verbose, -v        Show all new processes (not just detections)"
  echo "  --no-kill, -n        Detect but don't terminate processes"
  echo "  --interval MS        Set polling interval in ms (default: ", DefaultPollMs, ")"
  echo "  --profile NAME       Load EDR hook profile for API import detection"
  echo "                       Available: crowdstrike, carbonblack, cylance,"
  echo "                                  bitdefender, cortex, checkpoint"
  echo "  --list-profiles      Show available hook profiles"
  echo "  --no-etw             Disable ETW telemetry provider and Rule 8"
  echo "  --help, -h           Show this help"
  echo ""
  echo "Examples:"
  echo "  edr_agent.exe --verbose --no-kill"
  echo "  edr_agent.exe --profile crowdstrike"
  echo "  edr_agent.exe --profile carbonblack --verbose"
  echo ""
  echo "Challenges: See challenges/ directory or visit the GitHub Pages site"

# ============================================================
# Command line parsing
# ============================================================

proc parseConfig(): Config =
  result = Config(
    verbose: false,
    noKill: false,
    noEtw: false,
    pollInterval: DefaultPollMs,
    profile: HookProfile(name: "", hookedApis: @[])
  )

  var p = initOptParser()
  while true:
    p.next()
    case p.kind
    of cmdEnd: break
    of cmdShortOption, cmdLongOption:
      case p.key.toLowerAscii()
      of "verbose", "v": result.verbose = true
      of "no-kill", "n": result.noKill = true
      of "no-etw": result.noEtw = true
      of "interval", "i":
        result.pollInterval = parseInt(p.val)
        if result.pollInterval < 50:
          result.pollInterval = 50
      of "profile", "p":
        result.profile = loadHookProfile(p.val)
      of "list-profiles":
        echo "Available hook profiles:"
        for name in listProfiles():
          let prof = loadHookProfile(name)
          echo "  ", name, " (", prof.hookedApis.len, " hooked APIs)"
        quit(0)
      of "help", "h":
        showHelp()
        quit(0)
      else:
        echo "Unknown option: ", p.key
        quit(1)
    of cmdArgument:
      discard

# ============================================================
# Main
# ============================================================

proc main() =
  let cfg = parseConfig()

  displayBanner(cfg)

  SetConsoleCtrlHandler(ctrlHandler, WINBOOL(1))

  # Initialize ETW telemetry
  if not cfg.noEtw:
    if initEtwProvider():
      setColor(clGreen)
      echo "[", ts(), "] ETW provider registered"
    else:
      setColor(clYellow)
      echo "[", ts(), "] ETW provider registration failed"

    if startEtwSession():
      setColor(clGreen)
      echo "[", ts(), "] ETW session '", EtwSessionName, "' active"
    else:
      setColor(clYellow)
      echo "[", ts(), "] ETW session start failed (need admin?)"

  # Take initial process snapshot (don't analyze existing processes)
  # WEAKNESS: processes running before EDR starts are invisible (Challenge 11)
  let initial = enumerateProcesses()
  gKnownPids = initHashSet[DWORD]()
  for p in initial:
    gKnownPids.incl(p.pid)

  setColor(clCyan)
  echo "[", ts(), "] Initial snapshot: ", gKnownPids.len, " processes"
  echo "[", ts(), "] Poll interval: ", cfg.pollInterval, "ms"
  if cfg.noKill:
    setColor(clYellow)
    echo "[", ts(), "] Kill mode: DISABLED (detection only)"
  if cfg.verbose:
    echo "[", ts(), "] Verbose mode: ON"
  if cfg.profile.hookedApis.len > 0:
    setColor(clMagenta)
    echo "[", ts(), "] Hook profile: ", cfg.profile.name, " (", cfg.profile.hookedApis.len, " APIs)"
  setColor(clCyan)
  echo "[", ts(), "] Monitoring for new processes... (Ctrl+C to stop)"
  echo "============================================================"
  setColor(clReset)
  echo ""

  # Main monitoring loop
  var etwCheckCounter = 0
  while gRunning:
    # ETW integrity check every 10 cycles
    if not cfg.noEtw:
      inc etwCheckCounter
      if etwCheckCounter >= 10:
        etwCheckCounter = 0
        let etwDets = ruleEtwIntegrity()
        if etwDets.len > 0:
          let dummyInfo = ProcessInfo(pid: 0, exeName: "SYSTEM")
          respond(dummyInfo, etwDets, cfg)

    let current = enumerateProcesses()
    var newKnown = initHashSet[DWORD]()

    for p in current:
      newKnown.incl(p.pid)

      if p.pid notin gKnownPids:
        inc gStats.seen
        let detections = analyzeProcess(p, cfg)

        if detections.len > 0:
          respond(p, detections, cfg)
        elif cfg.verbose:
          setColor(clGreen)
          echo "[", ts(), "] [OK]       ", p.exeName, " (PID: ", p.pid, ")"
          setColor(clReset)

    gKnownPids = newKnown
    Sleep(DWORD(cfg.pollInterval))

  # Shutdown
  echo ""
  setColor(clYellow)
  echo "============================================================"
  echo "[", ts(), "] Shutting down..."

  if not cfg.noEtw:
    shutdownEtw()
    echo "[", ts(), "] ETW provider unregistered"

  setColor(clCyan)
  echo "[", ts(), "] Statistics:"
  echo "             Processes seen:  ", gStats.seen
  echo "             Detections:      ", gStats.detections
  echo "             Kills:           ", gStats.kills
  setColor(clGreen)
  echo "[", ts(), "] Shutdown complete"
  setColor(clReset)

when isMainModule and not defined(testing):
  main()
