///////////////////////////////////////////////////////////////////////////////
//
//  MostShittyEDR - Kernel Driver
//
//  A Windows kernel-mode driver that provides real-time process and thread
//  monitoring for the EDR bypass lab. Unlike the user-mode Nim agent (which
//  polls via CreateToolhelp32Snapshot), this driver receives synchronous
//  kernel callbacks -- no process can start or exit without being observed.
//
//  Architecture overview:
//
//    ┌──────────────────────────────────────────────────────────┐
//    │  Kernel (this driver)                                    │
//    │                                                          │
//    │  PsSetCreateProcessNotifyRoutineEx ──► ProcessCallback   │
//    │  PsSetCreateThreadNotifyRoutine    ──► ThreadCallback    │
//    │  ObRegisterCallbacks              ──► LsassHandleGuard  │
//    │         │                                                │
//    │         ▼                                                │
//    │  ┌─────────────┐    ┌──────────────┐                    │
//    │  │ Event Queue  │◄──│ Block Rules   │                    │
//    │  │ (LIST_ENTRY) │    │ (up to 64)   │                    │
//    │  └──────┬───────┘    └──────────────┘                    │
//    │         │  IOCTL_WAIT_FOR_EVENT                          │
//    │         ▼                                                │
//    │  ┌─────────────┐                                        │
//    │  │ Pending IRP  │ (single-slot, user-mode blocks here)  │
//    │  └──────┬───────┘                                        │
//    ├─────────┼────────────────────────────────────────────────┤
//    │         │  \\.\MostShittyEDR  (device symlink)                │
//    ├─────────┼────────────────────────────────────────────────┤
//    │         ▼                                                │
//    │  User-mode agent (edr_agent.exe / Agent.cpp)            │
//    │  Reads events, sends kill/block commands via IOCTLs     │
//    └──────────────────────────────────────────────────────────┘
//
//  IOCTLs:
//    0x222000  WAIT_FOR_EVENT    Agent blocks until next event arrives
//    0x222004  KILL_PROCESS      Agent requests kernel-level process kill
//    0x222008  ADD_BLOCK_RULE    Agent pushes a new block rule to kernel
//    0x22200C  CLEAR_BLOCK_RULES Agent resets all block rules
//    0x222010  SIGNAL_LSASS_DUMP Agent reports LSASS dump, kernel kills+logs
//
//  Build: requires Windows Driver Kit (WDK) and test-signing mode.
//
///////////////////////////////////////////////////////////////////////////////

#include <ntifs.h>
#include <ntddk.h>

///////////////////////////////////////////////////////////////////////////////
// Section 1: IOCTL codes
//
// CTL_CODE(DeviceType, Function, Method, Access)
// All use METHOD_BUFFERED: the I/O manager copies user buffers into
// Irp->AssociatedIrp.SystemBuffer, safe to access at any IRQL.
///////////////////////////////////////////////////////////////////////////////

#define IOCTL_WAIT_FOR_EVENT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_KILL_PROCESS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_ADD_BLOCK_RULE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_CLEAR_BLOCK_RULES \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_SIGNAL_LSASS_DUMP \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

///////////////////////////////////////////////////////////////////////////////
// Section 2: Event types and constants
///////////////////////////////////////////////////////////////////////////////

#define EVENT_TYPE_PROCESS_CREATE    1
#define EVENT_TYPE_PROCESS_EXIT      2
#define EVENT_TYPE_THREAD_CREATE     3
#define EVENT_TYPE_THREAD_EXIT       4
#define EVENT_TYPE_LSASS_ACCESS      5

#define BLOCK_RULE_MAX_ENTRIES       64

// These may not be defined in all WDK versions
#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE            (0x0001)
#endif
#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION    (0x0400)
#endif
#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ              (0x0010)
#endif
#ifndef STATUS_KILLED
#define STATUS_KILLED                ((NTSTATUS)0x00000128L)
#endif

///////////////////////////////////////////////////////////////////////////////
// Section 3: Shared data structures
//
// These structs define the ABI between kernel and user-mode. Both sides
// must agree on layout, so they use #pragma pack(push, 1) for wire-format
// compatibility regardless of compiler alignment settings.
//
// BYPASS LAB NOTE: The fixed-size WCHAR arrays (260/512) can be overflowed
// by a crafted image path or command line longer than the buffer. The
// SafeCopyUnicode helper truncates, but a real EDR would use dynamic
// allocation.
///////////////////////////////////////////////////////////////////////////////

#pragma pack(push, 1)

// Kernel -> User: describes a single telemetry event
typedef struct _EDR_EVENT {
    ULONG         EventType;          //  4 bytes: EVENT_TYPE_*
    LARGE_INTEGER Timestamp;          //  8 bytes: KeQuerySystemTime value
    ULONG64       ProcessId;          //  8 bytes
    ULONG64       ThreadId;           //  8 bytes (0 for process events)
    ULONG64       ParentProcessId;    //  8 bytes (only for PROCESS_CREATE)
    BOOLEAN       Blocked;            //  1 byte:  TRUE if kernel blocked it
    WCHAR         ImageFileName[260]; // 520 bytes: NT image path (truncated)
    WCHAR         CommandLine[512];   // 1024 bytes: process command line
} EDR_EVENT, *PEDR_EVENT;

// User -> Kernel: command payload for KILL / SIGNAL_LSASS_DUMP
typedef struct _EDR_COMMAND {
    ULONG   Action;     // 1 = execute the command
    ULONG64 ProcessId;  // target PID
} EDR_COMMAND, *PEDR_COMMAND;

// User -> Kernel: a single block rule (image suffix + cmdline substring)
typedef struct _BLOCK_RULE_ENTRY {
    WCHAR ImageSuffix[260];    // e.g. L"cmd.exe" -- matched as suffix
    WCHAR CmdLineSubstr[512]; // e.g. L"whoami"  -- matched as substring
} BLOCK_RULE_ENTRY, *PBLOCK_RULE_ENTRY;

#pragma pack(pop)

///////////////////////////////////////////////////////////////////////////////
// Section 4: Internal types and driver state
//
// The driver maintains:
//  - An event queue (doubly-linked list of EVENT_ENTRY nodes)
//  - A single pending IRP slot (the agent's blocking read)
//  - A block rule table (up to 64 suffix+substring rules)
//
// All shared state is protected by queued spinlocks. Queued spinlocks
// are preferred over regular spinlocks on multi-core systems because
// they reduce cache-line bouncing.
///////////////////////////////////////////////////////////////////////////////

typedef struct _EVENT_ENTRY {
    LIST_ENTRY ListEntry;  // linked-list node (must be first or use CONTAINING_RECORD)
    EDR_EVENT  Event;      // the event payload
} EVENT_ENTRY, *PEVENT_ENTRY;

typedef struct _DRIVER_STATE {
    LIST_ENTRY EventQueue; // head of the event FIFO
    KSPIN_LOCK QueueLock;  // protects EventQueue
    PIRP       PendingIrp; // the agent's blocking IOCTL_WAIT_FOR_EVENT IRP
    KSPIN_LOCK IrpLock;    // protects PendingIrp
} DRIVER_STATE, *PDRIVER_STATE;

typedef struct _BLOCK_RULE_TABLE {
    BLOCK_RULE_ENTRY Rules[BLOCK_RULE_MAX_ENTRIES];
    ULONG            Count;
    KSPIN_LOCK       Lock;
} BLOCK_RULE_TABLE;

static DRIVER_STATE     g_State;
static BLOCK_RULE_TABLE g_BlockRules  = { 0 };
PDEVICE_OBJECT          g_DeviceObject = NULL;
PVOID                   g_ObRegistrationHandle = NULL;

///////////////////////////////////////////////////////////////////////////////
// Section 5: Forward declarations
///////////////////////////////////////////////////////////////////////////////

DRIVER_UNLOAD DriverUnload;

_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CLOSE)
DRIVER_DISPATCH DispatchCreateClose;

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH DispatchIoControl;

OB_PREOP_CALLBACK_STATUS LsassHandleGuard(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation);

static VOID SafeCopyUnicode(
    _Out_writes_z_(dstMax) PWCHAR dst,
    _In_ SIZE_T dstMax,
    _In_ PCUNICODE_STRING src);

///////////////////////////////////////////////////////////////////////////////
// Section 6: Utility helpers
///////////////////////////////////////////////////////////////////////////////

// Safely copy a UNICODE_STRING into a fixed-size WCHAR buffer.
// Truncates if the source is longer than dstMax-1 characters.
static VOID SafeCopyUnicode(
    _Out_writes_z_(dstMax) PWCHAR dst,
    _In_ SIZE_T dstMax,
    _In_ PCUNICODE_STRING src)
{
    if (!src || !src->Buffer || src->Length == 0) {
        dst[0] = L'\0';
        return;
    }
    SIZE_T chars = min(src->Length / sizeof(WCHAR), dstMax - 1);
    RtlCopyMemory(dst, src->Buffer, chars * sizeof(WCHAR));
    dst[chars] = L'\0';
}

// Case-insensitive suffix match: does Str end with Suf?
// Uses RtlUpcaseUnicodeChar for locale-independent comparison.
static BOOLEAN WcsEndsWithInsensitive(
    _In_ PWCHAR Str, _In_ ULONG StrLen, _In_ PCWSTR Suf)
{
    SIZE_T sufLen = wcslen(Suf);
    if (!sufLen || StrLen < sufLen) return FALSE;

    SIZE_T offset = StrLen - sufLen;
    for (SIZE_T i = 0; i < sufLen; ++i) {
        if (RtlUpcaseUnicodeChar(Str[offset + i]) !=
            RtlUpcaseUnicodeChar(Suf[i]))
            return FALSE;
    }
    return TRUE;
}

// Case-insensitive substring search: does Str contain Sub?
// O(n*m) brute-force -- good enough for short rule strings.
static BOOLEAN WcsContainsInsensitive(
    _In_ PWCHAR Str, _In_ ULONG StrLen, _In_ PCWSTR Sub)
{
    SIZE_T subLen = wcslen(Sub);
    if (!subLen || StrLen < subLen) return FALSE;

    for (SIZE_T pos = 0; pos <= StrLen - subLen; ++pos) {
        BOOLEAN match = TRUE;
        for (SIZE_T i = 0; i < subLen; ++i) {
            if (RtlUpcaseUnicodeChar(Str[pos + i]) !=
                RtlUpcaseUnicodeChar(Sub[i])) {
                match = FALSE;
                break;
            }
        }
        if (match) return TRUE;
    }
    return FALSE;
}

// Check if a process matches a block rule.
// A rule matches when BOTH conditions are true (AND logic):
//  - ImageSuffix matches the end of the image path (or is empty = wildcard)
//  - CmdLineSubstr is found anywhere in the command line (or is empty = wildcard)
static BOOLEAN MatchBlockRule(
    _In_ PBLOCK_RULE_ENTRY Rule,
    _In_ PWCHAR ImageFileName, _In_ ULONG ImageLen,
    _In_ PWCHAR CmdLine,       _In_ ULONG CmdLineLen)
{
    BOOLEAN imgOk = (Rule->ImageSuffix[0] == L'\0') ||
        WcsEndsWithInsensitive(ImageFileName, ImageLen, Rule->ImageSuffix);

    BOOLEAN cmdOk = (Rule->CmdLineSubstr[0] == L'\0') ||
        WcsContainsInsensitive(CmdLine, CmdLineLen, Rule->CmdLineSubstr);

    return imgOk && cmdOk;
}

// Terminate a process by PID from kernel mode.
// Used by both IOCTL_KILL_PROCESS and IOCTL_SIGNAL_LSASS_DUMP to avoid
// code duplication. Returns the NTSTATUS from ZwTerminateProcess, or an
// error if the PID lookup or handle open failed.
static NTSTATUS TerminateProcessById(_In_ ULONG64 ProcessId)
{
    PEPROCESS process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[MostShittyEDR] PID %llu not found (0x%08X)\n", ProcessId, status);
        return status;
    }

    HANDLE hProcess = NULL;
    status = ObOpenObjectByPointer(
        process,
        OBJ_KERNEL_HANDLE,
        NULL,
        PROCESS_TERMINATE,
        *PsProcessType,
        KernelMode,
        &hProcess);

    if (NT_SUCCESS(status)) {
        status = ZwTerminateProcess(hProcess, STATUS_KILLED);
        ZwClose(hProcess);
        DbgPrint("[MostShittyEDR] Terminated PID %llu (0x%08X)\n", ProcessId, status);
    }

    ObDereferenceObject(process);
    return status;
}

///////////////////////////////////////////////////////////////////////////////
// Section 7: Event queue (producer-consumer pattern)
//
// Events flow from kernel callbacks (producers) to the user-mode agent
// (consumer) through a shared FIFO queue.
//
// Fast path: if the agent is already waiting (PendingIrp != NULL), the
//            event is copied directly into the IRP buffer and completed
//            immediately -- no allocation, no queue insertion.
//
// Slow path: if no agent is waiting, the event is heap-allocated and
//            appended to the queue. The agent will dequeue it on its
//            next IOCTL_WAIT_FOR_EVENT call.
//
// This design means at most ONE agent can be connected at a time
// (single pending IRP slot). A second concurrent WAIT_FOR_EVENT
// returns STATUS_DEVICE_BUSY.
///////////////////////////////////////////////////////////////////////////////

static VOID EnqueueEvent(_In_ PEDR_EVENT EventData)
{
    KLOCK_QUEUE_HANDLE irpHandle;
    PIRP pendingIrp = NULL;

    // Fast path: try to hand the event directly to a waiting agent
    KeAcquireInStackQueuedSpinLock(&g_State.IrpLock, &irpHandle);
    if (g_State.PendingIrp != NULL) {
        PIRP irp = g_State.PendingIrp;
        // Clear the cancel routine before completing -- required by the
        // IRP cancellation contract. If IoSetCancelRoutine returns NULL,
        // the cancel routine is already running; we must not touch the IRP.
        if (IoSetCancelRoutine(irp, NULL) != NULL) {
            pendingIrp = irp;
            g_State.PendingIrp = NULL;
        }
    }
    KeReleaseInStackQueuedSpinLock(&irpHandle);

    if (pendingIrp != NULL) {
        PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(pendingIrp);
        ULONG outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;

        if (outLen >= sizeof(EDR_EVENT)) {
            RtlCopyMemory(pendingIrp->AssociatedIrp.SystemBuffer,
                          EventData, sizeof(EDR_EVENT));
            pendingIrp->IoStatus.Information = sizeof(EDR_EVENT);
            pendingIrp->IoStatus.Status      = STATUS_SUCCESS;
        } else {
            pendingIrp->IoStatus.Information = 0;
            pendingIrp->IoStatus.Status      = STATUS_BUFFER_TOO_SMALL;
        }
        IoCompleteRequest(pendingIrp, IO_NO_INCREMENT);
        return;
    }

    // Slow path: allocate and queue the event for later retrieval
    PEVENT_ENTRY entry = (PEVENT_ENTRY)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(EVENT_ENTRY), 'rdsM');
    if (entry == NULL) {
        DbgPrint("[MostShittyEDR] EnqueueEvent: pool allocation failed, event dropped\n");
        return;
    }
    RtlCopyMemory(&entry->Event, EventData, sizeof(EDR_EVENT));

    KLOCK_QUEUE_HANDLE qHandle;
    KeAcquireInStackQueuedSpinLock(&g_State.QueueLock, &qHandle);
    InsertTailList(&g_State.EventQueue, &entry->ListEntry);
    KeReleaseInStackQueuedSpinLock(&qHandle);
}

///////////////////////////////////////////////////////////////////////////////
// Section 8: IRP cancel routine
//
// Called by the I/O manager when the agent's IOCTL_WAIT_FOR_EVENT IRP
// is cancelled (e.g. CancelIoEx from user-mode, or process exit).
// Runs at IRQL == DISPATCH_LEVEL with the system cancel spinlock held.
///////////////////////////////////////////////////////////////////////////////

static VOID CancelPendingIrp(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP           Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    // Remove this IRP from our pending slot (already at DISPATCH_LEVEL)
    KLOCK_QUEUE_HANDLE irpHandle;
    KeAcquireInStackQueuedSpinLockAtDpcLevel(&g_State.IrpLock, &irpHandle);
    if (g_State.PendingIrp == Irp)
        g_State.PendingIrp = NULL;
    KeReleaseInStackQueuedSpinLockFromDpcLevel(&irpHandle);

    // Release the system cancel spinlock before completing the IRP
    IoReleaseCancelSpinLock(Irp->CancelIrql);

    Irp->IoStatus.Status      = STATUS_CANCELLED;
    Irp->IoStatus.Information  = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

///////////////////////////////////////////////////////////////////////////////
// Section 9: Kernel callbacks
//
// These callbacks are invoked synchronously by the kernel -- the process
// or thread creation is blocked until the callback returns. This is the
// key advantage over user-mode polling: NO event can slip through.
//
// BYPASS LAB NOTES:
//  - ProcessCallback can DENY creation by setting CreationStatus. The
//    user-mode Nim agent cannot do this -- it can only kill after the fact.
//  - Block rules are evaluated here at process creation time, so even a
//    short-lived process is caught.
//  - ThreadCallback has no blocking capability in this implementation.
//  - LsassHandleGuard strips dangerous permissions from handles to
//    lsass.exe, making memory reads/dumps fail even if the process
//    is otherwise allowed to run.
///////////////////////////////////////////////////////////////////////////////

// Called for every process creation and exit on the system.
// Runs at PASSIVE_LEVEL in the context of the creating thread.
VOID ProcessCallback(
    PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);

    EDR_EVENT ev = {};
    KeQuerySystemTime(&ev.Timestamp);
    ev.ProcessId = (ULONG64)ProcessId;

    if (CreateInfo != NULL) {
        // --- Process creation ---
        ev.EventType       = EVENT_TYPE_PROCESS_CREATE;
        ev.ParentProcessId = (ULONG64)CreateInfo->ParentProcessId;

        if (CreateInfo->ImageFileName)
            SafeCopyUnicode(ev.ImageFileName, 260, CreateInfo->ImageFileName);
        if (CreateInfo->CommandLine)
            SafeCopyUnicode(ev.CommandLine, 512, CreateInfo->CommandLine);

        // Evaluate block rules against the new process.
        // If any rule matches, deny creation at the kernel level --
        // the process never actually starts.
        ULONG imgLen = (ULONG)wcslen(ev.ImageFileName);
        ULONG cmdLen = (ULONG)wcslen(ev.CommandLine);

        KLOCK_QUEUE_HANDLE ruleHandle;
        KeAcquireInStackQueuedSpinLock(&g_BlockRules.Lock, &ruleHandle);
        for (ULONG i = 0; i < g_BlockRules.Count; ++i) {
            if (MatchBlockRule(&g_BlockRules.Rules[i],
                               ev.ImageFileName, imgLen,
                               ev.CommandLine,   cmdLen)) {
                CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
                ev.Blocked = TRUE;
                DbgPrint("[MostShittyEDR-BLOCK] Blocked PID %llu via rule %lu\n",
                         ev.ProcessId, i);
                break;
            }
        }
        KeReleaseInStackQueuedSpinLock(&ruleHandle);
    } else {
        // --- Process exit ---
        ev.EventType = EVENT_TYPE_PROCESS_EXIT;
    }

    EnqueueEvent(&ev);
}

// Called for every thread creation and exit on the system.
// Runs at PASSIVE_LEVEL. Currently just logs the event -- no blocking.
VOID ThreadCallback(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create)
{
    EDR_EVENT ev = {};
    KeQuerySystemTime(&ev.Timestamp);
    ev.EventType = Create ? EVENT_TYPE_THREAD_CREATE : EVENT_TYPE_THREAD_EXIT;
    ev.ProcessId = (ULONG64)ProcessId;
    ev.ThreadId  = (ULONG64)ThreadId;
    EnqueueEvent(&ev);
}

// ObRegisterCallbacks pre-operation handler for process handles.
// Intercepts every handle open/duplicate targeting lsass.exe and strips
// PROCESS_VM_READ and PROCESS_QUERY_INFORMATION from the granted access
// mask. This prevents most user-mode memory dump techniques (procdump,
// MiniDumpWriteDump, etc.) from succeeding even if the process is allowed
// to run.
//
// BYPASS LAB NOTE: This only protects against handle-based access.
// Direct syscalls (NtReadVirtualMemory with a pre-existing handle) or
// kernel-mode reads bypass this entirely.
OB_PREOP_CALLBACK_STATUS LsassHandleGuard(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (OperationInformation->ObjectType != *PsProcessType)
        return OB_PREOP_SUCCESS;

    PEPROCESS TargetProcess = (PEPROCESS)OperationInformation->Object;
    if (!TargetProcess)
        return OB_PREOP_SUCCESS;

    PUNICODE_STRING ProcessImageName = NULL;
    NTSTATUS status = SeLocateProcessImageName(TargetProcess, &ProcessImageName);
    if (!NT_SUCCESS(status) || !ProcessImageName || !ProcessImageName->Buffer)
        return OB_PREOP_SUCCESS;

    if (wcsstr(ProcessImageName->Buffer, L"lsass.exe") != NULL) {
        ACCESS_MASK original = OperationInformation
            ->Parameters->CreateHandleInformation.OriginalDesiredAccess;
        ACCESS_MASK stripped = original & ~(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION);

        if (original != stripped) {
            OperationInformation
                ->Parameters->CreateHandleInformation.DesiredAccess = stripped;

            DbgPrint("[MostShittyEDR-LSASS] Handle access stripped: 0x%X -> 0x%X\n",
                     original, stripped);

            // Report the access attempt to user-mode
            EDR_EVENT ev = {};
            KeQuerySystemTime(&ev.Timestamp);
            ev.EventType = EVENT_TYPE_LSASS_ACCESS;
            ev.ProcessId = (ULONG64)PsGetCurrentProcessId();
            ev.Blocked   = TRUE;
            SafeCopyUnicode(ev.ImageFileName, 260, ProcessImageName);
            EnqueueEvent(&ev);
        }
    }

    ExFreePool(ProcessImageName);
    return OB_PREOP_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// Section 10: IOCTL handlers
//
// Each handler is called from DispatchIoControl and processes a single
// IOCTL type. They all follow the same pattern:
//   1. Validate input buffer size
//   2. Execute the operation
//   3. Set IRP status and complete the IRP
//   4. Return the NTSTATUS
///////////////////////////////////////////////////////////////////////////////

// IOCTL_KILL_PROCESS: User-mode agent requests a kernel-level process kill.
// This succeeds even against protected processes that can't be killed from
// user-mode (e.g. elevated processes when the agent runs as standard user).
static NTSTATUS HandleKillProcess(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION Stack)
{
    NTSTATUS status;
    ULONG inLen = Stack->Parameters.DeviceIoControl.InputBufferLength;

    if (inLen < sizeof(EDR_COMMAND)) {
        status = STATUS_BUFFER_TOO_SMALL;
    } else {
        PEDR_COMMAND cmd = (PEDR_COMMAND)Irp->AssociatedIrp.SystemBuffer;
        if (cmd->Action == 1) {
            status = TerminateProcessById(cmd->ProcessId);
        } else {
            status = STATUS_INVALID_PARAMETER;
        }
    }

    Irp->IoStatus.Status      = status;
    Irp->IoStatus.Information  = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// IOCTL_ADD_BLOCK_RULE: Adds a kernel-level block rule.
// Matched processes are denied creation by ProcessCallback (the process
// never starts). This is more powerful than user-mode killing because
// the target code never executes at all.
static NTSTATUS HandleAddBlockRule(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION Stack)
{
    NTSTATUS status;
    ULONG inLen = Stack->Parameters.DeviceIoControl.InputBufferLength;

    if (inLen < sizeof(BLOCK_RULE_ENTRY)) {
        status = STATUS_BUFFER_TOO_SMALL;
    } else {
        PBLOCK_RULE_ENTRY rule = (PBLOCK_RULE_ENTRY)Irp->AssociatedIrp.SystemBuffer;

        KLOCK_QUEUE_HANDLE ruleHandle;
        KeAcquireInStackQueuedSpinLock(&g_BlockRules.Lock, &ruleHandle);

        if (g_BlockRules.Count < BLOCK_RULE_MAX_ENTRIES) {
            RtlCopyMemory(&g_BlockRules.Rules[g_BlockRules.Count],
                           rule, sizeof(BLOCK_RULE_ENTRY));
            g_BlockRules.Count++;
            status = STATUS_SUCCESS;
            DbgPrint("[MostShittyEDR-BLOCK] Rule added (total: %lu)\n", g_BlockRules.Count);
        } else {
            status = STATUS_INSUFFICIENT_RESOURCES;
        }

        KeReleaseInStackQueuedSpinLock(&ruleHandle);
    }

    Irp->IoStatus.Status      = status;
    Irp->IoStatus.Information  = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// IOCTL_CLEAR_BLOCK_RULES: Removes all block rules. Used by the agent
// on startup before pushing its own rule set.
static NTSTATUS HandleClearBlockRules(_In_ PIRP Irp)
{
    KLOCK_QUEUE_HANDLE ruleHandle;
    KeAcquireInStackQueuedSpinLock(&g_BlockRules.Lock, &ruleHandle);
    RtlZeroMemory(g_BlockRules.Rules,
                   sizeof(BLOCK_RULE_ENTRY) * g_BlockRules.Count);
    g_BlockRules.Count = 0;
    KeReleaseInStackQueuedSpinLock(&ruleHandle);

    DbgPrint("[MostShittyEDR-BLOCK] All rules cleared\n");

    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information  = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// IOCTL_SIGNAL_LSASS_DUMP: User-mode agent detected an LSASS dump attempt
// and asks the kernel to kill the dumper process and log the event.
static NTSTATUS HandleSignalLsassDump(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION Stack)
{
    NTSTATUS status;
    ULONG inLen = Stack->Parameters.DeviceIoControl.InputBufferLength;

    if (inLen < sizeof(EDR_COMMAND)) {
        status = STATUS_BUFFER_TOO_SMALL;
    } else {
        PEDR_COMMAND cmd = (PEDR_COMMAND)Irp->AssociatedIrp.SystemBuffer;

        DbgPrint("[MostShittyEDR-LSASS] User-mode signal: LSASS dump by PID %llu\n",
                 cmd->ProcessId);

        if (cmd->Action == 1)
            TerminateProcessById(cmd->ProcessId);

        // Always enqueue a telemetry event regardless of kill success
        EDR_EVENT ev = {};
        KeQuerySystemTime(&ev.Timestamp);
        ev.EventType = EVENT_TYPE_LSASS_ACCESS;
        ev.ProcessId = cmd->ProcessId;
        ev.Blocked   = TRUE;
        wcscpy_s(ev.ImageFileName, 260, L"LSASS_DUMP_BLOCKED");
        EnqueueEvent(&ev);

        status = STATUS_SUCCESS;
    }

    Irp->IoStatus.Status      = status;
    Irp->IoStatus.Information  = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// IOCTL_WAIT_FOR_EVENT: The agent blocks here until an event is available.
//
// Three possible outcomes:
//   1. Queue has events  -> dequeue the oldest, return immediately
//   2. Queue is empty    -> pend the IRP, return STATUS_PENDING
//   3. Already pending   -> reject with STATUS_DEVICE_BUSY
//
// The pending IRP is completed asynchronously by EnqueueEvent (when a
// new event arrives) or by CancelPendingIrp (when the agent disconnects).
//
// IRQL note: IoMarkIrpPending must be called before the IRP might be
// completed by another thread. The cancel race (IRP cancelled between
// IoMarkIrpPending and IoSetCancelRoutine) is handled by checking
// Irp->Cancel after setting the cancel routine.
static NTSTATUS HandleWaitForEvent(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION Stack)
{
    ULONG outLen = Stack->Parameters.DeviceIoControl.OutputBufferLength;
    if (outLen < sizeof(EDR_EVENT)) {
        Irp->IoStatus.Status      = STATUS_BUFFER_TOO_SMALL;
        Irp->IoStatus.Information  = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_BUFFER_TOO_SMALL;
    }

    // Try to dequeue an event immediately
    KLOCK_QUEUE_HANDLE qHandle;
    KeAcquireInStackQueuedSpinLock(&g_State.QueueLock, &qHandle);

    if (!IsListEmpty(&g_State.EventQueue)) {
        PLIST_ENTRY  link  = RemoveHeadList(&g_State.EventQueue);
        PEVENT_ENTRY entry = CONTAINING_RECORD(link, EVENT_ENTRY, ListEntry);
        KeReleaseInStackQueuedSpinLock(&qHandle);

        RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer,
                       &entry->Event, sizeof(EDR_EVENT));
        ExFreePool(entry);

        Irp->IoStatus.Status      = STATUS_SUCCESS;
        Irp->IoStatus.Information  = sizeof(EDR_EVENT);
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }
    KeReleaseInStackQueuedSpinLock(&qHandle);

    // No events queued -- pend the IRP (only one allowed at a time)
    KLOCK_QUEUE_HANDLE irpHandle;
    KeAcquireInStackQueuedSpinLock(&g_State.IrpLock, &irpHandle);

    if (g_State.PendingIrp != NULL) {
        KeReleaseInStackQueuedSpinLock(&irpHandle);
        Irp->IoStatus.Status      = STATUS_DEVICE_BUSY;
        Irp->IoStatus.Information  = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_DEVICE_BUSY;
    }

    IoMarkIrpPending(Irp);
    IoSetCancelRoutine(Irp, CancelPendingIrp);

    // Handle the cancel race: if the IRP was already cancelled before
    // we set the cancel routine, we must complete it ourselves.
    if (Irp->Cancel) {
        if (IoSetCancelRoutine(Irp, NULL) != NULL) {
            KeReleaseInStackQueuedSpinLock(&irpHandle);
            Irp->IoStatus.Status      = STATUS_CANCELLED;
            Irp->IoStatus.Information  = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_CANCELLED;
        }
        // Cancel routine is already running -- it will complete the IRP
    }

    g_State.PendingIrp = Irp;
    KeReleaseInStackQueuedSpinLock(&irpHandle);
    return STATUS_PENDING;
}

///////////////////////////////////////////////////////////////////////////////
// Section 11: IRP dispatch
///////////////////////////////////////////////////////////////////////////////

// Handles IRP_MJ_CREATE and IRP_MJ_CLOSE -- device open/close from
// user-mode (CreateFile / CloseHandle). No access control: anyone can
// open the device. A real EDR would restrict this to the agent process.
_Use_decl_annotations_
NTSTATUS DispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information  = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// Routes IRP_MJ_DEVICE_CONTROL to the appropriate handler based on
// the IOCTL code.
_Use_decl_annotations_
NTSTATUS DispatchIoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG ioctl = stack->Parameters.DeviceIoControl.IoControlCode;

    switch (ioctl) {
    case IOCTL_KILL_PROCESS:
        return HandleKillProcess(Irp, stack);

    case IOCTL_ADD_BLOCK_RULE:
        return HandleAddBlockRule(Irp, stack);

    case IOCTL_CLEAR_BLOCK_RULES:
        return HandleClearBlockRules(Irp);

    case IOCTL_SIGNAL_LSASS_DUMP:
        return HandleSignalLsassDump(Irp, stack);

    case IOCTL_WAIT_FOR_EVENT:
        return HandleWaitForEvent(Irp, stack);

    default:
        Irp->IoStatus.Status      = STATUS_INVALID_DEVICE_REQUEST;
        Irp->IoStatus.Information  = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_DEVICE_REQUEST;
    }
}

///////////////////////////////////////////////////////////////////////////////
// Section 12: Driver lifecycle (DriverEntry + DriverUnload)
//
// DriverEntry registers all callbacks and creates the device. On failure,
// it unwinds in reverse order -- each registration step checks the
// previous one succeeded.
//
// DriverUnload tears down everything in reverse: callbacks first, then
// drain the queue, cancel pending IRP, and finally delete the device.
///////////////////////////////////////////////////////////////////////////////

VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    // 1. Unregister callbacks (stops new events from being produced)
    if (g_ObRegistrationHandle) {
        ObUnRegisterCallbacks(g_ObRegistrationHandle);
        g_ObRegistrationHandle = NULL;
    }

    NTSTATUS status = PsRemoveCreateThreadNotifyRoutine(ThreadCallback);
    if (!NT_SUCCESS(status))
        DbgPrint("[MostShittyEDR] Thread callback removal failed: 0x%08X\n", status);

    status = PsSetCreateProcessNotifyRoutineEx(ProcessCallback, TRUE);
    if (!NT_SUCCESS(status))
        DbgPrint("[MostShittyEDR] Process callback removal failed: 0x%08X\n", status);

    // 2. Drain the event queue (free all pooled event entries)
    KLOCK_QUEUE_HANDLE qHandle;
    KeAcquireInStackQueuedSpinLock(&g_State.QueueLock, &qHandle);
    while (!IsListEmpty(&g_State.EventQueue)) {
        PLIST_ENTRY  link  = RemoveHeadList(&g_State.EventQueue);
        PEVENT_ENTRY entry = CONTAINING_RECORD(link, EVENT_ENTRY, ListEntry);
        ExFreePool(entry);
    }
    KeReleaseInStackQueuedSpinLock(&qHandle);

    // 3. Cancel the pending IRP (if the agent is still blocking)
    KLOCK_QUEUE_HANDLE irpHandle;
    KeAcquireInStackQueuedSpinLock(&g_State.IrpLock, &irpHandle);
    PIRP irp = g_State.PendingIrp;
    g_State.PendingIrp = NULL;
    KeReleaseInStackQueuedSpinLock(&irpHandle);

    if (irp != NULL) {
        if (IoSetCancelRoutine(irp, NULL) != NULL) {
            irp->IoStatus.Status      = STATUS_CANCELLED;
            irp->IoStatus.Information  = 0;
            IoCompleteRequest(irp, IO_NO_INCREMENT);
        }
    }

    // 4. Delete device and symlink
    UNICODE_STRING symlink = RTL_CONSTANT_STRING(L"\\??\\MostShittyEDR");
    IoDeleteSymbolicLink(&symlink);
    if (g_DeviceObject)
        IoDeleteDevice(g_DeviceObject);

    DbgPrint("[MostShittyEDR] Driver unloaded\n");
}

extern "C"
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = DriverUnload;

    // --- Step 1: Create the device object and symbolic link ---
    // The symlink \\.\MostShittyEDR is what user-mode opens via CreateFile.
    UNICODE_STRING devname = RTL_CONSTANT_STRING(L"\\Device\\MostShittyEDR");
    UNICODE_STRING symlink = RTL_CONSTANT_STRING(L"\\??\\MostShittyEDR");

    NTSTATUS status = IoCreateDevice(
        DriverObject, 0, &devname,
        FILE_DEVICE_UNKNOWN, 0, FALSE, &g_DeviceObject);
    if (!NT_SUCCESS(status))
        return status;

    g_DeviceObject->Flags |= DO_BUFFERED_IO;

    status = IoCreateSymbolicLink(&symlink, &devname);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    // --- Step 2: Initialize internal state ---
    InitializeListHead(&g_State.EventQueue);
    KeInitializeSpinLock(&g_State.QueueLock);
    KeInitializeSpinLock(&g_State.IrpLock);
    KeInitializeSpinLock(&g_BlockRules.Lock);
    g_State.PendingIrp = NULL;

    // --- Step 3: Register IRP dispatch routines ---
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoControl;
    DriverObject->MajorFunction[IRP_MJ_CREATE]          = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]           = DispatchCreateClose;

    // --- Step 4: Register LSASS handle protection (ObRegisterCallbacks) ---
    // Altitude 370000 places us in the FSFilter activity monitor range.
    // A signed driver with an altitude allocation from Microsoft is required
    // in production; for the lab, test-signing mode is sufficient.
    OB_OPERATION_REGISTRATION opReg = { 0 };
    opReg.ObjectType    = PsProcessType;
    opReg.Operations    = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opReg.PreOperation  = LsassHandleGuard;
    opReg.PostOperation = NULL;

    DECLARE_CONST_UNICODE_STRING(Altitude, L"370000");

    OB_CALLBACK_REGISTRATION cbReg = { 0 };
    cbReg.Version                    = OB_FLT_REGISTRATION_VERSION;
    cbReg.OperationRegistrationCount = 1;
    cbReg.RegistrationContext        = NULL;
    cbReg.OperationRegistration      = &opReg;
    cbReg.Altitude                   = Altitude;

    status = ObRegisterCallbacks(&cbReg, &g_ObRegistrationHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[MostShittyEDR] ObRegisterCallbacks failed: 0x%08X\n", status);
        g_ObRegistrationHandle = NULL;
    } else {
        DbgPrint("[MostShittyEDR] LSASS handle protection active\n");
    }

    // --- Step 5: Register process creation/exit callback ---
    // PsSetCreateProcessNotifyRoutineEx (the "Ex" variant) receives
    // PPS_CREATE_NOTIFY_INFO with image name, command line, and the
    // ability to deny creation by setting CreationStatus.
    status = PsSetCreateProcessNotifyRoutineEx(ProcessCallback, FALSE);
    if (!NT_SUCCESS(status)) {
        if (g_ObRegistrationHandle) ObUnRegisterCallbacks(g_ObRegistrationHandle);
        IoDeleteSymbolicLink(&symlink);
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    // --- Step 6: Register thread creation/exit callback ---
    status = PsSetCreateThreadNotifyRoutine(ThreadCallback);
    if (!NT_SUCCESS(status)) {
        PsSetCreateProcessNotifyRoutineEx(ProcessCallback, TRUE);
        if (g_ObRegistrationHandle) ObUnRegisterCallbacks(g_ObRegistrationHandle);
        IoDeleteSymbolicLink(&symlink);
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    DbgPrint("[MostShittyEDR] Driver loaded: process + thread monitoring + LSASS protection\n");
    return STATUS_SUCCESS;
}
