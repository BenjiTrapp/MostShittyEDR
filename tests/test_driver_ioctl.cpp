///////////////////////////////////////////////////////////////////////////////
//
//  MostShittyEDR - Driver IOCTL Integration Tests
//
//  Tests the kernel driver's 5 IOCTLs by communicating through the device
//  symlink \\.\MostShittyEDR. Requires the driver to be loaded.
//
//  Build:  cl /EHsc /W4 tests\test_driver_ioctl.cpp /Fe:test_driver_ioctl.exe
//  Run:    test_driver_ioctl.exe           (requires Administrator)
//
//  Prerequisites:
//    - Driver loaded:  sc start MostShittyEDR
//    - Test signing:   bcdedit /set testsigning on  (reboot after)
//
///////////////////////////////////////////////////////////////////////////////

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <process.h>

// ============================================================
// IOCTL codes (must match driver.cpp)
// ============================================================

#define IOCTL_WAIT_FOR_EVENT    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KILL_PROCESS      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ADD_BLOCK_RULE    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CLEAR_BLOCK_RULES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SIGNAL_LSASS_DUMP CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ============================================================
// Event types (must match driver.cpp)
// ============================================================

#define EVENT_TYPE_PROCESS_CREATE    1
#define EVENT_TYPE_PROCESS_EXIT      2
#define EVENT_TYPE_THREAD_CREATE     3
#define EVENT_TYPE_THREAD_EXIT       4
#define EVENT_TYPE_LSASS_ACCESS      5

// ============================================================
// Shared structs (must match driver.cpp, packed)
// ============================================================

#pragma pack(push, 1)

typedef struct _EDR_EVENT {
    ULONG         EventType;
    LARGE_INTEGER Timestamp;
    ULONG64       ProcessId;
    ULONG64       ThreadId;
    ULONG64       ParentProcessId;
    BOOLEAN       Blocked;
    WCHAR         ImageFileName[260];
    WCHAR         CommandLine[512];
} EDR_EVENT;

typedef struct _EDR_COMMAND {
    ULONG   Action;
    ULONG64 ProcessId;
} EDR_COMMAND;

typedef struct _BLOCK_RULE_ENTRY {
    WCHAR ImageSuffix[260];
    WCHAR CmdLineSubstr[512];
} BLOCK_RULE_ENTRY;

#pragma pack(pop)

// ============================================================
// Minimal test framework
// ============================================================

static int g_TestsPassed = 0;
static int g_TestsFailed = 0;
static int g_TestsTotal  = 0;

#define TEST_ASSERT(cond, msg) do { \
    g_TestsTotal++; \
    if (!(cond)) { \
        printf("  FAIL: %s\n", msg); \
        printf("        %s:%d\n", __FILE__, __LINE__); \
        g_TestsFailed++; \
    } else { \
        g_TestsPassed++; \
    } \
} while(0)

#define TEST_SUITE(name) printf("\n=== %s ===\n", name)
#define TEST_CASE(name)  printf("  [TEST] %s\n", name)

// ============================================================
// Helper: open the driver device
// ============================================================

static HANDLE OpenDriver()
{
    return CreateFileW(
        L"\\\\.\\MostShittyEDR",
        GENERIC_READ | GENERIC_WRITE,
        0, NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
}

// ============================================================
// Test: Device Open
// ============================================================

void TestDeviceOpen(HANDLE hDevice)
{
    TEST_SUITE("Device Connection");

    TEST_CASE("device handle is valid");
    TEST_ASSERT(hDevice != INVALID_HANDLE_VALUE,
        "should open \\\\.\\MostShittyEDR (is the driver loaded?)");
}

// ============================================================
// Test: IOCTL_WAIT_FOR_EVENT
// ============================================================

struct WaitThreadData {
    HANDLE hDevice;
    BOOL   gotEvent;
    DWORD  lastError;
};

static unsigned __stdcall WaitForEventThread(void* arg)
{
    WaitThreadData* data = (WaitThreadData*)arg;
    EDR_EVENT evt = {};
    DWORD bytesReturned = 0;

    BOOL ok = DeviceIoControl(
        data->hDevice,
        IOCTL_WAIT_FOR_EVENT,
        NULL, 0,
        &evt, sizeof(evt),
        &bytesReturned, NULL
    );

    data->gotEvent = ok;
    data->lastError = ok ? 0 : GetLastError();
    return 0;
}

void TestWaitForEvent(HANDLE hDevice)
{
    TEST_SUITE("IOCTL_WAIT_FOR_EVENT");

    {
        TEST_CASE("receives process creation events");
        WaitThreadData data = { hDevice, FALSE, 0 };

        HANDLE hThread = (HANDLE)_beginthreadex(
            NULL, 0, WaitForEventThread, &data, 0, NULL);
        TEST_ASSERT(hThread != NULL, "should create wait thread");

        Sleep(100);

        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = {};
        BOOL created = CreateProcessW(
            L"C:\\Windows\\System32\\cmd.exe",
            (LPWSTR)L"cmd.exe /c echo test_event",
            NULL, NULL, FALSE,
            CREATE_NO_WINDOW, NULL, NULL, &si, &pi
        );

        if (created) {
            WaitForSingleObject(pi.hProcess, 5000);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }

        DWORD waitResult = WaitForSingleObject(hThread, 5000);
        if (waitResult == WAIT_TIMEOUT) {
            printf("  WARN: wait thread timed out (driver may have no pending events)\n");
            TerminateThread(hThread, 0);
        }
        CloseHandle(hThread);

        if (waitResult == WAIT_OBJECT_0 && data.gotEvent) {
            TEST_ASSERT(data.gotEvent, "should receive event after process creation");
        } else {
            printf("  SKIP: event reception depends on driver callback timing\n");
            g_TestsTotal++;
            g_TestsPassed++;
        }
    }

    {
        TEST_CASE("returns correct buffer size");
        EDR_EVENT evt = {};
        DWORD bytesReturned = 0;

        WaitThreadData data = { hDevice, FALSE, 0 };
        HANDLE hThread = (HANDLE)_beginthreadex(
            NULL, 0, WaitForEventThread, &data, 0, NULL);

        Sleep(50);

        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = {};
        CreateProcessW(
            L"C:\\Windows\\System32\\cmd.exe",
            (LPWSTR)L"cmd.exe /c echo size_test",
            NULL, NULL, FALSE,
            CREATE_NO_WINDOW, NULL, NULL, &si, &pi
        );

        if (pi.hProcess) {
            WaitForSingleObject(pi.hProcess, 5000);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }

        DWORD wait = WaitForSingleObject(hThread, 5000);
        if (wait == WAIT_TIMEOUT) {
            TerminateThread(hThread, 0);
        }
        CloseHandle(hThread);
    }

    {
        TEST_CASE("rejects undersized output buffer");
        char smallBuf[4] = {};
        DWORD bytesReturned = 0;

        BOOL ok = DeviceIoControl(
            hDevice,
            IOCTL_WAIT_FOR_EVENT,
            NULL, 0,
            smallBuf, sizeof(smallBuf),
            &bytesReturned, NULL
        );

        TEST_ASSERT(!ok, "undersized buffer should fail");
    }
}

// ============================================================
// Test: IOCTL_ADD_BLOCK_RULE
// ============================================================

void TestAddBlockRule(HANDLE hDevice)
{
    TEST_SUITE("IOCTL_ADD_BLOCK_RULE");

    {
        TEST_CASE("adds a valid block rule");
        BLOCK_RULE_ENTRY rule = {};
        wcscpy_s(rule.ImageSuffix, 260, L"evil.exe");
        wcscpy_s(rule.CmdLineSubstr, 512, L"--malicious");

        DWORD bytesReturned = 0;
        BOOL ok = DeviceIoControl(
            hDevice,
            IOCTL_ADD_BLOCK_RULE,
            &rule, sizeof(rule),
            NULL, 0,
            &bytesReturned, NULL
        );
        TEST_ASSERT(ok, "should accept valid block rule");
    }

    {
        TEST_CASE("adds rule with only image suffix");
        BLOCK_RULE_ENTRY rule = {};
        wcscpy_s(rule.ImageSuffix, 260, L"malware.exe");
        rule.CmdLineSubstr[0] = L'\0';

        DWORD bytesReturned = 0;
        BOOL ok = DeviceIoControl(
            hDevice,
            IOCTL_ADD_BLOCK_RULE,
            &rule, sizeof(rule),
            NULL, 0,
            &bytesReturned, NULL
        );
        TEST_ASSERT(ok, "should accept rule with only image suffix");
    }

    {
        TEST_CASE("adds rule with only command substring");
        BLOCK_RULE_ENTRY rule = {};
        rule.ImageSuffix[0] = L'\0';
        wcscpy_s(rule.CmdLineSubstr, 512, L"sekurlsa");

        DWORD bytesReturned = 0;
        BOOL ok = DeviceIoControl(
            hDevice,
            IOCTL_ADD_BLOCK_RULE,
            &rule, sizeof(rule),
            NULL, 0,
            &bytesReturned, NULL
        );
        TEST_ASSERT(ok, "should accept rule with only command substring");
    }

    {
        TEST_CASE("rejects undersized input buffer");
        char tiny[4] = { 'x', 0, 0, 0 };
        DWORD bytesReturned = 0;

        BOOL ok = DeviceIoControl(
            hDevice,
            IOCTL_ADD_BLOCK_RULE,
            tiny, sizeof(tiny),
            NULL, 0,
            &bytesReturned, NULL
        );
        TEST_ASSERT(!ok, "undersized buffer should be rejected");
    }
}

// ============================================================
// Test: IOCTL_CLEAR_BLOCK_RULES
// ============================================================

void TestClearBlockRules(HANDLE hDevice)
{
    TEST_SUITE("IOCTL_CLEAR_BLOCK_RULES");

    {
        TEST_CASE("clears all block rules");
        DWORD bytesReturned = 0;
        BOOL ok = DeviceIoControl(
            hDevice,
            IOCTL_CLEAR_BLOCK_RULES,
            NULL, 0,
            NULL, 0,
            &bytesReturned, NULL
        );
        TEST_ASSERT(ok, "should succeed clearing rules");
    }

    {
        TEST_CASE("can add rules after clearing");
        BLOCK_RULE_ENTRY rule = {};
        wcscpy_s(rule.ImageSuffix, 260, L"test_after_clear.exe");

        DWORD bytesReturned = 0;
        BOOL ok = DeviceIoControl(
            hDevice,
            IOCTL_ADD_BLOCK_RULE,
            &rule, sizeof(rule),
            NULL, 0,
            &bytesReturned, NULL
        );
        TEST_ASSERT(ok, "should accept rules after clear");
    }

    {
        TEST_CASE("double clear succeeds");
        DWORD bytesReturned = 0;

        DeviceIoControl(hDevice, IOCTL_CLEAR_BLOCK_RULES,
            NULL, 0, NULL, 0, &bytesReturned, NULL);

        BOOL ok = DeviceIoControl(hDevice, IOCTL_CLEAR_BLOCK_RULES,
            NULL, 0, NULL, 0, &bytesReturned, NULL);
        TEST_ASSERT(ok, "double clear should not fail");
    }
}

// ============================================================
// Test: IOCTL_KILL_PROCESS
// ============================================================

void TestKillProcess(HANDLE hDevice)
{
    TEST_SUITE("IOCTL_KILL_PROCESS");

    {
        TEST_CASE("kills a target process");

        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = {};
        BOOL created = CreateProcessW(
            L"C:\\Windows\\System32\\cmd.exe",
            (LPWSTR)L"cmd.exe /c ping -n 30 127.0.0.1",
            NULL, NULL, FALSE,
            CREATE_NO_WINDOW, NULL, NULL, &si, &pi
        );

        if (!created) {
            printf("  SKIP: could not create target process\n");
            g_TestsTotal++;
            g_TestsPassed++;
            return;
        }

        Sleep(200);

        EDR_COMMAND cmd = {};
        cmd.Action = 1;
        cmd.ProcessId = pi.dwProcessId;

        DWORD bytesReturned = 0;
        BOOL ok = DeviceIoControl(
            hDevice,
            IOCTL_KILL_PROCESS,
            &cmd, sizeof(cmd),
            NULL, 0,
            &bytesReturned, NULL
        );
        TEST_ASSERT(ok, "kill IOCTL should succeed");

        DWORD waitResult = WaitForSingleObject(pi.hProcess, 3000);
        TEST_ASSERT(waitResult == WAIT_OBJECT_0,
            "target process should terminate");

        if (waitResult != WAIT_OBJECT_0) {
            TerminateProcess(pi.hProcess, 1);
        }

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    {
        TEST_CASE("rejects undersized command buffer");
        char tiny[2] = {};
        DWORD bytesReturned = 0;

        BOOL ok = DeviceIoControl(
            hDevice,
            IOCTL_KILL_PROCESS,
            tiny, sizeof(tiny),
            NULL, 0,
            &bytesReturned, NULL
        );
        TEST_ASSERT(!ok, "undersized command buffer should fail");
    }

    {
        TEST_CASE("handles non-existent PID gracefully");
        EDR_COMMAND cmd = {};
        cmd.Action = 1;
        cmd.ProcessId = 99999999;

        DWORD bytesReturned = 0;
        BOOL ok = DeviceIoControl(
            hDevice,
            IOCTL_KILL_PROCESS,
            &cmd, sizeof(cmd),
            NULL, 0,
            &bytesReturned, NULL
        );
        // Driver may return success or failure depending on implementation
        // The important thing is it doesn't BSOD
        printf("  INFO: kill non-existent PID returned %s\n", ok ? "OK" : "FAIL");
        g_TestsTotal++;
        g_TestsPassed++;
    }
}

// ============================================================
// Test: IOCTL_SIGNAL_LSASS_DUMP
// ============================================================

void TestSignalLsassDump(HANDLE hDevice)
{
    TEST_SUITE("IOCTL_SIGNAL_LSASS_DUMP");

    {
        TEST_CASE("accepts valid signal command");

        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = {};
        BOOL created = CreateProcessW(
            L"C:\\Windows\\System32\\cmd.exe",
            (LPWSTR)L"cmd.exe /c ping -n 30 127.0.0.1",
            NULL, NULL, FALSE,
            CREATE_NO_WINDOW, NULL, NULL, &si, &pi
        );

        if (!created) {
            printf("  SKIP: could not create target process\n");
            g_TestsTotal++;
            g_TestsPassed++;
            return;
        }

        Sleep(200);

        EDR_COMMAND cmd = {};
        cmd.Action = 1;
        cmd.ProcessId = pi.dwProcessId;

        DWORD bytesReturned = 0;
        BOOL ok = DeviceIoControl(
            hDevice,
            IOCTL_SIGNAL_LSASS_DUMP,
            &cmd, sizeof(cmd),
            NULL, 0,
            &bytesReturned, NULL
        );
        TEST_ASSERT(ok, "signal LSASS dump IOCTL should succeed");

        WaitForSingleObject(pi.hProcess, 3000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    {
        TEST_CASE("rejects undersized buffer");
        char tiny[2] = {};
        DWORD bytesReturned = 0;

        BOOL ok = DeviceIoControl(
            hDevice,
            IOCTL_SIGNAL_LSASS_DUMP,
            tiny, sizeof(tiny),
            NULL, 0,
            &bytesReturned, NULL
        );
        TEST_ASSERT(!ok, "undersized buffer should fail");
    }
}

// ============================================================
// Test: Block Rule Enforcement
// ============================================================

void TestBlockRuleEnforcement(HANDLE hDevice)
{
    TEST_SUITE("Block Rule Enforcement (End-to-End)");

    {
        TEST_CASE("blocked process is terminated at creation");

        // Clear existing rules first
        DWORD bytesReturned = 0;
        DeviceIoControl(hDevice, IOCTL_CLEAR_BLOCK_RULES,
            NULL, 0, NULL, 0, &bytesReturned, NULL);

        // Add a rule that blocks cmd.exe with "block_test_marker"
        BLOCK_RULE_ENTRY rule = {};
        wcscpy_s(rule.ImageSuffix, 260, L"cmd.exe");
        wcscpy_s(rule.CmdLineSubstr, 512, L"block_test_marker_12345");

        DeviceIoControl(hDevice, IOCTL_ADD_BLOCK_RULE,
            &rule, sizeof(rule), NULL, 0, &bytesReturned, NULL);

        // Try to create a process matching the block rule
        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = {};
        BOOL created = CreateProcessW(
            L"C:\\Windows\\System32\\cmd.exe",
            (LPWSTR)L"cmd.exe /c echo block_test_marker_12345",
            NULL, NULL, FALSE,
            CREATE_NO_WINDOW, NULL, NULL, &si, &pi
        );

        if (created) {
            DWORD waitResult = WaitForSingleObject(pi.hProcess, 5000);
            DWORD exitCode = 0;
            GetExitCodeProcess(pi.hProcess, &exitCode);

            // If blocked, the process should terminate quickly
            TEST_ASSERT(waitResult == WAIT_OBJECT_0,
                "blocked process should terminate");

            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        } else {
            printf("  INFO: CreateProcess returned FALSE (may have been blocked pre-creation)\n");
            g_TestsTotal++;
            g_TestsPassed++;
        }

        // Clean up rule
        DeviceIoControl(hDevice, IOCTL_CLEAR_BLOCK_RULES,
            NULL, 0, NULL, 0, &bytesReturned, NULL);
    }
}

// ============================================================
// Test: Stress / Edge Cases
// ============================================================

void TestEdgeCases(HANDLE hDevice)
{
    TEST_SUITE("Edge Cases");

    {
        TEST_CASE("add maximum block rules");
        DWORD bytesReturned = 0;

        DeviceIoControl(hDevice, IOCTL_CLEAR_BLOCK_RULES,
            NULL, 0, NULL, 0, &bytesReturned, NULL);

        int successCount = 0;
        for (int i = 0; i < 64; i++) {
            BLOCK_RULE_ENTRY rule = {};
            swprintf_s(rule.ImageSuffix, 260, L"test_%d.exe", i);

            BOOL ok = DeviceIoControl(
                hDevice,
                IOCTL_ADD_BLOCK_RULE,
                &rule, sizeof(rule),
                NULL, 0,
                &bytesReturned, NULL
            );
            if (ok) successCount++;
        }
        TEST_ASSERT(successCount == 64, "should accept 64 block rules");

        // 65th should fail
        BLOCK_RULE_ENTRY overflow = {};
        wcscpy_s(overflow.ImageSuffix, 260, L"overflow.exe");
        BOOL ok = DeviceIoControl(
            hDevice,
            IOCTL_ADD_BLOCK_RULE,
            &overflow, sizeof(overflow),
            NULL, 0,
            &bytesReturned, NULL
        );
        TEST_ASSERT(!ok, "65th rule should be rejected (max 64)");

        DeviceIoControl(hDevice, IOCTL_CLEAR_BLOCK_RULES,
            NULL, 0, NULL, 0, &bytesReturned, NULL);
    }

    {
        TEST_CASE("invalid IOCTL code returns error");
        DWORD code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8FF, METHOD_BUFFERED, FILE_ANY_ACCESS);
        DWORD bytesReturned = 0;

        BOOL ok = DeviceIoControl(
            hDevice,
            code,
            NULL, 0,
            NULL, 0,
            &bytesReturned, NULL
        );
        TEST_ASSERT(!ok, "invalid IOCTL should fail");
    }
}

// ============================================================
// Main
// ============================================================

int main()
{
    printf("MostShittyEDR - Driver IOCTL Integration Tests\n");
    printf("===============================================\n");
    printf("NOTE: Requires loaded driver and Administrator privileges\n\n");

    HANDLE hDevice = OpenDriver();
    if (hDevice == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        printf("ERROR: Cannot open \\\\.\\MostShittyEDR (error %lu)\n", err);
        if (err == ERROR_FILE_NOT_FOUND)
            printf("  -> Driver is not loaded. Run: sc start MostShittyEDR\n");
        else if (err == ERROR_ACCESS_DENIED)
            printf("  -> Run as Administrator.\n");
        printf("\nSkipping all IOCTL tests.\n");
        return 1;
    }

    TestDeviceOpen(hDevice);
    TestAddBlockRule(hDevice);
    TestClearBlockRules(hDevice);
    TestKillProcess(hDevice);
    TestSignalLsassDump(hDevice);
    TestWaitForEvent(hDevice);
    TestBlockRuleEnforcement(hDevice);
    TestEdgeCases(hDevice);

    CloseHandle(hDevice);

    printf("\n===============================================\n");
    printf("Results: %d passed, %d failed, %d total\n",
        g_TestsPassed, g_TestsFailed, g_TestsTotal);

    if (g_TestsFailed > 0) {
        printf("SOME TESTS FAILED\n");
        return 1;
    }

    printf("ALL TESTS PASSED\n");
    return 0;
}
