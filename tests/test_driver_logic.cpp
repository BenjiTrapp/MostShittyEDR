///////////////////////////////////////////////////////////////////////////////
//
//  MostShittyEDR - Driver Logic Unit Tests
//
//  Tests the driver's utility functions in user-mode. These functions are
//  duplicated from driver.cpp with RtlUpcaseUnicodeChar replaced by
//  towupper for user-mode compatibility.
//
//  Build:  cl /EHsc /W4 tests\test_driver_logic.cpp /Fe:test_driver_logic.exe
//  Run:    test_driver_logic.exe
//
///////////////////////////////////////////////////////////////////////////////

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <wctype.h>

// ============================================================
// Test framework (minimal, no external deps)
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
// Driver utility functions (user-mode copies)
//
// These mirror driver.cpp exactly, but use towupper() instead
// of RtlUpcaseUnicodeChar() for user-mode compatibility.
// ============================================================

static BOOLEAN WcsEndsWithInsensitive(
    PWCHAR Str, ULONG StrLen, PCWSTR Suf)
{
    SIZE_T sufLen = wcslen(Suf);
    if (!sufLen || StrLen < sufLen) return FALSE;

    SIZE_T offset = StrLen - sufLen;
    for (SIZE_T i = 0; i < sufLen; ++i) {
        if (towupper(Str[offset + i]) != towupper(Suf[i]))
            return FALSE;
    }
    return TRUE;
}

static BOOLEAN WcsContainsInsensitive(
    PWCHAR Str, ULONG StrLen, PCWSTR Sub)
{
    SIZE_T subLen = wcslen(Sub);
    if (!subLen || StrLen < subLen) return FALSE;

    for (SIZE_T pos = 0; pos <= StrLen - subLen; ++pos) {
        BOOLEAN match = TRUE;
        for (SIZE_T i = 0; i < subLen; ++i) {
            if (towupper(Str[pos + i]) != towupper(Sub[i])) {
                match = FALSE;
                break;
            }
        }
        if (match) return TRUE;
    }
    return FALSE;
}

// Struct definitions matching driver.cpp
#pragma pack(push, 1)

typedef struct _BLOCK_RULE_ENTRY {
    WCHAR ImageSuffix[260];
    WCHAR CmdLineSubstr[512];
} BLOCK_RULE_ENTRY;

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

#pragma pack(pop)

static BOOLEAN MatchBlockRule(
    BLOCK_RULE_ENTRY* Rule,
    PWCHAR ImageFileName, ULONG ImageLen,
    PWCHAR CmdLine,       ULONG CmdLineLen)
{
    BOOLEAN imgOk = (Rule->ImageSuffix[0] == L'\0') ||
        WcsEndsWithInsensitive(ImageFileName, ImageLen, Rule->ImageSuffix);

    BOOLEAN cmdOk = (Rule->CmdLineSubstr[0] == L'\0') ||
        WcsContainsInsensitive(CmdLine, CmdLineLen, Rule->CmdLineSubstr);

    return imgOk && cmdOk;
}

// ============================================================
// Tests: WcsEndsWithInsensitive
// ============================================================

void TestSuffixMatching()
{
    TEST_SUITE("WcsEndsWithInsensitive");

    {
        TEST_CASE("exact match");
        WCHAR str[] = L"cmd.exe";
        TEST_ASSERT(WcsEndsWithInsensitive(str, 7, L"cmd.exe"), "exact match should succeed");
    }

    {
        TEST_CASE("suffix match");
        WCHAR str[] = L"C:\\Windows\\System32\\cmd.exe";
        TEST_ASSERT(WcsEndsWithInsensitive(str, (ULONG)wcslen(str), L"cmd.exe"), "suffix match should succeed");
    }

    {
        TEST_CASE("case insensitive");
        WCHAR str[] = L"C:\\Windows\\CMD.EXE";
        TEST_ASSERT(WcsEndsWithInsensitive(str, (ULONG)wcslen(str), L"cmd.exe"), "case insensitive match should succeed");
    }

    {
        TEST_CASE("mixed case");
        WCHAR str[] = L"Mimikatz.Exe";
        TEST_ASSERT(WcsEndsWithInsensitive(str, (ULONG)wcslen(str), L"mimikatz.exe"), "mixed case should match");
    }

    {
        TEST_CASE("no match");
        WCHAR str[] = L"powershell.exe";
        TEST_ASSERT(!WcsEndsWithInsensitive(str, (ULONG)wcslen(str), L"cmd.exe"), "non-matching suffix should fail");
    }

    {
        TEST_CASE("suffix longer than string");
        WCHAR str[] = L"x.exe";
        TEST_ASSERT(!WcsEndsWithInsensitive(str, 5, L"mimikatz.exe"), "suffix longer than string should fail");
    }

    {
        TEST_CASE("empty suffix");
        WCHAR str[] = L"test.exe";
        TEST_ASSERT(!WcsEndsWithInsensitive(str, 8, L""), "empty suffix should return FALSE");
    }

    {
        TEST_CASE("empty string");
        WCHAR str[] = L"";
        TEST_ASSERT(!WcsEndsWithInsensitive(str, 0, L"cmd.exe"), "empty string should fail");
    }
}

// ============================================================
// Tests: WcsContainsInsensitive
// ============================================================

void TestSubstringSearch()
{
    TEST_SUITE("WcsContainsInsensitive");

    {
        TEST_CASE("contains at start");
        WCHAR str[] = L"whoami /all";
        TEST_ASSERT(WcsContainsInsensitive(str, (ULONG)wcslen(str), L"whoami"), "should find at start");
    }

    {
        TEST_CASE("contains in middle");
        WCHAR str[] = L"cmd /c whoami /all";
        TEST_ASSERT(WcsContainsInsensitive(str, (ULONG)wcslen(str), L"whoami"), "should find in middle");
    }

    {
        TEST_CASE("contains at end");
        WCHAR str[] = L"run mimikatz";
        TEST_ASSERT(WcsContainsInsensitive(str, (ULONG)wcslen(str), L"mimikatz"), "should find at end");
    }

    {
        TEST_CASE("case insensitive");
        WCHAR str[] = L"INVOKE-MIMIKATZ -DumpCreds";
        TEST_ASSERT(WcsContainsInsensitive(str, (ULONG)wcslen(str), L"invoke-mimikatz"), "case insensitive should match");
    }

    {
        TEST_CASE("no match");
        WCHAR str[] = L"dir /s /b";
        TEST_ASSERT(!WcsContainsInsensitive(str, (ULONG)wcslen(str), L"mimikatz"), "non-matching should fail");
    }

    {
        TEST_CASE("substring longer than string");
        WCHAR str[] = L"hi";
        TEST_ASSERT(!WcsContainsInsensitive(str, 2, L"longer_substring"), "longer substring should fail");
    }

    {
        TEST_CASE("exact match");
        WCHAR str[] = L"whoami";
        TEST_ASSERT(WcsContainsInsensitive(str, 6, L"whoami"), "exact match should succeed");
    }
}

// ============================================================
// Tests: MatchBlockRule
// ============================================================

void TestBlockRuleMatching()
{
    TEST_SUITE("MatchBlockRule");

    {
        TEST_CASE("both conditions match");
        BLOCK_RULE_ENTRY rule = {};
        wcscpy_s(rule.ImageSuffix, 260, L"cmd.exe");
        wcscpy_s(rule.CmdLineSubstr, 512, L"whoami");

        WCHAR img[] = L"C:\\Windows\\System32\\cmd.exe";
        WCHAR cmd[] = L"cmd /c whoami";
        TEST_ASSERT(MatchBlockRule(&rule, img, (ULONG)wcslen(img), cmd, (ULONG)wcslen(cmd)),
            "both conditions met should match");
    }

    {
        TEST_CASE("image matches, command doesn't");
        BLOCK_RULE_ENTRY rule = {};
        wcscpy_s(rule.ImageSuffix, 260, L"cmd.exe");
        wcscpy_s(rule.CmdLineSubstr, 512, L"mimikatz");

        WCHAR img[] = L"C:\\Windows\\System32\\cmd.exe";
        WCHAR cmd[] = L"cmd /c dir";
        TEST_ASSERT(!MatchBlockRule(&rule, img, (ULONG)wcslen(img), cmd, (ULONG)wcslen(cmd)),
            "only image match should not trigger");
    }

    {
        TEST_CASE("command matches, image doesn't");
        BLOCK_RULE_ENTRY rule = {};
        wcscpy_s(rule.ImageSuffix, 260, L"powershell.exe");
        wcscpy_s(rule.CmdLineSubstr, 512, L"whoami");

        WCHAR img[] = L"C:\\Windows\\System32\\cmd.exe";
        WCHAR cmd[] = L"cmd /c whoami";
        TEST_ASSERT(!MatchBlockRule(&rule, img, (ULONG)wcslen(img), cmd, (ULONG)wcslen(cmd)),
            "only command match should not trigger");
    }

    {
        TEST_CASE("wildcard image (empty suffix matches any)");
        BLOCK_RULE_ENTRY rule = {};
        rule.ImageSuffix[0] = L'\0';
        wcscpy_s(rule.CmdLineSubstr, 512, L"sekurlsa");

        WCHAR img[] = L"any_process.exe";
        WCHAR cmd[] = L"sekurlsa::logonpasswords";
        TEST_ASSERT(MatchBlockRule(&rule, img, (ULONG)wcslen(img), cmd, (ULONG)wcslen(cmd)),
            "empty image suffix should match any");
    }

    {
        TEST_CASE("wildcard command (empty substr matches any)");
        BLOCK_RULE_ENTRY rule = {};
        wcscpy_s(rule.ImageSuffix, 260, L"mimikatz.exe");
        rule.CmdLineSubstr[0] = L'\0';

        WCHAR img[] = L"C:\\tools\\mimikatz.exe";
        WCHAR cmd[] = L"anything here";
        TEST_ASSERT(MatchBlockRule(&rule, img, (ULONG)wcslen(img), cmd, (ULONG)wcslen(cmd)),
            "empty command substr should match any");
    }

    {
        TEST_CASE("both wildcards match everything");
        BLOCK_RULE_ENTRY rule = {};
        rule.ImageSuffix[0] = L'\0';
        rule.CmdLineSubstr[0] = L'\0';

        WCHAR img[] = L"anything.exe";
        WCHAR cmd[] = L"any command";
        TEST_ASSERT(MatchBlockRule(&rule, img, (ULONG)wcslen(img), cmd, (ULONG)wcslen(cmd)),
            "double wildcard should match everything");
    }

    {
        TEST_CASE("case insensitive matching");
        BLOCK_RULE_ENTRY rule = {};
        wcscpy_s(rule.ImageSuffix, 260, L"mimikatz.exe");
        wcscpy_s(rule.CmdLineSubstr, 512, L"sekurlsa");

        WCHAR img[] = L"C:\\Tools\\MIMIKATZ.EXE";
        WCHAR cmd[] = L"SEKURLSA::LogonPasswords";
        TEST_ASSERT(MatchBlockRule(&rule, img, (ULONG)wcslen(img), cmd, (ULONG)wcslen(cmd)),
            "case insensitive matching should work");
    }
}

// ============================================================
// Tests: Struct Layout Validation
// ============================================================

void TestStructLayouts()
{
    TEST_SUITE("Struct Layout Validation");

    {
        TEST_CASE("EDR_EVENT size");
        // EventType(4) + Timestamp(8) + PID(8) + TID(8) + PPID(8) +
        // Blocked(1) + ImageFileName(520) + CommandLine(1024) = 1581
        TEST_ASSERT(sizeof(EDR_EVENT) == 1581,
            "EDR_EVENT packed size should be 1581 bytes");
    }

    {
        TEST_CASE("EDR_COMMAND size");
        // Action(4) + ProcessId(8) = 12
        TEST_ASSERT(sizeof(EDR_COMMAND) == 12,
            "EDR_COMMAND packed size should be 12 bytes");
    }

    {
        TEST_CASE("BLOCK_RULE_ENTRY size");
        // ImageSuffix(520) + CmdLineSubstr(1024) = 1544
        TEST_ASSERT(sizeof(BLOCK_RULE_ENTRY) == 1544,
            "BLOCK_RULE_ENTRY packed size should be 1544 bytes");
    }
}

// ============================================================
// Tests: IOCTL Code Validation
// ============================================================

void TestIoctlCodes()
{
    TEST_SUITE("IOCTL Code Validation");

    #define IOCTL_WAIT_FOR_EVENT    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
    #define IOCTL_KILL_PROCESS      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
    #define IOCTL_ADD_BLOCK_RULE    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
    #define IOCTL_CLEAR_BLOCK_RULES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
    #define IOCTL_SIGNAL_LSASS_DUMP CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

    {
        TEST_CASE("IOCTL codes are unique");
        TEST_ASSERT(IOCTL_WAIT_FOR_EVENT    != IOCTL_KILL_PROCESS, "IOCTLs must be unique");
        TEST_ASSERT(IOCTL_KILL_PROCESS      != IOCTL_ADD_BLOCK_RULE, "IOCTLs must be unique");
        TEST_ASSERT(IOCTL_ADD_BLOCK_RULE    != IOCTL_CLEAR_BLOCK_RULES, "IOCTLs must be unique");
        TEST_ASSERT(IOCTL_CLEAR_BLOCK_RULES != IOCTL_SIGNAL_LSASS_DUMP, "IOCTLs must be unique");
    }

    {
        TEST_CASE("IOCTL codes match expected values");
        TEST_ASSERT(IOCTL_WAIT_FOR_EVENT    == 0x222000, "WAIT_FOR_EVENT should be 0x222000");
        TEST_ASSERT(IOCTL_KILL_PROCESS      == 0x222004, "KILL_PROCESS should be 0x222004");
        TEST_ASSERT(IOCTL_ADD_BLOCK_RULE    == 0x222008, "ADD_BLOCK_RULE should be 0x222008");
        TEST_ASSERT(IOCTL_CLEAR_BLOCK_RULES == 0x22200C, "CLEAR_BLOCK_RULES should be 0x22200C");
        TEST_ASSERT(IOCTL_SIGNAL_LSASS_DUMP == 0x222010, "SIGNAL_LSASS_DUMP should be 0x222010");
    }

    {
        TEST_CASE("all use METHOD_BUFFERED");
        TEST_ASSERT((IOCTL_WAIT_FOR_EVENT & 3)    == 0, "should use METHOD_BUFFERED");
        TEST_ASSERT((IOCTL_KILL_PROCESS & 3)      == 0, "should use METHOD_BUFFERED");
        TEST_ASSERT((IOCTL_ADD_BLOCK_RULE & 3)    == 0, "should use METHOD_BUFFERED");
        TEST_ASSERT((IOCTL_CLEAR_BLOCK_RULES & 3) == 0, "should use METHOD_BUFFERED");
        TEST_ASSERT((IOCTL_SIGNAL_LSASS_DUMP & 3) == 0, "should use METHOD_BUFFERED");
    }
}

// ============================================================
// Tests: Event Type Constants
// ============================================================

void TestEventConstants()
{
    TEST_SUITE("Event Type Constants");

    #define EVENT_TYPE_PROCESS_CREATE 1
    #define EVENT_TYPE_PROCESS_EXIT   2
    #define EVENT_TYPE_THREAD_CREATE  3
    #define EVENT_TYPE_THREAD_EXIT    4
    #define EVENT_TYPE_LSASS_ACCESS   5

    {
        TEST_CASE("event types are sequential");
        TEST_ASSERT(EVENT_TYPE_PROCESS_CREATE == 1, "PROCESS_CREATE should be 1");
        TEST_ASSERT(EVENT_TYPE_PROCESS_EXIT   == 2, "PROCESS_EXIT should be 2");
        TEST_ASSERT(EVENT_TYPE_THREAD_CREATE  == 3, "THREAD_CREATE should be 3");
        TEST_ASSERT(EVENT_TYPE_THREAD_EXIT    == 4, "THREAD_EXIT should be 4");
        TEST_ASSERT(EVENT_TYPE_LSASS_ACCESS   == 5, "LSASS_ACCESS should be 5");
    }
}

// ============================================================
// Main
// ============================================================

int main()
{
    printf("MostShittyEDR - Driver Logic Unit Tests\n");
    printf("=======================================\n");

    TestSuffixMatching();
    TestSubstringSearch();
    TestBlockRuleMatching();
    TestStructLayouts();
    TestIoctlCodes();
    TestEventConstants();

    printf("\n=======================================\n");
    printf("Results: %d passed, %d failed, %d total\n",
        g_TestsPassed, g_TestsFailed, g_TestsTotal);

    if (g_TestsFailed > 0) {
        printf("SOME TESTS FAILED\n");
        return 1;
    }

    printf("ALL TESTS PASSED\n");
    return 0;
}
