## MostShittyEDR - Hook Profile Unit Tests
##
## Tests the EDR hook profile loader, parser, and Zw/Nt deduplication.
##
## Run: nim c -r -d:testing tests/test_profiles.nim
## Requires: winim (nimble install winim), profile files in profiles/

{.define: testing.}
import unittest
include ../src/edr_agent

# ============================================================
# Profile Loading
# ============================================================

suite "Hook Profile Loading":

  test "loads crowdstrike profile":
    let prof = loadHookProfile("crowdstrike")
    check prof.name == "crowdstrike"
    check prof.hookedApis.len > 0
    check prof.hookedApis.len >= 15

  test "loads carbonblack profile":
    let prof = loadHookProfile("carbonblack")
    check prof.name == "carbonblack"
    check prof.hookedApis.len > 0

  test "loads cylance profile":
    let prof = loadHookProfile("cylance")
    check prof.hookedApis.len > 0

  test "loads bitdefender profile":
    let prof = loadHookProfile("bitdefender")
    check prof.hookedApis.len >= 20

  test "loads cortex profile":
    let prof = loadHookProfile("cortex")
    check prof.hookedApis.len > 0

  test "loads checkpoint profile":
    let prof = loadHookProfile("checkpoint")
    check prof.hookedApis.len >= 20

  test "empty profile name returns empty":
    let prof = loadHookProfile("")
    check prof.hookedApis.len == 0

  test "'none' profile returns empty":
    let prof = loadHookProfile("none")
    check prof.hookedApis.len == 0

# ============================================================
# Profile Parsing
# ============================================================

suite "Hook Profile Parsing":

  test "all APIs start with 'Nt' (Zw deduplication)":
    let prof = loadHookProfile("crowdstrike")
    for api in prof.hookedApis:
      check api.startsWith("Nt")

  test "no duplicate entries":
    let prof = loadHookProfile("bitdefender")
    var seen: seq[string] = @[]
    for api in prof.hookedApis:
      check api notin seen
      seen.add(api)

  test "crowdstrike contains NtAllocateVirtualMemory":
    let prof = loadHookProfile("crowdstrike")
    check "NtAllocateVirtualMemory" in prof.hookedApis

  test "crowdstrike contains NtWriteVirtualMemory":
    let prof = loadHookProfile("crowdstrike")
    check "NtWriteVirtualMemory" in prof.hookedApis

  test "cortex contains NtProtectVirtualMemory":
    let prof = loadHookProfile("cortex")
    check "NtProtectVirtualMemory" in prof.hookedApis

  test "checkpoint contains NtWriteVirtualMemory":
    let prof = loadHookProfile("checkpoint")
    check "NtWriteVirtualMemory" in prof.hookedApis

  test "bitdefender has the most hooks":
    let bd = loadHookProfile("bitdefender")
    let cs = loadHookProfile("crowdstrike")
    let cb = loadHookProfile("carbonblack")
    check bd.hookedApis.len >= cs.hookedApis.len
    check bd.hookedApis.len >= cb.hookedApis.len

# ============================================================
# Profile Listing
# ============================================================

suite "Profile Listing":

  test "lists available profiles":
    let profiles = listProfiles()
    check profiles.len >= 6

  test "list contains expected profiles":
    let profiles = listProfiles()
    check "crowdstrike" in profiles
    check "carbonblack" in profiles
    check "cylance" in profiles
    check "bitdefender" in profiles
    check "cortex" in profiles
    check "checkpoint" in profiles

# ============================================================
# Cross-Profile Comparisons
# ============================================================

suite "Cross-Profile Analysis":

  test "all profiles contain NtWriteVirtualMemory":
    for name in @["crowdstrike", "carbonblack", "cylance", "bitdefender", "cortex", "checkpoint"]:
      let prof = loadHookProfile(name)
      check "NtWriteVirtualMemory" in prof.hookedApis

  test "all profiles contain NtMapViewOfSection":
    for name in @["crowdstrike", "carbonblack", "cylance", "bitdefender", "cortex", "checkpoint"]:
      let prof = loadHookProfile(name)
      check "NtMapViewOfSection" in prof.hookedApis

  test "all profiles contain NtQueueApcThread":
    for name in @["crowdstrike", "carbonblack", "cylance", "bitdefender", "cortex", "checkpoint"]:
      let prof = loadHookProfile(name)
      check "NtQueueApcThread" in prof.hookedApis
