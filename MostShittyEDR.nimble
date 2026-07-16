# Package
version       = "1.0.0"
author        = "BenjiTrapp"
description   = "MostShittyEDR - The World's Most Intentionally Terrible EDR - A Bypass Lab"
license       = "MIT"
srcDir        = "src"
bin           = @["edr_agent"]

# Dependencies
requires "nim >= 2.0.0"
requires "winim >= 3.9.0"

# Tasks
task test, "Run all Nim unit tests":
  exec "nim c -r tests/test_rules.nim"
  exec "nim c -r tests/test_profiles.nim"
