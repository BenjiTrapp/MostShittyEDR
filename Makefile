.PHONY: build clean install-deps run run-verbose run-safe run-driver help \
       test test-nim test-driver-logic test-driver-ioctl uninstall

NIM      ?= nim
NIMBLE   ?= nimble
CL       ?= cl
SRC       = src/edr_agent.nim
OUT       = edr_agent.exe
NIMFLAGS  = -d:release --opt:size --app:console

help:
	@echo "MostShittyEDR - Build Targets"
	@echo "=============================="
	@echo ""
	@echo "  make install-deps      - Install Nim dependencies (winim)"
	@echo "  make build             - Compile the EDR agent"
	@echo "  make build-debug       - Compile with debug symbols"
	@echo "  make run               - Build and run the EDR agent"
	@echo "  make run-verbose       - Build and run with verbose output"
	@echo "  make run-safe          - Build and run in detection-only mode"
	@echo "  make run-driver        - Build and run with kernel driver (requires Admin)"
	@echo "  make uninstall         - Uninstall agent + driver (requires Admin)"
	@echo "  make clean             - Remove build artifacts"
	@echo "  make test              - Run all unit tests (Nim + driver logic)"
	@echo "  make test-nim          - Run Nim agent unit tests"
	@echo "  make test-driver-logic - Run driver logic tests (user-mode, no driver needed)"
	@echo "  make test-driver-ioctl - Run driver IOCTL tests (requires loaded driver + Admin)"
	@echo ""

install-deps:
	$(NIMBLE) install winim -y

build: install-deps
	$(NIM) c $(NIMFLAGS) -o:$(OUT) $(SRC)

build-debug: install-deps
	$(NIM) c -d:debug --debugger:native -o:$(OUT) $(SRC)

run: build
	./$(OUT) --verbose

run-verbose: build
	./$(OUT) --verbose

run-safe: build
	./$(OUT) --verbose --no-kill

run-driver: build
	@echo "NOTE: Requires loaded driver and Administrator privileges"
	./$(OUT) --driver --verbose

clean:
	rm -f $(OUT)
	rm -f src/edr_agent
	rm -rf nimcache/
	rm -rf src/nimcache/

uninstall:
	@echo "Uninstalling agent + driver..."
	powershell -ExecutionPolicy Bypass -File uninstall.ps1 -Force

test: test-nim test-driver-logic

test-nim: install-deps
	$(NIM) c -r -d:testing tests/test_rules.nim
	$(NIM) c -r -d:testing tests/test_profiles.nim

test-driver-logic:
	$(CL) /EHsc /W4 tests/test_driver_logic.cpp /Fe:test_driver_logic.exe
	./test_driver_logic.exe

test-driver-ioctl:
	$(CL) /EHsc /W4 tests/test_driver_ioctl.cpp /Fe:test_driver_ioctl.exe
	@echo "NOTE: Requires loaded driver and Administrator privileges"
	./test_driver_ioctl.exe

test-cat:
	@echo "Category $(CAT) challenges - see challenges/ directory"
