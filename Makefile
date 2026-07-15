.PHONY: build clean install-deps run run-verbose run-safe help

NIM      ?= nim
NIMBLE   ?= nimble
SRC       = src/edr_agent.nim
OUT       = edr_agent.exe
NIMFLAGS  = -d:release --opt:size --app:console

help:
	@echo "MostShittyEDR - Build Targets"
	@echo "=============================="
	@echo ""
	@echo "  make install-deps  - Install Nim dependencies (winim)"
	@echo "  make build         - Compile the EDR agent"
	@echo "  make build-debug   - Compile with debug symbols"
	@echo "  make run           - Build and run the EDR agent"
	@echo "  make run-verbose   - Build and run with verbose output"
	@echo "  make run-safe      - Build and run in detection-only mode"
	@echo "  make clean         - Remove build artifacts"
	@echo "  make test          - Run all challenge test scripts"
	@echo "  make test-cat CAT=N - Run tests for category N"
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

clean:
	rm -f $(OUT)
	rm -f src/edr_agent
	rm -rf nimcache/
	rm -rf src/nimcache/

test:
	@echo "Run the EDR agent in one terminal, then execute challenge payloads in another."
	@echo "See challenges/ directory for instructions."

test-cat:
	@echo "Category $(CAT) challenges - see challenges/ directory"
