ROOT_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
UNIT_DIR := $(ROOT_DIR)/tests/unit
UNIT_BUILD_DIR := $(UNIT_DIR)/build
FUZZING_DIR := $(ROOT_DIR)/tests/fuzzing
FUZZING_BUILD_DIR := $(FUZZING_DIR)/build
MAKEFLAGS += --no-print-directory
TARGET ?= stax
JOBS ?= 8
FUZZ_SECONDS ?= 1

ifneq ($(wildcard $(ROOT_DIR)/tests/venv/bin/python),)
PYTHON ?= $(ROOT_DIR)/tests/venv/bin/python
else
PYTHON ?= python3
endif

.PHONY: help python-checks clang-format-src-check clang-format-generated-check tests-unit generated-fixture-drift unit-build unit-run fuzzing

help:
	@echo "Available targets:"
	@echo "  make -C tests python-checks Run Ruff format check, pylint, and mypy"
	@echo "  make -C tests clang-format-src-check Check clang-format-14 on src/*.c and src/*.h"
	@echo "  make -C tests tests-unit    Regenerate unit fixtures, check drift, build, and run unit tests"
	@echo "  make -C tests fuzzing       Build fuzzing harnesses and run each for $(FUZZ_SECONDS) seconds"

python-checks:
	cd $(ROOT_DIR) && ruff format --check . --exclude tests/venv
	cd $(ROOT_DIR) && pylint --rcfile=.pylintrc tests/application_client tests/standalone tests/swap
	cd $(ROOT_DIR) && mypy --config-file mypy.ini

clang-format-src-check:
	@cd $(ROOT_DIR) && \
	if command -v clang-format-14 >/dev/null 2>&1; then \
		SRC_FILES="$$(find src -type f \( -name '*.c' -o -name '*.h' \) | sort)"; \
		if [ -n "$$SRC_FILES" ]; then \
			clang-format-14 --dry-run --Werror $$SRC_FILES; \
		fi; \
	else \
		echo "WARNING: clang-format-14 not found; skipping src C formatting check"; \
	fi

clang-format-generated-check:
	@cd $(ROOT_DIR) && \
	if command -v clang-format-14 >/dev/null 2>&1; then \
		GENERATED_FILES="$$(find tests/unit/generated tests/unit/mock_crypto -type f \( -name '*.c' -o -name '*.h' \) | sort)"; \
		if [ -n "$$GENERATED_FILES" ]; then \
			clang-format-14 --dry-run --Werror $$GENERATED_FILES; \
		fi; \
	else \
		echo "WARNING: clang-format-14 not found; skipping generated C formatting check"; \
	fi

tests-unit: generated-fixture-drift unit-build unit-run

generated-fixture-drift:
	cd $(ROOT_DIR) && PYTHONPATH=. $(PYTHON) -m tests.unit.generators.generate_unit_tests_from_ragger all
	$(MAKE) clang-format-generated-check
	cd $(ROOT_DIR) && git diff --exit-code -- tests/unit/generated tests/unit/mock_crypto/crypto_mock_data.h

unit-build:
	cmake -S $(UNIT_DIR) -B $(UNIT_BUILD_DIR)
	cmake --build $(UNIT_BUILD_DIR) -j$(JOBS)

unit-run:
	CTEST_OUTPUT_ON_FAILURE=1 ctest --test-dir $(UNIT_BUILD_DIR) --output-on-failure

fuzzing:
	@test -n "$(BOLOS_SDK)" || (echo "BOLOS_SDK must be set for fuzzing builds" && exit 1)
	GNUMAKEFLAGS=--no-print-directory cmake -S $(FUZZING_DIR) -B $(FUZZING_BUILD_DIR) -DBOLOS_SDK=$(BOLOS_SDK) -DTARGET=$(TARGET) -DCMAKE_C_COMPILER=clang -DCMAKE_BUILD_TYPE=Debug -DSANITIZER=address
	GNUMAKEFLAGS=--no-print-directory cmake --build $(FUZZING_BUILD_DIR) -j$(JOBS)
	cd $(FUZZING_DIR) && ./run_all_fuzzers.sh $(FUZZ_SECONDS)
