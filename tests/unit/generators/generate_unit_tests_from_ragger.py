#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

"""
Unified generator for unit-test fixtures derived from ragger sources.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from tests.unit.generators.paths import UNIT_TESTS_DIR
from tests.unit.generators.paths import (
    REPO_ROOT,
    GENERATED_SIGN_TX_DIR,
    GENERATED_SIGN_MSG_DIR,
    GENERATED_CVOTE_DIR,
    GENERATED_OPCERT_DIR,
    GENERATED_PUBKEY_DIR,
    GENERATED_DERIVE_ADDRESS_DIR,
    GENERATED_NATIVE_SCRIPT_DIR,
)
from tests.unit.generators.mock_data_utils import regenerate_mock_data


# Import fixture generators
from tests.unit.generators.fixture_generators.tx_generators import (
    generate_tx_fixtures,
)

from tests.unit.generators.fixture_generators.derive_address_generators import (
    generate_address_derivation_fixtures,
)

from tests.unit.generators.fixture_generators.derive_native_script_generators import (
    generate_derive_native_script_fixtures,
)
from tests.unit.generators.fixture_generators.pubkey_generators import (
    generate_pubkey_fixtures,
)
from tests.unit.generators.fixture_generators.sign_msg_generators import (
    generate_sign_msg_fixtures,
)
from tests.unit.generators.fixture_generators.opcert_generators import (
    generate_opcert_fixtures,
)
from tests.unit.generators.fixture_generators.cvote_generators import (
    generate_cvote_fixtures,
)

# Import deny generators
from tests.unit.generators.deny_fixture_generators.tx_deny_generators import (
    generate_tx_deny_fixtures,
)

from tests.unit.generators.deny_fixture_generators.derive_address_deny_generators import (
    generate_address_derivation_deny_fixtures,
)

from tests.unit.generators.deny_fixture_generators.derive_native_script_deny_generators import (
    generate_derive_native_script_deny_fixtures,
)
from tests.unit.generators.deny_fixture_generators.pubkey_deny_generators import (
    generate_pubkey_deny_fixtures,
)
from tests.unit.generators.deny_fixture_generators.opcert_deny_generators import (
    generate_opcert_deny_fixtures,
)
from tests.unit.generators.deny_fixture_generators.cvote_deny_generators import (
    generate_cvote_deny_fixtures,
)

# Import test runners
from tests.unit.generators.test_runner_generators.tx_test_runner_generators import (
    generate_tx_test_runners,
)

from tests.unit.generators.test_runner_generators.derive_address_test_runner_generators import (
    generate_address_derivation_test_runners,
)

from tests.unit.generators.test_runner_generators.derive_native_script_runner_generators import (
    generate_native_script_test_runners,
)
from tests.unit.generators.test_runner_generators.derive_address_deny_runner_generators import (
    generate_address_derivation_deny_test_runners,
)
from tests.unit.generators.test_runner_generators.pubkey_test_runner_generators import (
    generate_pubkey_test_runners,
)
from tests.unit.generators.test_runner_generators.pubkey_deny_runner_generators import (
    generate_pubkey_deny_test_runners,
)
from tests.unit.generators.test_runner_generators.sign_msg_test_runner_generators import (
    generate_sign_msg_test_runners,
)
from tests.unit.generators.test_runner_generators.opcert_test_runner_generators import (
    generate_opcert_test_runners,
)
from tests.unit.generators.test_runner_generators.opcert_deny_runner_generators import (
    generate_opcert_deny_test_runners,
)
from tests.unit.generators.test_runner_generators.cvote_test_runner_generators import (
    generate_cvote_test_runners,
)
from tests.unit.generators.test_runner_generators.cvote_deny_runner_generators import (
    generate_cvote_deny_test_runners,
)
from tests.unit.generators.test_runner_generators.native_script_deny_runner_generators import (
    generate_native_script_deny_test_runners,
)

_REPORT_WIDTH = 88

# Match deny fixtures array for counting individual deny cases
_SIGN_TX_DENY_FIXTURES_PATTERN = re.compile(
    r"static const sign_tx_deny_fixture_t SIGN_TX_DENY_FIXTURES\[\]\s*=\s*\{(.*?)\n\};",
    flags=re.DOTALL,
)

# Match individual deny fixture entries inside the array
_SIGN_TX_DENY_ENTRY_PATTERN = re.compile(r"\.name\s*=")
_TX_FIXTURE_PATTERN = re.compile(
    r"static const tx_fixture_t (FIXTURE_[A-Z0-9_]+)\s*=\s*\{(.*?)\};",
    flags=re.DOTALL,
)
_TX_AUX_INCLUDED_PATTERN = re.compile(r"\.include_aux_data_hash\s*=\s*(true|false)")
_TX_AUX_TYPE_PATTERN = re.compile(r"\.aux_data_type\s*=\s*([A-Z0-9_]+|\d+)")


def _log_stage(message: str) -> None:
    print(f"\n--- {message} ---")


def _count_sign_tx_deny_fixtures() -> int:
    """Return the number of fixtures in sign_tx deny suite to account for per-test coverage."""
    fixtures_file = GENERATED_SIGN_TX_DIR / "test_sign_tx_fixtures_deny.h"
    if not fixtures_file.exists():
        return 0

    try:
        content = fixtures_file.read_text(encoding="utf-8")
    except OSError:
        return 0

    match = _SIGN_TX_DENY_FIXTURES_PATTERN.search(content)
    if not match:
        return 0

    fixture_body = match.group(1)
    return len(_SIGN_TX_DENY_ENTRY_PATTERN.findall(fixture_body))


def _fixture_has_cvote_aux_data(fixture_body: str) -> bool:
    aux_included_match = _TX_AUX_INCLUDED_PATTERN.search(fixture_body)
    aux_type_match = _TX_AUX_TYPE_PATTERN.search(fixture_body)
    if aux_included_match is None or aux_type_match is None:
        return False

    include_aux_data = aux_included_match.group(1) == "true"
    aux_type_token = aux_type_match.group(1)
    return include_aux_data and aux_type_token in {
        "1",
        "AUX_DATA_TYPE_CVOTE_REGISTRATION",
    }


def _count_sign_tx_fine_grained_entries_from_fixtures() -> int:
    """
    Count fine-grained sign-tx entries from fixture headers on disk.

    This mirrors tx runner generation granularity:
    - 4 entries per tx fixture (approve/reject-tx x expert-off/on)
    - +2 entries when fixture has CIP36 aux data (reject-aux x expert-off/on)
    - plus deny fixtures from SIGN_TX_DENY_FIXTURES
    """
    total_entries = 0
    fixture_headers = sorted(
        p
        for p in GENERATED_SIGN_TX_DIR.glob("test_sign_tx_fixtures_*.h")
        if p.name != "test_sign_tx_fixtures_deny.h"
    )

    for fixture_header_path in fixture_headers:
        try:
            header_content = fixture_header_path.read_text(encoding="utf-8")
        except OSError:
            continue

        for fixture_match in _TX_FIXTURE_PATTERN.finditer(header_content):
            fixture_body = fixture_match.group(2)
            total_entries += 4
            if _fixture_has_cvote_aux_data(fixture_body):
                total_entries += 2

    total_entries += _count_sign_tx_deny_fixtures()
    return total_entries


@dataclass
class CommandMetadata:
    id: str
    display_name: str
    ragger_file_name: str
    generated_dir: Path
    fixture_generators: list[Callable]
    runner_generators: list[Callable]
    deny_generators: list[Callable]
    generated_entries_count: int = 0


COMMAND_REGISTRY = [
    CommandMetadata(
        id="sign_tx",
        display_name="Sign Transaction",
        ragger_file_name="test_sign_tx.py",
        generated_dir=GENERATED_SIGN_TX_DIR,
        fixture_generators=[generate_tx_fixtures],
        runner_generators=[generate_tx_test_runners],
        deny_generators=[generate_tx_deny_fixtures],
    ),
    CommandMetadata(
        id="sign_msg",
        display_name="Sign Message",
        ragger_file_name="test_signMsg.py",
        generated_dir=GENERATED_SIGN_MSG_DIR,
        fixture_generators=[generate_sign_msg_fixtures],
        runner_generators=[generate_sign_msg_test_runners],
        deny_generators=[],
    ),
    CommandMetadata(
        id="sign_cvote",
        display_name="Sign CVote",
        ragger_file_name="test_cvote.py",
        generated_dir=GENERATED_CVOTE_DIR,
        fixture_generators=[generate_cvote_fixtures],
        runner_generators=[
            generate_cvote_test_runners,
            generate_cvote_deny_test_runners,
        ],
        deny_generators=[generate_cvote_deny_fixtures],
    ),
    CommandMetadata(
        id="sign_opcert",
        display_name="Sign Opcert",
        ragger_file_name="test_opcert.py",
        generated_dir=GENERATED_OPCERT_DIR,
        fixture_generators=[generate_opcert_fixtures],
        runner_generators=[
            generate_opcert_test_runners,
            generate_opcert_deny_test_runners,
        ],
        deny_generators=[generate_opcert_deny_fixtures],
    ),
    CommandMetadata(
        id="pubkey_export",
        display_name="Pubkey Export",
        ragger_file_name="test_pubkey.py",
        generated_dir=GENERATED_PUBKEY_DIR,
        fixture_generators=[generate_pubkey_fixtures],
        runner_generators=[
            generate_pubkey_test_runners,
            generate_pubkey_deny_test_runners,
        ],
        deny_generators=[generate_pubkey_deny_fixtures],
    ),
    CommandMetadata(
        id="derive_address",
        display_name="Derive Address",
        ragger_file_name="test_derive_address.py",
        generated_dir=GENERATED_DERIVE_ADDRESS_DIR,
        fixture_generators=[generate_address_derivation_fixtures],
        runner_generators=[
            generate_address_derivation_test_runners,
            generate_address_derivation_deny_test_runners,
        ],
        deny_generators=[generate_address_derivation_deny_fixtures],
    ),
    CommandMetadata(
        id="derive_native_script",
        display_name="Derive Native Script",
        ragger_file_name="test_derive_native_script.py",
        generated_dir=GENERATED_NATIVE_SCRIPT_DIR,
        fixture_generators=[generate_derive_native_script_fixtures],
        runner_generators=[
            generate_native_script_test_runners,
            generate_native_script_deny_test_runners,
        ],
        deny_generators=[generate_derive_native_script_deny_fixtures],
    ),
]


_CMOCKA_TEST_PATTERN = re.compile(r"cmocka_unit_test\(\s*([^)]+?)\s*\)")

_GENERATED_BY_SCRIPT = "tests/unit/generators/generate_unit_tests_from_ragger.py"


def _candidate_function_names_for_coverage_match(function_name: str) -> set[str]:
    """Return function-name variants used when matching generated unit tests."""
    candidate_names = {function_name}
    if function_name.endswith("_hash"):
        candidate_names.add(function_name[:-5])
    return candidate_names


def _extract_cmocka_test_names(file_path: Path) -> tuple[list[str], str]:
    """Return cmocka-registered test names plus the raw file content for coverage checks."""
    try:
        content = file_path.read_text(encoding="utf-8")
    except OSError:
        print(f"WARNING: Could not read {file_path} for counting cmocka tests")
        return [], ""
    names = [match.group(1).strip() for match in _CMOCKA_TEST_PATTERN.finditer(content)]
    return names, content


def _count_unit_tests_by_command() -> tuple[dict[str, int], int, set[str], str]:
    """
    Count unit-test entries per command and return the data along with total generated functions.

    The count is based on cmocka_unit_test() registrations so the reporting stays
    independent of the generator output formatting.
    IMPORTANT: this reads test sources from disk and does not depend on in-memory
    generation-phase counters/state from earlier steps in this script.

    Returns:
        (command_counts, total_funcs, registered_names, combined_content)
        registered_names: set of all function names registered via cmocka_unit_test()
        combined_content: concatenated raw source text (used only for A-vs-B sanity check)
    """
    command_counts: dict[str, int] = {cmd.id: 0 for cmd in COMMAND_REGISTRY}
    total_funcs = 0
    registered_names: set[str] = set()
    command_file_contents: list[str] = []

    def _add_file_content_only(path: Path) -> None:
        if not path.exists():
            raise FileNotFoundError(f"Unit test source missing: {path}")
        try:
            command_file_contents.append(path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise OSError(f"Failed reading {path}") from exc

    def _add_file_counts(path: Path, command: str) -> None:
        nonlocal total_funcs
        if not path.exists():
            raise FileNotFoundError(f"Unit test source missing: {path}")
        names, content = _extract_cmocka_test_names(path)
        command_counts[command] += len(names)
        total_funcs += len(names)
        registered_names.update(names)
        command_file_contents.append(content)

    # Keep sign-tx deny runner out of cmocka-based counting (counted via fixtures),
    # but include its source for function-name coverage matching.
    _add_file_content_only(GENERATED_SIGN_TX_DIR / "test_sign_tx_deny_tests.c")

    command_dir_map = {cmd.id: cmd.generated_dir for cmd in COMMAND_REGISTRY}

    for command, directory in command_dir_map.items():
        if directory.exists():
            for file_path in sorted(directory.glob("test_*.c")):
                _add_file_counts(file_path, command)

    combined_content = "\n".join(command_file_contents)
    return command_counts, total_funcs, registered_names, combined_content


def _is_covered_by_registered_names(
    candidate_names: set[str], registered_names: set[str]
) -> bool:
    """Option B: check coverage against the authoritative set of cmocka-registered names."""
    return any(
        candidate_name in registered_names
        or any(n.startswith(candidate_name + "_") for n in registered_names)
        for candidate_name in candidate_names
    )


def _is_covered_by_substring(
    candidate_names: set[str], unit_tests_content: str
) -> bool:
    """Option A: word-boundary regex check against raw source text."""
    return any(
        bool(re.search(rf"\b{re.escape(candidate_name)}\b", unit_tests_content))
        for candidate_name in candidate_names
    )


def _verify_ragger_test_coverage() -> None:
    """Verify that all ragger tests have corresponding unit test coverage."""
    # Collect ragger test names using pytest --collect-only
    ragger_tests_dir = REPO_ROOT / "tests" / "standalone"
    if not ragger_tests_dir.exists():
        print("WARNING: Ragger tests directory not found, skipping coverage check")
        return

    venv_pytest = REPO_ROOT / "tests" / "venv" / "bin" / "pytest"
    pytest_cmd = str(venv_pytest) if venv_pytest.exists() else "pytest"

    try:
        # Try to collect with a device parameter (ragger tests require --device)
        result = subprocess.run(
            [
                pytest_cmd,
                "--collect-only",
                "-q",
                "--device",
                "stax",
                str(ragger_tests_dir),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        # Check for collection errors (non-zero return code indicates failure)
        if result.returncode != 0:
            print(f"ERROR: pytest collection failed with return code {result.returncode}")
            if result.stderr:
                print("STDERR output:")
                print(result.stderr)
            if result.stdout:
                print("STDOUT output:")
                print(result.stdout)
            sys.exit(1)
        # Parse test names from pytest output (format: test_file.py::test_name[...])
        ragger_tests = [
            line.strip()
            for line in result.stdout.split("\n")
            if "::" in line and "test_" in line
        ]
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        print(f"ERROR: Could not collect ragger tests: {exc}")
        sys.exit(1)

    if not ragger_tests:
        print("ERROR: No ragger tests found - check that test files are present and importable")
        sys.exit(1)

    # Count total test cases (including parameterized variants)
    total_ragger_test_cases = len(ragger_tests)

    if not UNIT_TESTS_DIR.exists():
        print(f"ERROR: Unit test directory not found at {UNIT_TESTS_DIR}")
        sys.exit(1)

    ragger_command_counts = {cmd.id: 0 for cmd in COMMAND_REGISTRY}
    comparable_ragger_command_counts = {cmd.id: 0 for cmd in COMMAND_REGISTRY}
    skip_counts: dict[str, int] = defaultdict(int)
    unmapped_counts: dict[str, int] = defaultdict(int)

    skip_test_files = {
        "test_client_constants.py",
        "test_app_mainmenu.py",
        "test_error_cmd.py",
        "test_mock_key_derivation.py",
        "test_get_app_info.py",
    }
    skip_test_funcs = {
        "test_wrong_data_length",
        # test_sign_tx_deny coverage is tracked via _count_sign_tx_deny_fixtures() /
        # SIGN_TX_DENY_FIXTURES; the unit-test runner (test_sign_tx_deny_fixture) is
        # a fixture-driven loop, not a per-case cmocka registration, so it will never
        # appear in registered_unit_test_names under its ragger name.
        "test_sign_tx_deny",
    }
    ragger_test_funcs = set()

    for test_line in ragger_tests:
        if "::" not in test_line:
            continue
        module_part, func_part = test_line.split("::", 1)
        module_name = Path(module_part).name
        if module_name in skip_test_files:
            skip_counts[module_name] += 1
            continue
        command = next(
            (cmd.id for cmd in COMMAND_REGISTRY if cmd.ragger_file_name == module_name),
            None,
        )
        if command:
            ragger_command_counts[command] += 1
            comparable_ragger_command_counts[command] += 1
        else:
            unmapped_counts[module_name] += 1
        func_name = func_part.split("[", 1)[0]
        if func_name and func_name not in skip_test_funcs:
            ragger_test_funcs.add(func_name)

    # Coverage/counting is intentionally filesystem-based and independent from
    # generation-phase bookkeeping; it scans current unit-test files on disk.
    (
        unit_command_counts,
        total_unit_test_funcs,
        registered_unit_test_names,
        unit_tests_content,
    ) = _count_unit_tests_by_command()
    deny_fixture_count = _count_sign_tx_deny_fixtures()
    if deny_fixture_count:
        unit_command_counts["sign_tx"] += deny_fixture_count
    expanded_unit_test_count = total_unit_test_funcs + deny_fixture_count
    # For sign_tx, compare against fine-grained expected entries (same granularity
    # as generated unit tests), not raw pytest parameterized-case count.
    comparable_ragger_command_counts["sign_tx"] = (
        _count_sign_tx_fine_grained_entries_from_fixtures()
    )

    # Extract unique test function names from ragger tests
    # Format: test_file.py::test_func_name[param] -> extract test_func_name
    missing_coverage = []
    covered_coverage = []
    for func_name in sorted(ragger_test_funcs):
        # Some ragger tests expand into indexed unit tests. Match both the exact
        # function name and generated prefixes.
        candidate_function_names = _candidate_function_names_for_coverage_match(
            func_name
        )
        # We intentionally use two mechanisms (Option A and Option B) for coverage validation.
        # This redundancy is for validation purposes, and any mismatch between them will be manually investigated.
        # Primary check (B): coverage is determined by cmocka_unit_test() registrations only.
        found_by_registered = _is_covered_by_registered_names(
            candidate_function_names, registered_unit_test_names
        )
        # Sanity check (A): word-boundary regex over raw source text.
        found_by_substring = _is_covered_by_substring(
            candidate_function_names, unit_tests_content
        )
        if found_by_substring and not found_by_registered:
            print(
                f"WARNING: coverage inconsistency for '{func_name}': "
                f"found as word-boundary match in source text but NOT in cmocka registrations — "
                f"function may be defined but not registered as a test"
            )
        if found_by_registered:
            covered_coverage.append(func_name)
        else:
            missing_coverage.append(func_name)

    deny_note = ""
    if deny_fixture_count:
        deny_note = (
            f", includes {deny_fixture_count} fixtures sampled through "
            f"`SIGN_TX_DENY_FIXTURES`"
        )
    print("\nRagger test coverage check:")
    print(
        f"  Ragger: {total_ragger_test_cases} total test cases from {len(ragger_tests)} parameterized variants"
    )
    print(
        f"  Unit tests: {expanded_unit_test_count} total test entries "
        f"({total_unit_test_funcs} generated functions{deny_note})"
    )
    print("  Command breakdown:")
    for cmd in COMMAND_REGISTRY:
        command = cmd.id
        ragger_count = comparable_ragger_command_counts.get(command, 0)
        unit_count = unit_command_counts.get(command, 0)
        delta = unit_count - ragger_count
        delta_note = f" (Δ {delta:+d})" if delta else ""
        print(
            f"    - {cmd.display_name}: {ragger_count} Ragger -> {unit_count} unit entries{delta_note}"
        )
    if comparable_ragger_command_counts["sign_tx"] != ragger_command_counts["sign_tx"]:
        print(
            "  Note: Sign Transaction uses fine-grained fixture-based counting for comparison "
            f"(raw pytest cases: {ragger_command_counts['sign_tx']})."
        )
    if skip_counts:
        skip_total = sum(skip_counts.values())
        skip_details = ", ".join(
            f"{name}({count})" for name, count in sorted(skip_counts.items())
        )
        print(
            f"  Ignored {skip_total} pytest cases from auxiliary modules ({skip_details})"
        )
    if unmapped_counts:
        unmapped_total = sum(unmapped_counts.values())
        unmapped_details = ", ".join(
            f"{name}({count})" for name, count in sorted(unmapped_counts.items())
        )
        print(f"  Unmapped pytest modules ({unmapped_total} cases): {unmapped_details}")

    insufficient_commands = []
    mismatched_counts = []
    for cmd in COMMAND_REGISTRY:
        command = cmd.id
        ragger_count = comparable_ragger_command_counts.get(command, 0)
        unit_count = unit_command_counts.get(command, 0)

        # Validate in-memory generation against parsed cmocka tests.
        if hasattr(cmd, "generated_entries_count") and cmd.generated_entries_count > 0:
            in_memory_count = cmd.generated_entries_count
            if in_memory_count != unit_count:
                mismatched_counts.append(
                    f"{cmd.display_name}: Generated {in_memory_count} entries in memory, but parsed {unit_count} cmocka tests from files."
                )

        if unit_count < ragger_count:
            insufficient_commands.append(
                f"{cmd.display_name} (Ragger {ragger_count}, Unit {unit_count})"
            )

    if mismatched_counts:
        print("\n" + "!" * _REPORT_WIDTH)
        print(
            "!!! "
            + "WARNING: Mismatch between in-memory generation and file parsing".center(
                _REPORT_WIDTH - 8
            )
            + " !!!"
        )
        print(
            "!!! "
            + "(Intentional validation redundancy)".center(_REPORT_WIDTH - 8)
            + " !!!"
        )
        print("!" * _REPORT_WIDTH)
        for mismatch in mismatched_counts:
            print(f"  - {mismatch}")
        print("!" * _REPORT_WIDTH + "\n")

    if insufficient_commands:
        print(
            f"  ERROR: insufficient per-command coverage detected: {', '.join(insufficient_commands)}"
        )
    print(f"  Found {len(ragger_test_funcs)} unique ragger test functions to cover")
    print(
        f"  Coverage: {len(covered_coverage)} functions covered, {len(missing_coverage)} missing"
    )

    if missing_coverage:
        print(
            f"\n  WARNING: {len(missing_coverage)} test function(s) lack unit test coverage:"
        )
        for test in missing_coverage:
            print(f"    - {test}")

        # Show which test cases are missing for each uncovered function
        print("\n  Missing test cases by function:")
        for func_name in missing_coverage:
            # Find all ragger test cases for this function
            missing_test_cases = [
                line.strip() for line in ragger_tests if f"::{func_name}[" in line
            ]
            if missing_test_cases:
                print(f"    {func_name}: ({len(missing_test_cases)} cases)")
                for case in missing_test_cases:
                    # Extract just the test case name part for readability
                    if "::" in case:
                        _, test_case = case.split("::", 1)
                        print(f"      - {test_case}")
        print("\n" + "=" * _REPORT_WIDTH)
        print(
            "COVERAGE FAILURE: missing unit-test coverage for one or more ragger test functions."
        )
        print(
            "The generator run is unsuccessful until all missing functions above are covered."
        )
        print("=" * _REPORT_WIDTH)
        sys.exit(1)

    if mismatched_counts:
        print("\n" + "=" * _REPORT_WIDTH)
        print("MOCK DATA / COUNTING FAILURE: In-memory counts do not match file parsing.")
        print("The generator run is unsuccessful until all mismatches are resolved.")
        print("=" * _REPORT_WIDTH)
        sys.exit(1)

    if insufficient_commands:
        print("\n" + "=" * _REPORT_WIDTH)
        print("COVERAGE FAILURE: insufficient per-command coverage detected.")
        print("=" * _REPORT_WIDTH)
        sys.exit(1)

    print("\n  OK All ragger test functions have unit test coverage and consistent counts")


def run_all() -> None:
    _log_stage("Generating fixtures")
    for cmd in COMMAND_REGISTRY:
        for gen in cmd.fixture_generators:
            count = gen()
            if count is not None:
                cmd.generated_entries_count += count

    _log_stage("Generating test runners")
    for cmd in COMMAND_REGISTRY:
        for gen in cmd.runner_generators:
            count = gen()
            if count is not None:
                cmd.generated_entries_count += count

    _log_stage("Generating deny fixtures")
    for cmd in COMMAND_REGISTRY:
        for gen in cmd.deny_generators:
            count = gen()
            if count is not None:
                cmd.generated_entries_count += count

    _log_stage("Regenerating mock data")
    regenerate_mock_data()
    _log_stage("Verifying Ragger coverage")
    _verify_ragger_test_coverage()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate unit-test fixtures from ragger sources."
    )
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("all", help="Run all generators (default).")
    subparsers.add_parser("fixtures", help="Generate sign-tx fixture headers.")
    subparsers.add_parser(
        "generate-test-runners", help="Regenerate test_sign_tx_*.c files."
    )
    subparsers.add_parser("deny_tests", help="Generate deny fixture headers.")
    subparsers.add_parser("mock-data", help="Regenerate mocks/crypto_mock_data.h.")

    args = parser.parse_args()

    print(f"Unit tests directory: {UNIT_TESTS_DIR}")

    if args.command in (None, "all"):
        run_all()
    elif args.command == "fixtures":
        _log_stage("Generating fixtures")
        for cmd in COMMAND_REGISTRY:
            for gen in cmd.fixture_generators:
                count = gen()
                if count is not None:
                    cmd.generated_entries_count += count
    elif args.command == "generate-test-runners":
        _log_stage("Generating test runners")
        for cmd in COMMAND_REGISTRY:
            for gen in cmd.runner_generators:
                count = gen()
                if count is not None:
                    cmd.generated_entries_count += count
    elif args.command == "deny_tests":
        _log_stage("Generating deny fixtures")
        for cmd in COMMAND_REGISTRY:
            for gen in cmd.deny_generators:
                count = gen()
                if count is not None:
                    cmd.generated_entries_count += count
    elif args.command == "mock-data":
        _log_stage("Regenerating mock data")
        regenerate_mock_data()
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
