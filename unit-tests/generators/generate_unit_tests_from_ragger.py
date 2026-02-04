#!/usr/bin/env python3
"""
Unified generator for unit-test fixtures derived from ragger sources.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

from common import UNIT_TESTS_DIR
from paths import REPO_ROOT
from mock_data_utils import regenerate_mock_data


# Match reject fixtures array for counting individual reject cases
_SIGN_TX_REJECT_FIXTURES_PATTERN = re.compile(
    r"static const sign_tx_reject_fixture_t SIGN_TX_REJECT_FIXTURES\[\]\s*=\s*\{(.*?)\n\};",
    flags=re.DOTALL,
)

# Match individual reject fixture entries inside the array
_SIGN_TX_REJECT_ENTRY_PATTERN = re.compile(r"\.name\s*=")

# Import fixture generators
from fixture_generators.tx_generators import (
    generate_tx_fixtures,
)

from fixture_generators.derive_address_generators import (
    generate_address_derivation_fixtures,
)

from fixture_generators.derive_native_script_generators import (
    generate_derive_native_script_fixtures,
)
from fixture_generators.pubkey_generators import (
    generate_pubkey_fixtures,
)
from fixture_generators.sign_msg_generators import (
    generate_sign_msg_fixtures,
)
from fixture_generators.opcert_generators import (
    generate_opcert_fixtures,
)

# Import reject generators
from reject_fixture_generators.tx_reject_generators import (
    generate_tx_reject_fixtures,
)

from reject_fixture_generators.derive_address_reject_generators import (
    generate_address_derivation_reject_fixtures,
)

from reject_fixture_generators.derive_native_script_reject_generators import (
    generate_derive_native_script_reject_fixtures,
)
from reject_fixture_generators.pubkey_reject_generators import (
    generate_pubkey_reject_fixtures,
)

# Import test runners
from test_runner_generators.tx_test_runner_generators import (
    generate_tx_test_runners,
)

from test_runner_generators.derive_address_test_runner_generators import (
    generate_address_derivation_test_runners,
)

from test_runner_generators.derive_native_script_runner_generators import (
    generate_native_script_test_runners,
)
from test_runner_generators.derive_address_reject_runner_generators import (
    generate_address_derivation_reject_test_runners,
)
from test_runner_generators.pubkey_test_runner_generators import (
    generate_pubkey_test_runners,
)
from test_runner_generators.pubkey_reject_runner_generators import (
    generate_pubkey_reject_test_runners,
)
from test_runner_generators.sign_msg_test_runner_generators import (
    generate_sign_msg_test_runners,
)
from test_runner_generators.opcert_test_runner_generators import (
    generate_opcert_test_runners,
)

def _log_stage(message: str) -> None:
    print(f"\n--- {message} ---")


def _count_sign_tx_reject_fixtures() -> int:
    """Return the number of fixtures in sign_tx reject suite to account for per-test coverage."""
    fixtures_file = UNIT_TESTS_DIR / "test_sign_tx_fixtures_rejects.h"
    if not fixtures_file.exists():
        return 0

    try:
        content = fixtures_file.read_text(encoding="utf-8")
    except OSError:
        return 0

    match = _SIGN_TX_REJECT_FIXTURES_PATTERN.search(content)
    if not match:
        return 0

    fixture_body = match.group(1)
    return len(_SIGN_TX_REJECT_ENTRY_PATTERN.findall(fixture_body))


_COMMAND_ORDER = [
    "sign_tx",
    "sign_msg",
    "sign_cvote",
    "sign_opcert",
    "pubkey_export",
    "derive_address",
    "derive_native_script",
]

_COMMAND_DISPLAY_NAMES = {
    "sign_tx": "Sign Transaction",
    "sign_msg": "Sign Message",
    "sign_cvote": "Sign CVote",
    "sign_opcert": "Sign Opcert",
    "pubkey_export": "Pubkey Export",
    "derive_address": "Derive Address",
    "derive_native_script": "Derive Native Script",
}

_RAGGER_FILE_TO_COMMAND = {
    "test_sign_tx.py": "sign_tx",
    "test_signMsg.py": "sign_msg",
    "test_cvote.py": "sign_cvote",
    "test_opcert.py": "sign_opcert",
    "test_pubkey.py": "pubkey_export",
    "test_derive_address.py": "derive_address",
    "test_derive_native_script.py": "derive_native_script",
}

_CMOCKA_TEST_PATTERN = re.compile(r"cmocka_unit_test\(\s*([^)]+?)\s*\)")


def _extract_cmocka_test_names(file_path: Path) -> tuple[list[str], str]:
    """Return cmocka-registered test names plus the raw file content for coverage checks."""
    try:
        content = file_path.read_text(encoding="utf-8")
    except OSError:
        print(f"WARNING: Could not read {file_path} for counting cmocka tests")
        return [], ""
    names = [match.group(1).strip() for match in _CMOCKA_TEST_PATTERN.finditer(content)]
    return names, content


def _count_unit_tests_by_command() -> tuple[dict[str, int], int, str]:
    """
    Count unit-test entries per command and return the data along with total generated functions.

    The count is based on cmocka_unit_test() registrations so the reporting stays
    independent of the generator output formatting.
    """
    command_counts: dict[str, int] = {command: 0 for command in _COMMAND_ORDER}
    total_funcs = 0
    command_file_contents: list[str] = []

    def _add_file_counts(path: Path, command: str) -> None:
        nonlocal total_funcs
        if not path.exists():
            raise FileNotFoundError(f"Unit test source missing: {path}")
        names, content = _extract_cmocka_test_names(path)
        command_counts[command] += len(names)
        total_funcs += len(names)
        command_file_contents.append(content)

    tx_test_files = sorted(
        p for p in UNIT_TESTS_DIR.glob("test_sign_tx_*.c") if p.name != "test_sign_tx_rejects.c"
    )
    for path in tx_test_files:
        _add_file_counts(path, "sign_tx")

    unit_file_map = {
        "sign_msg": ["test_sign_msg.c"],
        "sign_cvote": ["test_cvote.c"],
        "sign_opcert": ["test_opcert.c"],
        "pubkey_export": ["test_pubkey.c", "test_pubkey_rejects.c"],
        "derive_address": ["test_derive_address.c", "test_derive_address_rejects.c"],
        "derive_native_script": ["test_native_script.c", "test_native_script_rejects.c"],
    }
    for command, filenames in unit_file_map.items():
        for filename in filenames:
            _add_file_counts(UNIT_TESTS_DIR / filename, command)

    combined_content = "\n".join(command_file_contents)
    return command_counts, total_funcs, combined_content


def _verify_ragger_test_coverage() -> None:
    """Verify that all ragger tests have corresponding unit test coverage."""
    # Collect ragger test names using pytest --collect-only
    ragger_tests_dir = REPO_ROOT / "tests" / "standalone"
    if not ragger_tests_dir.exists():
        print("WARNING: Ragger tests directory not found, skipping coverage check")
        return

    try:
        # Try to collect with a device parameter (ragger tests require --device)
        result = subprocess.run(
            ["pytest", "--collect-only", "-q", "--device", "stax", str(ragger_tests_dir)],
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
            line.strip() for line in result.stdout.split("\n")
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

    ragger_command_counts = {command: 0 for command in _COMMAND_ORDER}
    skip_counts: dict[str, int] = defaultdict(int)
    unmapped_counts: dict[str, int] = defaultdict(int)

    skip_test_files = {
        "test_client_constants.py",
        "test_app_mainmenu.py",
        "test_error_cmd.py",
        "test_mock_key_derivation.py",
        "test_get_app_info.py",
    }
    skip_test_funcs = {"test_wrong_data_length"}
    ragger_test_funcs = set()

    for test_line in ragger_tests:
        if "::" not in test_line:
            continue
        module_part, func_part = test_line.split("::", 1)
        module_name = Path(module_part).name
        if module_name in skip_test_files:
            skip_counts[module_name] += 1
            continue
        command = _RAGGER_FILE_TO_COMMAND.get(module_name)
        if command:
            ragger_command_counts[command] += 1
        else:
            unmapped_counts[module_name] += 1
        func_name = func_part.split("[", 1)[0]
        if func_name and func_name not in skip_test_funcs:
            ragger_test_funcs.add(func_name)

    unit_command_counts, total_unit_test_funcs, unit_tests_content = _count_unit_tests_by_command()
    reject_fixture_count = _count_sign_tx_reject_fixtures()
    if reject_fixture_count:
        unit_command_counts["sign_tx"] += reject_fixture_count
    expanded_unit_test_count = total_unit_test_funcs + reject_fixture_count

    # Extract unique test function names from ragger tests
    # Format: test_file.py::test_func_name[param] -> extract test_func_name
    missing_coverage = []
    covered_coverage = []
    for func_name in sorted(ragger_test_funcs):
        # Check if the ragger test function name appears in unit tests
        # Some functions like test_derive_native_script_hash expand to test_derive_native_script_*
        # So we check for both exact match and prefix match (with underscore)
        found = (func_name in unit_tests_content or
                 f"{func_name}_" in unit_tests_content or
                 func_name.rstrip("_hash") in unit_tests_content or
                 func_name.rstrip("_rejects") in unit_tests_content)
        if found:
            covered_coverage.append(func_name)
        else:
            missing_coverage.append(func_name)

    reject_note = ""
    if reject_fixture_count:
        reject_note = (f", includes {reject_fixture_count} fixtures sampled through "
                       f"`SIGN_TX_REJECT_FIXTURES`")
    print(f"\nRagger test coverage check:")
    print(f"  Ragger: {total_ragger_test_cases} total test cases from {len(ragger_tests)} parameterized variants")
    print(f"  Unit tests: {expanded_unit_test_count} total test entries "
          f"({total_unit_test_funcs} generated functions{reject_note})")
    print(f"  Command breakdown:")
    for command in _COMMAND_ORDER:
        ragger_count = ragger_command_counts.get(command, 0)
        unit_count = unit_command_counts.get(command, 0)
        delta = unit_count - ragger_count
        delta_note = f" (Δ {delta:+d})" if delta else ""
        print(f"    - {_COMMAND_DISPLAY_NAMES[command]}: {ragger_count} Ragger -> {unit_count} unit entries{delta_note}")
    if skip_counts:
        skip_total = sum(skip_counts.values())
        skip_details = ", ".join(f"{name}({count})" for name, count in sorted(skip_counts.items()))
        print(f"  Ignored {skip_total} pytest cases from auxiliary modules ({skip_details})")
    if unmapped_counts:
        unmapped_total = sum(unmapped_counts.values())
        unmapped_details = ", ".join(f"{name}({count})" for name, count in sorted(unmapped_counts.items()))
        print(f"  Unmapped pytest modules ({unmapped_total} cases): {unmapped_details}")
    mismatched_commands = []
    for command in _COMMAND_ORDER:
        ragger_count = ragger_command_counts.get(command, 0)
        unit_count = unit_command_counts.get(command, 0)
        if ragger_count != unit_count:
            mismatched_commands.append(
                f"{_COMMAND_DISPLAY_NAMES[command]} (Ragger {ragger_count}, Unit {unit_count})"
            )
    if mismatched_commands:
        print(f"  ERROR: per-command mismatches detected: {', '.join(mismatched_commands)}")
    print(f"  Found {len(ragger_test_funcs)} unique ragger test functions to cover")
    print(f"  Coverage: {len(covered_coverage)} functions covered, {len(missing_coverage)} missing")

    if missing_coverage:
        print(f"\n  WARNING: {len(missing_coverage)} test function(s) lack unit test coverage:")
        for test in missing_coverage:
            print(f"    - {test}")

        # Show which test cases are missing for each uncovered function
        print(f"\n  Missing test cases by function:")
        for func_name in missing_coverage:
            # Find all ragger test cases for this function
            missing_test_cases = [
                line.strip() for line in ragger_tests
                if f"::{func_name}[" in line
            ]
            if missing_test_cases:
                print(f"    {func_name}: ({len(missing_test_cases)} cases)")
                for case in missing_test_cases:
                    # Extract just the test case name part for readability
                    if "::" in case:
                        _, test_case = case.split("::", 1)
                        print(f"      - {test_case}")
    else:
        print(f"\n  OK All ragger test functions have unit test coverage")

    # Show breakdown of covered tests
    if covered_coverage:
        print(f"\n  Covered test functions:")
        for test in covered_coverage:
            print(f"    + {test}")


def run_all() -> None:
    _log_stage("Generating fixtures")
    generate_tx_fixtures()
    generate_address_derivation_fixtures()
    generate_derive_native_script_fixtures()
    generate_pubkey_fixtures()
    generate_sign_msg_fixtures()
    generate_opcert_fixtures()
    _log_stage("Generating test runners")
    generate_tx_test_runners()
    generate_address_derivation_test_runners()
    generate_native_script_test_runners()
    generate_address_derivation_reject_test_runners()
    generate_pubkey_test_runners()
    generate_sign_msg_test_runners()
    generate_opcert_test_runners()
    _log_stage("Generating reject fixtures")
    generate_tx_reject_fixtures()
    generate_address_derivation_reject_fixtures()
    generate_derive_native_script_reject_fixtures()
    generate_pubkey_reject_fixtures()
    generate_pubkey_reject_test_runners()
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
    subparsers.add_parser("rejects", help="Generate reject fixture headers.")
    subparsers.add_parser("mock-data", help="Regenerate mocks/crypto_mock_data.h.")

    args = parser.parse_args()

    print(f"Unit tests directory: {UNIT_TESTS_DIR}")

    if args.command in (None, "all"):
        run_all()
    elif args.command == "fixtures":
        _log_stage("Generating fixtures")
        generate_tx_fixtures()
        generate_address_derivation_fixtures()
        generate_derive_native_script_fixtures()
        generate_pubkey_fixtures()
        generate_sign_msg_fixtures()
        generate_opcert_fixtures()
    elif args.command == "generate-test-runners":
        _log_stage("Generating test runners")
        generate_tx_test_runners()
        generate_address_derivation_test_runners()
        generate_native_script_test_runners()
        generate_address_derivation_reject_test_runners()
        generate_pubkey_test_runners()
        generate_sign_msg_test_runners()
        generate_opcert_test_runners()
        generate_pubkey_reject_fixtures()
        generate_pubkey_reject_test_runners()
    elif args.command == "rejects":
        _log_stage("Generating reject fixtures")
        generate_tx_reject_fixtures()
        generate_address_derivation_reject_fixtures()
        generate_derive_native_script_reject_fixtures()
        generate_pubkey_reject_fixtures()
    elif args.command == "mock-data":
        _log_stage("Regenerating mock data")
        regenerate_mock_data()
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
